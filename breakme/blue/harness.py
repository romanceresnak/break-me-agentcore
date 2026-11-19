"""Blue agent on the Amazon Bedrock AgentCore managed harness.

Every BREAK ME tool is an `inline_function`: the harness emits the model's tool call
in the stream, stops with stopReason=tool_use and waits. We run the call through the
gateway (Cedar PEP -> IAM-bounded backend -> output guardrail) under the harness's own
runtimeSessionId and send the toolResult back on the same session.

Why inline functions and not a Gateway target: the gateway keeps per-session state
(taint after reading injected content, cumulative cost, single-use approvals). With
inline functions the session id is ours, exact and unforgeable by the model.

Harness-level limits that are part of the rule enforcement:
  allowedTools      only the BREAK ME tools (as @name): built-in shell / file / web tools are never offered
  maxIterations     caps the agent loop (no runaway retries)
  timeoutSeconds    caps one invocation
  executionRole     can invoke the model and write logs, nothing else (infra/terraform/harness.tf)

API shapes from the botocore service model (bedrock-agentcore-control CreateHarness,
bedrock-agentcore InvokeHarness).
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field

from ..config import artifact
from ..gateway import TOOLS
from .agents import AgentRun

DEFAULT_MODEL = os.environ.get("BREAKME_HARNESS_MODEL", "us.anthropic.claude-sonnet-4-6")
MAX_ITERATIONS = 15
TIMEOUT_SECONDS = 300


def tool_specs() -> list[dict]:
    return [{"type": "inline_function", "name": t["name"],
             "config": {"inlineFunction": {"description": t["description"], "inputSchema": t["input_schema"]}}}
            for t in TOOLS]


def allowed_tools() -> list[str]:
    """A bare name in allowedTools selects BUILT-IN tools only; configured tools (inline functions,
    MCP, gateway) are selected as @name. Bare names silently removed every BREAK ME tool (a real
    bug we hit). @name exposes exactly our tools and keeps shell / file / web_fetch hidden."""
    return ["@" + t["name"] for t in TOOLS]


def create_harness(name: str, role_arn: str, model_id: str = DEFAULT_MODEL, region: str | None = None,
                   wait: bool = True) -> dict:
    import boto3
    control = boto3.client("bedrock-agentcore-control", region_name=region)
    h = control.create_harness(
        harnessName=name,
        executionRoleArn=role_arn,
        model={"bedrockModelConfig": {"modelId": model_id, "maxTokens": 8000, "temperature": 0.2}},
        systemPrompt=[{"text": artifact("agent_instructions.md")}],
        tools=tool_specs(),
        allowedTools=allowed_tools(),
        memory={"disabled": {}},
        maxIterations=MAX_ITERATIONS,
        timeoutSeconds=TIMEOUT_SECONDS,
        tags={"Project": "break-me"},
    )
    if not wait:
        return h
    hid = h.get("harnessId") or h.get("harness", {}).get("harnessId") or h.get("harnessArn", "").split("/")[-1]
    for _ in range(90):
        g = control.get_harness(harnessId=hid)
        status = (g.get("harness") or g).get("status", "")
        if status in ("READY", "FAILED", "CREATE_FAILED"):
            return g
        time.sleep(5)
    return g


def new_session_id() -> str:
    return ("breakme-" + uuid.uuid4().hex + uuid.uuid4().hex)[:48]   # API needs >= 33 chars


@dataclass
class _Turn:
    text: str = ""
    stop: str = ""
    tool_uses: list = field(default_factory=list)   # [{"id", "name", "input"}]
    errors: list = field(default_factory=list)


def parse_stream(stream) -> _Turn:
    """Collect text, inline tool calls and the stop reason from one InvokeHarness stream."""
    t = _Turn()
    current: dict | None = None
    try:
        events = list(stream)
    except Exception as e:  # EventStreamError: max tokens, throttling, model errors
        t.errors.append(str(e)[:300])
        t.stop = "error"
        return t
    for ev in events:
        if "contentBlockStart" in ev:
            start = ev["contentBlockStart"].get("start", {})
            if "toolUse" in start:
                tu = start["toolUse"]
                current = {"id": tu["toolUseId"], "name": tu["name"], "type": tu.get("type"), "raw": ""}
        elif "contentBlockDelta" in ev:
            d = ev["contentBlockDelta"].get("delta", {})
            if "text" in d:
                t.text += d["text"]
            elif "toolUse" in d and current is not None:
                current["raw"] += d["toolUse"].get("input", "")
        elif "contentBlockStop" in ev:
            if current is not None:
                try:
                    current["input"] = json.loads(current["raw"] or "{}")
                except json.JSONDecodeError:
                    current["input"] = {}
                t.tool_uses.append(current)
                current = None
        elif "messageStop" in ev:
            t.stop = ev["messageStop"].get("stopReason", "")
        else:
            for k in ("runtimeClientError", "validationException", "internalServerException"):
                if k in ev:
                    t.errors.append(f"{k}: {ev[k].get('message', ev[k])}")
    return t


class HarnessAgent:
    """run(user_text, call_tool) - same contract as the other blue runtimes."""

    def __init__(self, harness_arn: str, region: str | None = None, model_id: str | None = None,
                 client=None):
        if client is None:
            import boto3
            client = boto3.client("bedrock-agentcore", region_name=region)
        self.client = client
        self.arn = harness_arn
        self.model_id = model_id
        self.name = f"harness:{model_id or 'default'}"
        self.inline_names = {t["name"] for t in TOOLS}
        self.last_session_id: str | None = None

    def _invoke(self, session_id: str, messages: list) -> _Turn:
        kw = {"harnessArn": self.arn, "runtimeSessionId": session_id, "messages": messages}
        if self.model_id:
            kw["model"] = {"bedrockModelConfig": {"modelId": self.model_id}}
        return parse_stream(self.client.invoke_harness(**kw)["stream"])

    def run(self, user_text: str, call_tool, max_rounds: int = MAX_ITERATIONS,
            session_id: str | None = None) -> AgentRun:
        sid = session_id or new_session_id()
        self.last_session_id = sid
        run = AgentRun(final="")
        texts: list[str] = []
        turn = self._invoke(sid, [{"role": "user", "content": [{"text": user_text}]}])
        for _ in range(max_rounds):
            if turn.text:
                texts.append(turn.text)
            if turn.errors:
                texts.append("(" + "; ".join(turn.errors) + ")")
                break
            pending = [u for u in turn.tool_uses if u["name"] in self.inline_names]
            if turn.stop != "tool_use" or not pending:
                break
            results = []
            for u in pending:
                r = call_tool(u["name"], u.get("input") or {})
                d = r.as_dict() if hasattr(r, "as_dict") else dict(r)
                run.steps.append({"tool": u["name"], "args": u.get("input"), "result": d})
                if d.get("action"):
                    run.attempted.append(d["action"])
                ok = d.get("status") in ("OK", "PENDING_APPROVAL")
                results.append({"toolResult": {"toolUseId": u["id"], "content": [{"text": d.get("output", "")}],
                                               "status": "success" if ok else "error"}})
            turn = self._invoke(sid, [{"role": "user", "content": results}])
        run.final = "\n".join(x for x in texts if x).strip() or f"(no text; stop reason {turn.stop})"
        return run

    @classmethod
    def from_env(cls) -> "HarnessAgent":
        return cls(os.environ["BREAKME_HARNESS_ARN"], os.environ.get("AWS_REGION", "us-east-1"),
                   os.environ.get("BREAKME_HARNESS_MODEL") or None)
