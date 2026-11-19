"""Amazon Bedrock Managed Agents (powered by OpenAI) - preview REST client.

Endpoint  https://bedrock-mantle.<region>.api.aws   (us-east-1, us-east-2, us-west-2)
Signing   SigV4, service "bedrock-mantle"
Paths     POST   /openai/v1/agents/sessions                 create session
          GET    /openai/v1/agents/sessions/{id}            retrieve (state)
          POST   /openai/v1/agents/sessions/{id}/events     submit agent.session.input.message
          GET    /openai/v1/agents/sessions/{id}/items      durable items (1-100 per page)
          DELETE /openai/v1/agents/sessions/{id}

Tools run in OUR execution environment: the exec host runs `codex exec-server` and the
STDIO MCP server `python -m breakme.mcp_server`, which forwards every call to the Tool API
(Cedar + IAM boundary). The exec host itself has no AWS permissions besides invoking the
Tool API, so even shell commands the agent runs there cannot touch AWS directly.

Request bodies match the AWS example bundle (bma/self-hosted/scripts/bma/0.create-session.sh,
2.submit-turn.sh, 3.read-result.sh). If a newer bundle changes a field, override the
create-session body with BREAKME_BMA_SESSION_TEMPLATE (a JSON file merged into it).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..config import ROOT, artifact
from ..gateway import TOOLS
from .agents import AgentRun


class BmaClient:
    def __init__(self, region: str = "us-east-1", endpoint: str | None = None):
        import boto3
        self.region = region
        self.endpoint = endpoint or f"https://bedrock-mantle.{region}.api.aws"
        self.creds = boto3.Session().get_credentials().get_frozen_credentials()

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        data = json.dumps(body).encode() if body is not None else None
        req = AWSRequest(method=method, url=self.endpoint + path, data=data,
                         headers={"content-type": "application/json"})
        SigV4Auth(self.creds, "bedrock-mantle", self.region).add_auth(req)
        r = urllib.request.Request(req.url, data=data, method=method, headers=dict(req.headers))
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:2000]
            raise RuntimeError(f"BMA {method} {path} -> HTTP {e.code}: {detail}") from None

    def create_session(self, model: str, instructions: str, role_arn: str, workspace: str,
                       mcp_command: str, mcp_args: list[str], mcp_cwd: str, mcp_env: dict) -> dict:
        """Body shape from the AWS example bundle (self-hosted/scripts/bma/0.create-session.sh)."""
        body = {
            "role_arn": role_arn,
            "agent": {
                "model": model,
                "instructions": instructions,
                "tools": [{
                    "type": "mcp",
                    "server_label": "breakme",
                    "transport": {"type": "stdio", "command": mcp_command, "args": mcp_args,
                                  "cwd": mcp_cwd, "env": mcp_env, "env_vars": []},
                    # Even the MCP surface is allow-listed; the Tool API re-checks everything.
                    "allowed_tools": [t["name"] for t in TOOLS],
                }],
            },
            "environment": {"type": "self_hosted", "workspace_directory": workspace,
                            "capability_directories": []},
            "stream": False,
        }
        tpl = os.environ.get("BREAKME_BMA_SESSION_TEMPLATE")
        if tpl:
            body.update(json.loads(open(tpl, encoding="utf-8").read()))
        return self._req("POST", "/openai/v1/agents/sessions", body)

    def submit(self, session_id: str, text: str) -> None:
        """Body shape from 2.submit-turn.sh. Accepted != completed: poll status afterwards."""
        self._req("POST", f"/openai/v1/agents/sessions/{session_id}/events", {"events": [{
            "type": "agent.session.input.message",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}],
        }]})

    def get(self, session_id: str) -> dict:
        return self._req("GET", f"/openai/v1/agents/sessions/{session_id}")

    def items(self, session_id: str, limit: int = 100) -> list[dict]:
        r = self._req("GET", f"/openai/v1/agents/sessions/{session_id}/items?limit={limit}")
        return r.get("data", r.get("items", [])) if isinstance(r, dict) else r

    def delete(self, session_id: str) -> None:
        self._req("DELETE", f"/openai/v1/agents/sessions/{session_id}")


TERMINAL = {"failed", "error", "cancelled", "closed"}


def _texts(item: dict) -> list[str]:
    """Assistant text from an item, tolerant to content-part naming (output_text / text)."""
    if item.get("role") not in (None, "assistant"):
        return []
    out = []
    for c in item.get("content") or []:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            out.append(c["text"])
    return out


@dataclass
class ManagedAgent:
    """Runs one turn on a live BMA session. Tool calls are recorded server-side by the Tool API."""
    client: BmaClient
    session_id: str
    name: str = "bma"

    @classmethod
    def from_env(cls) -> "ManagedAgent":
        c = BmaClient(os.environ.get("BMA_REGION", "us-east-1"))
        sid = os.environ.get("BREAKME_BMA_SESSION_ID")
        if not sid:
            repo = os.environ.get("BREAKME_REPO_DIR", str(ROOT))
            s = c.create_session(
                model=os.environ.get("BREAKME_BMA_MODEL", "openai.gpt-5.6-luna"),
                instructions=artifact("agent_instructions.md"),
                role_arn=os.environ["BMA_INFERENCE_ROLE_ARN"],
                workspace=os.environ.get("BMA_WORKSPACE_DIRECTORY", str(ROOT / "workspace")),
                mcp_command=os.environ.get("BREAKME_MCP_PYTHON", f"{repo}/.venv/bin/python"),
                mcp_args=["-m", "breakme.mcp_server"],
                mcp_cwd=repo,
                mcp_env={"BREAKME_TOOL_API_URL": os.environ["BREAKME_TOOL_API_URL"],
                         "AWS_REGION": os.environ.get("AWS_REGION", "us-east-1")},
            )
            sid = s["id"]
            print(f"created BMA session {sid} (environment {s.get('environment', {}).get('id')})")
            print(f"next: attach the exec server on the exec host, then: export BREAKME_BMA_SESSION_ID={sid}")
        return cls(c, sid)

    def run(self, user_text: str, call_tool=None, timeout_s: int = 300) -> AgentRun:
        before = {it.get("id") for it in self.client.items(self.session_id)}
        self.client.submit(self.session_id, user_text)
        t0, status = time.time(), ""
        time.sleep(2)
        while time.time() - t0 < timeout_s:
            status = self.client.get(self.session_id).get("status", "")
            if status == "idle" or status in TERMINAL:
                break
            time.sleep(2)
        new = [it for it in self.client.items(self.session_id) if it.get("id") not in before]
        texts = [t for it in new for t in _texts(it)]
        final = texts[-1] if texts else f"(no assistant text; session status {status})"
        return AgentRun(final=final, steps=[{"bma_item": it} for it in new])
