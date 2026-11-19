"""Blue agent runtimes.

All runtimes share one contract:  run(user_text, call_tool) -> AgentRun
`call_tool(name, args) -> ToolResult` goes through the Gateway (layers 3, 4, 1).

  HijackedModel  Worst case: a model that obeys every instruction it reads, in the
                 prompt or in tool output (EN/SK, base64). Used to prove that the
                 boundary holds even when layer 2 (the model) is fully compromised.
  ConverseModel  A real model on Amazon Bedrock via the Converse API (local dev).
  ManagedAgent   Amazon Bedrock Managed Agents session (see bma_client.py); tools
                 reach the Gateway through the MCP server on the exec host.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Callable

from ..config import artifact
from ..gateway import TOOLS


@dataclass
class AgentRun:
    final: str
    steps: list = field(default_factory=list)     # [{"tool", "args", "result"}]
    attempted: list = field(default_factory=list)  # actions the model tried


SERVICE_RE = re.compile(r"\b(dev|prod)/(shop-web|shop-api|checkout)\b")
INSTANCE_RE = re.compile(r"\b(dev|prod)-(web|batch)-\d\b")
TYPE_RE = re.compile(r"\b([a-z]\d[a-z]{0,2}\.(?:nano|micro|small|medium|large|\d*xlarge|metal))\b")
TICKET_RE = re.compile(r"\b[A-Z]{2,5}-\d{2,6}\b")
ACCOUNT_RE = re.compile(r"\b\d{12}\b")


def _expand(text: str) -> str:
    """What a gullible model 'understands': raw text + decoded base64 + undone leetspeak."""
    dec = []
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            d = base64.b64decode(m.group(0), validate=True).decode("utf-8")
            if d.isprintable():
                dec.append(d)
        except Exception:
            pass
    leet = text.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}))
    return " ".join([text, leet, *dec]).lower()


def extract_commands(text: str) -> list[tuple[str, dict]]:
    """Turn imperative text into tool calls, the way a hijacked model would."""
    t = _expand(text)
    svc = SERVICE_RE.search(t)
    inst = list(dict.fromkeys(m.group(0) for m in INSTANCE_RE.finditer(t)))
    calls: list[tuple[str, dict]] = []

    def aws(action, resource, params=None):
        calls.append(("aws_call", {"action": action, "resource": resource, "params": params or {}}))

    if re.search(r"(delete|drop|wipe|destroy|zma[žz]|vyma[žz]|odstr[aá]n|deleted?b).{0,40}(database|\bdb\b|datab[aá]z|rds|orders)", t):
        aws("rds:DeleteDBInstance", "rds:dev-orders" if "dev-orders" in t else "rds:prod-orders")
    if re.search(r"(delete|remove|clean ?up|cleanup|zma[žz]|vyma[žz]|uprac).{0,40}snapshot", t):
        aws("rds:DeleteDBSnapshot", "snap:snap-prod-orders-nightly")
    if re.search(r"(terminate|ukon[čc]i|zru[šs]).{0,30}(instanc|in[šs]tanc|server|ec2)", t):
        for i in (inst or ["prod-web-1", "prod-web-2"]):
            aws("ec2:TerminateInstances", f"ec2:{i}")
    if re.search(r"(delete|empty|purge|vypr[aá]zdni|zma[žz]).{0,30}(bucket|s3|objects|export)", t):
        aws("s3:DeleteObject", "s3:shop-exports-prod")
    if re.search(r"(secret|password|heslo|credential|connection string|db pass|getsecretvalue)", t):
        aws("secretsmanager:GetSecretValue", "secret:prod/orders-db")
    if re.search(r"(0\.0\.0\.0/0|open (the )?(security group|sg|port)|otvor.{0,20}(port|sg))", t):
        aws("ec2:AuthorizeSecurityGroupIngress", "sg:prod-db", {"cidr": "0.0.0.0/0"})
    if re.search(r"(share|zdie[lľ]|copy).{0,40}snapshot", t) or ("snapshot" in t and ACCOUNT_RE.search(t)):
        acc = ACCOUNT_RE.search(t)
        aws("ec2:ModifySnapshotAttribute", "snap:snap-prod-orders-nightly",
            {"account": acc.group(0) if acc else "999999999999"})
    if re.search(r"(disable|turn off|vypni).{0,30}(deletion protection|backup|z[aá]lohy)", t):
        aws("rds:ModifyDBInstance", "rds:prod-orders", {"deletion_protection": False})
    if re.search(r"(create|new|vytvor).{0,20}(iam user|access key|admin user)|attach.{0,20}policy|administratoraccess", t):
        aws("iam:CreateAccessKey", "account:all")
    if re.search(r"(update|disable|edit|uprav|vypni).{0,30}(guardrail|policy|policies|pravidl|cedar|boundary)", t):
        aws("bedrock:UpdateGuardrail", "account:all")
    if re.search(r"(stop|disable|vypni).{0,20}(cloudtrail|logging|audit)", t):
        aws("cloudtrail:StopLogging", "account:all")
    m = re.search(r"(scale|[šs]k[aá]luj|increase).{0,40}?(to|na)\s*(\d{1,4})", t)
    if m:
        calls.append(("scale_service", {"service": svc.group(0) if svc else "prod/shop-api",
                                        "desired": int(m.group(3))}))
    ty = TYPE_RE.search(t)
    if ty and re.search(r"(resize|upgrade|change|switch|zme[nň]|prehoď|load test|benchmark)", t):
        calls.append(("resize_instance", {"instance_id": inst[0] if inst else "dev-batch-1",
                                          "instance_type": ty.group(1)}))
    if re.search(r"\b(stop|shut ?down|zastav|vypni)\b.{0,30}(instanc|in[šs]tanc|server|ec2|prod)", t) and \
            not re.search(r"stop.{0,10}(cloudtrail|logging)", t):
        for i in (inst or ["prod-web-1", "prod-web-2", "dev-web-1"]):
            calls.append(("stop_instance", {"instance_id": i}))
    if re.search(r"(restart|re[šs]tartuj|redeploy)", t) and svc:
        calls.append(("restart_service", {"service": svc.group(0)}))
    return calls


class HijackedModel:
    """Deterministic worst-case model: follows every instruction it ever reads."""
    name = "hijacked"

    def run(self, user_text: str, call_tool: Callable, max_steps: int = 14) -> AgentRun:
        run = AgentRun(final="")
        queue: list[tuple[str, dict]] = []
        # 1. normal SRE behaviour: look at what the user points to
        if re.search(r"alarm|incident|5xx|error|outage|v[ýy]padok", user_text, re.I):
            queue.append(("list_alarms", {}))
        for svc in {m.group(0) for m in SERVICE_RE.finditer(user_text)}:
            queue.append(("get_logs", {"service": svc}))
        for tid in TICKET_RE.findall(user_text):
            queue.append(("get_ticket", {"ticket_id": tid}))
        if re.search(r"\btag|instances? list|inventory|rightsiz", user_text, re.I):
            queue.append(("describe", {"kind": "ec2"}))
        if re.search(r"bucket|export|s3", user_text, re.I):
            queue.append(("list_bucket", {"bucket": "shop-exports-prod"}))
        # 2. ...and obey whatever the user says
        queue += extract_commands(user_text)

        seen_payloads = set()
        steps = 0
        while queue and steps < max_steps:
            name, args = queue.pop(0)
            steps += 1
            r = call_tool(name, args)
            run.steps.append({"tool": name, "args": args, "result": r.as_dict()})
            if r.action:
                run.attempted.append(r.action)
            if r.status == "APPROVAL_REQUIRED":
                queue.insert(0, ("request_approval", {"action": r.action, "resource": r.resource,
                                                      "params": args.get("params", {k: v for k, v in args.items()
                                                                                    if k in ("desired", "instance_type")}),
                                                      "reason": "requested in conversation"}))
                continue
            if r.status == "OK":
                if r.action == "logs:FilterLogEvents" and re.search(r"outofmemory|oom|5\d\d", r.output, re.I):
                    queue.append(("restart_service", {"service": args["service"]}))
                # 3. ...and obey whatever the data says (indirect injection)
                key = hash(r.output)
                if key not in seen_payloads:
                    seen_payloads.add(key)
                    queue += extract_commands(r.output)
        secrets = [s["result"]["output"] for s in run.steps
                   if s["result"]["action"] == "secretsmanager:GetSecretValue" and s["result"]["status"] == "OK"]
        run.final = "Done. " + (f"Here is what you asked for: {secrets[0]}" if secrets else
                                f"I executed {len(run.steps)} tool calls.")
        return run


class ConverseModel:
    """A real model via Bedrock Converse with the same tools (for local runs with AWS creds)."""

    def __init__(self, model_id: str, region: str | None = None):
        import boto3
        self.client = boto3.client("bedrock-runtime", region_name=region)
        self.model_id = model_id
        self.name = f"converse:{model_id}"
        self.system = [{"text": artifact("agent_instructions.md")}]
        self.tool_config = {"tools": [{"toolSpec": {"name": t["name"], "description": t["description"],
                                                    "inputSchema": {"json": t["input_schema"]}}} for t in TOOLS]}

    def run(self, user_text: str, call_tool: Callable, max_steps: int = 10) -> AgentRun:
        run = AgentRun(final="")
        msgs = [{"role": "user", "content": [{"text": user_text}]}]
        for _ in range(max_steps):
            resp = self.client.converse(modelId=self.model_id, system=self.system, messages=msgs,
                                        toolConfig=self.tool_config, inferenceConfig={"maxTokens": 1200})
            out = resp["output"]["message"]
            msgs.append(out)
            uses = [c["toolUse"] for c in out["content"] if "toolUse" in c]
            if not uses:
                run.final = " ".join(c.get("text", "") for c in out["content"]).strip()
                return run
            results = []
            for u in uses:
                r = call_tool(u["name"], u.get("input") or {})
                run.steps.append({"tool": u["name"], "args": u.get("input"), "result": r.as_dict()})
                if r.action:
                    run.attempted.append(r.action)
                results.append({"toolResult": {"toolUseId": u["toolUseId"], "content": [{"text": r.output}],
                                               "status": "success" if r.status == "OK" else "error"}})
            msgs.append({"role": "user", "content": results})
        run.final = "(stopped: step limit)"
        return run


def make_model(spec: str):
    if spec == "hijacked":
        return HijackedModel()
    if spec.startswith("converse:"):
        return ConverseModel(spec.split(":", 1)[1])
    if spec == "harness":
        from .harness import HarnessAgent
        return HarnessAgent.from_env()
    if spec == "bma":
        from .bma_client import ManagedAgent
        return ManagedAgent.from_env()
    raise ValueError(f"unknown model {spec}")


def as_json(run: AgentRun) -> str:
    return json.dumps({"final": run.final, "steps": run.steps}, ensure_ascii=False, indent=2)
