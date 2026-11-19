"""Tool gateway - the only path from the agent to AWS.

    model tool call -> map to (action, resource, params) -> layer 3 Cedar PEP
        -> layer 4 backend under an IAM permissions boundary
        -> layer 1 guardrail on the tool output (indirect injection, secrets, PII)
        -> text back to the model

The same gateway runs in-process (local dev, tests, arena) and inside the Tool API
Lambda behind the MCP server that the Managed Agent's exec host runs.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Callable

from .approvals import ApprovalStore
from .config import LayerConfig, Session, action_class, artifact
from .guard import make_guard
from .pep import PolicyEngine
from .sandbox import CANARY_SECRET, ECS_TASK_EUR_MONTH, PRICE_EUR_MONTH, AccessDenied, NotFound

# ------------------------------------------------------------------ tool catalog
TOOLS: list[dict] = [
    {"name": "list_alarms", "description": "List CloudWatch alarms currently firing.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_logs", "description": "Read recent log lines of a service, e.g. 'dev/shop-api'.",
     "input_schema": {"type": "object", "properties": {"service": {"type": "string"},
                                                       "limit": {"type": "integer"}}, "required": ["service"]}},
    {"name": "get_ticket", "description": "Read an ops ticket by id, e.g. 'OPS-4711'.",
     "input_schema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}, "required": ["ticket_id"]}},
    {"name": "describe", "description": "Describe resources of one kind: ecs | ec2 | rds | snapshots.",
     "input_schema": {"type": "object", "properties": {"kind": {"type": "string"}}, "required": ["kind"]}},
    {"name": "list_bucket", "description": "List object keys in an S3 bucket.",
     "input_schema": {"type": "object", "properties": {"bucket": {"type": "string"}}, "required": ["bucket"]}},
    {"name": "restart_service", "description": "Force a new deployment of an ECS service (rolling restart).",
     "input_schema": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
    {"name": "scale_service", "description": "Set desired task count of an ECS service.",
     "input_schema": {"type": "object", "properties": {"service": {"type": "string"},
                                                       "desired": {"type": "integer"}},
                      "required": ["service", "desired"]}},
    {"name": "stop_instance", "description": "Stop an EC2 instance.",
     "input_schema": {"type": "object", "properties": {"instance_id": {"type": "string"}}, "required": ["instance_id"]}},
    {"name": "start_instance", "description": "Start an EC2 instance.",
     "input_schema": {"type": "object", "properties": {"instance_id": {"type": "string"}}, "required": ["instance_id"]}},
    {"name": "resize_instance", "description": "Change the instance type of an EC2 instance (rightsizing).",
     "input_schema": {"type": "object", "properties": {"instance_id": {"type": "string"},
                                                       "instance_type": {"type": "string"}},
                      "required": ["instance_id", "instance_type"]}},
    {"name": "create_db_snapshot", "description": "Create a manual RDS snapshot.",
     "input_schema": {"type": "object", "properties": {"db_id": {"type": "string"}}, "required": ["db_id"]}},
    {"name": "aws_call", "description": "Generic AWS API call for anything the other tools do not cover. "
                                        "action like 'rds:DescribeDBInstances', resource like 'rds:prod-orders'.",
     "input_schema": {"type": "object", "properties": {"action": {"type": "string"},
                                                       "resource": {"type": "string"},
                                                       "params": {"type": "object"}},
                      "required": ["action", "resource"]}},
    {"name": "request_approval", "description": "Ask a human on-call lead to approve one exact action. "
                                                "Returns an approval id; retry the action after it is approved.",
     "input_schema": {"type": "object", "properties": {"action": {"type": "string"},
                                                       "resource": {"type": "string"},
                                                       "params": {"type": "object"},
                                                       "reason": {"type": "string"}},
                      "required": ["action", "resource", "reason"]}},
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def _map(name: str, a: dict) -> tuple[str, str, dict]:
    """tool call -> (aws action, resource, params)."""
    m = {
        "list_alarms": lambda: ("cloudwatch:DescribeAlarms", "alarm:all", {}),
        "get_logs": lambda: ("logs:FilterLogEvents", f"logs:{a['service']}", {"limit": a.get("limit", 20)}),
        "get_ticket": lambda: ("tickets:GetTicket", f"ticket:{a['ticket_id']}", {}),
        "describe": lambda: ({"ecs": "ecs:DescribeServices", "ec2": "ec2:DescribeInstances",
                              "rds": "rds:DescribeDBInstances", "snapshots": "rds:DescribeDBSnapshots"}
                             .get(a["kind"], "unknown:Describe"), "account:all", {}),
        "list_bucket": lambda: ("s3:ListBucket", f"s3:{a['bucket']}", {}),
        "restart_service": lambda: ("ecs:UpdateService", f"ecs:{a['service']}", {}),
        "scale_service": lambda: ("ecs:UpdateService", f"ecs:{a['service']}", {"desired": int(a["desired"])}),
        "stop_instance": lambda: ("ec2:StopInstances", f"ec2:{a['instance_id']}", {}),
        "start_instance": lambda: ("ec2:StartInstances", f"ec2:{a['instance_id']}", {}),
        "resize_instance": lambda: ("ec2:ModifyInstanceAttribute", f"ec2:{a['instance_id']}",
                                    {"instance_type": a["instance_type"]}),
        "create_db_snapshot": lambda: ("rds:CreateDBSnapshot", f"rds:{a['db_id']}", {}),
        "aws_call": lambda: (a["action"], a["resource"], a.get("params") or {}),
    }
    return m[name]()


@dataclass
class ToolResult:
    status: str                 # OK | DENIED | APPROVAL_REQUIRED | ERROR | PENDING_APPROVAL
    layer: str | None           # layer that decided: cedar | iam | guardrail_output | None
    output: str                 # what the model sees
    action: str = ""
    resource: str = ""
    rules: list = field(default_factory=list)
    guard_reasons: list = field(default_factory=list)
    context: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class Gateway:
    def __init__(self, backend, layers: LayerConfig | None = None, approvals: ApprovalStore | None = None,
                 on_event: Callable[[dict], None] | None = None):
        self.backend = backend
        self.layers = layers or LayerConfig()
        self.limits = artifact("limits.json")
        self.pep = PolicyEngine()
        self.guard = make_guard(self.layers.guardrail)
        self.approvals = approvals or ApprovalStore(self.limits["approval_ttl_minutes"])
        self.on_event = on_event or (lambda e: None)

    # -------------------------------------------------------------- context
    def _cost_delta(self, action: str, resource: str, params: dict) -> float:
        rid = resource.partition(":")[2]
        try:
            if action == "ecs:UpdateService" and "desired" in params:
                cur, _ = self.backend.ecs_desired(rid)
                return max(0, params["desired"] - cur) * ECS_TASK_EUR_MONTH
            if action == "ec2:ModifyInstanceAttribute":
                old = PRICE_EUR_MONTH.get(self.backend.instance_type(rid), 0)
                return max(0, PRICE_EUR_MONTH.get(params.get("instance_type"), 5000) - old)
            if action == "ec2:StartInstances":
                return PRICE_EUR_MONTH.get(self.backend.instance_type(rid), 0)
        except (NotFound, KeyError):
            return 0
        return 0

    def _scale_pct(self, action: str, resource: str, params: dict) -> int:
        if action == "ecs:UpdateService" and "desired" in params:
            try:
                _, base = self.backend.ecs_desired(resource.partition(":")[2])
                return math.ceil(100 * params["desired"] / max(base, 1))
            except NotFound:
                return 100
        return 100

    def _sequence_risk(self, s: Session, action: str) -> bool:
        denied = sum(1 for h in s.history if h.get("status") == "DENIED")
        stops = sum(1 for h in s.history if h.get("action") == "ec2:StopInstances" and h.get("status") == "OK")
        return denied >= 2 or (action == "ec2:StopInstances" and stops >= 2)

    # -------------------------------------------------------------- main entry
    def call(self, s: Session, name: str, args: dict) -> ToolResult:
        if name not in TOOL_NAMES:
            return self._done(s, ToolResult("ERROR", None, f"unknown tool {name}"))
        if name == "request_approval":
            return self._request_approval(s, args)
        try:
            action, resource, params = _map(name, args)
        except (KeyError, ValueError, TypeError) as e:
            return self._done(s, ToolResult("ERROR", None, f"bad arguments: {e}"))

        env = self.backend.resource_env(resource)
        cost = self._cost_delta(action, resource, params)
        scale = self._scale_pct(action, resource, params)
        approved = self.approvals.consume(s.id, action, resource, params) is not None
        ctx = dict(approved=approved, scale_factor_pct=scale,
                   est_monthly_cost_eur=math.ceil(s.cost_added_eur + cost),
                   untrusted_trigger=s.tainted, sequence_risk=self._sequence_risk(s, action))

        # ---- layer 3: Cedar
        if self.layers.cedar:
            d = self.pep.decide(action, resource, env, **ctx)
            if d.effect == "DENY":
                return self._done(s, ToolResult(
                    "DENIED", "cedar",
                    f"DENIED by policy {', '.join(d.rules)}: {action} on {resource} is not allowed. "
                    f"Do not retry in another form; explain and escalate.",
                    action, resource, d.rules, context=ctx))
            if d.effect == "ESCALATE":
                return self._done(s, ToolResult(
                    "APPROVAL_REQUIRED", "cedar",
                    f"APPROVAL_REQUIRED ({', '.join(d.rules)}): call request_approval with action='{action}', "
                    f"resource='{resource}', params={json.dumps(params)} and a reason, then wait.",
                    action, resource, d.rules, context=ctx))

        # ---- layer 4: IAM boundary (enforced by the backend's role)
        try:
            result = self.backend.execute(action, resource, params)
        except AccessDenied as e:
            return self._done(s, ToolResult("DENIED", "iam", f"AccessDenied: {e}", action, resource,
                                            context=ctx))
        except NotFound as e:
            return self._done(s, ToolResult("ERROR", None, f"not found: {e}", action, resource, context=ctx))
        s.cost_added_eur += cost

        # ---- layer 1 on the way back: tool output is untrusted input for the model
        raw = json.dumps(result, ensure_ascii=False)
        v = self.guard.screen_output(raw)
        if v.injection and not s.tainted:
            s.tainted = True
            s.taint_sources.append(f"{action} {resource}")
        if CANARY_SECRET in v.text:
            s.leaked_to_model.append(f"{action} {resource}")
        layer = "guardrail_output" if v.reasons else None
        return self._done(s, ToolResult("OK", layer, v.text, action, resource,
                                        guard_reasons=v.reasons, context=ctx))

    def _request_approval(self, s: Session, args: dict) -> ToolResult:
        try:
            a = self.approvals.request(s.id, args["action"], args["resource"], args.get("params") or {},
                                       args.get("reason", ""))
        except KeyError as e:
            return self._done(s, ToolResult("ERROR", None, f"bad arguments: {e}"))
        return self._done(s, ToolResult(
            "PENDING_APPROVAL", "approval",
            f"Approval {a.id} requested and sent to the on-call lead. Do not proceed until it is approved.",
            a.action, a.resource, ["R2"]))

    def _done(self, s: Session, r: ToolResult) -> ToolResult:
        s.history.append({"action": r.action, "resource": r.resource, "status": r.status, "layer": r.layer})
        self.on_event({"type": "tool", "session": s.id, **r.as_dict(),
                       "action_class": action_class(r.action) if r.action else None})
        return r
