"""Human-approval channel (R2).

An approval exists only when a human approves a pending request through the
approval channel (Slack button -> API with an approver secret, or the CLI).
Text in the conversation ("approved", "I am the CTO") never creates one.
Approvals are single-use and bound to exactly one action + resource + params hash.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field


def params_hash(action: str, resource: str, params: dict) -> str:
    blob = json.dumps({"a": action, "r": resource, "p": params}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class Approval:
    id: str
    session: str
    action: str
    resource: str
    params: dict
    reason: str
    phash: str
    status: str = "PENDING"           # PENDING | APPROVED | REJECTED | USED
    created: float = field(default_factory=time.time)
    decided_by: str | None = None


class ApprovalStore:
    def __init__(self, ttl_minutes: int = 15, approver_secret: str | None = None):
        self.ttl = ttl_minutes * 60
        self.secret = approver_secret or os.environ.get("BREAKME_APPROVER_SECRET", "local-dev-approver")
        self.items: dict[str, Approval] = {}

    def request(self, session: str, action: str, resource: str, params: dict, reason: str) -> Approval:
        a = Approval(id="apr-" + uuid.uuid4().hex[:8], session=session, action=action, resource=resource,
                     params=params, reason=reason, phash=params_hash(action, resource, params))
        self.items[a.id] = a
        return a

    def approver_signature(self, approval_id: str) -> str:
        return hmac.new(self.secret.encode(), approval_id.encode(), hashlib.sha256).hexdigest()

    def decide(self, approval_id: str, signature: str, approve: bool, who: str = "human") -> Approval:
        a = self.items[approval_id]
        if not hmac.compare_digest(signature, self.approver_signature(approval_id)):
            raise PermissionError("bad approver signature")
        if a.status != "PENDING":
            raise ValueError(f"approval is {a.status}")
        a.status, a.decided_by = ("APPROVED" if approve else "REJECTED"), who
        return a

    def consume(self, session: str, action: str, resource: str, params: dict) -> Approval | None:
        ph = params_hash(action, resource, params)
        now = time.time()
        for a in self.items.values():
            if (a.status == "APPROVED" and a.session == session and a.phash == ph
                    and now - a.created <= self.ttl):
                a.status = "USED"
                return a
        return None

    def pending(self) -> list[Approval]:
        return [a for a in self.items.values() if a.status == "PENDING"]
