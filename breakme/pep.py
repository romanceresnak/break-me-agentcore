"""Layer 3 - Policy Enforcement Point (Cedar).

Every tool call is turned into a Cedar request:
  principal  BreakMe::Agent::"blue"
  action     BreakMe::Action::"<aws action>"   (parent = risk class from rules.yaml)
  resource   BreakMe::Resource::"<kind:id>"     attrs { env }
  context    { approved, scale_factor_pct, est_monthly_cost_eur, untrusted_trigger, sequence_risk }

Decision:
  ALLOW     a permit matched, no forbid matched
  ESCALATE  denied now, but would be allowed with a human approval (R2, R3, R4, R7, R8)
  DENY      denied even with approval (forbid matched or unknown action)

The same policies can be loaded into Amazon Verified Permissions or AgentCore Policy;
cedarpy evaluates them in-process so the PEP adds ~1 ms and has no network dependency.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import cedarpy

from .config import artifact

NS = "BreakMe"


@dataclass
class Decision:
    effect: str                       # ALLOW | ESCALATE | DENY
    rules: list = field(default_factory=list)
    reasons: list = field(default_factory=list)
    context: dict = field(default_factory=dict)


class PolicyEngine:
    def __init__(self):
        self.policies = artifact("policies.cedar")
        self.base_entities = artifact("cedar_entities.json")
        self.index = {p["policy_id"]: p for p in artifact("policy_index.json")["policies"]}

    def _eval(self, action: str, resource: str, env: str, ctx: dict):
        ents = self.base_entities + [{"uid": {"type": f"{NS}::Resource", "id": resource},
                                      "attrs": {"env": env}, "parents": []}]
        req = {"principal": f'{NS}::Agent::"blue"', "action": f'{NS}::Action::"{action}"',
               "resource": f'{NS}::Resource::"{resource}"', "context": ctx}
        return cedarpy.is_authorized(req, self.policies, ents)

    def decide(self, action: str, resource: str, env: str, *, approved: bool = False,
               scale_factor_pct: int = 100, est_monthly_cost_eur: int = 0,
               untrusted_trigger: bool = False, sequence_risk: bool = False) -> Decision:
        ctx = {"approved": approved, "scale_factor_pct": int(scale_factor_pct),
               "est_monthly_cost_eur": int(est_monthly_cost_eur),
               "untrusted_trigger": bool(untrusted_trigger), "sequence_risk": bool(sequence_risk)}
        r = self._eval(action, resource, env, ctx)
        rules = [self.index[p]["rule"] for p in r.diagnostics.reasons if p in self.index]
        if r.decision == cedarpy.Decision.Allow:
            return Decision("ALLOW", rules, [self.index[p]["effect"] for p in r.diagnostics.reasons], ctx)
        if rules:  # a forbid matched -> hard deny
            return Decision("DENY", rules, [self.index[p]["effect"] for p in r.diagnostics.reasons], ctx)
        if not approved:
            r2 = self._eval(action, resource, env, {**ctx, "approved": True})
            if r2.decision == cedarpy.Decision.Allow:
                why = []
                if env == "prod":
                    why.append("R2")
                if scale_factor_pct > 200:
                    why.append("R3")
                if est_monthly_cost_eur > 50:
                    why.append("R4")
                if untrusted_trigger:
                    why.append("R7")
                if sequence_risk:
                    why.append("R8")
                return Decision("ESCALATE", why or ["R2"], ["needs human approval"], ctx)
        return Decision("DENY", ["DEFAULT_DENY"], ["no permit matched (unknown or out-of-scope action)"], ctx)
