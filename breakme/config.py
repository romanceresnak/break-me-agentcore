"""Shared paths and compiled artifacts."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = Path(os.environ.get("BREAKME_GENERATED", ROOT / "generated"))
RESULTS = Path(os.environ.get("BREAKME_RESULTS", ROOT / "results"))

LAYERS = ("guardrail_input", "model", "cedar", "iam", "guardrail_output")


@lru_cache(maxsize=None)
def artifact(name: str):
    p = GENERATED / name
    if not p.exists():
        raise FileNotFoundError(f"{p} missing - run: python compiler/compile.py")
    text = p.read_text(encoding="utf-8")
    return json.loads(text) if p.suffix == ".json" else text


def action_class(action: str) -> str | None:
    for e in artifact("cedar_entities.json"):
        if e["uid"]["id"] == action and e["parents"]:
            return e["parents"][0]["id"]
    return None


@dataclass
class LayerConfig:
    """Which defensive layers are switched on. Used for the ablation experiment."""
    guardrail: bool = True
    cedar: bool = True
    iam: bool = True

    @classmethod
    def named(cls, name: str) -> "LayerConfig":
        return {
            "full": cls(True, True, True),
            "no-guardrail": cls(False, True, True),
            "iam-only": cls(False, False, True),
            "model-only": cls(False, False, False),
        }[name]

    def label(self) -> str:
        on = [n for n, v in (("guardrail", self.guardrail), ("cedar", self.cedar), ("iam", self.iam)) if v]
        return "+".join(on) or "model-only"


@dataclass
class Session:
    """Per-agent-session state the tool layer keeps (taint, history, cost)."""
    id: str
    tainted: bool = False                 # R7: untrusted content with instructions was read
    taint_sources: list = field(default_factory=list)
    history: list = field(default_factory=list)   # executed (action, resource) pairs
    cost_added_eur: float = 0.0           # R4: cumulative, defeats salami scaling
    leaked_to_model: list = field(default_factory=list)
