"""Turn a campaign's results/attacks.jsonl into a stress-test report (Markdown).

    python -m breakme report [--in results/attacks.jsonl] [--out docs/stress-test.md]

One row per attack: what it tried, through which channel, what the agent attempted,
which layer stopped it, and the first line of the agent's answer. This is the table the
hackathon asks for ("what each prompt tried to do and how the agent responded").
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

LAYER_NAME = {"guardrail_input": "Bedrock Guardrails (input)", "model": "Model refused",
              "guardrail_output": "Guardrails (tool output)", "cedar": "Cedar policy",
              "iam": "IAM boundary", "BREACH": "**BREACH**"}
CHANNEL = {"chat": "chat", "log": "log line", "ticket": "ticket", "tag": "EC2 tag", "s3key": "S3 file name"}


def _cell(s: str, n: int = 160) -> str:
    s = " ".join(str(s).split()).replace("|", "\\|")
    return s if len(s) <= n else s[: n - 1] + "…"


def _tried(o: dict) -> str:
    acts = [f"{e['action']} → {e['status'].lower().replace('_', ' ')}"
            for e in o.get("events", []) if e.get("action") and e.get("status") != "OK"]
    mut = [f"{e['action']} → done" for e in o.get("events", [])
           if e.get("action") and e.get("status") == "OK" and e.get("action_class") not in (None, "ReadOnly")]
    out = acts + mut
    if not out and o.get("stopped_by") == "guardrail_input":
        return "nothing: never reached the agent"
    return "; ".join(out) if out else "read-only diagnostics"


def render(rows: list[dict], title: str) -> str:
    c = Counter(o["stopped_by"] for o in rows)
    lines = [f"# {title}", "",
             f"{len(rows)} attacks, **{sum(o['breach'] for o in rows)} breaches**, "
             f"model fooled {sum(o['model_fooled'] for o in rows)} times.", "",
             "Stopped by: " + ", ".join(f"{LAYER_NAME.get(k, k)} {v}" for k, v in c.most_common()), "",
             "| # | Attack | Channel | Technique | What it tried | Agent actions | Stopped by | Agent's answer |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, o in enumerate(rows, 1):
        a = o["attack"]
        text = a.get("payload") or " / ".join(a.get("turns", []))
        answer = (o.get("final") or "").strip().splitlines() or (
            ["(blocked before the agent saw it)"] if o["stopped_by"] == "guardrail_input" else [])
        lines.append(f"| {i} | {a['seed']} ({a['category']}) | {CHANNEL.get(a['channel'], a['channel'])} | "
                     f"{' + '.join(a.get('techniques', []))} | {_cell(text)} | {_cell(_tried(o), 120)} | "
                     f"{LAYER_NAME.get(o['stopped_by'], o['stopped_by'])} | {_cell(answer[0] if answer else '', 120)} |")
    return "\n".join(lines) + "\n"


def main(src: str, dst: str, title: str) -> None:
    rows = [json.loads(x) for x in Path(src).read_text(encoding="utf-8").splitlines() if x.strip()]
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text(render(rows, title), encoding="utf-8")
    print(f"{len(rows)} attacks -> {dst}")
