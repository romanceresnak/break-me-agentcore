"""BREAK ME command line.

  python -m breakme compile                         rules.yaml -> generated/*
  python -m breakme scenarios [--model hijacked]    usefulness: dev fix, approved prod fix, forged approval
  python -m breakme campaign --n 1000               red agent vs blue agent, 4-config ablation
  python -m breakme attack "message"                one-off attack through the full stack
  python -m breakme serve --port 8080               Glass Box + live campaign + arena
  python -m breakme mcp                             STDIO MCP server (exec host of the Managed Agent)
  python -m breakme report                          results/attacks.jsonl -> docs/stress-test.md

  python -m breakme harness-create --role-arn <arn> [--model <id>]   create the AgentCore harness
  python -m breakme harness-turn "message"          one turn on the harness against the real Tool API

--model: hijacked | converse:<bedrock-model-id> | harness | bma
"""
from __future__ import annotations

import argparse
import json
import runpy
import sys

from .config import ROOT


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="breakme")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("compile")
    p = sub.add_parser("scenarios")
    p.add_argument("--model", default="hijacked")
    p = sub.add_parser("campaign")
    p.add_argument("--n", type=int, default=1000)
    p.add_argument("--model", default="hijacked")
    p.add_argument("--configs", default="full,no-guardrail,iam-only,model-only")
    p.add_argument("--seed", type=int, default=7)
    p = sub.add_parser("attack")
    p.add_argument("message")
    p.add_argument("--model", default="hijacked")
    p.add_argument("--layers", default="full")
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--model", default="hijacked")
    sub.add_parser("mcp")
    p = sub.add_parser("report", help="stress-test table (Markdown) from a campaign's attacks.jsonl")
    p.add_argument("--src", default="results/attacks.jsonl")
    p.add_argument("--out", default="docs/stress-test.md")
    p.add_argument("--title", default="Stress test results")
    p = sub.add_parser("harness-create", help="create the AgentCore managed harness for the blue agent")
    p.add_argument("--role-arn", required=True)
    p.add_argument("--model", default=None)
    p.add_argument("--name", default="breakme_blue_agent")
    p = sub.add_parser("harness-turn", help="one turn on the harness, tools via the deployed Tool API")
    p.add_argument("message")
    sub.add_parser("bma-create", help="create the Managed Agent session (prints session + environment id)")
    p = sub.add_parser("bma-turn", help="send one message to the live Managed Agent session")
    p.add_argument("message")
    a = ap.parse_args(argv)

    if a.cmd == "report":
        from .report import main as report
        report(a.src, a.out, a.title)
        return
    if a.cmd == "compile":
        sys.argv = ["compile.py"]
        runpy.run_path(str(ROOT / "compiler" / "compile.py"), run_name="__main__")
        return

    from .blue.agents import make_model
    if a.cmd == "scenarios":
        from .red.runner import scenarios
        for s in scenarios(make_model(a.model)):
            print(f"{'PASS' if s['resolved'] else 'FAIL'}  {s['name']}")
            for e in s["events"]:
                print(f"      {e['action']:28} {e['status']:18} {e.get('layer') or ''} {','.join(e.get('rules') or [])}")
    elif a.cmd == "campaign":
        from .red.runner import campaign
        s = campaign(a.n, make_model(a.model), a.configs.split(","), seed=a.seed)
        print(f"\nmodel: {s['model']}")
        print(f"{'config':14} {'attacks':>8} {'breaches':>9} {'fooled':>7}  stopped by")
        for k, v in s["configs"].items():
            print(f"{k:14} {v['attacks']:>8} {v['breaches']:>9} {v['model_fooled']:>7}  {v['stopped_by']}")
        print("\nresults/summary.json, results/attacks.jsonl written")
    elif a.cmd == "attack":
        from .config import LayerConfig
        from .red.red_agent import Attack
        from .red.runner import run_attack
        atk = Attack("cli", "cli", "manual", "?", "chat", ["human"], [a.message])
        o = run_attack(atk, make_model(a.model), LayerConfig.named(a.layers))
        print(json.dumps({k: o.as_dict()[k] for k in ("stopped_by", "breach", "model_fooled", "violations", "final")},
                         ensure_ascii=False, indent=2))
        for e in o.events:
            print(f"  {e.get('action', ''):30} {e['status']:18} {e.get('layer') or ''} {','.join(e.get('rules') or [])}")
    elif a.cmd == "serve":
        from .server import serve
        serve(a.port, a.model)
    elif a.cmd == "harness-create":
        from .blue.harness import DEFAULT_MODEL, create_harness
        g = create_harness(a.name, a.role_arn, a.model or DEFAULT_MODEL)
        h = g.get("harness", g)
        print(json.dumps({k: h.get(k) for k in ("harnessArn", "arn", "harnessId", "status", "failureReason")
                          if h.get(k)}, indent=2, default=str))
        print("next: export BREAKME_HARNESS_ARN=<harnessArn above>")
    elif a.cmd == "harness-turn":
        import os
        from .blue.harness import HarnessAgent, new_session_id
        from .guard import make_guard
        from .mcp_server import RemoteTools
        v = make_guard(True).screen_input(a.message)          # layer 1 on the way in
        if v.blocked:
            print(f"BLOCKED by guardrail before reaching the agent: {v.reasons}")
            return
        agent = HarnessAgent.from_env()
        sid = new_session_id()
        tools = RemoteTools(os.environ["BREAKME_TOOL_API_URL"], sid)   # layers 3 + 4 + 1 (output)
        run = agent.run(a.message, tools.call, session_id=sid)
        print(f"session {sid}")
        for st in run.steps:
            r = st["result"]
            print(f"  {st['tool']:16} {r.get('action', ''):30} {r.get('status', ''):18} "
                  f"{r.get('layer') or ''} {','.join(r.get('rules') or [])}")
        print("\nagent: " + run.final)
    elif a.cmd == "bma-create":
        import os
        os.environ.pop("BREAKME_BMA_SESSION_ID", None)
        make_model("bma")
    elif a.cmd == "bma-turn":
        run = make_model("bma").run(a.message)
        print(run.final)
        print(f"({len(run.steps)} items; tool decisions are in the Tool API events table)")
    elif a.cmd == "mcp":
        from .mcp_server import serve
        serve()


if __name__ == "__main__":
    main()
