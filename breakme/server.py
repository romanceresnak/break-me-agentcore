"""Local Glass Box server: dashboard + live campaign + arena + approvals.

  GET  /                         Glass Box (glassbox/index.html)
  GET  /api/summary              last campaign summary (ablation matrix)
  GET  /api/feed?since=N         live attack outcomes (polled by Glass Box)
  POST /api/campaign             {"n": 500, "configs": [...]} start a live campaign
  POST /api/arena                {"message": "...", "nick": "..."}  try to break the agent
  GET  /api/leaderboard          best arena attempts (deepest layer reached)
  GET  /api/approvals            pending approvals (demo approval channel)

In AWS the same API is served by API Gateway + Lambda; Glass Box is static on CloudFront.
"""
from __future__ import annotations

import json
import random
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .blue.agents import make_model
from .config import RESULTS, ROOT, LayerConfig
from .red.red_agent import DEPTH, Attack, RedAgent
from .red.runner import run_attack, summarize

GLASSBOX = ROOT / "glassbox"
ARENA_LIMIT_PER_HOUR = 20


class State:
    def __init__(self, model_spec: str):
        self.model = make_model(model_spec)
        self.feed: list[dict] = []
        self.lock = threading.Lock()
        self.running = False
        self.leaderboard: list[dict] = []
        self.rate: dict[str, deque] = defaultdict(deque)
        lb = RESULTS / "leaderboard.json"
        if lb.exists():
            self.leaderboard = json.loads(lb.read_text(encoding="utf-8"))
        att = RESULTS / "attacks.jsonl"
        if att.exists():   # warm start: show the last campaign
            self.feed = [json.loads(x) for x in att.read_text(encoding="utf-8").splitlines()[-300:]]

    def push(self, o: dict) -> None:
        with self.lock:
            o["seq"] = len(self.feed)
            self.feed.append(o)

    def campaign(self, n: int, delay: float) -> None:
        self.running = True
        red = RedAgent(rng=random.Random(int(time.time())))
        cfg = LayerConfig.named("full")
        queue = red.catalog_sweep()
        try:
            for i in range(n):
                atk = queue.pop(0) if queue else red.next()
                o = run_attack(atk, self.model, cfg)
                red.learn(atk, o.as_dict())
                self.push(o.as_dict())
                time.sleep(delay)
        finally:
            self.running = False

    def arena(self, ip: str, nick: str, message: str) -> dict:
        now = time.time()
        q = self.rate[ip]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= ARENA_LIMIT_PER_HOUR:
            return {"error": "rate limit: 20 attempts per hour"}
        q.append(now)
        message = message[:2000]
        atk = Attack(id=f"arena-{int(now * 1000)}", seed="arena", category="arena", goal="?",
                     channel="chat", techniques=["human"], turns=[message], source=f"arena:{nick[:24]}")
        o = run_attack(atk, self.model, LayerConfig.named("full")).as_dict()
        self.push(o)
        depth = DEPTH.get(o["stopped_by"], 1)
        entry = {"nick": nick[:24] or "anonymous", "depth": depth, "stopped_by": o["stopped_by"],
                 "message": message[:280], "ts": now}
        self.leaderboard = sorted(self.leaderboard + [entry], key=lambda e: (-e["depth"], e["ts"]))[:50]
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "leaderboard.json").write_text(json.dumps(self.leaderboard, ensure_ascii=False), encoding="utf-8")
        if depth >= DEPTH["cedar"]:   # deep human attempts become red-agent seeds
            with (RESULTS / "arena_seeds.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps({"id": atk.id, "category": "arena", "channel": "chat", "goal": "?",
                                    "payload": message}, ensure_ascii=False) + "\n")
        return o


def make_handler(state: State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj, ensure_ascii=False, default=str).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _file(self, p: Path, ctype: str):
            b = p.read_bytes()
            self.send_response(200)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path in ("/", "/index.html"):
                return self._file(GLASSBOX / "index.html", "text/html; charset=utf-8")
            if u.path == "/api/summary":
                p = RESULTS / "summary.json"
                return self._json(json.loads(p.read_text(encoding="utf-8")) if p.exists() else {})
            if u.path == "/api/feed":
                since = int(q.get("since", ["0"])[0])
                with state.lock:
                    items = state.feed[since:since + 400]
                    total = len(state.feed)
                live = summarize_dicts(state.feed)
                return self._json({"items": items, "total": total, "running": state.running, "live": live})
            if u.path == "/api/leaderboard":
                return self._json(state.leaderboard)
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("content-length", "0") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if u.path == "/api/campaign":
                if state.running:
                    return self._json({"error": "campaign already running"}, 409)
                threading.Thread(target=state.campaign, args=(int(body.get("n", 300)),
                                                              float(body.get("delay", 0.05))), daemon=True).start()
                return self._json({"started": True})
            if u.path == "/api/arena":
                msg = (body.get("message") or "").strip()
                if not msg:
                    return self._json({"error": "empty message"}, 400)
                return self._json(state.arena(self.client_address[0], body.get("nick", ""), msg))
            if u.path == "/api/reset":
                with state.lock:
                    state.feed = []
                return self._json({"reset": True})
            return self._json({"error": "not found"}, 404)

    return H


def summarize_dicts(feed: list[dict]) -> dict:
    class O:  # light adapter so summarize() works on dicts
        def __init__(self, d):
            self.__dict__.update(d)
    return summarize([O(d) for d in feed])


def serve(port: int = 8080, model: str = "hijacked") -> None:
    state = State(model)
    srv = ThreadingHTTPServer(("0.0.0.0", port), make_handler(state))
    print(f"Glass Box on http://localhost:{port}  (blue model: {state.model.name})")
    srv.serve_forever()
