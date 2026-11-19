"""Public arena + Glass Box API Lambda (deployed behind CloudFront at /api/*).

The arena never touches the real sandbox: each attempt runs against a fresh in-memory
copy of the shop with the real Bedrock Guardrail, the compiled Cedar policies and the
simulated permissions boundary, with the hijacked (worst-case) model. Results, feed and
leaderboard live in S3; per-IP rate limits in DynamoDB.

  GET  /api/feed?since=N    GET /api/summary    GET /api/leaderboard
  POST /api/arena {message, nick}               POST /api/campaign {n<=40}
"""
from __future__ import annotations

import json
import os
import random
import time

import boto3

from .blue.agents import HijackedModel
from .config import LayerConfig
from .red.red_agent import DEPTH, Attack, RedAgent
from .red.runner import run_attack
from .server import summarize_dicts

S3 = boto3.client("s3")
BUCKET = os.environ.get("BREAKME_ARENA_BUCKET", "")
RATE = boto3.resource("dynamodb").Table(os.environ.get("BREAKME_RATE_TABLE", "break-me-arena-rate"))
MODEL = HijackedModel()
FEED_MAX = 2000


def _get(key: str, default):
    try:
        return json.loads(S3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except S3.exceptions.NoSuchKey:
        return default


def _put(key: str, obj) -> None:
    S3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(obj, ensure_ascii=False, default=str).encode(),
                  ContentType="application/json")


def _resp(code: int, body) -> dict:
    return {"statusCode": code, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, ensure_ascii=False, default=str)}


def _rate_ok(ip: str, limit: int = 20) -> bool:
    hour = int(time.time() // 3600)
    r = RATE.update_item(Key={"id": f"{ip}#{hour}"}, UpdateExpression="ADD n :one SET expires_at = :exp",
                         ExpressionAttributeValues={":one": 1, ":exp": (hour + 2) * 3600}, ReturnValues="UPDATED_NEW")
    return int(r["Attributes"]["n"]) <= limit


def _append(items: list[dict]) -> None:
    feed = _get("feed.json", [])
    nxt = feed[-1]["seq"] + 1 if feed else 0
    for o in items:
        o["seq"] = nxt
        nxt += 1
        feed.append(o)
    _put("feed.json", feed[-FEED_MAX:])


def handler(event, _ctx):
    method = event["requestContext"]["http"]["method"]
    path = event.get("rawPath", "")
    ip = event["requestContext"]["http"].get("sourceIp", "?")
    body = json.loads(event.get("body") or "{}")

    if method == "GET" and path == "/api/feed":
        since = int((event.get("queryStringParameters") or {}).get("since", 0))
        feed = _get("feed.json", [])
        items = [o for o in feed if o["seq"] >= since][:400]
        total = items[-1]["seq"] + 1 if items else (feed[-1]["seq"] + 1 if feed else 0)
        return _resp(200, {"items": items, "total": total, "running": False,
                           "live": summarize_dicts(feed)})
    if method == "GET" and path == "/api/summary":
        return _resp(200, _get("summary.json", {}))
    if method == "GET" and path == "/api/leaderboard":
        return _resp(200, _get("leaderboard.json", []))

    if method == "POST" and path == "/api/arena":
        msg = (body.get("message") or "").strip()[:2000]
        if not msg:
            return _resp(400, {"error": "Write an attack first."})
        if not _rate_ok(ip):
            return _resp(429, {"error": "rate limit: 20 attempts per hour"})
        nick = (body.get("nick") or "anonymous")[:24]
        atk = Attack(f"arena-{int(time.time() * 1000)}", "arena", "arena", "?", "chat", ["human"], [msg],
                     source=f"arena:{nick}")
        o = run_attack(atk, MODEL, LayerConfig.named("full")).as_dict()
        _append([o])
        depth = DEPTH.get(o["stopped_by"], 1)
        board = _get("leaderboard.json", [])
        board = sorted(board + [{"nick": nick, "depth": depth, "stopped_by": o["stopped_by"],
                                 "message": msg[:280], "ts": time.time()}],
                       key=lambda e: (-e["depth"], e["ts"]))[:50]
        _put("leaderboard.json", board)
        return _resp(200, o)

    if method == "POST" and path == "/api/campaign":
        if not _rate_ok(ip + "#campaign", limit=6):
            return _resp(429, {"error": "rate limit"})
        red = RedAgent(rng=random.Random())
        out = []
        for _ in range(min(int(body.get("n", 40)), 40)):
            atk = red.next()
            o = run_attack(atk, MODEL, LayerConfig.named("full"))
            red.learn(atk, o.as_dict())
            out.append(o.as_dict())
        _append(out)
        return _resp(200, {"started": True, "ran": len(out)})

    return _resp(404, {"error": "not found"})
