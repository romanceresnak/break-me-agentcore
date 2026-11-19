"""STDIO MCP server that the Managed Agent's exec host runs.

It exposes the BREAK ME tools to the agent and forwards every call to the Tool API
(API Gateway + Lambda: Cedar PEP + IAM-bounded tool role). The exec host's own IAM
identity may only call execute-api:Invoke on that API, so nothing on this host - not
this server, not a shell command the agent runs - can reach AWS any other way.

Without BREAKME_TOOL_API_URL it runs the gateway in-process against the local
sandbox (handy for `codex` / MCP inspector testing offline).

Protocol: MCP over stdio, newline-delimited JSON-RPC 2.0 (initialize, tools/list, tools/call).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import uuid

from .gateway import TOOLS

PROTOCOL_VERSION = "2025-06-18"


class RemoteTools:
    def __init__(self, url: str, session: str):
        import boto3
        self.url, self.session = url.rstrip("/"), session
        self.region = os.environ.get("AWS_REGION", "eu-west-1")
        self.creds = boto3.Session().get_credentials()

    def call(self, name: str, args: dict) -> dict:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        body = json.dumps({"session": self.session, "args": args}).encode()
        req = AWSRequest(method="POST", url=f"{self.url}/tools/{name}", data=body,
                         headers={"content-type": "application/json"})
        SigV4Auth(self.creds.get_frozen_credentials(), "execute-api", self.region).add_auth(req)
        r = urllib.request.Request(req.url, data=body, method="POST", headers=dict(req.headers))
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read())


class LocalTools:
    def __init__(self, session: str):
        from .config import Session
        from .gateway import Gateway
        from .sandbox import Sandbox
        self.gw = Gateway(Sandbox())
        self.s = Session(session)

    def call(self, name: str, args: dict) -> dict:
        return self.gw.call(self.s, name, args).as_dict()


def _reply(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    msg["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve(stdin=sys.stdin) -> None:
    session = os.environ.get("BREAKME_SESSION_ID") or "bma-" + uuid.uuid4().hex[:8]
    url = os.environ.get("BREAKME_TOOL_API_URL")
    backend = RemoteTools(url, session) if url else LocalTools(session)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, id_ = msg.get("method"), msg.get("id")
        if id_ is None:            # notification (e.g. notifications/initialized)
            continue
        if method == "initialize":
            _reply(id_, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                         "serverInfo": {"name": "breakme", "version": "1.0.0"}})
        elif method == "tools/list":
            _reply(id_, {"tools": [{"name": t["name"], "description": t["description"],
                                    "inputSchema": t["input_schema"]} for t in TOOLS]})
        elif method == "tools/call":
            p = msg.get("params", {})
            try:
                r = backend.call(p["name"], p.get("arguments") or {})
                _reply(id_, {"content": [{"type": "text", "text": r["output"]}],
                             "isError": r["status"] not in ("OK", "PENDING_APPROVAL")})
            except Exception as e:  # never crash the agent's tool channel
                _reply(id_, {"content": [{"type": "text", "text": f"tool error: {e}"}], "isError": True})
        elif method == "ping":
            _reply(id_, {})
        else:
            _reply(id_, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    serve()
