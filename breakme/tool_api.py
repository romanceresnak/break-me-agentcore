"""Tool API Lambda (API Gateway HTTP API, IAM auth).

Routes
  POST /tools/{name}            body {session, args}      -> ToolResult (MCP server calls this)
  POST /approvals/{id}          body {approve, signature}  -> human approval channel (Slack app / CLI)
  GET  /approvals               pending approvals          (Slack notifier / Glass Box)
  GET  /events?session=<id>     tool events of a session  (Glass Box, judge)

State (DynamoDB): sessions (taint, history, cumulative cost), approvals, events.
The Lambda's execution role is the *tool role* and carries the compiled permissions boundary.
"""
from __future__ import annotations

import json
import os
import time
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

from .approvals import Approval, ApprovalStore
from .aws_backend import AwsBackend
from .config import Session
from .gateway import Gateway

_ddb = boto3.resource("dynamodb")
T_SESSIONS = _ddb.Table(os.environ.get("BREAKME_SESSIONS_TABLE", "break-me-sessions"))
T_APPROVALS = _ddb.Table(os.environ.get("BREAKME_APPROVALS_TABLE", "break-me-approvals"))
T_EVENTS = _ddb.Table(os.environ.get("BREAKME_EVENTS_TABLE", "break-me-events"))


def _clean(o):
    return json.loads(json.dumps(o, default=str), parse_float=Decimal)


class DynamoApprovals(ApprovalStore):
    def request(self, session, action, resource, params, reason):
        a = super().request(session, action, resource, params, reason)
        T_APPROVALS.put_item(Item=_clean(a.__dict__))
        self._notify(a)
        return a

    def _load(self, aid: str) -> Approval | None:
        it = T_APPROVALS.get_item(Key={"id": aid}).get("Item")
        if not it:
            return None
        it = json.loads(json.dumps(it, default=float))
        return Approval(**it)

    def decide(self, approval_id, signature, approve, who="human"):
        a = self._load(approval_id)
        if a is None:
            raise KeyError(approval_id)
        self.items[a.id] = a
        a = super().decide(approval_id, signature, approve, who)
        T_APPROVALS.put_item(Item=_clean(a.__dict__))
        return a

    def consume(self, session, action, resource, params):
        r = T_APPROVALS.scan(FilterExpression="#s = :s AND #ss = :a",
                             ExpressionAttributeNames={"#s": "session", "#ss": "status"},
                             ExpressionAttributeValues={":s": session, ":a": "APPROVED"})
        for it in r.get("Items", []):
            a = Approval(**json.loads(json.dumps(it, default=float)))
            self.items[a.id] = a
        a = super().consume(session, action, resource, params)
        if a:
            T_APPROVALS.update_item(Key={"id": a.id}, UpdateExpression="SET #ss = :u",
                                    ConditionExpression="#ss = :a",
                                    ExpressionAttributeNames={"#ss": "status"},
                                    ExpressionAttributeValues={":u": "USED", ":a": "APPROVED"})
        return a

    def _notify(self, a: Approval) -> None:
        topic = os.environ.get("BREAKME_APPROVAL_TOPIC_ARN")
        if topic:
            boto3.client("sns").publish(TopicArn=topic, Subject=f"BREAK ME approval {a.id}",
                                        Message=json.dumps(a.__dict__, default=str, indent=2))


def _load_session(sid: str) -> Session:
    it = T_SESSIONS.get_item(Key={"id": sid}).get("Item")
    if not it:
        return Session(sid)
    it = json.loads(json.dumps(it, default=float))
    return Session(**it)


def _save_session(s: Session) -> None:
    T_SESSIONS.put_item(Item=_clean(s.__dict__))


def _record(e: dict) -> None:
    item = _clean({**e, "pk": e["session"]})
    item["ts"] = Decimal(str(time.time()))      # numeric sort key, set after _clean (which stringifies)
    T_EVENTS.put_item(Item=item)


def _resp(code: int, body) -> dict:
    return {"statusCode": code, "headers": {"content-type": "application/json"},
            "body": json.dumps(body, default=str)}


def handler(event, _ctx):
    method = event["requestContext"]["http"]["method"]
    path = event.get("rawPath", "")
    body = json.loads(event.get("body") or "{}")

    if method == "POST" and path.startswith("/tools/"):
        name = path.rsplit("/", 1)[1]
        s = _load_session(body["session"])
        gw = Gateway(AwsBackend(), approvals=DynamoApprovals(), on_event=_record)
        r = gw.call(s, name, body.get("args") or {})
        _save_session(s)
        return _resp(200, r.as_dict())

    if method == "POST" and path.startswith("/approvals/"):
        aid = path.rsplit("/", 1)[1]
        try:
            a = DynamoApprovals().decide(aid, body.get("signature", ""), bool(body.get("approve")),
                                         body.get("who", "human"))
        except PermissionError:
            return _resp(403, {"error": "bad approver signature"})
        except (KeyError, ValueError) as e:
            return _resp(409, {"error": str(e)})
        return _resp(200, a.__dict__)

    if method == "GET" and path == "/approvals":
        r = T_APPROVALS.scan(FilterExpression="#ss = :p", ExpressionAttributeNames={"#ss": "status"},
                             ExpressionAttributeValues={":p": "PENDING"})
        return _resp(200, r.get("Items", []))

    if method == "GET" and path == "/events":
        sid = (event.get("queryStringParameters") or {}).get("session", "")
        r = T_EVENTS.query(KeyConditionExpression=Key("pk").eq(sid))
        return _resp(200, r.get("Items", []))

    return _resp(404, {"error": "not found"})
