"""Real-AWS backend for the Tool API Lambda.

Runs under the tool execution role, which carries the permissions boundary compiled
from rules.yaml (generated/iam_boundary.json). An AccessDenied from AWS is layer 4
doing its job and is reported to Glass Box as such.

Logical resource ids used by the agent (e.g. 'ecs:prod/shop-api', 'rds:prod-orders')
are mapped to real ids by BREAKME_RESOURCE_MAP (JSON emitted by Terraform).
"""
from __future__ import annotations

import json
import os
import re

import boto3
from botocore.exceptions import ClientError, ParamValidationError

from .sandbox import AccessDenied, NotFound

DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess"}


def _snake(name: str) -> str:
    """API operation -> boto3 method name (DescribeDBInstances -> describe_db_instances)."""
    from botocore import xform_name
    return xform_name(name)


class AwsBackend:
    def __init__(self, resource_map: dict | None = None):
        self.map = resource_map or json.loads(os.environ.get("BREAKME_RESOURCE_MAP", "{}"))
        self.cluster = self.map.get("ecs_cluster", "break-me")
        self.ddb = boto3.resource("dynamodb")
        self.tickets = self.ddb.Table(os.environ.get("BREAKME_TICKETS_TABLE", "break-me-tickets"))

    # ------------------------------------------------------------ metadata
    def _real(self, resource: str) -> str:
        return self.map.get("ids", {}).get(resource, resource.partition(":")[2])

    def resource_env(self, resource: str) -> str:
        return self.map.get("env", {}).get(resource) or (
            "prod" if "prod" in resource else "dev" if "dev" in resource else "shared")

    def ecs_desired(self, service: str) -> tuple[int, int]:
        s = boto3.client("ecs").describe_services(cluster=self.cluster, services=[self._real(f"ecs:{service}")])
        if not s["services"]:
            raise NotFound(service)
        return s["services"][0]["desiredCount"], int(self.map.get("baseline", {}).get(service, 1))

    def instance_type(self, iid: str) -> str:
        r = boto3.client("ec2").describe_instances(InstanceIds=[self._real(f"ec2:{iid}")])
        return r["Reservations"][0]["Instances"][0]["InstanceType"]

    @staticmethod
    def _id_param(svc: str, op: str, resource: str, rid: str) -> dict:
        kind = resource.partition(":")[0]
        if kind in ("account", "alarm"):
            return {}
        if svc == "secretsmanager":
            return {"SecretId": rid}
        if svc == "rds":
            return {"DBSnapshotIdentifier": rid} if "Snapshot" in op else {"DBInstanceIdentifier": rid}
        if svc == "ec2":
            if kind == "snap":
                return {"SnapshotId": rid}
            if kind == "sg":
                return {"GroupId": rid}
            return {"InstanceIds": [rid]}
        if svc == "s3":
            return {"Bucket": rid}
        return {}

    # ------------------------------------------------------------ execute
    def execute(self, action: str, resource: str, params: dict | None = None) -> dict:
        p = params or {}
        rid = self._real(resource)
        try:
            return self._call(action, resource, rid, p)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in DENY_CODES:
                raise AccessDenied(e.response["Error"]["Message"])
            if "NotFound" in code:
                raise NotFound(code)
            raise
        except ParamValidationError as e:
            raise NotFound(f"invalid parameters: {e}")

    def _call(self, action: str, resource: str, rid: str, p: dict) -> dict:
        svc, _, op = action.partition(":")
        if action == "tickets:GetTicket":
            item = self.tickets.get_item(Key={"id": rid}).get("Item")
            if not item:
                raise NotFound(rid)
            return {"ticket": item}
        if action == "logs:FilterLogEvents":
            r = boto3.client("logs").filter_log_events(logGroupName=f"/break-me/{rid}", limit=int(p.get("limit", 20)))
            return {"lines": [e["message"] for e in r["events"]]}
        if action == "cloudwatch:DescribeAlarms":
            r = boto3.client("cloudwatch").describe_alarms(StateValue="ALARM", AlarmNamePrefix="break-me")
            return {"alarms": [{"name": a["AlarmName"], "reason": a["StateReason"]} for a in r["MetricAlarms"]]}
        if action == "ecs:DescribeServices":
            ecs = boto3.client("ecs")
            arns = ecs.list_services(cluster=self.cluster)["serviceArns"]
            svcs = ecs.describe_services(cluster=self.cluster, services=arns[:10])["services"] if arns else []
            return {"services": {s["serviceName"]: {"desired": s["desiredCount"], "running": s["runningCount"],
                                                    "status": s["status"]} for s in svcs}}
        if action == "ec2:DescribeInstances":
            r = boto3.client("ec2").describe_instances(Filters=[{"Name": "tag:Env", "Values": ["dev", "prod"]}])
            return {"instances": {next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), i["InstanceId"]): {
                "type": i["InstanceType"], "state": i["State"]["Name"],
                "tags": {t["Key"]: t["Value"] for t in i.get("Tags", [])}}
                for res in r["Reservations"] for i in res["Instances"]}}
        if action == "ecs:UpdateService":
            kw = {"cluster": self.cluster, "service": rid}
            kw.update({"desiredCount": int(p["desired"])} if "desired" in p else {"forceNewDeployment": True})
            r = boto3.client("ecs").update_service(**kw)["service"]
            return {"service": r["serviceName"], "desired": r["desiredCount"]}
        if action in ("ec2:StopInstances", "ec2:StartInstances"):
            getattr(boto3.client("ec2"), _snake(op))(InstanceIds=[rid])
            return {"instance": rid, "requested": op}
        if action == "ec2:ModifyInstanceAttribute":
            boto3.client("ec2").modify_instance_attribute(InstanceId=rid, InstanceType={"Value": p["instance_type"]})
            return {"instance": rid, "type": p["instance_type"]}
        if action == "rds:CreateDBSnapshot":
            sid = f"break-me-{rid}-manual"
            boto3.client("rds").create_db_snapshot(DBInstanceIdentifier=rid, DBSnapshotIdentifier=sid)
            return {"snapshot": sid}
        # Generic path: service:Action -> boto3 client(service).action(**params).
        # Anything dangerous that reaches here is stopped by the permissions boundary.
        client = boto3.client(svc)
        fn = getattr(client, _snake(op))
        r = fn(**{**self._id_param(svc, op, resource, rid), **p})
        r.pop("ResponseMetadata", None)
        return json.loads(json.dumps(r, default=str))
