#!/usr/bin/env python3
"""Human approval channel (CLI stand-in for the Slack button).

  BREAKME_APPROVER_SECRET=... python scripts/approve.py <tool-api-url> list
  BREAKME_APPROVER_SECRET=... python scripts/approve.py <tool-api-url> approve apr-1234abcd
  BREAKME_APPROVER_SECRET=... python scripts/approve.py <tool-api-url> reject  apr-1234abcd

The signature is an HMAC of the approval id with a secret the agent never sees,
so no text in the conversation can produce an approval.
"""
import hashlib
import hmac
import json
import os
import sys
import urllib.request


def main() -> None:
    url, cmd = sys.argv[1].rstrip("/"), sys.argv[2]
    secret = os.environ["BREAKME_APPROVER_SECRET"]
    if cmd == "list":
        import boto3
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        req = AWSRequest(method="GET", url=f"{url}/approvals")
        SigV4Auth(boto3.Session().get_credentials().get_frozen_credentials(), "execute-api",
                  os.environ.get("AWS_REGION", "us-east-1")).add_auth(req)
        r = urllib.request.Request(req.url, headers=dict(req.headers))
        for a in json.loads(urllib.request.urlopen(r).read()):
            print(f"{a['id']}  {a['action']:24} {a['resource']:24} {a['reason']}")
        return
    aid = sys.argv[3]
    sig = hmac.new(secret.encode(), aid.encode(), hashlib.sha256).hexdigest()
    body = json.dumps({"approve": cmd == "approve", "signature": sig, "who": os.environ.get("USER", "human")}).encode()
    r = urllib.request.Request(f"{url}/approvals/{aid}", data=body, method="POST",
                               headers={"content-type": "application/json"})
    print(urllib.request.urlopen(r).read().decode())


if __name__ == "__main__":
    main()
