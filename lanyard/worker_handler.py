"""AWS Lambda entry point for a cloud-hosted agent that signs in with workload identity.

It holds no secret: it proves who it is with its own IAM role (lanyard-worker-role), gets a
10-minute Lanyard token, and runs the scripted release task through the gateway.
Invoke asynchronously and watch the console: aws lambda invoke --invocation-type Event ...
"""

import os

from .agent_runner import aws_workload_token, run


def handler(event, context):
    gateway = os.environ["LANYARD_URL"].rstrip("/")
    try:
        token = aws_workload_token(gateway, os.environ["LANYARD_AUDIENCE"])
    except RuntimeError as e:
        print(f"✗ {e}")
        return {"result": "refused", "error": str(e)}
    return {"result": run(gateway, token, "aws-worker-agent", float((event or {}).get("delay", 3)), color=False)}
