"""Deploy Lanyard to AWS Lambda (gateway behind a public function URL, tool servers private).

Usage: uv run python scripts/deploy_aws.py          (build build/lanyard.zip first: scripts/build_lambda.sh)

Creates or updates:
  - IAM roles: lanyard-tools-role (logs only), lanyard-gateway-role (DynamoDB table, invoke the
    two tool functions, apply the Bedrock guardrail)
  - Lambda functions: lanyard-gateway, lanyard-files, lanyard-deploy
  - A function URL for lanyard-gateway only. The tool functions have no URL.
Reads settings from .env; never uploads Auth0 client secrets.
"""

import json
import secrets
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import dotenv_values, set_key

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
ENV = dotenv_values(ENV_FILE)
REGION = ENV.get("AWS_REGION") or "us-east-1"
session = boto3.Session(profile_name=ENV.get("AWS_PROFILE") or None, region_name=REGION)
iam, lam, sts = session.client("iam"), session.client("lambda"), session.client("sts")
ACCOUNT = sts.get_caller_identity()["Account"]
ZIP = (ROOT / "build" / "lanyard.zip").read_bytes()
TABLE = ENV.get("LANYARD_TABLE", "lanyard")

TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def role(name: str, inline: dict | None = None) -> str:
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        fresh = False
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
        fresh = True
    iam.attach_role_policy(RoleName=name,
                           PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy", PolicyDocument=json.dumps(inline))
    if fresh:
        print(f"  created role {name}; waiting for IAM to propagate")
        time.sleep(12)
    return arn


def function(name: str, role_arn: str, handler: str, env: dict, timeout: int, memory: int = 512) -> str:
    config = dict(Role=role_arn, Handler=handler, Runtime="python3.13", Timeout=timeout, MemorySize=memory,
                  Environment={"Variables": env}, Architectures=["x86_64"])
    try:
        lam.get_function(FunctionName=name)
        lam.update_function_code(FunctionName=name, ZipFile=ZIP)
        lam.get_waiter("function_updated_v2").wait(FunctionName=name)
        config.pop("Architectures")
        lam.update_function_configuration(FunctionName=name, **config)
        print(f"  updated {name}")
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):
            try:
                lam.create_function(FunctionName=name, Code={"ZipFile": ZIP}, **config)
                break
            except lam.exceptions.InvalidParameterValueException as e:
                if "role" not in str(e).lower() or attempt == 5:
                    raise
                time.sleep(5)  # new role not assumable yet
        print(f"  created {name}")
    lam.get_waiter("function_active_v2").wait(FunctionName=name)
    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
    return f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"


def public_url(name: str) -> str:
    try:
        url = lam.get_function_url_config(FunctionName=name)["FunctionUrl"]
    except lam.exceptions.ResourceNotFoundException:
        url = lam.create_function_url_config(FunctionName=name, AuthType="NONE")["FunctionUrl"]
    # Lanyard does its own authentication (JWT for agents, password for admins).
    for sid, action, extra in (("public-url", "lambda:InvokeFunctionUrl", {"FunctionUrlAuthType": "NONE"}),
                               ("public-url-invoke", "lambda:InvokeFunction", {"InvokedViaFunctionUrl": True})):
        try:
            lam.add_permission(FunctionName=name, StatementId=sid, Action=action, Principal="*", **extra)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ResourceConflictException",):
                print(f"  note: {action} permission not added ({e.response['Error']['Code']})")
    return url.rstrip("/")


def main():
    password = ENV.get("LANYARD_CLOUD_ADMIN_PASSWORD")
    if not password:
        password = secrets.token_urlsafe(12)
        set_key(str(ENV_FILE), "LANYARD_CLOUD_ADMIN_PASSWORD", password, quote_mode="never")

    print("IAM roles")
    tools_role = role("lanyard-tools-role")
    gateway_role = role("lanyard-gateway-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan",
                                       "dynamodb:BatchWriteItem"],
         "Resource": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"},
        {"Effect": "Allow", "Action": "lambda:InvokeFunction",
         "Resource": [f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:lanyard-files",
                      f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:lanyard-deploy"]},
        {"Effect": "Allow", "Action": "bedrock:ApplyGuardrail",
         "Resource": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/*"},
    ]})

    print("Tool functions (private)")
    function("lanyard-files", tools_role, "servers.lambda_handler.handler", {"LANYARD_TOOL_SERVER": "files"}, 30)
    function("lanyard-deploy", tools_role, "servers.lambda_handler.handler", {"LANYARD_TOOL_SERVER": "deploy"}, 30)

    print("Gateway function")
    env = {
        "AUTH0_DOMAIN": ENV["AUTH0_DOMAIN"], "AUTH0_AUDIENCE": ENV["AUTH0_AUDIENCE"],
        "LANYARD_STORE": "dynamo", "LANYARD_TABLE": TABLE,
        "LANYARD_BACKENDS": json.dumps({"files": "lambda:lanyard-files", "deploy": "lambda:lanyard-deploy"}),
        "LANYARD_ADMIN_PASSWORD": password,
    }
    for k, v in ENV.items():  # client IDs only (for display names), never secrets
        if k.endswith("_CLIENT_ID") and v:
            env[k] = v
    if ENV.get("LANYARD_GUARDRAIL_ID"):
        env["LANYARD_GUARDRAIL_ID"] = ENV["LANYARD_GUARDRAIL_ID"]
        env["LANYARD_GUARDRAIL_VERSION"] = ENV.get("LANYARD_GUARDRAIL_VERSION", "DRAFT")
    function("lanyard-gateway", gateway_role, "lanyard.lambda_handler.handler", env, timeout=180, memory=1024)
    url = public_url("lanyard-gateway")

    set_key(str(ENV_FILE), "LANYARD_CLOUD_URL", url, quote_mode="never")
    print(f"\nDashboard: {url}/   (user: admin, password: LANYARD_CLOUD_ADMIN_PASSWORD in .env)")
    print(f"Agents:    LANYARD_URL={url} uv run python scripts/demo_agent.py trusted")


if __name__ == "__main__":
    main()
