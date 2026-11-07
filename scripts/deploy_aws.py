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
FILES_BUCKET = f"lanyard-files-{ACCOUNT}"
AUDIT_BUCKET = f"lanyard-audit-{ACCOUNT}"
SIM_KINDS = ["billing", "support", "analytics", "release", "research"]

TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def role(name: str, inline: dict | None = None, trust: str = TRUST, lambda_role: bool = True) -> str:
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=trust)
        fresh = False
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
        fresh = True
    if lambda_role:
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


def gateway_secret(password: str) -> str:
    """Gateway secrets live in AWS Secrets Manager, not in Lambda environment variables."""
    sm = session.client("secretsmanager")
    name = "lanyard/gateway"
    try:
        current = json.loads(sm.get_secret_value(SecretId=name)["SecretString"])
    except sm.exceptions.ResourceNotFoundException:
        current = {}
    value = {
        "LANYARD_ADMIN_PASSWORD": password,
        # Cloud-only key for workload tokens; kept across deploys so issued tokens stay valid.
        "LANYARD_SIGNING_KEY": current.get("LANYARD_SIGNING_KEY") or secrets.token_urlsafe(48),
    }
    if ENV.get("AUTH0_ADMIN_CLIENT_ID") and ENV.get("AUTH0_ADMIN_CLIENT_SECRET"):
        value["AUTH0_ADMIN_CLIENT_ID"] = ENV["AUTH0_ADMIN_CLIENT_ID"]
        value["AUTH0_ADMIN_CLIENT_SECRET"] = ENV["AUTH0_ADMIN_CLIENT_SECRET"]
    if current:
        arn = sm.put_secret_value(SecretId=name, SecretString=json.dumps(value))["ARN"]
    else:
        arn = sm.create_secret(Name=name, SecretString=json.dumps(value),
                               Description="Lanyard gateway secrets")["ARN"]
    print(f"  secret {name}: {', '.join(sorted(value))}")
    return arn


def audit_bucket() -> None:
    """Private bucket with Object Lock (compliance mode): archived audit records can't be altered."""
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=AUDIT_BUCKET)
    except ClientError:
        s3.create_bucket(Bucket=AUDIT_BUCKET, ObjectLockEnabledForBucket=True)
        print(f"  created {AUDIT_BUCKET}")
    s3.put_public_access_block(Bucket=AUDIT_BUCKET, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_object_lock_configuration(Bucket=AUDIT_BUCKET, ObjectLockConfiguration={
        "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}}})


def table_stream() -> str:
    ddb = session.client("dynamodb")
    desc = ddb.describe_table(TableName=TABLE)["Table"]
    if not desc.get("StreamSpecification", {}).get("StreamEnabled"):
        ddb.update_table(TableName=TABLE, StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"})
        ddb.get_waiter("table_exists").wait(TableName=TABLE)
        for _ in range(30):
            desc = ddb.describe_table(TableName=TABLE)["Table"]
            if desc.get("LatestStreamArn"):
                break
            time.sleep(2)
        print("  enabled DynamoDB stream")
    return desc["LatestStreamArn"]


def stream_mapping(function_name: str, stream_arn: str) -> None:
    existing = lam.list_event_source_mappings(FunctionName=function_name, EventSourceArn=stream_arn)
    if existing["EventSourceMappings"]:
        return
    lam.create_event_source_mapping(
        FunctionName=function_name, EventSourceArn=stream_arn, StartingPosition="LATEST",
        BatchSize=100, MaximumBatchingWindowInSeconds=10,
        FilterCriteria={"Filters": [{"Pattern": json.dumps(
            {"eventName": ["INSERT"], "dynamodb": {"NewImage": {"pk": {"S": ["audit"]}}}})}]})
    print("  connected stream to lanyard-archiver")


def schedule(function_arn: str) -> None:
    """EventBridge rule that starts the simulator every minute. Created disabled; scripts/simulator.sh toggles it."""
    ev = session.client("events")
    try:
        state = ev.describe_rule(Name="lanyard-simulator")["State"]
    except ev.exceptions.ResourceNotFoundException:
        state = "DISABLED"
    rule_arn = ev.put_rule(Name="lanyard-simulator", ScheduleExpression="rate(1 minute)", State=state,
                           Description="Lanyard traffic simulator")["RuleArn"]
    ev.put_targets(Rule="lanyard-simulator", Targets=[{"Id": "simulator", "Arn": function_arn}])
    try:
        lam.add_permission(FunctionName="lanyard-simulator", StatementId="eventbridge", Action="lambda:InvokeFunction",
                           Principal="events.amazonaws.com", SourceArn=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            raise
    print(f"  schedule lanyard-simulator: {state.lower()} (scripts/simulator.sh on|off)")


def main():
    password = ENV.get("LANYARD_CLOUD_ADMIN_PASSWORD")
    if not password:
        password = secrets.token_urlsafe(12)
        set_key(str(ENV_FILE), "LANYARD_CLOUD_ADMIN_PASSWORD", password, quote_mode="never")

    print("Secrets Manager")
    secret_arn = gateway_secret(password)

    print("IAM roles")
    tools_role = role("lanyard-tools-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{FILES_BUCKET}/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{FILES_BUCKET}"}]})
    worker_role = role("lanyard-worker-role")  # no AWS permissions: its identity is all it needs
    gateway_role = role("lanyard-gateway-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
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
    function("lanyard-files", tools_role, "servers.lambda_handler.handler",
             {"LANYARD_TOOL_SERVER": "files", "FILES_BUCKET": FILES_BUCKET}, 30)
    function("lanyard-deploy", tools_role, "servers.lambda_handler.handler", {"LANYARD_TOOL_SERVER": "deploy"}, 30)

    print("Gateway function")
    env = {
        "AUTH0_DOMAIN": ENV["AUTH0_DOMAIN"], "AUTH0_AUDIENCE": ENV["AUTH0_AUDIENCE"],
        "LANYARD_STORE": "dynamo", "LANYARD_TABLE": TABLE,
        "LANYARD_BACKENDS": json.dumps({"files": "lambda:lanyard-files", "deploy": "lambda:lanyard-deploy"}),
        "LANYARD_SECRET_ID": "lanyard/gateway",
        "LANYARD_AWS_ACCOUNT": ACCOUNT,
        "LANYARD_AUDIT_BUCKET": AUDIT_BUCKET,
        "LANYARD_FILES_BUCKET": FILES_BUCKET,
    }
    for k, v in ENV.items():  # client IDs only (for display names), never secrets
        if k.endswith("_CLIENT_ID") and v:
            env[k] = v
    if ENV.get("LANYARD_GUARDRAIL_ID"):
        env["LANYARD_GUARDRAIL_ID"] = ENV["LANYARD_GUARDRAIL_ID"]
        env["LANYARD_GUARDRAIL_VERSION"] = ENV.get("LANYARD_GUARDRAIL_VERSION", "DRAFT")
    function("lanyard-gateway", gateway_role, "lanyard.lambda_handler.handler", env, timeout=180, memory=1024)
    url = public_url("lanyard-gateway")

    print("Cloud agent (workload identity)")
    function("lanyard-worker", worker_role, "lanyard.worker_handler.handler",
             {"LANYARD_URL": url, "LANYARD_AUDIENCE": ENV["AUTH0_AUDIENCE"]}, timeout=300)

    print("AI agent (Claude Opus 5.5 on Bedrock)")
    ai_role = role("lanyard-ai-agent-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["bedrock-mantle:*", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": "*"}]})
    function("lanyard-ai-agent", ai_role, "lanyard.ai_agent.handler",
             {"LANYARD_URL": url, "LANYARD_AUDIENCE": ENV["AUTH0_AUDIENCE"]}, timeout=900)

    print("Traffic simulator")
    sim_role = role("lanyard-simulator-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role/lanyard-sim-*"}]})
    sim_trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"AWS": [sim_role, f"arn:aws:iam::{ACCOUNT}:root"]}}]})
    for kind in SIM_KINDS:  # one identity per simulated agent; no permissions, identity only
        role(f"lanyard-sim-{kind}", trust=sim_trust, lambda_role=False)
    sim_arn = function("lanyard-simulator", sim_role, "lanyard.simulator.handler",
                       {"LANYARD_URL": url, "LANYARD_AUDIENCE": ENV["AUTH0_AUDIENCE"]}, timeout=90)
    schedule(sim_arn)

    print("Audit archive (DynamoDB stream -> S3 Object Lock)")
    audit_bucket()
    stream_arn = table_stream()
    archiver_role = role("lanyard-archiver-role", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream",
                                       "dynamodb:ListStreams"], "Resource": stream_arn},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{AUDIT_BUCKET}/*"}]})
    function("lanyard-archiver", archiver_role, "lanyard.archiver.handler", {"AUDIT_BUCKET": AUDIT_BUCKET}, timeout=60)
    stream_mapping("lanyard-archiver", stream_arn)

    set_key(str(ENV_FILE), "LANYARD_CLOUD_URL", url, quote_mode="never")
    print(f"\nDashboard: {url}/   (user: admin, password: LANYARD_CLOUD_ADMIN_PASSWORD in .env)")
    print(f"Agents:    LANYARD_URL={url} uv run python scripts/demo_agent.py trusted")
    print("Cloud agent: scripts/run_cloud_agent.sh")


if __name__ == "__main__":
    main()
