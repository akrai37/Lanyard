"""Workload identity: agents running on AWS authenticate with their IAM role, no stored secret.

Flow (the same pattern HashiCorp Vault uses for AWS auth):
  1. The agent signs an sts:GetCallerIdentity request with its role credentials (SigV4),
     including an X-Lanyard-Audience header so the signature is only valid for Lanyard.
  2. It sends the signed request to Lanyard (POST /auth/aws) instead of to AWS.
  3. Lanyard forwards it to AWS STS. If AWS accepts the signature, STS answers with the caller's ARN.
  4. Lanyard maps the role to an agent identity and issues a short-lived Lanyard token.

The agent never sends its AWS credentials, and Lanyard never sees them.
"""

import re
import time

import httpx
import jwt

STS_URLS = {"https://sts.amazonaws.com/", "https://sts.us-east-1.amazonaws.com/"}
STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
AUDIENCE_HEADER = "x-lanyard-audience"
LANYARD_ISSUER = "lanyard"
TOKEN_TTL_SECONDS = 600


# ---------- agent side ----------

def sign_identity_proof(audience: str, session=None, region: str = "us-east-1") -> dict:
    """Build a signed (but unsent) GetCallerIdentity request, using whatever AWS credentials
    this process has: a Lambda/EC2/ECS role in the cloud, or a profile locally."""
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    session = session or boto3.Session(region_name=region)
    url = f"https://sts.{region}.amazonaws.com/"
    req = AWSRequest(method="POST", url=url, data=STS_BODY, headers={
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "X-Lanyard-Audience": audience,
    })
    SigV4Auth(session.get_credentials().get_frozen_credentials(), "sts", region).add_auth(req)
    return {"method": "POST", "url": url, "headers": dict(req.headers.items()), "body": STS_BODY}


# ---------- Lanyard side ----------

class WorkloadAuthError(Exception):
    pass


async def verify_identity_proof(proof: dict, audience: str, http: httpx.AsyncClient) -> str:
    """Check the proof is a GetCallerIdentity call bound to Lanyard, let AWS verify it, return the ARN."""
    if proof.get("method") != "POST" or proof.get("url") not in STS_URLS or proof.get("body") != STS_BODY:
        raise WorkloadAuthError("proof must be a signed sts:GetCallerIdentity request")
    headers = {k.lower(): v for k, v in (proof.get("headers") or {}).items()}
    if headers.get(AUDIENCE_HEADER) != audience:
        raise WorkloadAuthError("proof is not bound to this Lanyard audience")
    signed = re.search(r"SignedHeaders=([^,]+)", headers.get("authorization", ""))
    if not signed or AUDIENCE_HEADER not in signed.group(1).split(";"):
        raise WorkloadAuthError("audience header is not covered by the signature")

    forward = {k: v for k, v in headers.items() if k not in ("host", "content-length")}
    r = await http.post(proof["url"], content=STS_BODY, headers=forward)
    if r.status_code != 200:
        code = re.search(r"<Code>(.*?)</Code>", r.text)
        raise WorkloadAuthError(f"AWS rejected the signature ({code.group(1) if code else r.status_code})")
    arn = re.search(r"<Arn>(.*?)</Arn>", r.text)
    if not arn:
        raise WorkloadAuthError("unexpected STS response")
    return arn.group(1)


def role_from_arn(arn: str) -> tuple[str, str] | None:
    """arn:aws:sts::123456789012:assumed-role/RoleName/session -> ("123456789012", "RoleName")"""
    m = re.fullmatch(r"arn:aws:sts::(\d{12}):assumed-role/([\w+=,.@-]+)/[\w+=,.@-]+", arn)
    return (m.group(1), m.group(2)) if m else None


def issue_token(key: str, audience: str, agent_id: str, name: str, scopes: list[str], arn: str) -> tuple[str, int]:
    now = int(time.time())
    claims = {"iss": LANYARD_ISSUER, "aud": audience, "sub": agent_id, "azp": agent_id,
              "scope": " ".join(scopes), "iat": now, "exp": now + TOKEN_TTL_SECONDS,
              "lanyard_identity": "aws-iam", "lanyard_name": name, "lanyard_arn": arn}
    return jwt.encode(claims, key, algorithm="HS256"), TOKEN_TTL_SECONDS
