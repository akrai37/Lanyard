"""Traffic simulator: a handful of synthetic agents doing a normal day's work at Pinecrest Payments.

Each simulated agent has its own AWS IAM role (lanyard-sim-*) and signs in through Lanyard's
workload identity flow, so every simulated call goes through the real checks: identity,
revocation, scopes, guardrails and the audit log. Some behaviour is deliberately bad (reading a
poisoned ticket, trying a tool it lacks permission for) so the console shows realistic denials.

Cloud: the lanyard-simulator Lambda runs this for ~50 seconds each minute (EventBridge schedule).
Local: uv run python -m lanyard.simulator --minutes 2   (assumes the roles with your AWS profile)
"""

import os
import random
import threading
import time

import boto3
import httpx

from .agent_runner import call_tool
from .workload import sign_identity_proof

ROLE_PREFIX = "lanyard-sim-"


def _invoices():
    return f"invoices/INV-{random.randint(1001, 1020)}.md"


def _ticket():
    return f"tickets/TCK-{random.randint(2001, 2015)}.md"


def _report():
    return f"reports/weekly-metrics-w{random.randint(36, 44)}.md"


# role suffix -> list of (weight, tool, argument factory)
BEHAVIOUR = {
    "billing": [(3, "read_file", lambda: {"path": _invoices()}), (1, "list_files", lambda: {"prefix": "invoices/"}),
                (1, "read_file", lambda: {"path": "customers.csv"})],
    "support": [(4, "read_file", lambda: {"path": _ticket()}), (1, "list_files", lambda: {"prefix": "tickets/"})],
    "analytics": [(4, "read_file", lambda: {"path": _report()}),
                  (1, "write_file", lambda: {"path": "reports/forecast.md", "content": "# Forecast\nVolume up 4%.\n"}),
                  (1, "delete_file", lambda: {"path": "reports/old.md"})],
    "release": [(3, "read_file", lambda: {"path": "release_notes.md"}),
                (1, "deploy_service", lambda: {"service": random.choice(["payments-api", "ledger", "webhooks"]),
                                               "version": f"2.{random.randint(4, 9)}.{random.randint(0, 9)}",
                                               "environment": "staging"})],
    "research": [(3, "read_file", lambda: {"path": f"contracts/{random.choice(['acmerobotics', 'bluefernlabs', 'northwindfreight', 'cobalthealth', 'juniperretail', 'atlaslogistics'])}-msa.md"}),
                 (1, "write_file", lambda: {"path": f"reports/contract-summary-{random.randint(1, 9)}.md",
                                            "content": "# Contract summary\nRenewals due next quarter: 2.\n"})],
}


class SimAgent:
    def __init__(self, role_arn: str, gateway: str, audience: str, base_session: boto3.Session):
        self.role_arn, self.gateway, self.audience, self.base = role_arn, gateway, audience, base_session
        self.kind = role_arn.rsplit("/", 1)[-1][len(ROLE_PREFIX):]
        self.token, self.token_exp = None, 0.0

    def _token(self) -> str | None:
        if self.token and time.time() < self.token_exp - 60:
            return self.token
        creds = self.base.client("sts").assume_role(RoleArn=self.role_arn, RoleSessionName="lanyard-sim",
                                                    DurationSeconds=900)["Credentials"]
        session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                                aws_session_token=creds["SessionToken"], region_name="us-east-1")
        r = httpx.post(f"{self.gateway}/auth/aws", json=sign_identity_proof(self.audience, session), timeout=30)
        if r.status_code != 200:
            return None  # revoked or not registered: sit this round out
        self.token, self.token_exp = r.json()["access_token"], time.time() + r.json()["expires_in"]
        return self.token

    def work(self, until: float) -> None:
        actions = BEHAVIOUR.get(self.kind, BEHAVIOUR["billing"])
        weights = [w for w, *_ in actions]
        time.sleep(random.uniform(0, 4))
        while time.time() < until:
            token = self._token()
            if not token:
                return
            _, tool, args = random.choices(actions, weights)[0]
            status, _ = call_tool(self.gateway, token, tool, args())
            if status == 403:  # revoked mid-run
                return
            time.sleep(random.uniform(4, 10))


def run(gateway: str, audience: str, seconds: float, base_session: boto3.Session) -> int:
    account = base_session.client("sts").get_caller_identity()["Account"]
    roles = [f"arn:aws:iam::{account}:role/{ROLE_PREFIX}{k}" for k in BEHAVIOUR]
    until = time.time() + seconds
    agents = [SimAgent(r, gateway, audience, base_session) for r in roles]
    threads = [threading.Thread(target=a.work, args=(until,), daemon=True) for a in agents]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=seconds + 60)
    return len(agents)


def handler(event, context):
    """Lambda entry point: simulate traffic until just before the next scheduled run."""
    n = run(os.environ["LANYARD_URL"].rstrip("/"), os.environ["LANYARD_AUDIENCE"],
            float((event or {}).get("seconds", 50)), boto3.Session(region_name="us-east-1"))
    return {"agents": n}


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    from dotenv import dotenv_values

    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=1)
    args = ap.parse_args()
    env = dotenv_values(Path(__file__).resolve().parent.parent / ".env")
    gw = os.environ.get("LANYARD_URL", "http://127.0.0.1:8000").rstrip("/")
    print(f"simulating {len(BEHAVIOUR)} agents against {gw} for {args.minutes} min")
    run(gw, env["AUTH0_AUDIENCE"], args.minutes * 60,
        boto3.Session(profile_name=env.get("AWS_PROFILE") or None, region_name="us-east-1"))
