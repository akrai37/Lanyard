"""Scripted agent: a predictable stand-in for an LLM agent, for demos and testing.

Usage: uv run python scripts/demo_agent.py trusted|intern|aws [--delay SECONDS]

  trusted, intern   sign in with Auth0 client credentials
  aws               sign in with this machine's AWS identity (workload identity, no stored secret)

Set LANYARD_URL to use a gateway other than http://127.0.0.1:8000 (e.g. the cloud deployment).
"""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from dotenv import dotenv_values  # noqa: E402

from lanyard.agent_runner import aws_workload_token, run  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", nargs="?", default="trusted")
    ap.add_argument("--delay", type=float, default=3.0)
    args = ap.parse_args()
    gateway = os.environ.get("LANYARD_URL", "http://127.0.0.1:8000").rstrip("/")

    if args.agent == "aws":
        import boto3
        env = dotenv_values(ROOT / ".env")
        session = boto3.Session(profile_name=env.get("AWS_PROFILE") or None, region_name="us-east-1")
        try:
            token = aws_workload_token(gateway, env["AUTH0_AUDIENCE"], session)
        except RuntimeError as e:
            print(f"\033[31m✗ {e}\033[0m")
            return
        label = "aws workload agent"
    else:
        from get_token import get_token
        token = get_token(args.agent)
        label = f"{args.agent}-agent"
    run(gateway, token, label, args.delay)


if __name__ == "__main__":
    main()
