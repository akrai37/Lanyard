"""Print an Auth0 access token for an agent (client credentials grant).

Usage: uv run python scripts/get_token.py trusted|intern

Tokens are cached in .tokens/ until 5 minutes before expiry, because the Auth0
free plan limits machine-to-machine tokens per month.
"""

import json
import sys
import time
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
ENV = dotenv_values(ROOT / ".env")
CACHE = ROOT / ".tokens"


def get_token(agent: str) -> str:
    prefix = agent.upper().removesuffix("-AGENT")
    cache = CACHE / f"{prefix.lower()}.json"
    if cache.exists():
        cached = json.loads(cache.read_text())
        if cached["expires_at"] - 300 > time.time():
            return cached["access_token"]

    r = httpx.post(f"https://{ENV['AUTH0_DOMAIN']}/oauth/token", json={
        "grant_type": "client_credentials",
        "client_id": ENV[f"{prefix}_CLIENT_ID"],
        "client_secret": ENV[f"{prefix}_CLIENT_SECRET"],
        "audience": ENV["AUTH0_AUDIENCE"],
    })
    r.raise_for_status()
    data = r.json()
    CACHE.mkdir(exist_ok=True)
    cache.write_text(json.dumps({"access_token": data["access_token"],
                                 "expires_at": time.time() + data["expires_in"]}))
    cache.chmod(0o600)
    return data["access_token"]


if __name__ == "__main__":
    print(get_token(sys.argv[1] if len(sys.argv) > 1 else "trusted"))
