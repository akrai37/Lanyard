"""Scripted agent: a predictable stand-in for an LLM agent, for demos and testing.

Usage: uv run python scripts/demo_agent.py trusted|intern [--delay SECONDS]

It runs a fixed release task through the Lanyard gateway, one tool call at a time,
and keeps going until the task ends or Lanyard cuts it off.
"""

import argparse
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from get_token import get_token  # noqa: E402

GATEWAY = "http://127.0.0.1:8000/mcp"

STEPS = [
    ("list_files", {}),
    ("read_file", {"path": "q3_report.md"}),
    ("read_file", {"path": "release_notes.md"}),
    ("write_file", {"path": "release_plan.md", "content": "# Release plan\nShip payments-api v2.4.1 to staging.\n"}),
    ("deploy_service", {"service": "payments-api", "version": "2.4.1", "environment": "staging"}),
    ("read_file", {"path": "customers.csv"}),
    ("deploy_service", {"service": "payments-api", "version": "2.4.1", "environment": "production"}),
]

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", nargs="?", default="trusted")
    ap.add_argument("--delay", type=float, default=3.0)
    args = ap.parse_args()

    token = get_token(args.agent)
    client = httpx.Client(timeout=30, headers={
        "authorization": f"Bearer {token}",
        "accept": "application/json, text/event-stream",
    })
    next_id = 0

    def rpc(method, params=None):
        nonlocal next_id
        next_id += 1
        return client.post(GATEWAY, json={"jsonrpc": "2.0", "id": next_id, "method": method,
                                          "params": params or {}})

    print(f"{BOLD}{args.agent}-agent{RESET} signing in through Lanyard")
    r = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "demo-agent", "version": "1"}})
    if r.status_code != 200:
        print(f"{RED}✗ {r.status_code} {r.text}{RESET}")
        return
    r = rpc("tools/list")
    tools = [t["name"] for t in r.json()["result"]["tools"]]
    print(f"{DIM}tools visible to this agent: {', '.join(tools)}{RESET}\n")

    for name, arguments in STEPS:
        time.sleep(args.delay)
        r = rpc("tools/call", {"name": name, "arguments": arguments})
        label = f"{name}({', '.join(f'{k}={v!r}' for k, v in arguments.items() if k != 'content')})"
        if r.status_code == 403:
            print(f"{RED}✗ {label}  →  HTTP 403: {r.json()['error']['message']}{RESET}")
            print(f"\n{RED}{BOLD}Agent stopped: Lanyard revoked its access mid-task.{RESET}")
            return
        result = r.json().get("result", {})
        text = (result.get("content") or [{}])[0].get("text", "").strip().splitlines()
        first = text[0] if text else ""
        if result.get("isError"):
            print(f"{RED}✗ {label}  →  {first}{RESET}")
        else:
            print(f"{GREEN}✓ {label}{RESET}  {DIM}{first[:70]}{RESET}")

    print(f"\n{BOLD}Task finished.{RESET}")


if __name__ == "__main__":
    main()
