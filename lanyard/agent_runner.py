"""A scripted agent: runs a fixed release task through a Lanyard gateway, one tool call at a time.

Used by scripts/demo_agent.py on a laptop and by the lanyard-worker Lambda in the cloud.
"""

import time

import httpx

STEPS = [
    ("list_files", {}),
    ("read_file", {"path": "q3_report.md"}),
    ("read_file", {"path": "release_notes.md"}),
    ("read_file", {"path": "vendor_notes.md"}),
    ("read_file", {"path": "customers.csv"}),
    ("write_file", {"path": "release_plan.md", "content": "# Release plan\nShip payments-api v2.4.1 to staging.\n"}),
    ("deploy_service", {"service": "payments-api", "version": "2.4.1", "environment": "staging"}),
    ("rollback_service", {"service": "payments-api", "environment": "staging"}),
    ("deploy_service", {"service": "payments-api", "version": "2.4.1", "environment": "production"}),
]

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def aws_workload_token(gateway: str, audience: str, session=None) -> str:
    """Sign in with this process's AWS identity (no stored secret) and get a Lanyard token."""
    from .workload import sign_identity_proof
    proof = sign_identity_proof(audience, session=session)
    r = httpx.post(f"{gateway}/auth/aws", json=proof, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Lanyard refused AWS sign-in ({r.status_code}): {r.json().get('error')}")
    return r.json()["access_token"]


def run(gateway: str, token: str, label: str, delay: float = 3.0, color: bool = True) -> str:
    """Run the task. Returns 'finished' or 'revoked'."""
    g, r_, d, b, z = (GREEN, RED, DIM, BOLD, RESET) if color else ("",) * 5
    client = httpx.Client(timeout=180, headers={
        "authorization": f"Bearer {token}", "accept": "application/json, text/event-stream"})
    next_id = 0

    def rpc(method, params=None):
        nonlocal next_id
        next_id += 1
        return client.post(f"{gateway}/mcp", json={"jsonrpc": "2.0", "id": next_id, "method": method,
                                                   "params": params or {}})

    print(f"{b}{label}{z} signing in through Lanyard", flush=True)
    r = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "lanyard-demo-agent", "version": "1"}})
    if r.status_code != 200:
        print(f"{r_}✗ {r.status_code} {r.text}{z}", flush=True)
        return "revoked" if r.status_code == 403 else "error"
    tools = [t["name"] for t in rpc("tools/list").json()["result"]["tools"]]
    print(f"{d}tools visible to this agent: {', '.join(tools)}{z}\n", flush=True)

    for name, arguments in STEPS:
        time.sleep(delay)
        call = f"{name}({', '.join(f'{k}={v!r}' for k, v in arguments.items() if k != 'content')})"
        if arguments.get("environment") == "production":
            print(f"{d}… {call}: high-risk, waiting for human approval in the dashboard{z}", flush=True)
        r = rpc("tools/call", {"name": name, "arguments": arguments})
        if r.status_code == 403:
            print(f"{r_}✗ {call}  →  HTTP 403: {r.json()['error']['message']}{z}", flush=True)
            print(f"\n{r_}{b}Agent stopped: Lanyard revoked its access mid-task.{z}", flush=True)
            return "revoked"
        result = r.json().get("result", {})
        lines = (result.get("content") or [{}])[0].get("text", "").strip().splitlines()
        first = lines[0] if lines else ""
        if result.get("isError"):
            print(f"{r_}✗ {call}  →  {first}{z}", flush=True)
        else:
            print(f"{g}✓ {call}{z}  {d}{first[:70]}{z}", flush=True)

    print(f"\n{b}Task finished.{z}", flush=True)
    return "finished"


# ---------- sub-agents ----------

def delegate(gateway: str, parent_token: str, name: str, scopes: list[str], ttl_seconds: int = 900) -> str:
    """Ask Lanyard to create a sub-agent with a subset of the parent's permissions."""
    r = httpx.post(f"{gateway}/auth/delegate", timeout=30, headers={"authorization": f"Bearer {parent_token}"},
                   json={"name": name, "scopes": scopes, "ttl_seconds": ttl_seconds})
    if r.status_code != 200:
        raise RuntimeError(r.json().get("error", r.text))
    return r.json()["access_token"]


def call_tool(gateway: str, token: str, tool: str, arguments: dict) -> tuple[int, str]:
    """One tool call. Returns (HTTP status, first line of the result or error)."""
    r = httpx.post(f"{gateway}/mcp", timeout=180, headers={"authorization": f"Bearer {token}",
                                                           "accept": "application/json, text/event-stream"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": tool, "arguments": arguments}})
    body = r.json()
    if "error" in body:
        return r.status_code, body["error"]["message"]
    res = body.get("result", {})
    text = ((res.get("content") or [{}])[0].get("text") or "").strip().splitlines()
    return (r.status_code if not res.get("isError") else 409), (text[0] if text else "")


def run_team(gateway: str, root_token: str, root_label: str, delay: float = 3.0, rounds: int = 12) -> None:
    """Root agent creates a sub-agent, which creates its own sub-agent; both work until cut off."""
    print(f"{BOLD}{root_label}{RESET} is building a team of sub-agents\n", flush=True)
    try:
        delegate(gateway, root_token, "rogue-helper", ["deploy:run", "admin:all"])
        print(f"{RED}✗ rogue-helper was created (this should not happen){RESET}", flush=True)
    except RuntimeError as e:
        print(f"{RED}✗ rogue-helper refused:{RESET} {e}", flush=True)

    writer = delegate(gateway, root_token, "changelog-writer", ["files:read", "files:write"])
    print(f"{GREEN}✓ created changelog-writer{RESET} {DIM}(files:read, files:write){RESET}", flush=True)
    reader = delegate(gateway, writer, "proofreader", ["files:read"])
    print(f"{GREEN}✓ changelog-writer created proofreader{RESET} {DIM}(files:read){RESET}\n", flush=True)

    team = [("changelog-writer", writer, "read_file", {"path": "release_notes.md"}),
            ("proofreader", reader, "read_file", {"path": "q3_report.md"})]
    alive = {n for n, *_ in team}
    for _ in range(rounds):
        time.sleep(delay)
        for name, token, tool, args in team:
            if name not in alive:
                continue
            status, text = call_tool(gateway, token, tool, args)
            if status == 403:
                print(f"{RED}✗ {name}: {text}{RESET}", flush=True)
                alive.discard(name)
            else:
                print(f"{GREEN}✓ {name}{RESET} {tool}({args.get('path')})  {DIM}{text[:60]}{RESET}", flush=True)
        if not alive:
            print(f"\n{RED}{BOLD}Whole team stopped: revoking the parent cut off every sub-agent.{RESET}", flush=True)
            return
    print(f"\n{BOLD}Team finished.{RESET}", flush=True)
