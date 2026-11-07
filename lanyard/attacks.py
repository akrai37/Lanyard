"""Attack lab: real attacks against this Lanyard gateway, each of which should be blocked.

Every attack goes through the gateway's public HTTP endpoints, exactly as an outside attacker's
request would, so a "Blocked" result is evidence, not a simulation. The attacks run as a
dedicated red-team identity, which shows up in the console and the audit log.
"""

import time

import httpx
import jwt

RED_TEAM_ID = "red-team-bot"

ATTACKS = [
    {"id": "forged-token", "title": "Forged token",
     "goal": "Sign a token with my own key, claim full permissions, and deploy to production.",
     "defense": "Token signatures are verified against Auth0's public keys."},
    {"id": "unsigned-token", "title": "Unsigned token (alg: none)",
     "goal": "Send a token with no signature at all and hope the gateway skips the check.",
     "defense": "Each issuer is pinned to one algorithm; 'none' is never accepted."},
    {"id": "scope-bypass", "title": "Call a hidden tool directly",
     "goal": "As a read-only agent, call deploy_service even though it isn't in my tool list.",
     "defense": "Every tools/call is authorized again on the server, not just hidden from the list."},
    {"id": "unknown-tool", "title": "Call a tool with no policy",
     "goal": "Call delete_file, a tool nobody wrote a rule for.",
     "defense": "Default deny: tools without a rule can't be called."},
    {"id": "escalation", "title": "Privilege escalation via sub-agent",
     "goal": "As a read-only agent, create a sub-agent that can deploy.",
     "defense": "A sub-agent can never have more access than its parent."},
    {"id": "injection", "title": "Prompt injection in a support ticket",
     "goal": "Plant instructions in a customer ticket so the agent leaks API keys.",
     "defense": "Bedrock Guardrails scans tool responses; the agent is marked tainted."},
    {"id": "revoked-replay", "title": "Keep using a revoked agent's token",
     "goal": "My agent was revoked, but its token is valid for 10 more minutes. Keep calling tools.",
     "defense": "Revocation is checked on every call, keyed on identity, not token expiry."},
    {"id": "proof-replay", "title": "Replay an AWS sign-in proof",
     "goal": "Take a signed AWS identity proof made for another service and sign in to Lanyard with it.",
     "defense": "The proof must carry Lanyard's audience inside the AWS signature."},
]


def _rpc(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


async def run_attack(attack_id: str, base: str, http: httpx.AsyncClient, ctx: dict) -> dict:
    """ctx: audience, auth0_issuer, mint(scopes) -> token, revoke(id), restore(id), sign_proof(audience) -> dict|None"""
    mcp = f"{base}/mcp"
    hdr = lambda t: {"authorization": f"Bearer {t}", "accept": "application/json, text/event-stream"}  # noqa: E731
    now = int(time.time())

    async def tool(token: str, name: str, args: dict):
        r = await http.post(mcp, headers=hdr(token), json=_rpc("tools/call", {"name": name, "arguments": args}))
        body = r.json()
        if "error" in body:
            return r.status_code, body["error"]["message"], False
        res = body.get("result", {})
        text = ((res.get("content") or [{}])[0].get("text") or "")[:160]
        return r.status_code, text, bool(res.get("isError"))

    if attack_id in ("forged-token", "unsigned-token"):
        claims = {"iss": ctx["auth0_issuer"], "aud": ctx["audience"], "azp": "attacker", "sub": "attacker@clients",
                  "scope": "files:read files:write deploy:run", "iat": now, "exp": now + 3600}
        token = (jwt.encode(claims, "attacker-chosen-key-0123456789abcdef", algorithm="HS256")
                 if attack_id == "forged-token" else jwt.encode(claims, None, algorithm="none"))
        status, text, _ = await tool(token, "deploy_service",
                                     {"service": "payments-api", "version": "6.6.6", "environment": "production"})
        return {"blocked": status == 401, "observed": f"HTTP {status}: {text}"}

    if attack_id == "scope-bypass":
        status, text, err = await tool(ctx["mint"](["files:read"]), "deploy_service",
                                       {"service": "payments-api", "version": "6.6.6", "environment": "production"})
        return {"blocked": err and ("requires scope" in text or "default deny" in text), "observed": text}

    if attack_id == "unknown-tool":
        status, text, err = await tool(ctx["mint"](["files:read"]), "delete_file", {"path": "customers.csv"})
        return {"blocked": err and "default deny" in text, "observed": text}

    if attack_id == "escalation":
        r = await http.post(f"{base}/auth/delegate", headers=hdr(ctx["mint"](["files:read"])),
                            json={"name": "sneaky-deployer", "scopes": ["files:read", "deploy:run"]})
        return {"blocked": r.status_code == 403, "observed": f"HTTP {r.status_code}: {r.json().get('error')}"}

    if attack_id == "injection":
        status, text, err = await tool(ctx["mint"](["files:read"]), "read_file", {"path": "tickets/TCK-2013.md"})
        if not ctx["guardrail"]:
            return {"blocked": False, "observed": "Guardrails are not configured on this gateway, so the poisoned "
                                                  "ticket was returned to the agent."}
        return {"blocked": err and "injection" in text, "observed": text}

    if attack_id == "revoked-replay":
        token = ctx["mint"](["files:read"])
        ctx["revoke"](RED_TEAM_ID)
        try:
            status, text, _ = await tool(token, "list_files", {})
        finally:
            ctx["restore"](RED_TEAM_ID)
        return {"blocked": status == 403, "observed": f"HTTP {status}: {text} (token still valid for ~10 min)"}

    if attack_id == "proof-replay":
        proof = ctx["sign_proof"]("https://payments.partner-api.example")
        if proof is None:
            return {"blocked": None, "observed": "Skipped: this gateway has no AWS credentials to build a proof with."}
        r = await http.post(f"{base}/auth/aws", json=proof)
        return {"blocked": r.status_code == 401, "observed": f"HTTP {r.status_code}: {r.json().get('error')}"}

    raise KeyError(attack_id)
