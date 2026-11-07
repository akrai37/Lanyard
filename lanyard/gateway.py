"""Lanyard gateway: an MCP endpoint that authenticates agents and authorizes every tool call.

Agents connect to POST /mcp with an Auth0 access token. For each JSON-RPC message the gateway:
  1. verifies the token (signature via Auth0 JWKS, issuer, audience, expiry)
  2. checks whether the agent (Auth0 client_id) has been revoked
  3. for tools/list, returns only the tools the agent may use
  4. for tools/call, checks the tool's required scope and admin blocks, then forwards it
  5. writes every decision to the audit log
"""

import asyncio
import os
import time
from pathlib import Path

import httpx
import jwt
from dotenv import dotenv_values
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from .policy import BACKENDS, TOOL_SCOPES
from .store import SQLiteStore

ROOT = Path(__file__).resolve().parent.parent
ENV = {**dotenv_values(ROOT / ".env"), **os.environ}
DOMAIN = ENV["AUTH0_DOMAIN"]
AUDIENCE = ENV["AUTH0_AUDIENCE"]
ISSUER = f"https://{DOMAIN}/"

# Friendly names for known agents: TRUSTED_CLIENT_ID -> "trusted-agent"
AGENT_NAMES = {v: k[: -len("_CLIENT_ID")].lower() + "-agent" for k, v in ENV.items()
               if k.endswith("_CLIENT_ID") and v}

store = SQLiteStore(ENV.get("LANYARD_DB", ROOT / "lanyard.db"))
jwks = jwt.PyJWKClient(f"https://{DOMAIN}/.well-known/jwks.json", cache_keys=True, lifespan=3600)
http = httpx.AsyncClient(timeout=30)
app = FastAPI(title="Lanyard")

MCP_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
_tool_catalog: dict[str, tuple[str, dict]] = {}  # tool name -> (backend url, tool definition)


# ---------- helpers ----------

def rpc_result(rid, result, status=200):
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result}, status_code=status)


def rpc_error(rid, code, message, status=200, headers=None):
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}},
                        status_code=status, headers=headers)


def denied_tool_result(message):
    """A tool result the agent's model can read, rather than a transport failure."""
    return {"content": [{"type": "text", "text": message}], "isError": True}


async def verify_token(token: str) -> dict:
    key = await asyncio.to_thread(jwks.get_signing_key_from_jwt, token)
    return jwt.decode(token, key.key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)


async def backend_rpc(url: str, method: str, params: dict | None = None) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    r = await http.post(url, json=body, headers=MCP_HEADERS)
    r.raise_for_status()
    return r.json()


async def tool_catalog(refresh: bool = False) -> dict[str, tuple[str, dict]]:
    if refresh or not _tool_catalog:
        _tool_catalog.clear()
        for url in BACKENDS.values():
            resp = await backend_rpc(url, "tools/list")
            for tool in resp.get("result", {}).get("tools", []):
                _tool_catalog[tool["name"]] = (url, tool)
    return _tool_catalog


def tool_decision(tool: str, scopes: set[str], blocked: set[str]) -> tuple[bool, str]:
    required = TOOL_SCOPES.get(tool)
    if required is None:
        return False, f"'{tool}' is not in Lanyard policy (default deny)"
    if required not in scopes:
        return False, f"'{tool}' requires scope {required}"
    if tool in blocked:
        return False, f"'{tool}' blocked by admin"
    return True, f"scope {required}"


# ---------- MCP endpoint ----------

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    t0 = time.perf_counter()
    try:
        msg = await request.json()
    except ValueError:
        return rpc_error(None, -32700, "parse error", status=400)
    if isinstance(msg, list):
        return rpc_error(None, -32600, "batch requests are not supported", status=400)

    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    tool = params.get("name") if method == "tools/call" else None

    # 1. authenticate
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return rpc_error(rid, -32001, "missing bearer token", status=401,
                         headers={"WWW-Authenticate": 'Bearer realm="lanyard"'})
    try:
        claims = await verify_token(auth[7:].strip())
    except Exception as e:  # any verification failure is a 401
        store.log(agent_id="unknown", agent_name="unknown", method=method or "?", tool=tool,
                  decision="deny", reason=f"invalid token: {e}")
        return rpc_error(rid, -32001, f"invalid token: {e}", status=401,
                         headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})

    agent_id = claims.get("azp") or claims["sub"]
    name = AGENT_NAMES.get(agent_id, agent_id[:10])
    scopes = set(claims.get("scope", "").split())
    store.seen_agent(agent_id, name, sorted(scopes))

    def log(decision, reason, **detail):
        store.log(agent_id=agent_id, agent_name=name, method=method, tool=tool, decision=decision,
                  reason=reason, latency_ms=int((time.perf_counter() - t0) * 1000), detail=detail)

    # notifications (no id) need no response body
    if rid is None:
        return Response(status_code=202)

    # 2. revocation: checked on every request, even though the token is still valid
    rev = store.revocation(agent_id)
    if rev:
        secs_left = int(claims["exp"] - time.time())
        log("deny", f"agent revoked ({rev['reason']}); token still valid for {secs_left}s")
        return rpc_error(rid, -32003, f"Lanyard: access revoked for {name}", status=403)

    if method == "initialize":
        log("allow", "session started")
        return rpc_result(rid, {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "lanyard", "version": "0.1.0"},
            "instructions": "Tools are provided through the Lanyard gateway. Access is enforced per agent.",
        })

    if method == "ping":
        return rpc_result(rid, {})

    blocked = store.blocked_tools(agent_id)

    # 3. tools/list: only show what this agent may call
    if method == "tools/list":
        catalog = await tool_catalog(refresh=True)
        visible = [t for n, (_, t) in catalog.items() if tool_decision(n, scopes, blocked)[0]]
        log("allow", f"{len(visible)} of {len(catalog)} tools visible",
            visible=[t["name"] for t in visible])
        return rpc_result(rid, {"tools": visible})

    # 4. tools/call: authorize, then forward
    if method == "tools/call":
        ok, reason = tool_decision(tool, scopes, blocked)
        if not ok:
            log("deny", reason, arguments=params.get("arguments"))
            return rpc_result(rid, denied_tool_result(f"Lanyard denied this call: {reason}."))
        catalog = await tool_catalog()
        if tool not in catalog:
            catalog = await tool_catalog(refresh=True)
        if tool not in catalog:
            log("deny", f"'{tool}' not found on any backend")
            return rpc_error(rid, -32602, f"unknown tool: {tool}")
        try:
            resp = await backend_rpc(catalog[tool][0], "tools/call", params)
        except httpx.HTTPError as e:
            log("error", f"backend error: {e}")
            return rpc_error(rid, -32603, f"backend error: {e}")
        log("allow", reason, arguments=params.get("arguments"))
        return JSONResponse(resp | {"id": rid})

    return rpc_error(rid, -32601, f"method not supported: {method}")


@app.get("/mcp")
async def mcp_get():
    # We do not offer a server-initiated SSE stream; the spec allows 405 here.
    return Response(status_code=405)


@app.delete("/mcp")
async def mcp_delete():
    return Response(status_code=204)


# ---------- admin API (dashboard) ----------

@app.get("/api/state")
async def state(after: int = 0):
    agents = []
    for a in store.agents():
        scopes = set(a["scopes"].split())
        blocked = store.blocked_tools(a["agent_id"])
        tools = []
        for t, scope in TOOL_SCOPES.items():
            if scope not in scopes:
                status = "no-scope"
            elif t in blocked:
                status = "blocked"
            else:
                status = "allowed"
            tools.append({"name": t, "scope": scope, "status": status})
        agents.append(a | {"revoked": store.revocation(a["agent_id"]), "tools": tools})
    return {"agents": agents, "events": store.events(after)}


@app.post("/api/agents/{agent_id}/revoke")
async def revoke(agent_id: str):
    store.revoke(agent_id)
    store.log(agent_id=agent_id, agent_name=AGENT_NAMES.get(agent_id, agent_id[:10]), method="admin",
              tool=None, decision="admin", reason="agent revoked")
    return {"ok": True}


@app.post("/api/agents/{agent_id}/restore")
async def restore(agent_id: str):
    store.restore(agent_id)
    store.log(agent_id=agent_id, agent_name=AGENT_NAMES.get(agent_id, agent_id[:10]), method="admin",
              tool=None, decision="admin", reason="access restored")
    return {"ok": True}


@app.post("/api/agents/{agent_id}/tools/{tool}/toggle")
async def toggle_tool(agent_id: str, tool: str):
    now_blocked = store.toggle_tool_block(agent_id, tool)
    store.log(agent_id=agent_id, agent_name=AGENT_NAMES.get(agent_id, agent_id[:10]), method="admin",
              tool=tool, decision="admin", reason="tool blocked" if now_blocked else "tool unblocked")
    return {"blocked": now_blocked}


@app.get("/")
async def dashboard():
    return FileResponse(Path(__file__).parent / "dashboard.html")
