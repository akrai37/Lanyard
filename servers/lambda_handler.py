"""AWS Lambda entry point for the mock MCP tool servers.

The gateway invokes these functions directly with a JSON-RPC message; they have no public URL,
so the only way to reach a tool is through Lanyard. LANYARD_TOOL_SERVER selects files or deploy.
"""

import asyncio
import os
import shutil
from pathlib import Path

from mcp import Client

SERVER = os.environ.get("LANYARD_TOOL_SERVER", "files")

if SERVER == "files":
    if not os.environ.get("FILES_BUCKET"):
        # No S3 bucket configured: the package is read-only, so use a writable local copy.
        tmp = Path("/tmp/sandbox")
        if not tmp.exists():
            shutil.copytree(Path(__file__).parent / "sandbox", tmp)
        os.environ["FILES_SANDBOX"] = str(tmp)
    from servers.files_server import mcp as server
else:
    from servers.deploy_server import mcp as server


async def _handle(msg: dict) -> dict:
    method, params, rid = msg.get("method"), msg.get("params") or {}, msg.get("id")
    async with Client(server) as client:
        if method == "tools/list":
            result = await client.list_tools()
        elif method == "tools/call":
            result = await client.call_tool(params["name"], params.get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unsupported: {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result.model_dump(by_alias=True, exclude_none=True, mode="json")}


def handler(event, context):
    return asyncio.run(_handle(event))
