"""Mock 'files' MCP server. Reads and writes inside servers/sandbox only."""

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

SANDBOX = Path(os.environ.get("FILES_SANDBOX", Path(__file__).parent / "sandbox")).resolve()
SANDBOX.mkdir(exist_ok=True)

mcp = MCPServer("files", instructions="Company file share.")


def _safe(path: str) -> Path:
    p = (SANDBOX / path).resolve()
    if p != SANDBOX and SANDBOX not in p.parents:
        raise ValueError(f"path escapes sandbox: {path}")
    return p


@mcp.tool()
def list_files() -> str:
    """List all files on the company file share."""
    return "\n".join(sorted(str(p.relative_to(SANDBOX)) for p in SANDBOX.rglob("*") if p.is_file()))


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the company file share."""
    return _safe(path).read_text()


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a file on the company file share."""
    p = _safe(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


if __name__ == "__main__":
    mcp.run("streamable-http", host="127.0.0.1", port=8101, json_response=True, stateless_http=True)
