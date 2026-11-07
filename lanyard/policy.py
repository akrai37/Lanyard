"""Which MCP servers sit behind Lanyard, and which scope each tool requires.

Tools not listed here are denied (default deny).
"""

BACKENDS = {
    "files": "http://127.0.0.1:8101/mcp",
    "deploy": "http://127.0.0.1:8102/mcp",
}

TOOL_SCOPES = {
    "list_files": "files:read",
    "read_file": "files:read",
    "write_file": "files:write",
    "deploy_service": "deploy:run",
    "rollback_service": "deploy:run",
}
