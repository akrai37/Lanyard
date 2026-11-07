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

# Calls that also need a human to click Approve on the dashboard, even when the
# agent has the scope. A rule matches when every listed argument has that value.
APPROVAL_RULES = {
    "deploy_service": {"environment": "production"},
    "rollback_service": {"environment": "production"},
}
APPROVAL_TIMEOUT_SECONDS = 120


def needs_approval(tool: str, arguments: dict) -> bool:
    rule = APPROVAL_RULES.get(tool)
    return rule is not None and all(arguments.get(k) == v for k, v in rule.items())
