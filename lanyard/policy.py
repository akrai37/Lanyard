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

# Workload identities: AWS IAM roles that may sign in without any stored secret.
# Only roles in LANYARD_AWS_ACCOUNT (set in the environment) are accepted.
WORKLOAD_IDENTITIES = {
    # An agent running on AWS Lambda with its own role
    "lanyard-worker-role": {"name": "aws-worker-agent", "scopes": ["files:read", "deploy:run"]},
    # The hackathon participant role, so a laptop with event credentials can demo the flow
    "WSParticipantRole": {"name": "laptop-aws-agent", "scopes": ["files:read"]},
}


def needs_approval(tool: str, arguments: dict) -> bool:
    rule = APPROVAL_RULES.get(tool)
    return rule is not None and all(arguments.get(k) == v for k, v in rule.items())

# Tools needing these scopes are "risky": once an agent is tainted (it has read a prompt
# injection), any risky call needs human approval until an admin clears the taint.
RISKY_SCOPES = {"files:write", "deploy:run"}

# Sub-agents: how many levels deep an agent may delegate (root agent counts as 1).
MAX_DELEGATION_DEPTH = 3
