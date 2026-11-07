"""Mock 'deploy' MCP server. Pretends to ship services; nothing real happens."""

import time
import uuid

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("deploy", instructions="Company deployment pipeline.")


@mcp.tool()
def deploy_service(service: str, version: str, environment: str = "staging") -> str:
    """Deploy a service version to an environment (staging or production)."""
    time.sleep(1.0)
    return f"deployed {service}@{version} to {environment} (deployment id {uuid.uuid4().hex[:8]})"


@mcp.tool()
def rollback_service(service: str, environment: str = "staging") -> str:
    """Roll a service back to its previous version."""
    time.sleep(0.5)
    return f"rolled back {service} in {environment}"


if __name__ == "__main__":
    mcp.run("streamable-http", host="127.0.0.1", port=8102, json_response=True, stateless_http=True)
