#!/usr/bin/env bash
# Launch Claude Code as a Lanyard-governed agent.
# Usage: scripts/launch_agent.sh trusted|intern [extra claude args...]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${1:-trusted}"; shift || true
export LANYARD_TOKEN="$(cd "$ROOT" && uv run python scripts/get_token.py "$AGENT")"
cd "$ROOT/agent-workspace"
exec claude --mcp-config "$ROOT/agent-workspace/mcp.json" --strict-mcp-config "$@"
