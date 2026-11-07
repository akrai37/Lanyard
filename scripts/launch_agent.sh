#!/usr/bin/env bash
# Launch Claude Code as a Lanyard-governed agent.
# Usage: scripts/launch_agent.sh trusted|intern [extra claude args...]
# Uses the local gateway by default; set LANYARD_URL (e.g. the cloud URL) to use another.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${1:-trusted}"; shift || true
export LANYARD_URL="${LANYARD_URL:-http://127.0.0.1:8000}"
export LANYARD_TOKEN="$(cd "$ROOT" && uv run python scripts/get_token.py "$AGENT")"
cd "$ROOT/agent-workspace"
exec claude --mcp-config "$ROOT/agent-workspace/mcp.json" --strict-mcp-config "$@"
