#!/usr/bin/env bash
# Start the two mock MCP tool servers and the Lanyard gateway. Ctrl+C stops all three.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p logs
trap 'kill 0' EXIT INT TERM
uv run python servers/files_server.py  > logs/files.log  2>&1 &
uv run python servers/deploy_server.py > logs/deploy.log 2>&1 &
sleep 2
echo "Tool servers on :8101 (files) and :8102 (deploy). Gateway and dashboard: http://127.0.0.1:8000"
uv run uvicorn lanyard.gateway:app --host 127.0.0.1 --port 8000
