#!/usr/bin/env bash
# Reset Lanyard to a clean demo state: empty audit log, no revocations, no blocks,
# no pending approvals. The dashboard reloads itself.
# Usage: scripts/reset_demo.sh           (local gateway)
#        scripts/reset_demo.sh cloud     (the AWS deployment, using LANYARD_CLOUD_* from .env)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${1:-}" = "cloud" ]; then
  URL="$(grep '^LANYARD_CLOUD_URL=' "$ROOT/.env" | cut -d= -f2)"
  PW="$(grep '^LANYARD_CLOUD_ADMIN_PASSWORD=' "$ROOT/.env" | cut -d= -f2)"
  curl -fsS -u "admin:$PW" -X POST "$URL/api/reset" >/dev/null
  echo "Lanyard (cloud) reset. Dashboard: $URL/"
else
  curl -fsS -X POST http://127.0.0.1:8000/api/reset >/dev/null
  rm -f "$ROOT/servers/sandbox/release_plan.md"
  rm -rf "$ROOT/servers/sandbox/public"
  echo "Lanyard reset. Dashboard: http://127.0.0.1:8000"
fi
