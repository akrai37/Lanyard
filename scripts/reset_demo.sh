#!/usr/bin/env bash
# Reset Lanyard to a clean demo state: empty audit log, no revocations, no blocks,
# no pending approvals, and no files written by earlier runs. The dashboard reloads itself.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
curl -fsS -X POST http://127.0.0.1:8000/api/reset >/dev/null
rm -f "$ROOT/servers/sandbox/release_plan.md"
rm -rf "$ROOT/servers/sandbox/public"
echo "Lanyard reset. Dashboard: http://127.0.0.1:8000"
