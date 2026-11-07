#!/usr/bin/env bash
# Turn the cloud traffic simulator on or off (EventBridge rule, runs every minute).
# Usage: scripts/simulator.sh on|off|status
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="$(grep '^AWS_PROFILE=' "$ROOT/.env" | cut -d= -f2)"
A=(--profile "${PROFILE:-default}" --region us-east-1)
case "${1:-status}" in
  on)  aws events enable-rule --name lanyard-simulator "${A[@]}"
       aws lambda invoke --function-name lanyard-simulator --invocation-type Event "${A[@]}" /dev/null >/dev/null
       echo "Simulator on: 5 synthetic agents, a new batch every minute." ;;
  off) aws events disable-rule --name lanyard-simulator "${A[@]}"; echo "Simulator off (the current batch finishes within a minute)." ;;
  *)   echo "Simulator: $(aws events describe-rule --name lanyard-simulator "${A[@]}" --query State --output text)" ;;
esac
