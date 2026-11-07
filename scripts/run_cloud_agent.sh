#!/usr/bin/env bash
# Start the cloud agent (lanyard-worker Lambda). It signs in with its IAM role, no secret,
# and runs the release task through the cloud gateway. Watch it in the console.
# Usage: scripts/run_cloud_agent.sh [delay-seconds-between-calls]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="$(grep '^AWS_PROFILE=' "$ROOT/.env" | cut -d= -f2)"
aws lambda invoke --profile "${PROFILE:-default}" --region us-east-1 --function-name lanyard-worker \
  --invocation-type Event --cli-binary-format raw-in-base64-out \
  --payload "{\"delay\": ${1:-3}}" /dev/null >/dev/null
echo "Cloud agent started. Watch the console; it appears as aws-worker-agent."
