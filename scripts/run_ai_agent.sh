#!/usr/bin/env bash
# Start the AI agent (Claude Opus 5.5 on Bedrock, lanyard-ai-agent Lambda) and stream what it does.
# It signs in to Lanyard with its IAM role; watch its calls in the console. Ctrl+C stops the log, not the agent.
# Usage: scripts/run_ai_agent.sh ["optional task text"]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="$(grep '^AWS_PROFILE=' "$ROOT/.env" | cut -d= -f2)"
A=(--profile "${PROFILE:-default}" --region us-east-1)
PAYLOAD='{}'
[ $# -gt 0 ] && PAYLOAD="$(python3 -c 'import json,sys; print(json.dumps({"task": sys.argv[1]}))' "$1")"
aws lambda invoke --function-name lanyard-ai-agent --invocation-type Event --cli-binary-format raw-in-base64-out \
  --payload "$PAYLOAD" "${A[@]}" /dev/null >/dev/null
echo "AI agent started (Claude Opus 5.5 on Amazon Bedrock). Live output:"
# Filter on the AWS side (no pipe), so lines appear as soon as the agent writes them.
aws logs tail /aws/lambda/lanyard-ai-agent --since 10s --follow --format short "${A[@]}" \
  --filter-pattern '?"[claude]" ?"[tool]" ?"[lanyard]"'
