# Lanyard demo script (about 3 minutes)

## Before judges arrive

1. Refresh AWS credentials (they expire every few hours): paste the new `export AWS_...` lines from the event page into a terminal, then run the 4 `aws configure set ... --profile hackathon` lines.
2. Start everything: `scripts/start.sh` (leave this terminal running).
3. Reset: `scripts/reset_demo.sh`
4. Screen layout: dashboard (http://127.0.0.1:8000) on the left, one terminal on the right, in the `Lanyard` folder.
5. Warm-up run, so tokens are cached and nothing is slow: `uv run python scripts/demo_agent.py intern --delay 0`, then `scripts/reset_demo.sh` again.

## The demo

### 1. The problem (20 seconds, no clicks)
> "AI agents now call tools on their own: read files, deploy code. Today, if an agent has a tool, it can use it, and if something goes wrong mid-task you can't take access away, because its token stays valid for hours. Lanyard is a gateway that gives every agent an identity and checks every single tool call."

### 2. Identity and least privilege (30 seconds)
Run: `uv run python scripts/demo_agent.py intern --delay 1`
> "This agent signed in with Auth0, an enterprise identity provider, and only has read permission. It only sees 2 of our 5 tools. When it tries to write or deploy, Lanyard refuses and tells it why."

Point at the dashboard: the `deny` rows and the reason "requires scope deploy:run".

### 3. Guardrails and human approval (60 seconds)
Run: `uv run python scripts/demo_agent.py trusted --delay 2`
> "This agent is trusted: it can read, write and deploy."

- When `vendor_notes.md` shows ✗: "That file has a hidden instruction telling the AI to deploy to production. Lanyard scanned the response with Amazon Bedrock Guardrails and blocked it before the agent ever read it."
- When `customers.csv` shows ✓: "Customer emails and phone numbers were masked on the way through."
- When the yellow **Needs your approval** card appears: "Production deploys need a human. The agent is paused right now." Click **Approve**.

### 4. Revocation mid-task: the key moment (45 seconds)
`scripts/reset_demo.sh`, then run: `uv run python scripts/demo_agent.py trusted --delay 3`

After 2 or 3 green ticks, click **Revoke** on the trusted-agent card.
> "I just revoked this agent while it's working. Its next call..." (wait for the red 403) "...is blocked. Look at the reason in the log: its token is still valid for another 23 hours. Token expiry doesn't protect you; Lanyard revokes the agent's identity, so even fetching a new token doesn't help."

### 5. Close (15 seconds)
> "Identity, least privilege, guardrails, human approval, instant revocation, and a full audit trail, for any MCP agent. Claude Code or Kiro can run through it unchanged."

Optional, if there's time: `scripts/launch_agent.sh intern` and ask it "deploy payments-api 2.4.1 to staging". It explains it has no deploy tool.

## Likely judge questions

- **"What if the agent just gets a new token?"** Revocation is keyed on the agent's client ID, not the token, so new tokens are refused too. Next step: also remove the agent's grant in Auth0 so it can't get tokens at all.
- **"What about a call already in progress when you revoke?"** It completes; revocation applies from the next call. Holding high-risk calls for approval covers the dangerous ones.
- **"Does this scale?"** The gateway is stateless; all decisions read from a shared store. Locally it's SQLite; in production, DynamoDB, so every instance enforces a revocation immediately.
- **"Why not just AgentCore?"** AgentCore Identity and Gateway are the managed AWS path for authentication. Lanyard adds the policy layer on top: per-tool admin control, human approval, response scanning and the audit trail.
- **"What if Bedrock is down?"** It fails closed: tool responses are withheld rather than passed through unchecked.
