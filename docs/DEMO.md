# Lanyard demo script (about 3 minutes)

## Before judges arrive

**Use the cloud version.** It runs on AWS with its own permissions, so it keeps working when your laptop's AWS credentials expire, and you can say "this is live on AWS."

1. In the terminal, in the `Lanyard` folder, point the agent at the cloud:
   `export LANYARD_URL=$(grep '^LANYARD_CLOUD_URL=' .env | cut -d= -f2)`
2. Reset: `scripts/reset_demo.sh cloud`
3. Open the dashboard: the `LANYARD_CLOUD_URL` from `.env`, followed by `/`. Log in as `admin` with the `LANYARD_CLOUD_ADMIN_PASSWORD` from `.env`.
4. Screen layout: dashboard on the left, the terminal on the right.
5. Warm-up run, so the cloud is warm and tokens are cached: `uv run python scripts/demo_agent.py intern --delay 0`, then `scripts/reset_demo.sh cloud` again.

In every step below, use `scripts/reset_demo.sh cloud` instead of `scripts/reset_demo.sh`.

**Backup (local) version:** `scripts/start.sh`, dashboard at http://127.0.0.1:8000, and don't set `LANYARD_URL`. Refresh your AWS credentials first (the 4 `aws configure set ... --profile hackathon` lines); without them, the guardrail scan withholds every tool response.

**The AWS event account is deleted after the event**, along with the cloud version. The local version always works.

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

### 5. Workload identity: an agent with no secret (40 seconds)
`scripts/reset_demo.sh cloud`, then run: `scripts/run_cloud_agent.sh`, and open the **Agents** page.
> "This agent runs inside AWS Lambda, and it has no password, no API key, nothing stored. It proved who it is with its AWS role: it signed a request, AWS confirmed the signature, and Lanyard gave it a 10-minute token. It only got read and deploy, not write."

Click **Revoke** on `aws-worker-agent` while it works. Its next call shows **Denied** on the Overview.
> "And because Lanyard issues its tokens, a revoked workload can't even sign in again."

### 6. Close (15 seconds)
> "Identity, least privilege, guardrails, human approval, instant revocation, and a full audit trail, for any MCP agent. Claude Code or Kiro can run through it unchanged."

Optional, if there's time: `scripts/launch_agent.sh intern` and ask it "deploy payments-api 2.4.1 to staging". It explains it has no deploy tool.

## Likely judge questions

- **"What if the agent just gets a new token?"** Two layers. Revocation is keyed on the agent's identity, not the token, so a new token is blocked too. And Revoke also removes the agent's grant in Auth0, so Auth0 won't issue it a token in the first place. (This needs the `lanyard-admin` Auth0 app configured; the Policy page shows whether it's on.)
- **"Where is the workload identity?"** Agents on AWS sign in with their IAM role, no stored secret. It's the same pattern HashiCorp Vault uses: the agent signs an AWS request, AWS verifies the signature, and Lanyard only trusts roles in its own account. The signature includes a Lanyard-specific header, so it can't be replayed elsewhere.
- **"How do you stop a forged token?"** Each issuer is pinned to one algorithm and key: Auth0 tokens use RS256 with Auth0's public keys; Lanyard's own tokens use HS256 with a key in AWS Secrets Manager. We tested forged tokens and tampered signatures; both are rejected.
- **"What about a call already in progress when you revoke?"** It completes; revocation applies from the next call. Holding high-risk calls for approval covers the dangerous ones.
- **"Does this scale?"** "It's running on AWS Lambda right now, which runs as many copies of the gateway as traffic needs. The gateway is stateless; revocations live in DynamoDB with strongly consistent reads, so a revoke reaches every copy on the next call. We tested two gateways: revoke through one, and the other blocked the agent immediately."
- **"Can an agent skip Lanyard and call the tools directly?"** No. The tool servers are private Lambda functions with no public URL; only the gateway's IAM role can invoke them.
- **"Where are the secrets?"** The cloud gateway has no Auth0 secrets at all. It only verifies tokens using Auth0's public keys.
- **"Why not just AgentCore?"** AgentCore Identity and Gateway are the managed AWS path for authentication. Lanyard adds the policy layer on top: per-tool admin control, human approval, response scanning and the audit trail.
- **"What if Bedrock is down?"** It fails closed: tool responses are withheld rather than passed through unchecked.
