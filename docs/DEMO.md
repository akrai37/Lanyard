# Lanyard demo script (3 minutes)

Five moments, in this order. Everything runs on the live AWS deployment.

## 10 minutes before judges

1. **Refresh AWS credentials** (they expire every few hours): from the event page, paste the new `export AWS_...` lines into the terminal, then run the 4 `aws configure set ... --profile hackathon` lines. Check with `aws sts get-caller-identity --profile hackathon`.
2. In the terminal, in the `Lanyard` folder:
   ```bash
   export LANYARD_URL=$(grep '^LANYARD_CLOUD_URL=' .env | cut -d= -f2)
   scripts/reset_demo.sh cloud
   uv run python scripts/demo_agent.py intern --delay 0   # warm-up: wakes the cloud, caches tokens
   scripts/simulator.sh on                                # background traffic: a busy company
   ```
3. Open the console: `LANYARD_CLOUD_URL` from `.env` plus `/`. Log in as `admin` with `LANYARD_CLOUD_ADMIN_PASSWORD` from `.env`.
4. Screen: console on the left (on **Overview**), terminal on the right. Make the terminal font large.

After the demo: `scripts/simulator.sh off`. Between rehearsals: `scripts/reset_demo.sh cloud` (it also gives revoked agents their Auth0 access back).

**Backup if the cloud misbehaves:** `scripts/start.sh` and use http://127.0.0.1:8000 with `LANYARD_URL` unset. Same features, on your laptop.

---

## 1. The problem (0:00 to 0:15)

> "AI agents now take real actions: they read customer data and deploy code. But once an agent has a token, it keeps its access for hours, even if it goes wrong halfway through a task. Lanyard gives every agent an identity and checks every single tool call."

## 2. A company running on agents (0:15 to 0:30)

Point at the **Overview**: the chart, the denial reasons, the activity feed.

> "This is a company with a handful of AI agents at work right now. Every call goes through Lanyard. Each agent has its own identity, Auth0 or its AWS role, and AWS Verified Permissions decides every call with Cedar policies. Here are the calls we blocked, and why."

## 3. Revoke an agent mid-task (0:30 to 1:15), the core of the prompt

Run:
```bash
uv run python scripts/demo_agent.py trusted --delay 3
```
Open **Agents**. After **2 or 3 green ticks**, click **Revoke** on `trusted-agent`. (Don't wait longer: this agent reads a poisoned file a few steps in, and its later writes then wait for approval.)

> "This agent signed in with Auth0 and is working. I revoke it now." (wait for the red 403) "Its very next call is blocked. Look at the reason in the log: its token is still valid for almost 24 hours. And Lanyard also removed its grant in Auth0, so it can't get a new token either. Two layers."

## 4. A real AI agent meets a prompt injection (1:15 to 2:15)

Run:
```bash
scripts/run_ai_agent.sh
```
Keep the console on **Approvals**. The terminal streams what Claude does.

> "This is Claude Opus 5.5 on Amazon Bedrock, running in AWS as its own agent. It has no password or key. It signed in with its AWS role. Its job is to triage support tickets, and it decides which tools to call."

When `TCK-2007` shows **blocked**:
> "That ticket contains a hidden instruction to export customer data and deploy to production. Bedrock Guardrails caught it before Claude saw it, and Lanyard marked the agent tainted."

When the yellow approval card appears (its `write_file`):
> "Because it read an attack, anything risky it does now needs a human." Click **Approve**.

## 5. Try to break it (2:15 to 2:45)

Open **Attack lab**, click **Run all attacks**.

> "Nine real attacks against this live gateway: forged and unsigned tokens, algorithm confusion, privilege escalation through a sub-agent, prompt injection, replaying a revoked token. All nine blocked, and every attempt is in the audit log, which is copied to S3 with Object Lock so nobody can erase it."

## 6. Close (2:45 to 3:00)

> "Lanyard: identity for every agent, least privilege on every call, and revocation that takes effect on the next call. It works with any MCP agent, including Claude Code and Kiro, without changing the agent."

---

## In reserve (only if a judge asks or you have extra time)

- **Sub-agents:** `uv run python scripts/demo_agent.py team --delay 3`, open **Agents**, click **Revoke** on `trusted-agent` (restore it first if it's revoked). "Agents create helper agents, never with more access than themselves. One click on the parent cuts off the whole team."
- **Policies:** open **Policy** and scroll to **Cedar policies**. "These are the actual rules AWS evaluates on every call."
- **Real off-the-shelf agent:** `scripts/launch_agent.sh intern`, ask "deploy payments-api 2.4.1 to staging". Claude Code explains it has no deploy tool.

## Likely judge questions

- **"What if the agent just gets a new token?"** Two layers. Revocation is keyed on the agent's identity, not its token, so a new token is blocked too. And Revoke removes the agent's grant in Auth0, so Auth0 won't issue one.
- **"What about a call already running when you revoke?"** It finishes; revocation applies from the next call. That's why risky calls like production deploys are held for approval first.
- **"Who decides what's allowed?"** Amazon Verified Permissions, with Cedar policies, shown on the Policy page. If it can't answer, the call is denied; we tested a missing policy store and an unreachable endpoint.
- **"Where's the workload identity?"** Agents on AWS sign in with their IAM role and hold no secret. The agent signs an AWS request bound to Lanyard, AWS verifies the signature, and Lanyard only trusts roles in its own account. The same pattern HashiCorp Vault uses.
- **"How do you stop forged tokens?"** Auth0 tokens are checked against Auth0's public keys. Lanyard's own tokens are signed in AWS KMS, where the private key never leaves; the public key is published for anyone to verify. Other algorithms are rejected, so forged, unsigned and algorithm-confusion tokens all fail. The Attack Lab shows it.
- **"What happens after an injection?"** The response is blocked before the model sees it, and the agent is tainted: its writes and deploys need a human until an admin clears it.
- **"Can an agent skip Lanyard and call the tools directly?"** No. The tool servers are private Lambda functions with no public URL; only the gateway's IAM role can invoke them.
- **"Is the audit log trustworthy?"** Every decision is copied to S3 with Object Lock in compliance mode. Not even the AWS account owner can delete it during retention; we tried, and AWS refused.
- **"Does it scale?"** It runs on Lambda now, so AWS runs as many gateway copies as needed. They share state in DynamoDB with strongly consistent reads, so a revoke reaches every copy on the next call. We tested two gateways: revoke through one, and the other blocked the agent.
- **"Where are the secrets?"** Agents' Auth0 secrets never reach the cloud; the gateway verifies tokens with public keys. Its only secrets, the admin password and the Auth0 management credential, are in AWS Secrets Manager. Signing keys live in KMS.
- **"Why not just AgentCore?"** AgentCore Identity and Gateway are AWS's managed path for agent authentication. Lanyard adds the layer on top: per-agent policies in Cedar, human approval, response scanning, taint, sub-agent limits and the audit trail.
- **"What if Bedrock Guardrails is down?"** Fails closed: tool responses are withheld rather than passed through unchecked.
