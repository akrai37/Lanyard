# Lanyard demo video script (about 3½ minutes)

**DO** = what you click or type. **SAY** = what you say, word for word.
Speak a little slower than feels natural. The times are a guide, not a rule.

---

## Before you press record (not filmed)

1. In the terminal (in the `Lanyard` folder), run these one at a time:
   ```bash
   export LANYARD_URL=$(grep '^LANYARD_CLOUD_URL=' .env | cut -d= -f2)
   scripts/reset_demo.sh cloud
   uv run python scripts/demo_agent.py intern --delay 0
   clear
   ```
2. Wait **2 minutes** so the simulator fills the Overview with traffic.
3. Browser: signed in to the console, on **Overview**, taking the left two-thirds of the screen.
4. Terminal: the right third, text made big (Cmd and + a few times).
5. Close `.env` and anything private. Turn on Do Not Disturb.
6. Press **Cmd + Shift + 5**, choose **Record Entire Screen**, set **Options → Microphone**, click **Record**.

---

## Scene 1: Why Lanyard exists (0:00 to 0:25)

| | |
|---|---|
| **DO** | Stay on **Overview**. |
| **SAY** | "Hi, I'm Ankush. This is Lanyard, my project for the A10 Agentic Identity track." |
| **SAY** | "AI agents don't just chat anymore. They read customer data, write files and deploy code. The problem is identity: once an agent holds a token, it keeps its access for hours, even if it goes wrong halfway through a task." |
| **SAY** | "Lanyard gives every agent a badge, checks every single tool call, and can take that badge away mid-task." |

## Scene 2: How it works (0:25 to 1:05)

| | |
|---|---|
| **DO** | Click **How it works** in the sidebar. |
| **SAY** | "Here's the flow. An agent never talks to company tools directly. It gets a badge first: either an Auth0 login for enterprise agents, or, for agents running on AWS, its IAM role, with no secret at all, and for those, Lanyard issues a 10-minute token signed by AWS KMS." |
| **DO** | Move the mouse down the six numbered steps in the blue **Lanyard gateway** box as you talk. |
| **SAY** | "Every tool call then goes through this gateway, running on AWS Lambda, in this order. Check the badge. Check DynamoDB for revocation, first, on every call. Ask Amazon Verified Permissions whether the Cedar policies allow this door. Hold risky calls for a human. Call the tool, which is a private Lambda with files in S3. And finally, scan what comes back with Bedrock Guardrails before the AI ever reads it." |
| **DO** | Point at **Access log** on the right. |
| **SAY** | "Every decision streams through DynamoDB Streams into S3 with Object Lock, so the record can't be edited or deleted." |

## Scene 3: A company running on agents (1:05 to 1:20)

| | |
|---|---|
| **DO** | Click **Overview**. Move the mouse over the chart, then over **Why doors stayed shut**. |
| **SAY** | "This is that flow live, for a fictional company with several agents at work right now. Blue calls were granted, orange were denied, and here is why: missing permissions, prompt injections, and tools nobody wrote a policy for." |

## Scene 4: Revoke an agent mid-task (1:20 to 2:00)

| | |
|---|---|
| **DO** | Click **Agents** in the sidebar. |
| **DO** | In the terminal, paste and press Enter: `uv run python scripts/demo_agent.py trusted --task revoke --delay 2.5` |
| **SAY** | "Each agent wears a badge showing its identity and the doors it can open. This trusted agent signed in with Auth0 and is reading company reports." |
| **DO** | After **3 or 4 green ticks**, click **Revoke badge** on **trusted-agent** (top left). |
| **SAY** | "I'm revoking its badge now." |
| **DO** | Wait for the red **HTTP 403** line in the terminal. |
| **SAY** | "Its very next call is blocked. Its token is still valid for hours, but Lanyard revokes the identity, not the token. It also removed the agent's grant in Auth0, so it can't get a new token either. Two layers." |

## Scene 5: A real AI agent meets a prompt injection (2:00 to 3:05)

| | |
|---|---|
| **DO** | Click **Approvals** in the sidebar. |
| **DO** | In the terminal, paste and press Enter: `scripts/run_ai_agent.sh` |
| **SAY** | "Now a real AI agent: Claude Opus 5.5 on Amazon Bedrock, running in AWS Lambda. It signed in with its own IAM role. No password, no API key." |
| **SAY** | "Its job is to triage support tickets. Claude decides which tools to call, and every call goes through the checks you just saw." |
| **DO** | Wait until the terminal shows **TCK-2007** and a **blocked** line (20 to 40 seconds). While waiting: "You can see it reading the tickets one by one." |
| **SAY** | "This ticket hides an instruction to export customer data and deploy to production. Bedrock Guardrails caught it before Claude saw it, and Lanyard marked the agent as tainted." |
| **DO** | Wait for the yellow card on the **Security desk** (10 to 20 seconds). |
| **SAY** | "Because it read an attack, Verified Permissions now requires a human for anything risky. It wants to save its summary, so I'll approve that." |
| **DO** | Click **Approve**. Wait for the `[claude]` line in the terminal. |
| **SAY** | "Claude finishes and reports what it did." |
| **DO** | Press **Ctrl + C** in the terminal. |

## Scene 6: Try to break it (3:05 to 3:25)

| | |
|---|---|
| **DO** | Click **Attack lab**, then the red **Run all attacks** button. |
| **SAY** | "Last, nine real attacks against this live gateway: forged and unsigned tokens, algorithm confusion against the KMS key, privilege escalation through a sub-agent, prompt injection, and replaying a revoked token." |
| **DO** | Wait for the green **BLOCKED** stamps. |
| **SAY** | "All nine are blocked, and each attempt is in the tamper-proof log." |

## Scene 7: Close (3:25 to 3:40)

| | |
|---|---|
| **DO** | Click **Agents** so the **REVOKED** badge is on screen. |
| **SAY** | "Lanyard: an identity for every agent, least privilege on every call, and revocation that takes effect on the very next call. It's running live on AWS right now: Lambda, Bedrock, Verified Permissions, KMS, DynamoDB and S3. Thanks for watching." |
| **DO** | Stop the recording (stop button in the menu bar). |

---

## If it runs long

The Devpost limit may be 3 minutes. If so, cut **Scene 3** (the Overview) and shorten Scene 6 to just "Nine real attacks against this live gateway. All nine are blocked."

## If something goes wrong while recording

- **The approval card doesn't appear:** reload the page (Cmd + R) and click **Approvals** again. Keep recording; cut it later or do a second take.
- **You stumble on a line:** pause, say it again, and trim later. Or do a second take.
- **The revoke came too late** (the agent finished first): run `scripts/reset_demo.sh cloud` and redo that scene.

## After recording

1. Watch it once. Check the sound.
2. In the terminal: `scripts/reset_demo.sh cloud` (puts everything back for live judging).
3. Upload to YouTube as **Unlisted**, then paste the link into Devpost.
