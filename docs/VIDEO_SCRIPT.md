# Lanyard demo video script (about 3½ minutes)

DO  = what you click or type
SAY = what you say, word for word

Speak a little slower than feels natural.


====================================================================
BEFORE YOU PRESS RECORD (not filmed)
====================================================================

1. In the terminal, run these one at a time:

   export LANYARD_URL=$(grep '^LANYARD_CLOUD_URL=' .env | cut -d= -f2)
   scripts/reset_demo.sh cloud
   uv run python scripts/demo_agent.py intern --delay 0
   clear

2. Wait 2 minutes so the Overview fills with traffic.
3. Browser on the left (signed in, on Overview). Terminal on the right, text made big (Cmd and +).
4. Close .env and anything private. Turn on Do Not Disturb.
5. Press Cmd + Shift + 5 → Record Entire Screen → Options → Microphone → Record.


====================================================================
SCENE 1 · WHY LANYARD EXISTS (0:00 to 0:25)
====================================================================

DO:  Stay on Overview.

SAY: "Hi, I'm Ankush. This is Lanyard, my project for the A10 Agentic Identity track."

SAY: "AI agents don't just chat anymore. They read customer data, write files and deploy code.
      The problem is identity: once an agent holds a token, it keeps its access for hours,
      even if it goes wrong halfway through a task."

SAY: "Lanyard gives every agent a badge, checks every single tool call,
      and can take that badge away mid-task."


====================================================================
SCENE 2 · HOW IT WORKS (0:25 to 1:05)
====================================================================

DO:  Click "How it works" in the sidebar.

SAY: "Here's the flow. An agent never talks to company tools directly. It gets a badge first:
      either an Auth0 login for enterprise agents, or, for agents running on AWS, its IAM role,
      with no secret at all. For those, Lanyard issues a 10-minute token signed by AWS KMS."

DO:  Move the mouse down the 6 numbered steps in the blue "Lanyard gateway" box as you talk.

SAY: "Every tool call then goes through this gateway, running on AWS Lambda, in this order.
      Check the badge.
      Check DynamoDB for revocation, first, on every call.
      Ask Amazon Verified Permissions whether the Cedar policies allow this door.
      Hold risky calls for a human.
      Call the tool, which is a private Lambda with files in S3.
      And finally, scan what comes back with Bedrock Guardrails before the AI ever reads it."

DO:  Point at "Access log" on the right.

SAY: "Every decision streams through DynamoDB Streams into S3 with Object Lock,
      so the record can't be edited or deleted."


====================================================================
SCENE 3 · A COMPANY RUNNING ON AGENTS (1:05 to 1:20)
====================================================================

DO:  Click "Overview". Move the mouse over the chart, then over "Why doors stayed shut".

SAY: "This is that flow live, for a fictional company with several agents at work right now.
      Blue calls were granted, orange were denied, and here is why: missing permissions,
      prompt injections, and tools nobody wrote a policy for."


====================================================================
SCENE 4 · REVOKE AN AGENT MID-TASK (1:20 to 2:00)
====================================================================

DO:  Click "Agents" in the sidebar.

DO:  In the terminal, paste and press Enter:

     uv run python scripts/demo_agent.py trusted --task revoke --delay 2.5

SAY: "Each agent wears a badge showing its identity and the doors it can open.
      This trusted agent signed in with Auth0 and is reading company reports."

DO:  After 3 or 4 green ticks, click "Revoke badge" on trusted-agent (top left).

SAY: "I'm revoking its badge now."

DO:  Wait for the red "HTTP 403" line in the terminal.

SAY: "Its very next call is blocked. Its token is still valid for hours,
      but Lanyard revokes the identity, not the token. It also removed the agent's grant in Auth0,
      so it can't get a new token either. Two layers."


====================================================================
SCENE 5 · A REAL AI AGENT MEETS A PROMPT INJECTION (2:00 to 3:05)
====================================================================

DO:  Click "Approvals" in the sidebar.

DO:  In the terminal, paste and press Enter:

     scripts/run_ai_agent.sh

SAY: "Now a real AI agent: Claude Opus 5.5 on Amazon Bedrock, running in AWS Lambda.
      It signed in with its own IAM role. No password, no API key."

SAY: "Its job is to triage support tickets. Claude decides which tools to call,
      and every call goes through the checks you just saw."

DO:  Wait until the terminal shows TCK-2007 and a "blocked" line (20 to 40 seconds).
     While waiting, say: "You can see it reading the tickets one by one."

SAY: "This ticket hides an instruction to export customer data and deploy to production.
      Bedrock Guardrails caught it before Claude saw it, and Lanyard marked the agent as tainted."

DO:  Wait for the yellow card on the Security desk (10 to 20 seconds).

SAY: "Because it read an attack, Verified Permissions now requires a human for anything risky.
      It wants to save its summary, so I'll approve that."

DO:  Click "Approve". Wait for the [claude] line in the terminal.

SAY: "Claude finishes and reports what it did."

DO:  Press Ctrl + C in the terminal.


====================================================================
SCENE 6 · TRY TO BREAK IT (3:05 to 3:25)
====================================================================

DO:  Click "Attack lab", then the red "Run all attacks" button.

SAY: "Last, nine real attacks against this live gateway: forged and unsigned tokens,
      algorithm confusion against the KMS key, privilege escalation through a sub-agent,
      prompt injection, and replaying a revoked token."

DO:  Wait for the green BLOCKED stamps.

SAY: "All nine are blocked, and each attempt is in the tamper-proof log."


====================================================================
SCENE 7 · CLOSE (3:25 to 3:40)
====================================================================

DO:  Click "Agents" so the REVOKED badge is on screen.

SAY: "Lanyard: an identity for every agent, least privilege on every call,
      and revocation that takes effect on the very next call.
      It's running live on AWS right now: Lambda, Bedrock, Verified Permissions,
      KMS, DynamoDB and S3. Thanks for watching."

DO:  Stop the recording (stop button in the menu bar).


====================================================================
IF IT RUNS LONG (Devpost limit is 3 minutes)
====================================================================

Cut Scene 3. Shorten Scene 6 to: "Nine real attacks against this live gateway. All nine are blocked."


====================================================================
IF SOMETHING GOES WRONG
====================================================================

- Approval card doesn't appear: reload the page (Cmd + R), click Approvals again.
- You stumble on a line: pause, say it again, trim later. Or do a second take.
- The revoke came too late (the agent finished first): run scripts/reset_demo.sh cloud and redo Scene 4.


====================================================================
AFTER RECORDING
====================================================================

1. Watch it once. Check the sound.
2. In the terminal: scripts/reset_demo.sh cloud   (resets everything for live judging)
3. Upload to YouTube as "Unlisted", then paste the link into Devpost.
