"""Scan MCP tool responses with Amazon Bedrock Guardrails before the agent sees them.

- Prompt injection hidden in tool output (e.g. a poisoned file) -> the response is blocked.
- Emails and phone numbers -> masked in place.
"""

import asyncio

import boto3


class ToolResponseGuard:
    def __init__(self, guardrail_id: str, version: str, profile: str | None, region: str):
        session = boto3.Session(profile_name=profile, region_name=region)
        self._client = session.client("bedrock-runtime")
        self._id, self._version = guardrail_id, version

    def _scan_sync(self, text: str) -> dict:
        resp = self._client.apply_guardrail(
            guardrailIdentifier=self._id, guardrailVersion=self._version,
            source="INPUT",  # tool output is about to become model input
            content=[{"text": {"text": text}}],
        )
        findings, blocked = [], False
        for a in resp.get("assessments", []):
            for f in a.get("contentPolicy", {}).get("filters", []):
                findings.append(f["type"])
                blocked |= f.get("action") == "BLOCKED"
            for e in a.get("sensitiveInformationPolicy", {}).get("piiEntities", []):
                findings.append(e["type"])
        if resp["action"] != "GUARDRAIL_INTERVENED":
            return {"verdict": "pass", "text": text, "findings": []}
        if blocked:
            return {"verdict": "block", "text": text, "findings": findings}
        return {"verdict": "mask", "text": resp["outputs"][0]["text"], "findings": findings}

    async def scan(self, text: str) -> dict:
        return await asyncio.to_thread(self._scan_sync, text)
