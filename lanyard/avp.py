"""Authorization with Amazon Verified Permissions (Cedar policies).

Every tool call becomes a Cedar request:
  principal  Lanyard::Agent  {scopes, tainted, isSubAgent, identity}
  action     Lanyard::Action::"CallTool"
  resource   Lanyard::Tool   {name, requiredScope, risky}
  context    {environment, humanApproved, adminBlocked}

Policies whose description starts with "approval:" are human-approval gates: if they are the
only reason a call is denied, Lanyard holds the call for a person, then asks again with
humanApproved = true. Any other deny is final.

Fail closed: if Verified Permissions errors or is slow, the decision is DENY. Lanyard falls back
to its built-in rules only when no policy store is configured at all.
"""

import asyncio
import time
from dataclasses import dataclass

import boto3
from botocore.config import Config

NAMESPACE = "Lanyard"
POLICIES = {
    # description -> Cedar. The description prefix decides how a deny is handled.
    "permit: an agent may call a tool when its token has the tool's required scope":
        'permit (principal is Lanyard::Agent, action == Lanyard::Action::"CallTool", resource is Lanyard::Tool)\n'
        'when { principal.scopes.contains(resource.requiredScope) };',
    "forbid: an admin blocked this tool for this agent":
        'forbid (principal, action == Lanyard::Action::"CallTool", resource)\nwhen { context.adminBlocked };',
    "forbid: sub-agents may never deploy or roll back in production":
        'forbid (principal is Lanyard::Agent, action == Lanyard::Action::"CallTool", resource is Lanyard::Tool)\n'
        'when { principal.isSubAgent && context.environment == "production" && resource.requiredScope == "deploy:run" };',
    "approval: production deploys and rollbacks need a human":
        'forbid (principal, action == Lanyard::Action::"CallTool", resource is Lanyard::Tool)\n'
        'when { resource.requiredScope == "deploy:run" && context.environment == "production" && !context.humanApproved };',
    "approval: a tainted agent needs a human for risky tools":
        'forbid (principal is Lanyard::Agent, action == Lanyard::Action::"CallTool", resource is Lanyard::Tool)\n'
        'when { principal.tainted && resource.risky && !context.humanApproved };',
}


@dataclass
class Decision:
    allow: bool
    needs_approval: bool
    reason: str


class VerifiedPermissions:
    def __init__(self, policy_store_id: str, profile: str | None, region: str, timeout_seconds: float = 2.0):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.client = session.client("verifiedpermissions", config=Config(
            connect_timeout=timeout_seconds, read_timeout=timeout_seconds, retries={"max_attempts": 1}))
        self.store_id, self.timeout = policy_store_id, timeout_seconds
        self._policies: dict[str, dict] = {}
        self._loaded = 0.0

    def policies(self) -> dict[str, dict]:
        """policyId -> {description, statement}; refreshed every 60 s so console edits take effect."""
        if time.time() - self._loaded > 60:
            found = {}
            for page in self.client.get_paginator("list_policies").paginate(policyStoreId=self.store_id):
                for p in page["policies"]:
                    static = self.client.get_policy(policyStoreId=self.store_id, policyId=p["policyId"])
                    d = static["definition"]["static"]
                    found[p["policyId"]] = {"description": d.get("description", ""), "statement": d["statement"]}
            self._policies, self._loaded = found, time.time()
        return self._policies

    def _ask(self, agent: dict, tool: dict, context: dict) -> dict:
        def s(v):
            return {"string": v}
        return self.client.is_authorized(
            policyStoreId=self.store_id,
            principal={"entityType": f"{NAMESPACE}::Agent", "entityId": agent["id"]},
            action={"actionType": f"{NAMESPACE}::Action", "actionId": "CallTool"},
            resource={"entityType": f"{NAMESPACE}::Tool", "entityId": tool["name"]},
            context={"contextMap": {"environment": s(context.get("environment", "")),
                                    "humanApproved": {"boolean": context.get("humanApproved", False)},
                                    "adminBlocked": {"boolean": context.get("adminBlocked", False)}}},
            entities={"entityList": [
                {"identifier": {"entityType": f"{NAMESPACE}::Agent", "entityId": agent["id"]},
                 "attributes": {"scopes": {"set": [s(x) for x in sorted(agent["scopes"])]},
                                "tainted": {"boolean": agent["tainted"]},
                                "isSubAgent": {"boolean": agent["isSubAgent"]},
                                "identity": s(agent["identity"])}},
                {"identifier": {"entityType": f"{NAMESPACE}::Tool", "entityId": tool["name"]},
                 "attributes": {"name": s(tool["name"]), "requiredScope": s(tool["requiredScope"]),
                                "risky": {"boolean": tool["risky"]}}},
            ]})

    async def decide(self, agent: dict, tool: dict, context: dict) -> Decision:
        try:
            r = await asyncio.wait_for(asyncio.to_thread(self._ask, agent, tool, context), self.timeout + 1)
            policies = await asyncio.to_thread(self.policies)
        except Exception as e:  # unreachable, slow, throttled, misconfigured: deny
            return Decision(False, False, f"policy service unavailable, failing closed ({type(e).__name__})")
        if r.get("errors"):
            return Decision(False, False, "policy evaluation error, failing closed")
        ids = [p["policyId"] for p in r.get("determiningPolicies", [])]
        descs = [policies.get(i, {}).get("description", i) for i in ids]
        if r["decision"] == "ALLOW":
            return Decision(True, False, "Verified Permissions: " + "; ".join(d.split(": ", 1)[-1] for d in descs))
        if not ids:
            return Decision(False, False, "Verified Permissions: no policy permits this (default deny)")
        reason = "Verified Permissions: " + "; ".join(d.split(": ", 1)[-1] for d in descs)
        if not all(d.startswith("approval:") for d in descs) or context.get("humanApproved"):
            return Decision(False, False, reason)
        # Only approval gates said no. Ask a human only if approval would actually make it allowed;
        # never ask a person to approve a call the agent has no permission for.
        try:
            again = await asyncio.wait_for(asyncio.to_thread(
                self._ask, agent, tool, context | {"humanApproved": True}), self.timeout + 1)
        except Exception as e:
            return Decision(False, False, f"policy service unavailable, failing closed ({type(e).__name__})")
        if again["decision"] == "ALLOW":
            return Decision(False, True, reason)
        ids2 = [p["policyId"] for p in again.get("determiningPolicies", [])]
        descs2 = [policies.get(i, {}).get("description", i) for i in ids2]
        return Decision(False, False, "Verified Permissions: " + ("; ".join(d.split(": ", 1)[-1] for d in descs2)
                                                                  or "no policy permits this (default deny)"))


def create_store(profile: str | None, region: str) -> str:
    """Create a policy store with Lanyard's policies. Returns its id."""
    client = boto3.Session(profile_name=profile, region_name=region).client("verifiedpermissions")
    store_id = client.create_policy_store(validationSettings={"mode": "OFF"},
                                          description="Lanyard: who may call which MCP tool")["policyStoreId"]
    for description, statement in POLICIES.items():
        client.create_policy(policyStoreId=store_id, definition={
            "static": {"description": description, "statement": statement}})
    return store_id
