"""DynamoDB implementation of the Lanyard store (same methods as SQLiteStore).

Single table, partition key `pk`, sort key `sk`:
  agent / <agent_id>          name, scopes, last_seen
  revoked / <agent_id>        revoked_at, reason, grant_scopes
  taint / <agent_id>          tainted_at, reason
  block#<agent_id> / <tool>   admin tool block
  approval / <padded id>      tool, arguments, status
  audit / <padded id>         audit event
  counter / audit|approval    atomic id counters

Security-relevant reads (revocations, blocks, approvals) are strongly consistent, so a
revocation written by one gateway instance is enforced by every other instance on its next request.
"""

import json
import time
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError


def _pad(n: int) -> str:
    return f"{n:012d}"


def _plain(item: dict) -> dict:
    out = {}
    for k, v in item.items():
        if isinstance(v, Decimal):
            v = int(v) if v == v.to_integral_value() else float(v)
        out[k] = v
    return out


class DynamoStore:
    def __init__(self, table: str = "lanyard", profile: str | None = None, region: str = "us-east-1"):
        session = boto3.Session(profile_name=profile, region_name=region)
        self._t = session.resource("dynamodb").Table(table)

    def _next_id(self, name: str) -> int:
        r = self._t.update_item(Key={"pk": "counter", "sk": name}, UpdateExpression="ADD n :one",
                                ExpressionAttributeValues={":one": 1}, ReturnValues="UPDATED_NEW")
        return int(r["Attributes"]["n"])

    def _get(self, pk: str, sk: str) -> dict | None:
        item = self._t.get_item(Key={"pk": pk, "sk": sk}, ConsistentRead=True).get("Item")
        return _plain(item) if item else None

    def _query(self, pk: str, **kw) -> list[dict]:
        items, start = [], None
        while True:
            args = {"KeyConditionExpression": Key("pk").eq(pk), "ConsistentRead": True, **kw}
            if start:
                args["ExclusiveStartKey"] = start
            r = self._t.query(**args)
            items += [_plain(i) for i in r["Items"]]
            start = r.get("LastEvaluatedKey")
            if not start or "Limit" in kw:
                return items

    @staticmethod
    def _now() -> Decimal:
        return Decimal(str(round(time.time(), 3)))

    # agents
    def seen_agent(self, agent_id: str, name: str, scopes: list[str], identity: str = "auth0",
                   parent: str | None = None) -> None:
        item = {"pk": "agent", "sk": agent_id, "agent_id": agent_id, "name": name,
                "scopes": " ".join(scopes), "last_seen": self._now(), "identity": identity}
        if parent:
            item["parent"] = parent
        self._t.put_item(Item=item)

    def agents(self) -> list[dict]:
        return sorted(({k: v for k, v in a.items() if k not in ("pk", "sk")} for a in self._query("agent")),
                      key=lambda a: a["name"])

    # revocation
    def revoke(self, agent_id: str, reason: str = "revoked by admin", grant_scopes: list[str] | None = None) -> None:
        item = {"pk": "revoked", "sk": agent_id, "agent_id": agent_id, "revoked_at": self._now(), "reason": reason}
        if grant_scopes is not None:
            item["grant_scopes"] = json.dumps(grant_scopes)
        self._t.put_item(Item=item)

    def restore(self, agent_id: str) -> None:
        self._t.delete_item(Key={"pk": "revoked", "sk": agent_id})

    def revocations(self) -> list[dict]:
        return [r for r in (self.revocation(i["sk"]) for i in self._query("revoked")) if r]

    def revocation(self, agent_id: str) -> dict | None:
        r = self._get("revoked", agent_id)
        if not r:
            return None
        r = {k: v for k, v in r.items() if k not in ("pk", "sk")}
        r["grant_scopes"] = json.loads(r["grant_scopes"]) if r.get("grant_scopes") else None
        return r

    # taint: the agent has read content flagged as prompt injection
    def taint(self, agent_id: str, reason: str) -> None:
        self._t.put_item(Item={"pk": "taint", "sk": agent_id, "agent_id": agent_id,
                               "tainted_at": self._now(), "reason": reason})

    def clear_taint(self, agent_id: str) -> None:
        self._t.delete_item(Key={"pk": "taint", "sk": agent_id})

    def taint_of(self, agent_id: str) -> dict | None:
        r = self._get("taint", agent_id)
        return {k: v for k, v in r.items() if k not in ("pk", "sk")} if r else None

    # admin tool blocks
    def toggle_tool_block(self, agent_id: str, tool: str) -> bool:
        old = self._t.delete_item(Key={"pk": f"block#{agent_id}", "sk": tool}, ReturnValues="ALL_OLD")
        if old.get("Attributes"):
            return False
        self._t.put_item(Item={"pk": f"block#{agent_id}", "sk": tool})
        return True

    def blocked_tools(self, agent_id: str) -> set[str]:
        return {i["sk"] for i in self._query(f"block#{agent_id}")}

    # human approvals
    def request_approval(self, agent_id: str, agent_name: str, tool: str, arguments: dict) -> int:
        approval_id = self._next_id("approval")
        self._t.put_item(Item={"pk": "approval", "sk": _pad(approval_id), "id": approval_id, "ts": self._now(),
                               "agent_id": agent_id, "agent_name": agent_name, "tool": tool,
                               "arguments": json.dumps(arguments), "status": "pending"})
        return approval_id

    def approval_status(self, approval_id: int) -> str | None:
        r = self._get("approval", _pad(approval_id))
        return r["status"] if r else None

    def decide_approval(self, approval_id: int, status: str) -> dict | None:
        try:
            r = self._t.update_item(
                Key={"pk": "approval", "sk": _pad(approval_id)},
                UpdateExpression="SET #s = :new, decided_at = :t",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":new": status, ":t": self._now(), ":pending": "pending"},
                ReturnValues="ALL_NEW")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return None
            raise
        return _plain(r["Attributes"])

    def pending_approvals(self) -> list[dict]:
        items = self._query("approval", FilterExpression=Attr("status").eq("pending"))
        return [{k: v for k, v in i.items() if k not in ("pk", "sk")} | {"arguments": json.loads(i["arguments"])}
                for i in items]

    def reset(self) -> None:
        scan, start = [], None
        while True:
            r = self._t.scan(ProjectionExpression="pk, sk", **({"ExclusiveStartKey": start} if start else {}))
            scan += r["Items"]
            start = r.get("LastEvaluatedKey")
            if not start:
                break
        with self._t.batch_writer() as batch:
            for i in scan:
                batch.delete_item(Key={"pk": i["pk"], "sk": i["sk"]})

    # audit log
    def log(self, *, agent_id: str, agent_name: str, method: str, tool: str | None,
            decision: str, reason: str, latency_ms: int = 0, detail: dict | None = None) -> None:
        event_id = self._next_id("audit")
        item = {"pk": "audit", "sk": _pad(event_id), "id": event_id, "ts": self._now(), "agent_id": agent_id,
                "agent_name": agent_name, "method": method, "decision": decision, "reason": reason,
                "latency_ms": latency_ms, "detail": json.dumps(detail or {})}
        if tool:
            item["tool"] = tool
        self._t.put_item(Item=item)

    def latest_event_id(self) -> int:
        item = self._get("counter", "audit")  # reset deletes the counter, so ids start over
        return int(item["n"]) if item else 0

    def events(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        items = self._query("audit", KeyConditionExpression=Key("pk").eq("audit") & Key("sk").gt(_pad(after_id)),
                            ScanIndexForward=False, Limit=limit)
        return [{k: v for k, v in i.items() if k not in ("pk", "sk")} | {"tool": i.get("tool"),
                "detail": json.loads(i["detail"])} for i in reversed(items)]
