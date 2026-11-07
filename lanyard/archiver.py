"""Tamper-proof audit archive: DynamoDB stream -> S3 with Object Lock.

Every new audit event in the lanyard table arrives here through a DynamoDB stream and is
written to an S3 bucket that has Object Lock in compliance mode. For the retention period
nobody, including an account administrator, can change or delete those records, so the
audit trail survives even if the live table is wiped (as the demo reset does).
"""

import json
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer

_s3 = boto3.client("s3")
_des = TypeDeserializer()


def _plain(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    raise TypeError


def handler(event, context):
    rows = []
    for rec in event.get("Records", []):
        img = rec.get("dynamodb", {}).get("NewImage")
        if rec.get("eventName") != "INSERT" or not img:
            continue
        item = {k: _des.deserialize(v) for k, v in img.items()}
        if item.get("pk") != "audit":
            continue
        item.pop("pk", None)
        item.pop("sk", None)
        if isinstance(item.get("detail"), str):
            item["detail"] = json.loads(item["detail"])
        rows.append(item)
    if not rows:
        return {"archived": 0}
    rows.sort(key=lambda r: r["id"])
    now = datetime.now(timezone.utc)
    key = f"audit/{now:%Y/%m/%d/%H}/{int(rows[0]['id']):012d}-{int(rows[-1]['id']):012d}.jsonl"
    body = "\n".join(json.dumps(r, default=_plain, sort_keys=True) for r in rows) + "\n"
    _s3.put_object(Bucket=os.environ["AUDIT_BUCKET"], Key=key, Body=body.encode(),
                   ContentType="application/x-ndjson", ChecksumAlgorithm="SHA256")
    return {"archived": len(rows), "key": key}
