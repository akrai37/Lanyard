"""Mock 'files' MCP server: the company file share.

Storage is an S3 bucket when FILES_BUCKET is set (in the cloud, shared by every copy of
this server), otherwise the local servers/sandbox folder.
"""

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

BUCKET = os.environ.get("FILES_BUCKET")
SANDBOX = Path(os.environ.get("FILES_SANDBOX", Path(__file__).parent / "sandbox")).resolve()

mcp = MCPServer("files", instructions="Pinecrest Payments company file share.")


def _key(path: str) -> str:
    key = path.strip().lstrip("/")
    if not key or ".." in key.split("/"):
        raise ValueError(f"invalid path: {path}")
    return key


if BUCKET:
    import boto3
    _s3 = boto3.client("s3")

    def _list() -> list[str]:
        keys = []
        for page in _s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET):
            keys += [o["Key"] for o in page.get("Contents", [])]
        return sorted(keys)

    def _read(path: str) -> str:
        try:
            return _s3.get_object(Bucket=BUCKET, Key=_key(path))["Body"].read().decode()
        except _s3.exceptions.NoSuchKey:
            raise ValueError(f"no such file: {path}")

    def _write(path: str, content: str) -> None:
        _s3.put_object(Bucket=BUCKET, Key=_key(path), Body=content.encode(),
                       ContentType="text/plain; charset=utf-8")
else:
    SANDBOX.mkdir(exist_ok=True)

    def _safe(path: str) -> Path:
        p = (SANDBOX / _key(path)).resolve()
        if SANDBOX not in p.parents:
            raise ValueError(f"path escapes sandbox: {path}")
        return p

    def _list() -> list[str]:
        return sorted(str(p.relative_to(SANDBOX)) for p in SANDBOX.rglob("*") if p.is_file())

    def _read(path: str) -> str:
        p = _safe(path)
        if not p.is_file():
            raise ValueError(f"no such file: {path}")
        return p.read_text()

    def _write(path: str, content: str) -> None:
        p = _safe(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


@mcp.tool()
def list_files(prefix: str = "") -> str:
    """List files on the company file share, optionally under a folder prefix such as 'tickets/'."""
    return "\n".join(k for k in _list() if k.startswith(prefix))


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the company file share."""
    return _read(path)


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a file on the company file share."""
    _write(path, content)
    return f"wrote {len(content)} bytes to {path}"


if __name__ == "__main__":
    mcp.run("streamable-http", host="127.0.0.1", port=8101, json_response=True, stateless_http=True)
