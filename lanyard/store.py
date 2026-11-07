"""Lanyard state: revocations, admin tool blocks, known agents, audit log.

The gateway keeps no state of its own; everything goes through a Store so that
several gateway instances can share it. SQLiteStore is the local default; a
DynamoDB store can implement the same methods.
"""

import json
import sqlite3
import threading
import time
from pathlib import Path


class SQLiteStore:
    def __init__(self, path: str | Path = "lanyard.db"):
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY, name TEXT, scopes TEXT, last_seen REAL);
                CREATE TABLE IF NOT EXISTS revocations (
                    agent_id TEXT PRIMARY KEY, revoked_at REAL, reason TEXT);
                CREATE TABLE IF NOT EXISTS tool_blocks (
                    agent_id TEXT, tool TEXT, PRIMARY KEY (agent_id, tool));
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, agent_id TEXT, agent_name TEXT,
                    method TEXT, tool TEXT, decision TEXT, reason TEXT, latency_ms INTEGER, detail TEXT);
                """
            )

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # agents
    def seen_agent(self, agent_id: str, name: str, scopes: list[str]) -> None:
        self._q(
            "INSERT INTO agents VALUES (?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET "
            "name=excluded.name, scopes=excluded.scopes, last_seen=excluded.last_seen",
            (agent_id, name, " ".join(scopes), time.time()),
        )

    def agents(self) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM agents ORDER BY name")]

    # revocation
    def revoke(self, agent_id: str, reason: str = "revoked by admin") -> None:
        self._q("INSERT OR REPLACE INTO revocations VALUES (?,?,?)", (agent_id, time.time(), reason))

    def restore(self, agent_id: str) -> None:
        self._q("DELETE FROM revocations WHERE agent_id=?", (agent_id,))

    def revocation(self, agent_id: str) -> dict | None:
        rows = self._q("SELECT * FROM revocations WHERE agent_id=?", (agent_id,))
        return dict(rows[0]) if rows else None

    # admin tool blocks (narrow an agent's access below its token scopes)
    def toggle_tool_block(self, agent_id: str, tool: str) -> bool:
        if self._q("SELECT 1 FROM tool_blocks WHERE agent_id=? AND tool=?", (agent_id, tool)):
            self._q("DELETE FROM tool_blocks WHERE agent_id=? AND tool=?", (agent_id, tool))
            return False
        self._q("INSERT INTO tool_blocks VALUES (?,?)", (agent_id, tool))
        return True

    def blocked_tools(self, agent_id: str) -> set[str]:
        return {r["tool"] for r in self._q("SELECT tool FROM tool_blocks WHERE agent_id=?", (agent_id,))}

    # audit log
    def log(self, *, agent_id: str, agent_name: str, method: str, tool: str | None,
            decision: str, reason: str, latency_ms: int = 0, detail: dict | None = None) -> None:
        self._q(
            "INSERT INTO audit (ts, agent_id, agent_name, method, tool, decision, reason, latency_ms, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), agent_id, agent_name, method, tool, decision, reason, latency_ms,
             json.dumps(detail or {})),
        )

    def events(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        rows = self._q("SELECT * FROM audit WHERE id > ? ORDER BY id DESC LIMIT ?", (after_id, limit))
        return [dict(r) | {"detail": json.loads(r["detail"])} for r in reversed(rows)]
