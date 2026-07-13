"""
Arceo hosted — kill switches, admin actions, metrics (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Kill switches deny quota reservation at enqueue (global or per-workspace), which stops new spend
without touching running jobs or stored data. Every admin action lands in an append-only audit
table with actor + reason. Metrics are in-process counters exported in a plain text format;
production scraping fronts this via the deployment edge.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from collections import Counter

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kill_switches(
  scope TEXT PRIMARY KEY,          -- 'global' or a workspace_id
  reason TEXT NOT NULL, actor TEXT NOT NULL, tripped_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS admin_audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT, reason TEXT, ts REAL NOT NULL);
"""


class KillSwitchTripped(Exception):
    pass


class OpsStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(_SCHEMA)

    def _audit(self, actor: str, action: str, subject: str, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO admin_audit(actor,action,subject,reason,ts) VALUES(?,?,?,?,?)",
            (actor, action, subject, reason, time.time()))

    def record(self, actor: str, action: str, subject: str, reason: str) -> None:
        """Append a privileged control-plane action (e.g. scope_mint) to the audit log."""
        if not reason.strip():
            raise ValueError("audited actions require a non-empty reason")
        self._audit(actor, action, subject, reason)
        self.conn.commit()

    # --- kill switches ---
    def trip(self, scope: str, *, actor: str, reason: str) -> None:
        """scope: 'global' or a workspace_id. Requires a non-empty reason (runbook discipline)."""
        if not reason.strip():
            raise ValueError("a kill switch requires a reason")
        self.conn.execute(
            "INSERT OR REPLACE INTO kill_switches VALUES(?,?,?,?)",
            (scope, reason, actor, time.time()))
        self._audit(actor, "kill_switch_trip", scope, reason)
        self.conn.commit()

    def clear(self, scope: str, *, actor: str, reason: str) -> None:
        self.conn.execute("DELETE FROM kill_switches WHERE scope=?", (scope,))
        self._audit(actor, "kill_switch_clear", scope, reason)
        self.conn.commit()

    def check(self, workspace_id: str) -> None:
        """Raises KillSwitchTripped if the global switch or this workspace's switch is set."""
        row = self.conn.execute(
            "SELECT scope, reason FROM kill_switches WHERE scope IN ('global', ?) LIMIT 1",
            (workspace_id,)).fetchone()
        if row:
            scope = row["scope"] if isinstance(row, sqlite3.Row) else row[0]
            raise KillSwitchTripped(
                "service paused" if scope == "global" else "workspace paused")

    def active(self) -> list:
        return self.conn.execute(
            "SELECT * FROM kill_switches ORDER BY tripped_at").fetchall()

    def audit_tail(self, n: int = 50) -> list:
        return self.conn.execute(
            "SELECT * FROM admin_audit ORDER BY seq DESC LIMIT ?", (n,)).fetchall()


class Metrics:
    """Thread-safe monotonic counters; text exposition of `arceo_<name> <value>` lines."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters = Counter()

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters[name]

    def render(self) -> str:
        with self._lock:
            return "".join(f"arceo_{k} {v}\n" for k, v in sorted(self._counters.items()))
