"""
Arceo hosted — append-only usage ledger with atomic reserve/consume/refund (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Quotas are enforced TRANSACTIONALLY. A reservation counts against quota the instant it is created;
consuming settles it (still counted); refunding releases it (no longer counted). Idempotency keys make
reserve safe against duplicate/replayed requests (webhooks, retried enqueues). The ledger is the
source of truth for metered usage reported to billing — never the reverse.

Concurrency: writes use BEGIN IMMEDIATE so the check-usage-then-append step is serialized; two racing
reservations at the quota boundary cannot both succeed.
"""
from __future__ import annotations

import secrets
import sqlite3
import time
from dataclasses import dataclass

from .catalog import CUSTOM, Meter, Plan


_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_ledger(
  entry_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  meter TEXT NOT NULL,
  period TEXT NOT NULL,            -- billing period bucket, e.g. '2026-07'
  kind TEXT NOT NULL,             -- reserve | consume | refund
  amount INTEGER NOT NULL,
  reservation_id TEXT,            -- reserve rows: self; consume/refund: the reserve they settle
  idempotency_key TEXT,
  ref TEXT,                       -- opaque caller ref (e.g. run_id)
  ts REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_idem
  ON usage_ledger(workspace_id, meter, idempotency_key)
  WHERE idempotency_key IS NOT NULL AND kind='reserve';
CREATE INDEX IF NOT EXISTS idx_ledger_usage ON usage_ledger(workspace_id, meter, period);
CREATE INDEX IF NOT EXISTS idx_ledger_resv ON usage_ledger(reservation_id);
"""


class IdempotencyConflict(Exception):
    """The idempotency key was already used by a reservation that has since been refunded.
    A refunded reservation is terminal; replaying its key must NOT hand back quota-free
    capacity. The caller retries with a fresh key (and passes quota checks anew)."""


class QuotaExceeded(Exception):
    def __init__(self, meter: Meter, requested: int, used: int, quota: int):
        self.meter, self.requested, self.used, self.quota = meter, requested, used, quota
        super().__init__(
            f"quota exceeded for {meter.value}: requested {requested}, used {used}, quota {quota}")


@dataclass
class Reservation:
    reservation_id: str
    workspace_id: str
    meter: Meter
    amount: int
    period: str


def _now() -> float:
    return time.time()


class UsageLedger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute("PRAGMA foreign_keys=ON")
        # Block (don't instantly fail) when another writer holds the lock, so concurrent workers on
        # separate connections serialize cleanly instead of dropping legitimate reservations.
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(_SCHEMA)

    @classmethod
    def in_memory(cls) -> "UsageLedger":
        c = sqlite3.connect(":memory:", check_same_thread=False)
        c.row_factory = sqlite3.Row
        return cls(c)

    # --- reads ---
    def usage(self, workspace_id: str, meter: Meter, period: str) -> int:
        """Active usage = reserved − refunded (consumed reservations still count)."""
        row = self.conn.execute(
            """SELECT
                 COALESCE(SUM(CASE WHEN kind='reserve' THEN amount END),0) -
                 COALESCE(SUM(CASE WHEN kind='refund'  THEN amount END),0) AS used
               FROM usage_ledger
               WHERE workspace_id=? AND meter=? AND period=?""",
            (workspace_id, meter.value, period)).fetchone()
        return int(row["used"] or 0)

    def remaining(self, plan: Plan, workspace_id: str, meter: Meter, period: str) -> int | None:
        q = plan.quota(meter)
        if q == CUSTOM:
            return None  # unlimited / negotiated
        return max(0, q - self.usage(workspace_id, meter, period))

    # --- writes ---
    def reserve(self, plan: Plan, workspace_id: str, meter: Meter, amount: int, period: str,
                *, idempotency_key: str | None = None, ref: str | None = None) -> Reservation:
        if amount <= 0:
            raise ValueError("reserve amount must be positive")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            # Idempotent replay: return the existing reservation, do not double-count.
            if idempotency_key is not None:
                prior = self.conn.execute(
                    """SELECT * FROM usage_ledger WHERE workspace_id=? AND meter=?
                       AND idempotency_key=? AND kind='reserve'""",
                    (workspace_id, meter.value, idempotency_key)).fetchone()
                if prior:
                    refunded = self.conn.execute(
                        "SELECT 1 FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
                        (prior["reservation_id"],)).fetchone()
                    self.conn.execute("COMMIT")
                    if refunded:
                        # Terminal: the reservation was released. Replaying its key must not
                        # return quota-free capacity — the key is burned.
                        raise IdempotencyConflict(
                            f"idempotency key {idempotency_key!r} belongs to a refunded "
                            "reservation; retry with a new key")
                    return Reservation(prior["reservation_id"], workspace_id, meter,
                                       prior["amount"], prior["period"])
            q = plan.quota(meter)
            if q != CUSTOM:
                used = self.usage(workspace_id, meter, period)
                if used + amount > q:
                    self.conn.execute("ROLLBACK")
                    raise QuotaExceeded(meter, amount, used, q)
            rid = f"resv_{secrets.token_hex(8)}"
            self.conn.execute(
                "INSERT INTO usage_ledger VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f"led_{secrets.token_hex(8)}", workspace_id, meter.value, period, "reserve",
                 amount, rid, idempotency_key, ref, _now()))
            self.conn.execute("COMMIT")
            return Reservation(rid, workspace_id, meter, amount, period)
        except QuotaExceeded:
            raise
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise

    def _settle(self, reservation_id: str, kind: str) -> bool:
        """Append a consume/refund row for a reservation, once. Returns False if already settled
        that way (idempotent). Refund also blocked if already refunded."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            resv = self.conn.execute(
                "SELECT * FROM usage_ledger WHERE reservation_id=? AND kind='reserve'",
                (reservation_id,)).fetchone()
            if not resv:
                self.conn.execute("ROLLBACK")
                raise KeyError(f"unknown reservation {reservation_id}")
            already = self.conn.execute(
                "SELECT kind FROM usage_ledger WHERE reservation_id=? AND kind IN ('consume','refund')",
                (reservation_id,)).fetchall()
            settled_kinds = {r["kind"] for r in already}
            if "refund" in settled_kinds:
                # A refunded reservation is terminal — cannot consume or double-refund.
                self.conn.execute("ROLLBACK")
                return False
            if kind == "refund" and "consume" in settled_kinds:
                # Consumed reservations are terminal too: the costly work already ran, no refund.
                self.conn.execute("ROLLBACK")
                return False
            if kind in settled_kinds:
                self.conn.execute("ROLLBACK")
                return False
            self.conn.execute(
                "INSERT INTO usage_ledger VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f"led_{secrets.token_hex(8)}", resv["workspace_id"], resv["meter"], resv["period"],
                 kind, resv["amount"], reservation_id, None, resv["ref"], _now()))
            self.conn.execute("COMMIT")
            return True
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise

    def consume(self, reservation_id: str) -> bool:
        """Settle a reservation as used (quota stays consumed). Idempotent."""
        return self._settle(reservation_id, "consume")

    def refund(self, reservation_id: str) -> bool:
        """Release a reservation (e.g. job failed/cancelled before doing costly work). Idempotent;
        refusing after consume keeps double-refund impossible."""
        return self._settle(reservation_id, "refund")
