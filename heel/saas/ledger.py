"""
Heel hosted — append-only usage ledger with atomic reserve/consume/refund (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

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
  kind TEXT NOT NULL,             -- reserve | consume | refund | platform_fault_refund
  amount INTEGER NOT NULL,
  reservation_id TEXT,            -- reserve rows: self; consume/refund: the reserve they settle
  idempotency_key TEXT,
  ref TEXT,                       -- opaque caller ref (e.g. run_id)
  ts REAL NOT NULL,
  reason TEXT);
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


class GlobalCapExceeded(Exception):
    """The PLATFORM-WIDE cap for this meter/period is reached — the automatic circuit breaker
    that bounds aggregate (not just per-workspace) liability. Callers surface this as a
    temporary service condition (503), never as a per-tenant upgrade prompt."""
    def __init__(self, meter: Meter, used: int, cap: int):
        self.meter, self.used, self.cap = meter, used, cap
        super().__init__(f"platform circuit breaker: {meter.value} at {used}/{cap} this period")


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
                 COALESCE(SUM(CASE
                   WHEN kind IN ('reserve', 'platform_fault_refund') THEN amount
                   WHEN kind='refund' THEN -amount
                   ELSE 0 END),0) AS used
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
    def global_usage(self, meter: Meter, period: str) -> int:
        """Platform-wide active usage for a meter (reserved − refunded across ALL workspaces)."""
        row = self.conn.execute(
            """SELECT
                 COALESCE(SUM(CASE
                   WHEN kind IN ('reserve', 'platform_fault_refund') THEN amount
                   WHEN kind='refund' THEN -amount
                   ELSE 0 END),0) AS used
               FROM usage_ledger WHERE meter=? AND period=?""",
            (meter.value, period)).fetchone()
        return int(row["used"] or 0)

    def reserve(self, plan: Plan, workspace_id: str, meter: Meter, amount: int, period: str,
                *, idempotency_key: str | None = None, ref: str | None = None,
                global_cap: int | None = None) -> Reservation:
        """global_cap, when given, is the platform-wide ceiling for this meter/period — the
        automatic circuit breaker. It is checked inside the same write transaction as the
        per-workspace quota, so racing reservations cannot pierce it."""
        if amount <= 0:
            raise ValueError("reserve amount must be positive")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            reservation = self.reserve_in_transaction(
                plan,
                workspace_id,
                meter,
                amount,
                period,
                idempotency_key=idempotency_key,
                ref=ref,
                global_cap=global_cap,
            )
            self.conn.execute("COMMIT")
            return reservation
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise

    def reserve_in_transaction(
        self,
        plan: Plan,
        workspace_id: str,
        meter: Meter,
        amount: int,
        period: str,
        *,
        idempotency_key: str | None = None,
        ref: str | None = None,
        global_cap: int | None = None,
    ) -> Reservation:
        """Reserve quota inside a transaction owned by the caller.

        This method never begins, commits, or rolls back. It lets a higher-level service make the
        ledger entry atomic with its own durable records while ``reserve`` remains the standalone
        compatibility wrapper.
        """
        if amount <= 0:
            raise ValueError("reserve amount must be positive")
        if not self.conn.in_transaction:
            raise RuntimeError("reserve_in_transaction requires an active transaction")
        if idempotency_key is not None:
            prior = self.conn.execute(
                """SELECT * FROM usage_ledger WHERE workspace_id=? AND meter=?
                   AND idempotency_key=? AND kind='reserve'""",
                (workspace_id, meter.value, idempotency_key)).fetchone()
            if prior:
                refunded = self.conn.execute(
                    "SELECT 1 FROM usage_ledger WHERE reservation_id=? "
                    "AND kind IN ('refund','platform_fault_refund')",
                    (prior["reservation_id"],)).fetchone()
                if refunded:
                    raise IdempotencyConflict(
                        f"idempotency key {idempotency_key!r} belongs to a refunded "
                        "reservation; retry with a new key")
                return Reservation(
                    prior["reservation_id"], workspace_id, meter, prior["amount"], prior["period"])
        quota = plan.quota(meter)
        if quota != CUSTOM:
            used = self.usage(workspace_id, meter, period)
            if used + amount > quota:
                raise QuotaExceeded(meter, amount, used, quota)
        if global_cap is not None:
            global_used = self.global_usage(meter, period)
            if global_used + amount > global_cap:
                raise GlobalCapExceeded(meter, global_used, global_cap)
        reservation_id = f"resv_{secrets.token_hex(8)}"
        self.conn.execute(
            """INSERT INTO usage_ledger(
                 entry_id,workspace_id,meter,period,kind,amount,reservation_id,
                 idempotency_key,ref,ts,reason)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (f"led_{secrets.token_hex(8)}", workspace_id, meter.value, period, "reserve",
             amount, reservation_id, idempotency_key, ref, _now(), None))
        return Reservation(reservation_id, workspace_id, meter, amount, period)

    def _settle(self, reservation_id: str, kind: str) -> bool:
        """Append a consume/refund row for a reservation, once. Returns False if already settled
        that way (idempotent). Refund also blocked if already refunded."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            settled = self._settle_in_transaction(reservation_id, kind)
            self.conn.execute("COMMIT")
            return settled
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise

    def _settle_in_transaction(self, reservation_id: str, kind: str) -> bool:
        if not self.conn.in_transaction:
            raise RuntimeError("settlement requires an active transaction")
        resv = self.conn.execute(
            "SELECT * FROM usage_ledger WHERE reservation_id=? AND kind='reserve'",
            (reservation_id,)).fetchone()
        if not resv:
            raise KeyError(f"unknown reservation {reservation_id}")
        already = self.conn.execute(
            "SELECT kind FROM usage_ledger WHERE reservation_id=? AND kind IN ('consume','refund')",
            (reservation_id,)).fetchall()
        settled_kinds = {row["kind"] for row in already}
        if "refund" in settled_kinds:
            return False
        if kind == "refund" and "consume" in settled_kinds:
            return False
        if kind in settled_kinds:
            return False
        self.conn.execute(
            """INSERT INTO usage_ledger(
                 entry_id,workspace_id,meter,period,kind,amount,reservation_id,
                 idempotency_key,ref,ts,reason)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (f"led_{secrets.token_hex(8)}", resv["workspace_id"], resv["meter"], resv["period"],
             kind, resv["amount"], reservation_id, None, resv["ref"], _now(), None))
        return True

    def consume_in_transaction(self, reservation_id: str) -> bool:
        """Consume a reservation inside the caller's active transaction."""
        return self._settle_in_transaction(reservation_id, "consume")

    def consume(self, reservation_id: str) -> bool:
        """Settle a reservation as used (quota stays consumed). Idempotent."""
        return self._settle(reservation_id, "consume")

    def refund(self, reservation_id: str) -> bool:
        """Release a reservation (e.g. job failed/cancelled before doing costly work). Idempotent;
        refusing after consume keeps double-refund impossible."""
        return self._settle(reservation_id, "refund")

    def refund_consumed_in_transaction(self, reservation_id: str, reason: str) -> bool:
        """Refund one consumed canary-run unit exactly once inside a caller transaction."""
        if reason not in {"platform_fault", "runner_fault"}:
            raise ValueError("canary compensation reason must be platform or runner fault")
        if not self.conn.in_transaction:
            raise RuntimeError("refund_consumed_in_transaction requires an active transaction")
        resv = self.conn.execute(
            "SELECT * FROM usage_ledger WHERE reservation_id=? AND kind='reserve'",
            (reservation_id,),
        ).fetchone()
        if not resv:
            raise KeyError(f"unknown reservation {reservation_id}")
        if resv["meter"] != Meter.CANARY_RUNS.value:
            raise ValueError("only CANARY_RUNS reservations support consumed compensation")
        settled_kinds = {
            row["kind"] for row in self.conn.execute(
                "SELECT kind FROM usage_ledger WHERE reservation_id=? "
                "AND kind IN ('consume','refund','platform_fault_refund')",
                (reservation_id,),
            )
        }
        if "consume" not in settled_kinds or {"refund", "platform_fault_refund"} & settled_kinds:
            return False
        self.conn.execute(
            """INSERT INTO usage_ledger(
                 entry_id,workspace_id,meter,period,kind,amount,reservation_id,
                 idempotency_key,ref,ts,reason)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"led_{secrets.token_hex(8)}", resv["workspace_id"], resv["meter"],
                resv["period"], "platform_fault_refund", -resv["amount"], reservation_id,
                None, resv["ref"], _now(), reason,
            ),
        )
        return True
