"""
Heel hosted — billing/usage reconciliation (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Nightly-runnable invariants over the three sources of truth (workspaces, subscriptions, usage
ledger). Reports discrepancies instead of guessing; the only automatic repair is refunding
reservations that were never settled and whose job is dead — customer-favorable by construction.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

STALE_RESERVATION_S = 24 * 3600


@dataclass
class ReconciliationReport:
    plan_mismatches: list = field(default_factory=list)      # workspace pin != subscription plan
    unknown_subscription_workspaces: list = field(default_factory=list)
    dangling_reservations: list = field(default_factory=list)  # unsettled, no live job
    refunded: list = field(default_factory=list)               # auto-repaired this pass
    compensable_reservations: list = field(default_factory=list)
    compensated: list = field(default_factory=list)
    unapplied_events: int = 0

    @property
    def clean(self) -> bool:
        return not (self.plan_mismatches or self.unknown_subscription_workspaces
                    or self.dangling_reservations or self.compensable_reservations)


def _unsettled(conn: sqlite3.Connection) -> list:
    return conn.execute("""
        SELECT r.reservation_id, r.workspace_id, r.ts FROM usage_ledger r
        WHERE r.kind='reserve' AND NOT EXISTS (
          SELECT 1 FROM usage_ledger s
          WHERE s.reservation_id=r.reservation_id AND s.kind IN ('consume','refund'))
    """).fetchall()


def reconcile(conn: sqlite3.Connection, ledger, *, now: float | None = None,
              repair: bool = False) -> ReconciliationReport:
    """Run all checks on one control-plane DB. With repair=True, refunds stale unsettled
    reservations that have no queued/running job attached."""
    now = time.time() if now is None else now
    rep = ReconciliationReport()

    # 1. Workspace plan pin vs subscription record (active-ish states only; lapsed subs are
    #    expected to disagree until dunning resolves — entitlements already fall back to free).
    for r in conn.execute("""
        SELECT w.workspace_id, w.plan_id AS pinned, s.plan_id AS sub_plan, s.state
        FROM workspaces w JOIN subscriptions s ON s.workspace_id = w.workspace_id
        WHERE s.state IN ('trialing','active','past_due') AND w.plan_id != s.plan_id"""):
        rep.plan_mismatches.append((r["workspace_id"], r["pinned"], r["sub_plan"], r["state"]))

    # 2. Subscriptions pointing at workspaces that don't exist (webhook for deleted/foreign ws).
    for r in conn.execute("""
        SELECT s.workspace_id FROM subscriptions s
        WHERE NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.workspace_id=s.workspace_id)"""):
        rep.unknown_subscription_workspaces.append(r["workspace_id"])

    # 3. Reservations never settled. Fresh ones and ones with a live job are fine (the reaper
    #    owns lease expiry); stale ones with no queued/running job get refunded under repair.
    live_jobs = {rid for row in conn.execute(
        "SELECT reservations FROM jobs WHERE state IN ('queued','running')")
        for rid in json.loads(row["reservations"])} if _has_jobs(conn) else set()
    canary_reservations = _canary_reservations(conn)
    for r in _unsettled(conn):
        reservation_id = r["reservation_id"]
        if now - r["ts"] < STALE_RESERVATION_S or reservation_id in live_jobs:
            continue
        canary = canary_reservations.get(reservation_id)
        if canary is not None and canary["status"] not in {"terminal", "cancelled", "expired"}:
            # The canary coordinator, not legacy job reconciliation, owns every live grant.
            continue
        rep.dangling_reservations.append(reservation_id)
        if canary is not None:
            proven = _proves_canary_refund(canary)
            if repair and proven and _repair_canary_refund(conn, ledger, canary):
                rep.refunded.append(reservation_id)
        elif repair and ledger.refund(reservation_id):
            rep.refunded.append(reservation_id)

    # A consumed canary unit may receive one compensation only when the validated terminal
    # operational receipt still proves the closed platform/runner fault.  Durable run state alone
    # is not used to guess a result after receipt retention has elapsed.
    for canary in _compensable_canaries(conn):
        if not _proves_canary_compensation(canary):
            continue
        reservation_id = canary["reservation_id"]
        rep.compensable_reservations.append(reservation_id)
        if repair and _repair_canary_compensation(conn, ledger, canary):
            rep.compensated.append(reservation_id)
    if repair:
        rep.dangling_reservations = [x for x in rep.dangling_reservations
                                     if x not in set(rep.refunded)]
        rep.compensable_reservations = [
            value for value in rep.compensable_reservations
            if value not in set(rep.compensated)
        ]

    # 4. Webhook events received but never applied (out-of-order/rejected) — surfaced as a count.
    rep.unapplied_events = conn.execute(
        "SELECT COUNT(*) FROM billing_events WHERE applied=0").fetchone()[0]
    return rep


def _has_jobs(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone() is not None


def _has_canary_runs(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='canary_runs'"
    ).fetchone() is not None


def _canary_reservations(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    if not _has_canary_runs(conn):
        return {}
    return {
        row["reservation_id"]: row for row in conn.execute(
            "SELECT r.reservation_id,r.workspace_id,r.project_ref,r.run_id,r.status,"
            "r.quota_state,r.claimed_at_ms,r.execution_disposition,r.error_category,"
            "o.lifecycle_phase AS receipt_phase,o.error_category AS receipt_error,"
            "o.receipt_json FROM canary_runs r LEFT JOIN canary_operational_receipts o "
            "ON o.workspace_id=r.workspace_id AND o.project_ref=r.project_ref "
            "AND o.run_id=r.run_id WHERE r.reservation_id IS NOT NULL"
        )
    }


def _receipt(row: sqlite3.Row) -> dict | None:
    serialized = row["receipt_json"]
    if serialized is None:
        return None
    try:
        value = json.loads(serialized)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _proves_canary_refund(row: sqlite3.Row) -> bool:
    if row["quota_state"] != "reserved":
        return False
    if row["status"] in {"cancelled", "expired"} and row["claimed_at_ms"] is None:
        return True
    receipt = _receipt(row)
    return bool(
        row["status"] == "terminal"
        and row["receipt_phase"] == "terminal"
        and receipt is not None
        and isinstance(receipt.get("counters"), dict)
        and receipt["counters"].get("requests_started") == 0
    )


def _compensable_canaries(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    if not _has_canary_runs(conn):
        return []
    return conn.execute(
        "SELECT r.reservation_id,r.workspace_id,r.project_ref,r.run_id,r.status,"
        "r.quota_state,r.error_category,r.execution_disposition,"
        "o.lifecycle_phase AS receipt_phase,o.error_category AS receipt_error,o.receipt_json "
        "FROM canary_runs r JOIN canary_operational_receipts o "
        "ON o.workspace_id=r.workspace_id AND o.project_ref=r.project_ref AND o.run_id=r.run_id "
        "WHERE r.status='terminal' AND r.quota_state='consumed' "
        "AND r.error_category IN ('platform_fault','runner_fault') "
        "AND EXISTS(SELECT 1 FROM usage_ledger l WHERE l.reservation_id=r.reservation_id "
        "AND l.kind='consume') AND NOT EXISTS(SELECT 1 FROM usage_ledger l "
        "WHERE l.reservation_id=r.reservation_id "
        "AND l.kind IN ('refund','platform_fault_refund'))"
    ).fetchall()


def _proves_canary_compensation(row: sqlite3.Row) -> bool:
    receipt = _receipt(row)
    return bool(
        row["receipt_phase"] == "terminal"
        and row["receipt_error"] == row["error_category"]
        and receipt is not None
        and receipt.get("error_category") == row["error_category"]
        and isinstance(receipt.get("counters"), dict)
        and type(receipt["counters"].get("requests_started")) is int
        and receipt["counters"]["requests_started"] > 0
    )


def _repair_canary_refund(conn: sqlite3.Connection, ledger, row: sqlite3.Row) -> bool:
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = conn.execute(
            "SELECT status,quota_state FROM canary_runs WHERE workspace_id=? "
            "AND project_ref=? AND run_id=?", (row["workspace_id"], row["project_ref"], row["run_id"]),
        ).fetchone()
        if current is None or current["status"] not in {"terminal", "cancelled", "expired"} \
                or current["quota_state"] != "reserved":
            conn.rollback()
            return False
        created = ledger._settle_in_transaction(row["reservation_id"], "refund")
        if created:
            conn.execute(
                "UPDATE canary_runs SET quota_state='refunded' WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (row["workspace_id"], row["project_ref"], row["run_id"]),
            )
        conn.commit()
        return created
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def _repair_canary_compensation(conn: sqlite3.Connection, ledger, row: sqlite3.Row) -> bool:
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = conn.execute(
            "SELECT status,quota_state,error_category FROM canary_runs WHERE workspace_id=? "
            "AND project_ref=? AND run_id=?", (row["workspace_id"], row["project_ref"], row["run_id"]),
        ).fetchone()
        if (
            current is None or current["status"] != "terminal"
            or current["quota_state"] != "consumed"
            or current["error_category"] != row["error_category"]
        ):
            conn.rollback()
            return False
        created = ledger.refund_consumed_in_transaction(
            row["reservation_id"], row["error_category"],
        )
        if created:
            conn.execute(
                "UPDATE canary_runs SET quota_state='compensated' WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (row["workspace_id"], row["project_ref"], row["run_id"]),
            )
        conn.commit()
        return created
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
