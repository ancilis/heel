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
    unapplied_events: int = 0

    @property
    def clean(self) -> bool:
        return not (self.plan_mismatches or self.unknown_subscription_workspaces
                    or self.dangling_reservations)


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
    for r in _unsettled(conn):
        if now - r["ts"] < STALE_RESERVATION_S or r["reservation_id"] in live_jobs:
            continue
        rep.dangling_reservations.append(r["reservation_id"])
        if repair and ledger.refund(r["reservation_id"]):
            rep.refunded.append(r["reservation_id"])
    if repair:
        rep.dangling_reservations = [x for x in rep.dangling_reservations
                                     if x not in set(rep.refunded)]

    # 4. Webhook events received but never applied (out-of-order/rejected) — surfaced as a count.
    rep.unapplied_events = conn.execute(
        "SELECT COUNT(*) FROM billing_events WHERE applied=0").fetchone()[0]
    return rep


def _has_jobs(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone() is not None
