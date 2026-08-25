"""Phase 4 tests: reconciliation report and customer-favorable auto-repair."""
from __future__ import annotations

import os

os.environ.setdefault("HEEL_SIGNUP_MAX_PER_IP", "100000")   # suite shares one loopback IP
os.environ.setdefault("HEEL_SIGNUP_MAX_GLOBAL", "100000")

import time
import unittest

from heel.saas.catalog import CATALOG_VERSION, Meter, get_plan
from heel.saas.http_api import ControlPlane
from heel.saas.jobs import JobPlane
from heel.saas.reconcile import STALE_RESERVATION_S, reconcile
from heel.saas.tenancy import Role

from canary_test_support import NOW_MS, PROJECT, RUNNER, WORKSPACE, operational_projection
from test_canary_lifecycle import running_setup


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.cp = ControlPlane()
        self.addCleanup(self.cp.close)
        self.conn = self.cp.store.conn
        org = self.cp.store.create_org("t")
        self.wid = self.cp.store.create_workspace(org, "w", "free", CATALOG_VERSION)

    def test_clean_state(self):
        rep = reconcile(self.conn, self.cp.ledger)
        self.assertTrue(rep.clean)
        self.assertEqual(rep.unapplied_events, 0)

    def test_plan_mismatch_and_unknown_workspace(self):
        ev = self.cp.billing.event(self.wid, "sub.updated", "active", "pro")
        self.assertEqual(self.cp.subs.apply_event(ev), "applied")
        rep = reconcile(self.conn, self.cp.ledger)   # workspace still pinned to free
        self.assertEqual(rep.plan_mismatches[0][0], self.wid)
        ev2 = self.cp.billing.event("ws_ghost", "sub.updated", "active", "pro")
        self.cp.subs.apply_event(ev2)
        rep = reconcile(self.conn, self.cp.ledger)
        self.assertIn("ws_ghost", rep.unknown_subscription_workspaces)

    def test_stale_dangling_reservation_refunded_only_with_repair(self):
        r = self.cp.ledger.reserve(get_plan("free"), self.wid, Meter.RUNS, 1, "2026-07")
        future = time.time() + STALE_RESERVATION_S + 1
        rep = reconcile(self.conn, self.cp.ledger, now=future)
        self.assertIn(r.reservation_id, rep.dangling_reservations)
        self.assertEqual(rep.refunded, [])
        self.assertEqual(self.cp.ledger.usage(self.wid, Meter.RUNS, "2026-07"), 1)
        rep = reconcile(self.conn, self.cp.ledger, now=future, repair=True)
        self.assertIn(r.reservation_id, rep.refunded)
        self.assertEqual(self.cp.ledger.usage(self.wid, Meter.RUNS, "2026-07"), 0)
        self.assertTrue(reconcile(self.conn, self.cp.ledger, now=future).clean)

    def test_reservation_with_live_job_not_touched(self):
        r = self.cp.ledger.reserve(get_plan("free"), self.wid, Meter.RUNS, 1, "2026-07")
        self.cp.jobs.enqueue(self.wid, kind="synthetic", reservation_ids=[r.reservation_id])
        future = time.time() + STALE_RESERVATION_S + 1
        rep = reconcile(self.conn, self.cp.ledger, now=future, repair=True)
        self.assertEqual(rep.dangling_reservations, [])
        self.assertEqual(self.cp.ledger.usage(self.wid, Meter.RUNS, "2026-07"), 1)

    def test_fresh_reservation_not_flagged(self):
        self.cp.ledger.reserve(get_plan("free"), self.wid, Meter.RUNS, 1, "2026-07")
        self.assertTrue(reconcile(self.conn, self.cp.ledger).clean)

    def test_live_canary_reservation_is_owned_by_the_canary_lifecycle(self):
        conn, clock, _runner, coordinator, approved, _claim = running_setup()
        self.addCleanup(conn.close)
        reservation_id = approved["reservation_id"]

        report = reconcile(
            conn, coordinator.ledger,
            now=clock.value + STALE_RESERVATION_S + 1, repair=True,
        )

        self.assertNotIn(reservation_id, report.dangling_reservations)
        self.assertNotIn(reservation_id, report.refunded)
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
            (reservation_id,),
        ).fetchone()[0], 0)

    def test_terminal_canary_is_refunded_only_when_signed_receipt_proves_zero_requests(self):
        conn, clock, runner, coordinator, approved, _claim = running_setup()
        self.addCleanup(conn.close)
        grant = approved["grant"]
        coordinator.result(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase="terminal", requests_started=0,
                disposition="incomplete", error_category="containment_rejected",
                updated_at_ms=NOW_MS + 500,
            ),
        )
        reservation_id = approved["reservation_id"]
        conn.execute(
            "DELETE FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
            (reservation_id,),
        )
        conn.execute("UPDATE canary_runs SET quota_state='reserved'")
        conn.commit()

        report = reconcile(
            conn, coordinator.ledger,
            now=clock.value + STALE_RESERVATION_S + 1, repair=True,
        )
        self.assertIn(reservation_id, report.refunded)

        # Removing the validated operational receipt removes the proof needed for an automatic
        # refund. Reconciliation reports the inconsistency without guessing an outcome.
        conn.execute(
            "DELETE FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
            (reservation_id,),
        )
        conn.execute("DELETE FROM canary_operational_receipts")
        conn.commit()
        second = reconcile(
            conn, coordinator.ledger,
            now=clock.value + STALE_RESERVATION_S + 1, repair=True,
        )
        self.assertIn(reservation_id, second.dangling_reservations)
        self.assertNotIn(reservation_id, second.refunded)

    def test_proven_terminal_platform_fault_is_compensated_exactly_once(self):
        conn, clock, runner, coordinator, approved, _claim = running_setup()
        self.addCleanup(conn.close)
        grant = approved["grant"]
        coordinator.progress(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase="running", requests_started=1,
                updated_at_ms=NOW_MS + 200,
            ),
        )
        coordinator.result(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=1, phase="terminal", requests_started=1,
                disposition="failed", error_category="platform_fault",
                updated_at_ms=NOW_MS + 500,
            ),
        )
        reservation_id = approved["reservation_id"]
        conn.execute(
            "DELETE FROM usage_ledger WHERE reservation_id=? "
            "AND kind='platform_fault_refund'", (reservation_id,),
        )
        conn.execute("UPDATE canary_runs SET quota_state='consumed'")
        conn.commit()

        first = reconcile(conn, coordinator.ledger, now=clock.value, repair=True)
        second = reconcile(conn, coordinator.ledger, now=clock.value, repair=True)

        self.assertIn(reservation_id, first.compensated)
        self.assertEqual(second.compensated, [])
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM usage_ledger WHERE reservation_id=? "
            "AND kind='platform_fault_refund'", (reservation_id,),
        ).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
