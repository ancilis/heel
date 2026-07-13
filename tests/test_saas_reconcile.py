"""Phase 4 tests: reconciliation report and customer-favorable auto-repair."""
from __future__ import annotations

import time
import unittest

from arceo.saas.catalog import CATALOG_VERSION, Meter, get_plan
from arceo.saas.http_api import ControlPlane
from arceo.saas.jobs import JobPlane
from arceo.saas.reconcile import STALE_RESERVATION_S, reconcile
from arceo.saas.tenancy import Role


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.cp = ControlPlane()
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


if __name__ == "__main__":
    unittest.main()
