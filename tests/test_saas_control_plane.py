"""Tests for the hosted control-plane core (heel.saas): catalog, entitlement, ledger,
tenancy, billing. Offline, stdlib-only, deterministic."""
import sqlite3
import threading
import time
import unittest

from heel.saas.billing import (
    BillingStore, StubBilling, SubscriptionManager, SubState,
    WebhookVerificationError, live_price_id, verify_webhook_signature,
)
from heel.saas.catalog import (
    CATALOG_VERSION, CONFIG_GATED_FEATURES, CUSTOM, Feature, Meter,
    all_plans, get_plan, self_serve_plans,
)
from heel.saas.entitlement import EntitlementService, Subscription
from heel.saas.ledger import QuotaExceeded, UsageLedger
from heel.saas.tenancy import ControlPlaneStore, Role, hash_api_key, require, role_can

import hashlib
import hmac
import os


PERIOD = "2026-07"


def sub(plan_id="pro", state="active", ws="ws_1"):
    return Subscription(ws, plan_id, state, CATALOG_VERSION)


class TestCatalog(unittest.TestCase):
    def test_four_plans_ordered(self):
        self.assertEqual([p.id for p in all_plans()], ["free", "pro", "team", "enterprise"])

    def test_self_serve_excludes_enterprise(self):
        self.assertEqual([p.id for p in self_serve_plans()], ["free", "pro", "team"])

    def test_free_is_no_card_zero_price(self):
        free = get_plan("free")
        self.assertTrue(free.no_card)
        self.assertEqual(free.price_month_cents, 0)
        self.assertEqual(free.quota(Meter.RUNS), 25)
        self.assertEqual(free.quota(Meter.SEATS), 1)

    def test_quota_monotonic_across_tiers(self):
        for meter in (Meter.RUNS, Meter.VERIFIED_TARGETS, Meter.CONCURRENCY,
                      Meter.RETENTION_DAYS, Meter.SEATS):
            free, pro, team = (get_plan(p).quota(meter) for p in ("free", "pro", "team"))
            self.assertLessEqual(free, pro, meter)
            self.assertLessEqual(pro, team, meter)
            self.assertEqual(get_plan("enterprise").quota(meter), CUSTOM)

    def test_unknown_plan_raises(self):
        with self.assertRaises(KeyError):
            get_plan("platinum")

    def test_no_hardcoded_stripe_ids(self):
        for p in all_plans():
            self.assertTrue(p.price_env_var.startswith("HEEL_STRIPE_PRICE_"))

    def test_enterprise_gated_features_only_on_enterprise(self):
        for pid in ("free", "pro", "team"):
            self.assertFalse(get_plan(pid).features & CONFIG_GATED_FEATURES, pid)
        self.assertTrue(CONFIG_GATED_FEATURES <= get_plan("enterprise").features)


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.ledger = UsageLedger.in_memory()
        self.addCleanup(self.ledger.conn.close)
        self.pro = get_plan("pro")

    def test_reserve_counts_and_quota_blocks(self):
        for _ in range(300):
            self.ledger.reserve(self.pro, "ws", Meter.RUNS, 1, PERIOD)
        with self.assertRaises(QuotaExceeded):
            self.ledger.reserve(self.pro, "ws", Meter.RUNS, 1, PERIOD)
        self.assertEqual(self.ledger.remaining(self.pro, "ws", Meter.RUNS, PERIOD), 0)

    def test_refund_releases_consume_keeps(self):
        r1 = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 5, PERIOD)
        r2 = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 5, PERIOD)
        self.assertEqual(self.ledger.usage("ws", Meter.RUNS, PERIOD), 10)
        self.assertTrue(self.ledger.refund(r1.reservation_id))
        self.assertEqual(self.ledger.usage("ws", Meter.RUNS, PERIOD), 5)
        self.assertTrue(self.ledger.consume(r2.reservation_id))
        self.assertEqual(self.ledger.usage("ws", Meter.RUNS, PERIOD), 5)

    def test_settle_terminal_states(self):
        r = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 1, PERIOD)
        self.assertTrue(self.ledger.consume(r.reservation_id))
        self.assertFalse(self.ledger.consume(r.reservation_id))   # idempotent
        self.assertFalse(self.ledger.refund(r.reservation_id))    # no refund after consume
        r2 = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 1, PERIOD)
        self.assertTrue(self.ledger.refund(r2.reservation_id))
        self.assertFalse(self.ledger.refund(r2.reservation_id))   # no double refund
        self.assertFalse(self.ledger.consume(r2.reservation_id))  # refunded is terminal

    def test_unknown_reservation_raises(self):
        with self.assertRaises(KeyError):
            self.ledger.consume("resv_nope")

    def test_idempotent_reserve_replay(self):
        a = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 3, PERIOD, idempotency_key="job-1")
        b = self.ledger.reserve(self.pro, "ws", Meter.RUNS, 3, PERIOD, idempotency_key="job-1")
        self.assertEqual(a.reservation_id, b.reservation_id)
        self.assertEqual(self.ledger.usage("ws", Meter.RUNS, PERIOD), 3)

    def test_periods_and_tenants_isolated(self):
        self.ledger.reserve(self.pro, "ws_a", Meter.RUNS, 300, PERIOD)
        # Other tenant and other period unaffected
        self.ledger.reserve(self.pro, "ws_b", Meter.RUNS, 1, PERIOD)
        self.ledger.reserve(self.pro, "ws_a", Meter.RUNS, 1, "2026-08")

    def test_zero_or_negative_amount_rejected(self):
        for amt in (0, -1):
            with self.assertRaises(ValueError):
                self.ledger.reserve(self.pro, "ws", Meter.RUNS, amt, PERIOD)

    def test_enterprise_custom_quota_unlimited(self):
        ent = get_plan("enterprise")
        self.ledger.reserve(ent, "ws", Meter.RUNS, 10_000, PERIOD)
        self.assertIsNone(self.ledger.remaining(ent, "ws", Meter.RUNS, PERIOD))

    def test_concurrent_boundary_race_single_winner(self):
        """Two threads racing for the last unit of quota: exactly one must win."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        path = tmp.name
        keeper = sqlite3.connect(path, check_same_thread=False)
        self.addCleanup(keeper.close)
        keeper.row_factory = sqlite3.Row
        ledger_main = UsageLedger(keeper)
        free = get_plan("free")
        for _ in range(24):
            ledger_main.reserve(free, "ws", Meter.RUNS, 1, PERIOD)
        results = []

        def worker():
            c = sqlite3.connect(path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            lg = UsageLedger(c)
            try:
                lg.reserve(free, "ws", Meter.RUNS, 1, PERIOD)
                results.append("ok")
            except QuotaExceeded:
                results.append("blocked")
            finally:
                c.close()

        ts = [threading.Thread(target=worker) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(results), ["blocked", "ok"])
        self.assertEqual(ledger_main.usage("ws", Meter.RUNS, PERIOD), 25)


class TestEntitlements(unittest.TestCase):
    def setUp(self):
        self.ledger = UsageLedger.in_memory()
        self.addCleanup(self.ledger.conn.close)
        self.svc = EntitlementService(self.ledger, config_features=frozenset())

    def test_inactive_states_fall_back_to_free(self):
        for state in ("canceled", "unpaid", "incomplete"):
            self.assertEqual(self.svc.effective_plan(sub("team", state)).id, "free", state)
        for state in ("trialing", "active", "past_due"):
            self.assertEqual(self.svc.effective_plan(sub("team", state)).id, "team", state)

    def test_config_gated_features_never_dead_checkboxes(self):
        ent = sub("enterprise")
        self.assertFalse(self.svc.has_feature(ent, Feature.SSO))
        self.assertEqual(self.svc.feature_status(ent, Feature.SSO), "contact_sales")
        configured_ledger = UsageLedger.in_memory()
        self.addCleanup(configured_ledger.conn.close)
        configured = EntitlementService(configured_ledger,
                                        config_features=frozenset({Feature.SSO}))
        self.assertTrue(configured.has_feature(ent, Feature.SSO))
        self.assertEqual(configured.feature_status(ent, Feature.SSO), "enabled")

    def test_feature_status_unavailable_on_lower_tier(self):
        self.assertEqual(self.svc.feature_status(sub("free"), Feature.API), "unavailable")
        self.assertEqual(self.svc.feature_status(sub("pro"), Feature.API), "enabled")

    def test_reserve_and_can_run_through_service(self):
        s = sub("free")
        for _ in range(25):
            self.svc.reserve(s, Meter.RUNS, 1, PERIOD)
        self.assertFalse(self.svc.can_run(s, PERIOD))
        with self.assertRaises(QuotaExceeded):
            self.svc.reserve(s, Meter.RUNS, 1, PERIOD)
        self.assertEqual(self.svc.upgrade_target(s), "pro")

    def test_upgrade_target_chain(self):
        self.assertEqual(self.svc.upgrade_target(sub("pro")), "team")
        self.assertEqual(self.svc.upgrade_target(sub("team")), "enterprise")
        self.assertIsNone(self.svc.upgrade_target(sub("enterprise")))

    def test_canceled_paid_plan_enforces_free_quota(self):
        s = sub("team", "canceled")
        self.assertEqual(self.svc.quota(s, Meter.RUNS), 25)


class TestTenancy(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlaneStore()
        self.addCleanup(self.store.conn.close)
        self.org = self.store.create_org("Acme")
        self.ws = self.store.create_workspace(self.org, "prod", "free", CATALOG_VERSION)
        self.owner = self.store.create_user("owner@acme.test")
        self.store.add_member(self.ws, self.owner, Role.OWNER)

    def test_require_blocks_non_member_and_wrong_role(self):
        other_ws = self.store.create_workspace(self.org, "other", "free", CATALOG_VERSION)
        with self.assertRaises(PermissionError):
            require(self.store, other_ws, self.owner, "view")  # cross-tenant
        viewer = self.store.create_user("v@acme.test")
        self.store.add_member(self.ws, viewer, Role.VIEWER)
        self.assertEqual(require(self.store, self.ws, viewer, "view"), Role.VIEWER)
        with self.assertRaises(PermissionError):
            require(self.store, self.ws, viewer, "run_rehearsal")

    def test_role_capability_matrix(self):
        self.assertTrue(role_can(Role.OWNER, "create_scope"))
        self.assertFalse(role_can(Role.MEMBER, "create_scope"))
        self.assertTrue(role_can(Role.BILLING, "manage_billing"))
        self.assertFalse(role_can(Role.BILLING, "run_rehearsal"))

    def test_invite_flow_single_use_hashed(self):
        token = self.store.create_invite(self.ws, "new@acme.test", Role.MEMBER)
        row = self.store.conn.execute("SELECT token_hash FROM invites").fetchone()
        self.assertNotEqual(row["token_hash"], token)  # only the hash is stored
        uid = self.store.create_user("new@acme.test")
        self.assertEqual(self.store.accept_invite(self.ws, token, uid), Role.MEMBER)
        with self.assertRaises(PermissionError):
            self.store.accept_invite(self.ws, token, uid)  # single use
        with self.assertRaises(PermissionError):
            self.store.accept_invite(self.ws, "bogus", uid)

    def test_api_key_hashed_scoped_revocable(self):
        issued = self.store.issue_api_key(self.ws, Role.MEMBER, "ci")
        self.assertTrue(issued.secret.startswith("heel_sk_"))
        row = self.store.conn.execute("SELECT key_hash FROM api_keys").fetchone()
        self.assertNotIn(issued.secret, row["key_hash"])
        self.assertEqual(self.store.authenticate_api_key(issued.secret),
                         (self.ws, Role.MEMBER))
        self.assertIsNone(self.store.authenticate_api_key("heel_sk_wrong"))
        self.store.revoke_api_key(issued.key_id)
        self.assertIsNone(self.store.authenticate_api_key(issued.secret))

    def test_api_key_pepper_changes_hash(self):
        h1 = hash_api_key("s")
        os.environ["HEEL_API_KEY_PEPPER"] = "pep"
        try:
            self.assertNotEqual(hash_api_key("s"), h1)
        finally:
            del os.environ["HEEL_API_KEY_PEPPER"]

    def test_workspace_plan_pins_catalog_version(self):
        self.store.set_workspace_plan(self.ws, "pro", CATALOG_VERSION)
        row = self.store.get_workspace(self.ws)
        self.assertEqual((row["plan_id"], row["catalog_version"]), ("pro", CATALOG_VERSION))


class TestBilling(unittest.TestCase):
    def setUp(self):
        self.store = BillingStore.in_memory()
        self.addCleanup(self.store.conn.close)
        self.mgr = SubscriptionManager(self.store)
        self.stub = StubBilling()

    def _apply(self, ws, state, plan, **extra):
        return self.mgr.apply_event(self.stub.event(ws, f"sub.{state}", state, plan, **extra))

    def test_lifecycle_checkout_to_cancel(self):
        self.assertEqual(self._apply("ws", "incomplete", "pro"), "applied")
        self.assertEqual(self._apply("ws", "active", "pro"), "applied")
        self.assertEqual(self._apply("ws", "past_due", "pro"), "applied")
        self.assertEqual(self._apply("ws", "canceled", "pro"), "applied")
        self.assertEqual(self.store.get("ws").state, "canceled")
        self.assertEqual(self._apply("ws", "active", "team"), "applied")  # resubscribe + upgrade
        self.assertEqual(self.store.get("ws").plan_id, "team")

    def test_duplicate_event_noop(self):
        ev = self.stub.event("ws", "sub.active", "active", "pro")
        self.assertEqual(self.mgr.apply_event(ev), "applied")
        self.assertEqual(self.mgr.apply_event(ev), "duplicate")

    def test_stale_out_of_order_event_ignored(self):
        self._apply("ws", "active", "pro")     # version 1
        self._apply("ws", "canceled", "pro")   # version 2
        stale = {"id": "evt_old", "type": "sub.active", "workspace_id": "ws",
                 "state": "active", "plan_id": "pro", "version": 1}
        self.assertEqual(self.mgr.apply_event(stale), "stale")
        self.assertEqual(self.store.get("ws").state, "canceled")

    def test_illegal_transition_rejected(self):
        self._apply("ws", "canceled", "pro")
        bad = {"id": "evt_bad", "type": "sub.past_due", "workspace_id": "ws",
               "state": "past_due", "plan_id": "pro", "version": 99}
        self.assertEqual(self.mgr.apply_event(bad), "illegal")

    def test_unknown_plan_in_event_raises(self):
        ev = self.stub.event("ws", "sub.active", "active", "platinum")
        with self.assertRaises(KeyError):
            self.mgr.apply_event(ev)

    def test_webhook_signature_verify_and_replay_window(self):
        payload, secret, ts = b'{"id":"evt_1"}', "whsec_test", 1_000_000
        sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
        header = f"t={ts},v1={sig}"
        verify_webhook_signature(payload, header, secret, now=ts + 10)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, header, secret, now=ts + 3600)  # replay
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, f"t={ts},v1=deadbeef", secret, now=ts)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, header, "", now=ts)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, "garbage", secret, now=ts)

    def test_live_price_id_from_env_only(self):
        pro = get_plan("pro")
        os.environ.pop("HEEL_STRIPE_PRICE_PRO_MONTH", None)
        with self.assertRaises(KeyError):
            live_price_id(pro, "month")
        os.environ["HEEL_STRIPE_PRICE_PRO_MONTH"] = "price_env_123"
        try:
            self.assertEqual(live_price_id(pro, "month"), "price_env_123")
        finally:
            del os.environ["HEEL_STRIPE_PRICE_PRO_MONTH"]

    def test_stub_price_ids_clearly_fake(self):
        self.assertIn("stub", self.stub.price_id(get_plan("pro"), "month"))

    def test_entitlements_follow_billing_state(self):
        """End-to-end: webhook drives state; entitlement service answers from it."""
        ledger = UsageLedger.in_memory()
        self.addCleanup(ledger.conn.close)
        svc = EntitlementService(ledger, config_features=frozenset())
        self._apply("ws", "active", "pro")
        st = self.store.get("ws")
        s = Subscription("ws", st.plan_id, st.state, st.catalog_version)
        self.assertTrue(svc.has_feature(s, Feature.API))
        self._apply("ws", "unpaid", "pro")
        st = self.store.get("ws")
        s = Subscription("ws", st.plan_id, st.state, st.catalog_version)
        self.assertFalse(svc.has_feature(s, Feature.API))
        self.assertEqual(svc.quota(s, Meter.RUNS), 25)  # free quota enforced


if __name__ == "__main__":
    unittest.main()
