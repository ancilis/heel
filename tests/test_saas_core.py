"""SaaS control-plane core: catalog, tenancy, ledger, entitlements, billing."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arceo.saas.catalog import (
    CATALOG_VERSION, CONFIG_GATED_FEATURES, CUSTOM, Feature, Meter, all_plans,
    get_plan, self_serve_plans,
)
from arceo.saas.tenancy import (
    ControlPlaneStore, Role, role_can, require, hash_api_key,
)
from arceo.saas.ledger import UsageLedger, QuotaExceeded
from arceo.saas.entitlement import EntitlementService, Subscription
from arceo.saas.billing import (
    BillingStore, SubscriptionManager, StubBilling, SubState,
    verify_webhook_signature, WebhookVerificationError, live_price_id,
)
import hashlib
import hmac


PERIOD = "2026-07"


class CatalogTests(unittest.TestCase):
    def test_plans_present_and_ordered(self):
        ids = [p.id for p in all_plans()]
        self.assertEqual(ids, ["free", "pro", "team", "enterprise"])

    def test_free_is_no_card(self):
        self.assertTrue(get_plan("free").no_card)
        self.assertEqual(get_plan("free").price_month_cents, 0)

    def test_enterprise_contact_sales_and_custom(self):
        e = get_plan("enterprise")
        self.assertTrue(e.contact_sales)
        self.assertEqual(e.quota(Meter.RUNS), CUSTOM)
        self.assertNotIn(e, self_serve_plans())

    def test_no_hardcoded_price_ids(self):
        # Price env var names exist; actual ids are NEVER in code.
        self.assertEqual(get_plan("pro").price_env_var, "ARCEO_STRIPE_PRICE_PRO")

    def test_quota_monotonic_by_tier(self):
        runs = [get_plan(p).quota(Meter.RUNS) for p in ("free", "pro", "team")]
        self.assertEqual(runs, sorted(runs))


class TenancyTests(unittest.TestCase):
    def setUp(self):
        self.s = ControlPlaneStore()
        self.org = self.s.create_org("Acme")
        self.ws = self.s.create_workspace(self.org, "Acme WS", "free", CATALOG_VERSION)
        self.owner = self.s.create_user("owner@acme.test")
        self.s.add_member(self.ws, self.owner, Role.OWNER)

    def test_roles_capabilities(self):
        self.assertTrue(role_can(Role.OWNER, "manage_billing"))
        self.assertFalse(role_can(Role.VIEWER, "run_rehearsal"))
        self.assertFalse(role_can(Role.MEMBER, "create_scope"))
        self.assertTrue(role_can(Role.ADMIN, "create_scope"))

    def test_require_cross_tenant_denied(self):
        other_ws = self.s.create_workspace(self.org, "Other", "free", CATALOG_VERSION)
        with self.assertRaises(PermissionError):
            require(self.s, other_ws, self.owner, "view")  # not a member there

    def test_require_underprivileged_denied(self):
        viewer = self.s.create_user("v@acme.test")
        self.s.add_member(self.ws, viewer, Role.VIEWER)
        with self.assertRaises(PermissionError):
            require(self.s, self.ws, viewer, "run_rehearsal")
        self.assertEqual(require(self.s, self.ws, viewer, "view"), Role.VIEWER)

    def test_api_key_hashed_and_scoped(self):
        issued = self.s.issue_api_key(self.ws, Role.MEMBER, "ci")
        self.assertTrue(issued.secret.startswith("arceo_sk_"))
        # stored value is a hash, not the secret
        row = self.s.conn.execute("SELECT key_hash FROM api_keys WHERE key_id=?",
                                  (issued.key_id,)).fetchone()
        self.assertNotEqual(row["key_hash"], issued.secret)
        self.assertEqual(row["key_hash"], hash_api_key(issued.secret))
        auth = self.s.authenticate_api_key(issued.secret)
        self.assertEqual(auth, (self.ws, Role.MEMBER))

    def test_api_key_revocation(self):
        issued = self.s.issue_api_key(self.ws, Role.MEMBER)
        self.s.revoke_api_key(issued.key_id)
        self.assertIsNone(self.s.authenticate_api_key(issued.secret))

    def test_bad_api_key_rejected(self):
        self.assertIsNone(self.s.authenticate_api_key("arceo_sk_not_real"))

    def test_invite_flow(self):
        token = self.s.create_invite(self.ws, "new@acme.test", Role.MEMBER)
        newu = self.s.create_user("new@acme.test")
        role = self.s.accept_invite(self.ws, token, newu)
        self.assertEqual(role, Role.MEMBER)
        self.assertEqual(self.s.get_role(self.ws, newu), Role.MEMBER)
        # replay of the same invite fails
        with self.assertRaises(PermissionError):
            self.s.accept_invite(self.ws, token, newu)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = UsageLedger.in_memory()
        self.plan = get_plan("free")  # runs=25
        self.ws = "ws_test"

    def test_reserve_counts_usage(self):
        self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 5, PERIOD)
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 5)
        self.assertEqual(self.ledger.remaining(self.plan, self.ws, Meter.RUNS, PERIOD), 20)

    def test_quota_hard_stop(self):
        self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 25, PERIOD)
        with self.assertRaises(QuotaExceeded):
            self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 1, PERIOD)

    def test_refund_releases_quota(self):
        r = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 25, PERIOD)
        self.assertTrue(self.ledger.refund(r.reservation_id))
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 0)
        # can reserve again after refund
        self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 25, PERIOD)

    def test_consume_keeps_quota_used(self):
        r = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 10, PERIOD)
        self.assertTrue(self.ledger.consume(r.reservation_id))
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 10)

    def test_consumed_cannot_be_refunded(self):
        r = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 10, PERIOD)
        self.ledger.consume(r.reservation_id)
        self.assertFalse(self.ledger.refund(r.reservation_id))
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 10)

    def test_refund_is_idempotent(self):
        r = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 10, PERIOD)
        self.assertTrue(self.ledger.refund(r.reservation_id))
        self.assertFalse(self.ledger.refund(r.reservation_id))  # second is a no-op
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 0)

    def test_idempotent_reserve_no_double_count(self):
        r1 = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 5, PERIOD, idempotency_key="k1")
        r2 = self.ledger.reserve(self.plan, self.ws, Meter.RUNS, 5, PERIOD, idempotency_key="k1")
        self.assertEqual(r1.reservation_id, r2.reservation_id)
        self.assertEqual(self.ledger.usage(self.ws, Meter.RUNS, PERIOD), 5)

    def test_custom_quota_unlimited(self):
        ent = get_plan("enterprise")
        self.assertIsNone(self.ledger.remaining(ent, self.ws, Meter.RUNS, PERIOD))
        self.ledger.reserve(ent, self.ws, Meter.RUNS, 10_000, PERIOD)  # no cap

    def test_concurrent_reservations_respect_quota(self):
        # Realistic model: each worker has its OWN connection to a shared db file (like separate
        # processes). 40 workers each reserve 1 against a quota of 25 → exactly 25 succeed, never more.
        import sqlite3
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()

        def new_ledger():
            c = sqlite3.connect(tmp.name, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            return UsageLedger(c)

        new_ledger()  # create schema once
        successes, errors = [], []
        lock = threading.Lock()

        def worker():
            led = new_ledger()
            try:
                led.reserve(self.plan, "ws_race", Meter.RUNS, 1, PERIOD)
                with lock:
                    successes.append(1)
            except QuotaExceeded:
                pass
            except Exception as e:  # surface unexpected (e.g. lock) failures instead of hiding them
                with lock:
                    errors.append(repr(e))

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"unexpected reserve errors: {errors[:3]}")
        self.assertEqual(sum(successes), 25)
        self.assertEqual(new_ledger().usage("ws_race", Meter.RUNS, PERIOD), 25)
        os.unlink(tmp.name)


class EntitlementTests(unittest.TestCase):
    def setUp(self):
        self.ledger = UsageLedger.in_memory()
        self.ent = EntitlementService(self.ledger, config_features=frozenset())

    def sub(self, plan_id, state="active"):
        return Subscription("ws1", plan_id, state, CATALOG_VERSION)

    def test_inactive_falls_back_to_free(self):
        s = self.sub("pro", state="canceled")
        self.assertEqual(self.ent.effective_plan(s).id, "free")
        self.assertFalse(self.ent.has_feature(s, Feature.API))

    def test_past_due_keeps_access(self):
        s = self.sub("pro", state="past_due")
        self.assertTrue(self.ent.has_feature(s, Feature.API))

    def test_config_gated_feature_disabled_until_configured(self):
        s = self.sub("enterprise")
        self.assertFalse(self.ent.has_feature(s, Feature.SSO))
        self.assertEqual(self.ent.feature_status(s, Feature.SSO), "contact_sales")
        ent2 = EntitlementService(self.ledger, config_features=frozenset({Feature.SSO}))
        self.assertTrue(ent2.has_feature(s, Feature.SSO))

    def test_unavailable_feature_status(self):
        s = self.sub("free")
        self.assertEqual(self.ent.feature_status(s, Feature.API), "unavailable")

    def test_reserve_and_upgrade_hint(self):
        s = self.sub("free")
        for _ in range(25):
            self.ent.reserve(s, Meter.RUNS, 1, PERIOD)
        self.assertFalse(self.ent.can_run(s, PERIOD))
        with self.assertRaises(QuotaExceeded):
            self.ent.reserve(s, Meter.RUNS, 1, PERIOD)
        self.assertEqual(self.ent.upgrade_target(s), "pro")

    def test_enterprise_no_upgrade_target(self):
        self.assertIsNone(self.ent.upgrade_target(self.sub("enterprise")))

    def test_verified_run_ceiling_bounds_free_liability(self):
        # Free: runs=25 but verified_runs=5. All-verified usage must stop at 5, not 25.
        s = self.sub("free")
        for i in range(5):
            self.ent.reserve_run(s, PERIOD, verified=True, idempotency_key=f"r{i}")
        with self.assertRaises(QuotaExceeded):
            self.ent.reserve_run(s, PERIOD, verified=True, idempotency_key="r5")
        # The refund on failure means total RUNS usage is exactly 5 (no leaked run credit).
        self.assertEqual(self.ledger.usage("ws1", Meter.RUNS, PERIOD), 5)
        self.assertEqual(self.ledger.usage("ws1", Meter.VERIFIED_RUNS, PERIOD), 5)
        # Synthetic runs still available up to the total run credit.
        self.ent.reserve_run(s, PERIOD, verified=False, idempotency_key="syn0")
        self.assertEqual(self.ledger.usage("ws1", Meter.RUNS, PERIOD), 6)


class BillingTests(unittest.TestCase):
    def setUp(self):
        self.store = BillingStore.in_memory()
        self.mgr = SubscriptionManager(self.store)
        self.stub = StubBilling()

    def test_signature_roundtrip(self):
        payload = b'{"hello":"world"}'
        secret = "whsec_test"
        ts = 1000
        sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
        header = f"t={ts},v1={sig}"
        verify_webhook_signature(payload, header, secret, now=ts)  # ok
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, header, "wrong", now=ts)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(payload, header, secret, now=ts + 10_000)  # replay window

    def test_full_lifecycle(self):
        wid = "ws1"
        e = self.stub.event(wid, "checkout.completed", "active", "pro", interval="month")
        self.assertEqual(self.mgr.apply_event(e), "applied")
        self.assertEqual(self.store.get(wid).state, "active")
        self.assertEqual(self.store.get(wid).plan_id, "pro")
        # upgrade
        e2 = self.stub.event(wid, "sub.updated", "active", "team")
        self.assertEqual(self.mgr.apply_event(e2), "applied")
        self.assertEqual(self.store.get(wid).plan_id, "team")
        # dunning then cancel
        self.assertEqual(self.mgr.apply_event(self.stub.event(wid, "payment.failed", "past_due", "team")), "applied")
        self.assertEqual(self.mgr.apply_event(self.stub.event(wid, "sub.deleted", "canceled", "team")), "applied")
        self.assertEqual(self.store.get(wid).state, "canceled")

    def test_duplicate_event_is_noop(self):
        e = self.stub.event("ws1", "checkout.completed", "active", "pro")
        self.assertEqual(self.mgr.apply_event(e), "applied")
        self.assertEqual(self.mgr.apply_event(e), "duplicate")

    def test_out_of_order_event_rejected(self):
        wid = "ws1"
        e1 = self.stub.event(wid, "sub.updated", "active", "pro")   # version 1
        e2 = self.stub.event(wid, "sub.updated", "active", "team")  # version 2
        self.assertEqual(self.mgr.apply_event(e2), "applied")       # v2 first
        self.assertEqual(self.mgr.apply_event(e1), "stale")         # v1 arrives late
        self.assertEqual(self.store.get(wid).plan_id, "team")

    def test_illegal_transition_rejected(self):
        wid = "ws1"
        self.mgr.apply_event(self.stub.event(wid, "sub.deleted", "canceled", "pro"))
        # canceled -> past_due is not allowed
        disp = self.mgr.apply_event(self.stub.event(wid, "x", "past_due", "pro"))
        self.assertEqual(disp, "illegal")

    def test_stub_price_id_is_fake(self):
        self.assertIn("stub", self.stub.price_id(get_plan("pro"), "month"))

    def test_live_price_id_requires_env(self):
        os.environ.pop("ARCEO_STRIPE_PRICE_PRO_MONTH", None)
        with self.assertRaises(KeyError):
            live_price_id(get_plan("pro"), "month")


if __name__ == "__main__":
    unittest.main()
