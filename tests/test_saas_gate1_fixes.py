"""Gate-1 remediation tests: quota-replay, webhook fail-closed, execution-side enforcement,
catalog pinning, integrations cap, retention purge."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import sqlite3
import threading
import time
import unittest

from arceo.saas.billing import BillingStore, SubState
from arceo.saas.catalog import CATALOG_VERSION, Meter
from arceo.saas.http_api import ControlPlane, current_period, serve
from arceo.saas.jobs import JobPlane, RunBudget
from arceo.saas.ledger import UsageLedger

PW = "correct-horse-battery"
SECRET = "whsec_gate1"


def _conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _sign(payload: bytes, secret: str) -> str:
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


class Gate1HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane()
        cls.server = serve(cls.cp, webhook_secret=SECRET)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        # A second server with NO webhook secret, to prove the endpoint fails closed.
        cls.cp_open = ControlPlane()
        cls.server_open = serve(cls.cp_open)
        cls.port_open = cls.server_open.server_address[1]
        threading.Thread(target=cls.server_open.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for s in (cls.server, cls.server_open):
            s.shutdown()
            s.server_close()

    def req(self, method, path, body=None, headers=None, *, port=None):
        conn = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=10)
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, data, headers or {})
        r = conn.getresponse()
        raw = r.read()
        payload = json.loads(raw) if raw else {}
        cookies = r.getheader("Set-Cookie", "")
        conn.close()
        return r.status, payload, cookies

    def signup(self, email, *, port=None):
        status, body, cookies = self.req("POST", "/v1/signup",
                                         {"email": email, "password": PW}, port=port)
        self.assertEqual(status, 201)
        token = cookies.split(";")[0].split("=", 1)[1]
        return body["workspace_id"], {"Cookie": f"arceo_session={token}"}

    def test_idempotent_replay_creates_exactly_one_job(self):
        wid, hdr = self.signup("replay@example.com")
        body = {"idempotency_key": "same-key-123"}
        ids = set()
        for _ in range(20):
            status, resp, _ = self.req("POST", f"/v1/workspaces/{wid}/runs", body, hdr)
            self.assertEqual(status, 202)
            ids.add(resp["job_id"])
        self.assertEqual(len(ids), 1, "one reservation must fund at most one job")
        n = self.cp.store.conn.execute(
            "SELECT COUNT(*) AS n FROM jobs WHERE workspace_id=?", (wid,)).fetchone()["n"]
        self.assertEqual(n, 1)
        used = self.cp.ledger.usage(wid, Meter.RUNS, current_period())
        self.assertEqual(used, 1)

    def test_webhook_without_secret_fails_closed(self):
        wid, _ = self.signup("open@example.com", port=self.port_open)
        ev = {"id": "evt_1", "type": "sub.updated", "workspace_id": wid,
              "state": "active", "plan_id": "enterprise", "version": 1}
        status, body, _ = self.req("POST", "/v1/billing/webhook", ev, port=self.port_open)
        self.assertEqual(status, 503)
        # entitlements unchanged: still free
        self.assertEqual(self.cp_open.subscription(wid).plan_id, "free")

    def test_subscription_uses_pinned_catalog_version(self):
        wid, _ = self.signup("pinned@example.com")
        self.cp.billing_store.upsert(SubState(wid, "pro", "active", "2099-01-01", 1))
        sub = self.cp.subscription(wid)
        self.assertEqual(sub.catalog_version, "2099-01-01",
                         "grandfathering must resolve against the subscription's pinned catalog")

    def test_webhook_sync_pins_workspace_to_subscription_catalog(self):
        wid, _ = self.signup("sync@example.com")
        ev = {"id": f"evt_sync_{wid}", "type": "sub.updated", "workspace_id": wid,
              "state": "active", "plan_id": "pro", "version": 1,
              "catalog_version": CATALOG_VERSION}
        payload = json.dumps(ev).encode()
        status, _, _ = self.req("POST", "/v1/billing/webhook", ev,
                                {"X-Arceo-Billing-Signature": _sign(payload, SECRET),
                                 "Content-Type": "application/json"})
        # req() re-serializes identically (same dict order), so the signature matches
        self.assertEqual(status, 200)
        ws = self.cp.store.get_workspace(wid)
        self.assertEqual(ws["plan_id"], "pro")
        self.assertEqual(ws["catalog_version"], CATALOG_VERSION)

    def test_integrations_quota_caps_active_api_keys(self):
        wid, hdr = self.signup("keys@example.com")
        self.cp.store.conn.execute(
            "UPDATE workspaces SET plan_id='pro' WHERE workspace_id=?", (wid,))
        self.cp.store.conn.commit()
        key_ids = []
        for i in range(3):  # pro integrations quota = 3
            status, body, _ = self.req(
                "POST", f"/v1/workspaces/{wid}/api-keys", {"role": "member"}, hdr)
            self.assertEqual(status, 201)
            key_ids.append(body["key_id"])
        status, body, _ = self.req(
            "POST", f"/v1/workspaces/{wid}/api-keys", {"role": "member"}, hdr)
        self.assertEqual(status, 402)
        # revoking frees a slot
        self.assertEqual(self.req(
            "DELETE", f"/v1/workspaces/{wid}/api-keys/{key_ids[0]}", None, hdr)[0], 200)
        self.assertEqual(self.req(
            "POST", f"/v1/workspaces/{wid}/api-keys", {"role": "member"}, hdr)[0], 201)


class Gate1JobPlaneTests(unittest.TestCase):
    def _enqueue(self, jobs, ledger, ws, n):
        from arceo.saas.catalog import get_plan
        plan = get_plan("team")
        out = []
        for i in range(n):
            r = ledger.reserve(plan, ws, Meter.RUNS, 1, "2026-07")
            out.append(jobs.enqueue(ws, kind="synthetic",
                                    reservation_ids=[r.reservation_id]))
        return out

    def test_claim_enforces_concurrency_entitlement(self):
        conn = _conn()
        ledger = UsageLedger(conn)
        jobs = JobPlane(conn, concurrency_limit=lambda ws: 1)
        self._enqueue(jobs, ledger, "ws1", 3)
        first = jobs.claim("w1")
        self.assertIsNotNone(first)
        self.assertIsNone(jobs.claim("w2"), "workspace at concurrency limit must not be claimed")
        jobs.complete(first.job_id, "w1", ledger)
        self.assertIsNotNone(jobs.claim("w2"), "finishing a job frees the slot")

    def test_claim_skips_saturated_workspace_but_serves_others(self):
        conn = _conn()
        ledger = UsageLedger(conn)
        jobs = JobPlane(conn, concurrency_limit=lambda ws: 1)
        self._enqueue(jobs, ledger, "ws1", 2)
        self._enqueue(jobs, ledger, "ws2", 1)
        a = jobs.claim("w1")
        self.assertEqual(a.workspace_id, "ws1")
        b = jobs.claim("w2")
        self.assertEqual(b.workspace_id, "ws2", "saturated ws1 must be skipped, not block ws2")

    def test_retention_purge_deletes_old_finished_jobs(self):
        conn = _conn()
        ledger = UsageLedger(conn)
        jobs = JobPlane(conn, concurrency_limit=None)
        (job,) = self._enqueue(jobs, ledger, "ws1", 1)
        got = jobs.claim("w1")
        jobs.complete(got.job_id, "w1", ledger)
        conn.execute("UPDATE jobs SET finished_at=? WHERE job_id=?",
                     (time.time() - 10 * 86400, job.job_id))
        conn.commit()
        self.assertEqual(jobs.purge_retention(lambda ws: 7), 1)
        self.assertIsNone(jobs.get("ws1", job.job_id))

    def test_enqueue_replay_race_returns_single_job(self):
        conn = _conn()
        ledger = UsageLedger(conn)
        jobs = JobPlane(conn)
        from arceo.saas.catalog import get_plan
        r = ledger.reserve(get_plan("team"), "ws1", Meter.RUNS, 1, "2026-07",
                           idempotency_key="k1")
        j1 = jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r.reservation_id],
                          idempotency_key="k1")
        j2 = jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r.reservation_id],
                          idempotency_key="k1")
        self.assertEqual(j1.job_id, j2.job_id)


if __name__ == "__main__":
    unittest.main()
