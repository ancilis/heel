"""Phase 9: adversarial/black-box pass against the running control plane.

Every test here plays an attacker: cross-tenant probing, auth bypass, replay, races at the quota
boundary, and malformed input. The server must fail closed with the right status and no state
leak or double spend.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import http.client
import json
import threading
import time
import unittest

from arceo.saas.catalog import Meter, get_plan
from arceo.saas.http_api import ControlPlane, serve
from arceo.saas.ledger import QuotaExceeded

PW = "correct-horse-battery"


class AdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane()
        cls.server = serve(cls.cp, webhook_secret="whsec_adv")
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def req(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = raw if raw is not None else (
            json.dumps(body).encode() if body is not None else None)
        conn.request(method, path, data, headers or {})
        r = conn.getresponse()
        payload = r.read()
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {"_raw": payload[:100]}
        conn.close()
        return r.status, payload

    def signup(self, email):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/signup",
                     json.dumps({"email": email, "password": PW}).encode())
        r = conn.getresponse()
        b = json.loads(r.read())
        token = r.getheader("Set-Cookie").split(";")[0].split("=", 1)[1]
        conn.close()
        return b["workspace_id"], {"Cookie": f"arceo_session={token}"}, token

    def pin_plan(self, wid, plan_id="pro"):
        """Pin a workspace to a paid plan directly in the store (tests only)."""
        self.cp.store.conn.execute(
            "UPDATE workspaces SET plan_id=? WHERE workspace_id=?", (plan_id, wid))
        self.cp.store.conn.commit()

    # --- auth bypass ---
    def test_forged_and_mutated_credentials_rejected(self):
        wid, hdr, token = self.signup("adv1@example.com")
        for cookie in ("arceo_session=arceo_ses_forged", f"arceo_session={token[:-2]}xx",
                       "arceo_session=", "other=1"):
            status, _ = self.req("GET", f"/v1/workspaces/{wid}/summary",
                                 headers={"Cookie": cookie})
            self.assertEqual(status, 401, cookie)
        for authz in ("Bearer arceo_sk_forged", "Bearer ", "Basic Zm9v"):
            status, _ = self.req("GET", f"/v1/workspaces/{wid}/summary",
                                 headers={"Authorization": authz})
            self.assertEqual(status, 401, authz)

    def test_client_supplied_role_ignored(self):
        wid_a, _, _ = self.signup("adv-a@example.com")
        _, hdr_b, _ = self.signup("adv-b@example.com")
        # attacker claims a role via headers/body; server resolves membership only
        status, _ = self.req("POST", f"/v1/workspaces/{wid_a}/invites",
                             {"email": "x@e.co", "role": "admin", "as_role": "owner"},
                             {**hdr_b, "X-Role": "owner"})
        self.assertEqual(status, 403)

    # --- cross-tenant probing ---
    def test_cross_tenant_objects_unreachable(self):
        wid_a, hdr_a, _ = self.signup("tena@example.com")
        wid_b, hdr_b, _ = self.signup("tenb@example.com")
        self.pin_plan(wid_a)   # API keys are a paid-plan feature
        s, body = self.req("POST", f"/v1/workspaces/{wid_a}/runs", {}, hdr_a)
        job_id = body["job_id"]
        s, _ = self.req("GET", f"/v1/workspaces/{wid_b}/jobs/{job_id}", None, hdr_b)
        self.assertEqual(s, 404)             # exists, but not in B's tenant
        s, body = self.req("POST", f"/v1/workspaces/{wid_a}/api-keys", {"role": "member"}, hdr_a)
        key_id = body["key_id"]
        s, _ = self.req("DELETE", f"/v1/workspaces/{wid_b}/api-keys/{key_id}", None, hdr_b)
        self.assertEqual(s, 404)             # B cannot revoke A's key through B's workspace
        s, _ = self.req("DELETE", f"/v1/workspaces/{wid_a}/api-keys/{key_id}", None, hdr_b)
        self.assertEqual(s, 403)             # nor through A's workspace

    def test_invite_token_wrong_workspace_rejected(self):
        wid_a, hdr_a, _ = self.signup("inva@example.com")
        wid_b, _, _ = self.signup("invb@example.com")
        self.pin_plan(wid_a)   # free has 1 seat; invites need seat headroom
        s, body = self.req("POST", f"/v1/workspaces/{wid_a}/invites",
                           {"email": "j@e.co", "role": "viewer"}, hdr_a)
        token = body["invite_token"]
        _, hdr_j, _ = self.signup("j@e.co")
        s, _ = self.req("POST", f"/v1/workspaces/{wid_b}/invites/accept",
                        {"token": token}, hdr_j)
        self.assertEqual(s, 403)             # token is workspace-bound

    # --- replay / idempotency ---
    def test_webhook_replay_and_stale_timestamp(self):
        wid, _, _ = self.signup("replay@example.com")
        ev = self.cp.billing.event(wid, "sub.updated", "active", "pro")
        payload = json.dumps(ev).encode()

        def sig(ts):
            return f"t={ts},v1=" + hmac.new(
                b"whsec_adv", f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()

        ts = str(int(time.time()))
        s, b = self.req("POST", "/v1/billing/webhook", raw=payload,
                        headers={"X-Arceo-Billing-Signature": sig(ts)})
        self.assertEqual((s, b["disposition"]), (200, "applied"))
        s, b = self.req("POST", "/v1/billing/webhook", raw=payload,
                        headers={"X-Arceo-Billing-Signature": sig(ts)})
        self.assertNotEqual(b.get("disposition"), "applied")   # duplicate event id
        stale = str(int(time.time()) - 3600)
        s, _ = self.req("POST", "/v1/billing/webhook", raw=payload,
                        headers={"X-Arceo-Billing-Signature": sig(stale)})
        self.assertEqual(s, 400)                                # outside replay window

    def test_duplicate_idempotent_run_charged_once(self):
        wid, hdr, _ = self.signup("idem@example.com")
        for _ in range(3):
            s, _ = self.req("POST", f"/v1/workspaces/{wid}/runs",
                            {"idempotency_key": "same-key"}, hdr)
            self.assertEqual(s, 202)
        from arceo.saas.http_api import current_period
        self.assertEqual(
            self.cp.ledger.usage(wid, Meter.RUNS, current_period()), 1)

    # --- quota race ---
    def test_concurrent_reservations_never_exceed_quota(self):
        # One connection per worker (the ledger's documented concurrency contract);
        # BEGIN IMMEDIATE must serialize check-then-append at the quota boundary.
        import os
        import sqlite3
        import tempfile

        from arceo.saas.ledger import UsageLedger
        db = os.path.join(tempfile.mkdtemp(), "race.db")
        UsageLedger(sqlite3.connect(db))     # create schema
        plan = get_plan("free")   # RUNS quota 25
        wid = "ws_race_iso"
        ok, denied = [], []
        lock = threading.Lock()

        def grab(i):
            conn = sqlite3.connect(db)
            conn.row_factory = sqlite3.Row
            ledger = UsageLedger(conn)
            try:
                r = ledger.reserve(plan, wid, Meter.RUNS, 1, "2099-01")
                with lock:
                    ok.append(r)
            except QuotaExceeded:
                with lock:
                    denied.append(i)
            finally:
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(grab, range(60)))
        self.assertEqual(len(ok), 25)
        self.assertEqual(len(denied), 35)
        check = UsageLedger(sqlite3.connect(db))
        check.conn.row_factory = sqlite3.Row
        self.assertEqual(check.usage(wid, Meter.RUNS, "2099-01"), 25)

    # --- malformed input ---
    def test_malformed_and_oversized_bodies(self):
        wid, hdr, _ = self.signup("mal@example.com")
        s, _ = self.req("POST", f"/v1/workspaces/{wid}/runs", raw=b"{not json",
                        headers=hdr)
        self.assertEqual(s, 400)
        s, _ = self.req("POST", f"/v1/workspaces/{wid}/runs", raw=b'"a string"',
                        headers=hdr)
        self.assertEqual(s, 400)
        s, _ = self.req("POST", f"/v1/workspaces/{wid}/runs",
                        raw=b"x" * (70 * 1024), headers=hdr)
        self.assertEqual(s, 413)
        for path in ("/v1/../etc/passwd", "/v1/workspaces//runs", "/%2e%2e/", "/v2/health"):
            s, _ = self.req("GET", path)
            self.assertIn(s, (400, 404), path)


if __name__ == "__main__":
    unittest.main()
