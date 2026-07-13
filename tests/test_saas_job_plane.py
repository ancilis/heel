"""Phase 3 tests: target verification, egress guard, job plane, and the wired HTTP run path."""
from __future__ import annotations

import http.client
import json
import sqlite3
import threading
import unittest

from arceo.saas.egress import EgressPolicy
from arceo.saas.http_api import ControlPlane, serve
from arceo.saas.jobs import JobPlane, RunBudget
from arceo.saas.ledger import UsageLedger
from arceo.saas.verification import TargetVerifier, valid_hostname

PW = "correct-horse-battery"


def _conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


class HostnameTests(unittest.TestCase):
    def test_public_names_only(self):
        self.assertTrue(valid_hostname("app.example.com"))
        for bad in ("localhost", "127.0.0.1", "10.0.0.8", "box.local", "svc.internal",
                    "example.com:8080", "http://example.com", "intranet", "::1"):
            self.assertFalse(valid_hostname(bad), bad)


class VerifierTests(unittest.TestCase):
    def test_dns_and_http_challenge_flow(self):
        records = {}
        v = TargetVerifier(_conn(), dns_txt=lambda name: records.get(name, []))
        ch = v.start("ws1", "App.Example.COM.")
        self.assertEqual(ch.hostname, "app.example.com")
        self.assertFalse(v.check("ws1", "app.example.com"))       # not published yet
        records["_arceo.app.example.com"] = [f"arceo-verify={ch.token}"]
        self.assertTrue(v.check("ws1", "app.example.com"))
        self.assertTrue(v.is_verified("ws1", "app.example.com"))
        self.assertEqual(v.verified_count("ws1"), 1)
        # other workspaces don't inherit verification
        self.assertFalse(v.is_verified("ws2", "app.example.com"))
        v.revoke("ws1", "app.example.com")
        self.assertFalse(v.is_verified("ws1", "app.example.com"))

    def test_http_method_and_bad_hosts(self):
        pages = {}
        v = TargetVerifier(_conn(), http_get=lambda url: pages.get(url, ""))
        ch = v.start("ws1", "site.example.org")
        pages[ch.http_url] = f"arceo-verify={ch.token}\n"
        self.assertTrue(v.check("ws1", "site.example.org"))
        with self.assertRaises(ValueError):
            v.start("ws1", "127.0.0.1")

    def test_no_resolver_means_no_verification(self):
        v = TargetVerifier(_conn())
        v.start("ws1", "a.example.com")
        self.assertFalse(v.check("ws1", "a.example.com"))


class EgressTests(unittest.TestCase):
    def test_default_deny_and_allowlist(self):
        p = EgressPolicy(("app.example.com",))
        self.assertTrue(p.allows_host("app.example.com"))
        self.assertTrue(p.allows_host("api.app.example.com"))
        self.assertFalse(p.allows_host("evil.com"))
        self.assertFalse(p.allows_host("app.example.com", port=22))
        self.assertFalse(p.allows_host("93.184.216.34"))          # literal IPs never by name
        self.assertFalse(EgressPolicy().allows_host("app.example.com"))

    def test_rebinding_blocked_at_ip(self):
        p = EgressPolicy(("app.example.com",))
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.1.1", "0.0.0.0", "::1"):
            self.assertFalse(p.allows_ip(ip), ip)
        self.assertTrue(p.allows_ip("93.184.216.34"))
        with self.assertRaises(PermissionError):
            p.check("app.example.com", "10.0.0.1")
        with self.assertRaises(PermissionError):
            p.check("evil.com", "93.184.216.34")
        p.check("app.example.com", "93.184.216.34")   # allowed: no raise


class JobPlaneTests(unittest.TestCase):
    def setUp(self):
        conn = _conn()
        self.ledger = UsageLedger(conn)
        self.jobs = JobPlane(conn, scope_validator=lambda ws, ref: ref == f"scope-ok-{ws}")

    def _resv(self, ws="ws1"):
        from arceo.saas.catalog import Meter, get_plan
        return self.ledger.reserve(get_plan("pro"), ws, Meter.RUNS, 1, "2026-07")

    def test_synthetic_lifecycle_consumes_on_success(self):
        r = self._resv()
        job = self.jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r.reservation_id])
        claimed = self.jobs.claim("w1")
        self.assertEqual(claimed.job_id, job.job_id)
        self.assertIsNone(self.jobs.claim("w2"))                  # nothing else queued
        self.assertTrue(self.jobs.complete(job.job_id, "w1", self.ledger))
        self.assertFalse(self.ledger.refund(r.reservation_id))    # already consumed
        self.assertEqual(self.jobs.get("ws1", job.job_id).state, "succeeded")
        self.assertIsNone(self.jobs.get("ws2", job.job_id))       # tenant-scoped read

    def test_failure_refunds(self):
        from arceo.saas.catalog import Meter
        r = self._resv()
        used_before = self.ledger.usage("ws1", Meter.RUNS, "2026-07")
        job = self.jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r.reservation_id])
        self.jobs.claim("w1")
        self.assertTrue(self.jobs.fail(job.job_id, "w1", self.ledger))
        self.assertLess(self.ledger.usage("ws1", Meter.RUNS, "2026-07"), used_before)

    def test_reaper_refunds_dead_lease(self):
        r = self._resv()
        job = self.jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r.reservation_id])
        self.jobs.claim("w1", lease_s=-1)
        self.assertEqual(self.jobs.reap_expired(self.ledger), 1)
        self.assertEqual(self.jobs.get("ws1", job.job_id).state, "expired")

    def test_verified_fails_closed(self):
        r = self._resv()
        rid = [r.reservation_id]
        with self.assertRaises(PermissionError):    # unverified target
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                              target="a.example.com", target_is_verified=False,
                              scope_ref="scope-ok-ws1")
        with self.assertRaises(PermissionError):    # bad scope
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                              target="a.example.com", target_is_verified=True,
                              scope_ref="forged")
        with self.assertRaises(PermissionError):    # egress beyond target
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                              target="a.example.com", target_is_verified=True,
                              scope_ref="scope-ok-ws1",
                              budget=RunBudget(egress_hosts=("a.example.com", "evil.com")))
        job = self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                                target="a.example.com", target_is_verified=True,
                                scope_ref="scope-ok-ws1")
        self.assertEqual(job.budget.egress_hosts, ("a.example.com",))

    def test_no_validator_disables_verified(self):
        plane = JobPlane(_conn(), scope_validator=None)
        with self.assertRaises(PermissionError):
            plane.enqueue("ws1", kind="verified", reservation_ids=["x"],
                          target="a.example.com", target_is_verified=True,
                          scope_ref="anything")

    def test_synthetic_gets_no_egress(self):
        with self.assertRaises(PermissionError):
            self.jobs.enqueue("ws1", kind="synthetic", reservation_ids=["x"],
                              budget=RunBudget(egress_hosts=("a.example.com",)))


class HttpRunPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = {}
        cls.cp = ControlPlane(dns_txt=lambda name: cls.records.get(name, []),
                              scope_validator=lambda ws, ref: ref.startswith("scope-ok"))
        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, json.dumps(body).encode() if body is not None else None,
                     headers or {})
        r = conn.getresponse()
        payload = json.loads(r.read() or b"{}")
        conn.close()
        return r.status, payload

    def signup(self, email):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/signup",
                     json.dumps({"email": email, "password": PW}).encode())
        r = conn.getresponse()
        body = json.loads(r.read())
        token = r.getheader("Set-Cookie").split(";")[0].split("=", 1)[1]
        conn.close()
        return body["workspace_id"], {"Cookie": f"arceo_session={token}"}

    def test_verify_target_then_verified_run(self):
        wid, hdr = self.signup("runner@example.com")
        status, ch = self.req("POST", f"/v1/workspaces/{wid}/targets",
                              {"hostname": "app.example.com"}, hdr)
        self.assertEqual(status, 201)
        # verified run before verification → 403
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs",
                                  {"verified": True, "target": "app.example.com",
                                   "scope_ref": "scope-ok-1"}, hdr)[0], 403)
        self.records["_arceo.app.example.com"] = [f"arceo-verify={ch['token']}"]
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                                {"hostname": "app.example.com"}, hdr)
        self.assertTrue(body["verified"])
        # bad scope → 403 and quota refunded (free tier: 5 verified runs still intact after)
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs",
                                  {"verified": True, "target": "app.example.com",
                                   "scope_ref": "forged"}, hdr)[0], 403)
        # good scope → queued
        status, body = self.req("POST", f"/v1/workspaces/{wid}/runs",
                                {"verified": True, "target": "app.example.com",
                                 "scope_ref": "scope-ok-1"}, hdr)
        self.assertEqual(status, 202, body)
        status, job = self.req("GET", f"/v1/workspaces/{wid}/jobs/{body['job_id']}", None, hdr)
        self.assertEqual(job["state"], "queued")
        self.assertEqual(job["kind"], "verified")
        # free tier allows 5 verified runs total; the refunded forged one didn't count
        for i in range(4):
            s, b = self.req("POST", f"/v1/workspaces/{wid}/runs",
                            {"verified": True, "target": "app.example.com",
                             "scope_ref": "scope-ok-1"}, hdr)
            self.assertEqual(s, 202, b)
        s, b = self.req("POST", f"/v1/workspaces/{wid}/runs",
                        {"verified": True, "target": "app.example.com",
                         "scope_ref": "scope-ok-1"}, hdr)
        self.assertEqual(s, 402)
        self.assertEqual(b["meter"], "verified_runs")

    def test_target_limit_enforced(self):
        wid, hdr = self.signup("limits@example.com")
        status, ch = self.req("POST", f"/v1/workspaces/{wid}/targets",
                              {"hostname": "one.example.com"}, hdr)
        self.records["_arceo.one.example.com"] = [f"arceo-verify={ch['token']}"]
        self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                 {"hostname": "one.example.com"}, hdr)
        # free tier: 1 verified target
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets",
                                {"hostname": "two.example.com"}, hdr)
        self.assertEqual(status, 402)
        self.assertEqual(body["upgrade_to"], "pro")


if __name__ == "__main__":
    unittest.main()
