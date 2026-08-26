"""Phase 3 tests: target verification, egress guard, job plane, and the wired HTTP run path."""
from __future__ import annotations

import os

os.environ.setdefault("HEEL_SIGNUP_MAX_PER_IP", "100000")   # suite shares one loopback IP
os.environ.setdefault("HEEL_SIGNUP_MAX_GLOBAL", "100000")

import http.client
import json
import sqlite3
import threading
import unittest

from heel.saas.egress import EgressPolicy
from heel.saas.http_api import ControlPlane, serve
from heel.saas.jobs import JobPlane, RunBudget
from heel.saas.ledger import UsageLedger
from heel.saas.verification import TargetVerifier, valid_hostname

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
        self.addCleanup(v.conn.close)
        ch = v.start("ws1", "App.Example.COM.")
        self.assertEqual(ch.hostname, "app.example.com")
        self.assertFalse(v.check("ws1", "app.example.com"))       # not published yet
        records["_heel.app.example.com"] = [f"heel-verify={ch.token}"]
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
        self.addCleanup(v.conn.close)
        ch = v.start("ws1", "site.example.org")
        pages[ch.http_url] = f"heel-verify={ch.token}\n"
        self.assertTrue(v.check("ws1", "site.example.org"))
        with self.assertRaises(ValueError):
            v.start("ws1", "127.0.0.1")

    def test_no_resolver_means_no_verification(self):
        v = TargetVerifier(_conn())
        self.addCleanup(v.conn.close)
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
        self.conn = _conn()
        self.addCleanup(self.conn.close)
        self.ledger = UsageLedger(self.conn)
        self.jobs = JobPlane(self.conn, scope_validator=lambda ws, ref, tgt: ref == f"scope-ok-{ws}-{tgt}")

    def _resv(self, ws="ws1"):
        from heel.saas.catalog import Meter, get_plan
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
        from heel.saas.catalog import Meter
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
                              scope_ref="scope-ok-ws1-a.example.com")
        with self.assertRaises(PermissionError):    # bad scope
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                              target="a.example.com", target_is_verified=True,
                              scope_ref="forged")
        with self.assertRaises(PermissionError):    # egress beyond target
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                              target="a.example.com", target_is_verified=True,
                              scope_ref="scope-ok-ws1-a.example.com",
                              budget=RunBudget(egress_hosts=("a.example.com", "evil.com")))
        job = self.jobs.enqueue("ws1", kind="verified", reservation_ids=rid,
                                target="a.example.com", target_is_verified=True,
                                scope_ref="scope-ok-ws1-a.example.com")
        self.assertEqual(job.budget.egress_hosts, ("a.example.com",))

    def test_scope_is_bound_to_the_exact_target(self):
        # A scope minted for a.example.com must not authorize a run against b.example.com,
        # even though both belong to the same workspace and b is verified.
        r = self._resv()
        with self.assertRaises(PermissionError):
            self.jobs.enqueue("ws1", kind="verified", reservation_ids=[r.reservation_id],
                              target="b.example.com", target_is_verified=True,
                              scope_ref="scope-ok-ws1-a.example.com")

    def test_workspace_pinned_worker_never_claims_foreign_jobs(self):
        r1, r2 = self._resv("ws1"), self._resv("ws2")
        self.jobs.enqueue("ws1", kind="synthetic", reservation_ids=[r1.reservation_id])
        j2 = self.jobs.enqueue("ws2", kind="synthetic", reservation_ids=[r2.reservation_id])
        got = self.jobs.claim("worker-ws2", workspace_id="ws2")
        self.assertEqual(got.job_id, j2.job_id)
        self.assertIsNone(self.jobs.claim("worker-ws2", workspace_id="ws2"))  # ws1 job untouched

    def test_no_validator_disables_verified(self):
        plane = JobPlane(_conn(), scope_validator=None)
        self.addCleanup(plane.conn.close)
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
                              scope_validator=lambda ws, ref, tgt: ref.startswith("scope-ok"))
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
        return body["workspace_id"], {"Cookie": f"heel_session={token}"}

    def test_verify_target_then_verified_run(self):
        wid, hdr = self.signup("runner@example.com")
        status, ch = self.req("POST", f"/v1/workspaces/{wid}/targets",
                              {"hostname": "app.example.com"}, hdr)
        self.assertEqual(status, 201)
        # verified run before verification → 403
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs",
                                  {"verified": True, "target": "app.example.com",
                                   "scope_ref": "scope-ok-1"}, hdr)[0], 403)
        self.records["_heel.app.example.com"] = [f"heel-verify={ch['token']}"]
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
        self.records["_heel.one.example.com"] = [f"heel-verify={ch['token']}"]
        self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                 {"hostname": "one.example.com"}, hdr)
        # free tier: 1 verified target
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets",
                                {"hostname": "two.example.com"}, hdr)
        self.assertEqual(status, 402)
        self.assertEqual(body["upgrade_to"], "pro")


class ScopeMintPathTests(unittest.TestCase):
    """The hosted human-only scope path: verify target -> session mints scope -> verified run."""

    @classmethod
    def setUpClass(cls):
        cls.records = {}
        cls.cp = ControlPlane(
            dns_txt=lambda name: cls.records.get(name, []),
            scope_validator=lambda ws, ref, tgt: ref == f"minted-{ws}-{tgt}",
            scope_minter=lambda ws, tgt, uid: f"minted-{ws}-{tgt}")
        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    req = HttpRunPathTests.req
    signup = HttpRunPathTests.signup

    def _verify(self, wid, hdr, host):
        _, ch = self.req("POST", f"/v1/workspaces/{wid}/targets", {"hostname": host}, hdr)
        self.records[f"_heel.{host}"] = [f"heel-verify={ch['token']}"]
        self.req("POST", f"/v1/workspaces/{wid}/targets/check", {"hostname": host}, hdr)

    def test_mint_requires_stepup_reason_and_verified_target(self):
        wid, hdr = self.signup("minter@example.com")
        # unverified target refused before anything else can happen
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                  {"target": "app.example.com", "confirm_target": "app.example.com",
                                   "reason": "rehearsal"}, hdr)[0], 403)
        self._verify(wid, hdr, "app.example.com")
        # step-up confirmation must repeat the exact target
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                  {"target": "app.example.com", "confirm_target": "app.example.co",
                                   "reason": "rehearsal"}, hdr)[0], 400)
        # a reason is mandatory (it lands in the audit log)
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                  {"target": "app.example.com",
                                   "confirm_target": "app.example.com"}, hdr)[0], 400)
        status, body = self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                {"target": "app.example.com", "confirm_target": "app.example.com",
                                 "reason": "quarterly rehearsal"}, hdr)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["scope_ref"], f"minted-{wid}-app.example.com")
        # the mint is audited
        self.assertTrue(any(r["action"] == "scope_mint" for r in self.cp.ops.audit_tail()))
        # and the minted scope drives a verified run end to end
        status, run = self.req("POST", f"/v1/workspaces/{wid}/runs",
                               {"verified": True, "target": "app.example.com",
                                "scope_ref": body["scope_ref"]}, hdr)
        self.assertEqual(status, 202, run)
        # target binding at HTTP level: a scope minted for one target is refused for another
        # (cross-target unit coverage lives in test_scope_is_bound_to_the_exact_target)
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs",
                                  {"verified": True, "target": "other.example.com",
                                   "scope_ref": body["scope_ref"]}, hdr)[0], 403)

    def test_parallel_challenges_cannot_verify_past_target_quota(self):
        # Sol Gate-1 regression: start two challenges while under quota, verify one, then the
        # second check must be refused (402), not verified — quota is enforced at check time.
        wid, hdr = self.signup("parallel@example.com")   # free: 1 verified target
        _, ch1 = self.req("POST", f"/v1/workspaces/{wid}/targets", {"hostname": "a.example.com"}, hdr)
        _, ch2 = self.req("POST", f"/v1/workspaces/{wid}/targets", {"hostname": "b.example.com"}, hdr)
        self.records["_heel.a.example.com"] = [f"heel-verify={ch1['token']}"]
        self.records["_heel.b.example.com"] = [f"heel-verify={ch2['token']}"]
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                                {"hostname": "a.example.com"}, hdr)
        self.assertTrue(body["verified"])
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                                {"hostname": "b.example.com"}, hdr)
        self.assertEqual(status, 402, body)
        # re-checking the already-verified target stays allowed at the limit
        status, body = self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                                {"hostname": "a.example.com"}, hdr)
        self.assertEqual(status, 200)

    def test_api_keys_can_never_mint(self):
        wid, hdr = self.signup("keys@example.com")
        self.cp.store.conn.execute(
            "UPDATE workspaces SET plan_id='pro' WHERE workspace_id=?", (wid,))
        self.cp.store.conn.commit()   # API keys are a paid feature
        _, key = self.req("POST", f"/v1/workspaces/{wid}/api-keys",
                          {"role": "member", "name": "ci"}, hdr)
        khdr = {"Authorization": f"Bearer {key['secret']}"}
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                  {"target": "x.example.com", "confirm_target": "x.example.com",
                                   "reason": "nope"}, khdr)[0], 403)

    def test_unconfigured_minter_fails_closed(self):
        records = {}
        cp = ControlPlane(dns_txt=lambda name: records.get(name, []))
        server = serve(cp)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            saved_port, type(self).port = self.port, port
            try:
                wid, hdr = self.signup("nominter@example.com")
                _, ch = self.req("POST", f"/v1/workspaces/{wid}/targets",
                                 {"hostname": "app.example.com"}, hdr)
                records["_heel.app.example.com"] = [f"heel-verify={ch['token']}"]
                self.req("POST", f"/v1/workspaces/{wid}/targets/check",
                         {"hostname": "app.example.com"}, hdr)
                status, _ = self.req("POST", f"/v1/workspaces/{wid}/scopes",
                                     {"target": "app.example.com",
                                      "confirm_target": "app.example.com",
                                      "reason": "rehearsal"}, hdr)
                self.assertEqual(status, 501)
            finally:
                type(self).port = saved_port
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
