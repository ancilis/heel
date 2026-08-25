"""Phase 2 tests: auth store, migrations, and the require()-guarded control-plane HTTP API."""
from __future__ import annotations

import os

os.environ.setdefault("HEEL_SIGNUP_MAX_PER_IP", "100000")   # suite shares one loopback IP
os.environ.setdefault("HEEL_SIGNUP_MAX_GLOBAL", "100000")

import http.client
import json
import sqlite3
import threading
import unittest

from heel.saas.auth import (
    LOCKOUT_THRESHOLD, AuthStore, Session, ThrottledError,
)
from heel.saas.http_api import ControlPlane, serve
from heel.saas.migrate import (
    CONTROL_PLANE_MIGRATIONS, Migration, MigrationError, Migrator, copy_table, translate,
)
from heel.saas.tenancy import Role

PW = "correct-horse-battery"


class HostedResourceLifecycleTests(unittest.TestCase):
    def test_failed_bind_does_not_take_control_plane_ownership(self):
        occupied_cp = ControlPlane()
        occupied = serve(occupied_cp)
        self.addCleanup(occupied.server_close)
        contender = ControlPlane()
        self.addCleanup(contender.close)

        with self.assertRaises(OSError):
            serve(contender, port=occupied.server_address[1])

        try:
            result = contender.store.conn.execute("SELECT 1").fetchone()[0]
        except sqlite3.ProgrammingError:
            result = None
        self.assertEqual(result, 1)

    def test_server_close_releases_all_hosted_resources_idempotently(self):
        cp = ControlPlane()
        server = serve(cp)
        listening_socket = server.socket

        server.server_close()
        server.server_close()

        self.assertEqual(listening_socket.fileno(), -1)
        with self.assertRaises(sqlite3.ProgrammingError):
            cp.store.conn.execute("SELECT 1")


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthStore(sqlite3.connect(":memory:"))
        self.addCleanup(self.auth.conn.close)

    def test_password_roundtrip_and_weak_rejected(self):
        self.auth.set_password("u1", PW)
        self.assertTrue(self.auth.verify_password("u1", PW))
        self.assertFalse(self.auth.verify_password("u1", "wrong-password"))
        self.assertFalse(self.auth.verify_password("ghost", PW))
        with self.assertRaises(ValueError):
            self.auth.set_password("u2", "short")

    def test_session_lifecycle(self):
        self.auth.set_password("u1", PW)
        ses = self.auth.login("a@b.c", "u1", PW)
        self.assertEqual(self.auth.resolve_session(ses.token), "u1")
        self.auth.revoke_session(ses.token)
        self.assertIsNone(self.auth.resolve_session(ses.token))

    def test_lockout_after_failures(self):
        self.auth.set_password("u1", PW)
        for _ in range(LOCKOUT_THRESHOLD):
            with self.assertRaises(PermissionError):
                self.auth.login("a@b.c", "u1", "bad-password-x")
        with self.assertRaises(ThrottledError):
            self.auth.login("a@b.c", "u1", PW)
        # unknown emails burn failures too, without an oracle
        with self.assertRaises(PermissionError):
            self.auth.login("nobody@b.c", None, "whatever-pass")


class MigratorTests(unittest.TestCase):
    def test_apply_all_idempotent_and_ordered(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        m = Migrator(conn, CONTROL_PLANE_MIGRATIONS)
        self.assertEqual(m.apply_all(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.assertEqual(m.apply_all(), [])
        self.assertEqual(m.current_version(), 15)
        # schema actually exists
        conn.execute("SELECT user_id FROM users")
        conn.execute("SELECT session_id FROM sessions")

    def test_rejects_bad_ordering(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        bad = [Migration(2, "b", "CREATE TABLE t(a)"), Migration(1, "a", "CREATE TABLE s(a)")]
        with self.assertRaises(MigrationError):
            Migrator(conn, bad)

    def test_translate_postgres(self):
        self.assertIn("DOUBLE PRECISION", translate("CREATE TABLE t(x REAL)", "postgres"))
        with self.assertRaises(MigrationError):
            translate("SELECT 1", "mssql")

    def test_copy_table(self):
        src = sqlite3.connect(":memory:")
        dst = sqlite3.connect(":memory:")
        self.addCleanup(src.close)
        self.addCleanup(dst.close)
        for c in (src, dst):
            Migrator(c, CONTROL_PLANE_MIGRATIONS).apply_all()
        src.execute("INSERT INTO users VALUES('u1','a@b.c',0)")
        src.commit()
        self.assertEqual(copy_table(src, dst, "users"), 1)
        self.assertEqual(dst.execute("SELECT email FROM users").fetchone()[0], "a@b.c")
        with self.assertRaises(MigrationError):
            copy_table(src, dst, "users; DROP TABLE users")


class HttpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane()
        cls.server = serve(cls.cp, webhook_secret="whsec_test")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, data, headers or {})
        r = conn.getresponse()
        raw = r.read()
        payload = json.loads(raw) if raw else {}
        cookies = r.getheader("Set-Cookie", "")
        conn.close()
        return r.status, payload, cookies

    def signup(self, email):
        status, body, cookies = self.req("POST", "/v1/signup",
                                         {"email": email, "password": PW})
        self.assertEqual(status, 201)
        token = cookies.split(";")[0].split("=", 1)[1]
        return body["user_id"], body["workspace_id"], {"Cookie": f"heel_session={token}"}

    def pin_plan(self, wid, plan_id="pro"):
        """Pin a workspace to a paid plan directly in the store (tests only)."""
        self.cp.store.conn.execute(
            "UPDATE workspaces SET plan_id=? WHERE workspace_id=?", (plan_id, wid))
        self.cp.store.conn.commit()

    def test_health_and_plans_open(self):
        self.assertEqual(self.req("GET", "/v1/health")[0], 200)
        status, body, _ = self.req("GET", "/v1/plans")
        self.assertEqual(status, 200)
        self.assertIn("free", [p["id"] for p in body["plans"]])

    def test_signup_login_me_and_dup(self):
        _, wid, hdr = self.signup("alice@example.com")
        status, body, _ = self.req("GET", "/v1/me", headers=hdr)
        self.assertEqual(status, 200)
        self.assertEqual(body["workspaces"][0]["workspace_id"], wid)
        self.assertEqual(self.req("POST", "/v1/signup",
                                  {"email": "alice@example.com", "password": PW})[0], 409)
        status, _, cookies = self.req("POST", "/v1/login",
                                      {"email": "alice@example.com", "password": PW})
        self.assertEqual(status, 200)
        self.assertIn("heel_session=", cookies)

    def test_tenant_isolation(self):
        _, wid_a, _ = self.signup("isoa@example.com")
        _, _, hdr_b = self.signup("isob@example.com")
        status, body, _ = self.req("GET", f"/v1/workspaces/{wid_a}/summary", headers=hdr_b)
        self.assertEqual(status, 403)
        self.assertEqual(self.req("GET", f"/v1/workspaces/{wid_a}/summary")[0], 401)

    def test_invite_flow_and_role_limits(self):
        _, wid, hdr = self.signup("owner-inv@example.com")
        # free has a single seat: the invite is refused with an upgrade hint
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/invites",
                                   {"email": "m@example.com", "role": "member"}, hdr)
        self.assertEqual(status, 402)
        self.assertEqual(body["upgrade_to"], "pro")
        self.pin_plan(wid)
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/invites",
                                   {"email": "m@example.com", "role": "member"}, hdr)
        self.assertEqual(status, 201)
        token = body["invite_token"]
        _, _, hdr_m = self.signup("m@example.com")
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/invites/accept",
                                   {"token": token}, hdr_m)
        self.assertEqual(status, 200)
        self.assertEqual(body["role"], "member")
        # member cannot invite
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/invites",
                                  {"email": "x@example.com", "role": "viewer"}, hdr_m)[0], 403)
        # owner-role invites are rejected
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/invites",
                                  {"email": "x@example.com", "role": "owner"}, hdr)[0], 400)

    def test_api_keys_scoped_and_never_privileged(self):
        _, wid, hdr = self.signup("keys@example.com")
        # API access is a paid feature: key creation on free is refused with an upgrade hint
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/api-keys",
                                   {"role": "member", "name": "ci"}, hdr)
        self.assertEqual(status, 402)
        self.assertEqual(body["upgrade_to"], "pro")
        self.pin_plan(wid)
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/api-keys",
                                   {"role": "member", "name": "ci"}, hdr)
        self.assertEqual(status, 201)
        key_hdr = {"Authorization": f"Bearer {body['secret']}"}
        status, me, _ = self.req("GET", "/v1/me", headers=key_hdr)
        self.assertEqual(status, 200)
        self.assertEqual(me["workspace_id"], wid)
        # admin-role keys refused at mint time
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/api-keys",
                                  {"role": "admin"}, hdr)[0], 400)
        # key cannot cross tenants
        _, wid2, _ = self.signup("keys2@example.com")
        self.assertEqual(self.req("GET", f"/v1/workspaces/{wid2}/summary",
                                  headers=key_hdr)[0], 403)
        # revoke kills it
        self.assertEqual(self.req("DELETE",
                                  f"/v1/workspaces/{wid}/api-keys/{body['key_id']}",
                                  headers=hdr)[0], 200)
        self.assertEqual(self.req("GET", "/v1/me", headers=key_hdr)[0], 401)

    def test_runs_quota_and_upgrade_hint(self):
        _, wid, hdr = self.signup("quota@example.com")
        ok = 0
        for i in range(30):
            status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/runs",
                                       {"idempotency_key": f"r{i}"}, hdr)
            if status == 202:
                ok += 1
            else:
                self.assertEqual(status, 402)
                self.assertEqual(body["upgrade_to"], "pro")
                break
        self.assertEqual(ok, 25)  # free plan RUNS quota
        # verified runs without a verified target fail closed
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs",
                                  {"verified": True}, hdr)[0], 403)

    def test_checkout_and_webhook_upgrade(self):
        _, wid, hdr = self.signup("billing@example.com")
        status, body, _ = self.req("POST", f"/v1/workspaces/{wid}/billing/checkout",
                                   {"plan": "pro", "interval": "month"}, hdr)
        self.assertEqual(status, 200)
        # unsigned webhook is rejected
        ev = self.cp.billing.event(wid, "customer.subscription.updated", "active", "pro")
        self.assertEqual(self.req("POST", "/v1/billing/webhook", ev)[0], 400)
        # signed webhook applies and re-pins the workspace plan
        import hashlib, hmac, time
        payload = json.dumps(ev).encode()
        ts = str(int(time.time()))
        sig = hmac.new(b"whsec_test", f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/billing/webhook", payload,
                     {"X-Heel-Billing-Signature": f"t={ts},v1={sig}"})
        r = conn.getresponse()
        disposition = json.loads(r.read())
        conn.close()
        self.assertEqual(r.status, 200, disposition)
        self.assertEqual(disposition["disposition"], "applied")
        status, body, _ = self.req("GET", f"/v1/workspaces/{wid}/summary", headers=hdr)
        self.assertEqual(body["plan"], "pro")

    def test_bad_inputs(self):
        self.assertEqual(self.req("GET", "/v1/nope")[0], 404)
        self.assertEqual(self.req("POST", "/v1/signup",
                                  {"email": "bad", "password": PW})[0], 400)
        _, wid, hdr = self.signup("badplan@example.com")
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/billing/checkout",
                                  {"plan": "enterprise", "interval": "month"}, hdr)[0], 400)
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/billing/checkout",
                                  {"plan": "free", "interval": "month"}, hdr)[0], 400)


if __name__ == "__main__":
    unittest.main()
