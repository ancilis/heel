"""Phase 7 tests: kill switches, admin audit, metrics, health endpoints."""
from __future__ import annotations

import os

os.environ.setdefault("HEEL_SIGNUP_MAX_PER_IP", "100000")   # suite shares one loopback IP
os.environ.setdefault("HEEL_SIGNUP_MAX_GLOBAL", "100000")

import http.client
import json
import threading
import unittest

from heel.saas.http_api import ControlPlane, serve
from heel.saas.ops import KillSwitchTripped, Metrics, OpsStore

PW = "correct-horse-battery"


class OpsStoreTests(unittest.TestCase):
    def setUp(self):
        self.ops = ControlPlane().ops

    def test_workspace_and_global_switches(self):
        self.ops.check("ws1")   # clean: no raise
        self.ops.trip("ws1", actor="oncall", reason="abuse ticket 42")
        with self.assertRaises(KillSwitchTripped):
            self.ops.check("ws1")
        self.ops.check("ws2")   # other tenants unaffected
        self.ops.trip("global", actor="oncall", reason="provider incident")
        with self.assertRaises(KillSwitchTripped):
            self.ops.check("ws2")
        self.ops.clear("global", actor="oncall", reason="resolved")
        self.ops.clear("ws1", actor="oncall", reason="resolved")
        self.ops.check("ws1")

    def test_reason_required_and_audited(self):
        with self.assertRaises(ValueError):
            self.ops.trip("global", actor="x", reason="  ")
        self.ops.trip("ws9", actor="a1", reason="r1")
        self.ops.clear("ws9", actor="a1", reason="r2")
        actions = [r["action"] for r in self.ops.audit_tail()]
        self.assertEqual(actions[:2], ["kill_switch_clear", "kill_switch_trip"])


class MetricsTests(unittest.TestCase):
    def test_counters_render(self):
        m = Metrics()
        m.inc("a_total")
        m.inc("a_total", 2)
        self.assertEqual(m.get("a_total"), 3)
        self.assertIn("heel_a_total 3\n", m.render())


class OpsHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane()
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
        raw = r.read()
        conn.close()
        ct = r.getheader("Content-Type", "")
        return r.status, (json.loads(raw) if "json" in ct else raw.decode())

    def test_healthz_readyz_metrics(self):
        self.assertEqual(self.req("GET", "/v1/healthz")[0], 200)
        status, body = self.req("GET", "/v1/readyz")
        self.assertEqual((status, body["ready"]), (200, True))
        self.assertEqual(self.req("GET", "/v1/metrics")[0], 200)

    def test_kill_switch_blocks_enqueue_and_metrics_move(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/signup",
                     json.dumps({"email": "ops@example.com", "password": PW}).encode())
        r = conn.getresponse()
        b = json.loads(r.read())
        token = r.getheader("Set-Cookie").split(";")[0].split("=", 1)[1]
        conn.close()
        wid, hdr = b["workspace_id"], {"Cookie": f"heel_session={token}"}
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs", {}, hdr)[0], 202)
        before = self.cp.metrics.get("runs_enqueued_total")
        self.assertGreaterEqual(before, 1)
        self.cp.ops.trip(wid, actor="test", reason="abuse")
        status, body = self.req("POST", f"/v1/workspaces/{wid}/runs", {}, hdr)
        self.assertEqual(status, 503)
        self.assertEqual(self.cp.metrics.get("runs_enqueued_total"), before)
        self.cp.ops.clear(wid, actor="test", reason="done")
        self.assertEqual(self.req("POST", f"/v1/workspaces/{wid}/runs", {}, hdr)[0], 202)


if __name__ == "__main__":
    unittest.main()
