"""Phase 5 tests: server-rendered onboarding/dashboard on the shared control plane."""
from __future__ import annotations

import os

os.environ.setdefault("ARCEO_SIGNUP_MAX_PER_IP", "100000")   # suite shares one loopback IP
os.environ.setdefault("ARCEO_SIGNUP_MAX_GLOBAL", "100000")

import http.client
import threading
import unittest
import urllib.parse

from arceo.saas.http_api import ControlPlane, serve

PW = "correct-horse-battery"


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = {}
        cls.cp = ControlPlane(dns_txt=lambda name: cls.records.get(name, []))
        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def req(self, method, path, form=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        h = dict(headers or {})
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, h)
        r = conn.getresponse()
        data = r.read().decode()
        out = (r.status, data, r.getheader("Set-Cookie", ""), r.getheader("Location", ""))
        conn.close()
        return out

    def signup(self, email):
        status, _, cookie, loc = self.req("POST", "/app/signup",
                                          {"email": email, "password": PW})
        self.assertEqual(status, 303)
        self.assertEqual(loc, "/app")
        token = cookie.split(";")[0].split("=", 1)[1]
        return {"Cookie": f"arceo_session={token}"}

    def test_forms_render(self):
        for path in ("/app/signup-form", "/app/login-form"):
            status, body, _, _ = self.req("GET", path)
            self.assertEqual(status, 200)
            self.assertIn("<form", body)

    def test_anonymous_dashboard_redirects_to_login(self):
        status, _, _, loc = self.req("GET", "/app")
        self.assertEqual((status, loc), (303, "/app/login-form"))

    def test_signup_dashboard_run_and_target_flow(self):
        hdr = self.signup("dash@example.com")
        status, body, _, _ = self.req("GET", "/app", headers=hdr)
        self.assertEqual(status, 200)
        self.assertIn("Free", body)
        self.assertIn("runs", body)
        # synthetic run from the dashboard
        status, _, _, loc = self.req("POST", "/app/run", {}, hdr)
        self.assertEqual((status, loc), (303, "/app"))
        _, body, _, _ = self.req("GET", "/app", headers=hdr)
        self.assertIn("synthetic", body)
        self.assertIn("queued", body)
        # add + verify a target
        self.req("POST", "/app/target", {"hostname": "dash.example.com"}, hdr)
        _, body, _, _ = self.req("GET", "/app", headers=hdr)
        self.assertIn("pending", body)
        token = body.split("arceo-verify=")[1].split("<")[0]
        self.records["_arceo.dash.example.com"] = [f"arceo-verify={token}"]
        self.req("POST", "/app/target-check", {"hostname": "dash.example.com"}, hdr)
        _, body, _, _ = self.req("GET", "/app", headers=hdr)
        self.assertIn("verified", body)

    def test_bad_login_and_bad_target_show_errors(self):
        self.signup("errs@example.com")
        status, _, _, loc = self.req("POST", "/app/login",
                                     {"email": "errs@example.com", "password": "wrong-pass-x"})
        self.assertEqual(status, 303)
        self.assertIn("err=", loc)
        status, body, _, _ = self.req("GET", loc)
        self.assertIn("invalid email or password", body)
        hdr = self.signup("errs2@example.com")
        _, _, _, loc = self.req("POST", "/app/target", {"hostname": "127.0.0.1"}, hdr)
        self.assertIn("err=", loc)

    def test_xss_escaped(self):
        hdr = self.signup("xss@example.com")
        status, body, _, _ = self.req("GET", "/app?err=%3Cscript%3Ealert(1)%3C/script%3E",
                                      headers=hdr)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_logout(self):
        hdr = self.signup("bye@example.com")
        status, _, cookie, loc = self.req("GET", "/app/logout-form", headers=hdr)
        self.assertEqual((status, loc), (303, "/app/login-form"))
        self.assertIn("Max-Age=0", cookie)
        status, _, _, loc = self.req("GET", "/app", headers=hdr)
        self.assertEqual(loc, "/app/login-form")


if __name__ == "__main__":
    unittest.main()
