#!/usr/bin/env python3
"""
End-to-end smoke test for the hosted control plane (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Boots the real HTTP server on an ephemeral loopback port and drives the golden path:
signup → dashboard → synthetic run → target verify (stub DNS) → verified run guard →
checkout stub → kill switch → health/metrics. Exits non-zero on the first failure.
Run: python3 scripts/saas_smoke.py [db_path]
"""
from __future__ import annotations

import http.client
import json
import sys
import threading

sys.path.insert(0, ".")
from arceo.saas.http_api import ControlPlane, serve  # noqa: E402

RECORDS = {}


def main(db_path: str = ":memory:") -> int:
    cp = ControlPlane(db_path, dns_txt=lambda n: RECORDS.get(n, []),
                      scope_validator=lambda ws, ref: ref == "smoke-scope")
    server = serve(cp)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def req(method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, json.dumps(body).encode() if body is not None else None,
                  headers or {})
        r = c.getresponse()
        raw = r.read()
        ct = r.getheader("Content-Type", "")
        out = (r.status, json.loads(raw) if "json" in ct and raw else raw.decode(),
               r.getheader("Set-Cookie", ""))
        c.close()
        return out

    def check(name, cond, detail=""):
        if not cond:
            print(f"FAIL {name} {detail}")
            server.shutdown()
            return False
        print(f"ok   {name}")
        return True

    steps_ok = True
    status, _, _ = req("GET", "/v1/healthz")
    steps_ok &= check("healthz", status == 200)

    status, body, cookie = req("POST", "/v1/signup",
                               {"email": "smoke@example.com", "password": "smoke-passphrase"})
    steps_ok &= check("signup", status == 201, body)
    wid = body["workspace_id"]
    hdr = {"Cookie": cookie.split(";")[0]}

    status, body, _ = req("POST", f"/v1/workspaces/{wid}/runs", {}, hdr)
    steps_ok &= check("synthetic run", status == 202, body)

    status, ch, _ = req("POST", f"/v1/workspaces/{wid}/targets",
                        {"hostname": "smoke.example.com"}, hdr)
    steps_ok &= check("target challenge", status == 201, ch)
    RECORDS["_arceo.smoke.example.com"] = [f"arceo-verify={ch['token']}"]
    status, body, _ = req("POST", f"/v1/workspaces/{wid}/targets/check",
                          {"hostname": "smoke.example.com"}, hdr)
    steps_ok &= check("target verified", body.get("verified") is True)

    status, body, _ = req("POST", f"/v1/workspaces/{wid}/runs",
                          {"verified": True, "target": "smoke.example.com",
                           "scope_ref": "bad"}, hdr)
    steps_ok &= check("verified run refused without scope", status == 403)
    status, body, _ = req("POST", f"/v1/workspaces/{wid}/runs",
                          {"verified": True, "target": "smoke.example.com",
                           "scope_ref": "smoke-scope"}, hdr)
    steps_ok &= check("verified run queued with scope", status == 202, body)

    status, body, _ = req("POST", f"/v1/workspaces/{wid}/billing/checkout",
                          {"plan": "pro", "interval": "month"}, hdr)
    steps_ok &= check("checkout stub", status == 200 and "url" in json.dumps(body), body)

    cp.ops.trip(wid, actor="smoke", reason="drill")
    status, _, _ = req("POST", f"/v1/workspaces/{wid}/runs", {}, hdr)
    steps_ok &= check("kill switch 503", status == 503)
    cp.ops.clear(wid, actor="smoke", reason="drill done")

    status, text, _ = req("GET", "/v1/metrics")
    steps_ok &= check("metrics", status == 200 and "runs_enqueued_total" in text)

    server.shutdown()
    server.server_close()
    print("SMOKE " + ("PASS" if steps_ok else "FAIL"))
    return 0 if steps_ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:2]))
