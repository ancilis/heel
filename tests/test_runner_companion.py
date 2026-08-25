from __future__ import annotations

import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit

from heel.runner.companion import CompanionServer


def views():
    fixture_root = Path(__file__).parent / "fixtures/canary/contracts"
    operational = json.loads((fixture_root / "operational-run.v1.json").read_text())
    findings = json.loads((fixture_root / "canary-findings.v1.json").read_text())
    result = {
        "schema_version": "heel.local-result-view.v1",
        "operational_projection": operational,
        "findings_projection": findings,
        "containment_summary": {
            "event_count": 2, "head_digest": "a" * 64,
            "codes": ["admitted"], "redaction_count": 0,
        },
    }
    disclosure = {
        "schema_version": "heel.local-disclosure-preview.v1",
        "projection": findings,
        "projection_digest": findings["projection_digest"],
        "projection_bytes": len(__import__("heel.canary_contracts", fromlist=["canonical_bytes"]).canonical_bytes(findings)),
        "scenario_count": 1,
        "finding_count": 0,
    }
    return result, disclosure


def request(server, method, path, *, body=b"", headers=None, host=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
    supplied = {"Host": host or f"127.0.0.1:{server.port}", **(headers or {})}
    connection.request(method, path, body=body, headers=supplied)
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


def test_companion_is_loopback_fragment_bootstrapped_one_use_and_data_free_at_root():
    result, disclosure = views()
    server = CompanionServer(result, disclosure, bootstrap_bytes=b"x" * 32, clock=lambda: 100.0)
    server.start()
    try:
        parsed = urlsplit(server.url)
        assert parsed.hostname == "127.0.0.1" and parsed.fragment
        status, headers, body = request(server, "GET", "/")
        assert status == 200 and b"operational-run" not in body and b"canary-findings" not in body
        assert headers["Cache-Control"] == "no-store"
        assert headers["Content-Security-Policy"]
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Frame-Options"] == "DENY"

        bootstrap = json.dumps({"bootstrap": parsed.fragment}).encode()
        status, headers, _ = request(
            server, "POST", "/v1/session", body=bootstrap,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )
        assert status == 204
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
        assert "Domain=" not in headers["Set-Cookie"]
        assert request(
            server, "POST", "/v1/session", body=bootstrap,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )[0] == 403
        status, headers, payload = request(
            server, "GET", "/v1/result",
            headers={"Cookie": cookie, "X-Heel-Local-Origin": server.origin},
        )
        assert status == 200 and json.loads(payload) == result
        assert headers["Access-Control-Allow-Origin"] if "Access-Control-Allow-Origin" in headers else True
        assert "Access-Control-Allow-Origin" not in headers
        status, _, payload = request(
            server, "GET", "/v1/disclosure-preview",
            headers={"Cookie": cookie, "X-Heel-Local-Origin": server.origin},
        )
        assert status == 200 and json.loads(payload) == disclosure
    finally:
        server.close()


def test_companion_rejects_rebinding_cors_queries_encoded_paths_and_private_surfaces():
    result, disclosure = views()
    server = CompanionServer(result, disclosure)
    server.start()
    try:
        for method, path, headers, host in (
            ("GET", "/v1/result?raw=true", {}, None),
            ("GET", "/v1/%72esult", {}, None),
            ("OPTIONS", "/v1/result", {"Origin": "https://evil.example"}, None),
            ("GET", "/v1/result", {"Origin": "https://evil.example",
                                     "X-Heel-Local-Origin": "https://evil.example"}, None),
            ("GET", "/v1/evidence", {}, None),
            ("GET", "/v1/credentials", {}, None),
            ("GET", "/v1/raw-traffic", {}, None),
            ("GET", "/v1/result", {}, "attacker.example"),
            ("GET", "/v1/result", {}, f"localhost:{server.port}"),
        ):
            status, response_headers, payload = request(
                server, method, path, headers=headers, host=host,
            )
            assert status in {400, 403, 404, 405}
            assert b"canary-findings" not in payload and b"operational-run" not in payload
            assert "Access-Control-Allow-Origin" not in response_headers
    finally:
        server.close()


def test_companion_rejects_expired_or_oversized_bootstrap():
    result, disclosure = views()
    now = [100.0]
    server = CompanionServer(result, disclosure, bootstrap_bytes=b"z" * 32, clock=lambda: now[0])
    server.start()
    try:
        now[0] = 161.0
        payload = json.dumps({"bootstrap": urlsplit(server.url).fragment}).encode()
        assert request(
            server, "POST", "/v1/session", body=payload,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )[0] == 403
        assert request(
            server, "POST", "/v1/session", body=b"x" * 513,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )[0] in {400, 413}
    finally:
        server.close()
