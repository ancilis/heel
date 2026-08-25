from __future__ import annotations

import base64
import http.client
import json
from pathlib import Path
import socket
from urllib.parse import urlsplit

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.runner.companion import CompanionServer


def views():
    fixture_root = Path(__file__).parent / "fixtures/canary/contracts"
    operational = json.loads((fixture_root / "operational-run.v1.json").read_text())
    findings = json.loads((fixture_root / "canary-findings.v1.json").read_text())
    authority = SigningAuthority.generate()
    for record in (operational, findings):
        unsigned = {
            key: value for key, value in record.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        record.clear()
        record.update({
            **unsigned,
            "projection_digest": canonical_digest(unsigned),
            **authority.sign(canonical_bytes(unsigned)),
        })
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
    return result, disclosure, {authority.key_id: authority.public_key}


def request(server, method, path, *, body=b"", headers=None, host=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
    supplied = {"Host": host or f"127.0.0.1:{server.port}", **(headers or {})}
    connection.request(method, path, body=None if body == b"" else body, headers=supplied)
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


def test_companion_is_loopback_fragment_bootstrapped_one_use_and_data_free_at_root():
    result, disclosure, keys = views()
    server = CompanionServer(
        result, disclosure, trusted_runner_keys=keys,
        bootstrap_bytes=b"x" * 32, clock=lambda: 100.0,
    )
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
    result, disclosure, keys = views()
    server = CompanionServer(result, disclosure, trusted_runner_keys=keys)
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
    result, disclosure, keys = views()
    now = [100.0]
    server = CompanionServer(
        result, disclosure, trusted_runner_keys=keys,
        bootstrap_bytes=b"z" * 32, clock=lambda: now[0],
    )
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


def raw_request(server, payload):
    connection = socket.create_connection(("127.0.0.1", server.port), timeout=2)
    try:
        connection.sendall(payload)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)
    finally:
        connection.close()


def test_companion_rejects_duplicate_or_transfer_framed_security_headers():
    result, disclosure, keys = views()
    server = CompanionServer(result, disclosure, trusted_runner_keys=keys)
    server.start()
    try:
        origin = server.origin
        host = f"127.0.0.1:{server.port}"
        cases = (
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nX-Heel-Local-Origin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nOrigin: {origin}\r\nOrigin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nCookie: a=b\r\nCookie: c=d\r\n\r\n",
            f"POST /v1/session HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}",
            f"POST /v1/session HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        for source in cases:
            response = raw_request(server, source.encode("ascii"))
            status = int(response.split(b" ", 2)[1])
            assert status in {400, 403}
            assert b"Access-Control-Allow-Origin" not in response
    finally:
        server.close()


def test_companion_rejects_invalid_projection_signature_before_binding():
    result, disclosure, keys = views()
    invalid_signature = base64.b64encode(b"\0" * 64).decode("ascii")
    result["findings_projection"]["signature_b64"] = invalid_signature
    disclosure["projection"]["signature_b64"] = invalid_signature
    try:
        CompanionServer(result, disclosure, trusted_runner_keys=keys)
    except ValueError as error:
        assert "signature" in str(error)
    else:
        raise AssertionError("tampered findings signature was displayed")
