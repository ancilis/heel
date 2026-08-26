from __future__ import annotations

import base64
import http.client
import json
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.runner.companion import CompanionServer
from heel.runner.execution import ExecutionBundle, LocalCanaryExecutor
from tests.test_runner_stop import (
    ScriptedTransport, StaticVault, active_gate, compiled_pair, signed_grant,
)


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


def test_companion_rejects_caller_supplied_unverified_views():
    result, _, _ = views()
    with pytest.raises((TypeError, ValueError), match="store"):
        CompanionServer(result, "run_unverified")


def committed_run(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    return store, grant["run_id"], result.local_view, result.disclosure_preview


def request(server, method, path, *, body=b"", headers=None, host=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
    supplied = {"Host": host or f"127.0.0.1:{server.port}", **(headers or {})}
    connection.request(method, path, body=None if body == b"" else body, headers=supplied)
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


def test_companion_is_loopback_fragment_bootstrapped_one_use_and_data_free_at_root(tmp_path):
    store, run_id, result, disclosure = committed_run(tmp_path)
    server = CompanionServer(
        store, run_id,
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
        assert "unsafe-inline" not in headers["Content-Security-Policy"]
        assert b"document.cookie" not in body and b"localStorage" not in body
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Frame-Options"] == "DENY"

        bootstrap = json.dumps({"bootstrap": parsed.fragment}).encode()
        status, headers, session_body = request(
            server, "POST", "/v1/session", body=bootstrap,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )
        assert status == 200
        session = json.loads(session_body)["session"]
        assert len(session) == 43
        assert "Set-Cookie" not in headers
        assert request(
            server, "POST", "/v1/session", body=bootstrap,
            headers={"Content-Type": "application/json", "Origin": server.origin,
                     "X-Heel-Local-Origin": server.origin},
        )[0] == 403
        status, headers, payload = request(
            server, "GET", "/v1/result",
            headers={"X-Heel-Local-Session": session,
                     "X-Heel-Local-Origin": server.origin},
        )
        assert status == 200 and json.loads(payload) == result
        assert headers["Access-Control-Allow-Origin"] if "Access-Control-Allow-Origin" in headers else True
        assert "Access-Control-Allow-Origin" not in headers
        status, _, payload = request(
            server, "GET", "/v1/disclosure-preview",
            headers={"X-Heel-Local-Session": session,
                     "X-Heel-Local-Origin": server.origin},
        )
        assert status == 200 and json.loads(payload) == disclosure
        assert request(
            server, "GET", "/v1/result",
            headers={"Cookie": f"heel_local_session={session}",
                     "X-Heel-Local-Origin": server.origin},
        )[0] == 403
    finally:
        server.close()


def test_companion_rejects_rebinding_cors_queries_encoded_paths_and_private_surfaces(tmp_path):
    store, run_id, _, _ = committed_run(tmp_path)
    server = CompanionServer(store, run_id)
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


def test_companion_rejects_expired_or_oversized_bootstrap(tmp_path):
    store, run_id, _, _ = committed_run(tmp_path)
    now = [100.0]
    server = CompanionServer(
        store, run_id,
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


def test_companion_rejects_duplicate_or_transfer_framed_security_headers(tmp_path):
    store, run_id, _, _ = committed_run(tmp_path)
    server = CompanionServer(store, run_id)
    server.start()
    try:
        origin = server.origin
        host = f"127.0.0.1:{server.port}"
        cases = (
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nX-Heel-Local-Origin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nOrigin: {origin}\r\nOrigin: {origin}\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nCookie: a=b\r\nCookie: c=d\r\n\r\n",
            f"GET /v1/result HTTP/1.1\r\nHost: {host}\r\nX-Heel-Local-Origin: {origin}\r\nX-Heel-Local-Session: a\r\nX-Heel-Local-Session: b\r\n\r\n",
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


def test_companion_rejects_invalid_projection_signature_before_binding(tmp_path):
    store, run_id, _, _ = committed_run(tmp_path)
    path = store.run_path(run_id) / "finals.json"
    finals = json.loads(path.read_text())
    invalid_signature = base64.b64encode(b"\0" * 64).decode("ascii")
    finals["findings_projection"]["signature_b64"] = invalid_signature
    finals["local_view"]["findings_projection"]["signature_b64"] = invalid_signature
    finals["disclosure_preview"]["projection"]["signature_b64"] = invalid_signature
    core = {key: value for key, value in finals.items() if key != "finals_digest"}
    finals["finals_digest"] = canonical_digest(core)
    path.write_text(json.dumps(finals, sort_keys=True, separators=(",", ":")))
    with pytest.raises(ValueError, match="signature"):
        CompanionServer(store, run_id)
