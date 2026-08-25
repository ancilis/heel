import base64
import hashlib
import sqlite3
import time
import http.client
import json
import threading
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pytest

from heel.canary_contracts import canonical_bytes, validate_runner_identity
from heel.crypto import ed25519_key_id
from heel.runner.control_client import RunnerControlClient
from heel.saas.canary_store import CanaryStore
from heel.saas.runner_auth import RunnerAuthError, RunnerAuthStore
from heel.saas.http_api import ControlPlane, serve

PUBLIC_KEY = b"0123456789abcdef0123456789abcdef"
KEY_ID = ed25519_key_id(PUBLIC_KEY)

class Transport:
    def __init__(self): self.requests = []
    def post(self, path, *, headers=None, body=b""):
        self.requests.append((path, dict(headers or {}), body))
        return 200, {"X-Heel-Runner-Next-Nonce": "next-" + str(len(self.requests))}

class Signer:
    key_id = KEY_ID
    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return b"s" * 64

def client():
    transport, signer = Transport(), Signer()
    return RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=transport, nonce_source=lambda capability: capability + "-first"), transport, signer

def test_named_methods_use_fixed_workspace_paths_and_exact_pop_headers():
    control, transport, signer = client()
    control.claim()
    path, headers, body = transport.requests[0]
    assert path == "/v1/workspaces/ws/runners/runner/claim"
    assert headers == {"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": KEY_ID, "X-Heel-Runner-Timestamp-Ms": "1000", "X-Heel-Runner-Nonce": "runner_claim-first", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": base64.b64encode(b"s" * 64).decode()}
    expected = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": "ws", "runner_id": "runner", "key_id": KEY_ID, "capability": "runner_claim", "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000, "server_nonce": "runner_claim-first", "sequence": 1}
    assert signer.payloads == [b"heel.runner-pop.v1\0" + canonical_bytes(expected)]

def test_sequences_are_independent_per_run_capability_and_stop_ack_is_heartbeat():
    control, transport, _ = client()
    control.heartbeat(run_id="one")
    control.heartbeat(run_id="one")
    control.progress(run_id="one", progress=10)
    control.stop_ack(run_id="one")
    assert [h["X-Heel-Runner-Sequence"] for _, h, _ in transport.requests] == ["1", "2", "1", "3"]
    assert transport.requests[-1][0].endswith("/runs/one/stop-ack")
    assert canonical_bytes({"run_id": "one", "progress": 10}) == transport.requests[2][2]

def test_refuses_noncanonical_origin_bad_nonce_and_changed_retry():
    with pytest.raises(ValueError, match="pathless origin"):
        RunnerControlClient(origin="https://control.example?x=1", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "n")
    bad = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "")
    with pytest.raises(ValueError, match="nonce"):
        bad.claim()
    control, _, _ = client()
    control.progress(run_id="one", status="one")
    with pytest.raises(ValueError, match="changed body"):
        control.retry_last({"run_id": "one", "status": "two"})

def test_has_no_public_generic_request_api():
    control, _, _ = client()
    assert not hasattr(control, "request")
    public = {name for name, value in vars(RunnerControlClient).items() if callable(value) and not name.startswith("_")}
    assert public <= {"claim", "heartbeat", "progress", "result", "stop_ack", "retry_last"}


def test_replay_receipt_requires_a_fully_authenticated_byte_identical_pop():
    conn = sqlite3.connect(":memory:")
    CanaryStore(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(raw)
    now = int(time.time() * 1000)
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("r", "ws", "r", "active", time.time()))
    conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, "ws", "r", base64.b64encode(raw).decode(), "active", time.time()))
    nonce = "n" * 44
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "r", "claim", store._hash("nonce", nonce), 1, time.time() + 60))
    conn.commit()
    body, path = b"{}", "/v1/workspaces/ws/runners/r/claim"
    def headers(timestamp=now, signer=private):
        proof = {"schema_version":"heel.runner-request-proof.v1","workspace_id":"ws","runner_id":"r","key_id":key_id,"capability":"runner_claim","method":"POST","path":path,"body_sha256":hashlib.sha256(body).hexdigest(),"timestamp_ms":timestamp,"server_nonce":nonce,"sequence":1}
        signature = base64.b64encode(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()
        return {"X-Heel-Runner-Id":["r"],"X-Heel-Runner-Key-Id":[key_id],"X-Heel-Runner-Timestamp-Ms":[str(timestamp)],"X-Heel-Runner-Nonce":[nonce],"X-Heel-Runner-Sequence":["1"],"X-Heel-Runner-Signature":[signature],"Authorization":[],"Cookie":[]}
    accepted, next_nonce = store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(), action=lambda: {"status": "ok"})
    assert accepted == {"status": "ok"} and next_nonce
    assert store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(), action=lambda: {"status": "bad"}) == (accepted, next_nonce)
    with pytest.raises(RunnerAuthError):
        store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(now + 1), action=lambda: {"status": "leak"})
    receipt = conn.execute("SELECT response_json,next_nonce,response_ciphertext,next_nonce_ciphertext FROM canary_runner_request_ledger").fetchone()
    assert receipt[0] == "sealed" and receipt[1] != next_nonce and receipt[2] and receipt[3]


def test_http_pairing_exchange_returns_runner_only_challenge_for_activation():
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test")
    server = serve(cp)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    def request(method, path, body, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        payload = json.dumps(body, separators=(",", ":")).encode() if method == "POST" else None
        request_headers = ({"Content-Type":"application/json", **(headers or {})} if method == "POST" else (headers or {}))
        conn.request(method, path, payload, request_headers)
        response = conn.getresponse(); raw = response.read(); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, json.loads(raw), cookie
    try:
        _, signup, cookie = request("POST", "/v1/signup", {"email":"runner@example.test", "password":"correct-horse-battery"})
        browser = {"Cookie": cookie.split(";", 1)[0], "Origin":"https://heel.test", "X-Heel-Internal-Origin":"same-origin"}
        status, invitation, _ = request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings", {"schema_version":"heel.runner-pairing-invite.v1"}, browser)
        assert status == 201
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        from heel.saas.runner_auth import WORDS
        phrase = " ".join(WORDS[:6])
        status, exchanged, _ = request("POST", "/v1/runner-pairings/exchange", {"schema_version":"heel.runner-pairing-exchange.v1", "invitation_token":invitation["invitation_token"], "public_key_b64":public, "pairing_phrase":phrase, "runner_id":"runner-http", "runner_version":"v1", "adapters":{}})
        assert status == 201 and exchanged["activation_challenge"]
        status, inspect, _ = request("GET", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{exchanged['pairing_id']}", {}, browser)
        assert status == 200 and "activation_challenge" not in inspect
        fingerprint = hashlib.sha256(base64.b64decode(public)).hexdigest()
        assert request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{exchanged['pairing_id']}/approve", {"schema_version":"heel.runner-pairing-approve.v1", "pairing_phrase":phrase, "fingerprint":fingerprint}, browser)[0] == 200
        activation = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id":exchanged["pairing_id"], "challenge":exchanged["activation_challenge"]})
        signature = base64.b64encode(private.sign(activation)).decode()
        assert request("POST", f"/v1/runner-pairings/{exchanged['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v1", "signature_b64":signature})[0] == 200
        record = cp.store.conn.execute("SELECT identity_json,identity_digest FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?", (signup["workspace_id"], "runner-http")).fetchone()
        identity = validate_runner_identity(json.loads(record[0]))
        assert identity["identity_digest"] == record[1]
        assert identity["capabilities"] == ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]
        assert identity["pairing"]["fingerprint_confirmation"] == "confirmed"
        identity["rotation"]["previous_key_ids"].append("mutated")
        assert "mutated" not in cp.runner_auth.identity(signup["workspace_id"], "runner-http")["rotation"]["previous_key_ids"]
    finally:
        server.shutdown(); server.server_close()


def test_rotation_has_its_own_public_poll_and_activation_path():
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test")
    server = serve(cp); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    def request(method, path, body, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        raw = json.dumps(body, separators=(",", ":")).encode() if method == "POST" else None
        conn.request(method, path, raw, ({"Content-Type":"application/json", **(headers or {})} if method == "POST" else (headers or {})))
        response = conn.getresponse(); payload = json.loads(response.read()); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, payload, cookie
    try:
        _, signup, cookie = request("POST", "/v1/signup", {"email":"rotate@example.test", "password":"correct-horse-battery"})
        browser = {"Cookie":cookie.split(";", 1)[0], "Origin":"https://heel.test", "X-Heel-Internal-Origin":"same-origin"}
        _, invite, _ = request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings", {"schema_version":"heel.runner-pairing-invite.v1"}, browser)
        old = Ed25519PrivateKey.generate(); old_public = base64.b64encode(old.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        from heel.runner.identity import runner_phrase_words
        phrase = " ".join(runner_phrase_words()[:6])
        _, pending, _ = request("POST", "/v1/runner-pairings/exchange", {"schema_version":"heel.runner-pairing-exchange.v1", "invitation_token":invite["invitation_token"], "public_key_b64":old_public, "pairing_phrase":phrase, "runner_id":"rotating", "runner_version":"v1", "adapters":{}}, {})
        request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{pending['pairing_id']}/approve", {"schema_version":"heel.runner-pairing-approve.v1", "pairing_phrase":phrase, "fingerprint":pending["fingerprint"]}, browser)
        proof = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id":pending["pairing_id"], "challenge":pending["activation_challenge"]})
        request("POST", f"/v1/runner-pairings/{pending['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v1", "signature_b64":base64.b64encode(old.sign(proof)).decode()})
        new = Ed25519PrivateKey.generate(); new_public = base64.b64encode(new.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        old_fingerprint = hashlib.sha256(base64.b64decode(old_public)).hexdigest()
        status, rotation, _ = request("POST", f"/v1/workspaces/{signup['workspace_id']}/runners/rotating/rotate", {"schema_version":"heel.runner-rotation-start.v1", "previous_fingerprint":old_fingerprint, "public_key_b64":new_public, "pairing_phrase":phrase, "runner_version":"v2", "adapters":{}}, browser)
        assert status == 201 and "activation_challenge" not in rotation
        assert request("GET", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{rotation['pairing_id']}", {}, browser)[0] == 404
        assert request("POST", f"/v1/workspaces/{signup['workspace_id']}/runners/rotating/rotations/{rotation['pairing_id']}/approve", {"schema_version":"heel.runner-rotation-approve.v1", "pairing_phrase":phrase, "fingerprint":rotation["fingerprint"]}, browser)[0] == 200
        status, poll, _ = request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/poll", {})
        assert status == 200 and poll["activation_challenge"]
        proof = b"heel.runner-rotation-activate.v1\0" + canonical_bytes({"pairing_id":rotation["pairing_id"], "challenge":poll["activation_challenge"]})
        assert request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/activate", {"schema_version":"heel.runner-rotation-activate.v1", "signature_b64":base64.b64encode(new.sign(proof)).decode()})[0] == 200
        identity = cp.runner_auth.identity(signup["workspace_id"], "rotating")
        assert identity["state"] == "active" and identity["public_key"]["public_key_b64"] == new_public
        assert identity["rotation"]["previous_key_ids"]
    finally:
        server.shutdown(); server.server_close()


def test_runner_request_uses_a_fresh_connection_and_never_joins_human_write():
    """A short human write may delay, but never becomes part of, the runner PoP transaction."""
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "control.sqlite")
        opened = []
        def factory():
            conn = sqlite3.connect(path, check_same_thread=False)
            opened.append(conn)
            return conn
        cp = ControlPlane(path, runner_auth_pepper=b"r" * 32, runner_connection_factory=factory,
                          runner_connections_are_shared=False)
        try:
            cp.store.create_org("org")
            org = cp.store.conn.execute("SELECT org_id FROM orgs").fetchone()[0]
            workspace = cp.store.create_workspace(org, "ws", "free", "2026-08")
            private = Ed25519PrivateKey.generate()
            raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            key_id = ed25519_key_id(raw); nonce = "n" * 44
            cp.store.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", time.time()))
            cp.store.conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", base64.b64encode(raw).decode(), "active", time.time()))
            cp.store.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", cp.runner_auth._hash("nonce", nonce), 1, time.time() + 60)); cp.store.conn.commit()
            body = b"{}"; route = f"/v1/workspaces/{workspace}/runners/runner/claim"; now = int(time.time() * 1000)
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_claim", "method":"POST", "path":route, "body_sha256":hashlib.sha256(body).hexdigest(), "timestamp_ms":now, "server_nonce":nonce, "sequence":1}
            headers = {"X-Heel-Runner-Id":["runner"], "X-Heel-Runner-Key-Id":[key_id], "X-Heel-Runner-Timestamp-Ms":[str(now)], "X-Heel-Runner-Nonce":[nonce], "X-Heel-Runner-Sequence":["1"], "X-Heel-Runner-Signature":[base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()], "Authorization":[], "Cookie":[]}
            result, started = [], threading.Event()
            def heartbeat():
                started.set()
                with cp.runner_request_store() as isolated:
                    result.append(isolated.authenticate_and_consume(workspace_id=workspace, runner_id="runner", capability="runner_claim", path=route, raw_body=body, headers=headers, action=lambda: {"ok":"yes"})[0])
            cp.store.conn.execute("BEGIN IMMEDIATE"); cp.store.conn.execute("UPDATE workspaces SET name=name WHERE workspace_id=?", (workspace,))
            thread = threading.Thread(target=heartbeat); thread.start(); assert started.wait(1)
            time.sleep(.05); assert thread.is_alive()  # blocked on the database, not a second BEGIN on the human connection
            cp.store.conn.commit(); thread.join(2)
            assert result == [{"ok":"yes"}]
            assert opened and all(conn is not cp.store.conn for conn in opened)
        finally:
            cp.close()
