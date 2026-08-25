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

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_runner_identity
from heel.crypto import ed25519_key_id
from heel.runner.control_client import RunnerControlClient
from heel.saas.canary_store import CanaryStore
from heel.saas.runner_auth import RunnerAuthError, RunnerAuthStore, initialize_runner_auth_schema
from heel.saas.http_api import ControlPlane, serve

SIGNING_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"0123456789abcdef0123456789abcdef")
PUBLIC_KEY = SIGNING_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = ed25519_key_id(PUBLIC_KEY)

class Transport:
    def __init__(self): self.requests = []
    def post(self, path, *, headers=None, body=b""):
        self.requests.append((path, dict(headers or {}), body))
        return 200, {"X-Heel-Runner-Next-Nonce": "next-" + str(len(self.requests))}

class Signer:
    key_id = KEY_ID
    public_key = PUBLIC_KEY
    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return SIGNING_PRIVATE.sign(payload)

def client():
    transport, signer = Transport(), Signer()
    return RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=transport, nonce_source=lambda key: key[0] + "-first"), transport, signer

def client_projection(signer, phase="running"):
    from test_canary_contracts import _digest, operational
    value = operational(); value["lifecycle_phase"] = phase
    if phase == "claimed": value["timestamps"]["claimed_at_ms"] = 1
    elif phase == "running": value["timestamps"].update({"claimed_at_ms":1, "started_at_ms":1})
    elif phase == "stop_requested":
        value["timestamps"].update({"claimed_at_ms":1, "started_at_ms":1, "stop_requested_at_ms":1, "stop_acknowledged_at_ms":1}); value["stop_reason"] = "cloud_stop"
    value = _digest(value, "projection_digest"); value["signing_key_id"] = signer.key_id
    payload = {key:item for key,item in value.items() if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
    value["projection_digest"] = canonical_digest(payload); value["signature_b64"] = base64.b64encode(signer.sign(canonical_bytes(payload))).decode()
    return value

def test_named_methods_use_fixed_workspace_paths_and_exact_pop_headers():
    control, transport, signer = client()
    control.claim()
    path, headers, body = transport.requests[0]
    assert path == "/v1/workspaces/ws/runners/runner/claim"
    assert {key:value for key,value in headers.items() if key != "X-Heel-Runner-Signature"} == {"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": KEY_ID, "X-Heel-Runner-Timestamp-Ms": "1000", "X-Heel-Runner-Nonce": "claim-first", "X-Heel-Runner-Sequence": "1"}
    expected = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": "ws", "runner_id": "runner", "key_id": KEY_ID, "capability": "runner_claim", "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000, "server_nonce": "claim-first", "sequence": 1}
    assert signer.payloads == [b"heel.runner-pop.v1\0" + canonical_bytes(expected)]

def test_sequences_are_independent_per_run_capability_and_stop_ack_is_heartbeat():
    control, transport, signer = client()
    control.heartbeat(run_id="run", operational_projection=client_projection(signer))
    control.heartbeat(run_id="run", operational_projection=client_projection(signer))
    control.progress(run_id="run", operational_projection=client_projection(signer))
    control.stop_ack(run_id="run", operational_projection=client_projection(signer, "stop_requested"))
    assert [h["X-Heel-Runner-Sequence"] for _, h, _ in transport.requests] == ["1", "2", "1", "1"]
    assert transport.requests[-1][0].endswith("/runs/run/stop-ack")
    assert json.loads(transport.requests[2][2])["schema_version"] == "heel.runner-progress-request.v1"

def test_refuses_noncanonical_origin_bad_nonce_and_changed_retry():
    with pytest.raises(ValueError, match="pathless origin"):
        RunnerControlClient(origin="https://control.example?x=1", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "n")
    bad = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "")
    with pytest.raises(ValueError, match="nonce"):
        bad.claim()
    control, _, signer = client()
    control.progress(run_id="run", operational_projection=client_projection(signer))
    control.retry_last()

def test_has_no_public_generic_request_api():
    control, _, _ = client()
    assert not hasattr(control, "request")
    public = {name for name, value in vars(RunnerControlClient).items() if callable(value) and not name.startswith("_")}
    assert public <= {"claim", "heartbeat", "progress", "result", "stop_ack", "retry_last", "start_resync", "complete_resync", "install_rotation_claim"}


def test_replay_receipt_requires_a_fully_authenticated_byte_identical_pop():
    conn = sqlite3.connect(":memory:")
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(raw)
    now = int(time.time() * 1000)
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("r", "ws", "r", "active", time.time()))
    conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, "ws", "r", base64.b64encode(raw).decode(), "active", time.time()))
    nonce = "n" * 44
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "r", "claim", store._hash("nonce", nonce), 1, time.time() + 60))
    conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "r", "claim", 1, 0, time.time()))
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


def test_run_chain_allocator_issues_four_distinct_operation_chains_atomically():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)"); conn.execute("INSERT INTO workspaces VALUES('ws')")
    CanaryStore(conn); initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32, now=lambda: 100.0)
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1)); conn.commit()
    issued = store.provision_run_chains("ws", "runner", "run")
    assert set(issued) == {"heartbeat", "progress", "result", "stop-ack"}
    assert len({entry["next_nonce_b64"] for entry in issued.values()}) == 4
    assert all(entry["next_sequence"] == 1 and entry["generation"] == 0 for entry in issued.values())
    assert {row[0] for row in conn.execute("SELECT chain_name FROM canary_runner_nonce_chains")} == {
        "heartbeat:run", "progress:run", "result:run", "stop-ack:run",
    }


def test_run_chain_allocator_can_share_a_caller_owned_claim_transaction():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO workspaces VALUES('ws')")
    CanaryStore(conn); initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32, now=lambda: 100.0)
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        ("runner", "ws", "runner", "active", 1),
    )
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    issued = store.provision_run_chains_in_transaction("ws", "runner", "run")
    assert conn.in_transaction
    assert set(issued) == {"heartbeat", "progress", "result", "stop-ack"}
    conn.rollback()
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_runner_nonce_chains WHERE chain_name!='claim'"
    ).fetchone()[0] == 0


def test_resync_recovers_an_existing_chain_and_replays_only_the_same_signed_completion():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    workspace = "ws"; conn.execute("INSERT INTO workspaces VALUES(?)", (workspace,))
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    instant = [1_000.0]
    store = RunnerAuthStore(conn, pepper=b"p" * 32, now=lambda: instant[0])
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(public)
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", instant[0]))
    conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", base64.b64encode(public).decode(), "active", instant[0]))
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace, "runner", "heartbeat:run", store._hash("nonce", "old"), 8, instant[0] + 60))
    conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (workspace, "runner", "heartbeat:run", 8, 0, instant[0]))
    conn.commit()

    def signed(domain, schema, path, body, timestamp_ms=1_000_000):
        proof = {"schema_version": schema, "workspace_id": workspace, "runner_id": "runner", "key_id": key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms}
        return {"X-Heel-Runner-Id":["runner"], "X-Heel-Runner-Key-Id":[key_id], "X-Heel-Runner-Timestamp-Ms":[str(timestamp_ms)], "X-Heel-Runner-Signature":[base64.b64encode(private.sign(domain + canonical_bytes(proof))).decode()], "X-Heel-Runner-Nonce":[], "X-Heel-Runner-Sequence":[], "Authorization":[], "Cookie":[]}

    chain = {"operation":"heartbeat", "run_id":"run"}; client_nonce = base64.b64encode(b"c" * 32).decode()
    start_path = f"/v1/workspaces/{workspace}/runners/runner/resync/start"
    start = canonical_bytes({"schema_version":"heel.runner-resync-start.v2", "chain":chain, "client_nonce_b64":client_nonce})
    start_headers = signed(b"heel.runner-resync-start-pop.v2\0", "heel.runner-resync-start-proof.v2", start_path, start)
    challenge = store.start_resync(workspace_id=workspace, runner_id="runner", path=start_path, raw_body=start, headers=start_headers)
    assert challenge["next_sequence"] == 8
    instant[0] += 31
    assert store.start_resync(workspace_id=workspace, runner_id="runner", path=start_path, raw_body=start, headers=start_headers) == challenge
    complete_path = f"/v1/workspaces/{workspace}/runners/runner/resync/complete"
    complete = canonical_bytes({"schema_version":"heel.runner-resync-complete.v2", "challenge_id":challenge["challenge_id"], "chain":chain, "client_nonce_b64":client_nonce, "server_challenge_b64":challenge["server_challenge_b64"], "generation":challenge["generation"]})
    headers = signed(b"heel.runner-resync-complete-pop.v2\0", "heel.runner-resync-complete-proof.v2", complete_path, complete, 1_031_000)
    recovered = store.complete_resync(workspace_id=workspace, runner_id="runner", path=complete_path, raw_body=complete, headers=headers)
    assert recovered["next_sequence"] == 8 and base64.b64decode(recovered["next_nonce_b64"], validate=True)
    assert store.complete_resync(workspace_id=workspace, runner_id="runner", path=complete_path, raw_body=complete, headers=headers) == recovered
    changed = canonical_bytes({**json.loads(complete), "server_challenge_b64":base64.b64encode(b"x" * 32).decode()})
    with pytest.raises(RunnerAuthError):
        store.complete_resync(workspace_id=workspace, runner_id="runner", path=complete_path, raw_body=changed, headers=headers)


def test_http_resync_uses_current_key_and_replays_the_exact_completed_exchange():
    """Recovery has its own unsigned-by-browser HTTP surface and durable replay receipt."""
    with tempfile.TemporaryDirectory() as directory:
        cp = ControlPlane(str(Path(directory) / "control.sqlite"), runner_auth_pepper=b"r" * 32)
        server = serve(cp); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            org = cp.store.create_org("org"); workspace = cp.store.create_workspace(org, "ws", "free", "2026-08")
            private = Ed25519PrivateKey.generate(); raw_key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            public, key_id = base64.b64encode(raw_key).decode(), ed25519_key_id(raw_key)
            now = time.time(); timestamp = int(now * 1000)
            cp.store.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", now))
            cp.store.conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", public, "active", now))
            cp.store.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", cp.runner_auth._hash("nonce", "lost"), 4, now + 60))
            cp.store.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", 4, 0, now)); cp.store.conn.commit()
            for operation in ("heartbeat", "stop-ack", "result"):
                cp.store.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (workspace, "runner", f"{operation}:run", 1, 0, now))
            cp.store.conn.commit()

            def post(path, body, schema, domain, include_headers=False):
                proof = {"schema_version":schema, "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "method":"POST", "path":path, "body_sha256":hashlib.sha256(body).hexdigest(), "timestamp_ms":timestamp}
                headers = {"Content-Type":"application/json", "X-Heel-Runner-Id":"runner", "X-Heel-Runner-Key-Id":key_id, "X-Heel-Runner-Timestamp-Ms":str(timestamp), "X-Heel-Runner-Signature":base64.b64encode(private.sign(domain + canonical_bytes(proof))).decode()}
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", path, body, headers)
                response = conn.getresponse(); payload = json.loads(response.read()); status = response.status; response_headers = dict(response.getheaders()); conn.close()
                return (status, payload, response_headers) if include_headers else (status, payload)

            chain, client_nonce = {"operation":"claim", "run_id":None}, base64.b64encode(b"c" * 32).decode()
            start_path = f"/v1/workspaces/{workspace}/runners/runner/resync/start"
            assert post(start_path, b"{}", "heel.runner-resync-start-proof.v2", b"heel.runner-resync-start-pop.v2\0") == (401, {"schema_version":"heel.runner-error.v1", "code":"invalid_runner_auth"})
            start = canonical_bytes({"schema_version":"heel.runner-resync-start.v2", "chain":chain, "client_nonce_b64":client_nonce})
            status, challenge = post(start_path, start, "heel.runner-resync-start-proof.v2", b"heel.runner-resync-start-pop.v2\0")
            assert status == 200 and challenge["next_sequence"] == 4
            for operation, byte in (("heartbeat", b"h"), ("stop-ack", b"s")):
                fresh = canonical_bytes({"schema_version":"heel.runner-resync-start.v2", "chain":{"operation":operation,"run_id":"run"}, "client_nonce_b64":base64.b64encode(byte * 32).decode()})
                assert post(start_path, fresh, "heel.runner-resync-start-proof.v2", b"heel.runner-resync-start-pop.v2\0")[0] == 200
            limited = canonical_bytes({"schema_version":"heel.runner-resync-start.v2", "chain":{"operation":"result","run_id":"run"}, "client_nonce_b64":base64.b64encode(b"r" * 32).decode()})
            limited_status, limited_body, limited_headers = post(start_path, limited, "heel.runner-resync-start-proof.v2", b"heel.runner-resync-start-pop.v2\0", True)
            assert limited_status == 429 and limited_body["retry_after_ms"] == 60_000 and limited_headers["Retry-After"] == "60"
            complete_path = f"/v1/workspaces/{workspace}/runners/runner/resync/complete"
            complete = canonical_bytes({"schema_version":"heel.runner-resync-complete.v2", "challenge_id":challenge["challenge_id"], "chain":chain, "client_nonce_b64":client_nonce, "server_challenge_b64":challenge["server_challenge_b64"], "generation":challenge["generation"]})
            status, recovered = post(complete_path, complete, "heel.runner-resync-complete-proof.v2", b"heel.runner-resync-complete-pop.v2\0")
            assert status == 200 and recovered["next_sequence"] == 4
            assert post(complete_path, complete, "heel.runner-resync-complete-proof.v2", b"heel.runner-resync-complete-pop.v2\0") == (200, recovered)
        finally:
            server.shutdown(); server.server_close(); cp.close()


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
        status, exchanged, _ = request("POST", "/v1/runner-pairings/exchange", {"schema_version":"heel.runner-pairing-exchange.v2", "invitation_token":invitation["invitation_token"], "public_key_b64":public, "pairing_phrase":phrase, "display_name":"Runner HTTP", "runner_version":"v1", "adapters":{}})
        assert status == 201 and exchanged["activation_challenge"]
        status, inspect, _ = request("GET", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{exchanged['pairing_id']}", {}, browser)
        assert status == 200 and "activation_challenge" not in inspect
        fingerprint = hashlib.sha256(base64.b64decode(public)).hexdigest()
        assert request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{exchanged['pairing_id']}/approve", {"schema_version":"heel.runner-pairing-approve.v1", "pairing_phrase":phrase, "fingerprint":fingerprint}, browser)[0] == 200
        activation = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id":exchanged["pairing_id"], "challenge":exchanged["activation_challenge"]})
        signature = base64.b64encode(private.sign(activation)).decode()
        assert request("POST", f"/v1/runner-pairings/{exchanged['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v1", "signature_b64":signature})[0] == 200
        record = cp.store.conn.execute("SELECT identity_json,identity_digest FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?", (signup["workspace_id"], exchanged["runner_id"])).fetchone()
        identity = validate_runner_identity(json.loads(record[0]))
        assert identity["identity_digest"] == record[1]
        assert identity["capabilities"] == ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]
        assert identity["pairing"]["fingerprint_confirmation"] == "confirmed"
        identity["rotation"]["previous_key_ids"].append("mutated")
        assert "mutated" not in cp.runner_auth.identity(signup["workspace_id"], exchanged["runner_id"])["rotation"]["previous_key_ids"]
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
    class HttpTransport:
        def post(self, path, *, headers=None, body=b""):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
            conn.request("POST", path, body, headers or {})
            response = conn.getresponse(); payload = json.loads(response.read())
            response_headers = dict(response.getheaders()); status = response.status; conn.close()
            return status, response_headers, payload
    class LocalSigner:
        def __init__(self, private):
            self.private = private
            self.public_key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.key_id = ed25519_key_id(self.public_key)
        def sign(self, payload):
            return self.private.sign(payload)
    try:
        _, signup, cookie = request("POST", "/v1/signup", {"email":"rotate@example.test", "password":"correct-horse-battery"})
        browser = {"Cookie":cookie.split(";", 1)[0], "Origin":"https://heel.test", "X-Heel-Internal-Origin":"same-origin"}
        _, invite, _ = request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings", {"schema_version":"heel.runner-pairing-invite.v1"}, browser)
        old = Ed25519PrivateKey.generate(); old_public = base64.b64encode(old.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        from heel.runner.identity import runner_phrase_words
        phrase = " ".join(runner_phrase_words()[:6])
        _, pending, _ = request("POST", "/v1/runner-pairings/exchange", {"schema_version":"heel.runner-pairing-exchange.v2", "invitation_token":invite["invitation_token"], "public_key_b64":old_public, "pairing_phrase":phrase, "display_name":"Rotating runner", "runner_version":"v1", "adapters":{}}, {})
        request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{pending['pairing_id']}/approve", {"schema_version":"heel.runner-pairing-approve.v1", "pairing_phrase":phrase, "fingerprint":pending["fingerprint"]}, browser)
        proof = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id":pending["pairing_id"], "challenge":pending["activation_challenge"]})
        status, first_activation, _ = request("POST", f"/v1/runner-pairings/{pending['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v1", "signature_b64":base64.b64encode(old.sign(proof)).decode()})
        assert status == 200
        old_client = RunnerControlClient(
            origin="http://127.0.0.1", workspace_id=signup["workspace_id"], runner_id=pending["runner_id"],
            signer=LocalSigner(old), clock=lambda: int(time.time() * 1000), transport=HttpTransport(),
            nonce_source=lambda chain: first_activation["initial_claim_nonce"],
        )
        assert old_client.claim()[0] == 200
        new = Ed25519PrivateKey.generate(); new_public = base64.b64encode(new.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        old_fingerprint = hashlib.sha256(base64.b64decode(old_public)).hexdigest()
        status, rotation, _ = request("POST", f"/v1/workspaces/{signup['workspace_id']}/runners/{pending['runner_id']}/rotate", {"schema_version":"heel.runner-rotation-start.v1", "previous_fingerprint":old_fingerprint, "public_key_b64":new_public, "pairing_phrase":phrase, "runner_version":"v2", "adapters":{}}, browser)
        assert status == 201 and "activation_challenge" not in rotation
        assert request("GET", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{rotation['pairing_id']}", {}, browser)[0] == 404
        assert request("POST", f"/v1/workspaces/{signup['workspace_id']}/runners/{pending['runner_id']}/rotations/{rotation['pairing_id']}/approve", {"schema_version":"heel.runner-rotation-approve.v1", "pairing_phrase":phrase, "fingerprint":rotation["fingerprint"]}, browser)[0] == 200
        status, poll, _ = request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/poll", {})
        assert status == 200 and poll["activation_challenge"]
        v1_proof = b"heel.runner-rotation-activate.v1\0" + canonical_bytes({"pairing_id":rotation["pairing_id"], "challenge":poll["activation_challenge"]})
        assert request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/activate", {"schema_version":"heel.runner-rotation-activate.v1", "signature_b64":base64.b64encode(new.sign(v1_proof)).decode()})[0] == 400
        proof = b"heel.runner-rotation-activate.v2\0" + canonical_bytes({"pairing_id":rotation["pairing_id"], "challenge":poll["activation_challenge"]})
        status, activated, _ = request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/activate", {"schema_version":"heel.runner-rotation-activate.v2", "signature_b64":base64.b64encode(new.sign(proof)).decode()})
        assert status == 200
        assert set(activated) == {"schema_version", "workspace_id", "runner_id", "initial_claim_nonce", "initial_claim_sequence", "initial_claim_generation"}
        assert activated["schema_version"] == "heel.runner-rotation-activated.v2"
        assert activated["initial_claim_sequence"] == 2 and activated["initial_claim_generation"] == 1
        new_client = RunnerControlClient(
            origin="http://127.0.0.1", workspace_id=signup["workspace_id"], runner_id=pending["runner_id"],
            signer=LocalSigner(new), clock=lambda: int(time.time() * 1000), transport=HttpTransport(),
            nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("rotation install did not seed claim")),
        )
        installed = new_client.install_rotation_claim(activated)
        assert installed.initial_claim_sequence == 2 and installed.initial_claim_generation == 1
        assert new_client.claim()[0] == 200
        identity = cp.runner_auth.identity(signup["workspace_id"], pending["runner_id"])
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
            cp.store.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", 1, 0, time.time())); cp.store.conn.commit()
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


def test_real_http_heartbeat_bypasses_held_human_request_lock():
    """Run-operation paths have eight components and must never wait on the Python human lock."""
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "control.sqlite")
        cp = ControlPlane(path, runner_auth_pepper=b"r" * 32)
        server = serve(cp); served = threading.Thread(target=server.serve_forever, daemon=True); served.start()
        try:
            org = cp.store.create_org("org")
            workspace = cp.store.create_workspace(org, "ws", "free", "2026-08")
            private = Ed25519PrivateKey.generate()
            public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            raw = base64.b64decode(public); key_id = ed25519_key_id(raw)
            cp.store.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", time.time()))
            cp.store.conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", public, "active", time.time()))
            cp.store.conn.commit(); issued = cp.runner_auth.provision_run_chains(workspace, "runner", "run"); nonce = issued["heartbeat"]["next_nonce_b64"]
            stamp, stamp_ms, digest = time.time(), int(time.time() * 1000), "a" * 64
            cp.store.conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (workspace, "prj", "project", "owner", stamp))
            cp.store.conn.execute("INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at) VALUES(?,?,?,?,?,?,?)", ("env", workspace, "prj", "https://canary.example.com", "staging", "verified", stamp))
            cp.store.conn.execute(
                "INSERT INTO canary_approval_projections(approval_id,workspace_id,project_ref,run_id,"
                "environment_id,runner_id,runner_key_id,manifest_digest,projection_digest,signing_key_id,"
                "status,projection_json,scenario_ids_json,budgets_json,uploaded_by,approved_by,reason,"
                "created_at,expires_at,approved_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("approval", workspace, "prj", "run", "env", "runner", key_id, digest, digest,
                 key_id, "approved", json.dumps({"manifest_digest": digest}), "[]", "{}", "owner",
                 "owner", "test", stamp_ms, stamp_ms + 60_000, stamp_ms, stamp_ms + 120_000),
            )
            cp.store.conn.execute(
                "INSERT INTO canary_execution_grants(grant_id,workspace_id,project_ref,approval_id,"
                "run_id,environment_id,runner_id,runner_key_id,nonce_hash,grant_digest,grant_json,status,"
                "reservation_id,meter,period,idempotency_key,issued_at,expires_at,claimed_at,purge_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("g", workspace, "prj", "approval", "run", "env", "runner", key_id, "b" * 64,
                 digest, "{}", "claimed", "reservation", "canary_runs", "2026-08",
                 "ca1-" + "c" * 64, stamp_ms, stamp_ms + 60_000, stamp_ms, stamp_ms + 120_000),
            )
            cp.store.conn.execute(
                "INSERT INTO canary_runs(run_id,workspace_id,project_ref,approval_id,grant_id,"
                "environment_id,runner_id,runner_key_id,status,error_category,stop_reason,"
                "source_event_sequence,cloud_event_sequence,last_heartbeat_at_ms,claimed_at_ms,"
                "stop_generation,stop_ack_late,reservation_id,quota_state,kill_switch_generation,"
                "created_at,updated_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("run", workspace, "prj", "approval", "g", "env", "runner", key_id, "claimed",
                 "none", "none", -1, 0, stamp_ms, stamp_ms, 0, 0, "reservation", "reserved", 0,
                 stamp_ms, stamp_ms, stamp_ms + 120_000),
            )
            identity = cp.runner_auth._identity_record(workspace_id=workspace, runner_id="runner", public_key=public, fingerprint=hashlib.sha256(raw).hexdigest(), key_id=key_id, runner_version="v1", adapters_json="{}", paired_by="owner", paired_at=time.time(), heartbeat_at=time.time())
            cp.runner_auth._save_identity(identity, instant=time.time()); cp.store.conn.commit()
            from test_canary_contracts import _digest, operational
            projection = operational()
            projection["workspace_id"] = workspace
            projection["lifecycle_phase"] = "claimed"
            projection["timestamps"]["claimed_at_ms"] = 1
            payload = {key: value for key, value in projection.items()
                       if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
            projection["projection_digest"] = canonical_digest(payload)
            projection["signing_key_id"] = key_id
            projection["signature_b64"] = base64.b64encode(private.sign(canonical_bytes(payload))).decode()
            body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": "run", "operational_projection": projection})
            route = f"/v1/workspaces/{workspace}/runners/runner/runs/run/heartbeat"
            timestamp = int(time.time() * 1000)
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_heartbeat", "method":"POST", "path":route, "body_sha256":hashlib.sha256(body).hexdigest(), "timestamp_ms":timestamp, "server_nonce":nonce, "sequence":1}
            headers = {"Content-Type":"application/json", "X-Heel-Runner-Id":"runner", "X-Heel-Runner-Key-Id":key_id, "X-Heel-Runner-Timestamp-Ms":str(timestamp), "X-Heel-Runner-Nonce":nonce, "X-Heel-Runner-Sequence":"1", "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()}
            done, result = threading.Event(), []
            def heartbeat():
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                conn.request("POST", route, body, headers)
                response = conn.getresponse(); result.append((response.status, response.getheader("X-Heel-Runner-Next-Nonce"))); response.read(); conn.close(); done.set()
            with cp.request_lock:
                request = threading.Thread(target=heartbeat); request.start()
                assert done.wait(.75), "runner heartbeat waited on the human request lock"
            request.join(1)
            assert result[0][0] == 200 and result[0][1]
            other = Ed25519PrivateKey.generate()
            wrong_projection = json.loads(json.dumps(projection))
            wrong_projection["signing_key_id"] = ed25519_key_id(other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            wrong_payload = {key: value for key, value in wrong_projection.items()
                             if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
            wrong_projection["signature_b64"] = base64.b64encode(other.sign(canonical_bytes(wrong_payload))).decode()
            wrong_body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": "run", "operational_projection": wrong_projection})
            wrong_proof = {**proof, "body_sha256": hashlib.sha256(wrong_body).hexdigest(), "server_nonce": result[0][1], "sequence": 2}
            wrong_headers = {**headers, "X-Heel-Runner-Nonce":result[0][1], "X-Heel-Runner-Sequence":"2", "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(wrong_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", route, wrong_body, wrong_headers)
            assert conn.getresponse().status == 401; conn.close()
            tampered_projection = json.loads(json.dumps(projection))
            tampered_projection["counters"]["remaining_requests"] = 2  # digest/signature no longer attest this body.
            tampered_body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": "run", "operational_projection": tampered_projection})
            tampered_proof = {**proof, "body_sha256": hashlib.sha256(tampered_body).hexdigest(), "server_nonce": result[0][1], "sequence": 2}
            tampered_headers = {**headers, "X-Heel-Runner-Nonce":result[0][1], "X-Heel-Runner-Sequence":"2", "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(tampered_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", route, tampered_body, tampered_headers)
            assert conn.getresponse().status == 401; conn.close()
            stop_projection = operational(); stop_projection["workspace_id"] = workspace; stop_projection["lifecycle_phase"] = "stop_requested"; stop_projection["stop_reason"] = "cloud_stop"
            stop_projection["timestamps"].update({"claimed_at_ms":1, "started_at_ms":1, "stop_requested_at_ms":1, "stop_acknowledged_at_ms":1})
            stop_payload = {key:value for key,value in stop_projection.items() if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
            stop_projection["projection_digest"] = canonical_digest(stop_payload); stop_projection["signing_key_id"] = key_id; stop_projection["signature_b64"] = base64.b64encode(private.sign(canonical_bytes(stop_payload))).decode()
            stop_body = canonical_bytes({"schema_version":"heel.runner-stop-ack-request.v1", "run_id":"run", "operational_projection":stop_projection})
            stop_route = f"/v1/workspaces/{workspace}/runners/runner/runs/run/stop-ack"; stop_timestamp = int(time.time() * 1000); stop_nonce = issued["stop-ack"]["next_nonce_b64"]
            stop_proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_heartbeat", "method":"POST", "path":stop_route, "body_sha256":hashlib.sha256(stop_body).hexdigest(), "timestamp_ms":stop_timestamp, "server_nonce":stop_nonce, "sequence":1}
            stop_headers = {"Content-Type":"application/json", "X-Heel-Runner-Id":"runner", "X-Heel-Runner-Key-Id":key_id, "X-Heel-Runner-Timestamp-Ms":str(stop_timestamp), "X-Heel-Runner-Nonce":stop_nonce, "X-Heel-Runner-Sequence":"1", "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(stop_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", stop_route, stop_body, stop_headers)
            assert conn.getresponse().status == 200; conn.close()
        finally:
            server.shutdown(); server.server_close(); cp.close()
