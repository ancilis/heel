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
from heel.crypto import SigningAuthority, ed25519_key_id
from heel.runner.control_client import _RunGuard, RunnerControlClient
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.runtime import ActiveRunInstall, RunnerRuntimeState
from heel.saas.canary_store import CanaryStore
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.runner_auth import (
    RunnerActivationAbortDeferred, RunnerActivationReceiptExpired, RunnerAuthError, RunnerAuthStore, RunnerHttpAction,
    initialize_runner_auth_schema, validate_runner_auth_schema,
)
from heel.saas.http_api import ControlPlane, serve

SIGNING_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"0123456789abcdef0123456789abcdef")
PUBLIC_KEY = SIGNING_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = ed25519_key_id(PUBLIC_KEY)
RUN_ID = "crun_" + "a" * 32

class Transport:
    def __init__(self): self.requests = []
    def post(self, path, *, headers=None, body=b""):
        self.requests.append((path, dict(headers or {}), body))
        response_headers = {
            "X-Heel-Runner-Next-Nonce": base64.b64encode(
                bytes([len(self.requests)]) * 32,
            ).decode(),
        }
        if path.endswith("/claim"):
            return 204, response_headers, None
        if path.endswith("/heartbeat"):
            return 200, response_headers, {
                "active": True,
                "runner_state": "active",
                "proof_state": "valid",
                "proof_expires_at_ms": 2_000,
                "kill_switch_generation": 0,
                "stop_reason": "none",
                "server_time_ms": 1_000 + len(self.requests),
            }
        if path.endswith("/stop-ack"):
            return 200, response_headers, {
                "accepted": True, "deadline_met": True, "late": False,
            }
        request = json.loads(body)
        projection = request["operational_projection"]
        terminal = path.endswith("/result")
        return 200, response_headers, {
            "schema_version": "heel.canary-run-status.v1",
            "run_id": request["run_id"],
            "approval_id": "approval",
            "grant_id": projection["grant_id"],
            "status": "terminal" if terminal else "running",
            "execution_disposition": "completed" if terminal else None,
            "error_category": "none",
            "stop_reason": "none",
            "source_event_sequence": projection["event_sequence"],
            "quota_state": "reserved",
            "kill_switch_generation": 0,
            "stop_generation": 0,
            "stop_deadline_ms": None,
            "stop_acknowledged_at_ms": None,
            "stop_ack_late": False,
        }

class Signer(SecureSigner):
    key_id = KEY_ID
    public_key = PUBLIC_KEY
    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return SIGNING_PRIVATE.sign(payload)


def _enable_executable_protocol(conn, workspace_id, runner_id, *, activated_at=None):
    conn.execute(
        "INSERT INTO canary_runner_execution_protocols("
        "workspace_id,runner_id,protocol_version,control_protocol,exchange_digest,activated_at"
        ") VALUES(?,?,?,?,?,?)",
        (workspace_id, runner_id, 3, "heel.runner-control.v2", "a" * 64,
         time.time() if activated_at is None else activated_at),
    )


def _runtime(signer, *, workspace_id="ws", runner_id="runner", install_claim=True):
    root = Path(tempfile.mkdtemp(prefix="heel-runtime-"))
    identity = RunnerIdentity(
        runner_id=runner_id, workspace_id=workspace_id, runner_version="test",
        adapter_versions={}, public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=signer.key_id,
        pairing_phrase=(),
    )
    runtime = RunnerRuntimeState(root / "runtime.sqlite3", identity, signer)
    if install_claim:
        runtime.install_chain(
            operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"p" * 32).decode(),
            next_sequence=1, generation=0, now_ms=0,
        )
    return runtime

def client():
    transport, signer = Transport(), Signer()
    runtime = _runtime(signer)
    signer.payloads.clear()
    return RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=transport, nonce_source=lambda key: base64.b64encode(hashlib.sha256(f"{key[0]}:{key[1]}".encode()).digest()).decode(), runtime=runtime), transport, signer

def client_projection(signer, phase="running", *, run_id=RUN_ID):
    from test_canary_contracts import _digest, operational
    value = operational(); value["lifecycle_phase"] = phase; value["run_id"] = run_id
    if phase == "claimed": value["timestamps"]["claimed_at_ms"] = 1
    elif phase == "running": value["timestamps"].update({"claimed_at_ms":1, "started_at_ms":1})
    elif phase == "stop_requested":
        value["timestamps"].update({"claimed_at_ms":1, "started_at_ms":1, "stop_requested_at_ms":1, "stop_acknowledged_at_ms":1}); value["stop_reason"] = "cloud_stop"
    value = _digest(value, "projection_digest"); value["signing_key_id"] = signer.key_id
    payload = {key:item for key,item in value.items() if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
    value["projection_digest"] = canonical_digest(payload); value["signature_b64"] = base64.b64encode(signer.sign(canonical_bytes(payload))).decode()
    return value


def activate_claimed_run(control, run_id=RUN_ID):
    """Install a coherent post-claim active row through the durable claim transaction."""
    from tests.test_canary_contracts import approval as fixture_approval, grant as fixture_grant

    projection = fixture_approval()
    projection.update({"workspace_id": control.workspace_id, "project_id": "prj"})
    projection["runner"] = {
        "runner_id": control.runner_id, "runner_key_id": control.signer.key_id,
        "runner_version": "test", "adapter_versions": ["1"],
    }
    projection["signing_key_id"] = control.signer.key_id
    projection["signature_b64"] = base64.b64encode(b"s" * 64).decode("ascii")
    projection_unsigned = {
        key: value for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    projection["projection_digest"] = canonical_digest(projection_unsigned)

    grant = fixture_grant()
    grant.update({"workspace_id": control.workspace_id, "project_id": "prj", "run_id": run_id})
    grant["approval"] = {
        "projection_id": projection["projection_id"],
        "projection_digest": projection["projection_digest"],
        "manifest_digest": projection["manifest_digest"],
    }
    grant["runner_binding"] = {
        "runner_id": control.runner_id, "runner_key_id": control.signer.key_id,
        "public_key_digest": "a" * 64,
    }
    grant["kill_switch_generation"] = 0
    grant["signing_key_id"] = control.signer.key_id
    grant["signature_b64"] = base64.b64encode(b"s" * 64).decode("ascii")
    grant_unsigned = {
        key: value for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    grant["grant_digest"] = canonical_digest(grant_unsigned)

    claim = control.runtime.load_chain("claim", None)
    assert claim is not None
    path = f"/v1/workspaces/{control.workspace_id}/runners/{control.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": control.workspace_id,
        "runner_id": control.runner_id, "key_id": control.signer.key_id,
        "capability": "runner_claim", "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1_000,
        "server_nonce": claim.next_nonce_b64, "sequence": claim.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": control.runner_id,
        "X-Heel-Runner-Key-Id": control.signer.key_id, "X-Heel-Runner-Timestamp-Ms": "1000",
        "X-Heel-Runner-Signature": base64.b64encode(
            control.signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": claim.next_nonce_b64,
        "X-Heel-Runner-Sequence": str(claim.next_sequence),
    }
    pending = control.runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path,
        capability="runner_claim", headers=headers, body=body,
        expected_state_digest=claim.state_digest, now_ms=1_000,
    )
    nonce = base64.b64encode(b"q" * 32).decode()
    installed = tuple(
        (operation, run_id, nonce, 1, 0)
        for operation in ("heartbeat", "progress", "result", "stop-ack")
    )
    control.runtime.commit_call(
        pending.call_id, next_nonce_b64=base64.b64encode(b"n" * 32).decode(), now_ms=1_000,
        installed_chains=installed,
        active_run=ActiveRunInstall(
            run_id=run_id, approval_projection=projection, grant=grant,
            gate={
                "active": True, "runner_state": "active", "proof_state": "valid",
                "proof_expires_at_ms": 2_000, "kill_switch_generation": 0,
                "stop_reason": "none", "server_time_ms": 999,
            },
            claim_response_digest="a" * 64, gate_response_digest="b" * 64,
            claimed_at_ms=1_000, gate_received_at_ms=999,
        ),
    )
    with control._state_lock:
        control._tracked_runs.add(run_id)
        control._run_guards[run_id] = _RunGuard(threading.Lock(), object())
        for operation in ("heartbeat", "progress", "result", "stop-ack"):
            cursor = control.runtime.load_chain(operation, run_id)
            assert cursor is not None
            control._chains[f"{operation}:{run_id}"] = (
                cursor.next_nonce_b64, cursor.next_sequence, cursor.generation,
            )

def test_named_methods_use_fixed_workspace_paths_and_exact_pop_headers():
    control, transport, signer = client()
    control.claim()
    path, headers, body = transport.requests[0]
    assert path == "/v1/workspaces/ws/runners/runner/claim"
    claim_nonce = base64.b64encode(b"p" * 32).decode()
    assert {key:value for key,value in headers.items() if key != "X-Heel-Runner-Signature"} == {"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": KEY_ID, "X-Heel-Runner-Timestamp-Ms": "1000", "X-Heel-Runner-Nonce": claim_nonce, "X-Heel-Runner-Sequence": "1"}
    expected = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": "ws", "runner_id": "runner", "key_id": KEY_ID, "capability": "runner_claim", "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000, "server_nonce": claim_nonce, "sequence": 1}
    assert signer.payloads == [b"heel.runner-pop.v1\0" + canonical_bytes(expected)]


def test_context_methods_use_claim_chain_and_closed_context_routes():
    class ContextTransport:
        def __init__(self): self.requests = []
        def post(self, path, *, headers=None, body=b""):
            self.requests.append((path, headers, body))
            nonce = base64.b64encode(bytes([len(self.requests)]) * 32).decode()
            if path.endswith("/contexts/list"):
                return 200, {"X-Heel-Runner-Next-Nonce": nonce}, {"schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 1, "contexts": [], "has_more": False}
            unsigned = {"schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "a" * 32,
                        "workspace_id": "ws", "project_id": "project", "environment": {"environment_id": "env_" + "a" * 32, "origin": "https://staging.example.com", "environment_class": "staging", "verification_record_digest": "a" * 64},
                        "runner_binding": {"runner_id": "runner", "runner_key_id": KEY_ID, "public_key_digest": "a" * 64},
                        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 0, "expires_at_ms": 60_000}
            return 200, {"X-Heel-Runner-Next-Nonce": nonce}, {"schema_version": "heel.runner-context-claim-result.v1", "context_binding": {**unsigned, "binding_digest": canonical_digest(unsigned), "signing_key_id": "cloud", "signature_b64": base64.b64encode(b"s" * 64).decode()}, "claimed_at_ms": 1}
    transport, signer = ContextTransport(), Signer()
    control = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=transport, nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(), runtime=_runtime(signer))
    assert control.list_contexts()["contexts"] == []
    claim_unsigned = {"schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "a" * 32,
                      "workspace_id": "ws", "project_id": "project", "environment": {"environment_id": "env_" + "a" * 32, "origin": "https://staging.example.com", "environment_class": "staging", "verification_record_digest": "a" * 64},
                      "runner_binding": {"runner_id": "runner", "runner_key_id": KEY_ID, "public_key_digest": "a" * 64},
                      "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 0, "expires_at_ms": 60_000}
    control.claim_context("rcb_" + "a" * 32, canonical_digest(claim_unsigned))
    assert [item[0] for item in transport.requests] == [
        "/v1/workspaces/ws/runners/runner/contexts/list",
        "/v1/workspaces/ws/runners/runner/contexts/rcb_" + "a" * 32 + "/claim",
    ]
    assert [item[1]["X-Heel-Runner-Sequence"] for item in transport.requests] == ["1", "2"]


def test_context_methods_reject_extra_or_unsigned_claim_artifacts():
    class BadContextTransport:
        def post(self, path, *, headers=None, body=b""):
            del path, headers, body
            return 200, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"n" * 32).decode()}, {
                "schema_version": "heel.runner-context-claim-result.v1", "context_binding": {}, "claimed_at_ms": 1,
            }
    signer = Signer()
    control = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=BadContextTransport(), nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(), runtime=_runtime(signer))
    with pytest.raises(ValueError, match="invalid runner context response"):
        control.claim_context("rcb_" + "a" * 32, "a" * 64)


@pytest.mark.parametrize("operation", (
    "list-contexts", "claim-context", "submit-context-approval-projection",
))
def test_context_call_lost_response_is_durably_staged_for_restart_replay(operation):
    class LostResponseTransport:
        def __init__(self):
            self.requests = []

        def post(self, path, *, headers=None, body=b""):
            self.requests.append((path, dict(headers or {}), body))
            raise ConnectionError("response was lost after the request was accepted")

    from test_canary_contracts import approval

    signer, transport = Signer(), LostResponseTransport()
    runtime = _runtime(signer)
    control = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1_000, transport=transport,
        nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(), runtime=runtime,
    )
    binding_id, binding_digest = "rcb_" + "a" * 32, "a" * 64

    with pytest.raises(ConnectionError, match="response was lost"):
        if operation == "list-contexts":
            control.list_contexts()
        elif operation == "claim-context":
            control.claim_context(binding_id, binding_digest)
        else:
            control.submit_context_approval_projection(binding_id, binding_digest, approval())

    pending = runtime.load_pending_calls()
    assert len(pending) == 1
    assert pending[0].request_operation == operation
    assert pending[0].body == transport.requests[0][2]
    assert dict(pending[0].headers) == transport.requests[0][1]


@pytest.mark.parametrize("operation", (
    "list-contexts", "claim-context", "submit-context-approval-projection",
))
def test_context_pending_replay_uses_the_exact_sealed_request_before_reenabling_control(operation):
    class LostResponseTransport:
        def __init__(self): self.requests = []
        def post(self, path, *, headers=None, body=b""):
            self.requests.append((path, dict(headers or {}), body))
            raise ConnectionError("response was lost after the request was accepted")

    from test_canary_contracts import approval

    signer = Signer()
    runtime = _runtime(signer)
    lost = LostResponseTransport()
    control = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1_000, transport=lost,
        nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(), runtime=runtime,
    )
    projection = approval()
    binding_id = "rcb_" + "a" * 32
    unsigned_binding = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": binding_id,
        "workspace_id": "ws", "project_id": "project",
        "environment": {
            "environment_id": "env_" + "a" * 32, "origin": "https://staging.example.com",
            "environment_class": "staging", "verification_record_digest": "a" * 64,
        },
        "runner_binding": {
            "runner_id": "runner", "runner_key_id": KEY_ID, "public_key_digest": "a" * 64,
        },
        "authorization": {"user_id": "owner", "role": "owner"},
        "issued_at_ms": 0, "expires_at_ms": 60_000,
    }
    binding_digest = canonical_digest(unsigned_binding)
    with pytest.raises(ConnectionError):
        if operation == "list-contexts":
            control.list_contexts()
        elif operation == "claim-context":
            control.claim_context(binding_id, binding_digest)
        else:
            control.submit_context_approval_projection(binding_id, binding_digest, projection)
    staged = runtime.load_pending_calls()
    assert len(staged) == 1

    binding = {
        **unsigned_binding, "binding_digest": canonical_digest(unsigned_binding),
        "signing_key_id": "cloud", "signature_b64": base64.b64encode(b"s" * 64).decode(),
    }

    class ReplayTransport:
        def __init__(self): self.requests = []
        def post(self, path, *, headers=None, body=b""):
            self.requests.append((path, dict(headers or {}), body))
            assert path == staged[0].path and body == staged[0].body
            assert dict(headers or {}) == dict(staged[0].headers)
            response_headers = {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"q" * 32).decode()}
            if operation == "list-contexts":
                payload = {
                    "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 1,
                    "contexts": [], "has_more": False,
                }
                return 200, response_headers, payload
            if operation == "claim-context":
                return 200, response_headers, {
                    "schema_version": "heel.runner-context-claim-result.v1",
                    "context_binding": binding, "claimed_at_ms": 1,
                }
            return 201, response_headers, {
                "schema_version": "heel.canary-projection-submitted.v1",
                "approval_id": projection["projection_id"], "run_id": "crun_" + "b" * 32,
                "status": "approved", "projection_digest": projection["projection_digest"],
            }

    replay = ReplayTransport()
    fresh = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 9_999, transport=replay,
        nonce_source=lambda _: base64.b64encode(b"x" * 32).decode(), runtime=runtime,
    )
    with pytest.raises(ValueError, match="pending replay is required"):
        fresh.claim()
    outcomes = fresh.replay_all_pending(now_ms=9_999)
    assert [(item.call_id, item.request_operation, item.status) for item in outcomes] == [
        (staged[0].call_id, operation, 201 if operation == "submit-context-approval-projection" else 200),
    ]
    assert len(replay.requests) == 1 and runtime.load_pending_calls() == ()
    assert runtime.load_chain("claim", None).next_sequence == 2


def test_claim_pending_replay_is_byte_identical_and_unblocks_the_fresh_client():
    class LostThenReplay:
        def __init__(self): self.requests = []; self.lost = True
        def post(self, path, *, headers=None, body=b""):
            self.requests.append((path, dict(headers or {}), body))
            if self.lost:
                self.lost = False
                raise ConnectionError("claim response was lost")
            return 204, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"q" * 32).decode()}, None

    signer, transport = Signer(), LostThenReplay()
    runtime = _runtime(signer)
    control = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1_000, transport=transport,
        nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(), runtime=runtime,
    )
    with pytest.raises(ConnectionError, match="response was lost"):
        control.claim()
    pending = runtime.load_pending_calls()
    assert len(pending) == 1 and pending[0].request_operation == "claim"
    fresh = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 9_000, transport=transport,
        nonce_source=lambda _: base64.b64encode(b"x" * 32).decode(), runtime=runtime,
    )
    with pytest.raises(ValueError, match="pending replay is required"):
        fresh.claim()
    outcomes = fresh.replay_all_pending(now_ms=9_000)
    assert [(outcome.request_operation, outcome.status, outcome.body) for outcome in outcomes] == [
        ("claim", 204, None),
    ]
    assert transport.requests[1] == transport.requests[0]
    assert runtime.load_pending_calls() == ()
    assert runtime.load_chain("claim", None).next_sequence == 2


def test_context_projection_submit_rejects_substitution_without_advancing_claim_cursor():
    from test_canary_contracts import approval

    class ContextSigner(Signer):
        key_id = "rk"

    projection = approval()
    binding_id, binding_digest = "rcb_" + "a" * 32, "a" * 64
    valid = {
        "schema_version": "heel.canary-projection-submitted.v1", "approval_id": projection["projection_id"],
        "run_id": "crun_" + "b" * 32, "status": "approved",
        "projection_digest": projection["projection_digest"],
    }
    for field, replacement in (
        ("approval_id", "other"), ("projection_digest", "b" * 64),
        ("run_id", "run_not_closed"), ("status", "running"),
    ):
        class SubmitTransport:
            def post(self, path, *, headers=None, body=b""):
                del path, headers, body
                return 201, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"n" * 32).decode()}, {
                    **valid, field: replacement,
                }

        signer = ContextSigner()
        control = RunnerControlClient(
            origin="https://control.example", workspace_id="ws", runner_id="r", signer=signer,
            clock=lambda: 1, transport=SubmitTransport(), nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(),
            runtime=_runtime(signer, runner_id="r"),
        )
        with pytest.raises(ValueError, match="invalid runner context response"):
            control.submit_context_approval_projection(binding_id, binding_digest, projection)
        assert control._chains["claim"][1] == 1

    class ValidTransport:
        def post(self, path, *, headers=None, body=b""):
            del path, headers, body
            return 201, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"n" * 32).decode()}, valid

    signer = ContextSigner()
    control = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="r", signer=signer,
        clock=lambda: 1, transport=ValidTransport(), nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(),
        runtime=_runtime(signer, runner_id="r"),
    )
    assert control.submit_context_approval_projection(binding_id, binding_digest, projection) == valid
    assert control._chains["claim"][1] == 2


def test_context_list_does_not_replace_server_issued_order_with_expiry_order():
    class OrderedTransport:
        def post(self, path, *, headers=None, body=b""):
            del path, headers, body
            contexts = []
            for marker, expires_at_ms in (("b", 90_000), ("a", 2_000)):
                contexts.append({
                    "binding_id": "rcb_" + marker * 32, "binding_digest": marker * 64,
                    "project_id": "project", "environment_id": "env", "origin": "https://staging.example.com",
                    "environment_class": "staging", "verification_record_digest": marker * 64,
                    "expires_at_ms": expires_at_ms, "claimed": False,
                })
            return 200, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"n" * 32).decode()}, {
                "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 1,
                "contexts": contexts, "has_more": False,
            }

    signer = Signer()
    control = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1, transport=OrderedTransport(), nonce_source=lambda _: base64.b64encode(b"n" * 32).decode(),
        runtime=_runtime(signer),
    )
    assert [item["binding_id"] for item in control.list_contexts()["contexts"]] == [
        "rcb_" + "b" * 32, "rcb_" + "a" * 32,
    ]

def test_sequences_are_independent_per_run_capability_and_stop_ack_is_heartbeat():
    control, transport, signer = client()
    activate_claimed_run(control)
    control.heartbeat(run_id=RUN_ID, operational_projection=client_projection(signer))
    control.heartbeat(run_id=RUN_ID, operational_projection=client_projection(signer))
    control.progress(run_id=RUN_ID, operational_projection=client_projection(signer))
    control.stop_ack(run_id=RUN_ID, operational_projection=client_projection(signer, "stop_requested"))
    assert [h["X-Heel-Runner-Sequence"] for _, h, _ in transport.requests] == ["1", "2", "1", "1"]
    assert transport.requests[-1][0].endswith(f"/runs/{RUN_ID}/stop-ack")
    assert json.loads(transport.requests[2][2])["schema_version"] == "heel.runner-progress-request.v1"

def test_refuses_noncanonical_origin_bad_nonce_and_prohibited_generic_retry():
    with pytest.raises(ValueError, match="pathless origin"):
        RunnerControlClient(origin="https://control.example?x=1", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "n")
    signer = Signer()
    bad = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="r", signer=signer, clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "", runtime=_runtime(signer, runner_id="r"))
    assert bad.claim()[0] == 204  # persisted activation cursor, never nonce_source, is authoritative.
    control, _, signer = client()
    with pytest.raises(ValueError, match="active runner claim is required"):
        control.progress(run_id="run", operational_projection=client_projection(signer))
    assert not hasattr(control, "retry_last")

def test_has_no_public_generic_request_api():
    control, _, _ = client()
    assert not hasattr(control, "request")
    public = {name for name, value in vars(RunnerControlClient).items() if callable(value) and not name.startswith("_")}
    assert public == {"claim", "heartbeat", "progress", "result", "upload_findings", "stop_ack", "start_resync", "complete_resync", "install_rotation_claim", "list_contexts", "claim_context", "submit_context_approval_projection", "replay_pending_call", "replay_all_pending", "stage_recovered_result"}


def test_replay_receipt_requires_a_fully_authenticated_byte_identical_pop():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO workspaces VALUES(?)", ("ws",))
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(raw)
    now = int(time.time() * 1000)
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("r", "ws", "r", "active", time.time()))
    conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, "ws", "r", base64.b64encode(raw).decode(), "active", time.time()))
    _enable_executable_protocol(conn, "ws", "r")
    nonce = "n" * 44
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "r", "claim", store._hash("nonce", nonce), 1, time.time() + 60))
    conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "r", "claim", 1, 0, time.time()))
    conn.commit()
    body, path = b"{}", "/v1/workspaces/ws/runners/r/claim"
    def headers(timestamp=now, signer=private):
        proof = {"schema_version":"heel.runner-request-proof.v1","workspace_id":"ws","runner_id":"r","key_id":key_id,"capability":"runner_claim","method":"POST","path":path,"body_sha256":hashlib.sha256(body).hexdigest(),"timestamp_ms":timestamp,"server_nonce":nonce,"sequence":1}
        signature = base64.b64encode(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()
        return {"X-Heel-Runner-Id":["r"],"X-Heel-Runner-Key-Id":[key_id],"X-Heel-Runner-Timestamp-Ms":[str(timestamp)],"X-Heel-Runner-Nonce":[nonce],"X-Heel-Runner-Sequence":["1"],"X-Heel-Runner-Signature":[signature],"Authorization":[],"Cookie":[]}
    with pytest.raises(ValueError):
        store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(), action=lambda: {"bad": 1.5})
    with pytest.raises(ValueError):
        store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(), action=lambda: {"bad": object()})
    with pytest.raises(ValueError):
        store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(), action=lambda: {"bad": "x" * (513 * 1024)})
    accepted_status, accepted, next_nonce = store.authenticate_and_consume(
        workspace_id="ws", runner_id="r", capability="runner_claim", path=path,
        raw_body=body, headers=headers(),
        action=lambda: RunnerHttpAction(200, {"status": "ok", "active": "yes"}),
    )
    assert (accepted_status, accepted) == (200, {"status": "ok", "active": "yes"}) and next_nonce
    assert store.authenticate_and_consume(
        workspace_id="ws", runner_id="r", capability="runner_claim", path=path,
        raw_body=body, headers=headers(),
        action=lambda: RunnerHttpAction(200, {"status": "bad"}),
    ) == (accepted_status, accepted, next_nonce)
    with pytest.raises(RunnerAuthError):
        store.authenticate_and_consume(workspace_id="ws", runner_id="r", capability="runner_claim", path=path, raw_body=body, headers=headers(now + 1), action=lambda: {"status": "leak"})
    receipt = conn.execute("SELECT response_json,next_nonce,response_ciphertext,next_nonce_ciphertext,response_status,response_body_digest,retention_expires_at FROM canary_runner_request_ledger").fetchone()
    assert receipt[0] == "sealed-v2" and receipt[1] != next_nonce and receipt[2] and receipt[3]
    assert receipt[4] == 200 and receipt[5] == hashlib.sha256(canonical_bytes(accepted)).hexdigest()
    assert receipt[6] >= time.time() + 2_591_999
    # Exact receipt lookup remains ahead of freshness only for the immutable
    # thirty-day horizon.  At the boundary, it must never return a replayed
    # nonce/body that an authenticated reaper may already have retired.
    conn.execute(
        "UPDATE canary_runner_request_ledger SET created_at=0,retention_expires_at=0"
    )
    conn.commit()
    with pytest.raises(RunnerAuthError):
        store.authenticate_and_consume(
            workspace_id="ws", runner_id="r", capability="runner_claim", path=path,
            raw_body=body, headers=headers(), action=lambda: RunnerHttpAction(200, {"status": "leak"}),
        )
    reaped = store.reap_expired_auth(now=time.time(), limit=1)
    assert reaped.request_receipts == 1
    assert reaped.pairing_receipts == reaped.rotation_receipts == 0
    assert reaped.abort_receipts == reaped.pairing_parents == reaped.rotation_parents == 0
    assert reaped.old_keys == 0 and reaped.has_more is False
    assert conn.execute("SELECT 1 FROM canary_runner_request_ledger").fetchone() is None


def test_expired_v3_pairing_activation_abort_is_signed_idempotent_and_retained():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO workspaces VALUES(?)", ("ws",))
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    instant = [1_000.0]
    store = RunnerAuthStore(conn, pepper=b"p" * 32, now=lambda: instant[0])
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    invitation = store.invite("ws")
    phrase = " ".join(runner_phrase_words()[:6])
    pending = store.exchange(
        invitation.token, public, phrase, display_name="Runner", runner_version="v3",
        adapters={}, control_protocol="heel.runner-control.v2", exchange_digest="a" * 64,
    )
    store.approve("ws", pending.pairing_id, phrase=phrase, fingerprint=pending.fingerprint, actor="owner")
    request = {
        "schema_version": "heel.runner-pairing-activation-abort.v2",
        "pairing_id": pending.pairing_id, "runner_id": pending.runner_id,
        "pairing_exchange_digest": "a" * 64, "activation_request_digest": "b" * 64,
        "activation_challenge_digest": hashlib.sha256(
            base64.b64decode(pending.activation_challenge, validate=True),
        ).hexdigest(),
        "reason_code": "activation_challenge_expired",
    }
    request["signature_b64"] = base64.b64encode(private.sign(
        b"heel.runner-pairing-activation-abort.v2\0" + canonical_bytes(request),
    )).decode()
    with pytest.raises(RunnerActivationAbortDeferred) as deferred:
        store.abort_executable_pairing_activation(pending.pairing_id, request)
    assert deferred.value.response == {
        "schema_version": "heel.runner-pairing-activation-abort-deferred.v1",
        "code": "runner_activation_challenge_live", "pairing_id": pending.pairing_id,
        "runner_id": pending.runner_id, "pairing_exchange_digest": "a" * 64,
        "activation_challenge_digest": request["activation_challenge_digest"],
        "challenge_expires_at_ms": int(pending.expires_at * 1000),
        "server_time_ms": 1_000_000, "retry_after_ms": int(pending.expires_at * 1000) - 1_000_000,
    }
    assert conn.execute(
        "SELECT 1 FROM canary_runner_pairing_activation_abort_receipts WHERE pairing_id=?",
        (pending.pairing_id,),
    ).fetchone() is None
    instant[0] = pending.expires_at
    response = store.abort_executable_pairing_activation(pending.pairing_id, request)
    assert response["status"] == "expired" and response["runner_id"] == pending.runner_id
    assert response["schema_version"] == "heel.runner-pairing-activation-aborted.v2"
    assert response["activation_challenge_digest"] == request["activation_challenge_digest"]
    assert response["challenge_expires_at_ms"] == int(pending.expires_at * 1000)
    assert store.abort_executable_pairing_activation(pending.pairing_id, request) == response
    receipt = conn.execute(
        "SELECT expires_at FROM canary_runner_pairing_activation_abort_receipts WHERE pairing_id=?",
        (pending.pairing_id,),
    ).fetchone()
    assert receipt[0] == instant[0] + 2_592_000.0
    instant[0] = receipt[0]
    with pytest.raises(RunnerActivationReceiptExpired):
        store.abort_executable_pairing_activation(pending.pairing_id, request)
    first_reap = store.reap_expired_auth(now=instant[0], limit=1)
    assert first_reap.abort_receipts == 1
    assert first_reap.pairing_parents == 0 and first_reap.has_more is True
    second_reap = store.reap_expired_auth(now=instant[0], limit=1)
    assert second_reap.pairing_parents == 1 and second_reap.has_more is False


def test_http_pairing_abort_v2_returns_the_authenticated_deferred_body_before_expiry():
    instant = [time.time()]
    cp = ControlPlane(
        device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
        enable_device_auth=True, public_origin="http://127.0.0.1",
    )
    assert cp.runner_auth is not None
    cp.runner_auth._now = lambda: instant[0]
    server = serve(cp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        ).decode()
        org = cp.store.create_org("org")
        workspace = cp.store.create_workspace(org, "ws", "free", "2026-08")
        invitation = cp.runner_auth.invite(workspace)
        phrase = " ".join(runner_phrase_words()[:6])
        pending = cp.runner_auth.exchange(
            invitation.token, public, phrase, display_name="Runner", runner_version="v3",
            adapters={}, control_protocol="heel.runner-control.v2", exchange_digest="a" * 64,
        )
        cp.runner_auth.approve(
            workspace, pending.pairing_id, phrase=phrase, fingerprint=pending.fingerprint, actor="owner",
        )
        request = {
            "schema_version": "heel.runner-pairing-activation-abort.v2",
            "pairing_id": pending.pairing_id, "runner_id": pending.runner_id,
            "pairing_exchange_digest": "a" * 64, "activation_request_digest": "b" * 64,
            "activation_challenge_digest": hashlib.sha256(
                base64.b64decode(pending.activation_challenge, validate=True),
            ).hexdigest(),
            "reason_code": "activation_challenge_expired",
        }
        request["signature_b64"] = base64.b64encode(private.sign(
            b"heel.runner-pairing-activation-abort.v2\0" + canonical_bytes(request),
        )).decode()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request(
            "POST", f"/v1/runner-pairings/{pending.pairing_id}/activation-abort",
            canonical_bytes(request), {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        assert response.status == 409
        body = json.loads(raw)
        assert raw == canonical_bytes(body)
        assert body == {
            "schema_version": "heel.runner-pairing-activation-abort-deferred.v1",
            "code": "runner_activation_challenge_live", "pairing_id": pending.pairing_id,
            "runner_id": pending.runner_id, "pairing_exchange_digest": "a" * 64,
            "activation_challenge_digest": request["activation_challenge_digest"],
            "challenge_expires_at_ms": int(pending.expires_at * 1000),
            "server_time_ms": body["server_time_ms"], "retry_after_ms": body["retry_after_ms"],
        }
        assert body["server_time_ms"] < body["challenge_expires_at_ms"]
        assert body["retry_after_ms"] == body["challenge_expires_at_ms"] - body["server_time_ms"]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_old_runner_key_reaper_requires_m29_and_uses_its_exact_queue_index():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    legacy = sqlite3.connect(":memory:")
    Migrator(legacy, CONTROL_PLANE_MIGRATIONS[:28]).apply_all()
    legacy_store = RunnerAuthStore(legacy, pepper=b"p" * 32)
    with pytest.raises(RunnerAuthError, match="runner authentication schema upgrade required"):
        legacy_store.reap_expired_auth(now=3_000_000.0, limit=1)
    assert not legacy.in_transaction

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        ("old-runner", "ws", "Old runner", "active", 1),
    )
    conn.executemany(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        (
            ("old-key-a", "ws", "old-runner", "old-public-key-a", "verification_only", 1, 1),
            ("old-key-b", "ws", "old-runner", "old-public-key-b", "verification_only", 1, 1),
        ),
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT revoked_at,workspace_id,runner_id,key_id,attempt_count "
        "FROM canary_runner_key_retirement_queue "
        "INDEXED BY idx_canary_runner_key_retirement_due "
        "WHERE next_attempt_at<=? "
        "ORDER BY next_attempt_at,eligible_at,workspace_id,runner_id,key_id LIMIT ?",
        (3_000_000.0, 2),
    ).fetchall()
    assert any("idx_canary_runner_key_retirement_due" in row[-1] for row in plan)
    assert not any("USE TEMP B-TREE" in row[-1] or "SCAN canary_runner_key_retirement_queue" in row[-1] for row in plan)

    traced = []
    conn.set_trace_callback(traced.append)
    first = store.reap_expired_auth(now=3_000_000.0, limit=1)
    conn.set_trace_callback(None)
    assert any(
        "FROM canary_runner_key_retirement_queue INDEXED BY idx_canary_runner_key_retirement_due" in statement
        for statement in traced
    )
    assert first.old_keys == 1 and first.has_more is True
    assert conn.execute("SELECT key_id FROM canary_runner_keys").fetchone()[0] == "old-key-b"
    second = store.reap_expired_auth(now=3_000_000.0, limit=1)
    assert second.old_keys == 1 and second.has_more is False
    assert conn.execute("SELECT 1 FROM canary_runner_keys").fetchone() is None


def test_runner_auth_schema_rejects_a_same_name_m29_queue_index_with_wrong_columns():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    validate_runner_auth_schema(conn)
    conn.execute("DROP INDEX idx_canary_runner_key_retirement_due")
    conn.execute(
        "CREATE INDEX idx_canary_runner_key_retirement_due "
        "ON canary_runner_key_retirement_queue(eligible_at,next_attempt_at,workspace_id,runner_id,key_id)",
    )
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)


@pytest.mark.parametrize(
    ("index_name", "table_name", "columns", "predicate"),
    (
        (
            "idx_canary_runner_key_history_expiry", "canary_runner_keys",
            "workspace_id,runner_id,key_id,revoked_at",
            " WHERE status='verification_only' AND revoked_at IS NOT NULL",
        ),
        (
            "idx_canary_runner_pairing_parent_expiry_global", "canary_runner_pairings",
            "pairing_id,expires_at", " WHERE status IN ('activated','expired')",
        ),
        (
            "idx_canary_runner_rotation_parent_expiry_global", "canary_runner_rotations",
            "pairing_id,expires_at", " WHERE status IN ('rotated','expired')",
        ),
        (
            "idx_canary_runner_ledger_key_ref", "canary_runner_request_ledger",
            "key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_runner_context_links_runner_key_ref", "canary_runner_context_projection_links",
            "runner_key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_runner_context_events_runner_key_ref", "canary_runner_context_events",
            "runner_key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_canary_approval_runner_key_ref", "canary_approval_projections",
            "runner_key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_canary_runner_rotation_new_key_ref", "canary_runner_rotations",
            "key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_canary_runner_key_retirement_due", "canary_runner_key_retirement_queue",
            "eligible_at,next_attempt_at,workspace_id,runner_id,key_id", "",
        ),
    ),
)
def test_runner_auth_schema_requires_the_exact_sql_and_xinfo_for_each_reaper_index(
    index_name, table_name, columns, predicate,
):
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute(f"DROP INDEX {index_name}")
    conn.execute(f"CREATE INDEX {index_name} ON {table_name}({columns}){predicate}")
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)


def test_runner_auth_store_enables_foreign_keys_before_accepting_a_connection():
    conn = sqlite3.connect(":memory:")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0
    RunnerAuthStore(conn, pepper=b"p" * 32)
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_runner_auth_store_rejects_foreign_keys_disabled_inside_a_transaction():
    conn = sqlite3.connect(":memory:")
    conn.execute("BEGIN")
    with pytest.raises(RunnerAuthError, match="runner authentication requires foreign keys"):
        RunnerAuthStore(conn, pepper=b"p" * 32)
    assert conn.in_transaction
    conn.rollback()


def test_runner_auth_reaper_rejects_foreign_keys_disabled_after_construction_before_retirement():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        ("old-runner", "ws", "Old runner", "active", 1),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        ("old-key", "ws", "old-runner", "old-public-key", "verification_only", 1, 1),
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    conn.execute("PRAGMA foreign_keys=OFF")
    with pytest.raises(RunnerAuthError, match="runner authentication requires foreign keys"):
        store.reap_expired_auth(now=3_000_000.0, limit=1)
    assert conn.execute("SELECT COUNT(*) FROM canary_runner_keys").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM canary_runner_key_retirement_queue").fetchone()[0] == 1


def test_runner_auth_reaper_accepts_a_valid_phase_cursor_for_the_old_key_lane():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        ("old-runner", "ws", "Old runner", "active", 1),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        ("old-key", "ws", "old-runner", "old-public-key", "verification_only", 1, 1),
    )
    conn.commit()
    reaped = RunnerAuthStore(conn, pepper=b"p" * 32).reap_expired_auth(
        now=3_000_000.0, limit=1, phase_cursor=7,
    )
    assert reaped.old_keys == 1 and reaped.has_more is False


def test_runner_auth_reaper_ring_prioritizes_its_requested_lane_without_losing_due_work():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        ("old-runner", "ws", "Old runner", "active", 1),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        ("old-key", "ws", "old-runner", "old-public-key", "verification_only", 1, 1),
    )
    conn.execute(
        "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
        ("ws", "old-runner", "claim", 2, 0, 1),
    )
    digest = "a" * 64
    conn.execute(
        "INSERT INTO canary_runner_request_ledger("
        "workspace_id,runner_id,chain_name,sequence,generation,request_digest,response_json,next_nonce,created_at,"
        "nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,"
        "response_ciphertext,next_nonce_ciphertext,response_status,response_body_digest,retention_expires_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "ws", "old-runner", "claim", 1, 0, digest, "sealed-v2", "next", 1,
            digest, "receipt-only-key", "runner_claim", "POST", "/claim", 1,
            digest, digest, "ciphertext", "nonce-ciphertext", 200, digest, 1,
        ),
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)

    first = store.reap_expired_auth(now=3_000_000.0, limit=1, phase_cursor=7)
    assert first.old_keys == 1 and first.request_receipts == 0 and first.has_more is True
    assert conn.execute("SELECT COUNT(*) FROM canary_runner_request_ledger").fetchone()[0] == 1

    second = store.reap_expired_auth(now=3_000_000.0, limit=1, phase_cursor=0)
    assert second.request_receipts == 1 and second.old_keys == 0 and second.has_more is False


def test_m29_parent_reaper_selectors_stay_expiry_indexed_with_large_history():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    # These are planner-only irrelevant history rows; all production inserts
    # remain FK-checked by the control-plane connection.
    conn.commit()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executemany(
        "INSERT INTO canary_runner_pairings("
        "pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name"
        ") VALUES(?,?,?,?,?,?,?,?)",
        (
            (f"pair-{number:06d}", "ws", f"runner-{number:06d}", f"{number:064x}",
             "expired", 1.0, 4_000_000.0, None)
            for number in range(100_000)
        ),
    )
    conn.executemany(
        "INSERT INTO canary_runner_rotations("
        "pairing_id,workspace_id,runner_id,phrase,public_key,fingerprint,key_id,"
        "runner_version,adapters_json,status,created_at,expires_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            (f"rotation-{number:06d}", "ws", f"rotation-runner-{number:06d}",
             "phrase", "key", "a" * 64, f"key-{number:06d}", "v1", "{}",
             "expired", 1.0, 4_000_000.0)
            for number in range(100_000)
        ),
    )
    conn.commit()

    pairing_plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT pairing_id FROM canary_runner_pairings "
        "INDEXED BY idx_canary_runner_pairing_parent_expiry_global "
        "WHERE expires_at<=? AND status IN ('activated','expired') AND ("
        "(status='activated' "
        " AND EXISTS(SELECT 1 FROM canary_runner_execution_protocols ep "
        "  WHERE ep.workspace_id=canary_runner_pairings.workspace_id "
        "   AND ep.runner_id=canary_runner_pairings.runner_id) "
        " AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_receipts ar "
        "  WHERE ar.pairing_id=canary_runner_pairings.pairing_id)) "
        "OR (status='expired' "
        " AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_receipts ar "
        "  WHERE ar.pairing_id=canary_runner_pairings.pairing_id) "
        " AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_abort_receipts ab "
        "  WHERE ab.pairing_id=canary_runner_pairings.pairing_id))) "
        "ORDER BY expires_at,pairing_id LIMIT ?",
        (3_000_000.0, 129),
    ).fetchall()
    rotation_plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT pairing_id FROM canary_runner_rotations "
        "INDEXED BY idx_canary_runner_rotation_parent_expiry_global "
        "WHERE expires_at<=? AND status IN ('rotated','expired') "
        "AND NOT EXISTS(SELECT 1 FROM canary_runner_rotation_activation_receipts ar "
        " WHERE ar.pairing_id=canary_runner_rotations.pairing_id) "
        "AND NOT EXISTS(SELECT 1 FROM canary_runner_rotation_activation_abort_receipts ab "
        " WHERE ab.pairing_id=canary_runner_rotations.pairing_id) "
        "ORDER BY expires_at,pairing_id LIMIT ?",
        (3_000_000.0, 129),
    ).fetchall()

    for plan, index in (
        (pairing_plan, "idx_canary_runner_pairing_parent_expiry_global"),
        (rotation_plan, "idx_canary_runner_rotation_parent_expiry_global"),
    ):
        details = [row[-1] for row in plan]
        assert any(f"SEARCH canary_runner_" in detail and index in detail for detail in details)
        assert not any("SCAN canary_runner_pair" in detail or "SCAN canary_runner_rotation" in detail for detail in details)
        assert not any("USE TEMP B-TREE" in detail for detail in details)


def test_m29_old_key_reaper_reschedules_blocked_keys_without_starving_later_due_key():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    blocked = [(f"runner-{number:03d}", f"key-{number:03d}") for number in range(128)]
    survivor = ("runner-survivor", "key-survivor")
    conn.executemany(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        [
            (runner_id, "ws", runner_id, "active", 1.0)
            for runner_id, _key_id in [*blocked, survivor]
        ],
    )
    conn.executemany(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        [
            (key_id, "ws", runner_id, f"public-{key_id}", "verification_only", 1.0, 1.0)
            for runner_id, key_id in [*blocked, survivor]
        ],
    )
    conn.executemany(
        "INSERT INTO canary_runner_identity_records VALUES(?,?,?,?,?)",
        [
            (
                "ws", runner_id,
                json.dumps({"public_key": {"key_id": key_id}}, sort_keys=True),
                f"{number:064x}", 1.0,
            )
            for number, (runner_id, key_id) in enumerate(blocked)
        ],
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)

    first = store.reap_expired_auth(now=3_000_000.0, limit=128)
    assert first.old_keys == 0
    assert first.has_more is True
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_runner_key_retirement_queue "
        "WHERE next_attempt_at>3000000.0 AND attempt_count=1"
    ).fetchone()[0] == 128

    second = store.reap_expired_auth(now=3_000_000.0, limit=128)
    assert second.old_keys == 1
    assert second.has_more is False
    assert conn.execute(
        "SELECT 1 FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? AND key_id=?",
        ("ws", survivor[0], survivor[1]),
    ).fetchone() is None
    assert conn.execute("SELECT COUNT(*) FROM canary_runner_keys").fetchone()[0] == 128


def test_m29_old_key_reference_probes_remain_exact_point_accesses():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    plans = (
        (
            "canary_runner_identity_records", None,
            "SELECT 1 FROM canary_runner_identity_records "
            "WHERE workspace_id=? AND runner_id=? "
            "AND json_extract(identity_json,'$.public_key.key_id')=? LIMIT 1",
        ),
        (
            "canary_runner_request_ledger", "idx_canary_runner_ledger_key_ref",
            "SELECT 1 FROM canary_runner_request_ledger "
            "INDEXED BY idx_canary_runner_ledger_key_ref "
            "WHERE workspace_id=? AND runner_id=? AND key_id=? LIMIT 1",
        ),
        (
            "canary_runner_context_bindings", "idx_runner_context_runner_status_expiry",
            "SELECT 1 FROM canary_runner_context_bindings "
            "INDEXED BY idx_runner_context_runner_status_expiry "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_runner_context_projection_links", "idx_runner_context_links_runner_key_ref",
            "SELECT 1 FROM canary_runner_context_projection_links "
            "INDEXED BY idx_runner_context_links_runner_key_ref "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_runner_context_events", "idx_runner_context_events_runner_key_ref",
            "SELECT 1 FROM canary_runner_context_events "
            "INDEXED BY idx_runner_context_events_runner_key_ref "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_runner_context_affinities", None,
            "SELECT 1 FROM canary_runner_context_affinities "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_execution_grants", "idx_canary_grants_runner_status",
            "SELECT 1 FROM canary_execution_grants "
            "INDEXED BY idx_canary_grants_runner_status "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_approval_projections", "idx_canary_approval_runner_key_ref",
            "SELECT 1 FROM canary_approval_projections "
            "INDEXED BY idx_canary_approval_runner_key_ref "
            "WHERE workspace_id=? AND runner_id=? AND runner_key_id=? LIMIT 1",
        ),
        (
            "canary_runner_pairings", None,
            "SELECT 1 FROM canary_runner_pairings "
            "WHERE workspace_id=? AND runner_id=? AND key_id=? LIMIT 1",
        ),
        (
            "canary_runner_rotations", "idx_canary_runner_rotation_new_key_ref",
            "SELECT 1 FROM canary_runner_rotations "
            "INDEXED BY idx_canary_runner_rotation_new_key_ref "
            "WHERE workspace_id=? AND runner_id=? AND key_id=? LIMIT 1",
        ),
        (
            "canary_runner_rotations", "idx_canary_runner_rotation_old_key_history",
            "SELECT 1 FROM canary_runner_rotations "
            "INDEXED BY idx_canary_runner_rotation_old_key_history "
            "WHERE workspace_id=? AND runner_id=? AND old_key_id=? LIMIT 1",
        ),
    )
    try:
        for table, index, query in plans:
            details = [row[-1] for row in conn.execute(
                "EXPLAIN QUERY PLAN " + query, ("ws", "runner", "old-key"),
            )]
            assert any("SEARCH" in detail and table in detail for detail in details)
            if index is not None:
                assert any(index in detail for detail in details)
            assert not any(f"SCAN {table}" in detail or "USE TEMP B-TREE" in detail for detail in details)
    finally:
        conn.close()


def test_runner_auth_body_cap_requires_an_explicit_bounded_integer_override():
    conn = sqlite3.connect(":memory:")
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    arguments = {
        "workspace_id": "ws", "runner_id": "runner", "capability": "runner_result",
        "path": "/v1/workspaces/ws/runners/runner/runs/run/result-projection",
        "raw_body": b"{}", "headers": {}, "action": lambda: {},
    }
    for invalid in (True, 0, -1, 272 * 1024 + 1, "278528"):
        with pytest.raises(ValueError):
            store.authenticate_and_consume(**arguments, max_body_bytes=invalid)


def test_runner_result_projection_is_the_only_explicit_above_default_body_cap():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO workspaces VALUES(?)", ("ws",))
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    private = Ed25519PrivateKey.generate()
    raw_key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(raw_key)
    now = time.time()
    nonce = "u" * 44
    conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", now))
    conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, "ws", "runner", base64.b64encode(raw_key).decode(), "active", now))
    _enable_executable_protocol(conn, "ws", "runner", activated_at=now)
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "runner", "result:run", store._hash("nonce", nonce), 1, now + 60))
    conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "runner", "result:run", 1, 0, now))
    conn.commit()
    body = canonical_bytes({"chunks": ["x" * 4096 for _ in range(18)]})
    assert 64 * 1024 < len(body) < 272 * 1024
    path = "/v1/workspaces/ws/runners/runner/runs/run/result-projection"
    timestamp = int(now * 1000)
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": "ws",
        "runner_id": "runner", "key_id": key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": timestamp, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "X-Heel-Runner-Id": ["runner"], "X-Heel-Runner-Key-Id": [key_id],
        "X-Heel-Runner-Timestamp-Ms": [str(timestamp)], "X-Heel-Runner-Nonce": [nonce],
        "X-Heel-Runner-Sequence": ["1"],
        "X-Heel-Runner-Signature": [base64.b64encode(private.sign(
            b"heel.runner-pop.v1\0" + canonical_bytes(proof)
        )).decode()], "Authorization": [], "Cookie": [],
    }
    arguments = {
        "workspace_id": "ws", "runner_id": "runner", "capability": "runner_result",
        "path": path, "raw_body": body, "headers": headers,
        "chain_name": "result:run", "action": lambda: RunnerHttpAction(200, {"accepted": True}),
    }
    with pytest.raises(ValueError):
        store.authenticate_and_consume(**arguments)
    status, response, _ = store.authenticate_and_consume(
        **arguments, max_body_bytes=272 * 1024,
    )
    assert (status, response) == (200, {"accepted": True})


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
    _enable_executable_protocol(conn, workspace, "runner", activated_at=instant[0])
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
            _enable_executable_protocol(cp.store.conn, workspace, "runner", activated_at=now)
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
        status, activated, _ = request("POST", f"/v1/runner-pairings/{exchanged['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v1", "signature_b64":signature})
        assert status == 200
        record = cp.store.conn.execute("SELECT identity_json,identity_digest FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?", (signup["workspace_id"], exchanged["runner_id"])).fetchone()
        identity = validate_runner_identity(json.loads(record[0]))
        assert identity["identity_digest"] == record[1]
        assert identity["capabilities"] == ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]
        assert identity["pairing"]["fingerprint_confirmation"] == "confirmed"
        identity["rotation"]["previous_key_ids"].append("mutated")
        assert "mutated" not in cp.runner_auth.identity(signup["workspace_id"], exchanged["runner_id"])["rotation"]["previous_key_ids"]
        claim_body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
        timestamp_ms = int(time.time() * 1000)
        claim_path = f"/v1/workspaces/{signup['workspace_id']}/runners/{exchanged['runner_id']}/claim"
        claim_proof = {
            "schema_version": "heel.runner-request-proof.v1", "workspace_id": signup["workspace_id"],
            "runner_id": exchanged["runner_id"], "key_id": ed25519_key_id(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "capability": "runner_claim", "method": "POST", "path": claim_path,
            "body_sha256": hashlib.sha256(claim_body).hexdigest(), "timestamp_ms": timestamp_ms,
            "server_nonce": activated["initial_claim_nonce"], "sequence": 1,
        }
        status, blocked, _ = request("POST", claim_path, {"schema_version": "heel.runner-claim-request.v1"}, {
            "X-Heel-Runner-Id": exchanged["runner_id"], "X-Heel-Runner-Key-Id": claim_proof["key_id"],
            "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
            "X-Heel-Runner-Nonce": activated["initial_claim_nonce"], "X-Heel-Runner-Sequence": "1",
            "X-Heel-Runner-Signature": base64.b64encode(private.sign(
                b"heel.runner-pop.v1\0" + canonical_bytes(claim_proof),
            )).decode(),
        })
        assert (status, blocked) == (403, {"schema_version": "heel.runner-error.v1", "code": "runner_protocol_upgrade_required"})
        assert cp.store.conn.execute(
            "SELECT next_sequence FROM canary_runner_nonce_chains "
            "WHERE workspace_id=? AND runner_id=? AND chain_name='claim'",
            (signup["workspace_id"], exchanged["runner_id"]),
        ).fetchone()[0] == 1
    finally:
        server.shutdown(); server.server_close()


def test_http_v3_pairing_activation_replays_one_sealed_executable_cursor():
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test")
    server = serve(cp)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()

    def request(method, path, body, headers=None, *, raw_response=False):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        payload = json.dumps(body, separators=(",", ":")).encode() if method == "POST" else None
        request_headers = ({"Content-Type": "application/json", **(headers or {})}
                           if method == "POST" else (headers or {}))
        conn.request(method, path, payload, request_headers)
        response = conn.getresponse(); raw = response.read(); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, (raw if raw_response else json.loads(raw)), cookie

    try:
        _, signup, cookie = request(
            "POST", "/v1/signup", {"email": "v3-runner@example.test", "password": "correct-horse-battery"},
        )
        browser = {"Cookie": cookie.split(";", 1)[0], "Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"}
        status, invitation, _ = request(
            "POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings",
            {"schema_version": "heel.runner-pairing-invite.v1"}, browser,
        )
        assert status == 201
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        from heel.saas.runner_auth import WORDS
        phrase = " ".join(WORDS[:6])
        exchange_request = {
            "schema_version": "heel.runner-pairing-exchange.v3", "invitation_token": invitation["invitation_token"],
            "public_key_b64": public, "pairing_phrase": phrase, "display_name": "Runner V3",
            "runner_version": "v3", "adapters": {}, "control_protocol": "heel.runner-control.v2",
        }
        status, pending, _ = request("POST", "/v1/runner-pairings/exchange", exchange_request)
        assert status == 201
        assert set(pending) == {
            "schema_version", "pairing_id", "runner_id", "fingerprint", "status",
            "activation_challenge", "control_protocol", "pairing_exchange_digest",
            "challenge_expires_at_ms",
        }
        assert pending["schema_version"] == "heel.runner-pairing-pending.v3"
        assert pending["control_protocol"] == "heel.runner-control.v2"
        assert pending["pairing_exchange_digest"] == hashlib.sha256(canonical_bytes(exchange_request)).hexdigest()
        assert type(pending["challenge_expires_at_ms"]) is int
        row_expiry = cp.store.conn.execute(
            "SELECT expires_at FROM canary_runner_pairings WHERE pairing_id=?", (pending["pairing_id"],),
        ).fetchone()[0]
        assert pending["challenge_expires_at_ms"] == int(row_expiry * 1000)
        fingerprint = hashlib.sha256(base64.b64decode(public)).hexdigest()
        assert request(
            "POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{pending['pairing_id']}/approve",
            {"schema_version": "heel.runner-pairing-approve.v1", "pairing_phrase": phrase, "fingerprint": fingerprint}, browser,
        )[0] == 200
        client_nonce = base64.b64encode(b"v" * 32).decode()
        activation_core = {
            "pairing_id": pending["pairing_id"], "activation_challenge": pending["activation_challenge"],
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "client_activation_nonce_b64": client_nonce, "control_protocol": "heel.runner-control.v2",
        }
        activation = {
            "schema_version": "heel.runner-pairing-activate.v3", "client_activation_nonce_b64": client_nonce,
            "signature_b64": base64.b64encode(private.sign(
                b"heel.runner-pairing-activate.v3\0" + canonical_bytes(activation_core),
            )).decode(),
        }
        route = f"/v1/runner-pairings/{pending['pairing_id']}/activate"
        status, first_raw, _ = request("POST", route, activation, raw_response=True)
        first = json.loads(first_raw)
        assert status == 200
        assert set(first) == {
            "schema_version", "workspace_id", "runner_id", "runner_key_id", "pairing_exchange_digest",
            "initial_claim_nonce", "initial_claim_sequence", "initial_claim_generation", "capabilities",
            "control_protocol", "activated_at_ms",
        }
        assert first["schema_version"] == "heel.runner-pairing-activated.v3"
        assert first["initial_claim_sequence"] == 1 and first["initial_claim_generation"] == 0
        replay_status, replay_raw, _ = request("POST", route, activation, raw_response=True)
        assert replay_status == 200 and replay_raw == first_raw
        retention = cp.store.conn.execute(
            "SELECT p.expires_at,r.expires_at FROM canary_runner_pairings p "
            "JOIN canary_runner_pairing_activation_receipts r ON r.pairing_id=p.pairing_id "
            "WHERE p.pairing_id=?", (pending["pairing_id"],),
        ).fetchone()
        assert retention[0] == retention[1] and retention[0] >= first["activated_at_ms"] / 1000 + 2_591_999
        # A later invite must not resurrect the old global expiry sweep.
        cp.store.conn.execute(
            "UPDATE canary_runner_pairings SET expires_at=? WHERE pairing_id=?",
            (time.time() - 1, pending["pairing_id"]),
        )
        cp.store.conn.commit()
        cp.runner_auth.invite(signup["workspace_id"])
        assert cp.store.conn.execute(
            "SELECT 1 FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
            (pending["pairing_id"],),
        ).fetchone() is not None
        changed = dict(activation); changed["client_activation_nonce_b64"] = base64.b64encode(b"w" * 32).decode()
        assert request("POST", route, changed)[0] == 400
        execution = cp.store.conn.execute(
            "SELECT protocol_version,control_protocol,exchange_digest FROM canary_runner_execution_protocols "
            "WHERE workspace_id=? AND runner_id=?", (signup["workspace_id"], pending["runner_id"]),
        ).fetchone()
        assert tuple(execution) == (3, "heel.runner-control.v2", pending["pairing_exchange_digest"])
        # An activation receipt is byte-replay authority only through the
        # receipt horizon; executable authority remains pinned separately.
        cp.store.conn.execute(
            "UPDATE canary_runner_pairing_activation_receipts SET expires_at=0 WHERE pairing_id=?",
            (pending["pairing_id"],),
        )
        cp.store.conn.commit()
        status, expired, _ = request("POST", route, activation)
        assert status == 410
        assert expired == {
            "schema_version": "heel.runner-error.v1",
            "code": "runner_activation_receipt_expired",
        }
        reaped = cp.runner_auth.reap_expired_auth(now=time.time(), limit=2)
        assert reaped.pairing_receipts == 1 and reaped.pairing_parents == 1
        assert reaped.rotation_receipts == reaped.abort_receipts == reaped.old_keys == 0
        assert reaped.has_more is False
        assert cp.store.conn.execute(
            "SELECT 1 FROM canary_runner_pairings WHERE pairing_id=?", (pending["pairing_id"],),
        ).fetchone() is None
    finally:
        server.shutdown(); server.server_close(); cp.close()


def test_rotation_has_its_own_public_poll_and_activation_path():
    cloud = SigningAuthority.generate()
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test",
                      grant_authority=cloud)
    server = serve(cp); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    def request(method, path, body, headers=None, *, raw_response=False):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        raw = (
            canonical_bytes(body) if path.endswith("/activation-abort")
            else json.dumps(body, separators=(",", ":")).encode()
        ) if method == "POST" else None
        conn.request(method, path, raw, ({"Content-Type":"application/json", **(headers or {})} if method == "POST" else (headers or {})))
        response = conn.getresponse(); raw_response_body = response.read(); payload = raw_response_body if raw_response else json.loads(raw_response_body); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, payload, cookie
    class HttpTransport:
        def post(self, path, *, headers=None, body=b""):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
            conn.request("POST", path, body, headers or {})
            response = conn.getresponse(); raw_response = response.read()
            payload = json.loads(raw_response) if raw_response else None
            response_headers = dict(response.getheaders()); status = response.status; conn.close()
            return status, response_headers, payload

    class LocalSigner(SecureSigner):
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
        exchange = {"schema_version":"heel.runner-pairing-exchange.v3", "invitation_token":invite["invitation_token"], "public_key_b64":old_public, "pairing_phrase":phrase, "display_name":"Rotating runner", "runner_version":"v1", "adapters":{}, "control_protocol":"heel.runner-control.v2"}
        _, pending, _ = request("POST", "/v1/runner-pairings/exchange", exchange, {})
        request("POST", f"/v1/workspaces/{signup['workspace_id']}/runner-pairings/{pending['pairing_id']}/approve", {"schema_version":"heel.runner-pairing-approve.v1", "pairing_phrase":phrase, "fingerprint":pending["fingerprint"]}, browser)
        client_nonce = base64.b64encode(b"o" * 32).decode()
        activation_core = {"pairing_id":pending["pairing_id"], "activation_challenge":pending["activation_challenge"], "pairing_exchange_digest":pending["pairing_exchange_digest"], "client_activation_nonce_b64":client_nonce, "control_protocol":"heel.runner-control.v2"}
        proof = b"heel.runner-pairing-activate.v3\0" + canonical_bytes(activation_core)
        status, first_activation, _ = request("POST", f"/v1/runner-pairings/{pending['pairing_id']}/activate", {"schema_version":"heel.runner-pairing-activate.v3", "client_activation_nonce_b64":client_nonce, "signature_b64":base64.b64encode(old.sign(proof)).decode()})
        assert status == 200
        old_signer = LocalSigner(old)
        old_runtime = _runtime(old_signer, workspace_id=signup["workspace_id"], runner_id=pending["runner_id"], install_claim=False)
        old_runtime.install_chain(operation="claim", run_id=None, next_nonce_b64=first_activation["initial_claim_nonce"], next_sequence=1, generation=0, now_ms=first_activation["activated_at_ms"])
        old_client = RunnerControlClient(
            origin="http://127.0.0.1", workspace_id=signup["workspace_id"], runner_id=pending["runner_id"],
            signer=old_signer, clock=lambda: int(time.time() * 1000), transport=HttpTransport(),
            nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("v3 activation did not seed claim")),
            runtime=old_runtime,
        )
        assert old_client.claim()[0] == 204
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
        activation_request = {"schema_version":"heel.runner-rotation-activate.v2", "signature_b64":base64.b64encode(new.sign(proof)).decode()}
        abort_core = {
            "schema_version": "heel.runner-rotation-activation-abort.v1",
            "workspace_id": signup["workspace_id"], "runner_id": pending["runner_id"],
            "pairing_id": rotation["pairing_id"], "old_runner_key_id": old_signer.key_id,
            "new_runner_key_id": ed25519_key_id(base64.b64decode(new_public)),
            "activation_request_digest": hashlib.sha256(canonical_bytes(activation_request)).hexdigest(),
            "activation_challenge_digest": hashlib.sha256(base64.b64decode(poll["activation_challenge"])).hexdigest(),
            "challenge_expires_at_ms": int(cp.store.conn.execute(
                "SELECT expires_at FROM canary_runner_rotations WHERE pairing_id=?", (rotation["pairing_id"],),
            ).fetchone()[0] * 1000),
            "reason_code": "activation_challenge_expired",
        }
        abort = dict(abort_core)
        abort["old_signature_b64"] = base64.b64encode(old.sign(
            b"heel.runner-rotation-activation-abort.v1.old\0" + canonical_bytes(abort_core),
        )).decode()
        abort["new_signature_b64"] = base64.b64encode(new.sign(
            b"heel.runner-rotation-activation-abort.v1.new\0" + canonical_bytes(abort_core),
        )).decode()
        assert request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/activation-abort", abort)[0] == 409
        route = f"/v1/runner-rotations/{rotation['pairing_id']}/activate"
        status, activated_raw, _ = request("POST", route, activation_request, raw_response=True)
        activated = json.loads(activated_raw)
        assert status == 200
        assert set(activated) == {"schema_version", "workspace_id", "runner_id", "initial_claim_nonce", "initial_claim_sequence", "initial_claim_generation"}
        assert activated["schema_version"] == "heel.runner-rotation-activated.v2"
        assert activated["initial_claim_sequence"] == 2 and activated["initial_claim_generation"] == 1
        replay_status, replay_raw, _ = request("POST", route, activation_request, raw_response=True)
        assert replay_status == 200 and replay_raw == activated_raw
        changed = dict(activation_request)
        changed["signature_b64"] = base64.b64encode(b"z" * 64).decode()
        assert request("POST", f"/v1/runner-rotations/{rotation['pairing_id']}/activate", changed)[0] == 400
        assert cp.store.conn.execute(
            "SELECT 1 FROM canary_runner_rotation_activation_receipts WHERE pairing_id=?",
            (rotation["pairing_id"],),
        ).fetchone() is not None
        new_signer = LocalSigner(new)
        new_client = RunnerControlClient(
            origin="http://127.0.0.1", workspace_id=signup["workspace_id"], runner_id=pending["runner_id"],
            signer=new_signer, clock=lambda: int(time.time() * 1000), transport=HttpTransport(),
            nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("rotation install did not seed claim")),
            runtime=_runtime(new_signer, workspace_id=signup["workspace_id"], runner_id=pending["runner_id"], install_claim=False),
        )
        installed = new_client.install_rotation_claim(activated)
        assert installed.initial_claim_sequence == 2 and installed.initial_claim_generation == 1
        assert new_client.claim()[0] == 204
        identity = cp.runner_auth.identity(signup["workspace_id"], pending["runner_id"])
        assert identity["state"] == "active" and identity["public_key"]["public_key_b64"] == new_public
        assert identity["rotation"]["previous_key_ids"]
        # The signed identity is a bounded current summary.  Durable key rows
        # retain the full overlap/audit history, so the 21st rotation must not
        # turn a valid ceremony into a 500 after authority mutation.
        current_private = new
        for rotation_index in range(20):
            current_raw = current_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            next_private = Ed25519PrivateKey.generate()
            next_raw = next_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            status, next_rotation, _ = request(
                "POST", f"/v1/workspaces/{signup['workspace_id']}/runners/{pending['runner_id']}/rotate",
                {
                    "schema_version": "heel.runner-rotation-start.v1",
                    "previous_fingerprint": hashlib.sha256(current_raw).hexdigest(),
                    "public_key_b64": base64.b64encode(next_raw).decode(),
                    "pairing_phrase": phrase, "runner_version": "v-next", "adapters": {},
                }, browser,
            )
            assert status == 201
            assert request(
                "POST",
                f"/v1/workspaces/{signup['workspace_id']}/runners/{pending['runner_id']}/rotations/{next_rotation['pairing_id']}/approve",
                {
                    "schema_version": "heel.runner-rotation-approve.v1",
                    "pairing_phrase": phrase, "fingerprint": next_rotation["fingerprint"],
                }, browser,
            )[0] == 200
            status, challenge, _ = request(
                "POST", f"/v1/runner-rotations/{next_rotation['pairing_id']}/poll", {},
            )
            assert status == 200
            proof = b"heel.runner-rotation-activate.v2\0" + canonical_bytes({
                "pairing_id": next_rotation["pairing_id"],
                "challenge": challenge["activation_challenge"],
            })
            status, rotation_response, _ = request(
                "POST", f"/v1/runner-rotations/{next_rotation['pairing_id']}/activate",
                {
                    "schema_version": "heel.runner-rotation-activate.v2",
                    "signature_b64": base64.b64encode(next_private.sign(proof)).decode(),
                },
            )
            assert status == 200, (rotation_index, rotation_response)
            current_private = next_private
        identity = cp.runner_auth.identity(signup["workspace_id"], pending["runner_id"])
        assert len(identity["rotation"]["previous_key_ids"]) == 20
        expected_previous = sorted(row[0] for row in cp.store.conn.execute(
            "SELECT key_id FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? "
            "AND key_id<>? ORDER BY created_at DESC,key_id ASC LIMIT 20",
            (
                signup["workspace_id"], pending["runner_id"],
                ed25519_key_id(current_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
            ),
        ))
        assert identity["rotation"]["previous_key_ids"] == expected_previous
        audits = cp.store.conn.execute(
            "SELECT reason_code FROM canary_runner_audit_records WHERE workspace_id=? AND runner_id=? "
            "AND action='runner_rotated' ORDER BY created_at,audit_id",
            (signup["workspace_id"], pending["runner_id"]),
        ).fetchall()
        assert len(audits) == 21
        assert audits[-1][0] == "previous_key_history_window_advanced"
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
            _enable_executable_protocol(cp.store.conn, workspace, "runner")
            cp.store.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", cp.runner_auth._hash("nonce", nonce), 1, time.time() + 60)); cp.store.conn.commit()
            cp.store.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (workspace, "runner", "claim", 1, 0, time.time())); cp.store.conn.commit()
            body = b"{}"; route = f"/v1/workspaces/{workspace}/runners/runner/claim"; now = int(time.time() * 1000)
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_claim", "method":"POST", "path":route, "body_sha256":hashlib.sha256(body).hexdigest(), "timestamp_ms":now, "server_nonce":nonce, "sequence":1}
            headers = {"X-Heel-Runner-Id":["runner"], "X-Heel-Runner-Key-Id":[key_id], "X-Heel-Runner-Timestamp-Ms":[str(now)], "X-Heel-Runner-Nonce":[nonce], "X-Heel-Runner-Sequence":["1"], "X-Heel-Runner-Signature":[base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()], "Authorization":[], "Cookie":[]}
            result, started = [], threading.Event()
            def heartbeat():
                started.set()
                with cp.runner_request_store() as isolated:
                    result.append(isolated.authenticate_and_consume(workspace_id=workspace, runner_id="runner", capability="runner_claim", path=route, raw_body=body, headers=headers, action=lambda: RunnerHttpAction(200, {"ok":"yes"}) )[1])
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
        cp = ControlPlane(
            path, runner_auth_pepper=b"r" * 32,
            grant_authority=SigningAuthority.generate(),
        )
        server = serve(cp); served = threading.Thread(target=server.serve_forever, daemon=True); served.start()
        try:
            org = cp.store.create_org("org")
            workspace = cp.store.create_workspace(org, "ws", "free", CATALOG_VERSION)
            private = Ed25519PrivateKey.generate()
            public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            raw = base64.b64decode(public); key_id = ed25519_key_id(raw)
            cp.store.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", time.time()))
            cp.store.conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", public, "active", time.time()))
            stamp, stamp_ms, digest = time.time(), int(time.time() * 1000), "a" * 64
            cp.store.conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (workspace, "prj", "project", "owner", stamp))
            cp.store.conn.execute(
                "INSERT INTO users VALUES(?,?,?)", ("owner", "owner@example.test", stamp),
            )
            cp.store.conn.execute(
                "INSERT INTO memberships VALUES(?,?,?,?)", (workspace, "owner", "owner", stamp),
            )
            cp.store.conn.execute(
                "INSERT INTO canary_environments("
                "environment_id,workspace_id,project_ref,origin,environment_class,status,created_at,"
                "attestation_text,attestation_version,attestation_acknowledgement,attested_by,attested_at,"
                "proof_method,proof_version,normalization_version,challenge_generation,last_check_at,"
                "verified_at,proof_expires_at,verification_record_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "env", workspace, "prj", "https://canary.acme.dev", "staging", "verified",
                    stamp, "ownership verified; environment classification supplied by you", "v1",
                    "accepted", "owner", stamp, "https-file", "https-file.v1", "exact-origin.v1",
                    1, stamp, stamp, stamp + 3600, digest,
                ),
            )
            identity = cp.runner_auth._identity_record(workspace_id=workspace, runner_id="runner", public_key=public, fingerprint=hashlib.sha256(raw).hexdigest(), key_id=key_id, runner_version="1.0.0", adapters_json=json.dumps({"canary":"1.0.0"}), paired_by="owner", paired_at=time.time(), heartbeat_at=time.time())
            cp.runner_auth._save_identity(identity, instant=time.time())
            _enable_executable_protocol(cp.store.conn, workspace, "runner")
            cp.store.conn.commit()
            from canary_test_support import approval_projection, operational_projection
            from heel.saas.canary_runs import CanaryRunService
            runner_signer = SigningAuthority.from_private_key(private, key_id)
            runs = CanaryRunService(
                cp.store.conn, signing=cp.grant_authority,
                runner_auth=cp.runner_auth, initialize_schema=False,
            )
            approval = approval_projection(
                runner_signer, workspace_id=workspace, project_ref="prj",
                environment_id="env", runner_id="runner", verification_digest=digest,
            )
            submitted = runs.submit_projection(approval, uploaded_by="owner")
            approved = runs.approve(
                workspace, "prj", submitted["run_id"],
                projection_digest=approval["projection_digest"], actor="owner", role="owner",
                reason="Exercise the exact runner heartbeat lock boundary",
                exact_hostname="canary.acme.dev", recent_auth_at_ms=stamp_ms,
                idempotency_key="ca1-" + "c" * 64,
                expected_kill_switch_generation=0,
            )
            claimed = runs.claim(workspace, "runner", key_id)
            run_id = submitted["run_id"]
            nonce = claimed["chain_states"]["heartbeat"]["next_nonce_b64"]
            projection = operational_projection(
                runner_signer, approved["grant"], sequence=0, phase="claimed",
            )
            body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": run_id, "operational_projection": projection})
            route = f"/v1/workspaces/{workspace}/runners/runner/runs/{run_id}/heartbeat"
            timestamp = int(time.time() * 1000)
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_heartbeat", "method":"POST", "path":route, "body_sha256":hashlib.sha256(body).hexdigest(), "timestamp_ms":timestamp, "server_nonce":nonce, "sequence":claimed["chain_states"]["heartbeat"]["next_sequence"]}
            headers = {"Content-Type":"application/json", "X-Heel-Runner-Id":"runner", "X-Heel-Runner-Key-Id":key_id, "X-Heel-Runner-Timestamp-Ms":str(timestamp), "X-Heel-Runner-Nonce":nonce, "X-Heel-Runner-Sequence":str(proof["sequence"]), "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()}
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
            wrong_body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": run_id, "operational_projection": wrong_projection})
            wrong_proof = {**proof, "body_sha256": hashlib.sha256(wrong_body).hexdigest(), "server_nonce": result[0][1], "sequence": proof["sequence"] + 1}
            wrong_headers = {**headers, "X-Heel-Runner-Nonce":result[0][1], "X-Heel-Runner-Sequence":"2", "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(wrong_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", route, wrong_body, wrong_headers)
            assert conn.getresponse().status == 401; conn.close()
            tampered_projection = json.loads(json.dumps(projection))
            tampered_projection["counters"]["remaining_requests"] = 1  # digest/signature no longer attest this body.
            tampered_body = canonical_bytes({"schema_version": "heel.runner-heartbeat-request.v1", "run_id": run_id, "operational_projection": tampered_projection})
            tampered_proof = {**proof, "body_sha256": hashlib.sha256(tampered_body).hexdigest(), "server_nonce": result[0][1], "sequence": proof["sequence"] + 1}
            tampered_headers = {**headers, "X-Heel-Runner-Nonce":result[0][1], "X-Heel-Runner-Sequence":str(tampered_proof["sequence"]), "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(tampered_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", route, tampered_body, tampered_headers)
            assert conn.getresponse().status == 401; conn.close()
            stop_projection = operational_projection(
                runner_signer, approved["grant"], sequence=1, phase="stop_requested",
                stop_reason="cloud_stop", stop_requested_at_ms=stamp_ms,
                stop_acknowledged_at_ms=stamp_ms,
            )
            stop_body = canonical_bytes({"schema_version":"heel.runner-stop-ack-request.v1", "run_id":run_id, "operational_projection":stop_projection})
            stop_route = f"/v1/workspaces/{workspace}/runners/runner/runs/{run_id}/stop-ack"; stop_timestamp = int(time.time() * 1000); stop_chain = claimed["chain_states"]["stop-ack"]; stop_nonce = stop_chain["next_nonce_b64"]
            stop_proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace, "runner_id":"runner", "key_id":key_id, "capability":"runner_heartbeat", "method":"POST", "path":stop_route, "body_sha256":hashlib.sha256(stop_body).hexdigest(), "timestamp_ms":stop_timestamp, "server_nonce":stop_nonce, "sequence":stop_chain["next_sequence"]}
            stop_headers = {"Content-Type":"application/json", "X-Heel-Runner-Id":"runner", "X-Heel-Runner-Key-Id":key_id, "X-Heel-Runner-Timestamp-Ms":str(stop_timestamp), "X-Heel-Runner-Nonce":stop_nonce, "X-Heel-Runner-Sequence":str(stop_proof["sequence"]), "X-Heel-Runner-Signature":base64.b64encode(private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(stop_proof))).decode()}
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("POST", stop_route, stop_body, stop_headers)
            assert conn.getresponse().status == 409; conn.close()
        finally:
            server.shutdown(); server.server_close(); cp.close()
