import base64
import copy
import hashlib
import inspect
import os
import sqlite3
import time
import http.client
import json
import logging
import re
import socket
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
import heel.saas.runner_auth as runner_auth
from heel.saas.http_api import ControlPlane, serve
from heel.saas.tenancy import Role

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


def test_runner_auth_schema_rejects_a_one_open_rotation_index_shape_with_preserved_index_list():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS[:26]).apply_all()
    original = (
        "CREATE UNIQUE INDEX idx_canary_runner_one_open_rotation\n"
        " ON canary_runner_rotations(workspace_id,runner_id)\n"
        " WHERE status IN ('rotation_pending','rotation_approved');"
    )
    replacement = (
        "CREATE UNIQUE INDEX idx_canary_runner_one_open_rotation\n"
        " ON canary_runner_rotations(pairing_id)\n"
        " WHERE status IN ('rotation_pending','rotation_approved');"
    )
    altered_m27 = runner_auth.RUNNER_AUTH_SINGLE_OPEN_ROTATION_MIGRATION.replace(original, replacement)
    assert altered_m27 != runner_auth.RUNNER_AUTH_SINGLE_OPEN_ROTATION_MIGRATION
    conn.executescript(altered_m27)
    conn.executescript(runner_auth.RUNNER_AUTH_KEY_HISTORY_EXPIRY_MIGRATION)
    conn.executescript(runner_auth.RUNNER_AUTH_BOUNDED_RETENTION_MIGRATION)
    correct = sqlite3.connect(":memory:")
    correct.execute("PRAGMA foreign_keys=ON")
    Migrator(correct, CONTROL_PLANE_MIGRATIONS).apply_all()
    assert [tuple(row) for row in conn.execute("PRAGMA index_list(canary_runner_rotations)")] == [
        tuple(row) for row in correct.execute("PRAGMA index_list(canary_runner_rotations)")
    ]
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)


def test_runner_auth_forced_index_inventory_matches_every_indexed_by_clause():
    forced_names = set(re.findall(
        r"INDEXED BY ([A-Za-z0-9_]+)", inspect.getsource(runner_auth),
    ))
    exact_names = runner_auth._RUNNER_AUTH_EXACT_INDEX_NAMES
    assert len(exact_names) == len(set(exact_names))
    assert forced_names | {"idx_canary_runner_key_history_expiry"} == set(exact_names)


def test_runner_auth_schema_rejects_an_altered_one_open_rotation_predicate_with_preserved_index_list():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS[:26]).apply_all()
    original = (
        "CREATE UNIQUE INDEX idx_canary_runner_one_open_rotation\n"
        " ON canary_runner_rotations(workspace_id,runner_id)\n"
        " WHERE status IN ('rotation_pending','rotation_approved');"
    )
    replacement = (
        "CREATE UNIQUE INDEX idx_canary_runner_one_open_rotation\n"
        " ON canary_runner_rotations(workspace_id,runner_id)\n"
        " WHERE status='rotation_pending';"
    )
    conn.executescript(runner_auth.RUNNER_AUTH_SINGLE_OPEN_ROTATION_MIGRATION.replace(original, replacement))
    conn.executescript(runner_auth.RUNNER_AUTH_KEY_HISTORY_EXPIRY_MIGRATION)
    conn.executescript(runner_auth.RUNNER_AUTH_BOUNDED_RETENTION_MIGRATION)
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)


def test_runner_auth_schema_rejects_a_nonunique_one_open_rotation_index():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("DROP INDEX idx_canary_runner_one_open_rotation")
    conn.execute(
        "CREATE INDEX idx_canary_runner_one_open_rotation "
        "ON canary_runner_rotations(workspace_id,runner_id) "
        "WHERE status IN ('rotation_pending','rotation_approved')",
    )
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)


def test_one_open_rotation_index_rejects_a_second_open_ceremony_and_keeps_closed_history():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("PRAGMA foreign_keys=OFF")

    def insert(pairing_id, status):
        conn.execute(
            "INSERT INTO canary_runner_rotations("
            "pairing_id,workspace_id,runner_id,phrase,public_key,fingerprint,key_id,runner_version,"
            "adapters_json,status,created_at,expires_at,old_key_id,old_fingerprint"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                pairing_id, "ws", "runner", "phrase", "A" * 44, "a" * 64, pairing_id,
                "v1", "{}", status, 1, 2,
                "old-key" if status in {"rotation_pending", "rotation_approved"} else None,
                "b" * 64 if status in {"rotation_pending", "rotation_approved"} else None,
            ),
        )

    insert("closed-before", "rotated")
    insert("open", "rotation_pending")
    with pytest.raises(sqlite3.IntegrityError):
        insert("second-open", "rotation_approved")
    insert("closed-after", "expired")


def test_one_open_rotation_lookup_uses_its_exact_partial_index_without_a_scan():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    details = [row[-1] for row in conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT 1 FROM canary_runner_rotations INDEXED BY idx_canary_runner_one_open_rotation "
        "WHERE workspace_id=? AND runner_id=? "
        "AND status IN ('rotation_pending','rotation_approved') LIMIT 1",
        ("ws", "runner"),
    )]
    assert any(
        "SEARCH canary_runner_rotations" in detail
        and "idx_canary_runner_one_open_rotation" in detail
        and "workspace_id=? AND runner_id=?" in detail
        for detail in details
    )
    assert not any("SCAN canary_runner_rotations" in detail or "USE TEMP B-TREE" in detail for detail in details)


@pytest.mark.parametrize(
    ("index_name", "table_name", "columns", "predicate"),
    (
        (
            "idx_canary_runner_key_history_expiry", "canary_runner_keys",
            "workspace_id,runner_id,key_id,revoked_at",
            " WHERE status='verification_only' AND revoked_at IS NOT NULL",
        ),
        (
            "idx_canary_runner_ledger_retention", "canary_runner_request_ledger",
            "workspace_id,retention_expires_at,runner_id,chain_name,sequence,generation", "",
        ),
        (
            "idx_canary_runner_pairing_receipt_expiry", "canary_runner_pairing_activation_receipts",
            "pairing_id,expires_at", "",
        ),
        (
            "idx_canary_runner_rotation_receipt_expiry", "canary_runner_rotation_activation_receipts",
            "pairing_id,expires_at", "",
        ),
        (
            "idx_canary_runner_pairing_abort_receipt_expiry", "canary_runner_pairing_activation_abort_receipts",
            "pairing_id,expires_at", "",
        ),
        (
            "idx_canary_runner_rotation_abort_receipt_expiry", "canary_runner_rotation_activation_abort_receipts",
            "pairing_id,expires_at", "",
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
            "idx_runner_context_runner_status_expiry", "canary_runner_context_bindings",
            "runner_key_id,workspace_id,runner_id,status,expires_at_ms", "",
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
            "idx_canary_grants_runner_status", "canary_execution_grants",
            "runner_key_id,workspace_id,runner_id,status,issued_at", "",
        ),
        (
            "idx_canary_runner_rotation_new_key_ref", "canary_runner_rotations",
            "key_id,workspace_id,runner_id", "",
        ),
        (
            "idx_canary_runner_rotation_old_key_history", "canary_runner_rotations",
            "old_key_id,workspace_id,runner_id,status,created_at,pairing_id", "",
        ),
        (
            "idx_canary_runner_key_retirement_due", "canary_runner_key_retirement_queue",
            "eligible_at,next_attempt_at,workspace_id,runner_id,key_id", "",
        ),
        (
            "idx_canary_runner_one_open_rotation", "canary_runner_rotations",
            "pairing_id", " WHERE status IN ('rotation_pending','rotation_approved')",
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


@pytest.mark.parametrize(
    ("index_name", "table_name", "columns", "predicate"),
    (
        (
            "idx_canary_runner_key_history_expiry", "canary_runner_keys",
            "revoked_at,workspace_id,runner_id,key_id",
            " WHERE status='verification_only'",
        ),
        (
            "idx_canary_runner_pairing_parent_expiry_global", "canary_runner_pairings",
            "expires_at,pairing_id", " WHERE status='activated'",
        ),
        (
            "idx_canary_runner_rotation_parent_expiry_global", "canary_runner_rotations",
            "expires_at,pairing_id", " WHERE status='rotated'",
        ),
    ),
)
def test_runner_auth_schema_rejects_altered_partial_reaper_index_predicates(
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


def test_runner_auth_reaper_limit_counts_logical_work_not_key_queue_cascade_rows():
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
    pairings = [
        (
            f"pair-{number:03d}", "ws", f"runner-{number:03d}", f"{number:064x}",
            "activated", 1, 1, f"Runner {number}",
        )
        for number in range(127)
    ]
    conn.executemany(
        "INSERT INTO canary_runner_pairings("
        "pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name"
        ") VALUES(?,?,?,?,?,?,?,?)",
        pairings,
    )
    conn.executemany(
        "INSERT INTO canary_runner_pairing_activation_receipts VALUES(?,?,?,?,?)",
        [(pairing_id, "a" * 64, "sealed", 1, 1) for pairing_id, *_rest in pairings],
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    before = conn.total_changes
    reaped = store.reap_expired_auth(now=3_000_000.0, limit=128)
    assert reaped.pairing_receipts == 127 and reaped.old_keys == 1
    assert reaped.request_receipts == reaped.rotation_receipts == reaped.abort_receipts == 0
    assert reaped.pairing_parents == reaped.rotation_parents == 0 and reaped.has_more is False
    assert conn.total_changes - before == 129


@pytest.mark.parametrize(("key_count", "limit", "expected_changes"), ((1, 1, 2), (128, 128, 256)))
def test_runner_auth_reaper_key_retirement_bounds_physical_changes_per_logical_item(
    key_count, limit, expected_changes,
):
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        ("ws", "org", "ws", "free", CATALOG_VERSION, 1),
    )
    runners = [(f"runner-{number:03d}", "ws", f"Runner {number}", "active", 1) for number in range(key_count)]
    conn.executemany("INSERT INTO canary_runners VALUES(?,?,?,?,?)", runners)
    conn.executemany(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
        [
            (f"key-{number:03d}", "ws", f"runner-{number:03d}", f"public-{number}", "verification_only", 1, 1)
            for number in range(key_count)
        ],
    )
    conn.commit()
    store = RunnerAuthStore(conn, pepper=b"p" * 32)
    before = conn.total_changes
    reaped = store.reap_expired_auth(now=3_000_000.0, limit=limit)
    assert reaped.old_keys == key_count and reaped.has_more is False
    assert conn.total_changes - before == expected_changes


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


@pytest.mark.parametrize(
    ("table_name", "index_name", "query"),
    (
        (
            "canary_runner_request_ledger", "idx_canary_runner_ledger_retention",
            "SELECT workspace_id,runner_id,chain_name,sequence,generation "
            "FROM canary_runner_request_ledger INDEXED BY idx_canary_runner_ledger_retention "
            "WHERE retention_expires_at<=? "
            "ORDER BY retention_expires_at,workspace_id,runner_id,chain_name,sequence,generation LIMIT ?",
        ),
        (
            "canary_runner_pairing_activation_receipts", "idx_canary_runner_pairing_receipt_expiry",
            "SELECT pairing_id FROM canary_runner_pairing_activation_receipts "
            "INDEXED BY idx_canary_runner_pairing_receipt_expiry WHERE expires_at<=? "
            "ORDER BY expires_at,pairing_id LIMIT ?",
        ),
        (
            "canary_runner_rotation_activation_receipts", "idx_canary_runner_rotation_receipt_expiry",
            "SELECT pairing_id FROM canary_runner_rotation_activation_receipts "
            "INDEXED BY idx_canary_runner_rotation_receipt_expiry WHERE expires_at<=? "
            "ORDER BY expires_at,pairing_id LIMIT ?",
        ),
        (
            "canary_runner_pairing_activation_abort_receipts", "idx_canary_runner_pairing_abort_receipt_expiry",
            "SELECT pairing_id FROM canary_runner_pairing_activation_abort_receipts "
            "INDEXED BY idx_canary_runner_pairing_abort_receipt_expiry WHERE expires_at<=? "
            "ORDER BY expires_at,pairing_id LIMIT ?",
        ),
        (
            "canary_runner_rotation_activation_abort_receipts", "idx_canary_runner_rotation_abort_receipt_expiry",
            "SELECT pairing_id FROM canary_runner_rotation_activation_abort_receipts "
            "INDEXED BY idx_canary_runner_rotation_abort_receipt_expiry WHERE expires_at<=? "
            "ORDER BY expires_at,pairing_id LIMIT ?",
        ),
    ),
)
def test_runner_auth_receipt_reaper_selectors_remain_indexed(table_name, index_name, query):
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    details = [row[-1] for row in conn.execute(
        "EXPLAIN QUERY PLAN " + query, (3_000_000.0, 129),
    )]
    assert any("SEARCH" in detail and table_name in detail and index_name in detail for detail in details)
    assert not any(f"SCAN {table_name}" in detail or "USE TEMP B-TREE" in detail for detail in details)


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


def test_http_runner_revoke_requires_same_origin_recent_owner_and_exact_body():
    """POST /v1/workspaces/{ws}/runners/{id}/revoke over a real loopback server."""
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test")
    server = serve(cp)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    port = server.server_address[1]
    def request(method, path, body=None, headers=None, *, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        payload = raw if raw is not None else (json.dumps(body, separators=(",", ":")).encode() if body is not None else None)
        conn.request(method, path, payload, {**({"Content-Type": "application/json"} if payload is not None else {}), **(headers or {})})
        response = conn.getresponse(); data = response.read(); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, json.loads(data), cookie
    def raw_status(head):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(head); return int(sock.recv(4096).split(b" ", 2)[1])
    try:
        _, signup, cookie = request("POST", "/v1/signup", {"email": "revoke@example.test", "password": "correct-horse-battery"})
        wid = signup["workspace_id"]
        owner = cp.store.conn.execute("SELECT user_id FROM memberships WHERE workspace_id=?", (wid,)).fetchone()[0]
        browser = {"Cookie": cookie.split(";", 1)[0], "Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"}
        # A real runner: invite -> exchange -> owner approval of phrase + fingerprint -> activate.
        _, invitation, _ = request("POST", f"/v1/workspaces/{wid}/runner-pairings", {"schema_version": "heel.runner-pairing-invite.v1"}, browser)
        private = Ed25519PrivateKey.generate()
        public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        from heel.saas.runner_auth import WORDS
        phrase = " ".join(WORDS[:6])
        status, exchanged, _ = request("POST", "/v1/runner-pairings/exchange", {"schema_version": "heel.runner-pairing-exchange.v2", "invitation_token": invitation["invitation_token"], "public_key_b64": base64.b64encode(public_raw).decode(), "pairing_phrase": phrase, "display_name": "Runner revoke", "runner_version": "v1", "adapters": {}})
        assert status == 201
        assert request("POST", f"/v1/workspaces/{wid}/runner-pairings/{exchanged['pairing_id']}/approve", {"schema_version": "heel.runner-pairing-approve.v1", "pairing_phrase": phrase, "fingerprint": hashlib.sha256(public_raw).hexdigest()}, browser)[0] == 200
        activation = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id": exchanged["pairing_id"], "challenge": exchanged["activation_challenge"]})
        assert request("POST", f"/v1/runner-pairings/{exchanged['pairing_id']}/activate", {"schema_version": "heel.runner-pairing-activate.v1", "signature_b64": base64.b64encode(private.sign(activation)).decode()})[0] == 200
        runner_id = exchanged["runner_id"]
        path = f"/v1/workspaces/{wid}/runners/{runner_id}/revoke"
        body = {"schema_version": "heel.runner-revoke.v1", "reason_code": "human_revocation"}
        def runner_status():
            return cp.store.conn.execute("SELECT status FROM canary_runners WHERE workspace_id=? AND runner_id=?", (wid, runner_id)).fetchone()[0]
        def audit():
            return [tuple(row) for row in cp.store.conn.execute("SELECT actor,reason_code FROM canary_runner_audit_records WHERE workspace_id=? AND runner_id=? AND action='runner_revoked'", (wid, runner_id))]
        same_origin = (403, {"error": "same-origin browser ceremony is required", "code": "same_origin_required"})
        recent_auth = (403, {"error": "a recent owner or admin browser session is required", "code": "recent_auth_required"})
        invalid = (400, {"error": "invalid runner revocation", "code": "invalid_runner_revocation"})

        # The retired DELETE: generic framing still runs first (a body is ambiguous framing);
        # without a body the old route is simply unrouted.
        assert request("DELETE", f"/v1/workspaces/{wid}/runners/{runner_id}", body, browser)[:2] == (400, {"error": "request body is not allowed", "code": "ambiguous_request_framing"})
        assert request("DELETE", f"/v1/workspaces/{wid}/runners/{runner_id}", None, browser)[:2] == (404, {"error": "not found"})

        # Same-origin ceremony: Origin and the edge-derived internal-origin marker, checked first.
        for headers in ({k: v for k, v in browser.items() if k != "Origin"}, {**browser, "Origin": "https://evil.example"},
                        {k: v for k, v in browser.items() if k != "X-Heel-Internal-Origin"}, {**browser, "X-Heel-Internal-Origin": "cross-site"}):
            assert request("POST", path, body, headers)[:2] == same_origin
        assert request("POST", path, {"bad": True}, {"Origin": "https://heel.test"})[:2] == same_origin
        # Recent owner/admin browser session: anonymous, API key, stale, member/billing/viewer, other workspace.
        no_cookie = {k: v for k, v in browser.items() if k != "Cookie"}
        assert request("POST", path, body, no_cookie)[:2] == recent_auth
        api_key = cp.store.issue_api_key(wid, Role.MEMBER, "revoke-test")
        assert request("POST", path, body, {**no_cookie, "Authorization": f"Bearer {api_key.secret}"})[:2] == recent_auth
        assert request("POST", path, body, {**browser, "Authorization": f"Bearer {api_key.secret}"})[:2] == (400, {"error": "ambiguous authentication headers", "code": "ambiguous_request_headers"})
        for role in (Role.MEMBER, Role.BILLING, Role.VIEWER):
            user = cp.store.create_user(f"{role.value}@example.test"); cp.store.add_member(wid, user, role)
            assert request("POST", path, body, {**browser, "Cookie": f"heel_session={cp.auth.create_session(user).token}"})[:2] == recent_auth
        stranger = cp.store.create_user("stranger@example.test")
        assert request("POST", path, body, {**browser, "Cookie": f"heel_session={cp.auth.create_session(stranger).token}"})[:2] == recent_auth
        cp.store.conn.execute("UPDATE sessions SET created_at=? WHERE user_id=?", (time.time() - 901, owner)); cp.store.conn.commit()
        assert request("POST", path, body, browser)[:2] == recent_auth
        cp.store.conn.execute("UPDATE sessions SET created_at=? WHERE user_id=?", (time.time(), owner)); cp.store.conn.commit()

        # Exact closed body, checked only after the ceremony.
        for candidate in ({}, {"schema_version": "heel.runner-revoke.v1"}, {**body, "extra": 1},
                          {**body, "schema_version": "heel.runner-revoke.v0"}, {**body, "reason_code": None},
                          {**body, "reason_code": ["human_revocation"]}, {**body, "reason_code": ""}, {**body, "reason_code": " x"}):
            assert request("POST", path, candidate, browser)[:2] == invalid, candidate
        assert request("POST", path, None, browser, raw=b"")[:2] == invalid
        assert request("POST", path, None, browser, raw=b"[1]")[:2] == (400, {"error": "body must be a JSON object"})
        for malformed in (b"{", b'{"schema_version":"heel.runner-revoke.v1","reason_code":"a","reason_code":"b"}', b'{"x":NaN}', b"\xff"):
            assert request("POST", path, None, browser, raw=malformed)[:2] == (400, {"error": "invalid JSON body"}), malformed
        # Generic POST framing: one numeric Content-Length, no transfer coding, bounded size.
        head = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://heel.test\r\nX-Heel-Internal-Origin: same-origin\r\n"
                f"Cookie: {browser['Cookie']}\r\nContent-Type: application/json\r\n").encode()
        wire = canonical_bytes(body)
        assert raw_status(head + b"Content-Length: %d\r\nContent-Length: %d\r\n\r\n" % (len(wire), len(wire)) + wire) == 400
        assert raw_status(head + b"Transfer-Encoding: chunked\r\n\r\n%x\r\n" % len(wire) + wire + b"\r\n0\r\n\r\n") == 400
        assert raw_status(head + b"\r\n") == 400
        assert raw_status(head + b"Content-Length: %d\r\n\r\n" % (64 * 1024 + 1)) == 413
        assert request("POST", f"/v1/workspaces/{wid}/runners/runr_unknown/revoke", body, browser)[:2] == invalid
        assert runner_status() == "active" and audit() == []

        # An admin's recent browser session may revoke; the reason and actor are audited once.
        admin = cp.store.create_user("admin@example.test"); cp.store.add_member(wid, admin, Role.ADMIN)
        admin_browser = {**browser, "Cookie": f"heel_session={cp.auth.create_session(admin).token}"}
        assert request("POST", path, {**body, "reason_code": "device_lost"}, admin_browser)[:2] == (200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})
        assert runner_status() == "revoked" and audit() == [(admin, "device_lost")]
        identity = cp.runner_auth.identity(wid, runner_id)
        assert identity["state"] == "revoked" and identity["revocation"]["revoked_by"] == admin
        assert identity["revocation"]["reason_code"] == "device_lost"
        # Retries are refused without a second effect.
        assert request("POST", path, body, browser)[:2] == invalid
        assert request("POST", path, {**body, "reason_code": "device_lost"}, admin_browser)[:2] == invalid
        assert audit() == [(admin, "device_lost")]
    finally:
        server.shutdown(); server.server_close()


def test_http_v3_pairing_activation_replays_one_sealed_executable_cursor():
    cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                      enable_device_auth=True, public_origin="https://heel.test",
                      grant_authority=SigningAuthority.generate())
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
            "control_protocol", "activated_at_ms", "grant_authority",
        }
        assert first["schema_version"] == "heel.runner-pairing-activated.v4"
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



class _LiveHttpRun:
    """A real in-process control-plane HTTP server holding one approved, claimed canary run."""

    def __init__(self, directory):
        from canary_test_support import approval_projection
        from heel.saas.canary_runs import CanaryRunService

        self.cp = cp = ControlPlane(
            str(Path(directory) / "control.sqlite"), runner_auth_pepper=b"r" * 32,
            grant_authority=SigningAuthority.generate(),
        )
        self.server = serve(cp)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        org = cp.store.create_org("org")
        self.workspace = workspace = cp.store.create_workspace(org, "ws", "free", CATALOG_VERSION)
        self.private = private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        raw = base64.b64decode(public)
        self.key_id = key_id = ed25519_key_id(raw)
        cp.store.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", workspace, "runner", "active", time.time()))
        cp.store.conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (key_id, workspace, "runner", public, "active", time.time()))
        stamp, self.stamp_ms, digest = time.time(), int(time.time() * 1000), "a" * 64
        cp.store.conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (workspace, "prj", "project", "owner", stamp))
        cp.store.conn.execute("INSERT INTO users VALUES(?,?,?)", ("owner", "owner@example.test", stamp))
        cp.store.conn.execute("INSERT INTO memberships VALUES(?,?,?,?)", (workspace, "owner", "owner", stamp))
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
        self.signer = SigningAuthority.from_private_key(private, key_id)
        self.runs = runs = CanaryRunService(
            cp.store.conn, signing=cp.grant_authority, runner_auth=cp.runner_auth, initialize_schema=False,
        )
        approval = approval_projection(
            self.signer, workspace_id=workspace, project_ref="prj",
            environment_id="env", runner_id="runner", verification_digest=digest,
        )
        submitted = runs.submit_projection(approval, uploaded_by="owner")
        self.approval = approval
        self.grant = runs.approve(
            workspace, "prj", submitted["run_id"],
            projection_digest=approval["projection_digest"], actor="owner", role="owner",
            reason="Exercise the stop acknowledgement and result HTTP boundary",
            exact_hostname="canary.acme.dev", recent_auth_at_ms=self.stamp_ms,
            idempotency_key="ca1-" + "d" * 64, expected_kill_switch_generation=0,
        )["grant"]
        self.run_id = submitted["run_id"]
        self.chains = {
            name: dict(state) for name, state in runs.claim(workspace, "runner", key_id)["chain_states"].items()
        }

    def signed(self, operation, projection, *, nonce=None):
        """One request on the run's own nonce-sequenced chain, exactly as a runner signs it."""
        schema = {"heartbeat": "heel.runner-heartbeat-request.v1", "progress": "heel.runner-progress-request.v1", "stop-ack": "heel.runner-stop-ack-request.v1", "result": "heel.runner-result-request.v1"}[operation]
        capability = {"heartbeat": "runner_heartbeat", "progress": "runner_progress", "stop-ack": "runner_heartbeat", "result": "runner_result"}[operation]
        body = canonical_bytes({"schema_version": schema, "run_id": self.run_id, "operational_projection": projection})
        route = f"/v1/workspaces/{self.workspace}/runners/runner/runs/{self.run_id}/{operation}"
        chain = self.chains[operation]
        nonce = chain["next_nonce_b64"] if nonce is None else nonce
        timestamp = int(time.time() * 1000)
        proof = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": self.workspace, "runner_id": "runner", "key_id": self.key_id, "capability": capability, "method": "POST", "path": route, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp, "server_nonce": nonce, "sequence": chain["next_sequence"]}
        headers = {"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": self.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp), "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": str(chain["next_sequence"]), "X-Heel-Runner-Signature": base64.b64encode(self.private.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode()}
        return route, body, headers

    def send(self, route, body, headers):
        """POST exact bytes; returns status, raw response body and its runner response headers."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            conn.request("POST", route, body, headers)
            response = conn.getresponse()
            raw = response.read()
            runner_headers = {key: value for key, value in response.getheaders() if key.startswith("X-Heel-")}
        finally:
            conn.close()
        return response.status, raw, runner_headers

    def post(self, operation, projection, *, nonce=None):
        """One authenticated POST on the run's own nonce-sequenced chain, exactly as a runner signs it."""
        chain = self.chains[operation]
        status, raw, headers = self.send(*self.signed(operation, projection, nonce=nonce))
        next_nonce = headers.get("X-Heel-Runner-Next-Nonce")
        if next_nonce:
            chain["next_nonce_b64"], chain["next_sequence"] = next_nonce, chain["next_sequence"] + 1
        return status, json.loads(raw or b"null")

    def witness(self):
        return tuple(self.cp.store.conn.execute(
            "SELECT stop_ack_source_event_sequence,stop_ack_projection_digest,stop_ack_runner_local_at_ms "
            "FROM canary_runs WHERE run_id=?", (self.run_id,),
        ).fetchone())

    def finalized_digests(self):
        return [row[0] for row in self.cp.store.conn.execute(
            "SELECT payload_digest FROM canary_audit_records WHERE run_id=? AND action='finalized'",
            (self.run_id,),
        )]

    def cursors(self):
        return [tuple(row) for row in self.cp.store.conn.execute(
            "SELECT chain_name,next_sequence,generation FROM canary_runner_chain_cursors "
            "WHERE runner_id='runner' ORDER BY chain_name",
        )]

    def row(self):
        return self.cp.store.conn.execute(
            "SELECT status,execution_disposition,stop_reason,stop_acknowledged_at_ms,quota_state "
            "FROM canary_runs WHERE run_id=?", (self.run_id,),
        ).fetchone()

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.cp.close()


# The public envelope for the server's internal ``stop_conflict`` refusal.
_STATE_CONFLICT = {"schema_version": "heel.canary-error.v1", "code": "canary_state_conflict"}


def _stop_instants():
    """Runner-local signed (requested, acknowledged) instants on the shared projection timeline
    (claimed ``NOW_MS + 100``, started ``NOW_MS + 200``). Cloud receipt time decides lateness."""
    from canary_test_support import NOW_MS

    return NOW_MS + 300, NOW_MS + 400


def _stopped_terminal(live, *, acknowledged_at_ms, sequence=2):
    from canary_test_support import NOW_MS, operational_projection

    return operational_projection(
        live.signer, live.grant, sequence=sequence, phase="terminal", disposition="stopped",
        stop_reason="cloud_stop", stop_requested_at_ms=_stop_instants()[0],
        stop_acknowledged_at_ms=acknowledged_at_ms, updated_at_ms=NOW_MS + 1_000,
    )


def test_real_http_no_server_ack_null_terminal_remains_accepted():
    """Reject-before-accept: the stop acknowledgement never reached the Cloud. Over the real HTTP
    boundary an invented acknowledgement timestamp is refused, and the activated run's stopped
    terminal with a null acknowledgement is accepted once without any acknowledgement claim.
    (Formerly ``test_real_http_null_ack_stopped_terminal_after_an_ack_lost_before_the_cloud_accepted_it``;
    the scenario is unchanged.)"""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            live.runs.request_stop(
                live.workspace, "prj", live.run_id, actor="owner", reason="cloud_stop",
                expected_kill_switch_generation=0,
            )
            invented = _stopped_terminal(live, acknowledged_at_ms=_stop_instants()[1])
            status, payload = live.post("result", invented)
            assert (status, payload) == (409, _STATE_CONFLICT)
            assert live.row()["status"] == "stop_requested"
            status, payload = live.post("result", _stopped_terminal(live, acknowledged_at_ms=None))
            assert status == 200 and payload["status"] == "terminal"
            row = live.row()
            assert (row["status"], row["execution_disposition"], row["stop_reason"]) == ("terminal", "stopped", "cloud_stop")
            assert row["stop_acknowledged_at_ms"] is None  # never an acknowledgement claim
            assert row["quota_state"] == "refunded"  # zero requests started
            assert live.witness() == (None, None, None)
            assert live.finalized_digests() == [canonical_digest(_finalized_payload("none", (None, None, None), None))]
        finally:
            live.close()


def _finalized_payload(reconciliation, witness, server_acknowledged_at_ms, *, late=False):
    sequence, digest, local = witness
    return {
        "execution_disposition": "stopped", "ack_reconciliation": reconciliation,
        "stop_ack_source_event_sequence": sequence, "stop_ack_projection_digest": digest,
        "stop_ack_runner_local_at_ms": local,
        "server_acknowledged_at_ms": server_acknowledged_at_ms, "stop_ack_late": int(late),
    }


def _accepted_ack(live, *, times=None):
    """The Cloud accepts the signed acknowledgement; the caller decides whether its answer is lost."""
    from canary_test_support import operational_projection

    live.runs.request_stop(
        live.workspace, "prj", live.run_id, actor="owner", reason="cloud_stop",
        expected_kill_switch_generation=0,
    )
    if times is None:
        ack = operational_projection(
            live.signer, live.grant, sequence=1, phase="stop_requested", stop_reason="cloud_stop",
            stop_requested_at_ms=_stop_instants()[0], stop_acknowledged_at_ms=_stop_instants()[1],
            updated_at_ms=_stop_instants()[1],
        )
    else:
        ack = _live_projection(live, times, sequence=1, phase="stop_requested", acknowledged=times["acknowledged"])
    status, payload = live.post("stop-ack", ack)
    assert status == 200 and payload["accepted"] is True
    return ack


def test_real_http_matching_non_null_ack_terminal_remains_accepted():
    """The runner learned the accepted ACK: its terminal carries the same signed local ACK time
    and is accepted through the ordinary path, not through the NULL-ACK reconciliation."""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            ack = _accepted_ack(live)
            acknowledged = live.row()["stop_acknowledged_at_ms"]
            witness = (1, ack["projection_digest"], _stop_instants()[1])
            assert live.witness() == witness
            status, payload = live.post("result", _stopped_terminal(live, acknowledged_at_ms=_stop_instants()[1]))
            assert status == 200 and payload["status"] == "terminal"
            row = live.row()
            assert (row["status"], row["execution_disposition"], row["stop_acknowledged_at_ms"]) == ("terminal", "stopped", acknowledged)
            assert live.witness() == witness
            assert live.finalized_digests() == [canonical_digest(_finalized_payload("none", witness, acknowledged))]
        finally:
            live.close()


def test_real_http_accepted_ack_lost_response_null_terminal_reconciles():
    """Accepted-remote, lost-response (D): the Cloud accepted the acknowledgement but the runner
    never learned it, so the runner sends the null-ack stopped terminal. With the complete,
    write-once signed ACK witness the Cloud accepts that truthful terminal unchanged, keeps its
    own receipt time, and records ``cloud_recorded_client_unknown`` in the hashed terminal audit.
    (This was ``test_real_http_null_ack_stopped_terminal_is_refused_after_an_accepted_ack_whose_response_was_lost``,
    which recorded the former 409.)"""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            ack = _accepted_ack(live)  # this answer is what gets lost
            acknowledged = live.row()["stop_acknowledged_at_ms"]
            assert live.row()["status"] == "stop_requested" and acknowledged is not None
            witness = (1, ack["projection_digest"], _stop_instants()[1])
            assert live.witness() == witness
            terminal = _stopped_terminal(live, acknowledged_at_ms=None)
            status, payload = live.post("result", terminal)
            assert status == 200 and payload["status"] == "terminal"
            assert payload["stop_acknowledged_at_ms"] == acknowledged
            row = live.row()
            assert (row["status"], row["execution_disposition"], row["stop_reason"]) == ("terminal", "stopped", "cloud_stop")
            assert row["stop_acknowledged_at_ms"] == acknowledged  # Cloud receipt time, never rewritten
            assert row["quota_state"] == "refunded"
            assert live.witness() == witness
            receipt = live.cp.store.conn.execute(
                "SELECT receipt_digest,receipt_json FROM canary_operational_receipts WHERE run_id=?", (live.run_id,),
            ).fetchone()
            # The signed terminal is stored exactly as sent: its ACK stays NULL.
            assert receipt["receipt_digest"] == terminal["projection_digest"]
            assert receipt["receipt_json"] == canonical_bytes(terminal).decode()
            assert live.finalized_digests() == [canonical_digest(
                _finalized_payload("cloud_recorded_client_unknown", witness, acknowledged),
            )]
        finally:
            live.close()


class _LiveRunnerSigner(SecureSigner):
    def __init__(self, private):
        self.private = private
        self.public_key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload):
        return self.private.sign(payload)


class _LiveRunnerTransport:
    """Real loopback HTTP for a runner control client; it can drop one answer or one send."""

    def __init__(self, live):
        self.live, self.sent, self.answers = live, [], []
        self.lose_answers = 0
        self.refuse_sends = 0

    def post(self, path, *, headers=None, body=b""):
        self.sent.append((path, dict(headers or {}), body))
        if self.refuse_sends:
            self.refuse_sends -= 1
            raise ConnectionError("runner process stopped before the request left")
        answer = self.live.send(path, body, dict(headers or {}))
        self.answers.append(answer)
        if self.lose_answers:
            self.lose_answers -= 1
            raise ConnectionError("accepted result response was lost")
        status, raw, response_headers = answer
        return status, response_headers, (json.loads(raw) if raw else None)


class _RecordingResultVerifier:
    """Stand-in for the coordinator's Store anchor bridge; it authorizes only the exact pending call."""

    def __init__(self):
        self.calls = []

    def authorize_pending_result_replay(self, pending, *, now_ms):
        self.calls.append(("authorize", pending.call_id))
        return object()

    def consume(self, authority, *, pending, now_ms):
        self.calls.append(("consume", pending.call_id))


def _live_timeline():
    """Runner-local instants a few seconds in the past, so local terminal authority is valid now."""
    base = int(time.time() * 1000) - 5_000
    return {"claimed": base + 100, "started": base + 200, "requested": base + 300, "acknowledged": base + 400, "terminal": base + 1_000}


def _live_projection(live, times, *, sequence, phase, acknowledged):
    from canary_test_support import operational_projection
    from test_canary_lifecycle import resign_operational

    value = operational_projection(
        live.signer, live.grant, sequence=sequence, phase=phase, stop_reason="cloud_stop",
        disposition="stopped" if phase == "terminal" else None,
    )
    updated = times["terminal"] if phase == "terminal" else times["acknowledged"]
    value["timestamps"] = {
        "claimed_at_ms": times["claimed"], "started_at_ms": times["started"], "updated_at_ms": updated,
        "stop_requested_at_ms": times["requested"], "stop_acknowledged_at_ms": acknowledged,
        "terminal_at_ms": times["terminal"] if phase == "terminal" else None,
    }
    return resign_operational(value, live.signer)


def _live_runtime(live, root):
    signer = _LiveRunnerSigner(live.private)
    identity = RunnerIdentity(
        runner_id="runner", workspace_id=live.workspace, runner_version="test", adapter_versions={},
        public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=signer.key_id, pairing_phrase=(),
    )
    return RunnerRuntimeState(root / "runtime.sqlite3", identity, signer), signer


def _live_runner(live, root, transport, terminal, *, times):
    """Install the Cloud-issued run chains and authority in a durable runner runtime, then register
    the runner's local terminal: the state a runner holds right before it sends its result."""
    root.mkdir(mode=0o700, exist_ok=True)
    runtime, signer = _live_runtime(live, root)
    now = int(time.time() * 1000)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"p" * 32).decode(),
        next_sequence=1, generation=0, now_ms=now,
    )
    claim = runtime.load_chain("claim", None)
    path = f"/v1/workspaces/{live.workspace}/runners/runner/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": live.workspace,
        "runner_id": "runner", "key_id": signer.key_id, "capability": "runner_claim", "method": "POST",
        "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": now,
        "server_nonce": claim.next_nonce_b64, "sequence": claim.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": signer.key_id,
        "X-Heel-Runner-Timestamp-Ms": str(now),
        "X-Heel-Runner-Signature": base64.b64encode(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode("ascii"),
        "X-Heel-Runner-Nonce": claim.next_nonce_b64, "X-Heel-Runner-Sequence": str(claim.next_sequence),
    }
    pending = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path, capability="runner_claim",
        headers=headers, body=body, expected_state_digest=claim.state_digest, now_ms=now,
    )
    runtime.commit_call(
        pending.call_id, next_nonce_b64=base64.b64encode(b"n" * 32).decode(), now_ms=now,
        installed_chains=tuple(
            (operation, live.run_id, live.chains[operation]["next_nonce_b64"],
             live.chains[operation]["next_sequence"], live.chains[operation]["generation"])
            for operation in ("heartbeat", "progress", "result", "stop-ack")
        ),
        active_run=ActiveRunInstall(
            run_id=live.run_id, approval_projection=live.approval, grant=live.grant,
            gate={
                "active": True, "runner_state": "active", "proof_state": "valid",
                "proof_expires_at_ms": now + 3_600_000, "kill_switch_generation": 0,
                "stop_reason": "none", "server_time_ms": now,
            },
            claim_response_digest="a" * 64, gate_response_digest="b" * 64,
            claimed_at_ms=now, gate_received_at_ms=now,
        ),
    )
    control = _live_client(live, runtime, signer, transport)
    control._register_runtime_local_terminal({
        "run_id": live.run_id, "project_id": "prj", "grant_id": live.grant["grant_id"],
        "approval_projection_digest": live.approval["projection_digest"],
        "terminal_projection_digest": terminal["projection_digest"], "terminal_record_digest": "c" * 64,
        "terminal_at_ms": times["terminal"], "retention_expires_at_ms": times["terminal"] + 86_400_000,
    })
    return runtime, signer, control


def _live_client(live, runtime, signer, transport):
    return RunnerControlClient(
        origin="http://127.0.0.1", workspace_id=live.workspace, runner_id="runner", signer=signer,
        clock=lambda: int(time.time() * 1000), transport=transport,
        nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("run chains are Cloud-issued")),
        runtime=runtime,
    )


def _runtime_retired(runtime, run_id):
    return (
        runtime.load_pending_calls() == () and runtime.load_active_run_controls() == ()
        and all(runtime.load_chain(name, run_id) is None for name in ("heartbeat", "progress", "result", "stop-ack"))
        and runtime.load_terminal_state(run_id).state == "available"
    )


def test_d_reconciliation_keeps_expired_revoked_and_wrong_nonce_result_rejected_with_pending_evidence(tmp_path):
    """Authentication and the exact receipt ledger run before reconciliation. A wrong nonce, a revoked
    key and an expired replay receipt are refused; the Cloud witness and the runner's staged result
    stay intact, and none of these rejections becomes reconciliation authority."""
    from heel.runner.control_client import RunnerChainRecoveryRequired

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            ack = _accepted_ack(live, times=times)
            witness = (1, ack["projection_digest"], times["acknowledged"])
            before = (tuple(live.row()), live.witness(), live.cursors())
            terminal = _live_projection(live, times, sequence=2, phase="terminal", acknowledged=None)
            status, payload = live.post("result", terminal, nonce=base64.b64encode(b"w" * 32).decode())
            assert status == 401 and payload["code"] == "invalid_runner_auth"
            assert (tuple(live.row()), live.witness(), live.cursors()) == before
            transport = _LiveRunnerTransport(live)
            runtime, _, control = _live_runner(live, tmp_path / "revoked", transport, terminal, times=times)
            live.cp.store.conn.execute(
                "UPDATE canary_runner_keys SET status='revoked',revoked_at=? WHERE key_id=?",
                (time.time(), live.key_id),
            )
            live.cp.store.conn.commit()
            with pytest.raises(RunnerChainRecoveryRequired):
                control.result(run_id=live.run_id, operational_projection=terminal)
            assert transport.answers[-1][0] == 401
            assert (tuple(live.row()), live.witness(), live.cursors()) == before
            assert live.witness() == witness
            (pending,) = runtime.load_pending_calls()  # the exact staged result remains as evidence
            assert (pending.request_operation, pending.body) == ("result", transport.sent[-1][2])
            assert runtime.load_terminal_state(live.run_id).state == "local_terminal"
        finally:
            live.close()

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            _accepted_ack(live, times=times)
            terminal = _live_projection(live, times, sequence=2, phase="terminal", acknowledged=None)
            transport = _LiveRunnerTransport(live)
            runtime, _, control = _live_runner(live, tmp_path / "expired", transport, terminal, times=times)
            transport.lose_answers = 1
            with pytest.raises(ConnectionError):
                control.result(run_id=live.run_id, operational_projection=terminal)
            assert transport.answers[0][0] == 200 and live.row()["status"] == "terminal"
            settled = (tuple(live.row()), live.witness(), live.cursors())
            live.cp.store.conn.execute(
                "UPDATE canary_runner_request_ledger SET retention_expires_at=created_at WHERE chain_name=?",
                (f"result:{live.run_id}",),
            )
            live.cp.store.conn.commit()
            (pending,) = runtime.load_pending_calls()
            with pytest.raises(RunnerChainRecoveryRequired):
                control.replay_pending_call(
                    pending, now_ms=int(time.time() * 1000), result_verifier=_RecordingResultVerifier(),
                )
            assert transport.sent[1] == transport.sent[0] and transport.answers[1][0] == 401
            assert (tuple(live.row()), live.witness(), live.cursors()) == settled
            assert runtime.load_pending_calls() == (pending,)
            assert runtime.load_terminal_state(live.run_id).state == "local_terminal"
        finally:
            live.close()


def test_d_result_response_loss_replays_exactly_then_normal_result_commit_retires_runtime(tmp_path):
    """The reconciled D result's own answer is lost: the runner replays its exact sealed request, the
    Cloud returns the exact retained answer, and the ordinary terminal commit retires the run."""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            _accepted_ack(live, times=times)
            terminal = _live_projection(live, times, sequence=2, phase="terminal", acknowledged=None)
            transport = _LiveRunnerTransport(live)
            runtime, _, control = _live_runner(live, tmp_path / "runner", transport, terminal, times=times)
            transport.lose_answers = 1
            with pytest.raises(ConnectionError):
                control.result(run_id=live.run_id, operational_projection=terminal)
            first_status, first_raw, _ = transport.answers[0]
            assert first_status == 200 and json.loads(first_raw)["status"] == "terminal"
            settled = (tuple(live.row()), live.witness(), live.cursors(), live.finalized_digests())
            (pending,) = runtime.load_pending_calls()
            assert pending.body == transport.sent[0][2] and runtime.load_active_run_controls() != ()
            verifier = _RecordingResultVerifier()
            outcome = control.replay_pending_call(pending, now_ms=int(time.time() * 1000), result_verifier=verifier)
            assert transport.sent[1] == transport.sent[0]  # exact sealed bytes and headers
            # The exact retained answer: status, body bytes and next nonce (request IDs are per request).
            assert transport.answers[1][:2] == transport.answers[0][:2]
            assert transport.answers[1][2]["X-Heel-Runner-Next-Nonce"] == transport.answers[0][2]["X-Heel-Runner-Next-Nonce"]
            assert outcome.status == 200 and outcome.body["status"] == "terminal"
            assert verifier.calls == [("authorize", pending.call_id), ("consume", pending.call_id)]
            assert (tuple(live.row()), live.witness(), live.cursors(), live.finalized_digests()) == settled
            assert _runtime_retired(runtime, live.run_id)
        finally:
            live.close()


def test_d_restart_drains_already_staged_result_without_new_cursor_or_pending_deletion(tmp_path):
    """The D result was staged but the process stopped before sending it. A fresh client on the same
    durable runtime refuses new control work, drains the exact staged result first, and the Cloud
    reconciles it on its existing result chain; no cursor is added and nothing staged is dropped."""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            ack = _accepted_ack(live, times=times)
            terminal = _live_projection(live, times, sequence=2, phase="terminal", acknowledged=None)
            transport = _LiveRunnerTransport(live)
            runtime, signer, control = _live_runner(live, tmp_path / "runner", transport, terminal, times=times)
            transport.refuse_sends = 1
            with pytest.raises(ConnectionError):
                control.result(run_id=live.run_id, operational_projection=terminal)
            assert transport.answers == [] and live.row()["status"] == "stop_requested"
            cursors = live.cursors()
            (pending,) = runtime.load_pending_calls()

            restarted = RunnerRuntimeState(runtime.path, runtime.identity, signer)
            fresh_transport = _LiveRunnerTransport(live)
            fresh = _live_client(live, restarted, signer, fresh_transport)
            with pytest.raises(ValueError, match="pending replay is required"):
                fresh.result(run_id=live.run_id, operational_projection=terminal)
            assert fresh_transport.sent == [] and restarted.load_pending_calls() == (pending,)
            outcomes = fresh.replay_all_pending(now_ms=int(time.time() * 1000), result_verifier=_RecordingResultVerifier())
            assert [(item.request_operation, item.status) for item in outcomes] == [("result", 200)]
            assert fresh_transport.sent == [(pending.path, dict(pending.headers), pending.body)]
            row = live.row()
            assert (row["status"], row["execution_disposition"]) == ("terminal", "stopped")
            assert live.witness() == (1, ack["projection_digest"], times["acknowledged"])
            result_chain = f"result:{live.run_id}"
            assert [name for name, *_ in live.cursors()] == [name for name, *_ in cursors]
            assert [item for item in live.cursors() if item[0] != result_chain] == [item for item in cursors if item[0] != result_chain]
            (before_result,) = [item for item in cursors if item[0] == result_chain]
            (after_result,) = [item for item in live.cursors() if item[0] == result_chain]
            assert after_result == (result_chain, before_result[1] + 1, before_result[2])
            assert _runtime_retired(restarted, live.run_id)
        finally:
            live.close()

# --- T2b-1: grant-authority bootstrap in the v4 activation response -------------------------

V3_ACTIVATED_FIELDS = {
    "schema_version", "workspace_id", "runner_id", "runner_key_id", "pairing_exchange_digest",
    "initial_claim_nonce", "initial_claim_sequence", "initial_claim_generation", "capabilities",
    "control_protocol", "activated_at_ms",
}


class _PairingCeremony:
    """A real loopback control plane driven over HTTP: owner invite, runner exchange, owner approve.

    No row is seeded; the runner side is a locally held Ed25519 key. ``grant_authority`` is passed to
    ``ControlPlane`` exactly as production configuration does (``server.py``).
    """

    def __init__(self, grant_authority):
        self.cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                               enable_device_auth=True, public_origin="https://heel.test",
                               grant_authority=grant_authority)
        self.server = serve(self.cp)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.cp.close()

    def request(self, method, path, body=None, headers=None, *, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        payload = raw if raw is not None else (
            json.dumps(body, separators=(",", ":")).encode() if method == "POST" else None
        )
        request_headers = ({"Content-Type": "application/json", **(headers or {})}
                           if method == "POST" else (headers or {}))
        conn.request(method, path, payload, request_headers)
        response = conn.getresponse(); data = response.read(); cookie = response.getheader("Set-Cookie"); conn.close()
        return response.status, data, cookie

    def owner(self, email):
        status, data, cookie = self.request("POST", "/v1/signup", {"email": email, "password": "correct-horse-battery"})
        assert status == 201, data
        browser = {"Cookie": cookie.split(";", 1)[0], "Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"}
        return json.loads(data)["workspace_id"], browser

    def invite(self, workspace_id, browser):
        status, data, _ = self.request("POST", f"/v1/workspaces/{workspace_id}/runner-pairings",
                                       {"schema_version": "heel.runner-pairing-invite.v1"}, browser)
        assert status == 201, data
        return json.loads(data)["invitation_token"]

    def approve(self, workspace_id, browser, pairing_id, phrase, fingerprint):
        status, data, _ = self.request(
            "POST", f"/v1/workspaces/{workspace_id}/runner-pairings/{pairing_id}/approve",
            {"schema_version": "heel.runner-pairing-approve.v1", "pairing_phrase": phrase, "fingerprint": fingerprint},
            browser,
        )
        assert status == 200, data

    def approved_pairing(self, email):
        workspace_id, browser = self.owner(email)
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        phrase = " ".join(runner_phrase_words()[:6])
        exchange = {
            "schema_version": "heel.runner-pairing-exchange.v3", "invitation_token": self.invite(workspace_id, browser),
            "public_key_b64": public, "pairing_phrase": phrase, "display_name": "Runner V4",
            "runner_version": "v4", "adapters": {}, "control_protocol": "heel.runner-control.v2",
        }
        status, data, _ = self.request("POST", "/v1/runner-pairings/exchange", exchange)
        assert status == 201, data
        pending = json.loads(data)
        self.approve(workspace_id, browser, pending["pairing_id"], phrase, pending["fingerprint"])
        client_nonce = base64.b64encode(secrets_bytes(32)).decode()
        core = {
            "pairing_id": pending["pairing_id"], "activation_challenge": pending["activation_challenge"],
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "client_activation_nonce_b64": client_nonce, "control_protocol": "heel.runner-control.v2",
        }
        activation = {
            "schema_version": "heel.runner-pairing-activate.v3", "client_activation_nonce_b64": client_nonce,
            "signature_b64": base64.b64encode(private.sign(b"heel.runner-pairing-activate.v3\0" + canonical_bytes(core))).decode(),
        }
        return {"workspace_id": workspace_id, "pending": pending, "activation": activation,
                "route": f"/v1/runner-pairings/{pending['pairing_id']}/activate"}

    def state(self, pairing):
        conn = self.cp.store.conn
        return {
            "pairing": tuple(conn.execute("SELECT status FROM canary_runner_pairings WHERE pairing_id=?",
                                          (pairing["pending"]["pairing_id"],)).fetchone()),
            "runners": [tuple(row) for row in conn.execute(
                "SELECT runner_id,status FROM canary_runners WHERE workspace_id=?", (pairing["workspace_id"],))],
            "keys": conn.execute("SELECT COUNT(*) FROM canary_runner_keys WHERE workspace_id=?",
                                 (pairing["workspace_id"],)).fetchone()[0],
            "receipt": self.receipt(pairing),
        }

    def receipt(self, pairing):
        row = self.cp.store.conn.execute(
            "SELECT response_ciphertext FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
            (pairing["pending"]["pairing_id"],),
        ).fetchone()
        return None if row is None else row[0]

    def seal_receipt(self, pairing, response):
        """Write a receipt exactly as the server seals one (to model a receipt stored by an older server)."""
        pairing_id = pairing["pending"]["pairing_id"]
        try:
            text = canonical_bytes(response).decode()
        except ValueError:  # a tampered value the canonical encoder itself refuses (e.g. null)
            text = json.dumps(response, separators=(",", ":"), sort_keys=True)
        sealed = self.cp.runner_auth._seal(text, aad=f"pairing-v3-activation\0{pairing_id}".encode())
        self.cp.store.conn.execute(
            "UPDATE canary_runner_pairing_activation_receipts SET response_ciphertext=? WHERE pairing_id=?",
            (sealed, pairing_id),
        )
        self.cp.store.conn.commit()
        return sealed


def secrets_bytes(count):
    import secrets  # noqa: PLC0415 - local to keep the module import list unchanged.
    return secrets.token_bytes(count)


def test_v4_activation_response_carries_the_grant_authority_and_replays_byte_identically():
    from heel.crypto import load_public_key_base64, verify_envelope  # noqa: PLC0415
    from heel.saas.runner_contexts import CONTEXT_DOMAIN  # noqa: PLC0415
    cloud = SigningAuthority.generate()
    ceremony = _PairingCeremony(cloud)
    try:
        pairing = ceremony.approved_pairing("v4-runner@example.test")
        # Request injection: the runner cannot choose the authority it will trust.
        attacker = SigningAuthority.generate()
        injected = {**pairing["activation"], "grant_authority": {
            "key_id": attacker.key_id, "public_key_b64": attacker.canonical_public_key}}
        before = ceremony.state(pairing)
        status, data, _ = ceremony.request("POST", pairing["route"], injected)
        assert status == 400 and json.loads(data)["code"] == "invalid_runner_pairing"
        assert ceremony.state(pairing) == before and before["pairing"] == ("approved",) and before["receipt"] is None

        status, first_raw, _ = ceremony.request("POST", pairing["route"], pairing["activation"])
        assert status == 200
        first = json.loads(first_raw)
        assert set(first) == V3_ACTIVATED_FIELDS | {"grant_authority"}
        assert first["schema_version"] == "heel.runner-pairing-activated.v4"
        assert first["control_protocol"] == "heel.runner-control.v2"
        # The key is the control plane's own configured grant authority, nothing else.
        assert ceremony.cp.grant_authority is cloud
        assert first["grant_authority"] == {"key_id": cloud.key_id, "public_key_b64": cloud.canonical_public_key}
        assert ed25519_key_id(base64.b64decode(first["grant_authority"]["public_key_b64"])) == first["grant_authority"]["key_id"]
        assert first_raw == canonical_bytes(first)
        # The delivered key verifies what the control plane's binding service signs, and only that.
        trusted = {first["grant_authority"]["key_id"]: load_public_key_base64(first["grant_authority"]["public_key_b64"])}
        payload = CONTEXT_DOMAIN + canonical_bytes({"binding": "probe"})
        verify_envelope(trusted, ceremony.cp.runner_contexts.signing.sign(payload), payload)
        with pytest.raises(ValueError):
            verify_envelope(trusted, attacker.sign(payload), payload)

        receipt = ceremony.receipt(pairing)
        results, errors = [], []

        def replay():
            try:
                results.append(ceremony.request("POST", pairing["route"], pairing["activation"])[:2])
            except BaseException as error:  # surfaced below
                errors.append(error)

        threads = [threading.Thread(target=replay) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        assert errors == [] and len(results) == 8
        assert all(item == (200, first_raw) for item in results)
        # A key change on the control plane never re-keys a stored receipt: it replays as stored.
        ceremony.cp.grant_authority = SigningAuthority.generate()
        assert ceremony.request("POST", pairing["route"], pairing["activation"])[:2] == (200, first_raw)
        assert ceremony.request("POST", pairing["route"], injected)[0] == 400
        after = ceremony.state(pairing)
        assert after["receipt"] == receipt
        assert after["runners"] == [(pairing["pending"]["runner_id"], "active")] and after["keys"] == 1
    finally:
        ceremony.close()


def test_v4_activation_without_or_with_an_inconsistent_grant_authority_fails_before_state_changes():
    from types import SimpleNamespace  # noqa: PLC0415
    ceremony = _PairingCeremony(None)
    try:
        pairing = ceremony.approved_pairing("v4-absent@example.test")
        before = ceremony.state(pairing)
        status, data, _ = ceremony.request("POST", pairing["route"], pairing["activation"])
        assert status == 400 and json.loads(data)["code"] == "invalid_runner_pairing"
        assert ceremony.state(pairing) == before
        assert before == {"pairing": ("approved",), "runners": [], "keys": 0, "receipt": None}
        good, other = SigningAuthority.generate(), SigningAuthority.generate()
        inconsistent = [
            SimpleNamespace(public_key=good.public_key, public_key_bytes=good.public_key_bytes, key_id=other.key_id),
            SimpleNamespace(public_key=other.public_key, public_key_bytes=good.public_key_bytes, key_id=good.key_id),
            SimpleNamespace(public_key=good.public_key, public_key_bytes=good.public_key_bytes[:31], key_id=good.key_id),
            SimpleNamespace(public_key=good.public_key, public_key_bytes=bytearray(good.public_key_bytes), key_id=good.key_id),
            SimpleNamespace(public_key_bytes=good.public_key_bytes, key_id=good.key_id),
            {"key_id": good.key_id, "public_key_b64": good.canonical_public_key},
        ]
        for authority in inconsistent:
            with pytest.raises(RunnerAuthError):
                ceremony.cp.runner_auth.activate_executable(
                    pairing["pending"]["pairing_id"], pairing["activation"], grant_authority=authority,
                )
            assert ceremony.state(pairing) == before
        # The same approved pairing then activates once the control plane holds its authority.
        ceremony.cp.grant_authority = good
        status, data, _ = ceremony.request("POST", pairing["route"], pairing["activation"])
        assert status == 200
        assert json.loads(data)["grant_authority"] == {"key_id": good.key_id, "public_key_b64": good.canonical_public_key}
    finally:
        ceremony.close()


def test_stored_v3_and_v4_activation_receipts_replay_exactly_and_tampered_receipts_fail_closed():
    cloud = SigningAuthority.generate()
    ceremony = _PairingCeremony(cloud)
    try:
        pairing = ceremony.approved_pairing("v4-receipts@example.test")
        status, v4_raw, _ = ceremony.request("POST", pairing["route"], pairing["activation"])
        assert status == 200
        v4 = json.loads(v4_raw)
        # A receipt stored by the pre-v4 server: the identical response without the authority.
        v3 = {key: value for key, value in v4.items() if key != "grant_authority"}
        v3["schema_version"] = "heel.runner-pairing-activated.v3"
        sealed_v3 = ceremony.seal_receipt(pairing, v3)
        assert ceremony.request("POST", pairing["route"], pairing["activation"])[:2] == (200, canonical_bytes(v3))
        assert ceremony.receipt(pairing) == sealed_v3  # replay never rewrites or upgrades it
        other = SigningAuthority.generate()
        flipped = bytearray(base64.b64decode(cloud.canonical_public_key)); flipped[0] ^= 1
        noncanonical = cloud.canonical_public_key[:-2] + chr(ord(cloud.canonical_public_key[-2]) + 1) + "="
        tampered = [
            {**v4, "extra": True},
            {key: value for key, value in v4.items() if key != "grant_authority"},
            {**v3, "grant_authority": v4["grant_authority"]},
            {**v4, "schema_version": "heel.runner-pairing-activated.v5"},
            {**v4, "grant_authority": {**v4["grant_authority"], "extra": "x"}},
            {**v4, "grant_authority": {"key_id": other.key_id, "public_key_b64": cloud.canonical_public_key}},
            {**v4, "grant_authority": {"key_id": cloud.key_id, "public_key_b64": base64.b64encode(bytes(flipped)).decode()}},
            {**v4, "grant_authority": {"key_id": cloud.key_id, "public_key_b64": base64.b64encode(cloud.public_key_bytes[:31]).decode()}},
            {**v4, "grant_authority": {"key_id": cloud.key_id, "public_key_b64": noncanonical}},
            {**v4, "grant_authority": {"key_id": 1, "public_key_b64": cloud.canonical_public_key}},
            {**v4, "grant_authority": {"key_id": "k_\u00e9" + cloud.key_id[3:], "public_key_b64": cloud.canonical_public_key}},
            {**v4, "grant_authority": {"key_id": cloud.key_id, "public_key_b64": cloud.canonical_public_key[:-1] + "\u00e9"}},
            {**v4, "grant_authority": [cloud.key_id, cloud.canonical_public_key]},
            {**v4, "grant_authority": None},
        ]
        for response in tampered:
            sealed = ceremony.seal_receipt(pairing, response)
            status, data, _ = ceremony.request("POST", pairing["route"], pairing["activation"])
            assert status == 400 and json.loads(data)["code"] == "invalid_runner_pairing", response
            assert ceremony.receipt(pairing) == sealed
        # The original v4 receipt still replays byte for byte.
        ceremony.seal_receipt(pairing, v4)
        assert ceremony.request("POST", pairing["route"], pairing["activation"])[:2] == (200, v4_raw)
    finally:
        ceremony.close()


class _RecordingSecretBackend:
    """Test-only in-memory secret backend, injected through ``RunnerDaemon(secret_backend=...)``."""

    def __init__(self):
        self.values: dict[str, bytes] = {}

    def load(self, label):
        value = self.values.get(label)
        return None if value is None else bytes(value)

    def store(self, label, seed):
        if label in self.values:
            raise ValueError("runner signing identity already exists")
        self.values[label] = bytes(seed)

    def delete(self, label):
        self.values.pop(label, None)


class _LoopbackControlTransport:
    """Plain-HTTP stand-in for ``HTTPSControlTransport.post`` against the loopback control plane."""

    def __init__(self, ceremony):
        self.ceremony = ceremony

    def post(self, path, *, headers=None, body=b""):
        status, data, _ = self.ceremony.request("POST", path, headers=headers, raw=body)
        return status, {}, (json.loads(data) if data else None)


def _released_v3_activation_response(cls, value, *, material, pending):
    """The closed-set gate of ``RunnerStore._activation_response`` as shipped in heel_sim 1.2.0
    (b426fc2, ``store.py:1162-1170``): exactly the v3 field set and schema. The real 1.2.0 wheel
    against the new server is recorded separately in the T2b1 acceptance artifacts."""
    from heel.runner.store import RunnerStoreError  # noqa: PLC0415
    if not isinstance(value, dict) or set(value) != V3_ACTIVATED_FIELDS:
        raise RunnerStoreError("invalid executable pairing activation response")
    if value["schema_version"] != "heel.runner-pairing-activated.v3":
        raise RunnerStoreError("invalid executable pairing activation response")
    raise AssertionError("this model only gates; a v3 response is out of scope here")  # pragma: no cover


def _pair_daemon_over_loopback(ceremony, tmp_path, email, monkeypatch):
    from heel.runner.daemon import RunnerDaemon  # noqa: PLC0415

    class LoopbackDaemon(RunnerDaemon):
        def _transport(self, origin):
            return _LoopbackControlTransport(ceremony)

    workspace_id, browser = ceremony.owner(email)
    token = ceremony.invite(workspace_id, browser)
    home = tmp_path / email.split("@", 1)[0]
    home.mkdir(mode=0o700)
    backend = _RecordingSecretBackend()
    daemon = LoopbackDaemon(home, secret_backend=backend, poll_interval_seconds=0.05)
    outcome = {}
    pending = threading.Event()

    def emit(event):
        if event["event"] == "pairing_pending":
            outcome["pending"] = event
            pending.set()

    def run():
        try:
            outcome["result"] = daemon.pair("https://heel.test", token, emit=emit)
        except BaseException as error:  # inspected by the test
            outcome["error"] = error
            pending.set()

    thread = threading.Thread(target=run, daemon=True); thread.start()
    assert pending.wait(30)
    assert "error" not in outcome, outcome
    event = outcome["pending"]
    ceremony.approve(workspace_id, browser, event["pairing_id"], event["pairing_phrase"], event["fingerprint"])
    thread.join(30)
    assert not thread.is_alive()
    return daemon, backend, outcome


def test_old_and_new_activation_peers_fail_closed_with_response_rejected(tmp_path, monkeypatch):
    from heel.runner.daemon import RunnerPairingError  # noqa: PLC0415
    from heel.runner.store import RunnerStore  # noqa: PLC0415
    cloud = SigningAuthority.generate()

    # New runner (v4 only) against an old server, which answered the same state with v3.
    ceremony = _PairingCeremony(cloud)
    original = RunnerAuthStore.activate_executable

    def old_server(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        old = {key: value for key, value in response.items() if key != "grant_authority"}
        old["schema_version"] = "heel.runner-pairing-activated.v3"
        return old

    try:
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", old_server)
        daemon, backend, outcome = _pair_daemon_over_loopback(ceremony, tmp_path, "new-runner@example.test", monkeypatch)
        assert isinstance(outcome.get("error"), RunnerPairingError), outcome
        assert outcome["error"].code == "response_rejected"
        status = daemon.status()
        assert status["state"] == "pairing_incomplete" and status["next_steps"][0] == "heel runner unpair"
        assert daemon.unpair()["removed"] is True and backend.values == {}
        assert daemon.status() == {"state": "unpaired"}
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", original)

        # Old runner (1.2.0 strict v3 set) against the new server, which answers v4.
        monkeypatch.setattr(RunnerStore, "_activation_response", classmethod(_released_v3_activation_response))
        daemon, backend, outcome = _pair_daemon_over_loopback(ceremony, tmp_path, "old-runner@example.test", monkeypatch)
        assert isinstance(outcome.get("error"), RunnerPairingError), outcome
        assert outcome["error"].code == "response_rejected"
        assert daemon.status()["state"] == "pairing_incomplete"
        assert daemon.unpair()["removed"] is True and backend.values == {}
        monkeypatch.undo()

        # New runner against a server whose v4 authority was tampered in transit or at rest.
        attacker = SigningAuthority.generate()

        def tampering_server(self, *args, **kwargs):
            response = original(self, *args, **kwargs)
            return {**response, "grant_authority": {
                "key_id": response["grant_authority"]["key_id"], "public_key_b64": attacker.canonical_public_key}}

        monkeypatch.setattr(RunnerAuthStore, "activate_executable", tampering_server)
        daemon, backend, outcome = _pair_daemon_over_loopback(ceremony, tmp_path, "tampered@example.test", monkeypatch)
        assert isinstance(outcome.get("error"), RunnerPairingError), outcome
        assert outcome["error"].code == "response_rejected"
        assert daemon.status()["state"] == "pairing_incomplete"
        assert daemon.unpair()["removed"] is True and backend.values == {}
    finally:
        ceremony.close()


class _FilePairingCeremony(_PairingCeremony):
    """``_PairingCeremony`` on a file database, so runner requests own a short independent connection."""

    UNTOUCHED = {"pairing": "approved", "runners": 0, "keys": 0, "receipts": 0, "activated_audits": 0}
    ACTIVATED_ONCE = {"pairing": "activated", "runners": 1, "keys": 1, "receipts": 1, "activated_audits": 1}
    BUSY = {"schema_version": "heel.runner-error.v1", "code": "runner_control_busy", "retry_after_ms": 1000}

    def __init__(self, grant_authority, journal_mode="delete"):
        self._directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self._directory.name) / "control.sqlite")
        self.cp = ControlPlane(self.database, device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                               enable_device_auth=True, public_origin="https://heel.test",
                               grant_authority=grant_authority)
        assert self.cp.runner_connections_are_shared is False
        if journal_mode == "wal":  # before any request, as server.py configures production
            self.cp.store.conn.execute("PRAGMA journal_mode=WAL")
            self.cp.store.conn.execute("PRAGMA synchronous=FULL")
        check = sqlite3.connect(self.database)
        try:
            assert check.execute("PRAGMA journal_mode").fetchone()[0] == journal_mode
        finally:
            check.close()
        self.server = serve(self.cp)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        try:
            super().close()
        finally:
            self._directory.cleanup()

    def fresh_state(self, pairing):
        """Rows for this pairing and its runner, read on a new connection to the database file."""
        conn = sqlite3.connect(self.database)
        try:
            pairing_id, runner_id = pairing["pending"]["pairing_id"], pairing["pending"]["runner_id"]
            count = lambda sql, value: conn.execute(sql, (value,)).fetchone()[0]  # noqa: E731
            return {
                "pairing": conn.execute("SELECT status FROM canary_runner_pairings WHERE pairing_id=?",
                                        (pairing_id,)).fetchone()[0],
                "runners": count("SELECT COUNT(*) FROM canary_runners WHERE runner_id=? AND status='active'", runner_id),
                "keys": count("SELECT COUNT(*) FROM canary_runner_keys WHERE runner_id=?", runner_id),
                "receipts": count("SELECT COUNT(*) FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
                                  pairing_id),
                "activated_audits": count("SELECT COUNT(*) FROM canary_runner_audit_records WHERE runner_id=? "
                                          "AND action='runner_activated'", runner_id),
            }
        finally:
            conn.close()

    def assert_busy_then_activates_once(self, pairing, raw, answer, caplog):
        """The held request answered the named 503; afterwards the same bytes activate once and replay."""
        status, headers, body = answer
        assert status == 503, body
        assert json.loads(body) == self.BUSY
        assert [value for name, value in headers if name.lower() == "retry-after"] == ["1"]
        assert "control_plane_internal_error" not in caplog.text
        assert self.fresh_state(pairing) == self.UNTOUCHED
        status, _, first = _raw_post(self, pairing["route"], raw)
        assert status == 200 and json.loads(first)["schema_version"] == "heel.runner-pairing-activated.v4"
        assert _raw_post(self, pairing["route"], raw)[::2] == (200, first)
        assert self.fresh_state(pairing) == self.ACTIVATED_ONCE


def _raw_post(ceremony, path, raw):
    """POST exact bytes; return the status, every response header and the body bytes."""
    conn = http.client.HTTPConnection("127.0.0.1", ceremony.server.server_address[1], timeout=10)
    try:
        conn.request("POST", path, raw, {"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        conn.close()



@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_v3_activation_busy_at_begin_answers_503_then_the_same_bytes_activate_once(caplog, journal_mode):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    ceremony = _FilePairingCeremony(SigningAuthority.generate(), journal_mode)
    try:
        pairing = ceremony.approved_pairing("busy-begin@example.test")
        raw = canonical_bytes(pairing["activation"])
        human = ceremony.cp.store.conn
        human.execute("BEGIN IMMEDIATE")
        try:
            human.execute("UPDATE workspaces SET name=name WHERE workspace_id=?", (pairing["workspace_id"],))
            answer = _raw_post(ceremony, pairing["route"], raw)
        finally:
            human.rollback()
        ceremony.assert_busy_then_activates_once(pairing, raw, answer, caplog)
    finally:
        ceremony.close()


def test_v3_activation_busy_at_commit_answers_503_then_the_same_bytes_activate_once(caplog):
    """Rollback journal only: a WAL reader never blocks the activation's commit."""
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("busy-commit@example.test")
        ceremony.owner("busy-commit-other@example.test")  # two rows, so one fetch leaves the read open
        raw = canonical_bytes(pairing["activation"])
        with ceremony.cp.request_lock:
            cursor = ceremony.cp.store.conn.execute("SELECT * FROM workspaces")
            try:
                assert cursor.fetchone() is not None
                answer = _raw_post(ceremony, pairing["route"], raw)
            finally:
                cursor.close()
        ceremony.assert_busy_then_activates_once(pairing, raw, answer, caplog)
    finally:
        ceremony.close()


@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_busy_on_exchange_route_stays_500_with_a_numeric_code_only(caplog, journal_mode):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    ceremony = _FilePairingCeremony(SigningAuthority.generate(), journal_mode)
    try:
        workspace_id, browser = ceremony.owner("busy-exchange@example.test")
        private = Ed25519PrivateKey.generate()
        exchange = {
            "schema_version": "heel.runner-pairing-exchange.v3", "invitation_token": ceremony.invite(workspace_id, browser),
            "public_key_b64": base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
            "pairing_phrase": " ".join(runner_phrase_words()[:6]), "display_name": "Runner F3",
            "runner_version": "v4", "adapters": {}, "control_protocol": "heel.runner-control.v2",
        }
        human = ceremony.cp.store.conn
        human.execute("BEGIN IMMEDIATE")
        try:
            human.execute("UPDATE workspaces SET name=name WHERE workspace_id=?", (workspace_id,))
            status, headers, body = _raw_post(ceremony, "/v1/runner-pairings/exchange", canonical_bytes(exchange))
        finally:
            human.rollback()
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        assert [value for name, value in headers if name.lower() == "retry-after"] == []
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        assert set(records[0]) == {"event", "exception_type", "method", "request_id", "sqlite_primary_code"}
        assert records[0]["sqlite_primary_code"] == 5 and records[0]["exception_type"] == "OperationalError"
        assert records[0]["method"] == "POST"
    finally:
        ceremony.close()


def test_legacy_v1_activation_busy_stays_500(caplog, monkeypatch):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def busy(self, *args, **kwargs):
        error = sqlite3.OperationalError(canary)
        error.sqlite_errorcode = 5
        raise error

    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("busy-legacy@example.test")
        monkeypatch.setattr(RunnerAuthStore, "activate", busy)
        legacy = {"schema_version": "heel.runner-pairing-activate.v1", "signature_b64": "A" * 88}
        status, headers, body = _raw_post(ceremony, pairing["route"], canonical_bytes(legacy))
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        assert set(records[0]) == {"event", "exception_type", "method", "request_id", "sqlite_primary_code"}
        assert records[0]["sqlite_primary_code"] == 5 and records[0]["exception_type"] == "OperationalError"
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
        assert ceremony.fresh_state(pairing) == ceremony.UNTOUCHED
    finally:
        ceremony.close()


@pytest.mark.parametrize(("code", "expected"), [
    (..., None), (None, None), ("5", None), (5.0, None), (True, None), (-1, None), (0, None),
    (5 | (1 << 40), None), (0x10000, None), (1, 1), (11, 11), (0xFFFF, 255),
], ids=["absent", "none", "str", "float", "bool", "negative", "zero", "huge", "oversized", "error", "corrupt", "max"])
def test_non_busy_and_hostile_sqlite_errors_stay_500_without_leaking(caplog, monkeypatch, code, expected):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def failing(self, *args, **kwargs):
        error = sqlite3.OperationalError(canary)
        if code is not ...:
            error.sqlite_errorcode = code
        raise error

    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("busy-hostile@example.test")
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", failing)
        status, headers, body = _raw_post(ceremony, pairing["route"], canonical_bytes(pairing["activation"]))
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        keys = {"event", "exception_type", "method", "request_id"}
        if expected is None:
            assert set(records[0]) == keys
        else:
            assert set(records[0]) == keys | {"sqlite_primary_code"}
            assert type(records[0]["sqlite_primary_code"]) is int and records[0]["sqlite_primary_code"] == expected
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
        assert ceremony.fresh_state(pairing) == ceremony.UNTOUCHED
    finally:
        ceremony.close()


@pytest.mark.parametrize("code", [5, 517])
def test_busy_with_an_open_transaction_stays_500_and_persists_nothing(caplog, monkeypatch, code):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def busy_in_transaction(self, *args, **kwargs):
        self.conn.execute("BEGIN IMMEDIATE")  # left open: the guard, not the code, must refuse the 503
        error = sqlite3.OperationalError(canary)
        error.sqlite_errorcode = code
        raise error

    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("busy-open@example.test")
        raw = canonical_bytes(pairing["activation"])
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", busy_in_transaction)
        status, headers, body = _raw_post(ceremony, pairing["route"], raw)
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        assert set(records[0]) == {"event", "exception_type", "method", "request_id", "sqlite_primary_code"}
        assert records[0]["sqlite_primary_code"] == 5
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
        assert ceremony.fresh_state(pairing) == ceremony.UNTOUCHED
        # Closing the short connection discarded the open transaction: the real activation still works.
        monkeypatch.undo()
        assert _raw_post(ceremony, pairing["route"], raw)[0] == 200
        assert ceremony.fresh_state(pairing) == ceremony.ACTIVATED_ONCE
    finally:
        ceremony.close()


def test_generic_internal_error_log_keeps_its_four_keys(caplog, monkeypatch):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def failing(self, *args, **kwargs):
        raise RuntimeError(canary)

    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("generic-error@example.test")
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", failing)
        status, headers, body = _raw_post(ceremony, pairing["route"], canonical_bytes(pairing["activation"]))
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        assert set(records[0]) == {"event", "exception_type", "method", "request_id"}
        assert records[0]["exception_type"] == "RuntimeError"
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
    finally:
        ceremony.close()


@pytest.mark.parametrize("code", [5, 6, 261, 262, 517, 773],
                         ids=["busy", "locked", "busy_recovery", "locked_sharedcache", "busy_snapshot", "busy_timeout"])
def test_v3_activation_injected_busy_and_locked_codes_answer_the_named_503(caplog, monkeypatch, code):
    """Injected errors, classified by primary code on the permitted file-backed v3 route only."""
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def busy(self, *args, **kwargs):
        error = sqlite3.OperationalError(canary)
        error.sqlite_errorcode = code
        raise error

    ceremony = _FilePairingCeremony(SigningAuthority.generate())
    try:
        pairing = ceremony.approved_pairing("busy-injected@example.test")
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", busy)
        status, headers, body = _raw_post(ceremony, pairing["route"], canonical_bytes(pairing["activation"]))
        assert status == 503, body
        assert json.loads(body) == ceremony.BUSY
        assert [value for name, value in headers if name.lower() == "retry-after"] == ["1"]
        assert "control_plane_internal_error" not in caplog.text
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
        assert ceremony.fresh_state(pairing) == ceremony.UNTOUCHED
    finally:
        ceremony.close()


def test_shared_connection_v3_activation_busy_stays_500(caplog, monkeypatch):
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    canary = "CANARY-" + secrets_bytes(8).hex()

    def busy(self, *args, **kwargs):
        error = sqlite3.OperationalError(canary)
        error.sqlite_errorcode = 5
        raise error

    ceremony = _PairingCeremony(SigningAuthority.generate())
    try:
        assert ceremony.cp.runner_connections_are_shared is True
        pairing = ceremony.approved_pairing("busy-shared@example.test")
        monkeypatch.setattr(RunnerAuthStore, "activate_executable", busy)
        status, headers, body = _raw_post(ceremony, pairing["route"], canonical_bytes(pairing["activation"]))
        assert (status, json.loads(body)) == (500, {"error": "internal error"})
        assert [value for name, value in headers if name.lower() == "retry-after"] == []
        records = [json.loads(record.getMessage()) for record in caplog.records
                   if "control_plane_internal_error" in record.getMessage()]
        assert len(records) == 1
        assert set(records[0]) == {"event", "exception_type", "method", "request_id", "sqlite_primary_code"}
        assert records[0]["sqlite_primary_code"] == 5
        assert canary not in caplog.text and canary.encode() not in body and canary not in repr(headers)
        assert ceremony.state(pairing)["receipt"] is None
    finally:
        ceremony.close()


# --- C2: inactive-claim attestation over the real in-process HTTP boundary (C design §6, §11) ---

_INVALID_RUNNER_AUTH = (401, {"schema_version": "heel.runner-error.v1", "code": "invalid_runner_auth"})
_ATTESTATION_GUARDED_TABLES = (
    "canary_runs", "canary_execution_grants", "canary_approval_projections", "canary_operational_receipts",
    "usage_ledger", "canary_runner_nonce_chains", "canary_runner_chain_cursors", "canary_runner_request_ledger",
    "canary_run_events", "canary_audit_records", "canary_runner_keys", "canary_runner_resync_challenges",
)


def _attestation_refused(reason):
    return (409, {"schema_version": "heel.runner-error.v1", "code": "inactive_claim_attestation_refused", "reason": reason})


def _attestation_body(live, *, challenge=b"c" * 32, **overrides):
    from heel.canary_contracts import RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_SCHEMA

    approval_id = live.cp.store.conn.execute(
        "SELECT approval_id FROM canary_runs WHERE run_id=?", (live.run_id,),
    ).fetchone()[0]
    return canonical_bytes({
        "schema_version": RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_SCHEMA,
        "run_id": live.run_id, "project_id": "prj", "grant_id": live.grant["grant_id"],
        "grant_digest": live.grant["grant_digest"], "approval_id": approval_id,
        "approval_projection_digest": live.grant["approval"]["projection_digest"],
        "bound_runner_key_id": live.key_id,
        "client_challenge_b64": base64.b64encode(challenge).decode(),
        **overrides,
    })


def _attest(live, body=None, *, workspace=None, runner_id="runner", run_id=None, path=None, private=None,
            key_id=None, timestamp_ms=None, extra_headers=None, method="POST", sign_path=None, sign_body=None,
            domain=None):
    """POST exact bytes with only the resync proof header family; returns status, JSON, X-Heel headers."""
    from heel.canary_contracts import (
        RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN, RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA,
    )

    workspace = live.workspace if workspace is None else workspace
    run_id = live.run_id if run_id is None else run_id
    path = f"/v1/workspaces/{workspace}/runners/{runner_id}/runs/{run_id}/inactive-claim-attestation" if path is None else path
    body = _attestation_body(live) if body is None else body
    private = live.private if private is None else private
    key_id = live.key_id if key_id is None else key_id
    timestamp_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    proof = {
        "schema_version": RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA, "workspace_id": workspace,
        "runner_id": runner_id, "key_id": key_id, "method": "POST", "path": path if sign_path is None else sign_path,
        "body_sha256": hashlib.sha256(body if sign_body is None else sign_body).hexdigest(), "timestamp_ms": timestamp_ms,
    }
    signature = private.sign((RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN if domain is None else domain) + canonical_bytes(proof))
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": runner_id, "X-Heel-Runner-Key-Id": key_id,
        "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms), "X-Heel-Runner-Signature": base64.b64encode(signature).decode(),
        **(extra_headers or {}),
    }
    conn = http.client.HTTPConnection("127.0.0.1", live.server.server_address[1], timeout=5)
    try:
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        raw = response.read()
        runner_headers = {key: value for key, value in response.getheaders() if key.startswith("X-Heel-")}
    finally:
        conn.close()
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw
    return response.status, payload, runner_headers


def _guarded_state(live):
    conn = live.cp.store.conn
    return {table: sorted(map(tuple, conn.execute(f"SELECT * FROM {table}"))) for table in _ATTESTATION_GUARDED_TABLES}


def _attestation_audit(live):
    return [dict(row) for row in live.cp.store.conn.execute(
        "SELECT * FROM canary_inactive_claim_attestations ORDER BY created_at_ms,attestation_id"
    )]


def _cloud_stop(live):
    live.runs.request_stop(
        live.workspace, "prj", live.run_id, actor="owner", reason="cloud_stop",
        expected_kill_switch_generation=0,
    )


def _verify_attestation(live, payload, challenge):
    from heel.canary_contracts import inactive_claim_attestation_signing_payload, validate_inactive_claim_attestation
    from heel.crypto import verify_envelope

    assert validate_inactive_claim_attestation(payload) == payload
    authority = live.cp.grant_authority
    envelope = {"signing_key_id": payload["signing_key_id"], "signature_b64": payload["signature_b64"]}
    verify_envelope({authority.key_id: authority.public_key}, envelope, inactive_claim_attestation_signing_payload(payload))
    stranger = SigningAuthority.generate()
    with pytest.raises(ValueError):
        verify_envelope({stranger.key_id: stranger.public_key}, envelope, inactive_claim_attestation_signing_payload(payload))
    assert payload["client_challenge_b64"] == base64.b64encode(challenge).decode()
    approval_id = live.cp.store.conn.execute("SELECT approval_id FROM canary_runs WHERE run_id=?", (live.run_id,)).fetchone()[0]
    assert {key: payload[key] for key in (
        "workspace_id", "runner_id", "project_id", "run_id", "grant_id", "grant_digest", "approval_id",
        "approval_projection_digest", "bound_runner_key_id", "authenticated_runner_key_id",
    )} == {
        "workspace_id": live.workspace, "runner_id": "runner", "project_id": "prj", "run_id": live.run_id,
        "grant_id": live.grant["grant_id"], "grant_digest": live.grant["grant_digest"], "approval_id": approval_id,
        "approval_projection_digest": live.grant["approval"]["projection_digest"],
        "bound_runner_key_id": live.key_id, "authenticated_runner_key_id": live.key_id,
    }


def _expected_cloud(live):
    row = live.cp.store.conn.execute(
        "SELECT r.status,r.stop_reason,r.stop_generation,r.stop_requested_at_ms,r.stop_deadline_ms,r.terminal_at_ms,"
        "r.execution_disposition,g.status AS grant_status FROM canary_runs r JOIN canary_execution_grants g "
        "ON g.grant_id=r.grant_id WHERE r.run_id=?", (live.run_id,),
    ).fetchone()
    return {**dict(row), "started_at_ms": None, "stop_acknowledged_at_ms": None,
            "observation": "no_start_no_ack_no_execution_projection"}


def test_real_http_inactive_claim_attestation_roundtrip_uses_resync_header_family_and_pinned_signature():
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            _cloud_stop(live)
            before = _guarded_state(live)
            challenge = bytes(range(32))
            status, payload, headers = _attest(live, _attestation_body(live, challenge=challenge))
            assert status == 200, payload
            assert "X-Heel-Runner-Next-Nonce" not in headers  # no nonce is consumed or issued
            _verify_attestation(live, payload, challenge)
            assert payload["cloud"] == _expected_cloud(live)
            assert payload["cloud"]["status"] == "stop_requested" and payload["cloud"]["stop_reason"] == "cloud_stop"
            assert _guarded_state(live) == before
            [audit] = _attestation_audit(live)
            assert audit == {
                "attestation_id": payload["attestation_id"], "workspace_id": live.workspace, "runner_id": "runner",
                "run_id": live.run_id, "grant_id": live.grant["grant_id"], "authenticated_key_id": live.key_id,
                "request_signed_digest": audit["request_signed_digest"],
                "attestation_digest": payload["attestation_digest"], "cloud_status": "stop_requested",
                "created_at_ms": payload["attested_at_ms"], "purge_at": payload["attested_at_ms"] + 30 * 24 * 60 * 60 * 1000,
            }
            assert len(audit["request_signed_digest"]) == 64
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_rejects_nonce_sequence_headers_query_fragment_and_non_post():
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            _cloud_stop(live)
            before = _guarded_state(live)
            route = f"/v1/workspaces/{live.workspace}/runners/runner/runs/{live.run_id}/inactive-claim-attestation"
            body = _attestation_body(live)
            for extra in (
                {"X-Heel-Runner-Nonce": base64.b64encode(b"n" * 32).decode()}, {"X-Heel-Runner-Sequence": "1"},
                {"Authorization": "Bearer heel_sk_abc"}, {"Cookie": "heel_session=abc"},
            ):
                assert _attest(live, body, extra_headers=extra)[:2] == _INVALID_RUNNER_AUTH, extra
            for path in (route + "?x=1", route + "#fragment", route.replace("/runs/", "/r%75ns/"),
                         route.replace("inactive-claim-attestation", "inactive-claim-attestatio%6E")):
                assert _attest(live, body, path=path)[0] in {400, 401, 404}, path  # never routed to issuance
                assert _attestation_audit(live) == []
            assert _attest(live, body, path=route + "?x=1")[:2] == _INVALID_RUNNER_AUTH
            assert _attest(live, body, path=route + "#fragment")[0] == 404  # a fragment never routes
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                assert _attest(live, body, method=method)[0] in {400, 404, 405, 501}, method  # never issuance
            other = Ed25519PrivateKey.generate()
            for kwargs in (
                {"body": body + b" "},                                            # not canonical
                {"body": body.replace(b"{", b"{ ", 1)},                          # not canonical
                {"body": b"{" + b" " * 2048 + b"}"},                               # above the 2048-byte cap
                {"body": _attestation_body(live, run_id="crun_" + "f" * 32)},     # body run differs from path
                {"body": body, "sign_body": _attestation_body(live, challenge=b"x" * 32)},  # tampered body
                {"body": body, "sign_path": route.replace(live.run_id, "crun_" + "f" * 32)},  # tampered path
                {"body": body, "private": other},                                 # tampered PoP
                {"body": body, "domain": b"heel.runner-resync-start-pop.v2\0"},   # another PoP domain
                {"body": body, "timestamp_ms": int(time.time() * 1000) - 31_000},  # stale (allow_stale=False)
                {"body": body, "timestamp_ms": int(time.time() * 1000) + 31_000},
                {"body": body, "key_id": ed25519_key_id(other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)), "private": other},
                {"body": body, "extra_headers": {"X-Heel-Runner-Signature": ""}},
            ):
                assert _attest(live, **kwargs)[:2] == _INVALID_RUNNER_AUTH, kwargs.keys()
            assert _attestation_audit(live) == []
            assert _guarded_state(live) == before
            status, _, headers = _attest(live, body)
            assert status == 200 and "X-Heel-Runner-Next-Nonce" not in headers
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_is_issued_after_reaper_missing_ack_terminal_and_all_purges():
    from canary_test_support import Clock, operational_projection
    from heel.saas.canary_runs import CanaryRunService

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            # A pre-activation heartbeat leaves a 'claimed' receipt and no start.
            status, _ = live.post("heartbeat", operational_projection(live.signer, live.grant, sequence=0, phase="claimed"))
            assert status == 200
            _cloud_stop(live)
            clock = Clock(time.time() + 10)
            reaper = CanaryRunService(live.cp.store.conn, signing=live.cp.grant_authority, clock=clock, initialize_schema=False)
            assert reaper.expire_and_reconcile()["finalized_orphans"] == 1
            assert live.cp.store.conn.execute(
                "SELECT COUNT(*) FROM canary_audit_records WHERE run_id=? AND action='stop_ack_late' AND reason_code='missing_ack'",
                (live.run_id,),
            ).fetchone()[0] == 1
            start = clock.value
            for elapsed in (25 * 3600, 8 * 86400, 31 * 86400):  # 24 h payload, 7 d receipt, 30 d audit purges
                clock.value = start + elapsed
                reaper.expire_and_reconcile()
            auth = RunnerAuthStore(live.cp.store.conn, pepper=b"r" * 32, now=clock)
            while auth.purge_runner_request_receipts(clock.value)[1]:
                pass
            conn = live.cp.store.conn
            assert conn.execute("SELECT grant_json FROM canary_execution_grants").fetchone()[0] is None
            assert conn.execute("SELECT projection_json FROM canary_approval_projections").fetchone()[0] is None
            assert tuple(conn.execute(
                "SELECT receipt_json,lifecycle_phase,execution_disposition FROM canary_operational_receipts",
            ).fetchone()) == (None, "claimed", None)
            assert conn.execute("SELECT COUNT(*) FROM canary_runner_request_ledger").fetchone()[0] == 0
            row = live.row()
            assert (row["status"], row["execution_disposition"], row["stop_reason"]) == ("terminal", "stopped", "cloud_stop")
            before = _guarded_state(live)
            challenge = b"\x01" * 32
            status, payload, _ = _attest(live, _attestation_body(live, challenge=challenge))
            assert status == 200, payload
            _verify_attestation(live, payload, challenge)
            assert payload["cloud"] == _expected_cloud(live)
            assert (payload["cloud"]["status"], payload["cloud"]["execution_disposition"], payload["cloud"]["grant_status"]) == (
                "terminal", "stopped", "terminal")
            assert type(payload["cloud"]["terminal_at_ms"]) is int
            assert _guarded_state(live) == before
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_refuses_live_claimed_run_then_succeeds_after_reaper_persists_stop():
    from heel.saas.canary_reaper import CanaryReaper

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            before = _guarded_state(live)
            assert _attest(live)[:2] == _attestation_refused("run_live")
            conn = live.cp.store.conn
            for status in ("expired", "cancelled"):
                conn.execute("UPDATE canary_runs SET status=? WHERE run_id=?", (status, live.run_id)); conn.commit()
                assert _attest(live)[:2] == _attestation_refused("lifecycle_mismatch"), status
            conn.execute("UPDATE canary_runs SET status='claimed' WHERE run_id=?", (live.run_id,)); conn.commit()
            assert _guarded_state(live) == before and _attestation_audit(live) == []
            # The grant expires without any runner action; one reaper cycle persists the stop.
            reaper = CanaryReaper(
                str(Path(directory) / "control.sqlite"), signing=live.cp.grant_authority,
                runner_auth_pepper=b"r" * 32, clock=lambda: time.time() + 700,
            )
            assert reaper.run_once()["authority_stops"] == 1
            row = conn.execute("SELECT status,stop_reason,started_at_ms FROM canary_runs WHERE run_id=?", (live.run_id,)).fetchone()
            assert tuple(row) == ("stop_requested", "cloud_stop", None)
            challenge = b"\x02" * 32
            status, payload, _ = _attest(live, _attestation_body(live, challenge=challenge))
            assert status == 200, payload
            _verify_attestation(live, payload, challenge)
            assert payload["cloud"] == _expected_cloud(live)
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_refuses_started_acknowledged_d_witness_and_queued_terminal_rows():
    from canary_test_support import operational_projection

    observed = _attestation_refused("cloud_observed_execution")
    with tempfile.TemporaryDirectory() as directory:
        # Started, then the D-family queued NULL-ACK stopped terminal accepted by the Cloud.
        live = _LiveHttpRun(directory)
        try:
            status, _ = live.post("progress", operational_projection(
                live.signer, live.grant, sequence=0, phase="running", requests_started=1,
            ))
            assert status == 200
            _cloud_stop(live)
            assert _attest(live)[:2] == observed
            from canary_test_support import NOW_MS
            status, payload = live.post("result", operational_projection(
                live.signer, live.grant, sequence=1, phase="terminal", disposition="stopped",
                stop_reason="cloud_stop", requests_started=1, stop_requested_at_ms=_stop_instants()[0],
                stop_acknowledged_at_ms=None, updated_at_ms=NOW_MS + 1_000,
            ))
            assert status == 200 and payload["status"] == "terminal"
            assert live.row()["execution_disposition"] == "stopped"
            assert _attest(live)[:2] == observed
            assert _attestation_audit(live) == []
        finally:
            live.close()
    with tempfile.TemporaryDirectory() as directory:
        # Accepted stop acknowledgement (D witness written once with the Cloud receipt time).
        live = _LiveHttpRun(directory)
        try:
            _accepted_ack(live)
            assert live.witness() != (None, None, None)
            assert _attest(live)[:2] == observed
            assert _attestation_audit(live) == []
        finally:
            live.close()
    with tempfile.TemporaryDirectory() as directory:
        # Each predicate column alone refuses, on an otherwise attestable pre-activation stop.
        live = _LiveHttpRun(directory)
        try:
            status, _ = live.post("heartbeat", operational_projection(live.signer, live.grant, sequence=0, phase="claimed"))
            assert status == 200
            _cloud_stop(live)
            conn = live.cp.store.conn
            for table, assignment, restore in (
                ("canary_runs", "started_at_ms=1", "started_at_ms=NULL"),
                ("canary_runs", "stop_acknowledged_at_ms=1", "stop_acknowledged_at_ms=NULL"),
                ("canary_runs", "stop_ack_source_event_sequence=0", "stop_ack_source_event_sequence=NULL"),
                ("canary_runs", f"stop_ack_projection_digest='{'a' * 64}'", "stop_ack_projection_digest=NULL"),
                ("canary_runs", "stop_ack_runner_local_at_ms=1", "stop_ack_runner_local_at_ms=NULL"),
                ("canary_operational_receipts", "lifecycle_phase='running'", "lifecycle_phase='claimed'"),
                ("canary_operational_receipts", "lifecycle_phase='terminal'", "lifecycle_phase='claimed'"),
                ("canary_operational_receipts", "execution_disposition='stopped'", "execution_disposition=NULL"),
            ):
                conn.execute(f"UPDATE {table} SET {assignment} WHERE run_id=?", (live.run_id,)); conn.commit()
                assert _attest(live)[:2] == observed, assignment
                conn.execute(f"UPDATE {table} SET {restore} WHERE run_id=?", (live.run_id,)); conn.commit()
            assert _attestation_audit(live) == []
            status, payload, _ = _attest(live)
            assert status == 200, payload
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_refuses_binding_mismatch_and_401s_foreign_runner():
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            _cloud_stop(live)
            conn = live.cp.store.conn
            before = _guarded_state(live)
            for field, value in (
                ("project_id", "prj_other"), ("grant_id", "grant_other"), ("grant_digest", "f" * 64),
                ("approval_id", "ap_other"), ("approval_projection_digest", "e" * 64),
                ("bound_runner_key_id", "key_other"),
            ):
                assert _attest(live, _attestation_body(live, **{field: value}))[:2] == _attestation_refused("binding_mismatch"), field
            # A decomposed identifier is not the canonical NFC request the runner signed.
            raw = json.dumps(json.loads(_attestation_body(live)) | {"project_id": "préj"},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            assert _attest(live, raw)[:2] == _INVALID_RUNNER_AUTH
            # Not owned by the path (workspace, runner) or not present: authentication failure, not 409.
            assert _attest(live, run_id="crun_" + "f" * 32, body=_attestation_body(live, run_id="crun_" + "f" * 32))[:2] == _INVALID_RUNNER_AUTH
            foreign = Ed25519PrivateKey.generate()
            foreign_raw = foreign.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            foreign_key = ed25519_key_id(foreign_raw)
            conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner2", live.workspace, "runner2", "active", time.time()))
            conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (foreign_key, live.workspace, "runner2", base64.b64encode(foreign_raw).decode(), "active", time.time()))
            _enable_executable_protocol(conn, live.workspace, "runner2")
            other_workspace = live.cp.store.create_workspace(live.cp.store.create_org("org2"), "ws2", "free", CATALOG_VERSION)
            other_key_private = Ed25519PrivateKey.generate()
            other_raw = other_key_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner3", other_workspace, "runner3", "active", time.time()))
            conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)", (ed25519_key_id(other_raw), other_workspace, "runner3", base64.b64encode(other_raw).decode(), "active", time.time()))
            _enable_executable_protocol(conn, other_workspace, "runner3")
            conn.commit()
            before = _guarded_state(live)
            for body in (_attestation_body(live), _attestation_body(live, bound_runner_key_id=foreign_key)):
                assert _attest(live, body, runner_id="runner2", private=foreign, key_id=foreign_key)[:2] == _INVALID_RUNNER_AUTH
            assert _attest(live, workspace=other_workspace, runner_id="runner3", private=other_key_private, key_id=ed25519_key_id(other_raw))[:2] == _INVALID_RUNNER_AUTH
            # The live runner's key cannot authenticate for another runner or workspace path.
            assert _attest(live, runner_id="runner2")[:2] == _INVALID_RUNNER_AUTH
            # The protocol gate precedes PoP exactly as in start_resync (design §10.4): this pair has none.
            assert _attest(live, workspace=other_workspace)[:2] == (
                403, {"schema_version": "heel.runner-error.v1", "code": "runner_protocol_upgrade_required"})
            assert _guarded_state(live) == before and _attestation_audit(live) == []
            assert _attest(live)[0] == 200
        finally:
            live.close()


def test_real_http_inactive_claim_attestation_fails_closed_for_revoked_rotated_and_legacy_protocol_keys():
    upgrade = (403, {"schema_version": "heel.runner-error.v1", "code": "runner_protocol_upgrade_required"})
    for case in ("legacy", "rotated", "revoked"):
        with tempfile.TemporaryDirectory() as directory:
            live = _LiveHttpRun(directory)
            try:
                _cloud_stop(live)
                conn = live.cp.store.conn
                if case == "legacy":
                    conn.execute("DELETE FROM canary_runner_execution_protocols WHERE workspace_id=?", (live.workspace,))
                    conn.commit()
                elif case == "rotated":
                    # Rotation leaves the old key verification-only; no successor key may attest for it.
                    conn.execute("UPDATE canary_runner_keys SET status='verification_only' WHERE key_id=?", (live.key_id,))
                    conn.commit()
                else:
                    assert live.cp.runner_auth.revoke(live.workspace, "runner", actor="owner") is True
                before = _guarded_state(live)
                expected = upgrade if case == "legacy" else _INVALID_RUNNER_AUTH
                assert _attest(live)[:2] == expected, case
                assert _guarded_state(live) == before and _attestation_audit(live) == []
            finally:
                live.close()


def test_real_http_inactive_claim_attestation_leaves_expired_pending_heartbeat_chain_and_ledger_untouched():
    from canary_test_support import operational_projection

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            status, _ = live.post("heartbeat", operational_projection(live.signer, live.grant, sequence=0, phase="claimed"))
            assert status == 200
            # The next heartbeat was staged locally but its nonce has since expired on the Cloud.
            pending = live.signed("heartbeat", operational_projection(live.signer, live.grant, sequence=1, phase="claimed"))
            conn = live.cp.store.conn
            conn.execute(
                "UPDATE canary_runner_nonce_chains SET expires_at=0 WHERE workspace_id=? AND chain_name=?",
                (live.workspace, f"heartbeat:{live.run_id}"),
            )
            conn.commit()
            _cloud_stop(live)
            chain_tables = ("canary_runner_nonce_chains", "canary_runner_chain_cursors", "canary_runner_request_ledger")
            before = _guarded_state(live)
            assert before["canary_runner_request_ledger"]
            replay = _attestation_body(live, challenge=b"\x03" * 32)
            first = _attest(live, replay)
            second = _attest(live, replay)  # side-effect free: a replay is answered again, never interpreted
            for status, payload, headers in (first, second):
                assert status == 200, payload
                assert "X-Heel-Runner-Next-Nonce" not in headers
                _verify_attestation(live, payload, b"\x03" * 32)
            assert first[1]["attestation_id"] != second[1]["attestation_id"]
            after = _guarded_state(live)
            assert {table: after[table] for table in chain_tables} == {table: before[table] for table in chain_tables}
            assert after == before
            assert len(_attestation_audit(live)) == 2
            # The expired pending heartbeat is still exactly as it was: never resent, never consumed.
            assert live.send(*pending)[0] == 401
            assert _guarded_state(live) == before
        finally:
            live.close()


# --- PENDING-BODY-CAP: bodies over 3 072 B through the public client over real loopback HTTP ---------

def _wide_running_projection(live, times, *, sequence):
    """A wire-valid running heartbeat projection whose version fields are at their validator maxima."""
    from canary_test_support import operational_projection
    from test_canary_lifecycle import resign_operational

    value = operational_projection(
        live.signer, live.grant, sequence=sequence, phase="running", requests_started=1, requests_completed=1,
    )
    value["timestamps"] = {
        "claimed_at_ms": times["claimed"], "started_at_ms": times["started"],
        "updated_at_ms": times["started"] + sequence, "stop_requested_at_ms": None,
        "stop_acknowledged_at_ms": None, "terminal_at_ms": None,
    }
    value["versions"] = {
        "runner_version": "v" * 128, "engine_version": "e" * 128,
        "adapter_versions": sorted(f"{index:02d}" + "a" * 126 for index in range(20)),
    }
    return resign_operational(value, live.signer)


def _heartbeat_cursor(live):
    (cursor,) = [item for item in live.cursors() if item[0] == f"heartbeat:{live.run_id}"]
    return cursor


def test_public_heartbeat_over_3072_bytes_stages_sends_commits_over_real_loopback_http_and_replays_byte_identically_after_restart(
    tmp_path, capsys,
):
    """T-P6: the public ``heartbeat`` API stages, sends and commits a wire-valid heartbeat over 3 072 B;
    a second one whose send never left survives a restart and is replayed byte-identically once."""
    from heel.canary_contracts import validate_runner_heartbeat_request

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            terminal = _live_projection(live, times, sequence=9, phase="terminal", acknowledged=None)
            transport = _LiveRunnerTransport(live)
            runtime, signer, control = _live_runner(live, tmp_path / "runner", transport, terminal, times=times)
            initial = _heartbeat_cursor(live)

            first = _wide_running_projection(live, times, sequence=1)
            status, headers = control.heartbeat(run_id=live.run_id, operational_projection=first)
            ((_path, _headers, sent),) = transport.sent
            assert status == 200 and "X-Heel-Runner-Next-Nonce" in headers and transport.answers[0][0] == 200
            assert len(sent) > 3072 and sent == canonical_bytes(validate_runner_heartbeat_request({
                "schema_version": "heel.runner-heartbeat-request.v1", "run_id": live.run_id,
                "operational_projection": first,
            }))
            assert runtime.load_pending_calls() == ()
            after_first = _heartbeat_cursor(live)
            assert after_first[1] == initial[1] + 1

            second = _wide_running_projection(live, times, sequence=2)
            transport.refuse_sends = 1
            with pytest.raises(ConnectionError):
                control.heartbeat(run_id=live.run_id, operational_projection=second)
            assert len(transport.answers) == 1 and _heartbeat_cursor(live) == after_first
            (pending,) = runtime.load_pending_calls()
            assert pending.request_operation == "heartbeat" and pending.body == transport.sent[1][2]
            assert len(pending.body) > 3072

            restarted = RunnerRuntimeState(runtime.path, runtime.identity, signer)
            assert restarted.load_pending_calls() == (pending,)
            fresh_transport = _LiveRunnerTransport(live)
            fresh = _live_client(live, restarted, signer, fresh_transport)
            with pytest.raises(ValueError, match="pending replay is required"):
                fresh.heartbeat(run_id=live.run_id, operational_projection=second)
            assert fresh_transport.sent == []
            outcomes = fresh.replay_all_pending(now_ms=int(time.time() * 1000))
            assert [(item.request_operation, item.status) for item in outcomes] == [("heartbeat", 200)]
            assert fresh_transport.sent == [(pending.path, dict(pending.headers), pending.body)]
            assert restarted.load_pending_calls() == ()
            assert _heartbeat_cursor(live) == (after_first[0], after_first[1] + 1, after_first[2])
            assert fresh.replay_all_pending(now_ms=int(time.time() * 1000)) == ()
            assert len(fresh_transport.sent) == 1 and _heartbeat_cursor(live)[1] == after_first[1] + 1

            # Over the heartbeat route budget: a projection cannot be wire-valid at 36 865 B (its fields are
            # bounded), so an oversized one is refused by the client's own validation before staging or send.
            oversized = dict(_wide_running_projection(live, times, sequence=3))
            oversized["versions"] = {**oversized["versions"], "adapter_versions": ["a" * 2048] * 18}
            body_size = len(canonical_bytes({
                "schema_version": "heel.runner-heartbeat-request.v1", "run_id": live.run_id,
                "operational_projection": oversized,
            }))
            assert body_size > 36_864
            cursor = _heartbeat_cursor(live)
            with pytest.raises(ValueError):
                fresh.heartbeat(run_id=live.run_id, operational_projection=oversized)
            assert len(fresh_transport.sent) == 1 and restarted.load_pending_calls() == ()
            assert _heartbeat_cursor(live) == cursor
            with capsys.disabled():
                print(
                    f"\n[T-P6 measured] heartbeat bodies {len(sent)} B and {len(pending.body)} B over loopback HTTP; "
                    f"oversized projection body {body_size} B refused before send",
                )
        finally:
            live.close()


def _representative_findings(live, terminal, *, observations=2, text=800, title=120):
    """The live run's findings projection widened past 3 072 B. The control plane binds the scenario
    results to the approval's scenarios and action routes, so the single approved scenario is kept and
    only its observations and finding texts grow."""
    from test_canary_disclosure import _findings

    value = _findings(live.signer, live.grant, terminal)
    (scenario,) = value["scenario_results"]
    scenario["observations"] = [
        {**scenario["observations"][0], "semantic_role": f"role{item:02d}"} for item in range(observations)
    ]
    scenario["finding"] = {
        **scenario["finding"], "title": "T" * title, "reachability_rationale": "r" * text,
        "recommended_control": "c" * text, "regression_suggestion": "s" * text,
    }
    value["workspace_id"], value["project_id"], value["environment_id"] = live.workspace, "prj", "env"
    unsigned = {
        key: item for key, item in value.items() if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    value["projection_digest"] = canonical_digest(unsigned)
    value.update(live.signer.sign(canonical_bytes(unsigned)))
    return value


def _live_permit(live, findings):
    from heel.canary_contracts import CANARY_FINDINGS_SCHEMA

    metadata = {
        "projection_schema_version": CANARY_FINDINGS_SCHEMA, "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)), "scenario_count": len(findings["scenario_results"]),
        "finding_count": sum(item["finding"] is not None for item in findings["scenario_results"]),
    }
    disclosure = live.cp.canary_disclosure
    preview = disclosure.preview(
        live.workspace, "prj", live.run_id, runner_id="runner", runner_key_id=live.key_id, **metadata,
    )
    return disclosure.permit(
        live.workspace, "prj", live.run_id, request_id=preview["request_id"], actor="owner", role="owner",
        recent_auth_at_ms=int(time.time() * 1000), **metadata,
    )


def test_public_findings_upload_over_3072_bytes_round_trips_the_control_plane_over_loopback_http(tmp_path, capsys):
    """T-P8: after a real terminal result, the public ``upload_findings`` API stages and sends a findings
    upload over 3 072 B over loopback HTTP; the control plane answers ``synchronized`` and the runtime
    drains. (The two-scenario 4 569 B vector is staged by T-P3/T-P7; this run approves one scenario.) The permit is minted by the control plane's own
    disclosure service (the HTTP permit route needs a browser session this harness does not have)."""
    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            times = _live_timeline()
            _accepted_ack(live, times=times)
            terminal = _live_projection(live, times, sequence=2, phase="terminal", acknowledged=None)
            transport = _LiveRunnerTransport(live)
            runtime, signer, control = _live_runner(live, tmp_path / "runner", transport, terminal, times=times)
            control.result(run_id=live.run_id, operational_projection=terminal)
            assert transport.answers[-1][0] == 200 and _runtime_retired(runtime, live.run_id)
            authority = live.cp.grant_authority
            uploader = RunnerControlClient(
                origin="http://127.0.0.1", workspace_id=live.workspace, runner_id="runner", signer=signer,
                clock=lambda: int(time.time() * 1000), transport=transport,
                nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("run chains are Cloud-issued")),
                trusted_disclosure_keys={authority.key_id: authority.public_key}, runtime=runtime,
            )

            # Over the findings budget: a projection cannot be wire-valid at 278 529 B (≤ 4 scenarios, ≤ 20
            # observations, 4 096-byte strings), so an oversized one (an extra padded key) is refused by the
            # client's own validation before staging or sending.
            oversized = {**_representative_findings(live, terminal), "padding": ["x" * 4000] * 70}
            assert len(canonical_bytes(oversized)) > 278_528
            sends = len(transport.sent)
            with pytest.raises(ValueError):
                uploader.upload_findings(
                    run_id=live.run_id, permit=_live_permit(live, _representative_findings(live, terminal)),
                    findings_projection=oversized,
                )
            assert len(transport.sent) == sends and runtime.load_pending_calls() == ()
            assert runtime.load_terminal_state(live.run_id).state == "available"

            findings = _representative_findings(live, terminal)
            permit = _live_permit(live, findings)
            receipt = uploader.upload_findings(run_id=live.run_id, permit=permit, findings_projection=findings)
            path, _headers, sent = transport.sent[-1]
            assert path.endswith(f"/runs/{live.run_id}/result-projection") and transport.answers[-1][0] == 200
            assert sent == canonical_bytes({
                "schema_version": "heel.runner-findings-upload.v1", "run_id": live.run_id, "permit": permit,
                "findings_projection": findings,
            })
            assert len(sent) > 3072
            assert receipt["status"] == "synchronized" and receipt["projection_digest"] == findings["projection_digest"]
            assert runtime.load_pending_calls() == ()
            assert runtime.load_terminal_state(live.run_id).state == "consumed"
            stored = live.cp.store.conn.execute(
                "SELECT COUNT(*) FROM canary_findings_projections WHERE run_id=?", (live.run_id,),
            ).fetchone()[0]
            assert stored == 1
            with capsys.disabled():
                print(f"\n[T-P8 measured] findings upload body {len(sent)} B over loopback HTTP -> synchronized")
        finally:
            live.close()


# --- R2: client acceptance of an inactive-claim attestation (POSTRESET §7.2) ---

def _stuck_live_client(live, root, transport):
    """A runtime holding the Cloud-claimed run as an active group that never activated, and a
    client whose pinned grant trust set is the control plane's grant authority."""
    root.mkdir(mode=0o700, exist_ok=True)
    runtime, signer = _live_runtime(live, root)
    now = int(time.time() * 1000)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"p" * 32).decode(),
        next_sequence=1, generation=0, now_ms=now,
    )
    claim = runtime.load_chain("claim", None)
    path = f"/v1/workspaces/{live.workspace}/runners/runner/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": live.workspace,
        "runner_id": "runner", "key_id": signer.key_id, "capability": "runner_claim", "method": "POST",
        "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": now,
        "server_nonce": claim.next_nonce_b64, "sequence": claim.next_sequence,
    }
    pending = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path, capability="runner_claim",
        headers={"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": signer.key_id,
                 "X-Heel-Runner-Timestamp-Ms": str(now),
                 "X-Heel-Runner-Signature": base64.b64encode(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode(),
                 "X-Heel-Runner-Nonce": claim.next_nonce_b64, "X-Heel-Runner-Sequence": "1"},
        body=body, expected_state_digest=claim.state_digest, now_ms=now,
    )
    runtime.commit_call(
        pending.call_id, next_nonce_b64=base64.b64encode(b"n" * 32).decode(), now_ms=now,
        installed_chains=tuple(
            (operation, live.run_id, live.chains[operation]["next_nonce_b64"],
             live.chains[operation]["next_sequence"], live.chains[operation]["generation"])
            for operation in ("heartbeat", "progress", "result", "stop-ack")
        ),
        active_run=ActiveRunInstall(
            run_id=live.run_id, approval_projection=live.approval, grant=live.grant,
            gate={"active": True, "runner_state": "active", "proof_state": "valid",
                  "proof_expires_at_ms": now + 3_600_000, "kill_switch_generation": 0,
                  "stop_reason": "none", "server_time_ms": now},
            claim_response_digest="a" * 64, gate_response_digest="b" * 64,
            claimed_at_ms=now, gate_received_at_ms=now,
        ),
    )
    authority = live.cp.grant_authority
    challenges = []

    def random_source(size):
        challenges.append(os.urandom(size))
        return challenges[-1]

    control = RunnerControlClient(
        origin="http://127.0.0.1", workspace_id=live.workspace, runner_id="runner", signer=signer,
        clock=lambda: int(time.time() * 1000), transport=transport,
        nonce_source=lambda chain: (_ for _ in ()).throw(AssertionError("run chains are Cloud-issued")),
        resync_random_source=random_source, trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=runtime,
    )
    return runtime, control, challenges


def _runtime_tables(runtime):
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(runtime.path)) as conn:
        return {table: sorted(map(tuple, conn.execute(f"SELECT * FROM {table}"))) for table in (
            "active_runs", "control_chains", "pending_calls", "terminal_disclosures", "chain_recovery", "retired_claims",
        )}


def _resigned_attestation(payload, authority, **changes):
    """FAULTY SERVER: the (possibly compromised) grant authority signs a changed attestation."""
    from heel.canary_contracts import canonical_digest, inactive_claim_attestation_signing_payload

    record = {key: copy.deepcopy(value) for key, value in payload.items()
              if key not in {"attestation_digest", "signing_key_id", "signature_b64"}}
    for key, value in changes.items():
        if key.startswith("cloud."):
            record["cloud"][key[6:]] = value
        else:
            record[key] = value
    record["attestation_digest"] = canonical_digest(record)
    record.update(authority.sign(inactive_claim_attestation_signing_payload(record)))
    return record


def test_attestation_acceptance_requires_matching_challenge_pinned_signer_and_exact_active_row_bindings(tmp_path):
    from heel.runner.control_client import (
        RunnerInactiveClaimAttestationUntrusted, RunnerInactiveClaimRecoveryBlocked, VerifiedInactiveClaimAttestation,
    )
    from heel.runner.daemon import _serve_failure as daemon_serve_failure

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            transport = _LiveRunnerTransport(live)
            rewrite = {}
            real_post = transport.post

            def post(path, *, headers=None, body=b""):
                status, response_headers, payload = real_post(path, headers=headers, body=body)
                change = rewrite.pop("next", None)
                return (status, response_headers, payload) if change is None else change(status, response_headers, payload)

            transport.post = post
            runtime, control, challenges = _stuck_live_client(live, tmp_path / "runner", transport)
            _cloud_stop(live)
            before = _runtime_tables(runtime)
            authority = live.cp.grant_authority

            honest = control._attest_inactive_claim(live.run_id)

            assert isinstance(honest, VerifiedInactiveClaimAttestation)
            path, headers, body = transport.sent[-1]
            assert path == f"/v1/workspaces/{live.workspace}/runners/runner/runs/{live.run_id}/inactive-claim-attestation"
            assert set(headers) == {"Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id",
                                    "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature"}
            request = json.loads(body)
            assert canonical_bytes(request) == body
            assert request["client_challenge_b64"] == base64.b64encode(challenges[-1]).decode()
            evidence = honest.evidence
            assert (evidence.request_method, evidence.request_path, evidence.request_body) == ("POST", path, body)
            assert dict(evidence.request_headers) == {k: v for k, v in headers.items() if k != "Content-Type"}
            assert evidence.request_timestamp_ms == int(headers["X-Heel-Runner-Timestamp-Ms"])
            assert evidence.response_status == 200
            assert evidence.response_body == canonical_bytes(honest.attestation) and len(evidence.response_body) <= 8192
            _verify_attestation(live, honest.attestation, challenges[-1])
            assert honest.expected_state_digest == runtime.load_active_run_controls()[0].state_digest
            assert _runtime_tables(runtime) == before  # attestation alone changes nothing locally

            untrusted = SigningAuthority.generate()
            faulty = {
                # name: (rewrite of the real 200 answer, expected exception)
                "replayed-earlier-attestation": (lambda s, h, p: (s, h, copy.deepcopy(honest.attestation)), RunnerInactiveClaimRecoveryBlocked),
                "other-challenge": (lambda s, h, p: (s, h, _resigned_attestation(p, authority, client_challenge_b64=base64.b64encode(b"x" * 32).decode())), RunnerInactiveClaimRecoveryBlocked),
                "untrusted-signer": (lambda s, h, p: (s, h, _resigned_attestation(p, untrusted)), RunnerInactiveClaimAttestationUntrusted),
                "unsigned-change": (lambda s, h, p: (s, h, {**p, "attested_at_ms": p["attested_at_ms"] + 1}), RunnerInactiveClaimAttestationUntrusted),
                "started-at-reported": (lambda s, h, p: (s, h, _resigned_attestation(p, authority, **{"cloud.started_at_ms": 1})), RunnerInactiveClaimRecoveryBlocked),
                "oversized": (lambda s, h, p: (s, h, {**p, "padding": "x" * 9000}), RunnerInactiveClaimRecoveryBlocked),
                "status-only": (lambda s, h, p: (200, h, {"status": "terminal"}), RunnerInactiveClaimRecoveryBlocked),
                "empty-200": (lambda s, h, p: (200, h, None), RunnerInactiveClaimRecoveryBlocked),
            }
            for field, value in (
                ("run_id", "crun_" + "f" * 32), ("project_id", "prj_other"), ("grant_id", "grant_other"),
                ("grant_digest", "f" * 64), ("approval_id", "approval_other"), ("approval_projection_digest", "e" * 64),
                ("workspace_id", "ws_other"), ("runner_id", "runner_other"),
            ):
                faulty[f"binding-{field}"] = (
                    lambda s, h, p, field=field, value=value: (s, h, _resigned_attestation(p, authority, **{field: value})),
                    RunnerInactiveClaimRecoveryBlocked,
                )
            faulty["binding-runner-keys"] = (
                lambda s, h, p: (s, h, _resigned_attestation(p, authority, bound_runner_key_id="key_other", authenticated_runner_key_id="key_other")),
                RunnerInactiveClaimRecoveryBlocked,
            )
            for name, (change, expected) in faulty.items():
                # RATE-WINDOW SEAM: every case is a real signed request; reset the 3/min audit window.
                live.cp.store.conn.execute("DELETE FROM canary_inactive_claim_attestations")
                live.cp.store.conn.commit()
                rewrite["next"] = change
                with pytest.raises(expected) as refused:
                    control._attest_inactive_claim(live.run_id)
                assert daemon_serve_failure(refused.value) == (
                    ("rejected", "inactive_claim_attestation_untrusted")
                    if expected is RunnerInactiveClaimAttestationUntrusted else ("failed", "recovery_required")
                ), name
                assert "next" not in rewrite, name
                assert _runtime_tables(runtime) == before, name
            # Every refused answer was a fresh signed request with its own fresh challenge.
            sent = [json.loads(body)["client_challenge_b64"] for path, _h, body in transport.sent if path.endswith("/inactive-claim-attestation")]
            assert len(sent) == len(set(sent)) == 1 + len(faulty)
            # A verified attestation is bound to this client and its exact active-row snapshot.
            other_runtime, other, _ = _stuck_live_client(live, tmp_path / "other", _LiveRunnerTransport(live))
            with pytest.raises(ValueError):
                other._retire_inactive_claim(honest, reservation_probe="absent", now_ms=int(time.time() * 1000))
            assert other_runtime.load_retired_claim(live.run_id) is None
            record = control._retire_inactive_claim(honest, reservation_probe="absent", now_ms=int(time.time() * 1000))
            assert record.run_id == live.run_id and runtime.load_active_run_controls() == ()
            assert live.run_id not in control._tracked_runs and live.run_id not in control._run_guards
            assert not any(name.endswith(live.run_id) for name in control._chains)
            with pytest.raises(ValueError):
                control._attest_inactive_claim(live.run_id)  # no active claim is left to attest
        finally:
            live.close()
