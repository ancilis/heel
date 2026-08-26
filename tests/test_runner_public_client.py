import base64
import copy
import hashlib
import inspect
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import OPERATIONAL_RUN_SCHEMA, canonical_bytes, canonical_digest
from heel.crypto import ed25519_key_id
from heel.runner.control_client import PendingRunnerResync, RunnerControlClient, RunnerRotationActivated
from heel.runner.identity import (
    SecureSigner,
    bind_runner_identity,
    create_runner_pairing_material,
)


def test_open_core_runner_package_exports_pairing_and_recovery_types():
    from heel.runner import (  # noqa: PLC0415 - checks the installed public facade.
        PendingRunnerResync, RecoveredRunnerChain, RunnerPairingMaterial,
        RunnerRotationActivated,
        bind_runner_identity, create_runner_pairing_material,
    )
    assert all(item is not None for item in (PendingRunnerResync, RecoveredRunnerChain,
                                               RunnerPairingMaterial, RunnerRotationActivated,
                                               bind_runner_identity,
                                               create_runner_pairing_material))


class Signer(SecureSigner):
    _private_key = Ed25519PrivateKey.from_private_bytes(b"s" * 32)
    public_key = _private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = ed25519_key_id(public_key)

    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return self._private_key.sign(payload)


class Transport:
    def __init__(self): self.requests = []; self.responses = []
    def post(self, path, *, headers, body):
        self.requests.append((path, dict(headers), body))
        if self.responses:
            return self.responses.pop(0)
        response_headers = {
            "X-Heel-Runner-Next-Nonce": base64.b64encode(b"n" * 32).decode(),
        }
        if path.endswith("/claim"):
            return 204, response_headers, None
        if path.endswith("/heartbeat"):
            return 200, response_headers, {
                "active": True, "runner_state": "active", "proof_state": "valid",
                "proof_expires_at_ms": 2_000, "kill_switch_generation": 0,
                "stop_reason": "none", "server_time_ms": 1_000,
            }
        if path.endswith("/stop-ack"):
            return 200, response_headers, {
                "accepted": True, "deadline_met": True, "late": False,
            }
        request = json.loads(body)
        projection = request["operational_projection"]
        phase = "terminal" if path.endswith("/result") else "running"
        return 200, response_headers, {
            "schema_version": "heel.canary-run-status.v1", "run_id": request["run_id"],
            "approval_id": "approval", "grant_id": projection["grant_id"],
            "status": phase,
            "execution_disposition": "completed" if phase == "terminal" else None,
            "error_category": "none", "stop_reason": "none",
            "source_event_sequence": 1, "quota_state": "reserved",
            "kill_switch_generation": 0, "stop_generation": 0,
            "stop_deadline_ms": None, "stop_acknowledged_at_ms": None,
            "stop_ack_late": False,
        }


def operational_projection(phase: str) -> dict:
    timestamps = {"claimed_at_ms": None, "started_at_ms": None, "updated_at_ms": 1,
                  "stop_requested_at_ms": None, "stop_acknowledged_at_ms": None,
                  "terminal_at_ms": None}
    disposition = None
    stop_reason = "none"
    if phase == "claimed":
        timestamps["claimed_at_ms"] = 1
    elif phase == "running":
        timestamps.update({"claimed_at_ms": 1, "started_at_ms": 1})
    elif phase == "terminal":
        timestamps.update({"claimed_at_ms": 1, "started_at_ms": 1, "terminal_at_ms": 1})
        disposition = "completed"
    elif phase == "stop_requested":
        timestamps.update({"claimed_at_ms": 1, "started_at_ms": 1,
                           "stop_requested_at_ms": 1, "stop_acknowledged_at_ms": 1})
        stop_reason = "cloud_stop"
    else:
        raise AssertionError("unsupported test phase")
    value = {
        "schema_version": OPERATIONAL_RUN_SCHEMA, "run_id": "run", "grant_id": "grant",
        "workspace_id": "ws", "project_id": "project", "manifest_digest": "a" * 64,
        "approval_projection_digest": "b" * 64, "grant_digest": "c" * 64,
        "event_sequence": 1, "lifecycle_phase": phase, "execution_disposition": disposition,
        "timestamps": timestamps,
        "counters": {"requests_started": 0, "requests_completed": 0,
                     "response_bytes_read": 0, "actions_contained": 0, "retries_used": 0,
                     "remaining_requests": 1, "remaining_wall_ms": 1},
        "versions": {"runner_version": "1", "engine_version": "1", "adapter_versions": []},
        "error_category": "none", "stop_reason": stop_reason, "containment_codes": [],
        "redaction_count": 0, "projection_digest": "", "signing_key_id": Signer.key_id,
        "signature_b64": base64.b64encode(b"p" * 64).decode(),
    }
    value["projection_digest"] = canonical_digest({
        key: item for key, item in value.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    })
    value["signature_b64"] = base64.b64encode(Signer._private_key.sign(canonical_bytes({
        key: item for key, item in value.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }))).decode()
    return value


class NonceSource:
    def __init__(self): self.keys = []
    def __call__(self, key):
        self.keys.append(key)
        return f"{key[0]}:{key[1]}:nonce"


def test_pairing_material_has_no_client_runner_id_until_server_id_is_bound():
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.exchange_request("invitation")
    assert exchange == {
        "schema_version": "heel.runner-pairing-exchange.v2", "invitation_token": "invitation",
        "public_key_b64": base64.b64encode(signer.public_key).decode(),
        "pairing_phrase": " ".join(material.pairing_phrase), "display_name": "Runner One",
        "runner_version": "1.0", "adapters": {"http": "1.0"},
    }
    assert "runner_id" not in exchange
    identity = bind_runner_identity(material, workspace_id="ws", runner_id="runr_" + "a" * 32)
    assert identity.workspace_id == "ws" and identity.runner_id == "runr_" + "a" * 32


def test_pairing_display_name_is_closed_nfc_and_has_no_edge_whitespace():
    signer = Signer()
    with pytest.raises(ValueError):
        create_runner_pairing_material(" Runner", "1", {}, signer)
    with pytest.raises(ValueError):
        create_runner_pairing_material("A\x00B", "1", {}, signer)
    material = create_runner_pairing_material("Cafe\u0301", "1", {}, signer)
    assert material.display_name == "Caf\u00e9"


def test_named_run_control_requires_an_authenticated_active_claim_before_transport():
    signer, transport, nonces = Signer(), Transport(), NonceSource()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
                                 clock=lambda: 1000, transport=transport, nonce_source=nonces)
    client.claim()
    for method, projection in (
        (client.heartbeat, operational_projection("claimed")),
        (client.progress, operational_projection("running")),
        (client.result, operational_projection("terminal")),
        (client.stop_ack, operational_projection("stop_requested")),
    ):
        with pytest.raises(ValueError, match="active runner claim is required"):
            method(run_id="run", operational_projection=projection)
    assert transport.requests[0][2] == b'{"schema_version":"heel.runner-claim-request.v1"}'
    assert len(transport.requests) == 1
    assert nonces.keys == [("claim", None)]
    public = {name for name, method in vars(RunnerControlClient).items() if callable(method) and not name.startswith("_")}
    assert public == {"claim", "heartbeat", "progress", "result", "stop_ack",
                      "start_resync", "complete_resync", "install_rotation_claim",
                      "upload_findings", "list_contexts", "claim_context",
                      "submit_context_approval_projection"}
    assert all(parameter.kind is not inspect.Parameter.VAR_KEYWORD for method in (
        RunnerControlClient.claim, RunnerControlClient.heartbeat, RunnerControlClient.progress,
        RunnerControlClient.result, RunnerControlClient.stop_ack,
    ) for parameter in inspect.signature(method).parameters.values())


def test_control_diagnostics_are_bounded_frozen_and_sensitive_field_free():
    signer, transport, nonces = Signer(), Transport(), NonceSource()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1000, transport=transport, nonce_source=nonces,
    )
    for _ in range(130):
        client.claim()

    diagnostics = client.calls
    assert len(diagnostics) == 128
    assert client.calls_dropped == 2
    assert [(item.operation, item.status, item.sequence, item.generation) for item in diagnostics[:2]] == [
        ("claim", 204, 3, 0), ("claim", 204, 4, 0),
    ]
    assert all(not hasattr(item, field) for item in diagnostics for field in (
        "path", "headers", "body", "capability", "chain", "__dict__",
    ))
    diagnostics.pop()
    assert len(client.calls) == 128


def test_run_control_uses_fixed_striped_locks_without_per_run_lock_retention():
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=Signer(),
        clock=lambda: 1000, transport=Transport(), nonce_source=NonceSource(),
    )
    stripes = client._run_lock_stripes
    assert len(stripes) == 64
    assert len({id(lock) for lock in stripes}) == 64
    assert {
        id(client._operation_lock("heartbeat", f"run-{ordinal}"))
        for ordinal in range(10_000)
    }.issubset({id(lock) for lock in stripes})
    assert not hasattr(client, "_chain_locks")


@pytest.mark.parametrize(("method_name", "projection"), [
    ("heartbeat", (lambda: ({**operational_projection("claimed"), "private": {"headers": {"authorization": "secret"}}}))()),
    ("progress", (lambda: ({**operational_projection("running"), "padding": "x" * (37 * 1024)}))()),
    ("result", operational_projection("running")),
    ("stop_ack", (lambda: ({**operational_projection("stop_requested"), "signature_b64": base64.b64encode(b"q" * 64).decode()}))()),
])
def test_control_validation_fails_before_nonce_signing_or_transport(method_name, projection):
    signer, transport, nonces = Signer(), Transport(), NonceSource()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner",
                                 signer=signer, clock=lambda: 1000, transport=transport,
                                 nonce_source=nonces)
    with pytest.raises(ValueError):
        getattr(client, method_name)(run_id="run", operational_projection=copy.deepcopy(projection))
    assert nonces.keys == []
    assert signer.payloads == []
    assert transport.requests == []


@pytest.mark.parametrize(("method_name", "projection", "response"), [
    ("claim", None, (503, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"a" * 32).decode()}, None)),
    ("heartbeat", operational_projection("claimed"), (200, {"X-Heel-Runner-Next-Nonce": "bad"}, {})),
    ("progress", operational_projection("running"), (503, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"a" * 32).decode()}, {})),
    ("result", operational_projection("terminal"), (200, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"a" * 32).decode()}, {"unknown": True})),
    ("stop_ack", operational_projection("stop_requested"), (200, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"a" * 32).decode()}, {"accepted": True})),
])
def test_every_public_control_operation_rejects_non_exact_response_without_mutation(
    method_name, projection, response,
):
    transport, signer = Transport(), Signer()
    transport.responses = [response]
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(),
    )
    with pytest.raises(ValueError):
        if method_name == "claim":
            client.claim()
        else:
            getattr(client, method_name)(
                run_id="run", operational_projection=copy.deepcopy(projection),
            )
    assert client._chains == {}
    assert client.calls == []


def test_resync_install_serializes_behind_inflight_control_and_wins_generation():
    started, release = threading.Event(), threading.Event()
    recovered_nonce = base64.b64encode(b"r" * 32).decode()

    class BlockingTransport(Transport):
        def post(self, path, *, headers, body):
            self.requests.append((path, dict(headers), body))
            if path.endswith("/heartbeat"):
                started.set()
                assert release.wait(1)
                return 200, {"X-Heel-Runner-Next-Nonce": base64.b64encode(b"o" * 32).decode()}, {
                    "active": True, "runner_state": "active", "proof_state": "valid",
                    "proof_expires_at_ms": 2_000, "kill_switch_generation": 0,
                    "stop_reason": "none", "server_time_ms": 1_000,
                }
            assert path.endswith("/resync/complete")
            return 200, {}, {
                "schema_version": "heel.runner-resync-completed.v2",
                "chain": {"operation": "heartbeat", "run_id": "run"},
                "next_sequence": 9, "next_nonce_b64": recovered_nonce,
                "expires_at_ms": 2_000, "generation": 2,
            }

    transport, signer = BlockingTransport(), Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(),
    )
    with client._state_lock:
        client._tracked_runs.add("run")
        client._chains["heartbeat:run"] = (base64.b64encode(b"h" * 32).decode(), 8, 1)
    pending = PendingRunnerResync(
        "rrs_" + "a" * 32, "heartbeat", "run",
        base64.b64encode(b"c" * 32).decode(), base64.b64encode(b"s" * 32).decode(),
        8, 2_000, 1,
    )
    failures = []
    control = threading.Thread(target=lambda: client.heartbeat(
        run_id="run", operational_projection=operational_projection("claimed"),
    ))
    recovery = threading.Thread(target=lambda: _capture(failures, client.complete_resync, pending))
    control.start()
    assert started.wait(1)
    recovery.start()
    assert len(transport.requests) == 1
    release.set()
    control.join(1); recovery.join(1)
    assert failures == []
    assert client._chains["heartbeat:run"] == (recovered_nonce, 9, 2)


def test_rotation_install_serializes_behind_inflight_claim_and_wins_generation():
    started, release = threading.Event(), threading.Event()

    class BlockingClaimTransport(Transport):
        def post(self, path, *, headers, body):
            self.requests.append((path, dict(headers), body))
            started.set()
            assert release.wait(1)
            return 204, {
                "X-Heel-Runner-Next-Nonce": base64.b64encode(b"o" * 32).decode(),
            }, None

    transport, signer = BlockingClaimTransport(), Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(),
    )
    rotated_nonce = base64.b64encode(b"r" * 32).decode()
    activation = {
        "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
        "runner_id": "runner", "initial_claim_nonce": rotated_nonce,
        "initial_claim_sequence": 7, "initial_claim_generation": 3,
    }
    failures = []
    control = threading.Thread(target=client.claim)
    rotation = threading.Thread(target=lambda: _capture(
        failures, client.install_rotation_claim, activation,
    ))
    control.start()
    assert started.wait(1)
    rotation.start()
    release.set()
    control.join(1); rotation.join(1)
    assert failures == []
    assert client._chains["claim"] == (rotated_nonce, 7, 3)


def _capture(failures, method, *args):
    try:
        method(*args)
    except BaseException as exc:
        failures.append(exc)


def test_resync_signs_its_own_closed_envelopes_and_installs_recovered_sequence():
    signer, transport = Signer(), Transport()
    transport.responses = [
        (200, {}, {"schema_version": "heel.runner-resync-challenge.v2", "challenge_id": "rrs_" + "a" * 32,
                    "chain": {"operation": "heartbeat", "run_id": "run"},
                    "server_challenge_b64": base64.b64encode(b"s" * 32).decode(), "next_sequence": 8,
                    "generation": 4, "expires_at_ms": 2000}),
        (200, {}, {"schema_version": "heel.runner-resync-completed.v2", "chain": {"operation": "heartbeat", "run_id": "run"},
                    "next_sequence": 8, "next_nonce_b64": base64.b64encode(b"n" * 32).decode(),
                    "generation": 5, "expires_at_ms": 2000}),
    ]
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
                                 clock=lambda: 1000, transport=transport, nonce_source=NonceSource(),
                                 resync_random_source=lambda count: b"c" * count)
    with client._state_lock:
        client._tracked_runs.add("run")
    pending = client.start_resync(operation="heartbeat", run_id="run")
    assert pending.next_sequence == 8 and pending.generation == 4
    path, headers, body = transport.requests[0]
    assert path.endswith("/resync/start")
    assert set(headers) == {"Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature"}
    assert body == canonical_bytes({"schema_version": "heel.runner-resync-start.v2",
                                    "chain": {"operation": "heartbeat", "run_id": "run"},
                                    "client_nonce_b64": base64.b64encode(b"c" * 32).decode()})
    expected = {"schema_version": "heel.runner-resync-start-proof.v2", "workspace_id": "ws", "runner_id": "runner", "key_id": signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000}
    assert signer.payloads[-1] == b"heel.runner-resync-start-pop.v2\0" + canonical_bytes(expected)
    recovered = client.complete_resync(pending)
    assert recovered.next_sequence == 8 and recovered.generation == 5
    complete_path, _, complete_body = transport.requests[1]
    expected_complete = {"schema_version": "heel.runner-resync-complete-proof.v2", "workspace_id": "ws", "runner_id": "runner", "key_id": signer.key_id, "method": "POST", "path": complete_path, "body_sha256": hashlib.sha256(complete_body).hexdigest(), "timestamp_ms": 1000}
    assert signer.payloads[-1] == b"heel.runner-resync-complete-pop.v2\0" + canonical_bytes(expected_complete)
    assert canonical_bytes({"schema_version": "heel.runner-resync-complete.v2", "challenge_id": pending.challenge_id,
                            "chain": {"operation": "heartbeat", "run_id": "run"},
                            "client_nonce_b64": pending.client_nonce_b64,
                            "server_challenge_b64": pending.server_challenge_b64,
                            "generation": 4}) == complete_body
    client.heartbeat(run_id="run", operational_projection=operational_projection("claimed"))
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "8"
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == base64.b64encode(b"n" * 32).decode()


def test_resync_generation_install_is_monotonic_and_idempotent():
    chain = {"operation": "heartbeat", "run_id": "run"}
    nonce = base64.b64encode(b"n" * 32).decode()
    other = base64.b64encode(b"x" * 32).decode()
    completed = lambda generation, value=nonce: (200, {}, {
        "schema_version": "heel.runner-resync-completed.v2", "chain": chain,
        "next_sequence": 8, "next_nonce_b64": value, "generation": generation,
        "expires_at_ms": 2000,
    })
    transport, signer = Transport(), Signer()
    transport.responses = [completed(5), completed(5), completed(5, other), completed(4, other), completed(7, other)]
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner",
                                 signer=signer, clock=lambda: 1000, transport=transport,
                                 nonce_source=NonceSource())
    with client._state_lock:
        client._tracked_runs.add("run")
    pending = PendingRunnerResync("rrs_" + "a" * 32, "heartbeat", "run",
                                  base64.b64encode(b"c" * 32).decode(),
                                  base64.b64encode(b"s" * 32).decode(), 8, 2000, 4)
    assert client.complete_resync(pending).generation == 5
    assert client.complete_resync(pending).generation == 5
    with pytest.raises(ValueError):
        client.complete_resync(pending)
    lower = PendingRunnerResync(pending.challenge_id, pending.operation, pending.run_id,
                                pending.client_nonce_b64, pending.server_challenge_b64,
                                pending.next_sequence, pending.expires_at_ms, 3)
    with pytest.raises(ValueError):
        client.complete_resync(lower)
    with pytest.raises(ValueError):
        client.complete_resync(pending)  # generation seven is not pending generation plus one.
    client.heartbeat(run_id="run", operational_projection=operational_projection("claimed"))
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == nonce
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "8"


def test_rotation_v2_installs_consumed_claim_state_without_resetting_sequence_or_generation():
    transport, signer, nonces = Transport(), Signer(), NonceSource()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner",
                                 signer=signer, clock=lambda: 1000, transport=transport,
                                 nonce_source=nonces)
    client.claim()
    client.claim()
    rotated_nonce = base64.b64encode(b"r" * 32).decode()
    response = {
        "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
        "runner_id": "runner", "initial_claim_nonce": rotated_nonce,
        "initial_claim_sequence": 7, "initial_claim_generation": 3,
    }
    activated = client.install_rotation_claim(response)
    assert activated == RunnerRotationActivated(
        "heel.runner-rotation-activated.v2", "ws", "runner", rotated_nonce, 7, 3,
    )
    client.claim()
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == rotated_nonce
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "7"


def test_rotation_claim_install_rejects_v1_invalid_and_nonmonotonic_responses_without_mutation():
    transport, signer = Transport(), Signer()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner",
                                 signer=signer, clock=lambda: 1000, transport=transport,
                                 nonce_source=NonceSource())
    first_nonce = base64.b64encode(b"a" * 32).decode()
    response = {
        "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
        "runner_id": "runner", "initial_claim_nonce": first_nonce,
        "initial_claim_sequence": 9, "initial_claim_generation": 4,
    }
    assert client.install_rotation_claim(response).initial_claim_generation == 4
    assert client.install_rotation_claim(dict(response)) == RunnerRotationActivated(
        "heel.runner-rotation-activated.v2", "ws", "runner", first_nonce, 9, 4,
    )
    invalid = [
        {**response, "schema_version": "heel.runner-rotation-activated.v1"},
        {**response, "extra": "closed"},
        {**response, "workspace_id": "other"},
        {**response, "initial_claim_nonce": "not-base64"},
        {**response, "initial_claim_sequence": True},
        {**response, "initial_claim_generation": 3},
        {**response, "initial_claim_nonce": base64.b64encode(b"b" * 32).decode()},
        {**response, "initial_claim_sequence": 10},
    ]
    for candidate in invalid:
        with pytest.raises(ValueError):
            client.install_rotation_claim(candidate)
    newer = {**response, "initial_claim_nonce": base64.b64encode(b"n" * 32).decode(),
             "initial_claim_sequence": 12, "initial_claim_generation": 5}
    assert client.install_rotation_claim(newer).initial_claim_generation == 5
    client.claim()
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == newer["initial_claim_nonce"]
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "12"
