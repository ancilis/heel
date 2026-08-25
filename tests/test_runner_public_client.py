import base64
import hashlib
import inspect

import pytest

from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id
from heel.runner.control_client import RunnerControlClient
from heel.runner.identity import (
    SecureSigner,
    bind_runner_identity,
    create_runner_pairing_material,
)


def test_open_core_runner_package_exports_pairing_and_recovery_types():
    from heel.runner import (  # noqa: PLC0415 - checks the installed public facade.
        PendingRunnerResync, RecoveredRunnerChain, RunnerPairingMaterial,
        bind_runner_identity, create_runner_pairing_material,
    )
    assert all(item is not None for item in (PendingRunnerResync, RecoveredRunnerChain,
                                               RunnerPairingMaterial, bind_runner_identity,
                                               create_runner_pairing_material))


class Signer(SecureSigner):
    public_key = b"0123456789abcdef0123456789abcdef"
    key_id = ed25519_key_id(public_key)

    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return b"s" * 64


class Transport:
    def __init__(self): self.requests = []; self.responses = []
    def post(self, path, *, headers, body):
        self.requests.append((path, dict(headers), body))
        return self.responses.pop(0) if self.responses else (200, {"X-Heel-Runner-Next-Nonce": "next"})


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


def test_named_control_methods_emit_closed_bodies_and_separate_stop_ack_chain():
    signer, transport = Signer(), Transport()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
                                 clock=lambda: 1000, transport=transport, nonce_source=lambda cap: cap + "-nonce")
    projection = {"projection": "opaque"}
    client.claim()
    client.stop_ack(run_id="run", operational_projection=projection)
    assert transport.requests[0][2] == b'{"schema_version":"heel.runner-claim-request.v1"}'
    assert transport.requests[1][2] == canonical_bytes({"schema_version": "heel.runner-stop-ack-request.v1", "run_id": "run", "operational_projection": projection})
    assert transport.requests[1][1]["X-Heel-Runner-Nonce"] == "runner_heartbeat-nonce"
    assert transport.requests[1][1]["X-Heel-Runner-Sequence"] == "1"
    public = {name for name, method in vars(RunnerControlClient).items() if callable(method) and not name.startswith("_")}
    assert public == {"claim", "heartbeat", "progress", "result", "stop_ack", "retry_last", "start_resync", "complete_resync"}
    assert all(parameter.kind is not inspect.Parameter.VAR_KEYWORD for method in (
        RunnerControlClient.claim, RunnerControlClient.heartbeat, RunnerControlClient.progress,
        RunnerControlClient.result, RunnerControlClient.stop_ack,
    ) for parameter in inspect.signature(method).parameters.values())


def test_resync_signs_its_own_closed_envelopes_and_installs_recovered_sequence():
    signer, transport = Signer(), Transport()
    transport.responses = [
        (200, {}, {"schema_version": "heel.runner-resync-challenge.v1", "challenge_id": "rrs_" + "a" * 32,
                    "chain": {"operation": "heartbeat", "run_id": "run"},
                    "server_challenge_b64": base64.b64encode(b"s" * 32).decode(), "next_sequence": 8, "expires_at_ms": 2000}),
        (200, {}, {"schema_version": "heel.runner-resync-completed.v1", "chain": {"operation": "heartbeat", "run_id": "run"},
                    "next_sequence": 8, "next_nonce_b64": base64.b64encode(b"n" * 32).decode(), "expires_at_ms": 2000}),
    ]
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
                                 clock=lambda: 1000, transport=transport, nonce_source=lambda cap: cap + "-nonce",
                                 resync_random_source=lambda count: b"c" * count)
    pending = client.start_resync(operation="heartbeat", run_id="run")
    assert pending.next_sequence == 8
    path, headers, body = transport.requests[0]
    assert path.endswith("/resync/start")
    assert set(headers) == {"Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature"}
    expected = {"schema_version": "heel.runner-resync-start-proof.v1", "workspace_id": "ws", "runner_id": "runner", "key_id": signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000}
    assert signer.payloads[-1] == b"heel.runner-resync-start-pop.v1\0" + canonical_bytes(expected)
    recovered = client.complete_resync(pending)
    assert recovered.next_sequence == 8
    client.heartbeat(run_id="run", operational_projection={"projection": "opaque"})
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "8"
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == base64.b64encode(b"n" * 32).decode()
