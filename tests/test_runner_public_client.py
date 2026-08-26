import base64
import copy
import hashlib
import inspect
import json
from pathlib import Path
import pickle
import tempfile
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import OPERATIONAL_RUN_SCHEMA, canonical_bytes, canonical_digest
from heel.crypto import ed25519_key_id
from heel.runner.control_client import _RunGuard, PendingRunnerResync, RunnerControlClient, RunnerRotationActivated
from heel.runner.identity import (
    RunnerIdentity, SecureSigner,
    bind_runner_identity,
    create_runner_pairing_material,
)
from heel.runner.runtime import RunnerRuntimeState
from heel.runner.store import RunnerStore


RUN_ID = "crun_" + "a" * 32


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


class RotationSigner(SecureSigner):
    """Independent deterministic key material for local rotation journal tests."""

    def __init__(self, seed: bytes):
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload):
        return self._private_key.sign(payload)


def _rotation_identity(signer, *, version: str) -> RunnerIdentity:
    return RunnerIdentity(
        runner_id="runner", workspace_id="ws", runner_version=version,
        adapter_versions={"http": "1"}, public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=signer.key_id,
        pairing_phrase=(),
    )


class RotationSignerProvider:
    def __init__(self, values):
        self.values = dict(values)
        self.loaded = []
        self.created = []

    def load_existing(self, label):
        self.loaded.append(label)
        if label not in self.values:
            raise RuntimeError("runner signing identity is unavailable")
        return self.values[label]

    def create_new(self, label):
        self.created.append(label)
        raise AssertionError("rotation recovery must never create a signer")


def _complete_v3_pairing(root: Path, signer: SecureSigner, *, suffix: str):
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1", adapters={"http": "1"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.executable_exchange_request("invitation")
    pending = {
        "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": "pending_" + suffix * 32,
        "runner_id": "runr_" + suffix * 32, "fingerprint": material.fingerprint, "status": "pending",
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        "control_protocol": "heel.runner-control.v2",
        "pairing_exchange_digest": hashlib.sha256(canonical_bytes(exchange)).hexdigest(),
    }
    store = RunnerStore(root)
    activation = material.prepare_executable_activation(
        pending, store=store, now_ms=10, random_source=lambda count: b"n" * count,
    )
    response = {
        "schema_version": "heel.runner-pairing-activated.v3", "workspace_id": "ws",
        "runner_id": pending["runner_id"], "runner_key_id": signer.key_id,
        "pairing_exchange_digest": pending["pairing_exchange_digest"],
        "initial_claim_nonce": base64.b64encode(b"s" * 32).decode(),
        "initial_claim_sequence": 1, "initial_claim_generation": 0,
        "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
        "control_protocol": "heel.runner-control.v2", "activated_at_ms": 11,
    }
    identity = store.accept_pairing_activation(activation, response, now_ms=11)
    runtime_path = root / "runner" / "runtime.sqlite3"
    runtime = RunnerRuntimeState(runtime_path, identity, signer)
    assert store.finish_pairing_activation(runtime) == identity
    return store, identity, runtime, runtime_path


def _accepted_local_rotation(root: Path, *, suffix: str):
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    store, old_identity, _runtime, runtime_path = _complete_v3_pairing(root, old_signer, suffix=suffix)
    new_identity = RunnerIdentity(
        runner_id=old_identity.runner_id, workspace_id=old_identity.workspace_id, runner_version="2",
        adapter_versions={"http": "1"}, public_key_b64=base64.b64encode(new_signer.public_key).decode(),
        fingerprint=hashlib.sha256(new_signer.public_key).hexdigest(), key_id=new_signer.key_id,
        pairing_phrase=old_identity.pairing_phrase,
    )
    pending = {
        "schema_version": "heel.runner-rotation-activation-challenge.v1",
        "pairing_id": "rotate_" + suffix * 32,
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
    }
    prepared = store.prepare_rotation_activation(
        pending, old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-2", now_ms=20,
    )
    store.accept_rotation_activation(
        prepared,
        {
            "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
            "runner_id": old_identity.runner_id,
            "initial_claim_nonce": base64.b64encode(b"r" * 32).decode(),
            "initial_claim_sequence": 2, "initial_claim_generation": 1,
        },
        now_ms=21,
    )
    return store, old_identity, old_signer, new_identity, new_signer, prepared, runtime_path


class Transport:
    def __init__(self): self.requests = []; self.responses = []
    def post(self, path, *, headers, body):
        self.requests.append((path, dict(headers), body))
        if self.responses:
            return self.responses.pop(0)
        response_headers = {
            "X-Heel-Runner-Next-Nonce": base64.b64encode(
                bytes([len(self.requests) % 256]) * 32,
            ).decode(),
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
        "schema_version": OPERATIONAL_RUN_SCHEMA, "run_id": RUN_ID, "grant_id": "grant",
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
        return base64.b64encode(hashlib.sha256(repr(key).encode("utf-8")).digest()).decode("ascii")


def _runtime(signer, *, workspace_id="ws", runner_id="runner"):
    root = Path(tempfile.mkdtemp(prefix="heel-runtime-"))
    identity = RunnerIdentity(
        runner_id=runner_id, workspace_id=workspace_id, runner_version="test",
        adapter_versions={}, public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=signer.key_id,
        pairing_phrase=(),
    )
    runtime = RunnerRuntimeState(root / "runtime.sqlite3", identity, signer)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"p" * 32).decode(),
        next_sequence=1, generation=0, now_ms=0,
    )
    return runtime


def activate_claimed_run(client, run_id: str, *, states=None, generation=0, sequence=1):
    nonce = base64.b64encode(b"n" * 32).decode()
    with client._state_lock:
        client._tracked_runs.add(run_id)
        client._run_guards[run_id] = _RunGuard(threading.Lock(), object())
        for operation in states or ("heartbeat", "progress", "result", "stop-ack"):
            client._chains[f"{operation}:{run_id}"] = (nonce, sequence, generation)
            client.runtime.install_chain(
                operation=operation, run_id=run_id, next_nonce_b64=nonce,
                next_sequence=sequence, generation=generation, now_ms=1,
            )


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


def test_pairing_material_emits_a_closed_v3_executable_exchange_without_changing_v2():
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    assert material.exchange_request("invitation")["schema_version"] == "heel.runner-pairing-exchange.v2"
    assert material.executable_exchange_request("invitation") == {
        "schema_version": "heel.runner-pairing-exchange.v3",
        "invitation_token": "invitation",
        "public_key_b64": base64.b64encode(signer.public_key).decode(),
        "pairing_phrase": " ".join(material.pairing_phrase),
        "display_name": "Runner One",
        "runner_version": "1.0",
        "adapters": {"http": "1.0"},
        "control_protocol": "heel.runner-control.v2",
    }


def test_v3_pairing_journal_installs_the_server_claim_cursor_before_it_is_executable(tmp_path):
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.executable_exchange_request("invitation")
    pending = {
        "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": "pending_" + "a" * 32,
        "runner_id": "runr_" + "a" * 32, "fingerprint": material.fingerprint, "status": "pending",
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        "control_protocol": "heel.runner-control.v2",
        "pairing_exchange_digest": hashlib.sha256(canonical_bytes(exchange)).hexdigest(),
    }
    store = RunnerStore(tmp_path / "home")
    activation = material.prepare_executable_activation(
        pending, store=store, now_ms=10, random_source=lambda count: b"n" * count,
    )
    assert activation.request["schema_version"] == "heel.runner-pairing-activate.v3"
    assert (tmp_path / "home" / "runner" / "pairing-activation.json").is_file()
    response = {
        "schema_version": "heel.runner-pairing-activated.v3", "workspace_id": "ws",
        "runner_id": pending["runner_id"], "runner_key_id": signer.key_id,
        "pairing_exchange_digest": pending["pairing_exchange_digest"],
        "initial_claim_nonce": base64.b64encode(b"s" * 32).decode(),
        "initial_claim_sequence": 1, "initial_claim_generation": 0,
        "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
        "control_protocol": "heel.runner-control.v2", "activated_at_ms": 11,
    }
    identity = store.accept_pairing_activation(activation, response, now_ms=11)
    runtime = RunnerRuntimeState(tmp_path / "home" / "runner" / "runtime.sqlite3", identity, signer)
    assert store.finish_pairing_activation(runtime) == identity
    cursor = runtime.load_chain("claim", None)
    assert cursor is not None and cursor.next_nonce_b64 == response["initial_claim_nonce"]
    assert cursor.next_sequence == 1 and cursor.generation == 0
    assert not (tmp_path / "home" / "runner" / "pairing-activation.json").exists()
    assert (tmp_path / "home" / "runner" / "paired-identity.json").is_file()


def test_v3_accepted_pairing_journal_recovers_the_cursor_without_reissuing_activation(tmp_path):
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.executable_exchange_request("invitation")
    pending = {
        "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": "pending_" + "b" * 32,
        "runner_id": "runr_" + "b" * 32, "fingerprint": material.fingerprint, "status": "pending",
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        "control_protocol": "heel.runner-control.v2",
        "pairing_exchange_digest": hashlib.sha256(canonical_bytes(exchange)).hexdigest(),
    }
    root = tmp_path / "home"
    store = RunnerStore(root)
    activation = material.prepare_executable_activation(
        pending, store=store, now_ms=10, random_source=lambda count: b"n" * count,
    )
    response = {
        "schema_version": "heel.runner-pairing-activated.v3", "workspace_id": "ws",
        "runner_id": pending["runner_id"], "runner_key_id": signer.key_id,
        "pairing_exchange_digest": pending["pairing_exchange_digest"],
        "initial_claim_nonce": base64.b64encode(b"s" * 32).decode(),
        "initial_claim_sequence": 1, "initial_claim_generation": 0,
        "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
        "control_protocol": "heel.runner-control.v2", "activated_at_ms": 11,
    }
    store.accept_pairing_activation(activation, response, now_ms=11)
    restarted = RunnerStore(root)
    identity = restarted.recover_pairing_activation(
        material, runtime_path=root / "runner" / "runtime.sqlite3",
    )
    assert identity is not None and identity.runner_id == pending["runner_id"]
    runtime = RunnerRuntimeState(root / "runner" / "runtime.sqlite3", identity, signer)
    assert runtime.load_chain("claim", None).next_nonce_b64 == response["initial_claim_nonce"]
    assert not (root / "runner" / "pairing-activation.json").exists()


def test_v3_prepared_pairing_recovery_binds_the_signed_runner_before_accepting_response(tmp_path):
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.executable_exchange_request("invitation")
    runner_a, runner_b = "runr_" + "a" * 32, "runr_" + "b" * 32
    pending = {
        "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": "pending_" + "c" * 32,
        "runner_id": runner_a, "fingerprint": material.fingerprint, "status": "pending",
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        "control_protocol": "heel.runner-control.v2",
        "pairing_exchange_digest": hashlib.sha256(canonical_bytes(exchange)).hexdigest(),
    }
    root = tmp_path / "home"
    RunnerStore(root)
    material.prepare_executable_activation(
        pending, store=RunnerStore(root), now_ms=10, random_source=lambda count: b"n" * count,
    )
    journal_path = root / "runner" / "pairing-activation.json"
    original = journal_path.read_bytes()
    assert json.loads(original)["runner_id"] == runner_a
    restarted = RunnerStore(root)
    recovered = restarted.recover_pairing_activation(
        material, runtime_path=root / "runner" / "runtime.sqlite3",
    )
    assert recovered is not None and recovered.pending["runner_id"] == runner_a

    def response_for(runner_id):
        return {
            "schema_version": "heel.runner-pairing-activated.v3", "workspace_id": "ws",
            "runner_id": runner_id, "runner_key_id": signer.key_id,
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "initial_claim_nonce": base64.b64encode(b"s" * 32).decode(),
            "initial_claim_sequence": 1, "initial_claim_generation": 0,
            "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
            "control_protocol": "heel.runner-control.v2", "activated_at_ms": 11,
        }

    with pytest.raises(ValueError):
        restarted.accept_pairing_activation(recovered, response_for(runner_b), now_ms=11)
    assert journal_path.read_bytes() == original
    assert not (root / "runner" / "paired-identity.json").exists()
    identity = restarted.accept_pairing_activation(recovered, response_for(runner_a), now_ms=11)
    assert identity.runner_id == runner_a


def test_v3_prepared_pairing_recovery_rejects_a_tampered_signed_runner_id(tmp_path):
    signer = Signer()
    material = create_runner_pairing_material(
        display_name="Runner One", runner_version="1.0", adapters={"http": "1.0"},
        signer=signer, random_source=lambda count: bytes(range(count)),
    )
    exchange = material.executable_exchange_request("invitation")
    pending = {
        "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": "pending_" + "d" * 32,
        "runner_id": "runr_" + "d" * 32, "fingerprint": material.fingerprint, "status": "pending",
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        "control_protocol": "heel.runner-control.v2",
        "pairing_exchange_digest": hashlib.sha256(canonical_bytes(exchange)).hexdigest(),
    }
    root = tmp_path / "home"
    store = RunnerStore(root)
    material.prepare_executable_activation(
        pending, store=store, now_ms=10, random_source=lambda count: b"n" * count,
    )
    journal_path = root / "runner" / "pairing-activation.json"
    journal = json.loads(journal_path.read_text())
    assert journal["runner_id"] == pending["runner_id"]
    journal["runner_id"] = "runr_" + "e" * 32
    journal_path.write_text(json.dumps(journal, separators=(",", ":")))
    with pytest.raises(ValueError):
        RunnerStore(root).recover_pairing_activation(
            material, runtime_path=root / "runner" / "runtime.sqlite3",
        )
    assert not (root / "runner" / "paired-identity.json").exists()


def test_local_rotation_journal_is_dual_signed_and_never_serializes_the_new_signer(tmp_path):
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    old_identity = _rotation_identity(old_signer, version="1")
    new_identity = _rotation_identity(new_signer, version="2")
    store = RunnerStore(tmp_path / "home")
    pending = {
        "schema_version": "heel.runner-rotation-activation-challenge.v1",
        "pairing_id": "rotate_" + "a" * 32,
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
    }

    prepared = store.prepare_rotation_activation(
        pending, old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-2", now_ms=10,
    )

    journal_path = tmp_path / "home" / "runner" / "rotation-activation.json"
    journal = json.loads(journal_path.read_text())
    assert set(journal) == {
        "schema_version", "state", "pairing_id", "old_identity", "new_identity",
        "new_signer_label", "activation_challenge", "activation_request", "activation_response",
        "created_at_ms", "updated_at_ms", "journal_digest", "old_signing_key_id",
        "old_signature_b64", "new_signing_key_id", "new_signature_b64",
    }
    assert journal["state"] == "prepared"
    assert journal["new_signer_label"] == "heel-rotation-key-2"
    assert "_new_signer" not in repr(prepared)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(prepared)

    accepted = store.accept_rotation_activation(
        prepared,
        {
            "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
            "runner_id": "runner", "initial_claim_nonce": base64.b64encode(b"r" * 32).decode(),
            "initial_claim_sequence": 2, "initial_claim_generation": 1,
        },
        now_ms=11,
    )

    final_journal = json.loads(journal_path.read_text())
    assert final_journal["state"] == "accepted"
    assert accepted.new_signer_label == "heel-rotation-key-2"
    assert final_journal["old_signing_key_id"] == old_identity.key_id
    assert final_journal["new_signing_key_id"] == new_identity.key_id


def test_local_rotation_journal_rejects_a_tampered_signer_label_without_accepting(tmp_path):
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    old_identity = _rotation_identity(old_signer, version="1")
    new_identity = _rotation_identity(new_signer, version="2")
    store = RunnerStore(tmp_path / "home")
    pending = {
        "schema_version": "heel.runner-rotation-activation-challenge.v1",
        "pairing_id": "rotate_" + "b" * 32,
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
    }
    prepared = store.prepare_rotation_activation(
        pending, old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-2", now_ms=10,
    )
    journal_path = tmp_path / "home" / "runner" / "rotation-activation.json"
    journal = json.loads(journal_path.read_text())
    journal["new_signer_label"] = "heel-rotation-key-tampered"
    journal_path.write_text(json.dumps(journal, separators=(",", ":")))

    with pytest.raises(ValueError, match="rotation activation journal"):
        store.accept_rotation_activation(
            prepared,
            {
                "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
                "runner_id": "runner", "initial_claim_nonce": base64.b64encode(b"r" * 32).decode(),
                "initial_claim_sequence": 2, "initial_claim_generation": 1,
            },
            now_ms=11,
        )
    assert json.loads(journal_path.read_text())["state"] == "prepared"


def test_accepted_rotation_recovery_loads_the_named_signer_then_finishes_before_client_creation(tmp_path):
    root = tmp_path / "home"
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    store, old_identity, _runtime, runtime_path = _complete_v3_pairing(root, old_signer, suffix="c")
    new_identity = RunnerIdentity(
        runner_id=old_identity.runner_id, workspace_id=old_identity.workspace_id, runner_version="2",
        adapter_versions={"http": "1"}, public_key_b64=base64.b64encode(new_signer.public_key).decode(),
        fingerprint=hashlib.sha256(new_signer.public_key).hexdigest(), key_id=new_signer.key_id,
        pairing_phrase=old_identity.pairing_phrase,
    )
    pending = {
        "schema_version": "heel.runner-rotation-activation-challenge.v1",
        "pairing_id": "rotate_" + "c" * 32,
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
    }
    prepared = store.prepare_rotation_activation(
        pending, old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-2", now_ms=20,
    )
    store.accept_rotation_activation(
        prepared,
        {
            "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
            "runner_id": old_identity.runner_id,
            "initial_claim_nonce": base64.b64encode(b"r" * 32).decode(),
            "initial_claim_sequence": 2, "initial_claim_generation": 1,
        },
        now_ms=21,
    )

    provider = RotationSignerProvider({"heel-rotation-key-2": new_signer})
    recovered = RunnerStore(root).recover_rotation_activation(
        old_identity=old_identity, old_signer=old_signer, signer_provider=provider,
        runtime_path=runtime_path,
    )

    assert recovered == new_identity
    assert provider.loaded == ["heel-rotation-key-2"] and provider.created == []
    assert not (root / "runner" / "rotation-activation.json").exists()
    paired = json.loads((root / "runner" / "paired-identity.json").read_text())
    assert paired["identity"]["runner_key_id"] == new_identity.key_id
    assert paired["signer_label"] == "heel-rotation-key-2"
    runtime = RunnerRuntimeState(runtime_path, new_identity, new_signer)
    cursor = runtime.load_chain("claim", None)
    assert cursor is not None and (cursor.next_sequence, cursor.generation) == (2, 1)


def test_prepared_rotation_recovery_never_creates_a_missing_named_signer(tmp_path):
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    old_identity = _rotation_identity(old_signer, version="1")
    new_identity = _rotation_identity(new_signer, version="2")
    root = tmp_path / "home"
    RunnerStore(root).prepare_rotation_activation(
        {
            "schema_version": "heel.runner-rotation-activation-challenge.v1",
            "pairing_id": "rotate_" + "d" * 32,
            "activation_challenge": base64.b64encode(b"c" * 32).decode(),
        },
        old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-missing", now_ms=10,
    )
    provider = RotationSignerProvider({})

    with pytest.raises(ValueError, match="signing identity is unavailable"):
        RunnerStore(root).recover_rotation_activation(
            old_identity=old_identity, old_signer=old_signer, signer_provider=provider,
            runtime_path=root / "runner" / "runtime.sqlite3",
        )

    assert provider.loaded == ["heel-rotation-key-missing"] and provider.created == []


def test_rotation_recovery_rejects_new_selector_with_old_runtime_without_mutation(tmp_path):
    root = tmp_path / "home"
    old_signer = RotationSigner(b"o" * 32)
    new_signer = RotationSigner(b"n" * 32)
    store, old_identity, _runtime, runtime_path = _complete_v3_pairing(root, old_signer, suffix="e")
    new_identity = RunnerIdentity(
        runner_id=old_identity.runner_id, workspace_id=old_identity.workspace_id, runner_version="2",
        adapter_versions={"http": "1"}, public_key_b64=base64.b64encode(new_signer.public_key).decode(),
        fingerprint=hashlib.sha256(new_signer.public_key).hexdigest(), key_id=new_signer.key_id,
        pairing_phrase=old_identity.pairing_phrase,
    )
    pending = {
        "schema_version": "heel.runner-rotation-activation-challenge.v1",
        "pairing_id": "rotate_" + "e" * 32,
        "activation_challenge": base64.b64encode(b"c" * 32).decode(),
    }
    prepared = store.prepare_rotation_activation(
        pending, old_identity=old_identity, old_signer=old_signer,
        new_identity=new_identity, new_signer=new_signer,
        new_signer_label="heel-rotation-key-2", now_ms=20,
    )
    store.accept_rotation_activation(
        prepared,
        {
            "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": "ws",
            "runner_id": old_identity.runner_id,
            "initial_claim_nonce": base64.b64encode(b"r" * 32).decode(),
            "initial_claim_sequence": 2, "initial_claim_generation": 1,
        },
        now_ms=21,
    )
    old_paired = json.loads((root / "runner" / "paired-identity.json").read_text())
    forged_new_selector = store._pairing_signed_value(
        {
            "schema_version": "heel.local-paired-runner.v1",
            "identity": {
                "runner_id": new_identity.runner_id, "workspace_id": new_identity.workspace_id,
                "runner_version": new_identity.runner_version, "adapter_versions": new_identity.adapter_versions,
                "public_key_b64": new_identity.public_key_b64, "fingerprint": new_identity.fingerprint,
                "runner_key_id": new_identity.key_id,
            },
            "pairing_protocol_version": 3, "control_protocol": "heel.runner-control.v2",
            "pairing_id": old_paired["pairing_id"],
            "pairing_exchange_digest": old_paired["pairing_exchange_digest"],
            "activated_at_ms": old_paired["activated_at_ms"],
            "activation_response_digest": old_paired["activation_response_digest"],
            "signer_label": "heel-rotation-key-2",
        },
        signer=new_signer, domain=b"heel.local-paired-runner.v1\0", digest_field="record_digest",
    )
    (root / "runner" / "paired-identity.json").write_text(
        json.dumps(forged_new_selector, separators=(",", ":")),
    )

    with pytest.raises(ValueError, match="paired runner identity requires recovery"):
        RunnerStore(root).recover_rotation_activation(
            old_identity=old_identity, old_signer=old_signer,
            signer_provider=RotationSignerProvider({"heel-rotation-key-2": new_signer}),
            runtime_path=runtime_path,
        )
    cursor = RunnerRuntimeState(runtime_path, old_identity, old_signer).load_chain("claim", None)
    assert cursor is not None and (cursor.next_sequence, cursor.generation) == (1, 0)


@pytest.mark.parametrize("boundary", ("selector", "journal_unlink"))
def test_rotation_recovery_completes_only_the_durable_suffix_after_each_local_crash(tmp_path, monkeypatch, boundary):
    import heel.runner.store as runner_store_module

    root = tmp_path / "home"
    store, old_identity, old_signer, new_identity, new_signer, prepared, runtime_path = _accepted_local_rotation(
        root, suffix="f" if boundary == "selector" else "a",
    )
    original_write = runner_store_module._write_json
    original_unlink = runner_store_module.os.unlink

    if boundary == "selector":
        def fail_selector(directory_fd, filename, value):
            if filename == "paired-identity.json" and value.get("identity", {}).get("runner_key_id") == new_identity.key_id:
                raise OSError("injected selector write fault")
            return original_write(directory_fd, filename, value)
        monkeypatch.setattr(runner_store_module, "_write_json", fail_selector)
    else:
        def fail_unlink(filename, *args, **kwargs):
            if filename == "rotation-activation.json":
                raise OSError("injected rotation journal unlink fault")
            return original_unlink(filename, *args, **kwargs)
        monkeypatch.setattr(runner_store_module.os, "unlink", fail_unlink)

    with pytest.raises(OSError, match="injected"):
        store.finish_rotation_activation(
            prepared, RunnerRuntimeState(runtime_path, old_identity, old_signer),
        )

    monkeypatch.setattr(runner_store_module, "_write_json", original_write)
    monkeypatch.setattr(runner_store_module.os, "unlink", original_unlink)
    provider = RotationSignerProvider({"heel-rotation-key-2": new_signer})
    assert RunnerStore(root).recover_rotation_activation(
        old_identity=old_identity, old_signer=old_signer, signer_provider=provider,
        runtime_path=runtime_path,
    ) == new_identity
    assert not (root / "runner" / "rotation-activation.json").exists()
    cursor = RunnerRuntimeState(runtime_path, new_identity, new_signer).load_chain("claim", None)
    assert cursor is not None and (cursor.next_sequence, cursor.generation) == (2, 1)


def test_rotation_recovery_factory_boundary_never_constructs_a_live_control_client():
    source = inspect.getsource(RunnerStore.recover_rotation_activation)
    assert "RunnerControlClient" not in source and "RunnerCoordinator" not in source


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
                                 clock=lambda: 1000, transport=transport, nonce_source=nonces, runtime=_runtime(signer))
    client.claim()
    for method, projection in (
        (client.heartbeat, operational_projection("claimed")),
        (client.progress, operational_projection("running")),
        (client.result, operational_projection("terminal")),
        (client.stop_ack, operational_projection("stop_requested")),
    ):
        with pytest.raises(ValueError, match="active runner claim is required"):
            method(run_id=RUN_ID, operational_projection=projection)
    assert transport.requests[0][2] == b'{"schema_version":"heel.runner-claim-request.v1"}'
    assert len(transport.requests) == 1
    assert nonces.keys == []
    public = {name for name, method in vars(RunnerControlClient).items() if callable(method) and not name.startswith("_")}
    assert public == {"claim", "heartbeat", "progress", "result", "stop_ack",
                      "start_resync", "complete_resync", "install_rotation_claim",
                      "upload_findings", "list_contexts", "claim_context",
                      "submit_context_approval_projection"}
    assert all(parameter.kind is not inspect.Parameter.VAR_KEYWORD for method in (
        RunnerControlClient.claim, RunnerControlClient.heartbeat, RunnerControlClient.progress,
        RunnerControlClient.result, RunnerControlClient.stop_ack,
    ) for parameter in inspect.signature(method).parameters.values())


def test_control_client_requires_an_identity_pinned_runtime_backend():
    signer = Signer()
    with pytest.raises(TypeError, match="authenticated runner runtime state is required"):
        RunnerControlClient(
            origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
            clock=lambda: 1_000, transport=Transport(), nonce_source=NonceSource(),
        )


def test_control_claim_commits_its_authenticated_cursor_to_runtime_state():
    signer, transport, nonces = Signer(), Transport(), NonceSource()
    runtime = _runtime(signer)
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1_000, transport=transport, nonce_source=nonces, runtime=runtime,
    )

    client.claim()

    cursor = runtime.load_chain("claim", None)
    assert cursor is not None
    assert cursor.next_sequence == 2
    assert runtime.load_pending_calls() == ()


def test_control_diagnostics_are_bounded_frozen_and_sensitive_field_free():
    signer, transport, nonces = Signer(), Transport(), NonceSource()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1000, transport=transport, nonce_source=nonces, runtime=_runtime(signer),
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


def test_terminal_disclosures_do_not_consume_active_run_capacity_without_findings():
    signer, nonces = Signer(), NonceSource()

    class CapacityTransport(Transport):
        def post(self, path, *, headers, body):
            status, response_headers, response = super().post(path, headers=headers, body=body)
            if response_headers["X-Heel-Runner-Next-Nonce"] == headers["X-Heel-Runner-Nonce"]:
                response_headers = {
                    **response_headers,
                    "X-Heel-Runner-Next-Nonce": base64.b64encode(b"z" * 32).decode(),
                }
            return status, response_headers, response

    transport = CapacityTransport()
    runtime = _runtime(signer)
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1_000, transport=transport, nonce_source=nonces, runtime=runtime,
    )

    def terminal_for(run_id):
        value = operational_projection("terminal")
        unsigned = {
            key: copy.deepcopy(item) for key, item in value.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        unsigned["run_id"] = run_id
        return {
            **unsigned, "projection_digest": canonical_digest(unsigned),
            "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode(),
        }

    first_run = None
    for index in range(1_000):
        run_id = f"crun_{index:032x}"
        terminal = terminal_for(run_id)
        activate_claimed_run(client, run_id)
        registered = client._register_runtime_local_terminal({
            "run_id": run_id, "project_id": "project", "grant_id": "grant",
            "approval_projection_digest": "b" * 64,
            "terminal_projection_digest": terminal["projection_digest"],
            "terminal_record_digest": hashlib.sha256(run_id.encode()).hexdigest(),
            "terminal_at_ms": 1, "retention_expires_at_ms": 10_000,
        })
        assert registered.state == "local_terminal"
        assert client.result(run_id=run_id, operational_projection=terminal)[0] == 200
        if index == 64:
            assert client._tracked_runs == set()
            assert not client._run_guards
        if index == 0:
            first_run = run_id

    assert first_run is not None
    assert client._tracked_runs == set() and not client._run_guards
    assert runtime.lease_terminal_disclosure(
        first_run, expected_project_id="project", expected_grant_id="grant",
        expected_approval_projection_digest="b" * 64, now_ms=1_000,
    ) is not None


def test_terminal_result_cannot_recreate_an_inflight_heartbeat_chain(tmp_path):
    started, release = threading.Event(), threading.Event()

    class BlockingHeartbeatTransport(Transport):
        def post(self, path, *, headers, body):
            self.requests.append((path, dict(headers), body))
            if path.endswith("/heartbeat"):
                started.set()
                assert release.wait(1)
                return 200, {
                    "X-Heel-Runner-Next-Nonce": base64.b64encode(b"h" * 32).decode(),
                }, {
                    "active": True, "runner_state": "active", "proof_state": "valid",
                    "proof_expires_at_ms": 2_000, "kill_switch_generation": 0,
                    "stop_reason": "none", "server_time_ms": 1_000,
                }
            return super().post(path, headers=headers, body=body)

    transport, signer = BlockingHeartbeatTransport(), Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1_000, transport=transport, nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    run_id = RUN_ID
    activate_claimed_run(client, run_id)

    def for_run(phase):
        value = operational_projection(phase)
        value["run_id"] = run_id
        unsigned = {
            key: item for key, item in value.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        value["projection_digest"] = canonical_digest(unsigned)
        value["signature_b64"] = base64.b64encode(
            Signer._private_key.sign(canonical_bytes(unsigned))
        ).decode()
        return value

    failures = []
    def call_heartbeat():
        try:
            client.heartbeat(
                run_id=run_id,
                operational_projection=for_run("claimed"),
            )
        except BaseException as exc:
            failures.append(exc)

    heartbeat = threading.Thread(target=call_heartbeat)
    result_failures = []

    def call_result():
        try:
            client.result(run_id=run_id, operational_projection=for_run("terminal"))
        except BaseException as exc:
            result_failures.append(exc)

    terminal = for_run("terminal")
    client.runtime.register_local_terminal(
        run_id=run_id, project_id=terminal["project_id"], grant_id=terminal["grant_id"],
        approval_projection_digest=terminal["approval_projection_digest"],
        terminal_projection_digest=terminal["projection_digest"],
        terminal_record_digest="d" * 64, terminal_at_ms=1, retention_expires_at_ms=2_000,
    )
    heartbeat.start()
    assert started.wait(1)
    result = threading.Thread(target=call_result)
    result.start()
    assert len(transport.requests) == 1
    release.set()
    heartbeat.join(1); result.join(1)

    assert failures == []
    assert result_failures == []
    assert f"heartbeat:{run_id}" not in client._chains


def test_duplicate_terminal_result_waiter_fails_before_second_transport():
    started, release = threading.Event(), threading.Event()

    class BlockingResultTransport(Transport):
        def post(self, path, *, headers, body):
            self.requests.append((path, dict(headers), body))
            if path.endswith("/result"):
                started.set()
                assert release.wait(1)
                return 200, {
                    "X-Heel-Runner-Next-Nonce": base64.b64encode(b"r" * 32).decode(),
                }, {
                    "schema_version": "heel.canary-run-status.v1", "run_id": RUN_ID,
                    "approval_id": "approval", "grant_id": "grant", "status": "terminal",
                    "execution_disposition": "completed", "error_category": "none",
                    "stop_reason": "none", "source_event_sequence": 1,
                    "quota_state": "reserved", "kill_switch_generation": 0,
                    "stop_generation": 0, "stop_deadline_ms": None,
                    "stop_acknowledged_at_ms": None, "stop_ack_late": False,
                }
            return super().post(path, headers=headers, body=body)

    transport, signer = BlockingResultTransport(), Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1_000, transport=transport, nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    activate_claimed_run(client, RUN_ID)
    terminal = operational_projection("terminal")
    terminal["run_id"] = RUN_ID
    unsigned = {
        key: value for key, value in terminal.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    terminal["projection_digest"] = canonical_digest(unsigned)
    terminal["signature_b64"] = base64.b64encode(
        Signer._private_key.sign(canonical_bytes(unsigned))
    ).decode()
    client.runtime.register_local_terminal(
        run_id=RUN_ID, project_id=terminal["project_id"], grant_id=terminal["grant_id"],
        approval_projection_digest=terminal["approval_projection_digest"],
        terminal_projection_digest=terminal["projection_digest"],
        terminal_record_digest="d" * 64, terminal_at_ms=1, retention_expires_at_ms=2_000,
    )
    failures = []

    def submit():
        try:
            client.result(run_id=RUN_ID, operational_projection=terminal)
        except BaseException as exc:
            failures.append(exc)

    first, second = threading.Thread(target=submit), threading.Thread(target=submit)
    first.start()
    assert started.wait(1)
    second.start()
    assert len(transport.requests) == 1
    release.set()
    first.join(1); second.join(1)

    assert len(transport.requests) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ValueError)
    assert "active runner claim is required" in str(failures[0])


def test_run_control_tracks_at_most_one_lifecycle_guard_per_active_run():
    signer = Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
        clock=lambda: 1000, transport=Transport(), nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    for ordinal in range(64):
        activate_claimed_run(client, f"crun_{ordinal:032x}")
    assert len(client._run_guards) == 64
    assert all(isinstance(guard, _RunGuard) for guard in client._run_guards.values())
    assert not hasattr(client, "_run_lock_stripes")


def test_terminal_result_retires_live_chains_into_a_durable_disclosure_state():
    signer, transport = Signer(), Transport()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    activate_claimed_run(client, RUN_ID)
    terminal = operational_projection("terminal")
    client.runtime.register_local_terminal(
        run_id=RUN_ID, project_id=terminal["project_id"], grant_id=terminal["grant_id"],
        approval_projection_digest=terminal["approval_projection_digest"],
        terminal_projection_digest=terminal["projection_digest"],
        terminal_record_digest="d" * 64, terminal_at_ms=1, retention_expires_at_ms=2_000,
    )

    assert client.result(run_id=RUN_ID, operational_projection=terminal)[0] == 200
    lease = client.runtime.lease_terminal_disclosure(
        RUN_ID, expected_project_id="project", expected_grant_id="grant",
        expected_approval_projection_digest="b" * 64, now_ms=1_000,
    )
    assert lease is not None
    assert RUN_ID not in client._tracked_runs
    assert not any(name.endswith(":" + RUN_ID) for name in client._chains)


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
                                 nonce_source=nonces, runtime=_runtime(signer))
    signer.payloads.clear()
    with pytest.raises(ValueError):
        getattr(client, method_name)(run_id=RUN_ID, operational_projection=copy.deepcopy(projection))
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
def test_every_public_control_operation_preserves_durable_pending_call_on_non_exact_response(
    method_name, projection, response,
):
    transport, signer = Transport(), Signer()
    transport.responses = [response]
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    if method_name != "claim":
        activate_claimed_run(client, RUN_ID)
    before_chains = dict(client._chains)
    with pytest.raises(ValueError):
        if method_name == "claim":
            client.claim()
        else:
            getattr(client, method_name)(
                run_id=RUN_ID, operational_projection=copy.deepcopy(projection),
            )
    assert client._chains == before_chains
    pending = client.runtime.load_pending_calls()
    assert len(pending) == 1
    assert pending[0].request_operation == method_name.replace("_", "-")
    cursor = client.runtime.load_chain(
        "claim" if method_name == "claim" else method_name.replace("_", "-"),
        None if method_name == "claim" else RUN_ID,
    )
    if method_name == "claim":
        assert cursor is not None and cursor.next_sequence == 1 and cursor.generation == 0
    else:
        assert cursor is not None
        assert (cursor.next_sequence, cursor.generation) == (1, 0)
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
                "chain": {"operation": "heartbeat", "run_id": RUN_ID},
                "next_sequence": 9, "next_nonce_b64": recovered_nonce,
                "expires_at_ms": 2_000, "generation": 2,
            }

    transport, signer = BlockingTransport(), Signer()
    client = RunnerControlClient(
        origin="https://control.example", workspace_id="ws", runner_id="runner",
        signer=signer, clock=lambda: 1000, transport=transport,
        nonce_source=NonceSource(), runtime=_runtime(signer),
    )
    heartbeat_nonce = base64.b64encode(b"h" * 32).decode()
    with client._state_lock:
        client._tracked_runs.add(RUN_ID)
        client._run_guards[RUN_ID] = _RunGuard(threading.Lock(), object())
        client._chains[f"heartbeat:{RUN_ID}"] = (heartbeat_nonce, 8, 1)
    client.runtime.install_chain(
        operation="heartbeat", run_id=RUN_ID, next_nonce_b64=heartbeat_nonce,
        next_sequence=8, generation=1, now_ms=1,
    )
    pending = PendingRunnerResync(
        "rrs_" + "a" * 32, "heartbeat", RUN_ID,
        base64.b64encode(b"c" * 32).decode(), base64.b64encode(b"s" * 32).decode(),
        8, 2_000, 1,
    )
    failures = []
    control = threading.Thread(target=lambda: client.heartbeat(
        run_id=RUN_ID, operational_projection=operational_projection("claimed"),
    ))
    recovery = threading.Thread(target=lambda: _capture(failures, client.complete_resync, pending))
    control.start()
    assert started.wait(1)
    recovery.start()
    assert len(transport.requests) == 1
    release.set()
    control.join(1); recovery.join(1)
    assert failures == []
    assert client._chains[f"heartbeat:{RUN_ID}"] == (recovered_nonce, 9, 2)
    cursor = client.runtime.load_chain("heartbeat", RUN_ID)
    assert cursor is not None
    assert (cursor.next_nonce_b64, cursor.next_sequence, cursor.generation) == (
        recovered_nonce, 9, 2,
    )


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
        nonce_source=NonceSource(), runtime=_runtime(signer),
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
                    "chain": {"operation": "heartbeat", "run_id": RUN_ID},
                    "server_challenge_b64": base64.b64encode(b"s" * 32).decode(), "next_sequence": 8,
                    "generation": 4, "expires_at_ms": 2000}),
        (200, {}, {"schema_version": "heel.runner-resync-completed.v2", "chain": {"operation": "heartbeat", "run_id": RUN_ID},
                    "next_sequence": 8, "next_nonce_b64": base64.b64encode(b"n" * 32).decode(),
                    "generation": 5, "expires_at_ms": 2000}),
    ]
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer,
                                 clock=lambda: 1000, transport=transport, nonce_source=NonceSource(),
                                 resync_random_source=lambda count: b"c" * count, runtime=_runtime(signer))
    activate_claimed_run(client, RUN_ID, states=("heartbeat",), generation=4)
    pending = client.start_resync(operation="heartbeat", run_id=RUN_ID)
    assert pending.next_sequence == 8 and pending.generation == 4
    path, headers, body = transport.requests[0]
    assert path.endswith("/resync/start")
    assert set(headers) == {"Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature"}
    assert body == canonical_bytes({"schema_version": "heel.runner-resync-start.v2",
                                    "chain": {"operation": "heartbeat", "run_id": RUN_ID},
                                    "client_nonce_b64": base64.b64encode(b"c" * 32).decode()})
    expected = {"schema_version": "heel.runner-resync-start-proof.v2", "workspace_id": "ws", "runner_id": "runner", "key_id": signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000}
    assert signer.payloads[-1] == b"heel.runner-resync-start-pop.v2\0" + canonical_bytes(expected)
    recovered = client.complete_resync(pending)
    assert recovered.next_sequence == 8 and recovered.generation == 5
    complete_path, _, complete_body = transport.requests[1]
    expected_complete = {"schema_version": "heel.runner-resync-complete-proof.v2", "workspace_id": "ws", "runner_id": "runner", "key_id": signer.key_id, "method": "POST", "path": complete_path, "body_sha256": hashlib.sha256(complete_body).hexdigest(), "timestamp_ms": 1000}
    assert signer.payloads[-1] == b"heel.runner-resync-complete-pop.v2\0" + canonical_bytes(expected_complete)
    assert canonical_bytes({"schema_version": "heel.runner-resync-complete.v2", "challenge_id": pending.challenge_id,
                            "chain": {"operation": "heartbeat", "run_id": RUN_ID},
                            "client_nonce_b64": pending.client_nonce_b64,
                            "server_challenge_b64": pending.server_challenge_b64,
                            "generation": 4}) == complete_body
    client.heartbeat(run_id=RUN_ID, operational_projection=operational_projection("claimed"))
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "8"
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == base64.b64encode(b"n" * 32).decode()


def test_resync_generation_install_is_monotonic_and_idempotent():
    chain = {"operation": "heartbeat", "run_id": RUN_ID}
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
                                 nonce_source=NonceSource(), runtime=_runtime(signer))
    activate_claimed_run(client, RUN_ID, states=("heartbeat",), generation=4)
    pending = PendingRunnerResync("rrs_" + "a" * 32, "heartbeat", RUN_ID,
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
    client.heartbeat(run_id=RUN_ID, operational_projection=operational_projection("claimed"))
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == nonce
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "8"


def test_rotation_v2_installs_consumed_claim_state_without_resetting_sequence_or_generation():
    transport, signer, nonces = Transport(), Signer(), NonceSource()
    client = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner",
                                 signer=signer, clock=lambda: 1000, transport=transport,
                                 nonce_source=nonces, runtime=_runtime(signer))
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
                                 nonce_source=NonceSource(), runtime=_runtime(signer))
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
