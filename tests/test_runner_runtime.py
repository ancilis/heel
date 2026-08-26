from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id
from heel.runner.catalog import CATALOG_IDS
from heel.runner.identity import AcceptedRotationJournal, RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.runtime import (
    RunnerRuntimeConflict,
    RunnerRuntimeState,
    _SEAL_DOMAIN,
    _state_digest,
)


class Signer(SecureSigner):
    def __init__(self, seed: bytes = b"r" * 32) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)


def test_runtime_imports_without_the_runner_extra_but_refuses_construction_before_filesystem_access(tmp_path):
    script = r'''
import base64
import hashlib
import importlib.abc
from pathlib import Path
import sys

class BlockCrypto(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cryptography" or fullname.startswith("cryptography."):
            raise ModuleNotFoundError("cryptography intentionally unavailable")
        return None

sys.meta_path.insert(0, BlockCrypto())
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.runtime import RunnerRuntimeState, RunnerRuntimeUnavailable

class Signer(SecureSigner):
    public_key = b"p" * 32
    key_id = "rkey_runtime_smoke"
    def sign(self, payload):
        raise AssertionError("crypto must be loaded before signing")

signer = Signer()
identity = RunnerIdentity(
    runner_id="runr_" + "a" * 32,
    workspace_id="ws_123456789",
    runner_version="1",
    adapter_versions={},
    public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
    fingerprint=hashlib.sha256(signer.public_key).hexdigest(),
    key_id=signer.key_id,
    pairing_phrase=runner_phrase_words()[:6],
)
path = Path(sys.argv[1]) / "never-created" / "runtime.sqlite3"
try:
    RunnerRuntimeState(path, identity, signer)
except RunnerRuntimeUnavailable as error:
    assert str(error) == "authenticated runner runtime requires the 'runner' extra (install heel-sim[runner])"
else:
    raise AssertionError("runtime construction unexpectedly succeeded")
assert not path.parent.exists()
'''
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], cwd=Path(__file__).resolve().parents[1],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def _identity(signer: Signer) -> RunnerIdentity:
    import hashlib
    return RunnerIdentity(
        runner_id="runr_" + "a" * 32,
        workspace_id="ws_123456789", runner_version="1",
        adapter_versions={scenario: "1" for scenario in CATALOG_IDS},
        public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=signer.key_id,
        pairing_phrase=runner_phrase_words()[:6],
    )


def _rotation_journal(old: RunnerIdentity, new: RunnerIdentity, *, nonce: str) -> AcceptedRotationJournal:
    return AcceptedRotationJournal(
        pairing_id="pairing_rotation_123", old_identity=old, new_identity=new,
        activation_challenge=base64.b64encode(b"c" * 32).decode("ascii"),
        activation_request={"schema_version": "heel.runner-rotation-activate.v2", "signature_b64": "x"},
        activation_response={
            "schema_version": "heel.runner-rotation-activated.v2", "workspace_id": old.workspace_id,
            "runner_id": old.runner_id, "initial_claim_nonce": nonce,
            "initial_claim_sequence": 1, "initial_claim_generation": 1,
        },
        created_at_ms=1, updated_at_ms=2, new_signer_label="runner-rotation-key",
    )


def _runtime_with_available_disclosure(tmp_path, *, suffix: str = "d"):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    run_id = "crun_" + suffix * 32
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    cursor = runtime.install_chain(
        operation="result", run_id=run_id, next_nonce_b64=nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    runtime.register_local_terminal(
        run_id=run_id, project_id="prj_123456789", grant_id="grant_123456789",
        approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }
    staged = runtime.stage_call(
        request_operation="result", chain_operation="result", run_id=run_id, path=path,
        capability="runner_result", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=11,
    )
    available = runtime.commit_terminal_response(
        staged.call_id, next_nonce_b64=base64.b64encode(b"x" * 32).decode("ascii"), now_ms=12,
    )
    return runtime, signer, identity, run_id, available


def test_runtime_load_terminal_state_is_exact_and_read_only(tmp_path):
    runtime, _signer, _identity_value, run_id, available = _runtime_with_available_disclosure(tmp_path)

    assert runtime.load_terminal_state(run_id) == available
    assert runtime.load_terminal_state("crun_" + "e" * 32) is None


def test_runtime_seals_and_recovers_an_exact_claim_cursor(tmp_path):
    signer = Signer()
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)

    assert runtime.load_chain("claim", None) is None
    installed = runtime.install_chain(
        operation="claim", run_id=None,
        next_nonce_b64=base64.b64encode(b"n" * 32).decode("ascii"),
        next_sequence=1, generation=0, now_ms=1,
    )

    assert runtime.load_chain("claim", None) == installed
    assert installed.operation == "claim"
    assert installed.run_id is None
    assert installed.next_sequence == 1
    assert installed.generation == 0
    assert installed.state_digest != "0" * 64


def test_runtime_upgrades_v1_metadata_without_rewriting_existing_sealed_rows(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    path = tmp_path / "runtime.sqlite3"
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    chain = hashlib.sha256(canonical_bytes({"operation": "claim", "run_id": None})).hexdigest()
    core_without_digest = {
        "schema_version": "heel.runner-control-chain-state.v1",
        "workspace_id": identity.workspace_id, "runner_id": identity.runner_id,
        "runner_key_id": identity.key_id, "operation": "claim", "run_id": None,
        "next_nonce_b64": nonce, "next_sequence": 1, "generation": 0, "updated_at_ms": 1,
    }
    core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
    seal_payload = {
        "workspace_id": identity.workspace_id, "runner_id": identity.runner_id,
        "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint,
    }
    legacy_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=hashlib.sha256(signer.public_key).digest(), info=_SEAL_DOMAIN,
    ).derive(signer.sign(_SEAL_DOMAIN + canonical_bytes(seal_payload)))
    aad = "\0".join((
        "heel.runner-control-chain-state.v1", identity.workspace_id, identity.runner_id,
        identity.key_id, chain,
    )).encode("utf-8")
    sealed = b"q" * 12 + ChaCha20Poly1305(legacy_key).encrypt(
        b"q" * 12, canonical_bytes(core), aad,
    )
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
            "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v1'),"
            "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
            "public_key_digest TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO metadata VALUES(1,?,?,?,?,?)",
            ("heel.runner-runtime-state.v1", identity.workspace_id, identity.runner_id,
             identity.key_id, identity.fingerprint),
        )
        conn.execute(
            "CREATE TABLE control_chains(chain TEXT PRIMARY KEY,run_hash TEXT NULL,operation TEXT NOT NULL,"
            "next_sequence INTEGER NOT NULL,generation INTEGER NOT NULL,sealed_blob BLOB NOT NULL,"
            "updated_at_ms INTEGER NOT NULL)"
        )
        conn.execute(
            "INSERT INTO control_chains VALUES(?,?,?,?,?,?,?)",
            (chain, None, "claim", 1, 0, sealed, 1),
        )
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)

    runtime = RunnerRuntimeState(path, identity, signer)
    assert runtime.load_chain("claim", None).state_digest == core["state_digest"]
    assert RunnerRuntimeState(path, identity, signer).load_chain("claim", None).state_digest == core["state_digest"]
    with sqlite3.connect(path) as check:
        assert check.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v2"
        assert check.execute("SELECT sealed_blob FROM control_chains WHERE chain=?", (chain,)).fetchone()[0] == sealed


def test_runtime_finish_rotation_rewraps_the_stable_key_and_replaces_only_claim_cursor(tmp_path):
    old_signer = Signer(b"r" * 32)
    new_signer = Signer(b"s" * 32)
    old_identity = _identity(old_signer)
    new_identity = _identity(new_signer)
    path = tmp_path / "runtime.sqlite3"
    runtime = RunnerRuntimeState(path, old_identity, old_signer)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"o" * 32).decode("ascii"),
        next_sequence=5, generation=0, now_ms=1,
    )
    stable_key = runtime._key
    rotation_nonce = base64.b64encode(b"n" * 32).decode("ascii")

    journal = _rotation_journal(old_identity, new_identity, nonce=rotation_nonce)
    cursor = runtime.finish_rotation(
        journal,
        new_identity=new_identity, new_signer=new_signer,
    )

    assert runtime.identity == new_identity
    assert runtime.signer is new_signer
    assert runtime._key == stable_key
    assert (cursor.next_nonce_b64, cursor.next_sequence, cursor.generation) == (rotation_nonce, 1, 1)
    reopened = RunnerRuntimeState(path, new_identity, new_signer)
    assert reopened._key == stable_key
    assert reopened.load_chain("claim", None) == cursor
    assert reopened.finish_rotation(journal, new_identity=new_identity, new_signer=new_signer) == cursor


def test_runtime_finish_rotation_rejects_live_authority_without_mutation(tmp_path):
    old_signer = Signer(b"r" * 32)
    new_signer = Signer(b"s" * 32)
    old_identity = _identity(old_signer)
    new_identity = _identity(new_signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", old_identity, old_signer)
    old_cursor = runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"o" * 32).decode("ascii"),
        next_sequence=5, generation=0, now_ms=1,
    )
    runtime.install_chain(
        operation="heartbeat", run_id="crun_" + "a" * 32,
        next_nonce_b64=base64.b64encode(b"h" * 32).decode("ascii"),
        next_sequence=1, generation=0, now_ms=1,
    )

    with pytest.raises(Exception, match="active"):
        runtime.finish_rotation(
            _rotation_journal(old_identity, new_identity, nonce=base64.b64encode(b"n" * 32).decode("ascii")),
            new_identity=new_identity, new_signer=new_signer,
        )

    assert runtime.identity == old_identity
    assert runtime.load_chain("claim", None) == old_cursor


def test_runtime_stages_then_commits_an_exact_signed_claim_call(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    cursor = runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_claim",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 1, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "1",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }

    staged = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path,
        capability="runner_claim", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=1,
    )
    committed = runtime.commit_call(
        staged.call_id, next_nonce_b64=base64.b64encode(b"x" * 32).decode("ascii"), now_ms=2,
    )

    assert runtime.load_pending_calls() == ()
    assert committed.next_sequence == 2
    assert committed.next_nonce_b64 == base64.b64encode(b"x" * 32).decode("ascii")


def test_runtime_refuses_to_stage_an_initial_claim_without_the_persisted_v3_cursor(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_claim",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 1, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "1",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }

    with pytest.raises(RunnerRuntimeConflict, match="runtime chain is unavailable"):
        runtime.stage_call(
            request_operation="claim", chain_operation="claim", run_id=None, path=path,
            capability="runner_claim", headers=headers, body=body,
            expected_state_digest="0" * 64, now_ms=1,
        )
    assert runtime.load_pending_calls() == ()


def test_runtime_claim_commit_installs_exact_four_run_chains(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    cursor = runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_claim",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 1, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "1",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }
    staged = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path,
        capability="runner_claim", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=1,
    )
    run_id = "crun_" + "f" * 32
    installed = tuple(
        (operation, run_id, base64.b64encode(operation.encode().ljust(32, b"_")).decode("ascii"), 1, 0)
        for operation in ("heartbeat", "progress", "result", "stop-ack")
    )

    runtime.commit_call(
        staged.call_id, next_nonce_b64=base64.b64encode(b"x" * 32).decode("ascii"), now_ms=2,
        installed_chains=installed,
    )

    cursors = [runtime.load_chain(operation, run_id) for operation, *_ in installed]
    assert all(cursor is not None and cursor.next_sequence == 1 for cursor in cursors)


def test_runtime_registers_an_exact_local_terminal_anchor(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    state = runtime.register_local_terminal(
        run_id="crun_" + "a" * 32, project_id="prj_123456789", grant_id="grant_123456789",
        approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )

    assert state.state == "local_terminal"
    assert state.result_chain is None
    assert state.revision == 1
    assert state.prior_state_digest is None


def test_runtime_commits_result_into_available_disclosure_and_retires_run_chains(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    run_id = "crun_" + "a" * 32
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    cursor = runtime.install_chain(
        operation="result", run_id=run_id, next_nonce_b64=nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    runtime.register_local_terminal(
        run_id=run_id, project_id="prj_123456789", grant_id="grant_123456789",
        approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }
    staged = runtime.stage_call(
        request_operation="result", chain_operation="result", run_id=run_id, path=path,
        capability="runner_result", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=11,
    )

    available = runtime.commit_terminal_response(
        staged.call_id, next_nonce_b64=base64.b64encode(b"x" * 32).decode("ascii"), now_ms=12,
    )

    assert available.state == "available"
    assert available.result_chain is not None
    assert available.result_chain["next_sequence"] == 2
    assert runtime.load_chain("result", run_id) is None
    assert runtime.load_pending_calls() == ()


def test_runtime_leases_an_available_terminal_disclosure_once(tmp_path):
    signer = Signer()
    identity = _identity(signer)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    run_id = "crun_" + "b" * 32
    nonce = base64.b64encode(b"n" * 32).decode("ascii")
    cursor = runtime.install_chain(
        operation="result", run_id=run_id, next_nonce_b64=nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    runtime.register_local_terminal(
        run_id=run_id, project_id="prj_123456789", grant_id="grant_123456789",
        approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": "1",
    }
    staged = runtime.stage_call(
        request_operation="result", chain_operation="result", run_id=run_id, path=path,
        capability="runner_result", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=11,
    )
    runtime.commit_terminal_response(
        staged.call_id, next_nonce_b64=base64.b64encode(b"x" * 32).decode("ascii"), now_ms=12,
    )

    lease = runtime.lease_terminal_disclosure(
        run_id, expected_project_id="prj_123456789", expected_grant_id="grant_123456789",
        expected_approval_projection_digest="a" * 64, now_ms=12,
    )

    assert lease is not None


def test_runtime_stages_and_commits_a_leased_findings_disclosure(tmp_path):
    runtime, signer, identity, run_id, available = _runtime_with_available_disclosure(tmp_path)
    lease = runtime.lease_terminal_disclosure(
        run_id, expected_project_id="prj_123456789", expected_grant_id="grant_123456789",
        expected_approval_projection_digest="a" * 64, now_ms=12,
    )
    assert available.result_chain is not None
    nonce = available.result_chain["next_nonce_b64"]
    sequence = available.result_chain["next_sequence"]
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result-projection"
    body = canonical_bytes({"schema_version": "heel.runner-findings-upload.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 13, "server_nonce": nonce, "sequence": sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "13",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": str(sequence),
    }

    staged = runtime.stage_disclosure_call(lease, path=path, headers=headers, body=body, now_ms=13)
    consumed = runtime.commit_disclosure(
        staged.call_id, lease, next_nonce_b64=base64.b64encode(b"z" * 32).decode("ascii"),
        permit_id="permit_123456789", findings_projection_digest="d" * 64,
        receipt_digest="e" * 64, disclosed_at_ms=14,
    )

    assert staged.request_operation == "upload-findings"
    assert consumed.state == "consumed"
    assert consumed.result_chain is None
    assert runtime.load_pending_calls() == ()


def test_runtime_claims_then_finishes_a_due_terminal_prune(tmp_path):
    signer = Signer()
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    run_id = "crun_" + "e" * 32
    state = runtime.register_local_terminal(
        run_id=run_id, project_id="prj_123456789", grant_id="grant_123456789",
        approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )

    claimed = runtime.claim_due_prune(now_ms=20)
    runtime.finish_prune(
        run_id, expected_state_digest=claimed[0].state_digest,
        pruned_record_digest="d" * 64, now_ms=20,
    )

    assert claimed[0].state == "prune_pending"
    assert runtime.claim_due_prune(now_ms=20) == ()
