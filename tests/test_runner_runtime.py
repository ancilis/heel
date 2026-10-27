from __future__ import annotations

import base64
from contextlib import contextmanager
import gc
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import canonical_bytes
from heel.crypto import SigningAuthority, ed25519_key_id
from heel.runner.catalog import CATALOG_IDS
from heel.runner.identity import AcceptedRotationJournal, RunnerIdentity, SecureSigner, runner_phrase_words
import heel.runner.runtime as runtime_module
from heel.runner.runtime import (
    ActiveRunInstall,
    RunnerRuntimeConflict,
    RunnerRuntimeCorrupt,
    RunnerRuntimeState,
    _active_json_bytes,
    _active_state_digest,
    _SEAL_DOMAIN,
    _state_digest,
)
from tests.test_runner_stop import compiled_pair, signed_grant


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


def test_runtime_refuses_an_ancestor_symlink_before_creating_a_database(tmp_path):
    signer = Signer()
    target = tmp_path / "real-parent"
    target.mkdir(mode=0o700)
    alias = tmp_path / "linked-parent"
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state parent is unsafe"):
        RunnerRuntimeState(alias / "runtime.sqlite3", _identity(signer), signer)

    assert not (target / "runtime.sqlite3").exists()


def test_runtime_refuses_a_direct_database_symlink_before_sqlite_opens_it(tmp_path):
    signer = Signer()
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not a runtime database")
    os.chmod(target, 0o600)
    path = tmp_path / "runtime.sqlite3"
    path.symlink_to(target)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state is unsafe"):
        RunnerRuntimeState(path, _identity(signer), signer)

    assert target.read_bytes() == b"not a runtime database"


def test_runtime_rejects_a_database_swapped_only_while_sqlite_connects(tmp_path, monkeypatch):
    """Path checks alone cannot prove which inode SQLite opened."""
    signer = Signer()
    identity = _identity(signer)
    path = tmp_path / "runtime.sqlite3"
    alternate = tmp_path / "alternate.sqlite3"
    original_path = tmp_path / "original.sqlite3"
    original_runtime = RunnerRuntimeState(path, identity, signer)
    alternate_runtime = RunnerRuntimeState(alternate, identity, signer)
    del original_runtime, alternate_runtime
    gc.collect()

    original_connect = runtime_module.sqlite3.connect
    swapped = False

    def connect_with_transient_swap(database, *args, **kwargs):
        nonlocal swapped
        if database == str(path) and not swapped:
            swapped = True
            os.replace(path, original_path)
            os.replace(alternate, path)
            try:
                return original_connect(database, *args, **kwargs)
            finally:
                os.replace(path, alternate)
                os.replace(original_path, path)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_module.sqlite3, "connect", connect_with_transient_swap)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state is unsafe"):
        RunnerRuntimeState(path, identity, signer)

    assert swapped


def test_runtime_inode_guard_uses_the_fixed_isolated_stdio_only_bootstrap(tmp_path, monkeypatch):
    signer = Signer()
    identity = _identity(signer)
    sentinel = os.open(tmp_path / "unpassed-sentinel", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    captured: dict[str, object] = {}
    original_popen = runtime_module.subprocess.Popen

    def checked_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return original_popen(argv, **kwargs)

    monkeypatch.setattr(runtime_module.subprocess, "Popen", checked_popen)
    monkeypatch.setenv("PYTHONPATH", "/hostile/pythonpath")
    monkeypatch.setenv("PYTHONHOME", "/hostile/pythonhome")
    monkeypatch.setenv("PYTHONSTARTUP", "/hostile/startup")
    monkeypatch.setenv("VIRTUAL_ENV", "/hostile/venv")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/hostile/dylib")
    try:
        runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
        argv = captured["argv"]
        kwargs = captured["kwargs"]
        assert isinstance(argv, list)
        assert argv[:6] == [os.path.realpath(sys.executable, strict=True), "-I", "-S", "-B", "-c", runtime_module._RUNTIME_INODE_GUARD_BOOTSTRAP]
        assert os.path.isabs(argv[0])
        assert "heel" not in runtime_module._RUNTIME_INODE_GUARD_BOOTSTRAP
        assert isinstance(kwargs, dict)
        assert kwargs["cwd"] == "/"
        assert kwargs["env"] == {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
        assert kwargs["stdin"] is runtime_module.subprocess.DEVNULL
        assert kwargs["stdout"] is runtime_module.subprocess.DEVNULL
        assert kwargs["stderr"] is runtime_module.subprocess.DEVNULL
        assert kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        assert kwargs["restore_signals"] is True
        assert "shell" not in kwargs and "executable" not in kwargs
        assert isinstance(kwargs["pass_fds"], tuple)
        assert len(kwargs["pass_fds"]) == 2
        assert runtime._leaf_fd in kwargs["pass_fds"]
        assert sentinel not in kwargs["pass_fds"]
    finally:
        if "runtime" in locals():
            runtime.close()
        os.close(sentinel)


def test_runtime_inode_guard_rejects_a_world_writable_resolved_interpreter_before_spawn(tmp_path, monkeypatch):
    signer = Signer()
    unsafe = tmp_path / "python"
    unsafe.write_bytes(b"#!not-an-interpreter\n")
    unsafe.chmod(0o777)
    spawned = []

    def forbidden(*_args, **_kwargs):
        spawned.append(True)
        raise AssertionError("unsafe interpreter reached Popen")

    monkeypatch.setattr(runtime_module.sys, "executable", str(unsafe))
    monkeypatch.setattr(runtime_module.subprocess, "Popen", forbidden)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state helper is unavailable"):
        RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    assert spawned == []


def test_runtime_inode_guard_allows_a_trusted_group_writable_interpreter(tmp_path, monkeypatch):
    signer = Signer()
    candidate = os.path.realpath(sys.executable, strict=True)
    original_stat = runtime_module.os.stat

    def stat_with_group_writable_executable(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if os.fspath(path) == candidate:
            values = list(result)
            values[0] = (result.st_mode & ~0o777) | 0o775
            return os.stat_result(values)
        return result

    monkeypatch.setattr(runtime_module.os, "stat", stat_with_group_writable_executable)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    runtime.close()


def test_runtime_inode_guard_allows_a_trusted_group_writable_interpreter_parent(tmp_path, monkeypatch):
    signer = Signer()
    candidate_parent = os.path.dirname(os.path.realpath(sys.executable, strict=True))
    original_stat = runtime_module.os.stat

    def stat_with_group_writable_parent(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if os.fspath(path) == candidate_parent:
            values = list(result)
            values[0] = (result.st_mode & ~0o777) | 0o775
            return os.stat_result(values)
        return result

    monkeypatch.setattr(runtime_module.os, "stat", stat_with_group_writable_parent)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    runtime.close()


@pytest.mark.parametrize("suffix,fixture", [
    ("-wal", "symlink"), ("-shm", "hardlink"), ("-journal", "mode"),
])
def test_runtime_rejects_an_unsafe_sqlite_sidecar_before_connect(tmp_path, suffix, fixture):
    signer = Signer()
    path = tmp_path / "runtime.sqlite3"
    target = tmp_path / "sidecar-target"
    target.write_bytes(b"not a wal")
    target.chmod(0o600)
    sidecar = tmp_path / f"runtime.sqlite3{suffix}"
    if fixture == "symlink":
        sidecar.symlink_to(target)
    elif fixture == "hardlink":
        sidecar.hardlink_to(target)
    else:
        sidecar.write_bytes(b"not a journal")
        sidecar.chmod(0o644)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime SQLite sidecar is unsafe"):
        RunnerRuntimeState(path, _identity(signer), signer)


def test_runtime_rechecks_sqlite_sidecars_after_its_inode_probe(tmp_path, monkeypatch):
    signer = Signer()
    path = tmp_path / "runtime.sqlite3"
    runtime = RunnerRuntimeState(path, _identity(signer), signer)
    original_probe = runtime._probe_inode_guard
    target = tmp_path / "sidecar-target"
    target.write_bytes(b"not a wal")
    target.chmod(0o600)

    def inject_after_probe():
        original_probe()
        wal = tmp_path / "runtime.sqlite3-wal"
        wal.unlink()
        wal.symlink_to(target)

    monkeypatch.setattr(runtime, "_probe_inode_guard", inject_after_probe)
    try:
        with pytest.raises(RunnerRuntimeCorrupt, match="runtime SQLite sidecar is unsafe"):
            runtime.load_chain("claim", None)
    finally:
        wal = tmp_path / "runtime.sqlite3-wal"
        if wal.is_symlink():
            wal.unlink()
        runtime.close()


def test_runtime_poisoned_when_its_inode_guard_exits(tmp_path):
    signer = Signer()
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    process = runtime._inode_guard_process
    assert process is not None
    process.terminate()
    process.wait(timeout=1)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state helper is unavailable"):
        runtime.load_chain("claim", None)
    with pytest.raises(RunnerRuntimeCorrupt, match="requires reconstruction"):
        runtime.load_chain("claim", None)


def test_runtime_close_shuts_down_its_inode_guard(tmp_path):
    signer = Signer()
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", _identity(signer), signer)
    process = runtime._inode_guard_process
    assert process is not None

    runtime.close()

    assert process.poll() is not None
    assert runtime._inode_guard_process is None
    assert runtime._inode_guard_control is None
    with pytest.raises(RunnerRuntimeCorrupt, match="requires reconstruction"):
        runtime.load_chain("claim", None)


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


def test_active_runtime_canonicalizer_is_boolean_capable_but_still_closed():
    value = {"z": None, "gate": {"active": True, "stopped": False}, "accent": "é"}
    encoded = _active_json_bytes(value)

    assert encoded == b'{"accent":"\xc3\xa9","gate":{"active":true,"stopped":false},"z":null}'
    assert _active_state_digest(value) == hashlib.sha256(
        b"heel.runner-active-run-state-digest.v1\0" + encoded
    ).hexdigest()
    for invalid in (
        {"float": 1.5}, {"negative": -1}, {"large": 9_007_199_254_740_992},
        {"non_nfc": "e\u0301"}, {"control": "bad\ntext"}, {"surrogate": "\ud800"},
        {"nested": [[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]},
    ):
        with pytest.raises(ValueError):
            _active_json_bytes(invalid)

    with pytest.raises(ValueError):
        canonical_bytes({"active": True})


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
        prepared_journal_digest="d" * 64, runtime_rotation_intent_digest="e" * 64,
    )


def _runtime_with_active_run(tmp_path):
    """Build the post-claim runtime state through the public durable transaction."""
    _store, identity, signer, manifest, projection = compiled_pair(tmp_path / "authority")
    grant_authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, grant_authority)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    claim_nonce = base64.b64encode(b"c" * 32).decode("ascii")
    claim = runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=claim_nonce,
        next_sequence=1, generation=0, now_ms=1,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_claim",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 2, "server_nonce": claim_nonce, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "2",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": claim_nonce, "X-Heel-Runner-Sequence": "1",
    }
    pending = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None,
        path=path, capability="runner_claim", headers=headers, body=body,
        expected_state_digest=claim.state_digest, now_ms=2,
    )
    run_id = grant["run_id"]
    installed = tuple(
        (operation, run_id, base64.b64encode(marker * 32).decode("ascii"), 1, 0)
        for operation, marker in (
            ("heartbeat", b"h"), ("progress", b"p"),
            ("result", b"r"), ("stop-ack", b"s"),
        )
    )
    runtime.commit_call(
        pending.call_id, next_nonce_b64=base64.b64encode(b"n" * 32).decode("ascii"),
        now_ms=2, installed_chains=installed,
        active_run=ActiveRunInstall(
            run_id=run_id, approval_projection=projection, grant=grant,
            gate={
                "active": True, "runner_state": "active", "proof_state": "valid",
                "proof_expires_at_ms": 20_000, "kill_switch_generation": 7,
                "stop_reason": "none", "server_time_ms": 2_000,
            },
            claim_response_digest="a" * 64, gate_response_digest="b" * 64,
            claimed_at_ms=2, gate_received_at_ms=2,
        ),
    )
    return runtime, signer, identity, grant


def _runtime_with_available_disclosure(tmp_path, *, suffix: str = "d"):
    del suffix
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    cursor = runtime.load_chain("result", run_id)
    assert cursor is not None
    runtime.register_local_terminal(
        run_id=run_id, project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": cursor.next_nonce_b64, "sequence": 1,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": cursor.next_nonce_b64, "X-Heel-Runner-Sequence": "1",
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


@pytest.mark.parametrize("tamper", ("remove-active", "insert-extra-cursor"))
def test_active_hydration_rejects_orphaned_or_nonexact_cursor_groups(tmp_path, tamper):
    runtime, _signer, _identity_value, grant = _runtime_with_active_run(tmp_path)
    run_hash = hashlib.sha256(grant["run_id"].encode("utf-8")).hexdigest()

    with sqlite3.connect(runtime.path) as conn:
        if tamper == "remove-active":
            conn.execute("DELETE FROM active_runs WHERE run_hash=?", (run_hash,))
        else:
            original = conn.execute(
                "SELECT sealed_blob,updated_at_ms FROM control_chains "
                "WHERE run_hash=? AND operation='heartbeat'",
                (run_hash,),
            ).fetchone()
            assert original is not None
            conn.execute(
                "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
                "VALUES(?,?,?,?,?,?,?)",
                ("a" * 64, run_hash, "heartbeat", 1, 0, original[0], original[1]),
            )
    conn.close()

    with pytest.raises(RunnerRuntimeCorrupt, match="active run cursor group"):
        runtime.load_active_run_controls()


def test_active_hydration_rejects_an_available_terminal_that_coexists_with_live_cursors(tmp_path):
    runtime, _signer, _identity_value, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    local = runtime.register_local_terminal(
        run_id=run_id, project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"],
        terminal_projection_digest="b" * 64, terminal_record_digest="c" * 64,
        terminal_at_ms=10, retention_expires_at_ms=20,
    )
    result = runtime.load_chain("result", run_id)
    assert result is not None
    core = runtime._terminal_core(
        state="available", workspace_id=local.workspace_id, runner_id=local.runner_id,
        runner_key_id=local.runner_key_id, run_id=run_id, run_hash=local.run_hash,
        project_id=local.project_id, grant_id=local.grant_id,
        approval_projection_digest=local.approval_projection_digest,
        terminal_projection_digest=local.terminal_projection_digest,
        terminal_record_digest=local.terminal_record_digest,
        terminal_at_ms=local.terminal_at_ms,
        retention_expires_at_ms=local.retention_expires_at_ms,
        result_chain={
            "operation": "result", "run_id": run_id,
            "next_nonce_b64": base64.b64encode(b"x" * 32).decode("ascii"),
            "next_sequence": result.next_sequence + 1, "generation": result.generation,
        },
        available_at_ms=11, permit_id=None, findings_projection_digest=None,
        receipt_digest=None, disclosed_at_ms=None, revision=2,
        prior_state_digest=local.state_digest,
    )
    available = runtime._validate_terminal_core(core)
    blob = runtime._seal(core, schema=core["schema_version"], primary_fields=(local.run_hash,))
    with sqlite3.connect(runtime.path) as conn:
        conn.execute(
            "UPDATE terminal_disclosures SET state=?,sealed_blob=?,updated_at_ms=? WHERE run_hash=?",
            (available.state, blob, 11, local.run_hash),
        )
    conn.close()

    with pytest.raises(RunnerRuntimeCorrupt, match="active run terminal state is invalid"):
        runtime.load_active_run_controls()


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
        # v1 -> v2 -> v3 -> v4 (T2b2R1 recovery records) -> v5 (C retired claims) in one transaction;
        # sealed rows are untouched.
        assert check.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v5"
        assert check.execute("SELECT sealed_blob FROM control_chains WHERE chain=?", (chain,)).fetchone()[0] == sealed
    check.close()


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
    probe = runtime.probe_rotation_eligible(old_identity=old_identity)
    eligibility = runtime.assert_rotation_eligible(
        old_identity=old_identity, prepared_journal_digest="d" * 64,
        runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=1,
    )
    cursor = runtime.finish_rotation(
        journal,
        eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
    )

    assert runtime.identity == new_identity
    assert runtime.signer is new_signer
    assert runtime._key == stable_key
    assert (cursor.next_nonce_b64, cursor.next_sequence, cursor.generation) == (rotation_nonce, 1, 1)
    reopened = RunnerRuntimeState(path, new_identity, new_signer)
    assert reopened._key == stable_key
    assert reopened.load_chain("claim", None) == cursor
    assert reopened.finish_rotation(
        journal, eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
    ) == cursor


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
        probe = runtime.probe_rotation_eligible(old_identity=old_identity)
        runtime.assert_rotation_eligible(
            old_identity=old_identity, prepared_journal_digest="d" * 64,
            runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=1,
        )

    assert runtime.identity == old_identity
    assert runtime.load_chain("claim", None) == old_cursor


def test_stale_pre_rotation_runtime_cannot_write_after_another_instance_rotates(tmp_path):
    old_signer = Signer(b"r" * 32)
    new_signer = Signer(b"s" * 32)
    old_identity = _identity(old_signer)
    new_identity = _identity(new_signer)
    path = tmp_path / "runtime.sqlite3"
    rotating = RunnerRuntimeState(path, old_identity, old_signer)
    rotating.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"o" * 32).decode("ascii"),
        next_sequence=5, generation=0, now_ms=1,
    )
    stale = RunnerRuntimeState(path, old_identity, old_signer)
    probe = rotating.probe_rotation_eligible(old_identity=old_identity)
    eligibility = rotating.assert_rotation_eligible(
        old_identity=old_identity, prepared_journal_digest="d" * 64,
        runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=1,
    )
    rotating.finish_rotation(
        _rotation_journal(old_identity, new_identity, nonce=base64.b64encode(b"n" * 32).decode("ascii")),
        eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
    )

    with pytest.raises(RunnerRuntimeCorrupt):
        stale.register_local_terminal(
            run_id="crun_" + "d" * 32, project_id="prj_123456789", grant_id="grant_123456789",
            approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
            terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
        )

    reopened = RunnerRuntimeState(path, new_identity, new_signer)
    assert reopened.load_terminal_state("crun_" + "d" * 32) is None


def test_stale_runtime_cannot_write_while_rotation_holds_the_inode_lock(tmp_path):
    old_signer = Signer(b"r" * 32)
    new_signer = Signer(b"s" * 32)
    old_identity = _identity(old_signer)
    new_identity = _identity(new_signer)
    path = tmp_path / "runtime.sqlite3"
    rotating = RunnerRuntimeState(path, old_identity, old_signer)
    rotating.install_chain(
        operation="claim", run_id=None, next_nonce_b64=base64.b64encode(b"o" * 32).decode("ascii"),
        next_sequence=5, generation=0, now_ms=1,
    )
    stale = RunnerRuntimeState(path, old_identity, old_signer)
    probe = rotating.probe_rotation_eligible(old_identity=old_identity)
    eligibility = rotating.assert_rotation_eligible(
        old_identity=old_identity, prepared_journal_digest="d" * 64,
        runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=1,
    )
    entered, release = threading.Event(), threading.Event()
    original_connection = rotating._connection

    @contextmanager
    def pause_after_inode_probe(*args, **kwargs):
        with original_connection(*args, **kwargs) as conn:
            entered.set()
            assert release.wait(1)
            yield conn

    rotating._connection = pause_after_inode_probe
    failures: list[BaseException] = []

    def rotate() -> None:
        try:
            rotating.finish_rotation(
                _rotation_journal(old_identity, new_identity, nonce=base64.b64encode(b"n" * 32).decode("ascii")),
                eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
            )
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=rotate)
    worker.start()
    assert entered.wait(1)

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state database is invalid"):
        stale.register_local_terminal(
            run_id="crun_" + "e" * 32, project_id="prj_123456789", grant_id="grant_123456789",
            approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
            terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
        )

    release.set()
    worker.join(1)

    assert not worker.is_alive()
    assert failures == []
    with pytest.raises(RunnerRuntimeCorrupt):
        stale.register_local_terminal(
            run_id="crun_" + "e" * 32, project_id="prj_123456789", grant_id="grant_123456789",
            approval_projection_digest="a" * 64, terminal_projection_digest="b" * 64,
            terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
        )
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM terminal_disclosures").fetchone()[0] == 0
    conn.close()


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
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    cursor = runtime.load_chain("result", run_id)
    assert cursor is not None
    runtime.register_local_terminal(
        run_id=run_id, project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": cursor.next_nonce_b64, "sequence": cursor.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": cursor.next_nonce_b64,
        "X-Heel-Runner-Sequence": str(cursor.next_sequence),
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
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    cursor = runtime.load_chain("result", run_id)
    assert cursor is not None
    runtime.register_local_terminal(
        run_id=run_id, project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": cursor.next_nonce_b64, "sequence": cursor.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": cursor.next_nonce_b64,
        "X-Heel-Runner-Sequence": str(cursor.next_sequence),
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
        run_id, expected_project_id=grant["project_id"], expected_grant_id=grant["grant_id"],
        expected_approval_projection_digest=grant["approval"]["projection_digest"], now_ms=12,
    )

    assert lease is not None


def test_runtime_stages_and_commits_a_leased_findings_disclosure(tmp_path):
    runtime, signer, identity, run_id, available = _runtime_with_available_disclosure(tmp_path)
    lease = runtime.lease_terminal_disclosure(
        run_id, expected_project_id=available.project_id, expected_grant_id=available.grant_id,
        expected_approval_projection_digest=available.approval_projection_digest, now_ms=12,
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
    runtime, _signer, _identity_value, grant = _runtime_with_active_run(tmp_path)
    state = runtime.register_local_terminal(
        run_id=grant["run_id"], project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )

    claimed = runtime.claim_due_prune(now_ms=20)
    assert claimed.items[0].state == "prune_pending"
    assert runtime.load_prune_pending().items == claimed.items


def test_runtime_claims_one_specific_due_terminal_by_exact_digest(tmp_path):
    runtime, _signer, _identity_value, grant = _runtime_with_active_run(tmp_path)
    state = runtime.register_local_terminal(
        run_id=grant["run_id"], project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )

    claimed = runtime.claim_specific_due_prune(
        grant["run_id"], expected_state_digest=state.state_digest, now_ms=20,
    )
    assert claimed.state == "prune_pending"
    with pytest.raises(RunnerRuntimeConflict):
        runtime.claim_specific_due_prune(
            grant["run_id"], expected_state_digest=state.state_digest, now_ms=20,
        )


def test_runtime_due_prune_retires_a_staged_terminal_result_and_all_run_cursors(tmp_path):
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    cursors = {
        operation: runtime.load_chain(operation, run_id)
        for operation in ("heartbeat", "progress", "result", "stop-ack")
    }
    assert all(cursor is not None for cursor in cursors.values())
    runtime.register_local_terminal(
        run_id=run_id, project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    result = cursors["result"]
    assert result is not None
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1"})
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result"
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 11, "server_nonce": result.next_nonce_b64, "sequence": result.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "11",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": result.next_nonce_b64,
        "X-Heel-Runner-Sequence": str(result.next_sequence),
    }
    runtime.stage_call(
        request_operation="result", chain_operation="result", run_id=run_id, path=path,
        capability="runner_result", headers=headers, body=body,
        expected_state_digest=result.state_digest, now_ms=11,
    )

    claimed = runtime.claim_due_prune(now_ms=20)

    assert claimed.items[0].state == "prune_pending"
    assert runtime.load_pending_calls() == ()
    assert all(runtime.load_chain(operation, run_id) is None for operation in cursors)


def test_runtime_due_prune_retires_the_active_group_with_an_expired_local_terminal(tmp_path):
    runtime, _signer, _identity_value, grant = _runtime_with_active_run(tmp_path)
    runtime.register_local_terminal(
        run_id=grant["run_id"], project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"],
        terminal_projection_digest="b" * 64, terminal_record_digest="c" * 64,
        terminal_at_ms=10, retention_expires_at_ms=20,
    )

    claimed = runtime.claim_due_prune(now_ms=20)

    assert claimed.items[0].state == "prune_pending"
    assert runtime.load_active_run_controls() == ()


def test_runtime_due_prune_retires_a_staged_findings_disclosure(tmp_path):
    runtime, signer, identity, run_id, available = _runtime_with_available_disclosure(tmp_path)
    lease = runtime.lease_terminal_disclosure(
        run_id, expected_project_id=available.project_id, expected_grant_id=available.grant_id,
        expected_approval_projection_digest=available.approval_projection_digest, now_ms=12,
    )
    assert available.result_chain is not None
    body = canonical_bytes({"schema_version": "heel.runner-findings-upload.v1"})
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/result-projection"
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_result",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": 13, "server_nonce": available.result_chain["next_nonce_b64"],
        "sequence": available.result_chain["next_sequence"],
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": "13",
        "X-Heel-Runner-Signature": base64.b64encode(
            signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        ).decode("ascii"),
        "X-Heel-Runner-Nonce": available.result_chain["next_nonce_b64"],
        "X-Heel-Runner-Sequence": str(available.result_chain["next_sequence"]),
    }
    runtime.stage_disclosure_call(lease, path=path, headers=headers, body=body, now_ms=13)

    claimed = runtime.claim_due_prune(now_ms=20)

    assert claimed.items[0].state == "prune_pending"
    assert claimed.items[0].result_chain is None
    assert runtime.load_pending_calls() == ()


def test_runtime_restart_reclaims_a_durable_due_prune_pending_terminal(tmp_path):
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    path = runtime.path
    runtime.register_local_terminal(
        run_id=grant["run_id"], project_id=grant["project_id"], grant_id=grant["grant_id"],
        approval_projection_digest=grant["approval"]["projection_digest"], terminal_projection_digest="b" * 64,
        terminal_record_digest="c" * 64, terminal_at_ms=10, retention_expires_at_ms=20,
    )
    pending = runtime.claim_due_prune(now_ms=20)
    assert len(pending.items) == 1 and pending.items[0].state == "prune_pending"

    restarted = RunnerRuntimeState(path, identity, signer)

    recovered = restarted.load_prune_pending()
    assert recovered.items == pending.items
    assert recovered.has_more is False


@pytest.mark.parametrize("object_name", (
    "metadata",
    "control_chains",
    "pending_calls",
    "terminal_disclosures",
    "idx_terminal_disclosures_state_retention",
    "retired_claims",
    "idx_retired_claims_created",
))
def test_runtime_rejects_each_precreated_noncanonical_schema_object(tmp_path, object_name):
    signer = Signer()
    identity = _identity(signer)
    path = tmp_path / "runtime.sqlite3"
    RunnerRuntimeState(path, identity, signer)

    with sqlite3.connect(path) as conn:
        if object_name == "metadata":
            row = tuple(conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone())
            conn.execute("DROP TABLE metadata")
            conn.execute(
                "CREATE TABLE metadata("
                "singleton INTEGER PRIMARY KEY,schema_version TEXT NOT NULL,"
                "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
                "public_key_digest TEXT NOT NULL,state_key_ciphertext BLOB NOT NULL)"
            )
            conn.execute("INSERT INTO metadata VALUES(?,?,?,?,?,?,?)", (*row[:6], row[9]))
        elif object_name == "control_chains":
            conn.execute("DROP TABLE control_chains")
            conn.execute("CREATE TABLE control_chains(chain TEXT)")
        elif object_name == "pending_calls":
            conn.execute("DROP TABLE pending_calls")
            conn.execute("CREATE TABLE pending_calls(call_id TEXT)")
        elif object_name == "terminal_disclosures":
            conn.execute("DROP INDEX idx_terminal_disclosures_state_retention")
            conn.execute("DROP TABLE terminal_disclosures")
            conn.execute("CREATE TABLE terminal_disclosures(run_hash TEXT)")
        elif object_name == "retired_claims":
            conn.execute("DROP INDEX idx_retired_claims_created")
            conn.execute("DROP TABLE retired_claims")
            conn.execute("CREATE TABLE retired_claims(run_hash TEXT PRIMARY KEY,sealed_blob BLOB,created_at_ms INTEGER)")
            conn.execute("CREATE INDEX idx_retired_claims_created ON retired_claims(created_at_ms,run_hash)")
        elif object_name == "idx_retired_claims_created":
            conn.execute("DROP INDEX idx_retired_claims_created")
            conn.execute("CREATE INDEX idx_retired_claims_created ON retired_claims(run_hash)")
        else:
            conn.execute("DROP INDEX idx_terminal_disclosures_state_retention")
            conn.execute(
                "CREATE INDEX idx_terminal_disclosures_state_retention "
                "ON terminal_disclosures(run_hash)"
            )
    conn.close()

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state schema is invalid"):
        RunnerRuntimeState(path, identity, signer)


# ---------------------------------------------------------------------------
# T2b2R1: claim-chain authority recovery records (runtime schema v4).
# A staged claim-chain call the server never recorded can never replay after
# its proof window; only an accepted resync may retire it, atomically, into a
# sealed tombstone.  These tests exercise the runtime half of that contract.

_LIST_BODY = canonical_bytes({"schema_version": "heel.runner-context-list.v1"})


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _signed_claim_chain_headers(signer, identity, *, path, body, nonce, sequence, timestamp_ms=1):
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "capability": "runner_claim",
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp_ms": timestamp_ms, "server_nonce": nonce, "sequence": sequence,
    }
    return {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
        "X-Heel-Runner-Signature": _b64(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))),
        "X-Heel-Runner-Nonce": nonce, "X-Heel-Runner-Sequence": str(sequence),
    }


def _stage_claim_chain(runtime, signer, identity, *, operation="list-contexts", binding_id=None, claim_body=None):
    cursor = runtime.load_chain("claim", None)
    prefix = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}"
    if operation == "list-contexts":
        path, body = f"{prefix}/contexts/list", _LIST_BODY
    elif operation == "claim-context":
        binding_id = binding_id or "rcb_" + "b" * 32
        path = f"{prefix}/contexts/{binding_id}/claim"
        body = canonical_bytes({
            "schema_version": "heel.runner-context-claim.v1", "binding_id": binding_id,
            "binding_digest": "d" * 64,
        })
    elif operation == "submit-context-approval-projection":
        path = f"{prefix}/contexts/{'rcb_' + 'b' * 32}/approval-projections"
        body = canonical_bytes({"schema_version": "heel.runner-approval-projection-submit.v1"})
    else:
        assert operation == "claim"
        path = f"{prefix}/claim"
        body = canonical_bytes(claim_body or {"schema_version": "heel.runner-claim-request.v1"})
    headers = _signed_claim_chain_headers(
        signer, identity, path=path, body=body, nonce=cursor.next_nonce_b64, sequence=cursor.next_sequence,
    )
    return runtime.stage_call(
        request_operation=operation, chain_operation="claim", run_id=None, path=path,
        capability="runner_claim", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=1,
    )


def _resync_start(signer, identity, *, client_nonce, timestamp_ms=2):
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/resync/start"
    body = canonical_bytes({
        "schema_version": "heel.runner-resync-start.v2", "chain": {"operation": "claim", "run_id": None},
        "client_nonce_b64": client_nonce,
    })
    proof = {
        "schema_version": "heel.runner-resync-start-proof.v2", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
        "X-Heel-Runner-Signature": _b64(signer.sign(b"heel.runner-resync-start-pop.v2\0" + canonical_bytes(proof))),
    }
    return path, headers, body


def _resync_complete(signer, identity, *, challenge_id, client_nonce, server_challenge, generation, timestamp_ms=3):
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/resync/complete"
    body = canonical_bytes({
        "schema_version": "heel.runner-resync-complete.v2", "challenge_id": challenge_id,
        "chain": {"operation": "claim", "run_id": None}, "client_nonce_b64": client_nonce,
        "server_challenge_b64": server_challenge, "generation": generation,
    })
    proof = {
        "schema_version": "heel.runner-resync-complete-proof.v2", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id, "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
        "X-Heel-Runner-Signature": _b64(signer.sign(b"heel.runner-resync-complete-pop.v2\0" + canonical_bytes(proof))),
    }
    return path, headers, body


def _completed_attempt(runtime, signer, identity, *, generation=0, challenge_sequence=None):
    client_nonce, server_challenge = _b64(b"c" * 32), _b64(b"s" * 32)
    path, headers, body = _resync_start(signer, identity, client_nonce=client_nonce)
    attempt = runtime.begin_resync_attempt(
        operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
        timestamp_ms=2, now_ms=2,
    )
    attempt = runtime.record_resync_challenge(
        attempt, challenge_id="rrs_" + "e" * 32, server_challenge_b64=server_challenge,
        next_sequence=challenge_sequence or attempt_sequence(runtime), generation=generation,
        expires_at_ms=60_002, now_ms=2,
    )
    path, headers, body = _resync_complete(
        signer, identity, challenge_id="rrs_" + "e" * 32, client_nonce=client_nonce,
        server_challenge=server_challenge, generation=generation,
    )
    return runtime.record_resync_completion(
        attempt, path=path, headers=headers, body=body, timestamp_ms=3, now_ms=3,
    )


def _realistic_identity(signer):
    import dataclasses
    return dataclasses.replace(
        _identity(signer), workspace_id="ws_" + "9" * 24, runner_id="runr_" + "a" * 32,
    )


def attempt_sequence(runtime):
    return runtime.load_chain("claim", None).next_sequence


def _claim_runtime(tmp_path, *, name="runtime.sqlite3"):
    signer = Signer()
    # Production-length IDs: a claim-context path is then longer than the runtime's 128-byte
    # short-text fields, which a tombstone must still hold (found by the T2b2R1 HTTP gate).
    identity = _realistic_identity(signer)
    runtime = RunnerRuntimeState(tmp_path / name, identity, signer)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=_b64(b"n" * 32),
        next_sequence=4, generation=0, now_ms=1,
    )
    return runtime, signer, identity


@pytest.mark.parametrize("operation", ["list-contexts", "claim-context"])
def test_accepted_resync_atomically_supersedes_an_eligible_claim_chain_call_into_a_sealed_tombstone(tmp_path, operation):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity, operation=operation)
    attempt = _completed_attempt(runtime, signer, identity)
    recovered_nonce = _b64(b"r" * 32)

    cursor = runtime.commit_resync_supersession(
        attempt, pending, next_nonce_b64=recovered_nonce, next_sequence=4, generation=1, now_ms=5,
    )

    assert (cursor.next_nonce_b64, cursor.next_sequence, cursor.generation) == (recovered_nonce, 4, 1)
    assert runtime.load_pending_calls() == ()
    assert runtime.load_resync_attempt("claim") is None
    (tombstone,) = runtime.load_superseded_calls()
    assert (tombstone.call_id, tombstone.request_operation, tombstone.path, tombstone.sequence,
            tombstone.generation, tombstone.superseded_by_generation, tombstone.resync_challenge_id,
            tombstone.superseded_at_ms, tombstone.body_sha256) == (
        pending.call_id, operation, pending.path, 4, 0, 1, "rrs_" + "e" * 32, 5,
        hashlib.sha256(pending.body).hexdigest(),
    )
    # The audit row is sealed: neither the request body nor its signature is stored in clear.
    with sqlite3.connect(runtime.path) as conn:
        rows = conn.execute("SELECT kind,generation,sealed_blob FROM chain_recovery").fetchall()
    conn.close()
    assert [(kind, generation) for kind, generation, _blob in rows] == [("superseded_call", 1)]
    assert pending.body not in rows[0][2] and pending.headers["X-Heel-Runner-Signature"].encode() not in rows[0][2]
    # Reopening keeps the tombstone and nothing becomes replayable again.
    reopened = RunnerRuntimeState(runtime.path, identity, signer)
    assert reopened.load_pending_calls() == ()
    assert reopened.load_superseded_calls() == (tombstone,)


def test_supersession_refuses_ineligible_or_mismatched_intents_without_any_mutation(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    claim = _stage_claim_chain(runtime, signer, identity, operation="submit-context-approval-projection")
    attempt = _completed_attempt(runtime, signer, identity)
    before = (runtime.load_chain("claim", None), runtime.load_pending_calls(), runtime.load_resync_attempt("claim"))

    with pytest.raises(RunnerRuntimeConflict, match="not supersedable"):
        runtime.commit_resync_supersession(
            attempt, claim, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
        )
    for generation, sequence in ((0, 4), (2, 4), (1, 3)):
        # No advance, a generation the challenge does not prove, or a regressed sequence.
        with pytest.raises((RunnerRuntimeConflict, RunnerRuntimeCorrupt)):
            runtime.commit_resync_supersession(
                attempt, claim, next_nonce_b64=_b64(b"r" * 32), next_sequence=sequence,
                generation=generation, now_ms=5,
            )
    assert (runtime.load_chain("claim", None), runtime.load_pending_calls(),
            runtime.load_resync_attempt("claim")) == before
    assert runtime.load_superseded_calls() == ()


def test_supersession_requires_the_pending_call_to_sit_on_the_current_cursor_and_the_exact_attempt(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity)
    attempt = _completed_attempt(runtime, signer, identity)
    other = RunnerRuntimeState(tmp_path / "other.sqlite3", identity, signer)
    other.install_chain(
        operation="claim", run_id=None, next_nonce_b64=_b64(b"z" * 32),
        next_sequence=4, generation=0, now_ms=1,
    )
    # Same runner, another chain state: a different call that does not sit on this cursor.
    foreign = _stage_claim_chain(other, signer, identity)
    assert foreign.call_id != pending.call_id
    with pytest.raises((RunnerRuntimeConflict, RunnerRuntimeCorrupt)):
        runtime.commit_resync_supersession(
            attempt, foreign, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
        )
    # An attempt without its persisted completion request is not an accepted resync.
    runtime.discard_resync_attempt(attempt)
    client_nonce = _b64(b"k" * 32)
    path, headers, body = _resync_start(signer, identity, client_nonce=client_nonce)
    started = runtime.begin_resync_attempt(
        operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
        timestamp_ms=2, now_ms=2,
    )
    with pytest.raises(RunnerRuntimeConflict):
        runtime.commit_resync_supersession(
            started, pending, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
        )
    assert runtime.load_pending_calls() == (pending,)
    assert runtime.load_chain("claim", None).generation == 0


def test_resync_attempts_persist_exact_signed_bytes_and_compare_and_swap(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    client_nonce = _b64(b"c" * 32)
    path, headers, body = _resync_start(signer, identity, client_nonce=client_nonce)
    attempt = runtime.begin_resync_attempt(
        operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
        timestamp_ms=2, now_ms=2,
    )
    assert (attempt.start_path, dict(attempt.start_headers), attempt.start_body, attempt.challenge_id) == (
        path, headers, body, None,
    )
    reopened = RunnerRuntimeState(runtime.path, identity, signer)
    assert reopened.load_resync_attempt("claim") == attempt
    forged = dict(headers, **{"X-Heel-Runner-Signature": _b64(b"x" * 64)})
    with pytest.raises(Exception):
        runtime.begin_resync_attempt(
            operation="claim", path=path, headers=forged, body=body, client_nonce_b64=client_nonce,
            timestamp_ms=2, now_ms=2,
        )
    with pytest.raises(Exception):
        runtime.begin_resync_attempt(
            operation="heartbeat", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
            timestamp_ms=2, now_ms=2,
        )
    challenged = runtime.record_resync_challenge(
        attempt, challenge_id="rrs_" + "e" * 32, server_challenge_b64=_b64(b"s" * 32),
        next_sequence=4, generation=0, expires_at_ms=60_002, now_ms=3,
    )
    # A stale snapshot can no longer change the persisted attempt.
    with pytest.raises(RunnerRuntimeConflict):
        runtime.record_resync_challenge(
            attempt, challenge_id="rrs_" + "f" * 32, server_challenge_b64=_b64(b"t" * 32),
            next_sequence=4, generation=0, expires_at_ms=60_002, now_ms=3,
        )
    with pytest.raises(RunnerRuntimeConflict):
        runtime.discard_resync_attempt(attempt)
    assert runtime.load_resync_attempt("claim") == challenged
    # The challenge cannot regress below the local generation.
    lower, lower_signer, lower_identity = _claim_runtime(tmp_path, name="lower.sqlite3")
    lower._commit_resync_chain(
        operation="claim", run_id=None, next_nonce_b64=_b64(b"g" * 32), next_sequence=4,
        generation=1, now_ms=2,
    )
    p, h, b = _resync_start(lower_signer, lower_identity, client_nonce=client_nonce)
    lower_attempt = lower.begin_resync_attempt(
        operation="claim", path=p, headers=h, body=b, client_nonce_b64=client_nonce, timestamp_ms=2, now_ms=2,
    )
    with pytest.raises(RunnerRuntimeCorrupt):
        lower.record_resync_challenge(
            lower_attempt, challenge_id="rrs_" + "e" * 32, server_challenge_b64=_b64(b"s" * 32),
            next_sequence=4, generation=0, expires_at_ms=60_002, now_ms=3,
        )
    runtime.discard_resync_attempt(challenged)
    assert runtime.load_resync_attempt("claim") is None


def test_rotation_refuses_while_a_resync_attempt_is_open(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    client_nonce = _b64(b"c" * 32)
    path, headers, body = _resync_start(signer, identity, client_nonce=client_nonce)
    runtime.begin_resync_attempt(
        operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
        timestamp_ms=2, now_ms=2,
    )
    with pytest.raises(RunnerRuntimeConflict, match="recovery"):
        runtime.probe_rotation_eligible(old_identity=identity)


def test_runtime_v3_to_v4_migration_preserves_every_prior_row_and_rejects_a_tampered_tombstone(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity)
    cursor = runtime.load_chain("claim", None)
    path = runtime.path
    runtime.close()
    # Rebuild the exact v3 layout this file had before the T2b2R1 (v4) and C (v5) migrations existed.
    with sqlite3.connect(path) as conn:
        before = {table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                  for table in ("control_chains", "pending_calls", "terminal_disclosures", "active_runs")}
        metadata = conn.execute("SELECT * FROM metadata").fetchone()
        conn.execute("DROP TABLE retired_claims")
        conn.execute("DROP TABLE chain_recovery")
        conn.execute("ALTER TABLE metadata RENAME TO metadata_v4")
        conn.execute(runtime_module._V3_SCHEMA_SQL[0])
        conn.execute(
            "INSERT INTO metadata SELECT singleton,'heel.runner-runtime-state.v3',workspace_id,runner_id,"
            "runner_key_id,public_key_digest,authority_epoch,authority_identity_digest,"
            "rotation_fence_digest,state_key_ciphertext FROM metadata_v4"
        )
        conn.execute("DROP TABLE metadata_v4")
        assert RunnerRuntimeState._schema_matches(conn, runtime_module._V3_SCHEMA_SQL)
    conn.close()

    migrated = RunnerRuntimeState(path, identity, signer)
    assert migrated.load_chain("claim", None) == cursor
    assert migrated.load_pending_calls() == (pending,)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v5"
        after = {table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                 for table in ("control_chains", "pending_calls", "terminal_disclosures", "active_runs")}
        assert after == before
        migrated_metadata = conn.execute("SELECT * FROM metadata").fetchone()
        assert migrated_metadata[2:] == metadata[2:] and migrated_metadata[1] == "heel.runner-runtime-state.v5"
        assert conn.execute("SELECT COUNT(*) FROM chain_recovery").fetchone()[0] == 0
    conn.close()

    attempt = _completed_attempt(migrated, signer, identity)
    migrated.commit_resync_supersession(
        attempt, pending, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
    )
    with sqlite3.connect(path) as conn:
        (blob,) = conn.execute("SELECT sealed_blob FROM chain_recovery").fetchone()
        conn.execute("UPDATE chain_recovery SET sealed_blob=?", (blob[:-1] + bytes([blob[-1] ^ 1]),))
    conn.close()
    with pytest.raises(RunnerRuntimeCorrupt):
        RunnerRuntimeState(path, identity, signer).load_superseded_calls()
    # Corruption is never silently repaired: the file still holds the tampered row.
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM chain_recovery").fetchone()[0] == 1
    conn.close()


def test_accepted_resync_supersedes_a_staged_job_claim_only_when_the_server_cursor_equals_its_sequence(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity, operation="claim")
    # N == S: the sequence was never consumed at any generation; supersede with the proof recorded.
    attempt = _completed_attempt(runtime, signer, identity, challenge_sequence=4)
    cursor = runtime.commit_resync_supersession(
        attempt, pending, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
    )
    assert (cursor.next_sequence, cursor.generation) == (4, 1)
    (tombstone,) = runtime.load_superseded_calls()
    assert (tombstone.request_operation, tombstone.sequence, tombstone.challenge_next_sequence,
            tombstone.completed_next_sequence) == ("claim", 4, 4, 4)

    # N == S + 1 (from the challenge, the completion, or both): consumed -> refused, nothing changes.
    for challenge_sequence, completed in ((5, 5), (4, 5), (5, 4)):
        other, other_signer, other_identity = _claim_runtime(tmp_path, name=f"c{challenge_sequence}{completed}.sqlite3")
        staged = _stage_claim_chain(other, other_signer, other_identity, operation="claim")
        kept = _completed_attempt(other, other_signer, other_identity, challenge_sequence=challenge_sequence)
        before = (other.load_chain("claim", None), other.load_pending_calls(), other.load_resync_attempt("claim"))
        with pytest.raises(runtime_module.RuntimeClaimSequenceConsumed):
            other.commit_resync_supersession(
                kept, staged, next_nonce_b64=_b64(b"r" * 32), next_sequence=completed, generation=1, now_ms=5,
            )
        assert (other.load_chain("claim", None), other.load_pending_calls(),
                other.load_resync_attempt("claim")) == before
        assert other.load_superseded_calls() == ()

    # Any other claim body is not the fixed poll and is never superseded.
    odd, odd_signer, odd_identity = _claim_runtime(tmp_path, name="odd.sqlite3")
    staged = _stage_claim_chain(odd, odd_signer, odd_identity, operation="claim",
                                claim_body={"schema_version": "heel.runner-claim-request.v1", "x": 1})
    with pytest.raises(RunnerRuntimeConflict, match="not supersedable"):
        odd.commit_resync_supersession(
            _completed_attempt(odd, odd_signer, odd_identity, challenge_sequence=4), staged,
            next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
        )


def test_job_claim_supersession_refuses_while_a_local_run_is_active(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity, operation="claim")
    attempt = _completed_attempt(runtime, signer, identity, challenge_sequence=4)
    with sqlite3.connect(runtime.path) as conn:
        conn.execute("INSERT INTO active_runs VALUES(?,?,?)", ("a" * 64, b"x" * 64, 1))
    conn.close()
    with pytest.raises(RunnerRuntimeConflict, match="active run"):
        runtime.commit_resync_supersession(
            attempt, pending, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
        )


# --------------------------------------------------------------- T2b2R2: attempt mutations (4.1, 4.3)


def _recovery_bytes(path):
    with sqlite3.connect(path) as conn:
        rows = {table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("metadata", "control_chains", "pending_calls", "chain_recovery")}
    conn.close()
    return rows


def _fresh_start(runtime, signer, identity, fill=b"k", timestamp_ms=4):
    client_nonce = _b64(fill * 32)
    path, headers, body = _resync_start(signer, identity, client_nonce=client_nonce, timestamp_ms=timestamp_ms)
    return dict(operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
                timestamp_ms=timestamp_ms, now_ms=timestamp_ms)


def test_begin_resync_attempt_fails_closed_on_a_corrupt_existing_attempt_and_changes_no_byte(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity)
    _completed_attempt(runtime, signer, identity)
    with sqlite3.connect(runtime.path) as conn:
        blob = conn.execute("SELECT sealed_blob FROM chain_recovery WHERE kind='resync_attempt'").fetchone()[0]
        conn.execute("UPDATE chain_recovery SET sealed_blob=? WHERE kind='resync_attempt'",
                     (blob[:-1] + bytes([blob[-1] ^ 1]),))
    conn.close()
    before = _recovery_bytes(runtime.path)

    with pytest.raises(RunnerRuntimeCorrupt):
        runtime.begin_resync_attempt(**_fresh_start(runtime, signer, identity))

    assert _recovery_bytes(runtime.path) == before  # never repaired, replaced or deleted
    with pytest.raises(RunnerRuntimeCorrupt):
        runtime.load_resync_attempt("claim")
    reopened = RunnerRuntimeState(runtime.path, identity, signer)
    with pytest.raises(RunnerRuntimeCorrupt):
        reopened.begin_resync_attempt(**_fresh_start(reopened, signer, identity, fill=b"j"))
    assert _recovery_bytes(runtime.path) == before
    assert reopened.load_pending_calls() == (pending,)


@pytest.mark.parametrize("stage", ["started", "challenged", "completed"])
def test_begin_resync_attempt_refuses_to_replace_a_valid_unfinished_attempt(tmp_path, stage):
    runtime, signer, identity = _claim_runtime(tmp_path)
    if stage == "completed":
        existing = _completed_attempt(runtime, signer, identity)
    else:
        existing = runtime.begin_resync_attempt(**_fresh_start(runtime, signer, identity, fill=b"c", timestamp_ms=2))
        if stage == "challenged":
            existing = runtime.record_resync_challenge(
                existing, challenge_id="rrs_" + "e" * 32, server_challenge_b64=_b64(b"s" * 32),
                next_sequence=4, generation=0, expires_at_ms=60_002, now_ms=3,
            )
    before = _recovery_bytes(runtime.path)

    with pytest.raises(RunnerRuntimeConflict, match="already exists"):
        runtime.begin_resync_attempt(**_fresh_start(runtime, signer, identity))

    assert _recovery_bytes(runtime.path) == before
    reopened = RunnerRuntimeState(runtime.path, identity, signer)
    assert reopened.load_resync_attempt("claim") == existing
    # The explicit, validated transition: discard that exact attempt, then a fresh start.
    reopened.discard_resync_attempt(existing)
    fresh = reopened.begin_resync_attempt(**_fresh_start(reopened, signer, identity))
    assert reopened.load_resync_attempt("claim") == fresh != existing


def test_a_recorded_completion_is_resigned_only_for_the_identical_body_by_compare_and_swap(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    attempt = _completed_attempt(runtime, signer, identity)
    args = dict(challenge_id="rrs_" + "e" * 32, client_nonce=_b64(b"c" * 32),
                server_challenge=_b64(b"s" * 32), generation=0)
    path, headers, body = _resync_complete(signer, identity, timestamp_ms=40_000, **args)
    assert body == attempt.complete_body and headers != dict(attempt.complete_headers)

    resigned = runtime.resign_resync_completion(
        attempt, path=path, headers=headers, body=body, timestamp_ms=40_000, now_ms=40_000,
    )

    assert (resigned.complete_body, dict(resigned.complete_headers), resigned.complete_timestamp_ms) == (
        body, headers, 40_000,
    )
    assert (resigned.attempt_id, resigned.start_body, resigned.challenge_id) == (
        attempt.attempt_id, attempt.start_body, attempt.challenge_id,
    )
    assert RunnerRuntimeState(runtime.path, identity, signer).load_resync_attempt("claim") == resigned
    before = _recovery_bytes(runtime.path)
    # A stale snapshot, another body, or a forged signature never changes the persisted attempt.
    with pytest.raises(RunnerRuntimeConflict):
        runtime.resign_resync_completion(
            attempt, path=path, headers=headers, body=body, timestamp_ms=40_000, now_ms=40_000,
        )
    other_path, other_headers, other_body = _resync_complete(
        signer, identity, timestamp_ms=41_000, **{**args, "generation": 1},
    )
    with pytest.raises(RunnerRuntimeConflict):
        runtime.resign_resync_completion(
            resigned, path=other_path, headers=other_headers, body=other_body, timestamp_ms=41_000, now_ms=41_000,
        )
    forged = dict(headers, **{"X-Heel-Runner-Signature": _b64(b"x" * 64)})
    with pytest.raises(Exception):
        runtime.resign_resync_completion(
            resigned, path=path, headers=forged, body=body, timestamp_ms=40_000, now_ms=40_000,
        )
    assert _recovery_bytes(runtime.path) == before
    # An attempt with no recorded completion has nothing to re-sign.
    runtime.discard_resync_attempt(resigned)
    started = runtime.begin_resync_attempt(**_fresh_start(runtime, signer, identity))
    with pytest.raises(RunnerRuntimeConflict):
        runtime.resign_resync_completion(
            started, path=path, headers=headers, body=body, timestamp_ms=40_000, now_ms=40_000,
        )



def test_a_new_server_challenge_replaces_the_answered_one_only_by_compare_and_swap(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    started = runtime.begin_resync_attempt(**_fresh_start(runtime, signer, identity))
    with pytest.raises(RunnerRuntimeConflict):  # nothing to replace before a challenge exists
        runtime.replace_resync_challenge(
            started, challenge_id="rrs_" + "d" * 32, server_challenge_b64=_b64(b"t" * 32),
            next_sequence=4, generation=0, expires_at_ms=70_000, now_ms=5,
        )
    runtime.discard_resync_attempt(started)
    completed = _completed_attempt(runtime, signer, identity)
    before = _recovery_bytes(runtime.path)
    with pytest.raises(RunnerRuntimeConflict):  # the same challenge is not a new one
        runtime.replace_resync_challenge(
            completed, challenge_id=completed.challenge_id, server_challenge_b64=_b64(b"t" * 32),
            next_sequence=4, generation=0, expires_at_ms=70_000, now_ms=5,
        )
    runtime._commit_resync_chain(
        operation="claim", run_id=None, next_nonce_b64=_b64(b"g" * 32), next_sequence=4,
        generation=1, now_ms=4,
    )
    before = _recovery_bytes(runtime.path)
    with pytest.raises(RunnerRuntimeCorrupt):  # below the local generation
        runtime.replace_resync_challenge(
            completed, challenge_id="rrs_" + "d" * 32, server_challenge_b64=_b64(b"t" * 32),
            next_sequence=4, generation=0, expires_at_ms=70_000, now_ms=5,
        )
    assert _recovery_bytes(runtime.path) == before

    replaced = runtime.replace_resync_challenge(
        completed, challenge_id="rrs_" + "d" * 32, server_challenge_b64=_b64(b"t" * 32),
        next_sequence=4, generation=1, expires_at_ms=70_000, now_ms=5,
    )

    assert (replaced.attempt_id, replaced.start_body, dict(replaced.start_headers)) == (
        completed.attempt_id, completed.start_body, dict(completed.start_headers),
    )
    assert (replaced.challenge_id, replaced.challenge_generation, replaced.complete_body) == (
        "rrs_" + "d" * 32, 1, None,
    )
    assert RunnerRuntimeState(runtime.path, identity, signer).load_resync_attempt("claim") == replaced
    with pytest.raises(RunnerRuntimeConflict):  # a stale snapshot never changes it again
        runtime.replace_resync_challenge(
            completed, challenge_id="rrs_" + "f" * 32, server_challenge_b64=_b64(b"u" * 32),
            next_sequence=4, generation=1, expires_at_ms=70_000, now_ms=6,
        )


# ---------------------------------------------------------------------------
# C recovery, runtime phase R1: the v5 ``retired_claims`` archive, its archive-only serializer,
# the SQL-only load guards (Tier A), the authenticated on-demand read (Tier B), the atomic
# retirement transaction (Tier C) and the write-path anti-resurrection guard.
#
# Trust boundary of these fixtures: the runtime never interprets or verifies attestation bytes;
# the R2 control client verifies the grant-authority signature, the echoed challenge and every
# binding before it calls ``retire_inactive_claim``.  Unless a test says it uses bytes issued by
# the in-process control plane, the evidence below is synthetic and stands in for an attestation
# the client already accepted.  These tests therefore prove byte fidelity, bounds and local state
# transitions only -- never signature integration, the coordinator journey or a SaaS run.

import contextlib
import dataclasses
import json
import shutil
import tempfile
import time
from typing import Any

from heel.canary_contracts import ContractError, OPERATIONAL_RUN_SCHEMA, canonical_digest
from heel.canary_contracts import validate_runner_heartbeat_request
from heel.runner.runtime import _RuntimeSqliteConnection

_RUN_OPERATIONS = ("heartbeat", "progress", "result", "stop-ack")
_RETIRED_SCHEMA = "heel.runner-retired-claim.v1"
_TABLE_KEYS = {
    "metadata": "singleton", "control_chains": "chain", "pending_calls": "call_id",
    "terminal_disclosures": "run_hash", "active_runs": "run_hash",
    "chain_recovery": "record_id", "retired_claims": "run_hash",
}
_CAPABILITY = {
    "heartbeat": "runner_heartbeat", "progress": "runner_progress",
    "stop-ack": "runner_heartbeat", "result": "runner_result",
}
_STOPPED_GATE = {
    "active": False, "runner_state": "active", "proof_state": "valid",
    "proof_expires_at_ms": 20_000, "kill_switch_generation": 7,
    "stop_reason": "cloud_stop", "server_time_ms": 3_000,
}


def _semantic_rows(path):
    """RETIREMENT-RESYNC §5 semantic invariant: ordered full rows of every runtime table.

    Never file bytes (WAL and page bookkeeping may change while rows do not).  ``secure_delete``
    and ``synchronous`` are per-connection settings re-asserted by every runtime connection, so only
    the persistent ``journal_mode`` is compared here.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        tables = {name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        snapshot = {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY {key}").fetchall()
            for table, key in _TABLE_KEYS.items() if table in tables
        }
        snapshot["journal_mode"] = conn.execute("PRAGMA journal_mode").fetchone()[0]
    return snapshot


def _rows_for(path, table, run_hash):
    with contextlib.closing(sqlite3.connect(path)) as conn:
        key = _TABLE_KEYS[table]
        return conn.execute(
            f"SELECT * FROM {table} WHERE run_hash=? ORDER BY {key}", (run_hash,),
        ).fetchall()


def _raw(path, statement, parameters=()):
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute(statement, parameters)
        conn.commit()


def _run_hash_of(run_id):
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _chain_key(operation, run_id):
    return hashlib.sha256(canonical_bytes({"operation": operation, "run_id": run_id})).hexdigest()


@dataclasses.dataclass
class _Retirable:
    runtime: RunnerRuntimeState
    signer: Any
    identity: RunnerIdentity
    projection: dict
    authority: SigningAuthority
    grant: dict

    @property
    def run_id(self):
        return self.grant["run_id"]



def _install_claimed_run(runtime, signer, identity, projection, grant, *, gate=None, now_ms=2):
    """Install one run group through the public claim transaction (stage + commit_call)."""
    cursor = runtime.load_chain("claim", None)
    if cursor is None:
        cursor = runtime.install_chain(
            operation="claim", run_id=None, next_nonce_b64=_b64(b"c" * 32),
            next_sequence=1, generation=0, now_ms=1,
        )
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    headers = _signed_claim_chain_headers(
        signer, identity, path=path, body=body, nonce=cursor.next_nonce_b64,
        sequence=cursor.next_sequence, timestamp_ms=now_ms,
    )
    pending = runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path,
        capability="runner_claim", headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=now_ms,
    )
    run_id = grant["run_id"]
    installed = tuple(
        (operation, run_id, _b64(hashlib.sha256(f"{operation}:{run_id}".encode()).digest()), 1, 0)
        for operation in _RUN_OPERATIONS
    )
    return runtime.commit_call(
        pending.call_id, next_nonce_b64=_b64(hashlib.sha256(f"claim:{run_id}".encode()).digest()),
        now_ms=now_ms, installed_chains=installed,
        active_run=ActiveRunInstall(
            run_id=run_id, approval_projection=projection, grant=grant,
            gate=dict(gate or _STOPPED_GATE), claim_response_digest="a" * 64,
            gate_response_digest="b" * 64, claimed_at_ms=now_ms, gate_received_at_ms=now_ms,
        ),
    )


def _grant_for(base, authority, run_id):
    from tests.test_runner_stop import resign_grant

    return resign_grant({**base, "run_id": run_id}, authority)


def _retirable(tmp_path, *, name="runtime.sqlite3"):
    _store, identity, signer, _manifest, projection = compiled_pair(tmp_path / "authority")
    authority = SigningAuthority.generate()
    grant = signed_grant(_manifest, projection, identity, authority)
    runtime = RunnerRuntimeState(tmp_path / name, identity, signer)
    _install_claimed_run(runtime, signer, identity, projection, grant)
    return _Retirable(runtime, signer, identity, projection, authority, grant)


def _projection_for(signer, grant, projection, *, adapter_versions=(), runner_version="1",
                    engine_version="1", identifiers=None, lifecycle="claimed", maximal_numbers=False):
    ids = identifiers or {
        "grant_id": grant["grant_id"], "workspace_id": grant["workspace_id"],
        "project_id": grant["project_id"],
    }
    big = _MAX_SAFE if maximal_numbers else None
    unsigned = {
        "schema_version": OPERATIONAL_RUN_SCHEMA, "run_id": grant["run_id"], **ids,
        "manifest_digest": grant["approval"]["manifest_digest"],
        "approval_projection_digest": projection["projection_digest"],
        "grant_digest": grant["grant_digest"],
        "event_sequence": big or 0, "lifecycle_phase": lifecycle, "execution_disposition": None,
        "timestamps": {
            "claimed_at_ms": big or 2, "started_at_ms": None, "updated_at_ms": big or 3,
            "stop_requested_at_ms": None, "stop_acknowledged_at_ms": None, "terminal_at_ms": None,
        },
        "counters": {
            "requests_started": 10 if maximal_numbers else 0,
            "requests_completed": 10 if maximal_numbers else 0,
            "response_bytes_read": big or 0,
            "actions_contained": 10 if maximal_numbers else 0,
            "retries_used": 1 if maximal_numbers else 0,
            "remaining_requests": 10 if maximal_numbers else 20,
            "remaining_wall_ms": 60_000,
        },
        "versions": {
            "runner_version": runner_version, "engine_version": engine_version,
            "adapter_versions": list(adapter_versions),
        },
        "error_category": "credential_unavailable" if maximal_numbers else "none",
        "stop_reason": "local_emergency_stop" if maximal_numbers else "none",
        "containment_codes": sorted({
            "admitted", "action_started", "action_completed", "action_rejected",
            "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted",
        }) if maximal_numbers else [],
        "redaction_count": big or 0,
    }
    return {
        **unsigned, "projection_digest": canonical_digest(unsigned),
        "signing_key_id": signer.key_id,
        "signature_b64": _b64(signer.sign(canonical_bytes(unsigned))),
    }


_MAX_SAFE = 9_007_199_254_740_991


def _heartbeat_body(projection_value, run_id):
    request = validate_runner_heartbeat_request({
        "schema_version": "heel.runner-heartbeat-request.v1", "run_id": run_id,
        "operational_projection": projection_value,
    })
    return canonical_bytes(request)


def _stage_run_call(runtime, signer, identity, run_id, operation, body, *, timestamp_ms=5):
    cursor = runtime.load_chain(operation, run_id)
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/runs/{run_id}/{operation}"
    proof = {
        "schema_version": "heel.runner-request-proof.v1", "workspace_id": identity.workspace_id,
        "runner_id": identity.runner_id, "key_id": identity.key_id,
        "capability": _CAPABILITY[operation], "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
        "server_nonce": cursor.next_nonce_b64, "sequence": cursor.next_sequence,
    }
    headers = {
        "Content-Type": "application/json", "X-Heel-Runner-Id": identity.runner_id,
        "X-Heel-Runner-Key-Id": identity.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
        "X-Heel-Runner-Signature": _b64(signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))),
        "X-Heel-Runner-Nonce": cursor.next_nonce_b64, "X-Heel-Runner-Sequence": str(cursor.next_sequence),
    }
    return runtime.stage_call(
        request_operation=operation, chain_operation=operation, run_id=run_id, path=path,
        capability=_CAPABILITY[operation], headers=headers, body=body,
        expected_state_digest=cursor.state_digest, now_ms=timestamp_ms,
    )


def _stage_heartbeat(fixture, run_id=None, grant=None):
    grant = grant or fixture.grant
    run_id = run_id or grant["run_id"]
    body = _heartbeat_body(_projection_for(fixture.signer, grant, fixture.projection), run_id)
    return _stage_run_call(fixture.runtime, fixture.signer, fixture.identity, run_id, "heartbeat", body)


def _synthetic_evidence(identity, run_id, *, timestamp_ms=7):
    """Synthetic accepted-attestation stand-in (see the section header): bounds-valid, never verified."""
    return runtime_module.InactiveClaimAttestationEvidence(
        request_method="POST",
        request_path=(
            f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}"
            f"/runs/{run_id}/inactive-claim-attestation"
        ),
        request_headers={
            "X-Heel-Runner-Id": identity.runner_id, "X-Heel-Runner-Key-Id": identity.key_id,
            "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
            "X-Heel-Runner-Signature": _b64(b"\x01" * 64),
        },
        request_body=canonical_bytes({"schema": "synthetic-request", "run_id": run_id}),
        request_timestamp_ms=timestamp_ms, response_status=200,
        response_body=canonical_bytes({"schema": "synthetic-response", "run_id": run_id}),
    )


def _active_digest(runtime, run_id):
    (control,) = [item for item in runtime.load_active_run_controls() if item.run_id == run_id]
    return control.state_digest


def _retire(fixture, *, run_id=None, evidence=None, probe="absent", now_ms=50, expected=None):
    runtime = fixture.runtime
    run_id = run_id or fixture.run_id
    return runtime.retire_inactive_claim(
        run_id, expected_state_digest=expected or _active_digest(runtime, run_id),
        evidence=evidence or _synthetic_evidence(fixture.identity, run_id),
        reservation_probe=probe, now_ms=now_ms,
    )


def _open_retired_core(runtime, run_id):
    run_hash = _run_hash_of(run_id)
    with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
        blob = conn.execute("SELECT sealed_blob FROM retired_claims WHERE run_hash=?", (run_hash,)).fetchone()[0]
    return runtime._open_stable(blob, schema=_RETIRED_SCHEMA, record_id=run_hash)


def _reseal_retired_core(runtime, run_id, core):
    """Re-seal a (tampered) core under the exact archive AAD with a recomputed retired digest."""
    run_hash = _run_hash_of(run_id)
    body = {key: value for key, value in core.items() if key != "state_digest"}
    resealed = {**body, "state_digest": runtime_module._retired_state_digest(body)}
    blob = runtime._seal_stable(resealed, schema=_RETIRED_SCHEMA, record_id=run_hash)
    _raw(runtime.path, "UPDATE retired_claims SET sealed_blob=? WHERE run_hash=?", (blob, run_hash))


def _count_stable_key_decrypts(runtime, monkeypatch):
    """Record every AEAD decryption made with the runtime's stable state key (not the KEK unwrap)."""
    calls = []
    real = runtime._crypto
    stable_key = runtime._key

    class CountingAead:
        def __init__(self, key):
            self._key = key
            self._inner = real.aead(key)

        def encrypt(self, nonce, data, aad):
            return self._inner.encrypt(nonce, data, aad)

        def decrypt(self, nonce, data, aad):
            if self._key == stable_key:
                calls.append(aad)
            return self._inner.decrypt(nonce, data, aad)

    monkeypatch.setattr(runtime, "_crypto", runtime_module._RuntimeCrypto(
        aead=CountingAead, hashes=real.hashes, hkdf=real.hkdf,
    ))
    return calls


def _supersede_claim_chain_calls(runtime, signer, identity, count):
    """Real claim-chain recovery: stage, resync and supersede ``count`` calls into sealed tombstones."""
    for index in range(count):
        cursor = runtime.load_chain("claim", None)
        pending = _stage_claim_chain(runtime, signer, identity)
        attempt = _completed_attempt(
            runtime, signer, identity, generation=cursor.generation,
            challenge_sequence=cursor.next_sequence,
        )
        runtime.commit_resync_supersession(
            attempt, pending, next_nonce_b64=_b64(index.to_bytes(4, "big") * 8),
            next_sequence=cursor.next_sequence, generation=cursor.generation + 1, now_ms=5 + index,
        )


@pytest.fixture(scope="module")
def tombstoned_template(tmp_path_factory):
    """One retirable run beside the 512 tombstones the runtime retains (built once, copied per test)."""
    root = tmp_path_factory.mktemp("tombstoned-template")
    fixture = _retirable(root)
    _supersede_claim_chain_calls(fixture.runtime, fixture.signer, fixture.identity, 512)
    fixture.runtime.close()
    with contextlib.closing(sqlite3.connect(fixture.runtime.path)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return fixture


def _copy_template(template, tmp_path):
    target = tmp_path / "copied" / "runtime.sqlite3"
    target.parent.mkdir(mode=0o700)
    shutil.copyfile(template.runtime.path, target)
    os.chmod(target, 0o600)
    runtime = RunnerRuntimeState(target, template.identity, template.signer)
    return dataclasses.replace(template, runtime=runtime)


def _rotation_journal_after(runtime, old, new, *, nonce):
    """The accepted rotation journal for the runtime's current claim cursor (generation + 1)."""
    journal = _rotation_journal(old, new, nonce=nonce)
    generation = runtime.load_chain("claim", None).generation + 1
    return dataclasses.replace(journal, activation_response={
        **journal.activation_response, "initial_claim_generation": generation,
    })


def _component_bytes(component):
    return base64.b64decode(component["sealed_blob_b64"], validate=True)


# --------------------------------------------------------------------- serializer (T-S1..T-S5)

def test_retired_archive_grammar_allows_only_the_five_base64_paths_beyond_4096_and_keeps_every_other_closed_rule():
    encode = runtime_module._retired_json_bytes
    parse = runtime_module._retired_json_parse
    assert set(runtime_module._RETIRED_LONG_TEXT_PATHS) == {
        ("active", "sealed_blob_b64"), ("chains", "*", "sealed_blob_b64"),
        ("pending", "*", "sealed_blob_b64"), ("attestation", "request", "body_b64"),
        ("attestation", "response", "body_b64"),
    }
    # Everywhere else the public 4 096-byte string rule is unchanged.
    assert encode({"note": "a" * 4096})
    for value in ({"note": "a" * 4097}, {"active": {"index": "a" * 4097}}):
        with pytest.raises(ValueError):
            encode(value)
    with pytest.raises(ContractError):
        canonical_bytes({"active": {"sealed_blob_b64": "A" * 8008}})
    # Long paths: base64 alphabet, padding, exact per-path text caps.
    assert encode({"active": {"sealed_blob_b64": "A" * 8008}})
    assert encode({"chains": [{"sealed_blob_b64": "A" * 5464}]})
    assert encode({"attestation": {"response": {"body_b64": "A" * 10924}}})
    for value in (
        {"active": {"sealed_blob_b64": "A" * 8007 + "*"}},
        {"active": {"sealed_blob_b64": "A" * 8009}},
        {"active": {"sealed_blob_b64": "A" * 8006 + "\n" + "A"}},
        {"active": {"sealed_blob_b64": "A" * 524292}},
        {"chains": [{"sealed_blob_b64": "A" * 5468}]},
        {"pending": [{"sealed_blob_b64": "A" * 524292}]},
        {"attestation": {"request": {"body_b64": "A=AA"}}},
        {"attestation": {"response": {"body_b64": "A" * 10928}}},
    ):
        with pytest.raises(ValueError):
            encode(value)
    # Every other closed rule of the public canonicalizer still applies.
    for value in (
        {"flag": True}, {"negative": -1}, {"large": _MAX_SAFE + 1}, {"float": 1.5},
        {"non_nfc": "é"}, {"control": "a\x01b"}, {"surrogate": "\ud800"},
        {"nested": [[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]},
    ):
        with pytest.raises(ValueError):
            encode(value)
    with pytest.raises(ValueError):
        encode({1: "non-string key"})
    # Same bytes as the public canonicalizer wherever both accept.
    small = {"b": [1, {"c": "é"}], "a": "x", "active": {"sealed_blob_b64": "QUJD"}}
    assert encode(small) == canonical_bytes(small)
    assert parse(encode(small)) == small
    for plaintext in (
        b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a": 1}', b'{"a":NaN}', b'[1]', b'{"a":true}',
    ):
        with pytest.raises(ValueError):
            parse(plaintext)


def test_retired_archive_text_caps_bound_allocation_and_byte_caps_are_exact_after_decode(tmp_path):
    fixture = _retirable(tmp_path)
    _stage_heartbeat(fixture)
    _retire(fixture)
    core = _open_retired_core(fixture.runtime, fixture.run_id)
    validate = fixture.runtime._validate_retired_core
    validate(core, run_id=fixture.run_id)

    def variant(mutator):
        changed = json.loads(json.dumps(core))
        mutator(changed)
        body = {key: value for key, value in changed.items() if key != "state_digest"}
        return {**body, "state_digest": runtime_module._retired_state_digest(body)}

    cases = (
        (lambda c, b: c["attestation"]["response"].__setitem__("body_b64", b), 8192, 8193, 8194),
        (lambda c, b: c["attestation"]["request"].__setitem__("body_b64", b), 2048, 2049, 2050),
        (lambda c, b: c["chains"][0].__setitem__("sealed_blob_b64", b), 4096, 4098, 4099),
    )
    for setter, allowed, decoded_too_long, text_too_long in cases:
        assert len(_b64(b"x" * decoded_too_long)) == len(_b64(b"x" * allowed))
        validate(variant(lambda c: setter(c, _b64(b"x" * allowed))), run_id=fixture.run_id)
        # The text passes the grammar's allocation cap; only the exact decoded byte cap refuses it.
        accepted_text = variant(lambda c: setter(c, _b64(b"x" * decoded_too_long)))
        runtime_module._retired_json_bytes(accepted_text)
        with pytest.raises(RunnerRuntimeCorrupt):
            validate(accepted_text, run_id=fixture.run_id)
        with pytest.raises(ValueError):
            variant(lambda c: setter(c, _b64(b"x" * text_too_long)))
    for path in (("active",), ("pending", 0)):
        def oversize(c, path=path):
            target = c[path[0]] if len(path) == 1 else c[path[0]][path[1]]
            target["sealed_blob_b64"] = _b64(b"x" * 393217)
        with pytest.raises(ValueError):
            variant(oversize)
    # Non-canonical base64 (unused padding bits) passes the alphabet but fails strict canonical decode.
    with pytest.raises(RunnerRuntimeCorrupt):
        validate(variant(lambda c: c["attestation"]["request"].__setitem__("body_b64", "QUJD" + "QR==")),
                 run_id=fixture.run_id)


def test_retire_inactive_claim_archives_a_real_active_component_beyond_4096_base64_and_load_retired_claim_opens_it(
    tmp_path, monkeypatch,
):
    """T-S3: the §1 fixture state (active text > 4 096 chars) with real control-plane attestation bytes.

    The attestation bytes are issued by the in-process control plane for its own run; this runtime
    archives them as opaque evidence, exactly as the serializer design's probe did.  The coherent
    same-run journey is test 4a.
    """
    from tests.test_runner_control_http import _LiveHttpRun

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            evidence, _attestation = _real_attestation_evidence(live)
        finally:
            live.close()
    runtime, signer, identity, grant = _runtime_with_active_run(tmp_path)
    run_id = grant["run_id"]
    run_hash = _run_hash_of(run_id)
    fixture = _Retirable(runtime, signer, identity, {}, None, grant)
    before_active = _rows_for(runtime.path, "active_runs", run_hash)
    assert len(_b64(before_active[0][1])) > 4096
    before_chains = _rows_for(runtime.path, "control_chains", run_hash)

    record = _retire(fixture, evidence=evidence)

    assert record.active["sealed_blob_b64"] == _b64(before_active[0][1])
    assert {item["index"]["chain"]: _component_bytes(item) for item in record.chains} == {
        row[0]: row[5] for row in before_chains
    }
    assert base64.b64decode(record.attestation["request"]["body_b64"]) == evidence.request_body
    assert base64.b64decode(record.attestation["response"]["body_b64"]) == evidence.response_body
    assert dict(record.attestation["request"]["headers"]) == dict(evidence.request_headers)
    calls = _count_stable_key_decrypts(runtime, monkeypatch)
    assert runtime.load_retired_claim(run_id) == record
    assert len(calls) == 1
    calls.clear()
    assert runtime.load_retired_claim(run_id, authenticate_components=True) == record
    assert len(calls) == 6


def test_open_stable_refuses_an_over_bound_retired_blob_before_decryption_and_leaves_tombstones_unchanged(
    tmp_path, monkeypatch,
):
    runtime, signer, identity = _claim_runtime(tmp_path)
    pending = _stage_claim_chain(runtime, signer, identity)
    attempt = _completed_attempt(runtime, signer, identity)
    runtime.commit_resync_supersession(
        attempt, pending, next_nonce_b64=_b64(b"r" * 32), next_sequence=4, generation=1, now_ms=5,
    )
    with sqlite3.connect(runtime.path) as conn:
        tombstone_rows = conn.execute("SELECT * FROM chain_recovery ORDER BY record_id").fetchall()
    conn.close()
    tombstones = runtime.load_superseded_calls()

    calls = _count_stable_key_decrypts(runtime, monkeypatch)
    bound = runtime_module._RETIRED_CLAIM_BOUND
    assert bound == 1_095_036
    with pytest.raises(RunnerRuntimeCorrupt):
        runtime._open_stable(b"\0" * (bound + 1), schema=_RETIRED_SCHEMA, record_id="a" * 64)
    assert calls == []
    with pytest.raises(RunnerRuntimeCorrupt):
        runtime._open_stable(b"\0" * bound, schema=_RETIRED_SCHEMA, record_id="a" * 64)
    assert len(calls) == 1
    # The tombstone (else) arm is untouched: same rows, same opened records, same 4 096 ceiling.
    assert runtime.load_superseded_calls() == tombstones
    with sqlite3.connect(runtime.path) as conn:
        assert conn.execute("SELECT * FROM chain_recovery ORDER BY record_id").fetchall() == tombstone_rows
    conn.close()
    with pytest.raises(ContractError):
        runtime._seal_stable(
            {"long": "a" * 4097}, schema="heel.runner-superseded-call.v1", record_id="b" * 64,
        )


def test_retired_state_digest_uses_its_own_domain_over_the_archive_bytes():
    digest = runtime_module._retired_state_digest
    core = {"schema_version": _RETIRED_SCHEMA, "run_id": "crun_" + "a" * 32, "value": 1}
    assert runtime_module._RETIRED_STATE_DIGEST_DOMAIN == b"heel.runner-retired-claim-digest.v1\0"
    assert digest(core) == hashlib.sha256(
        b"heel.runner-retired-claim-digest.v1\0" + runtime_module._retired_json_bytes(core)
    ).hexdigest()
    assert digest(core) != _state_digest(core)
    assert digest({**core, "value": 2}) != digest(core)
    assert digest({"active": {"sealed_blob_b64": "A" * 8008}})


# --------------------------------------------------------------------- schema v5 (T-U1)

def _downgrade_to_v4(path):
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("DROP INDEX idx_retired_claims_created")
        conn.execute("DROP TABLE retired_claims")
        conn.execute("ALTER TABLE metadata RENAME TO metadata_v5")
        conn.execute(runtime_module._V4_SCHEMA_SQL[0])
        conn.execute(
            "INSERT INTO metadata SELECT singleton,'heel.runner-runtime-state.v4',workspace_id,runner_id,"
            "runner_key_id,public_key_digest,authority_epoch,authority_identity_digest,"
            "rotation_fence_digest,state_key_ciphertext FROM metadata_v5"
        )
        conn.execute("DROP TABLE metadata_v5")
        conn.commit()
        assert RunnerRuntimeState._schema_matches(conn, runtime_module._V4_SCHEMA_SQL)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def test_runtime_v4_to_v5_upgrade_preserves_every_row_and_rejects_permissive_precreated_schema(tmp_path):
    fixture = _retirable(tmp_path / "source")
    _stage_heartbeat(fixture)
    _supersede_claim_chain_calls(fixture.runtime, fixture.signer, fixture.identity, 1)
    fixture.runtime.close()
    source = fixture.runtime.path
    _downgrade_to_v4(source)
    variants = {}
    for name in ("plain", "permissive", "run-chain-recovery"):
        target = tmp_path / name / "runtime.sqlite3"
        target.parent.mkdir(mode=0o700)
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        variants[name] = target
    _raw(variants["permissive"], "CREATE TABLE retired_claims(run_hash TEXT PRIMARY KEY,sealed_blob BLOB,created_at_ms INTEGER)")
    _raw(
        variants["run-chain-recovery"],
        "INSERT INTO chain_recovery(record_id,kind,chain,generation,sealed_blob,created_at_ms) VALUES(?,?,?,?,?,?)",
        ("e" * 64, "superseded_call", _chain_key("heartbeat", fixture.run_id), 1, b"\0" * 29, 1),
    )
    before = {name: _semantic_rows(path) for name, path in variants.items()}

    upgraded = RunnerRuntimeState(variants["plain"], fixture.identity, fixture.signer)
    after = _semantic_rows(variants["plain"])
    assert after["metadata"][0][1] == "heel.runner-runtime-state.v5"
    assert after["metadata"][0][2:] == before["plain"]["metadata"][0][2:]
    for table in ("control_chains", "pending_calls", "terminal_disclosures", "active_runs", "chain_recovery"):
        assert after[table] == before["plain"][table]
    assert after["retired_claims"] == []
    with contextlib.closing(sqlite3.connect(variants["plain"])) as conn:
        assert RunnerRuntimeState._schema_matches(conn, runtime_module._V5_SCHEMA_SQL)
    assert [item.run_id for item in upgraded.load_active_run_controls()] == [fixture.run_id]
    assert len(upgraded.load_superseded_calls()) == 1

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime state schema is invalid"):
        RunnerRuntimeState(variants["permissive"], fixture.identity, fixture.signer)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime chain recovery index is invalid"):
        RunnerRuntimeState(variants["run-chain-recovery"], fixture.identity, fixture.signer)
    for name in ("permissive", "run-chain-recovery"):
        assert _semantic_rows(variants[name]) == before[name]


# --------------------------------------------------------------------- Tier C: the retirement transaction

def test_retire_inactive_claim_seals_active_chains_and_every_pending_core_then_removes_exactly_that_group(tmp_path):
    fixture = _retirable(tmp_path)
    other = _grant_for(fixture.grant, fixture.authority, "crun_" + "b" * 32)
    _install_claimed_run(fixture.runtime, fixture.signer, fixture.identity, fixture.projection, other, now_ms=3)
    target_pending = _stage_heartbeat(fixture)
    _stage_heartbeat(fixture, grant=other)
    _stage_claim_chain(fixture.runtime, fixture.signer, fixture.identity)
    path = fixture.runtime.path
    run_hash = _run_hash_of(fixture.run_id)
    before = _semantic_rows(path)
    rows = {table: _rows_for(path, table, run_hash) for table in ("active_runs", "control_chains", "pending_calls")}
    expected_digest = _active_digest(fixture.runtime, fixture.run_id)
    evidence = _synthetic_evidence(fixture.identity, fixture.run_id)

    record = _retire(fixture, evidence=evidence, now_ms=77)

    after = _semantic_rows(path)
    assert after["retired_claims"] == [(run_hash, after["retired_claims"][0][1], 77)]
    for table in ("active_runs", "control_chains", "pending_calls"):
        assert [row for row in after[table] if row not in before[table]] == []
        assert [row for row in before[table] if row not in after[table]] == rows[table]
    for table in ("metadata", "terminal_disclosures", "chain_recovery"):
        assert after[table] == before[table]
    (active,) = rows["active_runs"]
    assert record.active == {
        "table": "active_runs", "schema": "heel.runner-active-run-state.v1",
        "primary_fields": [run_hash], "index": {"run_hash": run_hash, "updated_at_ms": active[2]},
        "sealed_blob_b64": _b64(active[1]),
    }
    assert [item["index"]["operation"] for item in record.chains] == list(_RUN_OPERATIONS)
    for item in record.chains:
        (row,) = [row for row in rows["control_chains"] if row[0] == item["index"]["chain"]]
        assert item["index"] == {
            "chain": row[0], "run_hash": row[1], "operation": row[2], "next_sequence": row[3],
            "generation": row[4], "updated_at_ms": row[6],
        }
        assert _component_bytes(item) == row[5]
    (pending_row,) = rows["pending_calls"]
    (pending,) = record.pending
    assert pending["delivery"] == "uncertain"
    assert pending["primary_fields"] == [target_pending.call_id]
    assert pending["index"] == {
        "call_id": pending_row[0], "chain": pending_row[1], "run_hash": pending_row[2],
        "operation": pending_row[3], "sequence": pending_row[4], "generation": pending_row[5],
        "created_at_ms": pending_row[7],
    }
    assert _component_bytes(pending) == pending_row[6]
    assert dict(record.local_observations) == {"reservation": "absent", "terminal": "absent"}
    assert dict(record.sealing_identity) == {
        "workspace_id": fixture.identity.workspace_id, "runner_id": fixture.identity.runner_id,
        "runner_key_id": fixture.identity.key_id, "public_key_digest": fixture.identity.fingerprint,
        "authority_epoch": 1,
    }
    assert base64.b64decode(record.attestation["request"]["body_b64"]) == evidence.request_body
    assert base64.b64decode(record.attestation["response"]["body_b64"]) == evidence.response_body
    assert record.reason == "cloud_inactive_attested" and record.created_at_ms == 77
    assert record.active["sealed_blob_b64"] and expected_digest
    assert [item.run_id for item in fixture.runtime.load_active_run_controls()] == [other["run_id"]]
    assert fixture.runtime.load_retired_claim(fixture.run_id) == record
    reopened = RunnerRuntimeState(path, fixture.identity, fixture.signer)
    assert reopened.load_retired_claim(fixture.run_id, authenticate_components=True) == record


@pytest.mark.parametrize("case", (
    "changed-snapshot", "unknown-run", "local-terminal", "progress-pending", "reservation-reserved",
    "reservation-journal-pending", "reservation-unresolved", "reservation-not-a-string",
    "chain-recovery-row",
))
def test_retire_inactive_claim_rejects_changed_snapshot_terminal_or_non_heartbeat_pending_without_mutation(
    tmp_path, case,
):
    fixture = _retirable(tmp_path)
    runtime = fixture.runtime
    kwargs = {}
    if case == "changed-snapshot":
        kwargs["expected"] = "0" * 64
    elif case == "unknown-run":
        kwargs["run_id"] = "crun_" + "c" * 32
        kwargs["expected"] = "0" * 64
    elif case == "local-terminal":
        runtime.register_local_terminal(
            run_id=fixture.run_id, project_id=fixture.grant["project_id"], grant_id=fixture.grant["grant_id"],
            approval_projection_digest=fixture.grant["approval"]["projection_digest"],
            terminal_projection_digest="b" * 64, terminal_record_digest="c" * 64,
            terminal_at_ms=10, retention_expires_at_ms=20,
        )
    elif case == "progress-pending":
        body = canonical_bytes({
            "schema_version": "heel.runner-progress-request.v1", "run_id": fixture.run_id,
            "operational_projection": _projection_for(fixture.signer, fixture.grant, fixture.projection),
        })
        _stage_run_call(runtime, fixture.signer, fixture.identity, fixture.run_id, "progress", body)
    elif case.startswith("reservation-"):
        kwargs["probe"] = {
            "reservation-reserved": "reserved", "reservation-journal-pending": "journal_pending",
            "reservation-unresolved": "unresolved", "reservation-not-a-string": object(),
        }[case]
    if case == "chain-recovery-row":
        expected = _active_digest(runtime, fixture.run_id)
        kwargs["expected"] = expected
        _raw(
            runtime.path,
            "INSERT INTO chain_recovery(record_id,kind,chain,generation,sealed_blob,created_at_ms) VALUES(?,?,?,?,?,?)",
            ("d" * 64, "resync_attempt", _chain_key("heartbeat", fixture.run_id), 0, b"\0" * 29, 1),
        )
    before = _semantic_rows(runtime.path)

    expected_error = {
        "changed-snapshot": (RunnerRuntimeConflict, "runtime active run state changed"),
        "unknown-run": (RunnerRuntimeConflict, "runtime active run is unavailable"),
        "local-terminal": (RunnerRuntimeConflict, "runtime retirement requires no local terminal"),
        "progress-pending": (RunnerRuntimeConflict, "runtime retirement requires only a heartbeat pending call"),
        "chain-recovery-row": (RunnerRuntimeCorrupt, "runtime chain recovery index is invalid"),
    }.get(case, (RunnerRuntimeConflict, "runtime retirement requires an absent local reservation"))
    with pytest.raises(expected_error[0], match=expected_error[1]):
        _retire(fixture, **kwargs)

    assert _semantic_rows(runtime.path) == before
    assert before["retired_claims"] == []


@pytest.mark.parametrize("kind", ("resync_attempt", "superseded_call"))
def test_retire_inactive_claim_refuses_a_chain_recovery_row_on_a_run_chain_without_mutation(
    tmp_path, monkeypatch, kind,
):
    fixture = _retirable(tmp_path)
    expected = _active_digest(fixture.runtime, fixture.run_id)
    _raw(
        fixture.runtime.path,
        "INSERT INTO chain_recovery(record_id,kind,chain,generation,sealed_blob,created_at_ms) VALUES(?,?,?,?,?,?)",
        ("d" * 64, kind, _chain_key("heartbeat", fixture.run_id), 0, b"\0" * 29, 1),
    )
    before = _semantic_rows(fixture.runtime.path)
    # Tier A3 refuses the corrupt row on every connection, before the transaction starts.
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime chain recovery index is invalid"):
        _retire(fixture, expected=expected)
    assert _semantic_rows(fixture.runtime.path) == before
    # With A3 disabled (fault isolation only), R0 inside the transaction still refuses on its own.
    monkeypatch.setattr(fixture.runtime, "_assert_claim_only_recovery_locked", lambda conn: None)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime retired claim has chain recovery rows"):
        _retire(fixture, expected=expected)
    assert _semantic_rows(fixture.runtime.path) == before


@pytest.mark.parametrize("stage", ("started", "challenged", "completed"))
def test_retire_inactive_claim_leaves_an_open_claim_chain_resync_attempt_and_tombstones_byte_identical(
    tmp_path, tombstoned_template, stage,
):
    fixture = _copy_template(tombstoned_template, tmp_path)
    runtime = fixture.runtime
    client_nonce = _b64(b"q" * 32)
    path, headers, body = _resync_start(fixture.signer, fixture.identity, client_nonce=client_nonce)
    attempt = runtime.begin_resync_attempt(
        operation="claim", path=path, headers=headers, body=body, client_nonce_b64=client_nonce,
        timestamp_ms=2, now_ms=2,
    )
    if stage in {"challenged", "completed"}:
        cursor = runtime.load_chain("claim", None)
        attempt = runtime.record_resync_challenge(
            attempt, challenge_id="rrs_" + "f" * 32, server_challenge_b64=_b64(b"s" * 32),
            next_sequence=cursor.next_sequence, generation=cursor.generation,
            expires_at_ms=60_002, now_ms=2,
        )
    if stage == "completed":
        path, headers, body = _resync_complete(
            fixture.signer, fixture.identity, challenge_id="rrs_" + "f" * 32, client_nonce=client_nonce,
            server_challenge=_b64(b"s" * 32), generation=attempt.challenge_generation,
        )
        attempt = runtime.record_resync_completion(
            attempt, path=path, headers=headers, body=body, timestamp_ms=3, now_ms=3,
        )
    before = _semantic_rows(runtime.path)
    assert len(before["chain_recovery"]) == 513

    _retire(fixture)

    assert _semantic_rows(runtime.path)["chain_recovery"] == before["chain_recovery"]
    assert runtime.load_resync_attempt("claim") == attempt
    with pytest.raises(RunnerRuntimeConflict, match="runtime rotation has a pending chain recovery"):
        runtime.probe_rotation_eligible(old_identity=fixture.identity)
    runtime.discard_resync_attempt(attempt)
    new_signer = Signer(b"z" * 32)
    new_identity = dataclasses.replace(
        fixture.identity, public_key_b64=base64.b64encode(new_signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(new_signer.public_key).hexdigest(), key_id=new_signer.key_id,
    )
    journal = _rotation_journal_after(runtime, fixture.identity, new_identity, nonce=_b64(b"w" * 32))
    probe = runtime.probe_rotation_eligible(old_identity=fixture.identity)
    eligibility = runtime.assert_rotation_eligible(
        old_identity=fixture.identity, prepared_journal_digest="d" * 64,
        runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=60,
    )
    runtime.finish_rotation(
        journal, eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
    )
    assert runtime.load_retired_claim(fixture.run_id, authenticate_components=True).run_id == fixture.run_id
    assert len(runtime.load_superseded_calls(limit=64)) == 64


def test_retire_inactive_claim_records_zero_run_chain_recovery_rows_and_the_four_chain_keys(tmp_path, monkeypatch):
    """T-B1 / T-B1': Tier B recomputes the four keys; decryption counts 1 by default, 7 / 6 with components."""
    fixture = _retirable(tmp_path)
    other = _grant_for(fixture.grant, fixture.authority, "crun_" + "b" * 32)
    _install_claimed_run(fixture.runtime, fixture.signer, fixture.identity, fixture.projection, other, now_ms=3)
    _stage_heartbeat(fixture)
    runtime = fixture.runtime
    keys = {operation: _chain_key(operation, fixture.run_id) for operation in _RUN_OPERATIONS}

    record = _retire(fixture)
    _retire(fixture, run_id=other["run_id"])

    assert dict(record.chain_recovery) == {"run_chain_rows": 0, "run_chains": keys}
    assert runtime.load_retired_claim("crun_" + "e" * 32) is None
    calls = _count_stable_key_decrypts(runtime, monkeypatch)
    assert runtime.load_retired_claim(fixture.run_id) == record
    assert len(calls) == 1
    calls.clear()
    assert runtime.load_retired_claim(fixture.run_id, authenticate_components=True) == record
    assert len(calls) == 7
    calls.clear()
    assert runtime.load_retired_claim(other["run_id"], authenticate_components=True).pending == ()
    assert len(calls) == 6
    monkeypatch.undo()

    original = _open_retired_core(runtime, fixture.run_id)
    mutations = {
        "mutated-key": lambda c: c["chain_recovery"]["run_chains"].__setitem__("progress", "0" * 64),
        "nonzero-count": lambda c: c["chain_recovery"].__setitem__("run_chain_rows", 1),
        "extra-key": lambda c: c["chain_recovery"].__setitem__("extra", 0),
        "extra-top-level-key": lambda c: c.__setitem__("extra", 0),
        "wrong-created-at": lambda c: c.__setitem__("created_at_ms", c["created_at_ms"] + 1),
        "pending-not-heartbeat": lambda c: c["pending"][0]["index"].__setitem__("operation", "progress"),
        "delivery-certain": lambda c: c["pending"][0].__setitem__("delivery", "delivered"),
        "chain-order": lambda c: c["chains"].reverse(),
    }
    for name, mutate in mutations.items():
        tampered = json.loads(json.dumps(original))
        mutate(tampered)
        _reseal_retired_core(runtime, fixture.run_id, tampered)
        with pytest.raises(RunnerRuntimeCorrupt):
            runtime.load_retired_claim(fixture.run_id)
        # Tier A never opens archives: the runtime itself still opens and serves live calls.
        assert runtime.load_chain("claim", None) is not None
        assert RunnerRuntimeState(runtime.path, fixture.identity, fixture.signer).load_chain("claim", None)
    # A tampered digest alone is refused even though the outer AEAD tag is valid.
    tampered = json.loads(json.dumps(original))
    tampered["state_digest"] = "0" * 64
    run_hash = _run_hash_of(fixture.run_id)
    _raw(runtime.path, "UPDATE retired_claims SET sealed_blob=? WHERE run_hash=?", (
        runtime._seal_stable(tampered, schema=_RETIRED_SCHEMA, record_id=run_hash), run_hash,
    ))
    with pytest.raises(RunnerRuntimeCorrupt):
        runtime.load_retired_claim(fixture.run_id)


def test_load_retired_claim_authenticates_every_embedded_component_under_the_sealing_identity_after_rotation(
    tmp_path, tombstoned_template, monkeypatch,
):
    """T-B2 (and RETIREMENT-RESYNC §5 test 9): stable outer seal, historical component AAD, rotation untouched."""
    fixture = _copy_template(tombstoned_template, tmp_path)
    runtime = fixture.runtime
    _stage_heartbeat(fixture)
    record = _retire(fixture)
    tombstones = runtime.load_superseded_calls(limit=64)
    old_identity = fixture.identity
    new_signer = Signer(b"y" * 32)
    new_identity = dataclasses.replace(
        old_identity, public_key_b64=base64.b64encode(new_signer.public_key).decode("ascii"),
        fingerprint=hashlib.sha256(new_signer.public_key).hexdigest(), key_id=new_signer.key_id,
    )
    stable_key = runtime._key
    journal = _rotation_journal_after(runtime, old_identity, new_identity, nonce=_b64(b"w" * 32))
    probe = runtime.probe_rotation_eligible(old_identity=old_identity)
    eligibility = runtime.assert_rotation_eligible(
        old_identity=old_identity, prepared_journal_digest="d" * 64,
        runtime_rotation_intent_digest="e" * 64, probe=probe, now_ms=60,
    )
    statements = []
    original_execute = _RuntimeSqliteConnection.execute

    def traced(self, sql, parameters=()):
        statements.append(sql)
        return original_execute(self, sql, parameters)

    opened_retired = []
    original_open_stable = runtime._open_stable

    def tracked_open_stable(value, *, schema, record_id):
        if schema == _RETIRED_SCHEMA:
            opened_retired.append(record_id)
        return original_open_stable(value, schema=schema, record_id=record_id)

    monkeypatch.setattr(_RuntimeSqliteConnection, "execute", traced)
    monkeypatch.setattr(runtime, "_open_stable", tracked_open_stable)
    runtime.finish_rotation(
        journal,
        eligibility=eligibility, new_identity=new_identity, new_signer=new_signer,
    )
    monkeypatch.undo()
    assert opened_retired == []
    assert not [sql for sql in statements if "sealed_blob" in sql and "retired_claims" in sql]
    assert [sql for sql in statements if "retired_claims" in sql]  # Tier A ran, column-only
    assert runtime._key == stable_key and runtime.identity == new_identity

    assert runtime.load_superseded_calls(limit=64) == tombstones
    reopened = RunnerRuntimeState(runtime.path, new_identity, new_signer)
    assert reopened.load_retired_claim(fixture.run_id, authenticate_components=True) == record
    # The embedded cores authenticate under the historical identity AAD only, never the new one.
    with pytest.raises(RunnerRuntimeCorrupt):
        reopened._open(
            base64.b64decode(record.active["sealed_blob_b64"]), schema="heel.runner-active-run-state.v1",
            primary_fields=tuple(record.active["primary_fields"]),
        )
    original = _open_retired_core(reopened, fixture.run_id)
    components = [("active", None)] + [("chains", index) for index in range(4)] + [("pending", 0)]
    for section, index in components:
        tampered = json.loads(json.dumps(original))
        component = tampered[section] if index is None else tampered[section][index]
        blob = bytearray(base64.b64decode(component["sealed_blob_b64"]))
        blob[len(blob) // 2] ^= 1
        component["sealed_blob_b64"] = _b64(bytes(blob))
        _reseal_retired_core(reopened, fixture.run_id, tampered)
        assert reopened.load_retired_claim(fixture.run_id).run_id == fixture.run_id
        with pytest.raises(RunnerRuntimeCorrupt):
            reopened.load_retired_claim(fixture.run_id, authenticate_components=True)


# --------------------------------------------------------------------- crash and atomicity

@pytest.mark.parametrize("crash_before", ("DELETE FROM active_runs", "DELETE FROM control_chains"))
def test_retire_inactive_claim_crash_between_insert_and_commit_leaves_every_source_row_and_no_retired_row(
    tmp_path, monkeypatch, crash_before,
):
    fixture = _retirable(tmp_path)
    _stage_heartbeat(fixture)
    before = _semantic_rows(fixture.runtime.path)
    seen = []
    original_execute = _RuntimeSqliteConnection.execute

    def crashing(self, sql, parameters=()):
        seen.append(sql)
        if type(sql) is str and sql.startswith(crash_before):
            raise RuntimeError("injected crash")
        return original_execute(self, sql, parameters)

    monkeypatch.setattr(_RuntimeSqliteConnection, "execute", crashing)
    with pytest.raises(RuntimeError, match="injected crash"):
        _retire(fixture)
    monkeypatch.undo()
    assert any(sql.startswith("INSERT INTO retired_claims") for sql in seen)
    if crash_before == "DELETE FROM control_chains":
        assert any(sql.startswith("DELETE FROM active_runs") for sql in seen)

    reopened = RunnerRuntimeState(fixture.runtime.path, fixture.identity, fixture.signer)
    assert _semantic_rows(fixture.runtime.path) == before
    record = _retire(dataclasses.replace(fixture, runtime=reopened))
    assert reopened.load_retired_claim(fixture.run_id) == record


# --------------------------------------------------------------------- Tier A: SQL-only load guards

@pytest.mark.parametrize("table", ("active_runs", "control_chains", "pending_calls", "terminal_disclosures"))
def test_runtime_open_fails_closed_when_a_retired_run_hash_also_appears_in_any_authority_table(
    tmp_path, monkeypatch, table,
):
    fixture = _retirable(tmp_path)
    _retire(fixture)
    run_hash = _run_hash_of(fixture.run_id)
    sentinel = b"S" * 29
    statements = {
        "active_runs": ("INSERT INTO active_runs(run_hash,sealed_blob,updated_at_ms) VALUES(?,?,?)",
                        (run_hash, sentinel, 1)),
        "control_chains": (
            "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
            "VALUES(?,?,?,?,?,?,?)", (_chain_key("heartbeat", fixture.run_id), run_hash, "heartbeat", 1, 0, sentinel, 1),
        ),
        "pending_calls": (
            "INSERT INTO pending_calls(call_id,chain,run_hash,operation,sequence,generation,sealed_blob,created_at_ms) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("9" * 64, _chain_key("heartbeat", fixture.run_id), run_hash, "heartbeat", 1, 0, sentinel, 1),
        ),
        "terminal_disclosures": (
            "INSERT INTO terminal_disclosures(run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms) "
            "VALUES(?,?,?,?,?)", (run_hash, 1, "local_terminal", sentinel, 1),
        ),
    }
    _raw(fixture.runtime.path, *statements[table])
    opened = []
    original_open = fixture.runtime._open
    monkeypatch.setattr(fixture.runtime, "_open", lambda value, **kw: (opened.append(value), original_open(value, **kw))[1])
    original_open_stable = fixture.runtime._open_stable
    monkeypatch.setattr(
        fixture.runtime, "_open_stable",
        lambda value, **kw: (opened.append(value), original_open_stable(value, **kw))[1],
    )

    with pytest.raises(RunnerRuntimeCorrupt, match="runtime retired claim index is invalid"):
        fixture.runtime.load_chain("claim", None)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime retired claim index is invalid"):
        RunnerRuntimeState(fixture.runtime.path, fixture.identity, fixture.signer)
    assert sentinel not in opened
    assert not [value for value in opened if len(value) > 29]


@pytest.mark.parametrize("kind", ("resync_attempt", "superseded_call"))
@pytest.mark.parametrize("retired", (True, False))
def test_runtime_open_fails_closed_on_any_chain_recovery_row_outside_the_claim_chain(
    tmp_path, tombstoned_template, kind, retired,
):
    fixture = _copy_template(tombstoned_template, tmp_path)
    runtime = fixture.runtime
    begin = _resync_start(fixture.signer, fixture.identity, client_nonce=_b64(b"q" * 32))
    runtime.begin_resync_attempt(
        operation="claim", path=begin[0], headers=begin[1], body=begin[2],
        client_nonce_b64=_b64(b"q" * 32), timestamp_ms=2, now_ms=2,
    )
    # Valid recovery state (512 claim-key tombstones + one attempt = 513 rows) opens.
    assert len(_semantic_rows(runtime.path)["chain_recovery"]) == 513
    assert RunnerRuntimeState(runtime.path, fixture.identity, fixture.signer).load_resync_attempt("claim")
    if retired:
        _retire(fixture)
        run_id = fixture.run_id
    else:
        run_id = "crun_" + "7" * 32
    _raw(
        runtime.path,
        "INSERT INTO chain_recovery(record_id,kind,chain,generation,sealed_blob,created_at_ms) VALUES(?,?,?,?,?,?)",
        ("c" * 64, kind, _chain_key("stop-ack", run_id), 0, b"\0" * 29, 1),
    )
    before = _semantic_rows(runtime.path)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime chain recovery index is invalid"):
        runtime.load_chain("claim", None)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime chain recovery index is invalid"):
        RunnerRuntimeState(runtime.path, fixture.identity, fixture.signer)
    assert _semantic_rows(runtime.path) == before


def test_retired_claim_beside_live_active_group_is_corrupt_and_fails_closed(tmp_path):
    fixture = _retirable(tmp_path)
    run_hash = _run_hash_of(fixture.run_id)
    (active,) = _rows_for(fixture.runtime.path, "active_runs", run_hash)
    _retire(fixture)
    _raw(fixture.runtime.path, "INSERT INTO active_runs(run_hash,sealed_blob,updated_at_ms) VALUES(?,?,?)", active)
    before = _semantic_rows(fixture.runtime.path)
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime retired claim index is invalid"):
        fixture.runtime.load_active_run_controls()
    with pytest.raises(RunnerRuntimeCorrupt, match="runtime retired claim index is invalid"):
        RunnerRuntimeState(fixture.runtime.path, fixture.identity, fixture.signer)
    assert _semantic_rows(fixture.runtime.path) == before


# --------------------------------------------------------------------- write-path anti-resurrection

def _stage_claim(runtime, signer, identity, *, timestamp_ms):
    cursor = runtime.load_chain("claim", None)
    path = f"/v1/workspaces/{identity.workspace_id}/runners/{identity.runner_id}/claim"
    body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    return runtime.stage_call(
        request_operation="claim", chain_operation="claim", run_id=None, path=path,
        capability="runner_claim",
        headers=_signed_claim_chain_headers(
            signer, identity, path=path, body=body, nonce=cursor.next_nonce_b64,
            sequence=cursor.next_sequence, timestamp_ms=timestamp_ms,
        ),
        body=body, expected_state_digest=cursor.state_digest, now_ms=timestamp_ms,
    )


def test_commit_call_refuses_to_install_an_active_group_for_a_retired_run_without_mutation(tmp_path):
    fixture = _retirable(tmp_path)
    runtime = fixture.runtime
    _retire(fixture)
    staged = _stage_claim(runtime, fixture.signer, fixture.identity, timestamp_ms=9)
    before = _semantic_rows(runtime.path)

    def commit(grant):
        run_id = grant["run_id"]
        return runtime.commit_call(
            staged.call_id, next_nonce_b64=_b64(b"N" * 32), now_ms=9,
            installed_chains=tuple((op, run_id, _b64(op[0].encode() * 32), 1, 0) for op in _RUN_OPERATIONS),
            active_run=ActiveRunInstall(
                run_id=run_id, approval_projection=fixture.projection, grant=grant,
                gate=dict(_STOPPED_GATE), claim_response_digest="a" * 64,
                gate_response_digest="b" * 64, claimed_at_ms=9, gate_received_at_ms=9,
            ),
        )

    with pytest.raises(RunnerRuntimeConflict, match="runtime active run was retired"):
        commit(fixture.grant)
    assert _semantic_rows(runtime.path) == before
    assert runtime.get_pending_call(staged.call_id) == staged
    # The claim chain is not poisoned: the same staged claim installs a different run.
    other = _grant_for(fixture.grant, fixture.authority, "crun_" + "d" * 32)
    commit(other)
    assert [item.run_id for item in runtime.load_active_run_controls()] == [other["run_id"]]


def test_install_chain_refuses_a_run_chain_for_a_retired_run(tmp_path):
    fixture = _retirable(tmp_path)
    runtime = fixture.runtime
    _retire(fixture)
    before = _semantic_rows(runtime.path)
    with pytest.raises(RunnerRuntimeConflict, match="runtime active run was retired"):
        runtime.install_chain(
            operation="heartbeat", run_id=fixture.run_id, next_nonce_b64=_b64(b"h" * 32),
            next_sequence=1, generation=0, now_ms=9,
        )
    assert _semantic_rows(runtime.path) == before
    claim = runtime.load_chain("claim", None)
    assert runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=claim.next_nonce_b64,
        next_sequence=claim.next_sequence, generation=claim.generation, now_ms=claim.updated_at_ms,
    ) == claim


# --------------------------------------------------------------------- sizes (tests 4a / 4b / 4c)

class _LostResponseTransport:
    """The request leaves; no response arrives (the C 'delivery uncertain' case)."""

    def __init__(self):
        self.requests = []

    def post(self, path, *, headers=None, body=b""):
        self.requests.append((path, dict(headers or {}), body))
        raise OSError("response lost")


class _LiveSigner(SecureSigner):
    def __init__(self, private, key_id):
        self._private = private
        self.public_key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = key_id

    def sign(self, payload):
        return self._private.sign(payload)


def _real_attestation_evidence(live, *, challenge=b"C" * 32):
    """Ask the real in-process control plane over loopback HTTP; return the exact wire bytes."""
    import http.client

    from heel.canary_contracts import RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN
    from heel.canary_contracts import RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA
    from tests.test_runner_control_http import _attestation_body, _cloud_stop, _verify_attestation

    _cloud_stop(live)
    body = _attestation_body(live, challenge=challenge)
    path = f"/v1/workspaces/{live.workspace}/runners/runner/runs/{live.run_id}/inactive-claim-attestation"
    timestamp_ms = int(time.time() * 1000)
    proof = {
        "schema_version": RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA, "workspace_id": live.workspace,
        "runner_id": "runner", "key_id": live.key_id, "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
    }
    headers = {
        "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": live.key_id,
        "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms),
        "X-Heel-Runner-Signature": _b64(live.private.sign(
            RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN + canonical_bytes(proof)
        )),
    }
    conn = http.client.HTTPConnection("127.0.0.1", live.server.server_address[1], timeout=5)
    try:
        conn.request("POST", path, body, {"Content-Type": "application/json", **headers})
        response = conn.getresponse()
        raw = response.read()
        status = response.status
    finally:
        conn.close()
    assert status == 200, raw
    attestation = json.loads(raw)
    _verify_attestation(live, attestation, challenge)
    return runtime_module.InactiveClaimAttestationEvidence(
        request_method="POST", request_path=path, request_headers=headers, request_body=body,
        request_timestamp_ms=timestamp_ms, response_status=status, response_body=raw,
    ), attestation


def _largest_admitted_versions(build_body, *, limit):
    """Largest-first reduction: keep 128-byte versions, then fill adapter versions up to ``limit``."""
    versions = []
    for index in range(20):
        candidate = versions + [chr(ord("a") + index) * 128]
        if len(build_body(candidate)) > limit:
            break
        versions = candidate
    if len(versions) < 20:
        tail_prefix = chr(ord("a") + len(versions))
        for length in range(128, 0, -1):
            candidate = versions + [tail_prefix * length]
            if len(build_body(candidate)) <= limit:
                versions = candidate
                break
    return versions


def test_retired_claim_largest_state_the_existing_runtime_admits_fits_the_metadata_cap_and_the_derived_bound(
    tmp_path, capsys,
):
    """Test 4a: the largest state the existing runtime admits, staged through the real client path.

    The runtime adopts the in-process control plane's runner identity and installs that plane's own
    signed grant and approval, so the archived attestation is the genuine one for the archived run.
    Every heartbeat field is at its validator maximum except ``adapter_versions``, reduced largest
    first until the canonical body is the largest ``stage_call`` admits (PENDING-BODY-CAP, ≤ 3 072 B).
    """
    from heel.runner.control_client import RunnerControlClient
    from tests.test_runner_control_http import _LiveHttpRun

    with tempfile.TemporaryDirectory() as directory:
        live = _LiveHttpRun(directory)
        try:
            signer = _LiveSigner(live.private, live.key_id)
            identity = RunnerIdentity(
                runner_id="runner", workspace_id=live.workspace, runner_version="1.0.0",
                adapter_versions={"canary": "1.0.0"},
                public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
                fingerprint=hashlib.sha256(signer.public_key).hexdigest(), key_id=live.key_id,
                pairing_phrase=runner_phrase_words()[:6],
            )
            runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
            runtime.install_chain(
                operation="claim", run_id=None, next_nonce_b64=_b64(b"c" * 32),
                next_sequence=1, generation=0, now_ms=1,
            )
            staged_claim = _stage_claim(runtime, signer, identity, timestamp_ms=2)
            runtime.commit_call(
                staged_claim.call_id, next_nonce_b64=_b64(b"n" * 32), now_ms=2,
                installed_chains=tuple(
                    (op, live.run_id, live.chains[op]["next_nonce_b64"], live.chains[op]["next_sequence"],
                     live.chains[op]["generation"])
                    for op in _RUN_OPERATIONS
                ),
                active_run=ActiveRunInstall(
                    run_id=live.run_id, approval_projection=live.approval, grant=live.grant,
                    gate={
                        "active": True, "runner_state": "active", "proof_state": "valid",
                        "proof_expires_at_ms": 2_000_000_000_000,
                        "kill_switch_generation": live.grant["kill_switch_generation"],
                        "stop_reason": "none", "server_time_ms": 2,
                    },
                    claim_response_digest="a" * 64, gate_response_digest="b" * 64,
                    claimed_at_ms=2, gate_received_at_ms=2,
                ),
            )
            ids = {"grant_id": live.grant["grant_id"], "workspace_id": live.workspace, "project_id": "prj"}

            def projection(versions):
                return _projection_for(
                    signer, live.grant, live.approval, adapter_versions=versions,
                    runner_version="r" * 128, engine_version="e" * 128, identifiers=ids,
                    maximal_numbers=True,
                )

            def body_of(versions):
                return _heartbeat_body(projection(versions), live.run_id)

            versions = _largest_admitted_versions(body_of, limit=3072)
            body = body_of(versions)
            assert len(body) <= 3072 and len(body_of(versions + ["z" * 128])) > 3072
            transport = _LostResponseTransport()
            client = RunnerControlClient(
                origin="https://control.example", workspace_id=live.workspace, runner_id="runner",
                signer=signer, clock=lambda: 3, transport=transport,
                nonce_source=lambda _key: _b64(b"x" * 32), runtime=runtime,
            )
            with pytest.raises(OSError, match="response lost"):
                client.heartbeat(run_id=live.run_id, operational_projection=projection(versions))
            ((_path, _headers, sent_body),) = transport.requests
            assert sent_body == body
            (staged,) = runtime.load_pending_calls()
            assert staged.request_operation == "heartbeat" and staged.body == body
            run_hash = _run_hash_of(live.run_id)
            sources = {
                table: _rows_for(runtime.path, table, run_hash)
                for table in ("active_runs", "control_chains", "pending_calls")
            }
            evidence, _attestation = _real_attestation_evidence(live)
        finally:
            live.close()

    record = runtime.retire_inactive_claim(
        live.run_id, expected_state_digest=_active_digest(runtime, live.run_id), evidence=evidence,
        reservation_probe="absent", now_ms=int(time.time() * 1000),
    )
    core = _open_retired_core(runtime, live.run_id)
    metadata = runtime_module._retired_metadata_size(core)
    with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
        blob_length = conn.execute("SELECT length(sealed_blob) FROM retired_claims").fetchone()[0]
    assert metadata <= runtime_module._RETIRED_CLAIM_METADATA_CAP == 24_576
    assert blob_length <= runtime_module._RETIRED_CLAIM_BOUND == 1_095_036
    assert _component_bytes(record.active) == sources["active_runs"][0][1]
    assert [_component_bytes(item) for item in record.chains] == [
        next(row[5] for row in sources["control_chains"] if row[2] == op) for op in _RUN_OPERATIONS
    ]
    assert _component_bytes(record.pending[0]) == sources["pending_calls"][0][6]
    assert base64.b64decode(record.attestation["request"]["body_b64"]) == evidence.request_body
    assert base64.b64decode(record.attestation["response"]["body_b64"]) == evidence.response_body
    assert runtime.load_retired_claim(live.run_id, authenticate_components=True) == record
    with capsys.disabled():
        print(
            "\n[R1 test 4a measured] heartbeat body", len(body), "B; adapter_versions", len(versions),
            "(last", len(versions[-1]) if versions else 0, "B); pending blob", len(sources["pending_calls"][0][6]),
            "B; active blob", len(sources["active_runs"][0][1]), "B; attestation request",
            len(evidence.request_body), "B, response", len(evidence.response_body), "B; metadata", metadata,
            "B; archive blob", blob_length, "B",
        )


def _maximal_wire_heartbeat(signer, grant, projection):
    ids = {"grant_id": "g" * 128, "workspace_id": "w" * 128, "project_id": "p" * 128}
    value = _projection_for(
        signer, grant, projection, adapter_versions=[chr(ord("a") + i) * 128 for i in range(20)],
        runner_version="r" * 128, engine_version="e" * 128, identifiers=ids, maximal_numbers=True,
    )
    return value, _heartbeat_body(value, grant["run_id"])


def test_retired_claim_shape_at_every_field_ceiling_including_a_wire_valid_maximal_heartbeat_stays_under_the_cap(
    tmp_path, capsys,
):
    """Test 4b (RETIREMENT-RESYNC §5 test 5 extended): a shape computation, not a reachability claim."""
    from heel.runner.control_client import RunnerControlClient

    fixture = _retirable(tmp_path)
    runtime = fixture.runtime
    projection_value, body = _maximal_wire_heartbeat(fixture.signer, fixture.grant, fixture.projection)
    # The maximal body is wire-valid and its runner signature verifies the way the client checks it.
    validate_runner_heartbeat_request(json.loads(body))
    RunnerControlClient._verify_projection_signature(SimpleSigned(fixture.signer), projection_value)
    hypothetical_pending = {
        "schema_version": "heel.runner-pending-call.v1", "workspace_id": "w" * 128, "runner_id": "r" * 128,
        "runner_key_id": "k" * 128, "call_id": "0" * 64, "request_operation": "heartbeat",
        "chain_operation": "heartbeat", "run_id": fixture.run_id, "path": "/" + "p" * 4095,
        "capability": "runner_heartbeat", "method": "POST",
        "headers": {name: "h" * 4096 for name in (
            "Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms",
            "X-Heel-Runner-Signature", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence",
        )},
        "body_b64": _b64(body), "body_sha256": "0" * 64, "server_nonce_b64": _b64(b"n" * 32),
        "sequence": _MAX_SAFE, "generation": _MAX_SAFE, "prior_chain_state_digest": "0" * 64,
        "created_at_ms": _MAX_SAFE, "state_digest": "0" * 64,
    }
    pending_plaintext = json.dumps(hypothetical_pending, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    pending_blob_length = len(pending_plaintext.encode()) + 28
    assert pending_blob_length <= 393_216 and len(_b64(b"\0" * pending_blob_length)) <= 524_288

    quote = '"' * 128  # the worst escaping the grammar admits: 2 bytes per byte
    ceiling_text = {
        "active": "A" * 524_288, "chain": "A" * 5_464, "pending": "A" * 524_288,
        "request": "A" * 2_732, "response": "A" * 10_924,
    }
    core = runtime._retired_core(
        run_id=fixture.run_id, created_at_ms=_MAX_SAFE,
        sealing_identity={
            "workspace_id": quote, "runner_id": quote, "runner_key_id": quote,
            "public_key_digest": "f" * 64, "authority_epoch": _MAX_SAFE,
        },
        active={
            "table": "active_runs", "schema": "heel.runner-active-run-state.v1", "primary_fields": ["f" * 64],
            "index": {"run_hash": "f" * 64, "updated_at_ms": _MAX_SAFE},
            "sealed_blob_b64": ceiling_text["active"],
        },
        chains=[{
            "table": "control_chains", "schema": "heel.runner-control-chain-state.v1",
            "primary_fields": ["f" * 64],
            "index": {
                "chain": "f" * 64, "run_hash": "f" * 64, "operation": operation,
                "next_sequence": _MAX_SAFE, "generation": _MAX_SAFE, "updated_at_ms": _MAX_SAFE,
            },
            "sealed_blob_b64": ceiling_text["chain"],
        } for operation in _RUN_OPERATIONS],
        pending=[{
            "table": "pending_calls", "schema": "heel.runner-pending-call.v1", "primary_fields": ["f" * 64],
            "index": {
                "call_id": "f" * 64, "chain": "f" * 64, "run_hash": "f" * 64, "operation": "heartbeat",
                "sequence": _MAX_SAFE, "generation": _MAX_SAFE, "created_at_ms": _MAX_SAFE,
            },
            "delivery": "uncertain", "sealed_blob_b64": ceiling_text["pending"],
        }],
        attestation={
            "request": {
                "method": "POST",
                "path": f"/v1/workspaces/{quote}/runners/{quote}/runs/{fixture.run_id}/inactive-claim-attestation",
                "headers": {
                    "X-Heel-Runner-Id": quote, "X-Heel-Runner-Key-Id": quote,
                    "X-Heel-Runner-Timestamp-Ms": str(_MAX_SAFE),
                    "X-Heel-Runner-Signature": _b64(b"\xff" * 64),
                },
                "body_b64": ceiling_text["request"], "timestamp_ms": _MAX_SAFE,
            },
            "response": {"status": 200, "body_b64": ceiling_text["response"]},
        },
    )
    metadata = runtime_module._retired_metadata_size(core)
    total = len(runtime_module._retired_json_bytes(core)) + 28
    assert metadata <= runtime_module._RETIRED_CLAIM_METADATA_CAP
    assert total <= runtime_module._RETIRED_CLAIM_BOUND <= 2_097_152
    with capsys.disabled():
        print(
            "\n[R1 test 4b measured] wire-valid maximal heartbeat body", len(body), "B (base64",
            len(_b64(body)), "chars); hypothetical pending blob", pending_blob_length,
            "B; ceiling-shape metadata", metadata, "B (hand count 23167, cap 24576); ceiling-shape sealed size",
            total, "B (bound 1095036)",
        )


class SimpleSigned:
    """Minimal stand-in exposing exactly what ``_verify_projection_signature`` reads from ``self``."""

    def __init__(self, signer):
        self.signer = signer


def test_stage_call_refuses_a_wire_valid_heartbeat_body_over_3072_bytes_pending_body_cap_backlog(tmp_path):
    """Test 4c pins PENDING-BODY-CAP (launch backlog): flip this assertion when the cap is fixed."""
    fixture = _retirable(tmp_path)
    _projection_value, body = _maximal_wire_heartbeat(fixture.signer, fixture.grant, fixture.projection)
    assert len(body) > 3072
    validate_runner_heartbeat_request(json.loads(body))
    before = _semantic_rows(fixture.runtime.path)
    with pytest.raises(ContractError):
        _stage_run_call(fixture.runtime, fixture.signer, fixture.identity, fixture.run_id, "heartbeat", body)
    assert _semantic_rows(fixture.runtime.path) == before


# --------------------------------------------------------------------- Tier A query plan and timing (T-P1)

def test_runtime_open_guards_plan_live_first_and_stay_bounded_with_ten_thousand_retired_records(
    tmp_path, tombstoned_template, capsys,
):
    """T-P1: a full *reachable* live/recovery population plus 10 000 retired rows, no ANALYZE.

    Reachable maxima differ from the loose SQL limits: chain_recovery holds 512 tombstones plus one
    attempt (513), never its 769 ceiling.  The 10 000 retired rows are a documented raw-SQL fixture
    (29-byte blobs, valid CHECKs): Tier A compares index columns only and never opens them.
    """
    fixture = _copy_template(tombstoned_template, tmp_path)
    runtime = fixture.runtime
    for index in range(63):
        grant = _grant_for(fixture.grant, fixture.authority, f"crun_{index + 1:032x}")
        _install_claimed_run(runtime, fixture.signer, fixture.identity, fixture.projection, grant, now_ms=3)
    controls = runtime.load_active_run_controls()
    assert len(controls) == 64
    grants = {control.run_id: dict(control.grant) for control in controls}
    for run_id in sorted(grants):
        _stage_heartbeat(fixture, grant=grants[run_id])
    for run_id in sorted(grants)[:9]:
        body = canonical_bytes({
            "schema_version": "heel.runner-progress-request.v1", "run_id": run_id,
            "operational_projection": _projection_for(fixture.signer, grants[run_id], fixture.projection),
        })
        _stage_run_call(runtime, fixture.signer, fixture.identity, run_id, "progress", body)
    begin = _resync_start(fixture.signer, fixture.identity, client_nonce=_b64(b"q" * 32))
    runtime.begin_resync_attempt(
        operation="claim", path=begin[0], headers=begin[1], body=begin[2],
        client_nonce_b64=_b64(b"q" * 32), timestamp_ms=2, now_ms=2,
    )
    _stage_claim_chain(runtime, fixture.signer, fixture.identity)

    def counts():
        with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
            return {
                table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("active_runs", "control_chains", "pending_calls", "chain_recovery", "retired_claims")
            }

    def time_connections():
        samples = []
        for _ in range(10):
            started = time.perf_counter()
            with runtime._connection():
                pass
            samples.append(time.perf_counter() - started)
        return samples

    live_counts = counts()
    assert live_counts == {
        "active_runs": 64, "control_chains": 257, "pending_calls": 74, "chain_recovery": 513,
        "retired_claims": 0,
    }
    without_retired = time_connections()
    with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
        conn.executemany(
            "INSERT INTO retired_claims(run_hash,sealed_blob,created_at_ms) VALUES(?,?,?)",
            ((hashlib.sha256(b"retired-%d" % index).hexdigest(), b"\0" * 29, index) for index in range(10_000)),
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'sqlite_stat%'").fetchone()[0] == 0
        plans = {
            statement: [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + statement, (
                (_chain_key("claim", None),) if "chain_recovery" in statement else ()
            ))]
            for statement in runtime_module._RETIRED_CLAIM_GUARD_SQL
        }
    with_retired = time_connections()
    assert counts()["retired_claims"] == 10_000
    assert len(plans) == 5
    for statement, details in plans.items():
        assert not any(detail.startswith("SCAN r") for detail in details), (statement, details)
        if "retired_claims" in statement:
            alias = statement.split("FROM ", 1)[1].split(" ", 2)[1]
            assert details[0].startswith((f"SCAN {alias}", f"SEARCH {alias}")), (statement, details)
            assert any(
                detail.startswith("SEARCH r USING") and "(run_hash=?)" in detail for detail in details
            ), (statement, details)
        else:
            assert details == ["SCAN chain_recovery"], details
    # §6.4 of the serializer design: grammar cost on a ceiling-sized archive plaintext.
    ceiling = {"active": {"sealed_blob_b64": "A" * 524_288}, "pending": [{"sealed_blob_b64": "A" * 524_288}]}
    started = time.perf_counter()
    runtime_module._retired_json_parse(runtime_module._retired_json_bytes(ceiling))
    ceiling_parse = time.perf_counter() - started
    with capsys.disabled():
        print("\n[R1 T-P1 measured] counts", live_counts, "+ 10000 retired rows")
        for statement, details in plans.items():
            print("[R1 T-P1 plan]", statement, "=>", details)
        print(
            "[R1 T-P1 timing] 10 x _connection() without retired rows: median %.4f s max %.4f s; "
            "with 10000 retired rows: median %.4f s max %.4f s; ceiling-size grammar round trip %.4f s" % (
                sorted(without_retired)[5], max(without_retired), sorted(with_retired)[5],
                max(with_retired), ceiling_parse,
            )
        )


# --------------------------------------------------------------------- pruned-run resurrection (pruning ruling C2)

def test_retire_inactive_claim_archives_a_resurrected_pruned_group_verbatim_and_grants_nothing(tmp_path):
    """C2: a group resurrected for an already pruned and compacted run is archived verbatim; nothing is granted.

    The run executes, terminates and is pruned and compacted through the real Store and runtime paths.
    The group is then re-installed by ``commit_call`` from a SYNTHETIC claim body naming the pruned run
    (it stands in for a faulty server's replay; this direct API test makes no HTTP or client claim), and
    retired with the fixture attestation.  ``reservation: "absent"`` is the current probe value, not
    history: the Store's signed compaction floor still refuses the pruned grant.
    """
    from heel.runner.execution import ExecutionBundle
    from heel.runner.store import RunReservationProbe, RunnerStoreError
    from tests.test_runner_stop import (
        LocalCanaryExecutor, ScriptedTransport, StaticVault, _install_runtime_active_claim, active_gate,
    )

    store, identity, signer, manifest, projection = compiled_pair(tmp_path / "authority")
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    run_id = grant["run_id"]
    target = ScriptedTransport([401, 200, 200, 403])
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    ).execute(ExecutionBundle(manifest, projection, grant), transport=target, gate_source=active_gate)
    target_requests = len(target.calls)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    _install_runtime_active_claim(runtime, identity, signer, projection, grant)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(run_id))
    store.detach_terminal(run_id, runtime=runtime, expected_local_state_digest=local.state_digest, now_ms=2_000)
    pending = runtime.claim_due_prune(now_ms=store.load_run(run_id)["retention_expires_at_ms"])[0]
    receipt = store.prune_runtime_terminal(
        run_id, runtime=runtime, expected_runtime_state_digest=pending.state_digest,
        now_ms=pending.retention_expires_at_ms,
    )
    store.finish_pruned_compaction(
        runtime.finish_prune(receipt=receipt, expected_prune_pending_state_digest=pending.state_digest),
        runtime=runtime,
    )
    runs = store.run_path(run_id).parent

    def store_files():
        return {path.name: path.read_bytes() for path in sorted(runs.iterdir())}

    compacted = store_files()
    assert sorted(compacted) == ["run-authority-checkpoint.json", "run-authority-index.json"]
    assert store.probe_run_reservation(run_id) is RunReservationProbe.ABSENT
    assert runtime.load_active_run_controls() == ()

    # SYNTHETIC claim body (labelled): commit_call re-installs the pruned run's group.
    _install_claimed_run(runtime, signer, identity, projection, grant, now_ms=pending.retention_expires_at_ms + 1)
    run_hash = _run_hash_of(run_id)
    installed = {
        table: _rows_for(runtime.path, table, run_hash) for table in ("active_runs", "control_chains", "pending_calls")
    }
    assert len(installed["active_runs"]) == 1 and len(installed["control_chains"]) == 4
    assert installed["pending_calls"] == []
    assert runtime.load_terminal_state(run_id) is None
    probe = store.probe_run_reservation(run_id)
    assert probe is RunReservationProbe.ABSENT
    with pytest.raises(RunnerStoreError, match="execution grant has expired"):
        store.reserve_run(grant, retention_expires_at_ms=pending.retention_expires_at_ms + 2)
    assert store_files() == compacted

    fixture = _Retirable(runtime, signer, identity, projection, authority, grant)
    record = _retire(fixture, probe=probe, now_ms=pending.retention_expires_at_ms + 3)

    (active,) = installed["active_runs"]
    assert record.active["sealed_blob_b64"] == _b64(active[1])
    assert record.active["index"] == {"run_hash": run_hash, "updated_at_ms": active[2]}
    for item in record.chains:
        (row,) = [row for row in installed["control_chains"] if row[0] == item["index"]["chain"]]
        assert _component_bytes(item) == row[5]
        assert item["index"] == {
            "chain": row[0], "run_hash": row[1], "operation": row[2], "next_sequence": row[3],
            "generation": row[4], "updated_at_ms": row[6],
        }
    assert record.pending == ()
    assert dict(record.local_observations) == {"reservation": "absent", "terminal": "absent"}
    assert runtime.load_retired_claim(run_id, authenticate_components=True) == record
    # Grants nothing: no runtime authority, no Store change, no reservation, no reinstall, no target traffic.
    assert runtime.load_active_run_controls() == ()
    assert all(_rows_for(runtime.path, table, run_hash) == [] for table in ("active_runs", "control_chains", "pending_calls"))
    assert store_files() == compacted
    assert store.probe_run_reservation(run_id) is RunReservationProbe.ABSENT
    with pytest.raises(RunnerStoreError, match="execution grant has expired"):
        store.reserve_run(grant, retention_expires_at_ms=pending.retention_expires_at_ms + 4)
    staged = _stage_claim(runtime, signer, identity, timestamp_ms=pending.retention_expires_at_ms + 5)
    with pytest.raises(RunnerRuntimeConflict, match="runtime active run was retired"):
        runtime.commit_call(
            staged.call_id, next_nonce_b64=_b64(b"F" * 32), now_ms=pending.retention_expires_at_ms + 5,
            installed_chains=tuple((op, run_id, _b64(op[-1].encode() * 32), 1, 0) for op in _RUN_OPERATIONS),
            active_run=ActiveRunInstall(
                run_id=run_id, approval_projection=projection, grant=grant, gate=dict(_STOPPED_GATE),
                claim_response_digest="c" * 64, gate_response_digest="d" * 64,
                claimed_at_ms=pending.retention_expires_at_ms + 5,
                gate_received_at_ms=pending.retention_expires_at_ms + 5,
            ),
        )
    assert runtime.load_active_run_controls() == ()
    assert len(target.calls) == target_requests
