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
        # v1 -> v2 -> v3 -> v4 (T2b2R1 recovery records) in one transaction; sealed rows are untouched.
        assert check.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v4"
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
    # Rebuild the exact v3 layout this file had before the T2b2R1 migration existed.
    with sqlite3.connect(path) as conn:
        before = {table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                  for table in ("control_chains", "pending_calls", "terminal_disclosures", "active_runs")}
        metadata = conn.execute("SELECT * FROM metadata").fetchone()
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
        assert conn.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v4"
        after = {table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                 for table in ("control_chains", "pending_calls", "terminal_disclosures", "active_runs")}
        assert after == before
        migrated_metadata = conn.execute("SELECT * FROM metadata").fetchone()
        assert migrated_metadata[2:] == metadata[2:] and migrated_metadata[1] == "heel.runner-runtime-state.v4"
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
