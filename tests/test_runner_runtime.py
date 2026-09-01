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
        assert check.execute("SELECT schema_version FROM metadata").fetchone()[0] == "heel.runner-runtime-state.v3"
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
