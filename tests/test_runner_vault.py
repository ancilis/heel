from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from heel.runner.store import RunnerStore, UnsupportedSecureStorageError
from heel.runner.vault import (
    EphemeralVault,
    KeychainVault,
    SecretServiceVault,
    SecretTooLargeError,
    VaultUnavailable,
)


class ScriptedCommand:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((tuple(argv), kwargs))
        return self.results.pop(0)


def completed(code=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)


def test_store_is_descriptor_anchored_owner_only_and_never_persists_secrets(tmp_path):
    root = tmp_path / "heel-home"
    store = RunnerStore(root)
    record = store.add_credential(
        label="CI bearer",
        auth_profile="bearer",
        handle_id="a" * 32,
        secret=b"sk-local-must-never-be-written",
    )

    assert record == {
        "label": "ci-bearer",
        "credential_handle_id": "a" * 32,
        "auth_profile": "bearer",
    }
    assert store.list_credentials() == [record]
    assert (root.stat().st_mode & 0o777) == 0o700
    assert ((root / "runner").stat().st_mode & 0o777) == 0o700
    metadata = root / "runner" / "credentials.json"
    assert (metadata.stat().st_mode & 0o777) == 0o600
    raw = metadata.read_bytes()
    assert b"sk-local-must-never-be-written" not in raw
    assert all("secret" not in key.lower() for key in json.loads(raw)[0])


def test_store_persists_minimized_inventory_but_never_raw_openapi(tmp_path):
    store = RunnerStore(tmp_path / "heel-home")
    routes = [{
        "method": "GET",
        "route_template": "/items/{item_id}",
        "operation_id": "getitem",
        "placeholders": ["item_id"],
    }]
    raw_marker = "OPENAPI-RAW-MARKER-MUST-NOT-BE-STORED"
    store.replace_routes(routes, source_digest="b" * 64)

    assert store.list_routes() == routes
    assert raw_marker not in "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "heel-home" / "runner").iterdir()
        if path.is_file()
    )

    with pytest.raises(ValueError, match="placeholder"):
        store.replace_routes([{
            "method": "GET",
            "route_template": "/items/{item_id}",
            "operation_id": "getitem",
            "placeholders": [],
        }], source_digest="c" * 64)


def test_store_rejects_symlink_and_nonregular_metadata_targets(tmp_path):
    root = tmp_path / "heel-home"
    store = RunnerStore(root)
    assert store.list_credentials() == []
    runner = root / "runner"
    outside = tmp_path / "outside"
    outside.write_text("[]", encoding="utf-8")
    (runner / "credentials.json").symlink_to(outside)
    with pytest.raises(OSError):
        store.list_credentials()
    (runner / "credentials.json").unlink()
    os.mkfifo(runner / "credentials.json")
    with pytest.raises(OSError):
        store.list_credentials()


def test_ephemeral_env_is_one_shot_and_fd_is_inherited_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("HEEL_CANARY_SECRET", "ephemeral-value")
    env = EphemeralVault(env_name="HEEL_CANARY_SECRET")
    assert env.load("a" * 32) == b"ephemeral-value"
    assert "HEEL_CANARY_SECRET" not in os.environ

    descriptor = os.open(tmp_path / "secret", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"fd-value")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.set_inheritable(descriptor, True)
        assert EphemeralVault(fd=descriptor, timeout_seconds=0.2).load("b" * 32) == b"fd-value"
    finally:
        os.close(descriptor)

    with pytest.raises(ValueError, match="exactly one"):
        EphemeralVault(env_name="A", fd=3)
    with pytest.raises(ValueError, match="inherited"):
        EphemeralVault(fd=2)


def test_ephemeral_secret_is_bounded_and_never_persisted(monkeypatch):
    monkeypatch.setenv("HEEL_CANARY_SECRET", "x" * (16 * 1024 + 1))
    with pytest.raises(SecretTooLargeError):
        EphemeralVault(env_name="HEEL_CANARY_SECRET").load("a" * 32)
    assert "HEEL_CANARY_SECRET" not in os.environ
    with pytest.raises(VaultUnavailable):
        EphemeralVault(env_name="MISSING").store("a" * 32, b"value")


def test_keychain_is_create_only_fixed_argv_stdin_only_and_timed():
    command = ScriptedCommand([completed(44), completed(0)])
    vault = KeychainVault(command=command, timeout_seconds=2)
    vault.store("a" * 32, b"keychain-secret")

    lookup, create = command.calls
    assert lookup[0] == (
        "security", "find-generic-password", "-s", "heel.runner.canary.v1",
        "-a", "a" * 32,
    )
    assert create[0] == (
        "security", "add-generic-password", "-s", "heel.runner.canary.v1",
        "-a", "a" * 32, "-w",
    )
    assert "-U" not in create[0]
    assert b"keychain-secret" not in " ".join(create[0]).encode()
    assert create[1] == {
        "input": b"keychain-secret", "capture_output": True, "check": False,
        "shell": False, "timeout": 2,
    }


def test_os_vaults_refuse_overwrite_and_bound_command_output():
    for vault_class, exists_code in ((KeychainVault, 0), (SecretServiceVault, 0)):
        command = ScriptedCommand([completed(exists_code, stdout=b"already-there")])
        with pytest.raises(VaultUnavailable, match="already exists"):
            vault_class(command=command).store("a" * 32, b"new-value")
        assert len(command.calls) == 1

    command = ScriptedCommand([completed(1, stderr=b"x" * 4097)])
    with pytest.raises(VaultUnavailable, match="bounded"):
        SecretServiceVault(command=command).store("a" * 32, b"value")


def test_secret_service_uses_closed_attributes_and_secret_stdin():
    command = ScriptedCommand([completed(1), completed(0)])
    vault = SecretServiceVault(command=command, timeout_seconds=1)
    vault.store("f" * 32, b"secret-service-value")

    lookup, create = command.calls
    assert lookup[0] == ("secret-tool", "lookup", "heel", "canary", "handle", "f" * 32)
    assert create[0] == (
        "secret-tool", "store", "--label=Heel canary credential",
        "heel", "canary", "handle", "f" * 32,
    )
    assert create[1]["input"] == b"secret-service-value"
    assert create[1]["shell"] is False


def test_live_gate_fails_without_vault_while_static_state_remains_available(tmp_path):
    store = RunnerStore(tmp_path / "home")
    store.replace_routes([], source_digest="0" * 64)
    assert store.list_routes() == []
    with pytest.raises(UnsupportedSecureStorageError):
        store.require_live_vault(None)
