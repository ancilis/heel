from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from heel.crypto import ed25519_key_id
from heel.runner.catalog import CATALOG_IDS
from heel.runner.compiler import CanaryCompiler
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.openapi_routes import RouteInventory
from heel.runner.store import RunnerContext, RunnerStore, UnsupportedSecureStorageError
from heel.runner.vault import (
    MAX_COMMAND_OUTPUT_BYTES,
    EphemeralVault,
    KeychainVault,
    SecretServiceVault,
    VaultUnavailable,
    _run_bounded_process,
    ephemeral_environment_name,
    validate_credential_secret,
)


class Signer(SecureSigner):
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload):
        return self._key.sign(payload)


def store_and_identity(tmp_path):
    signer = Signer()
    identity = RunnerIdentity(
        runner_id="runner_123456789", workspace_id="ws_123456789", runner_version="1",
        adapter_versions={scenario: "1" for scenario in CATALOG_IDS},
        public_key_b64=base64.b64encode(signer.public_key).decode(),
        fingerprint=__import__("hashlib").sha256(signer.public_key).hexdigest(),
        key_id=signer.key_id, pairing_phrase=runner_phrase_words()[:6],
    )
    store = RunnerStore(tmp_path / "home")
    store.bind_context(RunnerContext(
        workspace_id="ws_123456789", project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    ), identity=identity, signer=signer, signer_label="test-signer")
    return store, identity, signer


def test_bounded_process_drains_eight_megabytes_without_retaining_it():
    result = _run_bounded_process(
        (sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*(8*1024*1024))"),
        payload=None,
        timeout_seconds=5,
    )
    assert result.returncode == 0
    assert len(result.stdout) == MAX_COMMAND_OUTPUT_BYTES + 1


def test_bounded_process_uses_minimal_environment_devnull_and_no_shell():
    observed = {}

    class Input:
        def write(self, value): observed["payload"] = bytes(value)
        def flush(self): pass
        def close(self): pass

    class Process:
        stdin = Input()
        stdout = io.BytesIO(b"ok")
        def wait(self, timeout=None): observed["timeout"] = timeout; return 0
        def kill(self): pass

    def popen(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return Process()

    result = _run_bounded_process(
        ("/usr/bin/example", "fixed"), payload=b"opaque", timeout_seconds=2,
        popen=popen,
    )
    assert result.stdout == b"ok"
    assert observed["payload"] == b"opaque"
    assert observed["kwargs"] == {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "bufsize": 0,
        "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    }


class ScriptedRunner:
    def __init__(self, returncodes):
        self.returncodes = list(returncodes)
        self.calls = []

    def __call__(self, command, *, payload, timeout_seconds):
        self.calls.append((tuple(command), payload, timeout_seconds))
        code, output = self.returncodes.pop(0)
        return type("Result", (), {"returncode": code, "stdout": output})()


def verified(path: str, *, allowed_paths, platform_name):
    assert os.path.isabs(path)
    assert path in allowed_paths
    return path


def test_os_vaults_use_verified_absolute_paths_fixed_argv_and_create_only(monkeypatch):
    monkeypatch.setenv("PATH", "/tmp/attacker-controlled")
    keychain_runner = ScriptedRunner([(44, b""), (0, b"")])
    keychain = KeychainVault(
        runner=keychain_runner, verifier=verified, platform_name="Darwin",
    )
    keychain.store("a" * 32, b"keychain-value")
    assert keychain_runner.calls[0][0][0] == "/usr/bin/security"
    assert keychain_runner.calls[1][0] == (
        "/usr/bin/security", "add-generic-password", "-s", "heel.runner.canary.v1",
        "-a", "a" * 32, "-w",
    )
    assert "-U" not in keychain_runner.calls[1][0]
    assert keychain_runner.calls[1][1] == b"keychain-value"
    assert b"keychain-value" not in " ".join(keychain_runner.calls[1][0]).encode()

    secret_runner = ScriptedRunner([(1, b""), (0, b"")])
    secret_service = SecretServiceVault(
        runner=secret_runner, verifier=verified, platform_name="Linux",
        executable_path="/usr/bin/secret-tool",
    )
    secret_service.store("b" * 32, b"secret-service-value")
    assert secret_runner.calls[1][0] == (
        "/usr/bin/secret-tool", "store", "--label=Heel canary credential",
        "heel", "canary", "handle", "b" * 32,
    )
    assert secret_runner.calls[1][1] == b"secret-service-value"


def test_linux_secret_tool_path_is_allowlisted_and_path_hijack_never_used():
    with pytest.raises(VaultUnavailable, match="allowlisted"):
        SecretServiceVault(
            runner=ScriptedRunner([]), verifier=verified, platform_name="Linux",
            executable_path="/tmp/secret-tool",
        )


def test_command_vault_rejects_the_output_limit_sentinel_and_missing_fd_source():
    oversized = KeychainVault(
        runner=ScriptedRunner([(0, b"x" * (MAX_COMMAND_OUTPUT_BYTES + 1))]),
        verifier=verified,
        platform_name="Darwin",
    )
    with pytest.raises(VaultUnavailable):
        oversized.load("c" * 32)

    with pytest.raises(VaultUnavailable, match="unavailable"):
        EphemeralVault("d" * 32, source_kind="inherited_fd").load()


def test_pending_create_activate_rolls_back_and_recovers_orphans(tmp_path):
    store, _, _ = store_and_identity(tmp_path)

    class FakeVault:
        backend_id = "macos_keychain"
        supported = True
        def __init__(self): self.values = {}
        def store(self, handle, secret): self.values[handle] = bytes(secret)
        def load(self, handle):
            if handle not in self.values: raise VaultUnavailable("missing")
            return self.values[handle]
        def exists(self, handle): return handle in self.values
        def delete(self, handle): self.values.pop(handle, None)

    vault = FakeVault()
    record = store.create_os_credential(
        semantic_role="authenticated", auth_profile="bearer", label="local bearer",
        vault=vault, secret=b"opaque-bearer-token",
    )
    assert record["state"] == "active"
    assert vault.exists(record["credential_handle_id"])

    failing = FakeVault()
    def fail_store(handle, secret):
        raise VaultUnavailable("create failed")
    failing.store = fail_store
    with pytest.raises(VaultUnavailable):
        store.create_os_credential(
            semantic_role="object_owner", auth_profile="bearer", label="owner",
            vault=failing, secret=b"owner-token",
        )
    assert "object_owner" not in {item["semantic_role"] for item in store.list_credentials()}

    pending = store.reserve_os_credential(
        semantic_role="object_owner", auth_profile="bearer", label="owner",
        backend="macos_keychain",
    )
    vault.values[pending["credential_handle_id"]] = b"recovered-token"
    store.recover_credentials({"macos_keychain": vault})
    recovered = {item["semantic_role"]: item for item in store.list_credentials()}
    assert recovered["object_owner"]["state"] == "active"


def test_flock_prevents_lost_update_and_files_are_owner_only_single_link(tmp_path):
    store, _, _ = store_and_identity(tmp_path)
    barrier = threading.Barrier(3)
    errors = []

    def add(role):
        try:
            barrier.wait()
            store.register_ephemeral_credential(
                semantic_role=role, auth_profile="bearer",
                source_kind="environment", label=role,
            )
        except BaseException as error:
            errors.append(error)

    threads = [
        threading.Thread(target=add, args=("authenticated",)),
        threading.Thread(target=add, args=("object_owner",)),
    ]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads: thread.join()
    assert errors == []
    assert {item["semantic_role"] for item in store.list_credentials()} == {
        "authenticated", "object_owner",
    }

    inventory = RouteInventory(json.loads(
        (Path(__file__).parent / "fixtures/canary/staging-openapi.json").read_text()
    ))
    store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
    barrier = threading.Barrier(3)
    errors.clear()

    def map_scenario(scenario, route, fixtures):
        try:
            barrier.wait()
            store.save_mapping(
                scenario, method="GET", route_template=route, fixture_bindings=fixtures,
            )
        except BaseException as error:
            errors.append(error)

    threads = [
        threading.Thread(
            target=map_scenario,
            args=("anonymous_authenticated_read", "/health", {}),
        ),
        threading.Thread(
            target=map_scenario,
            args=("object_ownership_read", "/items/{item_id}", {"item_id": "local-item"}),
        ),
    ]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads: thread.join()
    assert errors == []
    assert {item["scenario_id"] for item in store.list_mappings()} == {
        "anonymous_authenticated_read", "object_ownership_read",
    }

    context_dir = tmp_path / "home" / "runner" / "contexts" / store.namespace
    for name in (".metadata.lock", "credentials.json", "routes.json", "mappings.json"):
        status = (context_dir / name).stat()
        assert status.st_mode & 0o777 == 0o600
        assert status.st_nlink == 1


def test_ephemeral_sources_are_per_handle_xor_one_shot_and_registration_does_not_consume(tmp_path, monkeypatch):
    store, _, _ = store_and_identity(tmp_path)
    record = store.register_ephemeral_credential(
        semantic_role="authenticated", auth_profile="bearer",
        source_kind="environment", label="ephemeral bearer",
    )
    name = ephemeral_environment_name(record["credential_handle_id"], source_kind="environment")
    monkeypatch.setenv(name, "ephemeral-token")
    assert os.environ[name] == "ephemeral-token"  # registration did not consume it
    assert EphemeralVault(record["credential_handle_id"], source_kind="environment").load() == b"ephemeral-token"
    assert name not in os.environ

    fd_file = tmp_path / "fd-secret"
    fd_file.write_bytes(b"fd-token")
    descriptor = os.open(fd_file, os.O_RDONLY)
    os.set_inheritable(descriptor, True)
    fd_name = ephemeral_environment_name(record["credential_handle_id"], source_kind="inherited_fd")
    monkeypatch.setenv(fd_name, str(descriptor))
    try:
        assert EphemeralVault(record["credential_handle_id"], source_kind="inherited_fd").load() == b"fd-token"
    finally:
        os.close(descriptor)
    assert fd_name not in os.environ

    env_name = ephemeral_environment_name(record["credential_handle_id"], source_kind="environment")
    fd_name = ephemeral_environment_name(record["credential_handle_id"], source_kind="inherited_fd")
    monkeypatch.setenv(env_name, "must-not-win")
    monkeypatch.setenv(fd_name, "7")
    with pytest.raises(VaultUnavailable, match="exclusive"):
        EphemeralVault(record["credential_handle_id"], source_kind="environment").load()
    assert env_name not in os.environ and fd_name not in os.environ


def test_live_prepare_resolves_every_nonanonymous_role_and_fails_when_supported_vault_is_absent(tmp_path):
    store, runner_identity, signer = store_and_identity(tmp_path)
    inventory = RouteInventory(json.loads(
        (Path(__file__).parent / "fixtures/canary/staging-openapi.json").read_text()
    ))
    store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
    store.save_mapping("anonymous_authenticated_read", method="GET", route_template="/health")
    record = store.reserve_os_credential(
        semantic_role="authenticated", auth_profile="bearer", label="bearer",
        backend="macos_keychain",
    )
    store.activate_credential(record["credential_handle_id"])

    class Absent:
        backend_id = "macos_keychain"
        supported = True
        def load(self, handle): raise VaultUnavailable("absent")

    compiler = CanaryCompiler(store=store, identity=runner_identity, signer=signer, now_ms=7)
    with pytest.raises(UnsupportedSecureStorageError):
        compiler.prepare_live(["anonymous_authenticated_read"], vaults={"macos_keychain": Absent()})


def test_live_prepare_consumes_each_exact_ephemeral_source_and_requires_reinjection(
    tmp_path, monkeypatch,
):
    store, runner_identity, signer = store_and_identity(tmp_path)
    inventory = RouteInventory(json.loads(
        (Path(__file__).parent / "fixtures/canary/staging-openapi.json").read_text()
    ))
    store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
    store.save_mapping("anonymous_authenticated_read", method="GET", route_template="/health")
    store.save_mapping(
        "object_ownership_read", method="GET", route_template="/items/{item_id}",
        fixture_bindings={"item_id": "local-item"},
    )
    names = []
    for role in ("authenticated", "object_owner", "non_owner"):
        record = store.register_ephemeral_credential(
            semantic_role=role, auth_profile="bearer",
            source_kind="environment", label=role,
        )
        name = ephemeral_environment_name(
            record["credential_handle_id"], source_kind="environment",
        )
        names.append(name)
        monkeypatch.setenv(name, f"opaque-{role}")

    compiler = CanaryCompiler(store=store, identity=runner_identity, signer=signer, now_ms=7)
    assert compiler.prepare_live([
        "anonymous_authenticated_read", "object_ownership_read",
    ]) == {"credential_count": 3}
    assert all(name not in os.environ for name in names)
    with pytest.raises(UnsupportedSecureStorageError):
        compiler.prepare_live([
            "anonymous_authenticated_read", "object_ownership_read",
        ])


def test_bearer_api_key_and_cookie_jar_validation_are_closed():
    assert validate_credential_secret("bearer", b"opaque-token", "https://staging.acme.dev") == b"opaque-token"
    assert validate_credential_secret("x_api_key", b"api-key", "https://staging.acme.dev") == b"api-key"
    cookie = canonical = json.dumps({
        "schema_version": "heel.cookie-jar.v1",
        "cookies": [{
            "name": "session", "value": "opaque", "path": "/",
            "secure": True, "http_only": True, "same_site": "strict",
        }],
    }, sort_keys=True, separators=(",", ":")).encode()
    assert validate_credential_secret("cookie_jar", cookie, "https://staging.acme.dev") == canonical
    for invalid in (
        b"raw-cookie=not-a-jar",
        cookie.replace(b'"secure":true', b'"secure":false'),
        cookie[:-1] + b',"domain":"evil.example"}',
    ):
        with pytest.raises(ValueError, match="cookie"):
            validate_credential_secret("cookie_jar", invalid, "https://staging.acme.dev")
