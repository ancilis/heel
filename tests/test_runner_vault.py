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

import heel.runner.store as runner_store_module
from heel.crypto import SigningAuthority, ed25519_key_id
from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.runner.catalog import CATALOG_IDS
from heel.runner.compiler import CanaryCompiler
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.openapi_routes import RouteInventory
from heel.runner.store import (
    RunnerContext, RunnerContextRolloverEvidence, RunnerStore, RunnerStoreError,
    UnsupportedSecureStorageError,
)
from heel.runner.vault import (
    MAX_COMMAND_OUTPUT_BYTES,
    MAX_SECRET_BYTES,
    EphemeralVault,
    KeychainVault,
    SecretServiceVault,
    SecretTooLargeError,
    VaultUnavailable,
    _run_bounded_process,
    ephemeral_environment_name,
    validate_credential_secret,
)
from tests.test_runner_stop import compiled_pair, signed_grant


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


def _cloud_context_artifact(
    identity, authority, context, *, binding_id, verification_record_digest, issued_at_ms, expires_at_ms,
):
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": binding_id,
        "workspace_id": identity.workspace_id, "project_id": context.project_id,
        "environment": {
            "environment_id": context.environment_id, "origin": context.origin,
            "environment_class": context.environment_class,
            "verification_record_digest": verification_record_digest,
        },
        "runner_binding": {
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        },
        "authorization": {"user_id": "owner", "role": "owner"},
        "issued_at_ms": issued_at_ms, "expires_at_ms": expires_at_ms,
    }
    return {
        **unsigned, "binding_digest": canonical_digest(unsigned),
        **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
    }


def _install_cloud_authority(root, identity, signer, *, binding_marker: str, authority=None):
    """Create one complete selected Cloud tuple for Cloud-mode hostile tests."""
    store = RunnerStore(root)
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    )
    authority = authority or SigningAuthority.generate()
    artifact = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + binding_marker * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    return store, context, authority, artifact


def test_cloud_context_sidecar_requires_domain_signature_and_is_immutable(tmp_path):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "a" * 32, "workspace_id": identity.workspace_id,
        "project_id": "prj_123456789", "environment": {"environment_id": "env_123456789", "origin": "https://staging.acme.dev", "environment_class": "staging", "verification_record_digest": "0" * 64},
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {**unsigned, "binding_digest": canonical_digest(unsigned)}
    artifact.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)))
    assert store.install_cloud_context_binding(artifact, identity=identity, signer=signer, signer_label="test-signer", trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1) == store.load_context()
    assert store.load_cloud_context_binding()["binding_id"] == artifact["binding_id"]
    assert store.verify_cloud_context_binding(identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1)["binding_id"] == artifact["binding_id"]
    renewal_unsigned = {
        **unsigned, "binding_id": "rcb_" + "b" * 32,
            "issued_at_ms": 2, "expires_at_ms": 60_002,
    }
    renewal = {**renewal_unsigned, "binding_digest": canonical_digest(renewal_unsigned)}
    renewal.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(renewal_unsigned)))
    with pytest.raises(RunnerStoreError, match="cannot be replaced"):
        store.install_cloud_context_binding(renewal, identity=identity, signer=signer, signer_label="test-signer", trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2)
    renewal_evidence = RunnerContextRolloverEvidence(
        artifact["binding_id"], artifact["binding_digest"], renewal["binding_id"],
        renewal["binding_digest"], 60_001,
    )
    assert store.install_cloud_context_binding(renewal, identity=identity, signer=signer, signer_label="test-signer", trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_001, rollover_evidence=renewal_evidence) == store.load_context()
    assert store.verify_cloud_context_binding(identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_001)["binding_id"] == renewal["binding_id"]
    with pytest.raises(RunnerStoreError, match="invalid cloud context"):
        store.verify_cloud_context_binding(identity=identity, trusted_cloud_keys={"other": authority.public_key}, now_ms=1)
    artifact["binding_id"] = "rcb_" + "b" * 32
    with pytest.raises(ValueError):
        store.install_cloud_context_binding(artifact, identity=identity, signer=signer, signer_label="test-signer", trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1)
    with store._transaction(exclusive=True) as context_fd:
        runner_store_module._write_json(context_fd, "cloud-context-provenance.json", {
            "schema_version": "heel.cloud-context-provenance.v1",
            "binding_id": "rcb_" + "b" * 32,
            "binding_digest": "f" * 64,
        })
    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        store.verify_cloud_context_binding(
            identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )


def test_cloud_authority_commit_prevents_static_downgrade_after_sidecars_are_deleted(tmp_path):
    """A selected Cloud context remains Cloud even if mutable sidecars disappear."""
    _bound, identity, signer = store_and_identity(tmp_path)
    store = RunnerStore(tmp_path / "cloud-home")
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    )
    authority = SigningAuthority.generate()
    artifact = _cloud_context_artifact(
        identity, authority, context,
        binding_id="rcb_" + "d" * 32,
        verification_record_digest="0" * 64,
        issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    assert store.load_binding()["schema_version"] == "heel.bound-runner-context.v2"
    with store._transaction(exclusive=True) as context_fd:
        os.unlink("cloud-context-binding.json", dir_fd=context_fd)
        os.unlink("cloud-context-provenance.json", dir_fd=context_fd)
        os.fsync(context_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(tmp_path / "cloud-home")


@pytest.mark.parametrize(
    "removed",
    (
        "cloud-context-binding.json", "cloud-context-provenance.json", "authority-commit",
        "active-context.json", "all-cloud-authority-files",
    ),
)
def test_cloud_authority_tuple_component_loss_fails_closed(tmp_path, removed):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    root = tmp_path / "cloud-home"
    store = RunnerStore(root)
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    )
    authority = SigningAuthority.generate()
    artifact = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "e" * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    commit_filename = store._cloud_authority_commit_filename(
        store.load_binding()["authority_commit_digest"],
    )
    if removed == "active-context.json":
        with store._open_runner(create=False) as runner_fd:
            assert runner_fd is not None
            os.unlink("active-context.json", dir_fd=runner_fd)
            os.fsync(runner_fd)
    else:
        with store._transaction(exclusive=True) as context_fd:
            filenames = (
                ("cloud-context-binding.json", "cloud-context-provenance.json", commit_filename)
                if removed == "all-cloud-authority-files"
                else (commit_filename if removed == "authority-commit" else removed,)
            )
            for filename in filenames:
                os.unlink(filename, dir_fd=context_fd)
            os.fsync(context_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(root)


def test_cloud_authority_rejects_restored_v1_binding_and_selector(tmp_path):
    """Cloud mode is irrevocable even if both mutable current files are rolled back."""
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    root = tmp_path / "cloud-home"
    store = RunnerStore(root)
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    )
    authority = SigningAuthority.generate()
    artifact = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "f" * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    cloud_binding = store.load_binding()
    legacy_binding = {
        key: cloud_binding[key]
        for key in ("schema_version", "namespace", "context", "identity", "signer_label")
    }
    legacy_binding["schema_version"] = "heel.bound-runner-context.v1"
    with store._transaction(exclusive=True) as context_fd:
        runner_store_module._write_json(context_fd, "binding.json", legacy_binding)
        os.fsync(context_fd)
    with store._open_runner(create=False) as runner_fd:
        assert runner_fd is not None
        runner_store_module._write_json(runner_fd, "active-context.json", {
            "schema_version": "heel.active-runner-context.v1",
            "namespace": context.namespace,
        })
        os.fsync(runner_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(root)


@pytest.mark.parametrize("tamper", ("signature", "binding_digest", "context"))
def test_cloud_authority_commit_tampering_fails_closed(tmp_path, tamper):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    root = tmp_path / "cloud-home"
    store, _context, _authority, _artifact = _install_cloud_authority(
        root, identity, signer, binding_marker="a",
    )
    filename = store._cloud_authority_commit_filename(
        store.load_binding()["authority_commit_digest"],
    )
    with store._transaction(exclusive=True) as context_fd:
        commit = runner_store_module._read_json(context_fd, filename, None)
        assert isinstance(commit, dict)
        if tamper == "signature":
            commit["signature_b64"] = base64.b64encode(b"\\x00" * 64).decode("ascii")
        elif tamper == "binding_digest":
            commit["binding_digest"] = "f" * 64
        else:
            commit["context"] = {
                **commit["context"], "origin": "https://other.invalid",
            }
        runner_store_module._write_json(context_fd, filename, commit)
        os.fsync(context_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(root)


def test_cloud_authority_rejects_cross_paired_commit_record(tmp_path):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    authority = SigningAuthority.generate()
    left, _context, _authority, _artifact = _install_cloud_authority(
        tmp_path / "left", identity, signer, binding_marker="a", authority=authority,
    )
    right, _context, _authority, _artifact = _install_cloud_authority(
        tmp_path / "right", identity, signer, binding_marker="b", authority=authority,
    )
    left_filename = left._cloud_authority_commit_filename(
        left.load_binding()["authority_commit_digest"],
    )
    right_filename = right._cloud_authority_commit_filename(
        right.load_binding()["authority_commit_digest"],
    )
    with right._transaction(exclusive=False) as context_fd:
        cross_paired = runner_store_module._read_json(context_fd, right_filename, None)
    with left._transaction(exclusive=True) as context_fd:
        runner_store_module._write_json(context_fd, left_filename, cross_paired)
        os.fsync(context_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(tmp_path / "left")


def test_cloud_authority_rejects_old_v2_selector_without_rollover_journal(tmp_path):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    root = tmp_path / "cloud-home"
    store, context, authority, old = _install_cloud_authority(
        root, identity, signer, binding_marker="a",
    )
    with store._open_runner(create=False) as runner_fd:
        assert runner_fd is not None
        old_selector = runner_store_module._read_json(runner_fd, "active-context.json", None)
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "b" * 32,
        verification_record_digest="0" * 64, issued_at_ms=60_002, expires_at_ms=120_003,
    )
    store.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=RunnerContextRolloverEvidence(
            old["binding_id"], old["binding_digest"], new["binding_id"],
            new["binding_digest"], 60_002,
        ),
    )
    with store._open_runner(create=False) as runner_fd:
        assert runner_fd is not None
        runner_store_module._write_json(runner_fd, "active-context.json", old_selector)
        os.fsync(runner_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        RunnerStore(root)


def test_cloud_renewal_recovers_forward_from_signed_v2_rollover_selector_prefix(tmp_path, monkeypatch):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    root = tmp_path / "cloud-home"
    store = RunnerStore(root)
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    )
    authority = SigningAuthority.generate()
    old = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "1" * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "2" * 32,
        verification_record_digest="0" * 64, issued_at_ms=60_002, expires_at_ms=120_003,
    )
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    original_write = runner_store_module._write_json

    def fail_new_selector(directory_fd, filename, value):
        if filename == "active-context.json":
            raise OSError("injected v2 selector failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_new_selector)
    with pytest.raises(OSError, match="v2 selector"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=RunnerContextRolloverEvidence(
                old["binding_id"], old["binding_digest"], new["binding_id"], new["binding_digest"], 60_002,
            ),
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)

    restarted = RunnerStore.for_runtime(root, identity=identity, signer=signer)
    assert restarted.finish_pending_context_rollover(
        identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
    )["binding_id"] == new["binding_id"]
    assert restarted.load_cloud_context_binding()["binding_id"] == new["binding_id"]


def test_expired_cloud_context_rolls_forward_only_with_closed_rollover_evidence(tmp_path):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    old_unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "1" * 32,
        "workspace_id": identity.workspace_id, "project_id": "prj_123456789",
        "environment": {"environment_id": "env_123456789", "origin": "https://staging.acme.dev", "environment_class": "staging", "verification_record_digest": "0" * 64},
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    old = {**old_unsigned, "binding_digest": canonical_digest(old_unsigned)}
    old.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(old_unsigned)))
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    new_unsigned = {
        **old_unsigned, "binding_id": "rcb_" + "2" * 32,
        "environment": {**old_unsigned["environment"], "verification_record_digest": "1" * 64},
        "issued_at_ms": 60_002, "expires_at_ms": 120_003,
    }
    new = {**new_unsigned, "binding_digest": canonical_digest(new_unsigned)}
    new.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(new_unsigned)))
    evidence = RunnerContextRolloverEvidence(
        old_binding_id=old["binding_id"], old_binding_digest=old["binding_digest"],
        new_binding_id=new["binding_id"], new_binding_digest=new["binding_digest"],
        observed_server_time_ms=60_002,
    )

    assert store.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=evidence,
    ).verification_record_digest == "1" * 64
    assert store.load_context().verification_record_digest == "1" * 64
    assert store.verify_cloud_context_binding(
        identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
    )["binding_id"] == new["binding_id"]


def test_proof_generation_rollover_rejects_current_old_authority_and_preserves_it(tmp_path):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()
    old = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "d" * 32,
        verification_record_digest=context.verification_record_digest,
        issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "e" * 32,
        verification_record_digest="e" * 64, issued_at_ms=2, expires_at_ms=120_002,
    )
    evidence = RunnerContextRolloverEvidence(
        old["binding_id"], old["binding_digest"], new["binding_id"],
        new["binding_digest"], 2,
    )

    with pytest.raises(RunnerStoreError, match="cannot be replaced"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2,
            rollover_evidence=evidence,
        )

    assert store.load_context().verification_record_digest == old["environment"]["verification_record_digest"]
    assert store.load_cloud_context_binding()["binding_digest"] == old["binding_digest"]


def test_constructed_private_receipt_cannot_authorize_current_cloud_rollover(tmp_path):
    """Only a client-registered list/claim receipt may replace current authority."""
    import heel.runner.control_client as control_client_module

    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()
    old = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "c" * 32,
        verification_record_digest=context.verification_record_digest,
        issued_at_ms=1, expires_at_ms=60_001,
    )
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "b" * 32,
        verification_record_digest="b" * 64, issued_at_ms=2, expires_at_ms=120_002,
    )
    forged = control_client_module._RunnerContextRolloverReceipt(
        control_client_module._ROLLOVER_RECEIPT_CONSTRUCTOR,
        client_instance=object(),
        evidence={
            "old_binding_id": old["binding_id"],
            "old_binding_digest": old["binding_digest"],
            "new_binding_id": new["binding_id"],
            "new_binding_digest": new["binding_digest"],
            "observed_server_time_ms": 2,
            "list_request_digest": "forged",
            "claim_request_digest": "forged",
            "list_generation": 0,
            "claim_generation": 0,
        },
    )
    forged._bind_store(store)

    with pytest.raises(RunnerStoreError, match="rollover receipt"):
        store._install_cloud_context_binding_from_control(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2,
            rollover_receipt=forged,
        )

    assert store.load_context().verification_record_digest == old["environment"]["verification_record_digest"]
    assert store.load_cloud_context_binding()["binding_digest"] == old["binding_digest"]


def test_first_cloud_install_journal_blocks_static_adoption_and_exact_retry_recovers(tmp_path, monkeypatch):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    store = RunnerStore(tmp_path / "fresh")
    authority = SigningAuthority.generate()
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789", environment_id="env_123456789",
        origin="https://staging.acme.dev", verification_record_digest="0" * 64,
        environment_class="staging",
    )
    artifact = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "f" * 32,
        verification_record_digest=context.verification_record_digest, issued_at_ms=1, expires_at_ms=60_001,
    )
    original_write = runner_store_module._write_json

    def fail_sidecar(directory_fd, filename, value):
        if filename == "cloud-context-binding.json":
            raise OSError("injected initial sidecar failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_sidecar)
    with pytest.raises(OSError, match="initial sidecar"):
        store.install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)

    restarted = RunnerStore(tmp_path / "fresh")
    assert not restarted.is_context_bound
    with pytest.raises(RunnerStoreError, match="installation requires recovery"):
        restarted.bind_context(context, identity=identity, signer=signer, signer_label="test-signer")
    rejected = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "e" * 32,
        verification_record_digest="e" * 64, issued_at_ms=2, expires_at_ms=120_002,
    )
    with pytest.raises(RunnerStoreError, match="cannot be installed over an active context"):
        restarted.install_cloud_context_binding(
            rejected, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2,
        )
    assert not restarted.is_context_bound
    assert restarted.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    ) == context
    assert restarted.load_context() == context


def test_first_cloud_install_retries_root_journal_cleanup_after_active_pointer_fault(tmp_path, monkeypatch):
    _bound, identity, signer = store_and_identity(tmp_path / "fixture")
    store = RunnerStore(tmp_path / "fresh")
    authority = SigningAuthority.generate()
    context = RunnerContext(
        workspace_id=identity.workspace_id, project_id="prj_123456789", environment_id="env_123456789",
        origin="https://staging.acme.dev", verification_record_digest="0" * 64,
        environment_class="staging",
    )
    artifact = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "c" * 32,
        verification_record_digest=context.verification_record_digest, issued_at_ms=1, expires_at_ms=60_001,
    )
    original_unlink = runner_store_module.os.unlink

    def fail_root_journal(path, *args, **kwargs):
        if path == "context-install.json":
            raise OSError("injected root journal unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(runner_store_module.os, "unlink", fail_root_journal)
    with pytest.raises(OSError, match="root journal unlink"):
        store.install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )
    monkeypatch.setattr(runner_store_module.os, "unlink", original_unlink)
    restarted = RunnerStore(tmp_path / "fresh")
    assert restarted.is_context_bound
    assert restarted.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    ) == context
    assert not restarted._has_pending_cloud_install()


def test_proof_generation_rollover_refuses_a_nonterminal_reserved_local_run(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()

    def artifact(binding_id, verification_digest, issued_at, expires_at):
        unsigned = {
            "schema_version": "heel.runner-context-binding.v1", "binding_id": binding_id,
            "workspace_id": identity.workspace_id, "project_id": context.project_id,
            "environment": {
                "environment_id": context.environment_id, "origin": context.origin,
                "environment_class": context.environment_class,
                "verification_record_digest": verification_digest,
            },
            "runner_binding": {
                "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
                "public_key_digest": identity.fingerprint,
            },
            "authorization": {"user_id": "owner", "role": "owner"},
            "issued_at_ms": issued_at, "expires_at_ms": expires_at,
        }
        return {
            **unsigned, "binding_digest": canonical_digest(unsigned),
            **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
        }

    old = artifact("rcb_" + "5" * 32, context.verification_record_digest, 1, 60_001)
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    grant = signed_grant(manifest, projection, identity, authority, issued=1_000, expires=10_000)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    new = artifact("rcb_" + "6" * 32, "6" * 64, 60_002, 120_003)
    evidence = RunnerContextRolloverEvidence(
        old["binding_id"], old["binding_digest"], new["binding_id"], new["binding_digest"], 60_002,
    )

    with pytest.raises(RunnerStoreError, match="requires terminal local runs"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=evidence,
        )
    store.transition_run(grant["run_id"], "finalizing", now_ms=2_000)
    with pytest.raises(RunnerStoreError, match="final projections are unavailable"):
        store.transition_run(grant["run_id"], "terminal", now_ms=2_001)


def test_rollover_journal_blocks_normal_load_then_recovers_exact_crash_state(tmp_path, monkeypatch):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    old_unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "3" * 32,
        "workspace_id": identity.workspace_id, "project_id": "prj_123456789",
        "environment": {"environment_id": "env_123456789", "origin": "https://staging.acme.dev", "environment_class": "staging", "verification_record_digest": "0" * 64},
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    old = {**old_unsigned, "binding_digest": canonical_digest(old_unsigned)}
    old.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(old_unsigned)))
    store.install_cloud_context_binding(old, identity=identity, signer=signer, signer_label="test-signer", trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1)
    new_unsigned = {
        **old_unsigned, "binding_id": "rcb_" + "4" * 32,
        "environment": {**old_unsigned["environment"], "verification_record_digest": "4" * 64},
        "issued_at_ms": 60_002, "expires_at_ms": 120_003,
    }
    new = {**new_unsigned, "binding_digest": canonical_digest(new_unsigned)}
    new.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(new_unsigned)))
    evidence = RunnerContextRolloverEvidence(old["binding_id"], old["binding_digest"], new["binding_id"], new["binding_digest"], 60_002)
    original_write = runner_store_module._write_json

    def fail_new_sidecar(directory_fd, filename, value):
        if filename == "cloud-context-binding.json" and value == new:
            raise OSError("injected rollover sidecar failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_new_sidecar)
    with pytest.raises(OSError, match="rollover sidecar"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=evidence,
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)
    restarted = RunnerStore(tmp_path / "home")
    with pytest.raises(RunnerStoreError, match="rollover requires recovery"):
        restarted.load_context()
    assert restarted.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=evidence,
    ).verification_record_digest == "4" * 64
    assert restarted.load_context().verification_record_digest == "4" * 64


@pytest.mark.parametrize("failure", ["unlink", "directory_fsync"])
def test_rollover_new_state_retries_exact_cleanup_after_journal_removal_fault(
    tmp_path, monkeypatch, failure,
):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()
    old = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "9" * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "a" * 32,
        verification_record_digest="a" * 64, issued_at_ms=60_002, expires_at_ms=120_003,
    )
    evidence = RunnerContextRolloverEvidence(
        old["binding_id"], old["binding_digest"], new["binding_id"], new["binding_digest"], 60_002,
    )
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    original_unlink = runner_store_module.os.unlink
    original_fsync = runner_store_module.os.fsync
    journal_removed = [False]

    def unlink_journal(path, *args, **kwargs):
        if path == "context-rollover.json":
            if failure == "unlink":
                raise OSError("injected rollover unlink failure")
            journal_removed[0] = True
        return original_unlink(path, *args, **kwargs)

    def fsync_after_journal_removal(descriptor):
        if failure == "directory_fsync" and journal_removed[0]:
            raise OSError("injected rollover directory fsync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(runner_store_module.os, "unlink", unlink_journal)
    monkeypatch.setattr(runner_store_module.os, "fsync", fsync_after_journal_removal)
    with pytest.raises(OSError, match="injected rollover"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=evidence,
        )
    monkeypatch.setattr(runner_store_module.os, "unlink", original_unlink)
    monkeypatch.setattr(runner_store_module.os, "fsync", original_fsync)

    restarted = RunnerStore(tmp_path / "home")
    if failure == "unlink":
        with pytest.raises(RunnerStoreError, match="rollover requires recovery"):
            restarted.load_context()
    assert restarted.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=evidence,
    ).verification_record_digest == "a" * 64
    # Recovery completion is idempotent after the journal finalizer is durable.
    assert restarted.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=evidence,
    ).verification_record_digest == "a" * 64


@pytest.mark.parametrize("tamper", ["signature", "evidence", "artifact"])
def test_rollover_new_state_rejects_a_tampered_pending_journal(tmp_path, monkeypatch, tamper):
    store, identity, signer = store_and_identity(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()
    old = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "b" * 32,
        verification_record_digest="0" * 64, issued_at_ms=1, expires_at_ms=60_001,
    )
    new = _cloud_context_artifact(
        identity, authority, context, binding_id="rcb_" + "c" * 32,
        verification_record_digest="c" * 64, issued_at_ms=60_002, expires_at_ms=120_003,
    )
    evidence = RunnerContextRolloverEvidence(
        old["binding_id"], old["binding_digest"], new["binding_id"], new["binding_digest"], 60_002,
    )
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    original_unlink = runner_store_module.os.unlink

    def fail_journal_unlink(path, *args, **kwargs):
        if path == "context-rollover.json":
            raise OSError("injected rollover unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(runner_store_module.os, "unlink", fail_journal_unlink)
    with pytest.raises(OSError, match="injected rollover unlink"):
        store.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=evidence,
        )
    monkeypatch.setattr(runner_store_module.os, "unlink", original_unlink)

    restarted = RunnerStore(tmp_path / "home")
    with restarted._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
        journal = runner_store_module._read_json(context_fd, "context-rollover.json", None)
        if tamper == "signature":
            journal["signature_b64"] = "A" * 88
        else:
            if tamper == "evidence":
                journal["evidence"]["new_binding_digest"] = "d" * 64
            else:
                journal["artifact"]["binding_digest"] = "d" * 64
            unsigned = {
                key: value for key, value in journal.items()
                if key not in {"signing_key_id", "signature_b64"}
            }
            journal["signature_b64"] = base64.b64encode(
                signer.sign(canonical_bytes(unsigned)),
            ).decode("ascii")
        runner_store_module._write_json(context_fd, "context-rollover.json", journal)
    with pytest.raises(RunnerStoreError, match="(invalid cloud context rollover journal|does not match recovery)"):
        restarted.install_cloud_context_binding(
            new, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
            rollover_evidence=evidence,
        )


def test_first_cloud_context_sidecar_failure_never_publishes_static_authority(tmp_path, monkeypatch):
    _bound, identity, signer = store_and_identity(tmp_path / "identity")
    store = RunnerStore(tmp_path / "cloud")
    authority = SigningAuthority.generate()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "c" * 32,
        "workspace_id": identity.workspace_id, "project_id": "prj_123456789",
        "environment": {"environment_id": "env_123456789", "origin": "https://staging.acme.dev", "environment_class": "staging", "verification_record_digest": "0" * 64},
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {**unsigned, "binding_digest": canonical_digest(unsigned)}
    artifact.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)))
    original_write = runner_store_module._write_json

    def fail_sidecar(directory_fd, filename, value):
        if filename == "cloud-context-binding.json":
            raise OSError("injected sidecar failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_sidecar)
    with pytest.raises(OSError, match="injected sidecar failure"):
        store.install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )

    restarted = RunnerStore(tmp_path / "cloud")
    assert not restarted.is_context_bound
    with pytest.raises(RunnerStoreError):
        restarted.load_context()


@pytest.mark.parametrize(
    "failed_filename",
    ["cloud-context-provenance.json", "cloud-context-binding.json", "active-context.json"],
)
def test_first_cloud_install_recovers_after_each_commit_record_failure(
    tmp_path, monkeypatch, failed_filename,
):
    _bound, identity, signer = store_and_identity(tmp_path / "identity")
    root = tmp_path / "cloud"
    store = RunnerStore(root)
    authority = SigningAuthority.generate()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "e" * 32,
        "workspace_id": identity.workspace_id, "project_id": "prj_123456789",
        "environment": {"environment_id": "env_123456789", "origin": "https://staging.acme.dev", "environment_class": "staging", "verification_record_digest": "0" * 64},
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {**unsigned, "binding_digest": canonical_digest(unsigned)}
    artifact.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)))
    original_write = runner_store_module._write_json

    def fail_one_commit_record(directory_fd, filename, value):
        if filename == failed_filename:
            raise OSError(f"injected {filename} failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_one_commit_record)
    with pytest.raises(OSError, match="injected"):
        store.install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)

    restarted = RunnerStore(root)
    assert not restarted.is_context_bound
    assert restarted.install_cloud_context_binding(
        artifact, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    ) == restarted.load_context()
    assert restarted.has_cloud_context_provenance()
    assert restarted.verify_cloud_context_binding(
        identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )["binding_digest"] == artifact["binding_digest"]


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
    keychain_runner = FakeSecurity()
    keychain = KeychainVault(
        runner=keychain_runner, verifier=verified, platform_name="Darwin",
    )
    keychain.store("a" * 32, b"keychain-value")
    assert all(call[0][0] == "/usr/bin/security" for call in keychain_runner.calls)
    adds = [call for call in keychain_runner.calls if call[0][1:] == ("-i",)]
    assert len(adds) == 2
    assert all(b" -U" not in payload for _, payload, _ in adds)
    assert all(b"keychain-value" not in " ".join(command).encode() for command, _, _ in keychain_runner.calls)

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


# --------------------------------------------------------------------------- macOS Keychain v2 (R23D)

import hashlib as _hashlib
import platform as _platform
import secrets as _secrets

from heel.runner import vault as vault_module


class FakeSecurity:
    """In-memory ``/usr/bin/security``: find/delete argv and ``-i`` single-line adds on stdin."""

    def __init__(self, items=None, *, add_codes=None, delete_codes=None, mutate=None):
        self.items = dict(items or {})
        self.calls = []
        self.add_codes = dict(add_codes or {})      # account -> rc returned instead of adding
        self.delete_codes = dict(delete_codes or {})
        self.mutate = mutate                        # optional hook(service, account, value) -> stored value

    def __call__(self, command, *, payload, timeout_seconds):
        self.calls.append((tuple(command), payload, timeout_seconds))
        verb = command[1]
        if verb == "-i":
            assert payload.endswith(b"\n") and payload.count(b"\n") == 1
            tokens = payload.decode("ascii").split()
            assert tokens[0] == "add-generic-password" and tokens[1::2][:3] == ["-s", "-a", "-w"]
            service, account, value = tokens[2], tokens[4], tokens[6].encode()
            code = self.add_codes.get(account)
            if code is not None:
                return self._result(code)
            if (service, account) in self.items:
                return self._result(45)
            if self.mutate is not None:
                value = self.mutate(service, account, value)
            self.items[(service, account)] = value
            return self._result(0)
        service, account = command[command.index("-s") + 1], command[command.index("-a") + 1]
        if verb == "find-generic-password":
            if (service, account) not in self.items:
                return self._result(44)
            return self._result(0, self.items[(service, account)] + b"\n" if command[-1] == "-w" else b"attributes")
        if verb == "delete-generic-password":
            code = self.delete_codes.get(account)
            if code is not None:
                return self._result(code)
            return self._result(0 if self.items.pop((service, account), None) is not None else 44)
        raise AssertionError(command)

    @staticmethod
    def _result(code, stdout=b""):
        return type("Result", (), {"returncode": code, "stdout": stdout})()

    def accounts(self, service="heel.runner.canary.v2"):
        return sorted(account for svc, account in self.items if svc == service)


def _keychain(fake):
    return KeychainVault(runner=fake, verifier=verified, platform_name="Darwin")


V2, V1 = "heel.runner.canary.v2", "heel.runner.canary.v1"
H = "c" * 32


def _tag(secret):
    return _hashlib.sha256(secret).hexdigest()[:32]


def test_keychain_v2_store_writes_chunks_then_header_last_with_one_command_per_invocation():
    secret = bytes(range(256)) * 64  # 16384 bytes, every byte value
    fake = FakeSecurity()
    _keychain(fake).store(H, secret)
    adds = [(command, payload) for command, payload, _ in fake.calls if command[1] == "-i"]
    assert [command for command, _ in adds] == [("/usr/bin/security", "-i")] * 9
    accounts = [payload.split()[4].decode() for _, payload in adds]
    assert accounts == [f"{H}.{index}" for index in range(8)] + [H]
    for command, payload in adds:
        assert payload.endswith(b"\n") and payload.count(b"\n") == 1
        assert len(payload) <= 3584 and b" -U " not in payload
    encoded = base64.b64encode(secret)
    assert b"".join(fake.items[(V2, f"{H}.{index}")] for index in range(8)) == encoded
    assert all(len(fake.items[(V2, f"{H}.{index}")]) == 3072 for index in range(7))
    assert len(fake.items[(V2, f"{H}.7")]) == 344
    assert fake.items[(V2, H)] == f"v2.16384.8.{_tag(secret)}".encode()
    for command, _, _ in fake.calls:
        assert encoded[:64].decode() not in " ".join(command)
    assert _keychain(fake).load(H) == secret


def test_keychain_v2_chunk_count_and_line_length_bounds_hold_at_max_secret():
    from heel.runner.identity import SECURITY_INTERACTIVE_MAX_LINE_BYTES, security_interactive_add_command

    assert vault_module._KEYCHAIN_MAX_CHUNKS == 8
    assert vault_module._KEYCHAIN_CHUNK_CHARS == 3072
    longest = security_interactive_add_command(V2, f"{H}.7", b"A" * 3072)
    assert len(longest) == 3160 < SECURITY_INTERACTIVE_MAX_LINE_BYTES < 4095
    fake = FakeSecurity()
    with pytest.raises(SecretTooLargeError):
        _keychain(fake).store(H, b"x" * (MAX_SECRET_BYTES + 1))
    with pytest.raises(ValueError):
        _keychain(fake).store(H, b"")
    assert fake.calls == []


def test_keychain_v2_store_aborts_on_duplicate_chunk_without_deleting_foreign_items():
    foreign = {(V2, f"{H}.0"): b"Zm9yZWlnbg=="}
    fake = FakeSecurity(foreign)
    with pytest.raises(VaultUnavailable, match="already exists"):
        _keychain(fake).store(H, b"x" * 9000)
    assert fake.items == foreign
    assert not [call for call in fake.calls if call[0][1] == "delete-generic-password"]

    fake = FakeSecurity(add_codes={f"{H}.3": 45})
    with pytest.raises(VaultUnavailable, match="already exists"):
        _keychain(fake).store(H, b"y" * 12000)
    deleted = [call[0][-1] for call in fake.calls if call[0][1] == "delete-generic-password"]
    assert deleted == [f"{H}.2", f"{H}.1", f"{H}.0"]
    assert fake.items == {}

    fake = FakeSecurity(add_codes={f"{H}.1": 1})
    with pytest.raises(VaultUnavailable, match="vault unavailable"):
        _keychain(fake).store(H, b"z" * 5000)
    assert fake.items == {}


def test_keychain_v2_store_rolls_back_only_created_items_when_readback_mismatches():
    def truncate(service, account, value):
        return value[:-4] if account == f"{H}.1" else value

    unrelated = {(V2, "d" * 32): b"v2.1.1." + b"0" * 32}
    fake = FakeSecurity(unrelated, mutate=truncate)
    with pytest.raises(VaultUnavailable, match="vault unavailable"):
        _keychain(fake).store(H, b"q" * 4000)
    deleted = [call[0][-1] for call in fake.calls if call[0][1] == "delete-generic-password"]
    assert deleted == [H, f"{H}.1", f"{H}.0"]
    assert fake.items == unrelated

    fake = FakeSecurity(mutate=truncate, delete_codes={f"{H}.0": 1})
    with pytest.raises(VaultUnavailable) as caught:
        _keychain(fake).store(H, b"q" * 4000)
    assert "cleanup incomplete" in "".join(getattr(caught.value, "__notes__", []))
    assert (V2, H) not in fake.items


def _stored(secret):
    fake = FakeSecurity()
    _keychain(fake).store(H, secret)
    return fake


@pytest.mark.parametrize("damage", [
    "missing-chunk", "short-chunk", "long-chunk", "swapped-chunks", "tag-mismatch",
    "length-count-mismatch", "zero-length", "count-9", "v3-header", "chunk-not-base64",
])
def test_keychain_v2_load_fails_closed_on_missing_short_extra_or_swapped_chunk_and_bad_tag(damage):
    secret = _secrets.token_bytes(5000)
    fake = _stored(secret)
    fake.items[(V1, H)] = b"legacy-must-not-be-used"
    header = fake.items[(V2, H)].decode()
    if damage == "missing-chunk":
        del fake.items[(V2, f"{H}.1")]
    elif damage == "short-chunk":
        fake.items[(V2, f"{H}.0")] = fake.items[(V2, f"{H}.0")][:-1]
    elif damage == "long-chunk":
        fake.items[(V2, f"{H}.2")] += b"A"
    elif damage == "swapped-chunks":
        other = _stored(_secrets.token_bytes(5000))
        fake.items[(V2, f"{H}.0")] = other.items[(V2, f"{H}.0")]
    elif damage == "tag-mismatch":
        fake.items[(V2, H)] = (header[:-32] + "0" * 32).encode()
    elif damage == "length-count-mismatch":
        fake.items[(V2, H)] = header.replace(".3.", ".2.", 1).encode()
    elif damage == "zero-length":
        fake.items[(V2, H)] = f"v2.0.1.{'0' * 32}".encode()
    elif damage == "count-9":
        fake.items[(V2, H)] = header.replace(".3.", ".9.", 1).encode()
    elif damage == "v3-header":
        fake.items[(V2, H)] = ("v3" + header[2:]).encode()
    elif damage == "chunk-not-base64":
        chunk = fake.items[(V2, f"{H}.0")]
        fake.items[(V2, f"{H}.0")] = b"!" + chunk[1:]
    fake.calls.clear()
    with pytest.raises(VaultUnavailable, match="invalid material") as caught:
        _keychain(fake).load(H)
    assert not [call for call in fake.calls if V1 in call[0]]
    assert "5000" not in str(caught.value)


def test_keychain_v2_header_present_never_consults_legacy_service():
    secret = b"current-v2-secret"
    fake = _stored(secret)
    fake.items[(V1, H)] = b"stale-legacy-value"
    fake.calls.clear()
    assert _keychain(fake).load(H) == secret
    assert not [call for call in fake.calls if V1 in call[0]]


def test_keychain_legacy_v1_valid_item_is_served_unchanged_and_never_rewritten():
    legacy = {(V1, H): b"LegacyDummyValue123"}
    fake = FakeSecurity(legacy)
    vault = _keychain(fake)
    assert vault.exists(H) is True
    assert vault.load(H) == b"LegacyDummyValue123"
    assert fake.items == legacy
    assert not [call for call in fake.calls if call[0][1] in {"-i", "delete-generic-password"}]


def test_keychain_legacy_v1_empty_item_fails_closed_with_remove_and_readd_message_and_blocks_store():
    legacy = {(V1, H): b""}
    fake = FakeSecurity(legacy)
    vault = _keychain(fake)
    with pytest.raises(VaultUnavailable, match="empty; remove it and add it again"):
        vault.load(H)
    with pytest.raises(VaultUnavailable, match="already exists"):
        vault.store(H, b"replacement")
    assert fake.items == legacy
    vault.delete(H)
    assert fake.items == {}


def test_keychain_exists_is_header_or_legacy_only_not_orphan_chunks():
    fake = FakeSecurity({(V2, f"{H}.0"): b"QUJD", (V2, f"{H}.1"): b"QUJD"})
    vault = _keychain(fake)
    assert vault.exists(H) is False
    with pytest.raises(VaultUnavailable, match="not found"):
        vault.load(H)
    # The orphan prefix blocks a store at its first slot without being deleted by it.
    with pytest.raises(VaultUnavailable, match="already exists"):
        vault.store(H, b"new")
    assert fake.accounts() == [f"{H}.0", f"{H}.1"]
    assert _keychain(FakeSecurity({(V2, H): b"v2.1.1." + b"0" * 32})).exists(H) is True
    vault = _keychain(ScriptedRunner([(1, b"")]))
    with pytest.raises(VaultUnavailable, match="vault unavailable"):
        vault.exists(H)


def test_keychain_delete_sweeps_header_then_eight_slots_then_legacy_and_reports_failure_after_completing():
    fake = _stored(_secrets.token_bytes(16384))
    fake.items[(V1, H)] = b"legacy"
    fake.calls.clear()
    _keychain(fake).delete(H)
    order = [(call[0][3], call[0][5]) for call in fake.calls]
    assert order == [(V2, H)] + [(V2, f"{H}.{index}") for index in range(8)] + [(V1, H)]
    assert fake.items == {}
    _keychain(fake).delete(H)  # idempotent

    fake = _stored(b"p" * 9000)
    fake.delete_codes = {f"{H}.1": 1}
    with pytest.raises(VaultUnavailable, match="vault unavailable"):
        _keychain(fake).delete(H)
    assert len(fake.calls) - fake.calls.index(next(c for c in fake.calls if c[0][1] == "delete-generic-password")) == 10
    assert fake.accounts() == [f"{H}.1"]
    assert _keychain(fake).exists(H) is False


def test_keychain_vault_errors_never_contain_secret_bytes_or_lengths():
    secret = b"SECRET-MARKER-" + b"9" * 4321
    failures = []
    for options in ({"add_codes": {H: 1}}, {"add_codes": {f"{H}.0": 45}},
                    {"mutate": lambda service, account, value: value[:-1] if account == f"{H}.0" else value}):
        with pytest.raises(VaultUnavailable) as caught:
            _keychain(FakeSecurity(**options)).store(H, secret)
        failures.append(caught.value)
    fake = _stored(secret)
    fake.items[(V2, f"{H}.1")] = fake.items[(V2, f"{H}.1")][:-2]
    with pytest.raises(VaultUnavailable) as caught:
        _keychain(fake).load(H)
    failures.append(caught.value)
    for error in failures:
        rendered = f"{error!s} {error!r} {getattr(error, '__notes__', [])!r}"
        assert "SECRET-MARKER" not in rendered and "4335" not in rendered and "4321" not in rendered
        assert base64.b64encode(secret)[:16].decode() not in rendered


class _SweepVault:
    backend_id = "macos_keychain"
    supported = True

    def __init__(self, *, fail_deletes=0):
        self.deleted, self.fail_deletes = [], fail_deletes

    def exists(self, handle):
        return False

    def delete(self, handle):
        self.deleted.append(handle)
        if self.fail_deletes:
            self.fail_deletes -= 1
            raise VaultUnavailable("secure credential vault unavailable")


def test_pending_keychain_recovery_sweeps_orphan_slots_and_keeps_the_record_until_deletion_succeeds(tmp_path):
    store, _, _ = store_and_identity(tmp_path)
    pending = store.reserve_os_credential(
        semantic_role="object_owner", auth_profile="bearer", label="owner", backend="macos_keychain",
    )
    handle = pending["credential_handle_id"]
    failing = _SweepVault(fail_deletes=1)
    store.recover_credentials({"macos_keychain": failing})
    # Partial delete failure: the pending record and its handle stay for a retry.
    kept = {item["credential_handle_id"]: item for item in store.list_credentials()}
    assert failing.deleted == [handle] and kept[handle]["state"] == "pending"
    store.recover_credentials({"macos_keychain": failing})
    assert failing.deleted == [handle, handle]
    assert handle not in {item["credential_handle_id"] for item in store.list_credentials()}

    # A real (fake-backed) orphan prefix is swept by the recovery delete.
    fake = FakeSecurity()
    vault = _keychain(fake)
    pending = store.reserve_os_credential(
        semantic_role="object_owner", auth_profile="bearer", label="owner", backend="macos_keychain",
    )
    handle = pending["credential_handle_id"]
    fake.items[(V2, f"{handle}.0")] = b"QUJD"
    fake.items[(V2, f"{handle}.1")] = b"QUJD"
    store.recover_credentials({"macos_keychain": vault})
    assert fake.items == {}
    assert handle not in {item["credential_handle_id"] for item in store.list_credentials()}


def test_pending_recovery_for_other_backends_never_deletes_and_drops_the_absent_record(tmp_path):
    store, _, _ = store_and_identity(tmp_path)
    pending = store.reserve_os_credential(
        semantic_role="object_owner", auth_profile="bearer", label="owner", backend="linux_secret_service",
    )

    class SecretService(_SweepVault):
        backend_id = "linux_secret_service"

    vault = SecretService(fail_deletes=1)
    store.recover_credentials({"linux_secret_service": vault})
    assert vault.deleted == []
    assert pending["credential_handle_id"] not in {
        item["credential_handle_id"] for item in store.list_credentials()
    }


_REAL_KEYCHAIN = pytest.mark.skipif(
    _platform.system() != "Darwin" or not os.path.isfile("/usr/bin/security"),
    reason="real macOS Keychain only",
)


def _real_find_rc(service, account):
    return subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", service, "-a", account],
        capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).returncode


def _real_raw_add(service, account, line_value):
    subprocess.run(
        ["/usr/bin/security", "-i"], capture_output=True, timeout=20,
        input=f"add-generic-password -s {service} -a {account} -w {line_value}\n".encode(),
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


@_REAL_KEYCHAIN
@pytest.mark.parametrize("name", [
    "min-1", "binary-newline-meta", "2303", "2304", "2305", "4607", "4608", "cookie-jar", "max-16384",
])
def test_macos_keychain_v2_round_trip_min_max_binary_newline(name):
    values = {
        "min-1": b"\x01", "binary-newline-meta": b"\x00\xff\r\n'\"$;|&<>\\ -U -w",
        "2303": _secrets.token_bytes(2303), "2304": _secrets.token_bytes(2304),
        "2305": _secrets.token_bytes(2305), "4607": _secrets.token_bytes(4607),
        "4608": _secrets.token_bytes(4608),
        "cookie-jar": json.dumps({"cookies": [{"name": "session", "value": "dummy"}]}).encode(),
        "max-16384": _secrets.token_bytes(MAX_SECRET_BYTES),
    }
    vault, handle = KeychainVault(), _secrets.token_hex(16)
    try:
        vault.store(handle, values[name])
        assert vault.exists(handle) is True
        assert vault.load(handle) == values[name]
    finally:
        vault.delete(handle)
    assert vault.exists(handle) is False
    assert _real_find_rc(V2, f"{handle}.0") == 44


@_REAL_KEYCHAIN
def test_macos_keychain_v2_duplicate_and_concurrent_store_same_handle_yields_one_owner():
    vault, handle = KeychainVault(), _secrets.token_hex(16)
    values = [_secrets.token_bytes(7000), _secrets.token_bytes(7000)]
    outcomes = [None, None]
    barrier = threading.Barrier(2)

    def write(index):
        barrier.wait()
        try:
            KeychainVault().store(handle, values[index])
            outcomes[index] = "stored"
        except VaultUnavailable as error:
            outcomes[index] = str(error)

    try:
        threads = [threading.Thread(target=write, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        assert sorted(outcomes) == ["secure credential already exists", "stored"]
        assert vault.load(handle) == values[outcomes.index("stored")]
        with pytest.raises(VaultUnavailable, match="already exists"):
            vault.store(handle, b"again")
    finally:
        vault.delete(handle)
    assert vault.exists(handle) is False


@_REAL_KEYCHAIN
def test_macos_keychain_v2_orphan_prefix_blocks_store_and_is_swept_by_delete():
    vault, handle = KeychainVault(), _secrets.token_hex(16)
    try:
        _real_raw_add(V2, f"{handle}.0", "QUJD")
        _real_raw_add(V2, f"{handle}.1", "QUJD")
        assert vault.exists(handle) is False
        with pytest.raises(VaultUnavailable, match="already exists"):
            vault.store(handle, b"x" * 5000)
        assert _real_find_rc(V2, f"{handle}.1") == 0
    finally:
        vault.delete(handle)
    assert _real_find_rc(V2, f"{handle}.0") == 44 and _real_find_rc(V2, f"{handle}.1") == 44


@_REAL_KEYCHAIN
def test_macos_keychain_v2_truncated_chunk_fails_closed():
    vault, handle = KeychainVault(), _secrets.token_hex(16)
    try:
        vault.store(handle, _secrets.token_bytes(5000))
        subprocess.run(
            ["/usr/bin/security", "delete-generic-password", "-s", V2, "-a", f"{handle}.1"],
            capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        with pytest.raises(VaultUnavailable, match="invalid material"):
            vault.load(handle)
        assert _real_find_rc(V1, handle) == 44
    finally:
        vault.delete(handle)
    assert vault.exists(handle) is False


@_REAL_KEYCHAIN
def test_macos_keychain_legacy_v1_empty_and_valid_items_behave_as_specified():
    vault = KeychainVault()
    empty, valid = _secrets.token_hex(16), _secrets.token_hex(16)
    try:
        # The pre-R23 prompted protocol with one value stores an empty item (T2aR D2).
        subprocess.run(
            ["/usr/bin/security", "add-generic-password", "-s", V1, "-a", empty, "-w"],
            input=b"legacy", capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        _real_raw_add(V1, valid, "LegacyDummyValue123")
        assert vault.exists(empty) is True
        with pytest.raises(VaultUnavailable, match="empty; remove it and add it again"):
            vault.load(empty)
        with pytest.raises(VaultUnavailable, match="already exists"):
            vault.store(empty, b"replacement")
        assert _real_find_rc(V1, empty) == 0 and _real_find_rc(V2, empty) == 44
        assert vault.load(valid) == b"LegacyDummyValue123"
        assert _real_find_rc(V2, valid) == 44
    finally:
        vault.delete(empty)
        vault.delete(valid)
    assert _real_find_rc(V1, empty) == 44 and _real_find_rc(V1, valid) == 44
