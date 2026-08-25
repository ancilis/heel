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
    EphemeralVault,
    KeychainVault,
    SecretServiceVault,
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
    with pytest.raises(RunnerStoreError, match="provenance"):
        store.verify_cloud_context_binding(
            identity=identity, trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )


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
    store.transition_run(grant["run_id"], "terminal", now_ms=2_001)
    assert store.install_cloud_context_binding(
        new, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=60_002,
        rollover_evidence=evidence,
    ).verification_record_digest == "6" * 64


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
