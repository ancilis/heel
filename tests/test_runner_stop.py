from __future__ import annotations

import copy
import json
import os
import shutil
import threading
import time

import pytest

from heel.canary_contracts import (
    EXECUTION_GRANT_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_canary_findings,
    validate_operational_run,
)
from heel.crypto import SigningAuthority
from heel.runner.containment import ContainmentError, ContainmentLog
from heel.runner.execution import (
    ExecutionBundle,
    ExecutionGate,
    LocalCanaryExecutor,
    validate_execution_bundle,
)
from heel.runner.http_transport import BoundedResponseEvidence, TargetResponse, TransportFailure
from heel.runner.service import ClaimLease, RunnerService
from heel.runner.runtime import RunnerRuntimeState
from heel.runner.store import RunnerStoreError
from tests.test_runner_compiler import CanaryCompiler, add_roles, bound_store, map_scenarios


ALL_ERRORS = sorted({
    "none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired",
    "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted",
    "containment_rejected", "cloud_disconnected",
})
ALL_STOPS = sorted({
    "none", "local_emergency_stop", "cloud_stop", "runner_revoked",
    "target_revoked", "kill_switch",
})
OPERATIONAL_CODES = sorted({
    "admitted", "action_started", "action_completed", "action_rejected",
    "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted",
})


def compiled_pair(tmp_path):
    store, identity, signer = bound_store(tmp_path)
    map_scenarios(store)
    add_roles(store)
    result = CanaryCompiler(
        store=store, identity=identity, signer=signer, now_ms=1_000,
    ).compile(["anonymous_authenticated_read", "object_ownership_read"])
    return store, identity, signer, result.manifest, result.projection


def signed_grant(manifest, projection, identity, authority, *, issued=1_000, expires=10_000):
    unsigned = {
        "schema_version": EXECUTION_GRANT_SCHEMA,
        "grant_id": "grant_123456789",
        "run_id": "crun_" + "a" * 32,
        "workspace_id": manifest["workspace_id"],
        "project_id": manifest["project_id"],
        "approval": {
            "projection_id": projection["projection_id"],
            "projection_digest": projection["projection_digest"],
            "manifest_digest": manifest["manifest_digest"],
        },
        "environment": copy.deepcopy(manifest["environment"]),
        "runner_binding": {
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        },
        "approval_actor": {"user_id": "user_owner_123", "role": "owner"},
        "approval_reason": "Release canary",
        "consented_at_ms": issued,
        "budgets": copy.deepcopy(manifest["budgets"]),
        "egress": copy.deepcopy(manifest["egress"]),
        "retry_policy": copy.deepcopy(manifest["retry_policy"]),
        "grant_nonce": "nonce_123456789",
        "kill_switch_generation": 7,
        "operational_receipt_policy": {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "maximum_bytes": 32 * 1024,
            "allowed_error_categories": ALL_ERRORS,
            "allowed_stop_reasons": ALL_STOPS,
            "allowed_containment_codes": OPERATIONAL_CODES,
        },
        "issued_at_ms": issued,
        "expires_at_ms": expires,
    }
    grant = {
        **unsigned,
        "grant_digest": canonical_digest(unsigned),
        **authority.sign(canonical_bytes(unsigned)),
    }
    return grant


def resign_grant(grant, authority):
    unsigned = {
        key: copy.deepcopy(value) for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    return {
        **unsigned,
        "grant_digest": canonical_digest(unsigned),
        **authority.sign(canonical_bytes(unsigned)),
    }


def active_gate(now=2_000):
    return ExecutionGate(
        active=True,
        runner_state="active",
        proof_state="valid",
        proof_expires_at_ms=20_000,
        kill_switch_generation=7,
        stop_reason="none",
        server_time_ms=now,
    )


def test_execution_bundle_is_exactly_bound_signed_fresh_and_reserved_once(tmp_path):
    store, identity, _, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    bundle = ExecutionBundle(manifest, projection, grant)
    trusted = {authority.key_id: authority.public_key}

    validated = validate_execution_bundle(
        bundle, store=store, identity=identity, trusted_grant_keys=trusted,
        now_ms=2_000, gate=active_gate(),
    )
    assert validated.grant["grant_digest"] == grant["grant_digest"]
    reserved = store.reserve_run(validated.grant, retention_expires_at_ms=86_400_000)
    assert store.reserve_run(validated.grant, retention_expires_at_ms=86_400_000) == reserved

    mutations = []
    wrong_runner = copy.deepcopy(grant)
    wrong_runner["runner_binding"]["runner_id"] = "runner_other"
    mutations.append(resign_grant(wrong_runner, authority))
    lower_budget = copy.deepcopy(grant)
    lower_budget["budgets"]["maximum_requests"] -= 1
    mutations.append(resign_grant(lower_budget, authority))
    wrong_project = copy.deepcopy(grant)
    wrong_project["project_id"] = "project_other"
    mutations.append(resign_grant(wrong_project, authority))
    for mutated in mutations:
        with pytest.raises(ValueError):
            validate_execution_bundle(
                ExecutionBundle(manifest, projection, mutated), store=store, identity=identity,
                trusted_grant_keys=trusted, now_ms=2_000, gate=active_gate(),
            )
    with pytest.raises(ValueError, match="expired"):
        validate_execution_bundle(
            bundle, store=store, identity=identity, trusted_grant_keys=trusted,
            now_ms=10_000, gate=active_gate(10_000),
            )


def test_run_authority_rejects_a_signed_reservation_with_an_extra_field(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    run_path = store.run_path(grant["run_id"])
    record_path = run_path.parent / f"reservation-{run_path.name}.json"
    stored = json.loads(record_path.read_text())
    core = {
        key: value for key, value in stored.items()
        if key not in {"record_digest", "signing_key_id", "signature_b64"}
    }
    core["unexpected"] = "authority extension"
    record_path.write_bytes(canonical_bytes(
        store._signed_run_authority_value(core, signer=signer, record_digest=True)
    ))

    with pytest.raises(RunnerStoreError, match="invalid local run authority record"):
        store.recover_run_reservation(grant["run_id"])


def test_run_authority_journal_rejects_a_signed_noncanonical_next_index_before_recovery(
    tmp_path, monkeypatch,
):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    with monkeypatch.context() as fault:
        fault.setattr(store, "_ensure_json_exact", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("interrupted")))
        with pytest.raises(OSError, match="interrupted"):
            store.reserve_run(grant, retention_expires_at_ms=86_400_000)

    journal_path = store.run_path(grant["run_id"]).parent / "run-authority-journal.json"
    journal = json.loads(journal_path.read_text())
    index_core = {
        key: value for key, value in journal["next_index"].items()
        if key not in {"signing_key_id", "signature_b64"}
    }
    index_core["unexpected"] = "authority extension"
    journal_core = {
        key: value for key, value in journal.items()
        if key not in {"signing_key_id", "signature_b64"}
    }
    journal_core["next_index"] = store._signed_run_authority_value(
        index_core, signer=signer, record_digest=False,
    )
    journal_path.write_bytes(canonical_bytes(
        store._signed_run_authority_value(journal_core, signer=signer, record_digest=False)
    ))

    with pytest.raises(RunnerStoreError, match="local run authority index is invalid"):
        store.recover_run_reservation(grant["run_id"])
    assert not (store.run_path(grant["run_id"]) / "state.json").exists()


def test_queue_only_terminal_pruning_is_rejected_without_runtime_authority(tmp_path, monkeypatch):
    import heel.runner.store as store_module

    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    deadline = store.load_run(grant["run_id"])["retention_expires_at_ms"]
    with monkeypatch.context() as fault:
        fault.setattr(store_module.os, "listdir", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("history listing")))
        with pytest.raises(RunnerStoreError, match="runtime terminal prune is required"):
            store.prune_expired_runs(now_ms=deadline)
    run_path = store.run_path(grant["run_id"])
    assert run_path.exists()
    assert not (run_path.parent / f"pruned-{run_path.name}.json").exists()


def test_terminal_run_directory_loss_never_resurrects_a_consumed_grant(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    shutil.rmtree(store.run_path(grant["run_id"]))

    with pytest.raises(RunnerStoreError, match="terminal local run is unavailable"):
        store.recover_run_reservation(grant["run_id"])


def test_terminal_state_rollback_never_replays_a_consumed_grant(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    state_path = store.run_path(grant["run_id"]) / "state.json"
    state = json.loads(state_path.read_text())
    state["state"] = "verified"
    state_path.write_bytes(canonical_bytes(state))
    replay_transport = ScriptedTransport([200])

    with pytest.raises(RunnerStoreError, match="local run authority reservation is unavailable"):
        LocalCanaryExecutor(
            store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key},
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
            monotonic=lambda: 1.0,
        ).execute(
            ExecutionBundle(manifest, projection, grant),
            transport=replay_transport, gate_source=active_gate,
        )
    assert replay_transport.calls == []


def test_terminal_queue_replay_rejects_rolled_back_mutable_terminal_state(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    state_path = store.run_path(grant["run_id"]) / "state.json"
    rolled_back = json.loads(state_path.read_text())
    rolled_back["state"] = "finalizing"
    state_path.write_bytes(canonical_bytes(rolled_back))

    with pytest.raises(RunnerStoreError, match="terminal queue is invalid"):
        store.transition_run(grant["run_id"], "terminal", now_ms=2_001)
    assert json.loads(state_path.read_text())["state"] == "finalizing"


def test_nonempty_legacy_run_root_never_receives_a_zero_authority_index_implicitly(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    run_path = store.run_path(grant["run_id"])
    index_path = run_path.parent / "run-authority-index.json"
    index_path.unlink()
    assert run_path.is_dir()
    assert not index_path.exists()
    assert run_path.name in {entry.name for entry in run_path.parent.iterdir()}
    assert (run_path.parent.parent / "binding.json").is_file()

    restarted = type(store)(store.root)
    assert restarted.namespace == store.namespace
    context = store.load_context()
    assert not index_path.exists()
    with pytest.raises(RunnerStoreError, match="local run authority index is unavailable"):
        restarted.bind_context(
            context, identity=identity, signer=signer, signer_label="runner-test-key",
        )
    assert not index_path.exists()


def test_first_context_bind_recovers_when_zero_authority_index_write_crashes(tmp_path, monkeypatch):
    import heel.runner.store as store_module

    source, identity, signer = bound_store(tmp_path / "source")
    context = source.load_context()
    store = type(source)(tmp_path / "faulted")
    create_json = store_module._create_json

    def fail_zero_index(directory_fd, filename, value):
        if filename == "run-authority-index.json":
            raise OSError("zero index interrupted")
        return create_json(directory_fd, filename, value)

    with monkeypatch.context() as fault:
        fault.setattr(store_module, "_create_json", fail_zero_index)
        with pytest.raises(OSError, match="zero index interrupted"):
            store.bind_context(
                context, identity=identity, signer=signer, signer_label="runner-test-key",
            )

    restarted = type(store)(store.root)
    assert not restarted.is_context_bound
    restarted.bind_context(
        context, identity=identity, signer=signer, signer_label="runner-test-key",
    )
    assert restarted.is_context_bound


def test_authenticated_legacy_authority_upgrade_rebuilds_one_reservation_index(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    expected = store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    index_path = store.run_path(grant["run_id"]).parent / "run-authority-index.json"
    index_path.unlink()

    restarted = type(store).for_runtime(store.root, identity=identity, signer=signer)
    restarted.upgrade_legacy_run_authority_index()

    assert restarted.recover_run_reservation(grant["run_id"]) == expected


def test_executor_refuses_a_restart_store_without_pinned_runtime_authority(tmp_path):
    store, identity, signer, _manifest, _projection = compiled_pair(tmp_path)
    restarted = type(store)(store.root)

    with pytest.raises(RunnerStoreError, match="authenticated runner store is required"):
        LocalCanaryExecutor(
            store=restarted, identity=identity, signer=signer,
            trusted_grant_keys={"unused": SigningAuthority.generate().public_key},
        )


@pytest.mark.parametrize("checkpoint", ["write", "fsync", "rename"])
def test_create_only_records_are_never_visible_before_atomic_publish(
    tmp_path, monkeypatch, checkpoint,
):
    import heel.runner.store as store_module

    directory_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with monkeypatch.context() as fault:
            if checkpoint == "write":
                real_write = os.write
                writes = [0]

                def interrupted_write(descriptor, value):
                    if writes[0]:
                        raise OSError("simulated crash")
                    writes[0] += 1
                    return real_write(descriptor, value[:max(1, len(value) // 2)])

                fault.setattr(store_module.os, "write", interrupted_write)
            elif checkpoint == "fsync":
                fault.setattr(
                    store_module.os, "fsync",
                    lambda descriptor: (_ for _ in ()).throw(OSError("simulated crash")),
                )
            else:
                fault.setattr(
                    store_module.os, "rename",
                    lambda *args, **kwargs: (_ for _ in ()).throw(OSError("simulated crash")),
                )
            with pytest.raises(OSError, match="simulated crash"):
                store_module._create_json(directory_fd, "finals.json", {"complete": "yes"})
        assert not (tmp_path / "finals.json").exists()
        assert list(tmp_path.iterdir()) == []
        store_module._create_json(directory_fd, "finals.json", {"complete": "yes"})
        assert json.loads((tmp_path / "finals.json").read_text()) == {"complete": "yes"}
    finally:
        os.close(directory_fd)


def test_interrupted_consumption_marker_can_be_safely_retried(tmp_path, monkeypatch):
    import heel.runner.store as store_module

    store, identity, _, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    real_write = os.write
    writes = [0]

    def interrupted_write(descriptor, value):
        if writes[0]:
            raise OSError("simulated crash")
        writes[0] += 1
        return real_write(descriptor, value[:max(1, len(value) // 2)])

    with monkeypatch.context() as fault:
        fault.setattr(store_module.os, "write", interrupted_write)
        with pytest.raises(OSError, match="simulated crash"):
            store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    assert store.load_run_grant(grant["run_id"]) == grant


def test_containment_chain_is_zero_based_signed_closed_and_tamper_evident(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    log = ContainmentLog(
        store=store, signer=signer, run_id=grant["run_id"], grant_id=grant["grant_id"],
        manifest_digest=manifest["manifest_digest"], clock_ms=lambda: 2_000,
    )
    first = log.append("grant_verified", detail_code="grant_exact")
    events_path = store.run_path(grant["run_id"]) / "events"
    unfinished = events_path / ".00000000000000000001.json.0123456789abcdef01234567.tmp"
    unfinished.write_bytes(b'{"partial":')
    unfinished.chmod(0o600)
    assert log.load() == [first]
    second = log.append(
        "action_started", action_ordinal=0, scenario_id="anonymous_authenticated_read",
        semantic_role="anonymous", attempt=1, detail_code="admitted",
        counters={"requests_started": 1},
    )
    assert first["sequence"] == 0 and first["previous_event_digest"] == "0" * 64
    assert second["sequence"] == 1
    assert second["previous_event_digest"] == first["event_digest"]
    assert not unfinished.exists()
    assert [item["event_code"] for item in log.load()] == ["grant_verified", "action_started"]
    with pytest.raises(ValueError, match="event code"):
        log.append("raw_response", detail_code="forbidden")

    event_path = store.run_path(grant["run_id"]) / "events" / "00000000000000000001.json"
    value = __import__("json").loads(event_path.read_text())
    value["detail_code"] = "tampered"
    event_path.write_text(__import__("json").dumps(value, separators=(",", ":"), sort_keys=True))
    with pytest.raises(ContainmentError):
        log.load()


def test_local_evidence_is_opaque_owner_only_bounded_and_retention_pruned(tmp_path):
    store, identity, _, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    state = store.reserve_run(grant, retention_expires_at_ms=50_000)
    assert state["runner_authority"] == {
        "runner_key_id": identity.key_id,
        "public_key_b64": identity.public_key_b64,
        "public_key_digest": identity.fingerprint,
    }
    headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
    body = b"{}"
    reference = store.store_response_evidence(
        grant["run_id"], action_ordinal=0, attempt=1, status_code=200,
        raw_headers=headers, raw_body=body, expires_at_ms=40_000,
    )
    assert reference.startswith("ev1_") and len(reference) == 68
    assert store.load_response_evidence(grant["run_id"], reference, now_ms=2_000) == (
        headers, body,
    )
    evidence_dir = store.run_path(grant["run_id"]) / "evidence"
    binary = evidence_dir / f"{reference}.bin"
    assert binary.stat().st_mode & 0o777 == 0o600
    assert not binary.read_bytes().startswith(b"{")
    with pytest.raises(ValueError, match="exceeds"):
        store.store_response_evidence(
            grant["run_id"], action_ordinal=0, attempt=1, status_code=200,
            raw_headers=b"x" * (16 * 1024 + 1), raw_body=b"", expires_at_ms=40_000,
        )
    with pytest.raises(RunnerStoreError, match="expired"):
        store.load_response_evidence(grant["run_id"], reference, now_ms=40_000)
    assert store.prune_expired_evidence(now_ms=40_000) == 1
    assert store.run_path(grant["run_id"]).is_dir()
    with pytest.raises(RunnerStoreError, match="final projections are unavailable"):
        store.transition_run(grant["run_id"], "terminal", now_ms=3_000)


def test_evidence_references_are_random_and_integrity_digest_stays_local(tmp_path):
    store, identity, _, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=50_000)
    values = {
        "action_ordinal": 0, "attempt": 1, "status_code": 200,
        "raw_headers": b"Content-Length: 2", "raw_body": b"{}",
        "expires_at_ms": 40_000,
    }
    first = store.store_response_evidence(grant["run_id"], **values)
    second = store.store_response_evidence(grant["run_id"], **values)
    guessed = "ev1_" + __import__("hashlib").sha256(b"\0".join((
        grant["run_id"].encode(), b"0", b"1", b"200",
        values["raw_headers"], values["raw_body"],
    ))).hexdigest()
    assert first != second
    assert first != guessed and second != guessed
    metadata = json.loads(
        (store.run_path(grant["run_id"]) / "evidence" / f"{first}.meta").read_text()
    )
    assert metadata["content_sha256"] == __import__("hashlib").sha256(
        len(values["raw_headers"]).to_bytes(4, "big")
        + values["raw_headers"] + values["raw_body"],
    ).hexdigest()
    assert store.load_response_evidence(grant["run_id"], first, now_ms=2_000) == (
        values["raw_headers"], values["raw_body"],
    )


def test_store_reverifies_bound_runner_signatures_on_save_and_load(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    assert store.load_final_projections(grant["run_id"])["local_view"] == result.local_view
    run_path = store.run_path(grant["run_id"])
    path = run_path / "finals.json"
    for projection_name in ("operational_projection", "findings_projection"):
        original = path.read_bytes()
        tampered = json.loads(original)
        tampered[projection_name]["signature_b64"] = __import__("base64").b64encode(
            b"\0" * 64,
        ).decode("ascii")
        tampered["local_view"][projection_name]["signature_b64"] = tampered[
            projection_name
        ]["signature_b64"]
        if projection_name == "findings_projection":
            tampered["disclosure_preview"]["projection"]["signature_b64"] = tampered[
                projection_name
            ]["signature_b64"]
        core = {key: value for key, value in tampered.items() if key != "finals_digest"}
        tampered["finals_digest"] = canonical_digest(core)
        path.write_text(json.dumps(tampered, sort_keys=True, separators=(",", ":")))
        with pytest.raises(RunnerStoreError, match="signature"):
            store.load_final_projections(grant["run_id"])
        path.write_bytes(original)
    state_path = run_path / "state.json"
    state = json.loads(state_path.read_text())
    replacement = SigningAuthority.generate()
    state["runner_authority"] = {
        "runner_key_id": replacement.key_id,
        "public_key_b64": replacement.canonical_public_key,
        "public_key_digest": __import__("hashlib").sha256(
            replacement.public_key_bytes,
        ).hexdigest(),
    }
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunnerStoreError, match="bound identity"):
        store.load_final_projections(grant["run_id"])


def test_terminal_runtime_anchor_is_derived_from_the_signed_local_terminal_authority(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )

    anchor = store._runtime_terminal_anchor(grant["run_id"])

    assert anchor == {
        "run_id": grant["run_id"], "project_id": grant["project_id"],
        "grant_id": grant["grant_id"],
        "approval_projection_digest": projection["projection_digest"],
        "terminal_projection_digest": result.operational_projection["projection_digest"],
        "terminal_record_digest": anchor["terminal_record_digest"],
        "terminal_at_ms": 2_000,
        "retention_expires_at_ms": store.load_run(grant["run_id"])["retention_expires_at_ms"],
    }


def test_detach_terminal_signs_one_immutable_record_before_result_transport(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    anchor = store._runtime_terminal_anchor(grant["run_id"])
    local = runtime.register_local_terminal(**anchor)

    detached_digest = store.detach_terminal(
        grant["run_id"], runtime=runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )

    assert detached_digest == store.detach_terminal(
        grant["run_id"], runtime=runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )
    assert len(detached_digest) == 64
    assert runtime.load_terminal_state(grant["run_id"]) == local


def test_terminal_detach_recovery_drains_the_signed_queue_without_run_scan(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)

    assert store.recover_terminal_detaches(runtime=runtime, now_ms=2_000) == 1
    state = runtime.load_terminal_state(grant["run_id"])
    assert state is not None and state.state == "local_terminal"
    assert store.recover_terminal_detaches(runtime=runtime, now_ms=2_000) == 0


def test_terminal_detach_journal_recovers_after_record_write_crash(tmp_path, monkeypatch):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(grant["run_id"]))
    ensure = store._ensure_json_exact

    def fail_detached_record(directory_fd, filename, value):
        if filename.startswith("detached-"):
            raise OSError("injected detached record crash")
        return ensure(directory_fd, filename, value)

    with monkeypatch.context() as fault:
        fault.setattr(store, "_ensure_json_exact", fail_detached_record)
        with pytest.raises(OSError, match="injected detached record crash"):
            store.detach_terminal(
                grant["run_id"], runtime=runtime,
                expected_local_state_digest=local.state_digest, now_ms=2_000,
            )

    restarted = type(store).for_runtime(store.root, identity=identity, signer=signer)
    assert restarted.detach_terminal(
        grant["run_id"], runtime=runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )


def test_runtime_prune_removes_a_detached_terminal_only_after_signed_store_prune(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(grant["run_id"]))
    store.detach_terminal(
        grant["run_id"], runtime=runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )
    pending = runtime.claim_due_prune(
        now_ms=store.load_run(grant["run_id"])["retention_expires_at_ms"],
    )[0]

    pruned = store.prune_runtime_terminal(
        grant["run_id"], runtime=runtime,
        expected_runtime_state_digest=pending.state_digest,
        now_ms=pending.retention_expires_at_ms,
    )

    runtime.finish_prune(
        grant["run_id"], expected_state_digest=pending.state_digest,
        pruned_record_digest=pruned, now_ms=pending.retention_expires_at_ms,
    )
    assert runtime.load_terminal_state(grant["run_id"]) is None


def test_store_derives_containment_summary_and_rejects_event_or_view_tampering(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    run_path = store.run_path(grant["run_id"])
    finals_path = run_path / "finals.json"
    original_finals = finals_path.read_bytes()
    finals = json.loads(original_finals)
    finals["local_view"]["containment_summary"]["event_count"] = 0
    finals["local_view"]["containment_summary"]["head_digest"] = "0" * 64
    core = {key: value for key, value in finals.items() if key != "finals_digest"}
    finals["finals_digest"] = canonical_digest(core)
    finals_path.write_text(json.dumps(finals, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunnerStoreError, match="containment summary"):
        store.load_final_projections(grant["run_id"])
    finals_path.write_bytes(original_finals)

    finals = json.loads(original_finals)
    operational = finals["operational_projection"]
    unsigned = {
        key: copy.deepcopy(value) for key, value in operational.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["counters"]["requests_started"] += 1
    unsigned["counters"]["remaining_requests"] -= 1
    altered_operational = {
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        "signing_key_id": signer.key_id,
        "signature_b64": __import__("base64").b64encode(
            signer.sign(canonical_bytes(unsigned)),
        ).decode("ascii"),
    }
    finals["operational_projection"] = altered_operational
    finals["local_view"]["operational_projection"] = altered_operational
    core = {key: value for key, value in finals.items() if key != "finals_digest"}
    finals["finals_digest"] = canonical_digest(core)
    finals_path.write_bytes(canonical_bytes(finals))
    with pytest.raises(RunnerStoreError, match="projection mismatch"):
        store.load_final_projections(grant["run_id"])
    finals_path.write_bytes(original_finals)

    event_path = run_path / "events" / "00000000000000000001.json"
    event = json.loads(event_path.read_text())
    event["signature_b64"] = __import__("base64").b64encode(b"x" * 64).decode()
    event_path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunnerStoreError, match="containment chain"):
        store.load_final_projections(grant["run_id"])


def test_final_projections_cannot_be_substituted_between_runs_on_one_runner(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant_a = signed_grant(manifest, projection, identity, authority)
    grant_b = copy.deepcopy(grant_a)
    grant_b.update({
        "grant_id": "grant_987654321",
        "run_id": "run_987654321",
        "grant_nonce": "nonce_987654321",
    })
    grant_b = resign_grant(grant_b, authority)
    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    for grant in (grant_a, grant_b):
        executor.execute(
            ExecutionBundle(manifest, projection, grant),
            transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
        )
    path_a = store.run_path(grant_a["run_id"]) / "finals.json"
    path_b = store.run_path(grant_b["run_id"]) / "finals.json"
    original_a = json.loads(path_a.read_text())
    substituted = json.loads(path_b.read_text())
    substituted["local_view"]["containment_summary"] = original_a[
        "local_view"
    ]["containment_summary"]
    core = {key: value for key, value in substituted.items() if key != "finals_digest"}
    substituted["finals_digest"] = canonical_digest(core)
    path_a.write_bytes(canonical_bytes(substituted))
    with pytest.raises(RunnerStoreError, match="projection mismatch"):
        store.load_final_projections(grant_a["run_id"])


@pytest.mark.parametrize("checkpoint", ["reserved", "between_actions", "finalizing"])
def test_recovery_finalizes_every_consumed_nonterminal_without_target_replay(tmp_path, checkpoint):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    log = ContainmentLog(
        store=store, signer=signer, run_id=grant["run_id"], grant_id=grant["grant_id"],
        manifest_digest=manifest["manifest_digest"], clock_ms=lambda: 2_000,
    )
    if checkpoint != "reserved":
        log.append("grant_verified", detail_code="grant_exact")
        store.transition_run(grant["run_id"], "running", now_ms=2_000)
        log.append("run_started", detail_code="all_preflight_valid")
    if checkpoint == "between_actions":
        binding = {
            "action_ordinal": 0, "scenario_id": "anonymous_authenticated_read",
            "semantic_role": "anonymous", "attempt": 1,
        }
        log.append("admitted", detail_code="exact_action", **binding)
        log.append("action_started", detail_code="target_read",
                   counters={"requests_started": 1, "actions_contained": 1}, **binding)
        log.append("action_completed", detail_code="bounded_response",
                   counters={"requests_started": 1, "requests_completed": 1,
                             "actions_contained": 1}, **binding)
    if checkpoint == "finalizing":
        store.transition_run(grant["run_id"], "finalizing", now_ms=2_000)
    transport = ScriptedTransport([200])
    recovered = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
        monotonic=lambda: 1.0,
    ).recover(grant["run_id"], transport=transport)
    assert transport.calls == []
    assert recovered.execution_disposition == "incomplete"
    assert recovered.assessment_outcome == "inconclusive"
    assert store.load_run(grant["run_id"])["state"] == "terminal"


def test_recovery_rejects_a_rolled_back_finalizing_state_after_terminal_authority(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    state_path = store.run_path(grant["run_id"]) / "state.json"
    state = json.loads(state_path.read_text())
    state["state"] = "finalizing"
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunnerStoreError, match="terminal queue is invalid"):
        LocalCanaryExecutor(
            store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key},
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
        ).recover(grant["run_id"])
    assert store.load_run(grant["run_id"])["state"] == "finalizing"


def test_recovery_never_reconstructs_a_missing_run_after_reserve_commits(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    run_path = store.run_path(grant["run_id"])
    shutil.rmtree(run_path)
    with pytest.raises(RunnerStoreError, match="local run reservation is unavailable"):
        LocalCanaryExecutor(
            store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key},
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
            monotonic=lambda: 1.0,
        ).recover(grant["run_id"], transport=ScriptedTransport([200]))


@pytest.mark.parametrize("visible_legacy_files", [1, 2, 3])
def test_recovery_rejects_partial_final_replacement_after_terminal_authority(tmp_path, visible_legacy_files):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    run_path = store.run_path(grant["run_id"])
    names = ("operational.json", "findings.json", "local-view.json", "disclosure-preview.json")
    committed = json.loads((run_path / "finals.json").read_text())
    values = dict(zip(names, (
        committed["operational_projection"], committed["findings_projection"],
        committed["local_view"], committed["disclosure_preview"],
    ), strict=True))
    (run_path / "finals.json").unlink()
    for name in names[:visible_legacy_files]:
        (run_path / name).write_bytes(canonical_bytes(values[name]))
    state_path = run_path / "state.json"
    state = json.loads(state_path.read_text())
    state["state"] = "finalizing"
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    transport = ScriptedTransport([200])
    with pytest.raises(RunnerStoreError, match="terminal queue is invalid"):
        LocalCanaryExecutor(
            store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key},
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
            monotonic=lambda: 1.0,
        ).recover(grant["run_id"], transport=transport)
    assert transport.calls == []
    assert not (run_path / "finals.json").exists()


class StaticVault:
    supported = True
    backend_id = "ephemeral_env"

    def load(self, handle_id):
        return b"canary-secret-token"


class ScriptedTransport:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = []

    def request(
        self, action, *, credential, cancellation, retry_policy, remaining_requests,
        before_attempt, evidence_context, evidence_sink, redactor,
    ):
        del retry_policy, remaining_requests, redactor
        before_attempt(1, None)
        self.calls.append((action, credential))
        status = self.statuses.pop(0)
        raw_body = b"" if action.method == "HEAD" else b"{}"
        reference = evidence_sink(BoundedResponseEvidence(
            action_ordinal=evidence_context.action_ordinal,
            scenario_id=action.scenario_id,
            semantic_auth_role=action.semantic_auth_role,
            method=action.method,
            route_template=evidence_context.route_template,
            attempt=1,
            status_code=status,
            raw_headers=b"Content-Type: application/json\r\nContent-Length: 2",
            raw_body=raw_body,
        ))
        return TargetResponse(
            status, "absent" if action.method == "HEAD" else "json_object",
            len(raw_body), 1, reference, 0,
        )


def test_executor_builds_frozen_private_and_cloud_projections_without_raw_values(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    transport = ScriptedTransport([401, 200, 200, 403])
    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    result = executor.execute(
        ExecutionBundle(manifest, projection, grant),
        transport=transport, gate_source=active_gate,
    )
    assert result.assessment_outcome == "blocked"
    assert result.execution_disposition == "completed"
    assert [item["assessment_outcome"] for item in result.findings_projection["scenario_results"]] == [
        "blocked", "blocked",
    ]
    validate_operational_run(result.operational_projection)
    validate_canary_findings(result.findings_projection)
    assert "assessment" not in canonical_bytes(result.operational_projection).decode()
    serialized = canonical_bytes(result.local_view).decode()
    for forbidden in ("canary-secret-token", "canary-a-item-0137", "credential_handle_id", "raw_response"):
        assert forbidden not in serialized
    assert [call[0].semantic_auth_role for call in transport.calls] == [
        "anonymous", "authenticated", "object_owner", "non_owner",
    ]
    refs = [
        ref
        for scenario in result.findings_projection["scenario_results"]
        for ref in scenario["local_evidence_refs"]
    ]
    assert len(refs) == 4 and all(ref.startswith("ev1_") for ref in refs)
    assert store.load_response_evidence(grant["run_id"], refs[0], now_ms=2_000)[1] in {
        b"", b"{}",
    }


def test_executor_persists_raw_attempt_evidence_but_projects_only_refs_and_counts(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class SecretEvidenceTransport(ScriptedTransport):
        def request(
            self, action, *, credential, cancellation, retry_policy, remaining_requests,
            before_attempt, evidence_context, evidence_sink, redactor,
        ):
            del credential, cancellation, retry_policy, remaining_requests
            before_attempt(1, None)
            raw_headers = b"Authorization: Bearer canary-secret-token"
            raw_body = b'{"token":"canary-secret-token"}'
            assert redactor.count_bytes(raw_headers, raw_body) >= 2
            reference = evidence_sink(BoundedResponseEvidence(
                action_ordinal=evidence_context.action_ordinal,
                scenario_id=action.scenario_id,
                semantic_auth_role=action.semantic_auth_role,
                method=action.method,
                route_template=evidence_context.route_template,
                attempt=1, status_code=200, raw_headers=raw_headers, raw_body=raw_body,
            ))
            self.calls.append((action, None))
            return TargetResponse(200, "json_object", len(raw_body), 1, reference, 2)

    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    result = executor.execute(
        ExecutionBundle(manifest, projection, grant),
        transport=SecretEvidenceTransport([200] * 4), gate_source=active_gate,
    )
    assert result.operational_projection["redaction_count"] == 8
    assert result.findings_projection["redaction_count"] == 8
    assert result.local_view["containment_summary"]["redaction_count"] == 8
    assert "redacted" in result.operational_projection["containment_codes"]
    reference = result.findings_projection["scenario_results"][0]["local_evidence_refs"][0]
    assert store.load_response_evidence(grant["run_id"], reference, now_ms=2_000) == (
        b"Authorization: Bearer canary-secret-token",
        b'{"token":"canary-secret-token"}',
    )
    safe = canonical_bytes(result.local_view)
    assert b"canary-secret-token" not in safe
    assert raw_headers_not_present(safe)


def raw_headers_not_present(value):
    return b"Authorization" not in value and b"raw_headers" not in value


def test_every_actual_attempt_rechecks_live_gate_before_retry_and_reserves_once(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    current_gate = [active_gate()]
    gate_calls = []

    def live_gate():
        gate_calls.append(current_gate[0])
        return current_gate[0]

    class RetryAfterRevocation:
        def request(self, action, *, before_attempt, **kwargs):
            del action, kwargs
            before_attempt(1, None)
            current_gate[0] = ExecutionGate(
                True, "active", "revoked", 20_000, 7, "none", 2_001,
            )
            before_attempt(2, "connect_error")
            raise AssertionError("revoked retry was admitted")

    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=RetryAfterRevocation(), gate_source=live_gate,
    )
    assert len(gate_calls) >= 4
    assert result.execution_disposition == "stopped"
    assert result.operational_projection["stop_reason"] == "target_revoked"
    assert result.operational_projection["counters"]["requests_started"] == 1
    assert result.operational_projection["counters"]["retries_used"] == 0


def test_executor_passes_the_exact_signed_zero_retry_policy(tmp_path, monkeypatch):
    from heel.runner import compiler as compiler_module

    monkeypatch.setitem(compiler_module.RETRY_POLICY, "maximum_retries", 0)
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class ZeroRetryTransport(ScriptedTransport):
        def request(self, action, *, retry_policy, **kwargs):
            assert retry_policy.maximum_retries == 0
            assert retry_policy.retryable_failure_codes == ("connect_error", "timeout")
            return super().request(
                action, retry_policy=retry_policy, **kwargs,
            )

    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ZeroRetryTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    assert result.execution_disposition == "completed"
    assert result.operational_projection["counters"]["retries_used"] == 0


def test_fixed_server_time_cannot_renew_live_authority_past_half_second(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    clock = Clock()

    gate_calls = [0]

    def gate_that_stalls_before_returning():
        gate_calls[0] += 1
        if gate_calls[0] == 3:
            clock.value = 0.501
        return active_gate()

    result = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=clock,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([200] * 4), gate_source=gate_that_stalls_before_returning,
    )
    assert result.execution_disposition == "incomplete"
    assert result.operational_projection["error_category"] == "cloud_disconnected"
    assert result.operational_projection["counters"]["requests_started"] == 0


@pytest.mark.parametrize(
    "failure_code,expected_disposition,expected_error",
    [
        ("dns_changed", "incomplete", "dns_changed"),
        ("connect_error", "incomplete", "target_unavailable"),
        ("response_rejected", "failed", "containment_rejected"),
    ],
)
def test_systemic_transport_failures_force_inconclusive_and_closed_cloud_disposition(
    tmp_path, failure_code, expected_disposition, expected_error,
):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class FailingTransport:
        def request(self, action, *, before_attempt, **kwargs):
            del action, kwargs
            before_attempt(1, None)
            raise TransportFailure(failure_code, requests_made=1)

    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    result = executor.execute(
        ExecutionBundle(manifest, projection, grant),
        transport=FailingTransport(), gate_source=active_gate,
    )
    assert result.assessment_outcome == "inconclusive"
    assert result.execution_disposition == expected_disposition
    assert result.operational_projection["error_category"] == expected_error
    assert all(
        item["assessment_outcome"] == "inconclusive"
        for item in result.findings_projection["scenario_results"]
    )


def test_run_aggregate_is_observed_if_any_complete_scenario_is_observed(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    result = executor.execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([200, 200, 200, 403]), gate_source=active_gate,
    )
    assert result.assessment_outcome == "observed"
    assert result.execution_disposition == "completed"
    assert [item["assessment_outcome"] for item in result.findings_projection["scenario_results"]] == [
        "observed", "blocked",
    ]


def test_crash_after_action_started_never_retries_target(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    log = ContainmentLog(
        store=store, signer=signer, run_id=grant["run_id"], grant_id=grant["grant_id"],
        manifest_digest=manifest["manifest_digest"], clock_ms=lambda: 2_000,
    )
    log.append("grant_verified", detail_code="grant_exact")
    log.append(
        "action_started", action_ordinal=0, scenario_id="anonymous_authenticated_read",
        semantic_role="anonymous", attempt=1, detail_code="admitted",
        counters={"requests_started": 1},
    )
    transport = ScriptedTransport([200])
    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    recovered = executor.recover(grant["run_id"], transport=transport)
    assert recovered.execution_disposition == "incomplete"
    assert recovered.assessment_outcome == "inconclusive"
    assert transport.calls == []


class BlockingExecutor:
    def __init__(self):
        self.started = threading.Event()
        self.cancelled = threading.Event()

    def execute(self, lease, *, cancellation, on_progress):
        self.started.set()
        while not cancellation.cancelled:
            time.sleep(0.005)
        self.cancelled.set()
        return {"operational_projection": lease.operational_projection}


class StopCoordinator:
    def __init__(self, lease):
        self.lease = lease
        self.claimed = False
        self.heartbeats = []
        self.acks = []
        self.ack_deadlines = []
        self.ack_projections = []

    def claim(self):
        if self.claimed:
            return None
        self.claimed = True
        return self.lease

    def heartbeat(self, run_id, operational_projection):
        self.heartbeats.append(time.monotonic())
        return ExecutionGate(True, "active", "valid", 20_000, 7, "cloud_stop", 2_000)

    def progress(self, run_id, operational_projection):
        return None

    def result(self, run_id, operational_projection):
        return None

    def stop_ack(self, run_id, operational_projection, *, deadline):
        self.acks.append(time.monotonic())
        self.ack_deadlines.append(deadline)
        self.ack_projections.append(operational_projection)


def test_supervisor_treats_a_closed_progress_stop_response_as_control():
    progress_returned = threading.Event()
    projection = {"run_id": "run_123456789", "lifecycle_phase": "running"}
    lease = ClaimLease("run_123456789", object(), projection)

    class ProgressStopCoordinator(StopCoordinator):
        def heartbeat(self, run_id, operational_projection):
            assert progress_returned.wait(1)
            return ExecutionGate(True, "active", "valid", 20_000, 7, "none", 2_000)

        def progress(self, run_id, operational_projection):
            progress_returned.set()
            return {"status": "stop_requested", "stop_reason": "cloud_stop"}

    class ProgressStopExecutor:
        def execute(self, lease, *, cancellation, on_progress):
            on_progress(lease.operational_projection)
            assert cancellation.cancelled
            assert cancellation.stop_ack_event.wait(1)
            return {"operational_projection": lease.operational_projection}

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            assert stop_reason == "cloud_stop"
            return projection

    coordinator = ProgressStopCoordinator(lease)
    assert RunnerService(
        coordinator=coordinator, executor=ProgressStopExecutor(),
        heartbeat_interval=0.05, idle_poll_interval=2.0,
    ).run_once() is True
    assert len(coordinator.acks) == 1


def test_supervisor_heartbeat_cancels_blocked_target_and_acks_within_five_seconds():
    projection = {"run_id": "run_123456789", "lifecycle_phase": "running"}
    lease = ClaimLease("run_123456789", object(), projection)
    coordinator = StopCoordinator(lease)
    executor = BlockingExecutor()
    service = RunnerService(
        coordinator=coordinator, executor=executor, heartbeat_interval=0.05,
        idle_poll_interval=2.0,
    )
    started = time.monotonic()
    service.run_once()
    elapsed = time.monotonic() - started
    assert executor.started.is_set() and executor.cancelled.is_set()
    assert coordinator.acks and coordinator.acks[0] - coordinator.heartbeats[0] < 5
    assert coordinator.ack_deadlines[0] - coordinator.heartbeats[0] <= 5
    assert elapsed < 1


def test_stop_ack_is_issued_once_before_executor_unwinds_and_uses_absolute_deadline():
    ack_called = threading.Event()
    executor_returned = threading.Event()

    class SlowUnwindExecutor(BlockingExecutor):
        def execute(self, lease, *, cancellation, on_progress):
            self.started.set()
            while not cancellation.cancelled:
                time.sleep(0.005)
            assert ack_called.wait(1)
            executor_returned.set()
            return {"operational_projection": lease.operational_projection}

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            return {**projection, "stop_reason": stop_reason, "proposed_at_ms": proposed_at_ms}

    class ImmediateStop(StopCoordinator):
        def stop_ack(self, run_id, operational_projection, *, deadline):
            assert not executor_returned.is_set()
            assert deadline > time.monotonic()
            super().stop_ack(run_id, operational_projection, deadline=deadline)
            ack_called.set()

    lease = ClaimLease("run_123456789", object(), {
        "run_id": "run_123456789", "lifecycle_phase": "running",
    })
    coordinator = ImmediateStop(lease)
    executor = SlowUnwindExecutor()
    RunnerService(
        coordinator=coordinator, executor=executor, heartbeat_interval=0.05,
        idle_poll_interval=2.0,
    ).run_once()
    assert len(coordinator.acks) == 1
    assert executor_returned.is_set()


def test_failed_stop_ack_never_records_a_local_acknowledgement_timestamp():
    observed = []

    class WaitingExecutor(BlockingExecutor):
        def execute(self, lease, *, cancellation, on_progress):
            del on_progress
            while not cancellation.cancelled:
                time.sleep(0.005)
            assert cancellation.stop_ack_event.wait(1)
            observed.append(getattr(cancellation, "stop_acknowledged_at_ms", None))
            return {"operational_projection": lease.operational_projection}

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            del lease, stop_reason, proposed_at_ms
            return projection

    class FailedAck(StopCoordinator):
        def stop_ack(self, run_id, operational_projection, *, deadline):
            super().stop_ack(run_id, operational_projection, deadline=deadline)
            raise TimeoutError("control plane unavailable")

    lease = ClaimLease("run_123456789", object(), {
        "run_id": "run_123456789", "lifecycle_phase": "running",
    })
    coordinator = FailedAck(lease)
    RunnerService(
        coordinator=coordinator, executor=WaitingExecutor(), heartbeat_interval=0.05,
        idle_poll_interval=2.0,
    ).run_once()
    assert len(coordinator.acks) == 1
    assert observed == [None]


def test_stop_ack_is_not_started_when_projection_preparation_exhausts_deadline():
    now = [0.0]

    class DeadlineExecutor(BlockingExecutor):
        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            del lease, stop_reason, proposed_at_ms
            now[0] = 5.0
            return projection

    lease = ClaimLease("run_123456789", object(), {
        "run_id": "run_123456789", "lifecycle_phase": "running",
    })
    coordinator = StopCoordinator(lease)
    executor = DeadlineExecutor()
    service = RunnerService(
        coordinator=coordinator, executor=executor, heartbeat_interval=0.05,
        idle_poll_interval=2.0, monotonic=lambda: now[0],
    )
    worker = threading.Thread(target=service.run_once)
    worker.start()
    assert executor.started.wait(1)
    assert service.request_local_stop() is True
    worker.join(2)
    assert not worker.is_alive()
    assert coordinator.acks == []


def test_local_and_cloud_stop_race_uses_one_async_ack_and_suppresses_result():
    cloud_stop = threading.Event()

    class RaceCoordinator(StopCoordinator):
        def __init__(self, lease):
            super().__init__(lease)
            self.results = 0

        def heartbeat(self, run_id, operational_projection):
            self.heartbeats.append(time.monotonic())
            reason = "cloud_stop" if cloud_stop.is_set() else "none"
            return ExecutionGate(True, "active", "valid", 20_000, 7, reason, 2_000)

        def result(self, run_id, operational_projection):
            self.results += 1

    lease = ClaimLease("run_123456789", object(), {
        "run_id": "run_123456789", "lifecycle_phase": "running",
    })
    coordinator = RaceCoordinator(lease)
    executor = BlockingExecutor()
    service = RunnerService(
        coordinator=coordinator, executor=executor, heartbeat_interval=0.01,
        idle_poll_interval=2.0,
    )
    worker = threading.Thread(target=service.run_once)
    worker.start()
    assert executor.started.wait(1)
    began = time.monotonic()
    assert service.request_local_stop() is True
    assert time.monotonic() - began < 0.1
    cloud_stop.set()
    worker.join(2)
    assert not worker.is_alive()
    assert len(coordinator.acks) == 1
    assert coordinator.results == 0


def test_real_executor_stop_interrupts_blocked_transport_and_never_starts_next_action(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class BlockingTransport:
        def __init__(self):
            self.started = threading.Event()
            self.calls = []

        def request(self, action, *, cancellation, before_attempt, **kwargs):
            del kwargs
            before_attempt(1, None)
            self.calls.append(action)
            self.started.set()
            assert cancellation is not None
            while not cancellation.cancelled:
                time.sleep(0.005)
            raise TransportFailure("cancelled", requests_made=1)

    transport = BlockingTransport()
    local = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=time.monotonic,
    )

    class Adapter:
        def execute(self, lease, *, cancellation, on_progress):
            return local.execute(
                lease.bundle, transport=transport, gate_source=active_gate,
                cancellation=cancellation, on_progress=on_progress,
            )

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            return local.prepare_stop_ack(
                lease.run_id, stop_reason=stop_reason, proposed_at_ms=proposed_at_ms,
            )

    class CoordinatorAfterStart(StopCoordinator):
        def __init__(self, lease):
            super().__init__(lease)
            self.heartbeat_projections = []

        def heartbeat(self, run_id, operational_projection):
            self.heartbeats.append(time.monotonic())
            self.heartbeat_projections.append(operational_projection)
            reason = "cloud_stop" if transport.started.is_set() else "none"
            return ExecutionGate(True, "active", "valid", 20_000, 7, reason, 2_000)

    lease = ClaimLease(grant["run_id"], ExecutionBundle(manifest, projection, grant), {
        "run_id": grant["run_id"], "lifecycle_phase": "claimed",
    })
    coordinator = CoordinatorAfterStart(lease)
    service = RunnerService(
        coordinator=coordinator, executor=Adapter(), heartbeat_interval=0.05,
        idle_poll_interval=2.0,
    )
    service.run_once()
    assert len(transport.calls) == 1
    assert coordinator.acks
    assert coordinator.ack_projections[0]["timestamps"]["stop_acknowledged_at_ms"] is None
    assert coordinator.ack_projections[0]["event_sequence"] > max(
        item.get("event_sequence", -1)
        for item in coordinator.heartbeat_projections
        if item.get("stop_reason", "none") == "none"
    )
    assert "stop_observed" in coordinator.ack_projections[0]["containment_codes"]
    final = store.load_final_projections(grant["run_id"])
    assert final["operational_projection"]["execution_disposition"] == "stopped"
    assert final["operational_projection"]["timestamps"]["stop_acknowledged_at_ms"] is not None
    assert final["findings_projection"]["assessment_outcome"] == "inconclusive"


def test_prepare_stop_ack_snapshots_budget_counters_under_the_execution_lock(tmp_path):
    from heel.saas.canary_runs import CanaryRunService

    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    local = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    )
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    store.transition_run(grant["run_id"], "running", now_ms=2_000)
    log = ContainmentLog(
        store=store, signer=signer, run_id=grant["run_id"],
        grant_id=grant["grant_id"], manifest_digest=manifest["manifest_digest"],
        clock_ms=lambda: 2_000,
    )
    log.append("grant_verified", detail_code="grant_exact")
    log.append("run_started", detail_code="all_preflight_valid")
    counters = {
        "requests_started": 1, "requests_completed": 0,
        "response_bytes_read": 0, "actions_contained": 1, "retries_used": 0,
    }
    budget_lock = threading.Lock()
    local._set_active_context({
        "manifest": manifest, "projection": projection, "grant": grant,
        "started_at": 2_000, "started_monotonic": 1.0,
        "counters": counters, "budget_lock": budget_lock,
        "redaction_state": {"count": 0}, "log": log,
    })
    result: list[dict] = []
    finished = threading.Event()

    budget_lock.acquire()
    counters["actions_contained"] = 0
    worker = threading.Thread(target=lambda: (
        result.append(local.prepare_stop_ack(
            grant["run_id"], stop_reason="cloud_stop", proposed_at_ms=2_000,
        )),
        finished.set(),
    ))
    worker.start()
    completed_mid_update = finished.wait(0.1)
    counters["actions_contained"] = 1
    budget_lock.release()
    worker.join(1)

    assert completed_mid_update is False
    assert not worker.is_alive() and len(result) == 1
    acknowledgement = result[0]
    assert acknowledgement["counters"]["requests_started"] == 1
    assert acknowledgement["counters"]["actions_contained"] == 1
    assert CanaryRunService._operational_within_budget(
        acknowledgement, projection, grant,
    ) is True


@pytest.mark.parametrize(
    "stop_after_completed,overtake_progress,expected_sequences",
    [
        (1, False, (4, 5, 6)),
        (4, True, (13, 14, 15)),
    ],
)
def test_runner_service_real_executor_sparse_sequences_survive_cloud_stop_progress_race(
    tmp_path, stop_after_completed, overtake_progress, expected_sequences,
):
    import base64

    from canary_test_support import Clock, NOW, NOW_MS, connect
    from heel.runner.coordinator import RunnerCoordinator, RunnerStopAcknowledgement
    from heel.saas.canary_runs import CanaryRunService
    from heel.saas.catalog import CATALOG_VERSION
    from heel.saas.runner_auth import RunnerAuthStore

    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    conn = connect()
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        (manifest["workspace_id"], "org_canary", "Executor", "free", CATALOG_VERSION, NOW),
    )
    conn.execute(
        "INSERT INTO memberships VALUES(?,?,?,?)",
        (manifest["workspace_id"], "user_owner", "owner", NOW),
    )
    conn.execute(
        "INSERT INTO projects VALUES(?,?,?,?,?)",
        (manifest["workspace_id"], manifest["project_id"], "Executor", "user_owner", NOW),
    )
    environment = manifest["environment"]
    conn.execute(
        "INSERT INTO canary_environments("
        "environment_id,workspace_id,project_ref,origin,environment_class,status,created_at,"
        "attestation_text,attestation_version,attestation_acknowledgement,attested_by,attested_at,"
        "proof_method,proof_version,normalization_version,challenge_generation,last_check_at,"
        "verified_at,proof_expires_at,verification_record_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            environment["environment_id"], manifest["workspace_id"], manifest["project_id"],
            environment["origin"], environment["environment_class"], "verified", NOW,
            "ownership verified; environment classification supplied by you", "v1", "accepted",
            "user_owner", NOW, "https-file", "https-file.v1", "exact-origin.v1", 1,
            NOW, NOW, NOW + 3600, environment["verification_record_digest"],
        ),
    )
    public_key = base64.b64encode(signer.public_key).decode("ascii")
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        (identity.runner_id, manifest["workspace_id"], "Executor", "active", NOW),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
        (identity.key_id, manifest["workspace_id"], identity.runner_id, public_key, "active", NOW),
    )
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"s" * 32, now=clock)
    identity_record = auth._identity_record(
        workspace_id=manifest["workspace_id"], runner_id=identity.runner_id,
        public_key=public_key, fingerprint=identity.fingerprint, key_id=identity.key_id,
        runner_version=identity.runner_version,
        adapters_json=json.dumps(identity.adapter_versions), paired_by="user_owner",
        paired_at=NOW, heartbeat_at=NOW,
    )
    auth._save_identity(identity_record, instant=NOW)
    conn.commit()

    cloud = SigningAuthority.generate()
    coordinator = CanaryRunService(
        conn, signing=cloud, runner_auth=auth, clock=clock,
    )
    submitted = coordinator.submit_projection(projection, uploaded_by="user_owner")
    approved = coordinator.approve(
        manifest["workspace_id"], manifest["project_id"], submitted["run_id"],
        projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
        reason="Exercise real sparse containment sequence coordination",
        exact_hostname=manifest["egress"]["hostname"], recent_auth_at_ms=NOW_MS,
        idempotency_key="ca1-" + "d" * 64, expected_kill_switch_generation=0,
    )
    grant = approved["grant"]
    coordinator.claim(
        manifest["workspace_id"], identity.runner_id, identity.key_id,
    )

    claim_builder = object.__new__(RunnerCoordinator)
    claim_builder.identity = identity
    claim_builder.signer = signer
    claimed_projection = claim_builder._claimed_projection(
        manifest, projection, grant, claimed_at_ms=NOW_MS + 100,
    )

    executor = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={cloud.key_id: cloud.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: NOW_MS + 100,
        monotonic=time.monotonic,
    )
    heartbeat_released = threading.Event()
    acknowledgement_committed = threading.Event()
    observed_progress: list[dict] = []
    observed_acknowledgements: list[dict] = []
    observed_results: list[dict] = []
    overtaken_receipts: list[tuple] = []
    heartbeat_failures: list[object] = []
    cloud_request_lock = threading.Lock()

    class CloudBridge:
        claimed_once = False
        stop_started_at = None

        def claim(self):
            if self.claimed_once:
                return None
            self.claimed_once = True
            return ClaimLease(
                grant["run_id"], ExecutionBundle(manifest, projection, grant),
                claimed_projection,
            )

        def progress(self, run_id, value):
            assert run_id == grant["run_id"]
            observed_progress.append(value)
            if value["counters"]["requests_completed"] != stop_after_completed:
                with cloud_request_lock:
                    return coordinator.progress(
                        manifest["workspace_id"], manifest["project_id"], run_id,
                        identity.runner_id, value,
                    )
            # Freeze the Cloud stop after the runner produced progress but before that
            # synchronous progress call commits, which is the real supervisor race.
            self.stop_started_at = time.monotonic()
            with cloud_request_lock:
                coordinator.request_stop(
                    manifest["workspace_id"], manifest["project_id"], run_id,
                    actor="user_owner", reason="cloud_stop",
                    expected_kill_switch_generation=0,
                )
            if overtake_progress:
                # The independent heartbeat/ack chain commits a newer containment position
                # while this already-produced progress snapshot is still in flight.
                heartbeat_released.set()
                assert acknowledgement_committed.wait(1)
                with cloud_request_lock:
                    status = coordinator.progress(
                        manifest["workspace_id"], manifest["project_id"], run_id,
                        identity.runner_id, value,
                    )
                run_state = conn.execute(
                    "SELECT source_event_sequence,source_projection_digest FROM canary_runs "
                    "WHERE run_id=?", (run_id,),
                ).fetchone()
                receipt = conn.execute(
                    "SELECT source_event_sequence,receipt_digest,receipt_json "
                    "FROM canary_operational_receipts WHERE run_id=?", (run_id,),
                ).fetchone()
                overtaken_receipts.append((
                    *tuple(run_state), receipt[0], receipt[1],
                    json.loads(receipt[2])["counters"],
                ))
            else:
                with cloud_request_lock:
                    status = coordinator.progress(
                        manifest["workspace_id"], manifest["project_id"], run_id,
                        identity.runner_id, value,
                    )
                heartbeat_released.set()
                assert acknowledgement_committed.wait(1)
            return status

        def heartbeat(self, run_id, value):
            assert heartbeat_released.wait(1)
            try:
                with cloud_request_lock:
                    gate = coordinator.heartbeat(
                        manifest["workspace_id"], manifest["project_id"], run_id,
                        identity.runner_id, value,
                    )
            except BaseException as exc:
                stored = conn.execute(
                    "SELECT source_event_sequence,source_projection_digest,status,stop_reason "
                    "FROM canary_runs WHERE run_id=?", (run_id,),
                ).fetchone()
                heartbeat_failures.append((
                    exc, value.get("event_sequence"), value.get("projection_digest"),
                    value.get("lifecycle_phase"), value.get("stop_reason"), tuple(stored),
                ))
                raise
            return ExecutionGate(**gate)

        def stop_ack(self, run_id, value, *, deadline):
            assert time.monotonic() < deadline
            unsigned = {
                key: copy.deepcopy(item) for key, item in value.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            acknowledged_at = max(
                NOW_MS + 200,
                unsigned["timestamps"]["updated_at_ms"],
                unsigned["timestamps"]["stop_requested_at_ms"],
            )
            unsigned["timestamps"] = {
                **unsigned["timestamps"],
                "updated_at_ms": acknowledged_at,
                "stop_acknowledged_at_ms": acknowledged_at,
            }
            acknowledgement = {
                **unsigned,
                "projection_digest": canonical_digest(unsigned),
                "signing_key_id": signer.key_id,
                "signature_b64": base64.b64encode(
                    signer.sign(canonical_bytes(unsigned)),
                ).decode("ascii"),
            }
            observed_acknowledgements.append(acknowledgement)
            with cloud_request_lock:
                response = coordinator.ack_stop(
                    manifest["workspace_id"], manifest["project_id"], run_id,
                    identity.runner_id, acknowledgement,
                )
            acknowledgement_committed.set()
            return RunnerStopAcknowledgement(
                **response, acknowledged_at_ms=acknowledged_at,
            )

        def result(self, run_id, value):
            observed_results.append(value)
            with cloud_request_lock:
                return coordinator.result(
                    manifest["workspace_id"], manifest["project_id"], run_id,
                    identity.runner_id, value,
                )

    class ExecutorAdapter:
        def execute(self, lease, *, cancellation, on_progress):
            return executor.execute(
                lease.bundle, transport=ScriptedTransport([401, 200, 200, 403]),
                gate_source=lambda: ExecutionGate(
                    True, "active", "valid", NOW_MS + 60_000, 0, "none", NOW_MS,
                ),
                cancellation=cancellation, on_progress=on_progress,
            )

        def prepare_stop_ack(self, lease, value, stop_reason, proposed_at_ms):
            del value
            return executor.prepare_stop_ack(
                lease.run_id, stop_reason=stop_reason, proposed_at_ms=proposed_at_ms,
            )

    def service_monotonic():
        # Hold the first heartbeat before it snapshots so this probe deterministically
        # reproduces the synchronous progress-commit race reported by the real supervisor.
        if (
            threading.current_thread().name == "heel-runner-heartbeat"
            and not heartbeat_released.is_set()
        ):
            assert heartbeat_released.wait(1)
        return time.monotonic()

    bridge = CloudBridge()
    assert RunnerService(
        coordinator=bridge, executor=ExecutorAdapter(), heartbeat_interval=0.01,
        idle_poll_interval=2.0, clock_ms=lambda: NOW_MS + 200,
        monotonic=service_monotonic,
    ).run_once() is True

    stopped_progress = next(
        value for value in observed_progress
        if value["counters"]["requests_completed"] == stop_after_completed
    )
    assert (
        stopped_progress["event_sequence"],
        observed_acknowledgements[0]["event_sequence"],
        observed_results[0]["event_sequence"],
    ) == expected_sequences
    if overtake_progress:
        acknowledgement = observed_acknowledgements[0]
        assert overtaken_receipts == [(
            acknowledgement["event_sequence"], acknowledgement["projection_digest"],
            acknowledgement["event_sequence"], acknowledgement["projection_digest"],
            acknowledgement["counters"],
        )]
    assert time.monotonic() - bridge.stop_started_at < 5
    status = coordinator.get_status(
        manifest["workspace_id"], manifest["project_id"], grant["run_id"],
    )
    assert status["status"] == "terminal"
    assert status["execution_disposition"] == "stopped"
    assert status["error_category"] == "none", heartbeat_failures


def test_real_executor_local_emergency_stop_transitions_and_allocates_ack_sequence(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class BlockingTransport:
        def __init__(self):
            self.started = threading.Event()

        def request(self, action, *, cancellation, before_attempt, **kwargs):
            del action, kwargs
            before_attempt(1, None)
            self.started.set()
            while not cancellation.cancelled:
                time.sleep(0.005)
            raise TransportFailure("cancelled", requests_made=1)

    transport = BlockingTransport()
    local = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=time.monotonic,
    )

    class Adapter:
        def execute(self, lease, *, cancellation, on_progress):
            return local.execute(
                lease.bundle, transport=transport, gate_source=active_gate,
                cancellation=cancellation, on_progress=on_progress,
            )

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            return local.prepare_stop_ack(
                lease.run_id, stop_reason=stop_reason, proposed_at_ms=proposed_at_ms,
            )

    lease = ClaimLease(
        grant["run_id"], ExecutionBundle(manifest, projection, grant),
        {"run_id": grant["run_id"], "lifecycle_phase": "claimed", "event_sequence": 0},
    )
    class LocalCoordinator(StopCoordinator):
        def heartbeat(self, run_id, operational_projection):
            self.heartbeats.append(time.monotonic())
            return ExecutionGate(True, "active", "valid", 20_000, 7, "none", 2_000)

    coordinator = LocalCoordinator(lease)
    service = RunnerService(
        coordinator=coordinator, executor=Adapter(), heartbeat_interval=0.05,
        idle_poll_interval=2.0,
    )
    worker = threading.Thread(target=service.run_once)
    worker.start()
    assert transport.started.wait(1)
    assert service.request_local_stop() is True
    worker.join(2)
    assert not worker.is_alive()
    assert len(coordinator.ack_projections) == 1
    acknowledgement = coordinator.ack_projections[0]
    assert acknowledgement["stop_reason"] == "local_emergency_stop"
    assert acknowledgement["event_sequence"] > lease.operational_projection["event_sequence"]
    assert "stop_observed" in acknowledgement["containment_codes"]
    assert store.load_run(grant["run_id"])["state"] == "terminal"
