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
        "run_id": "run_123456789",
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
    store.reserve_run(validated.grant, retention_expires_at_ms=86_400_000)
    with pytest.raises(ValueError, match="already consumed"):
        store.reserve_run(validated.grant, retention_expires_at_ms=86_400_000)

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
    with pytest.raises(RunnerStoreError, match="transition"):
        store.transition_run(grant["run_id"], "terminal", now_ms=3_000)
    store.transition_run(grant["run_id"], "finalizing", now_ms=3_000)
    store.transition_run(grant["run_id"], "terminal", now_ms=4_000)
    assert store.prune_expired_runs(now_ms=49_999) == 0
    assert store.prune_expired_runs(now_ms=50_000) == 1
    assert not store.run_path(grant["run_id"]).exists()


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


def test_recovery_verifies_existing_finals_then_marks_finalizing_run_terminal(tmp_path):
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
    state_path = store.run_path(grant["run_id"]) / "state.json"
    state = json.loads(state_path.read_text())
    state["state"] = "finalizing"
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    recovered = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
    ).recover(grant["run_id"])
    assert recovered.local_view == result.local_view
    assert store.load_run(grant["run_id"])["state"] == "terminal"


def test_recovery_reconstructs_run_after_consumption_marker_before_state(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    run_path = store.run_path(grant["run_id"])
    shutil.rmtree(run_path)
    recovered = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
        monotonic=lambda: 1.0,
    ).recover(grant["run_id"], transport=ScriptedTransport([200]))
    assert recovered.execution_disposition == "incomplete"
    assert store.load_run(grant["run_id"])["state"] == "terminal"
    assert store.load_run_grant(grant["run_id"]) == grant


@pytest.mark.parametrize("visible_legacy_files", [1, 2, 3])
def test_recovery_never_observes_partial_legacy_final_writes(tmp_path, visible_legacy_files):
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
    recovered = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 3_000,
        monotonic=lambda: 1.0,
    ).recover(grant["run_id"], transport=transport)
    assert transport.calls == []
    assert recovered.execution_disposition == "incomplete"
    assert (run_path / "finals.json").is_file()


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
        def heartbeat(self, run_id, operational_projection):
            self.heartbeats.append(time.monotonic())
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
    final = store.load_final_projections(grant["run_id"])
    assert final["operational_projection"]["execution_disposition"] == "stopped"
    assert final["operational_projection"]["timestamps"]["stop_acknowledged_at_ms"] is not None
    assert final["findings_projection"]["assessment_outcome"] == "inconclusive"
