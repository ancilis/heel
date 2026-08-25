from __future__ import annotations

import copy
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
from heel.runner.http_transport import TargetResponse, TransportFailure
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
    second = log.append(
        "action_started", action_ordinal=0, scenario_id="anonymous_authenticated_read",
        semantic_role="anonymous", attempt=1, detail_code="admitted",
        counters={"requests_started": 1},
    )
    assert first["sequence"] == 0 and first["previous_event_digest"] == "0" * 64
    assert second["sequence"] == 1
    assert second["previous_event_digest"] == first["event_digest"]
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
    store.reserve_run(grant, retention_expires_at_ms=50_000)
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
    with pytest.raises(RunnerStoreError, match="transition"):
        store.transition_run(grant["run_id"], "terminal", now_ms=3_000)
    store.transition_run(grant["run_id"], "finalizing", now_ms=3_000)
    store.transition_run(grant["run_id"], "terminal", now_ms=4_000)
    assert store.prune_expired_runs(now_ms=49_999) == 0
    assert store.prune_expired_runs(now_ms=50_000) == 1
    assert not store.run_path(grant["run_id"]).exists()


class StaticVault:
    supported = True
    backend_id = "ephemeral_env"

    def load(self, handle_id):
        return b"canary-secret-token"


class ScriptedTransport:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = []

    def request(self, action, *, credential=None, cancellation=None):
        self.calls.append((action, credential))
        status = self.statuses.pop(0)
        return TargetResponse(status, "absent" if action.method == "HEAD" else "json_object", 2, 1)


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
        def request(self, action, *, credential=None, cancellation=None):
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

    def stop_ack(self, run_id, operational_projection):
        self.acks.append(time.monotonic())


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
    assert elapsed < 1


def test_real_executor_stop_interrupts_blocked_transport_and_never_starts_next_action(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)

    class BlockingTransport:
        def __init__(self):
            self.started = threading.Event()
            self.calls = []

        def request(self, action, *, credential=None, cancellation=None):
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
    final = store.load_final_projections(grant["run_id"])
    assert final["operational_projection"]["execution_disposition"] == "stopped"
    assert final["findings_projection"]["assessment_outcome"] == "inconclusive"
