"""Bounded, deterministic execution of an exact customer-local canary grant."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import copy
from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any

from heel.canary_contracts import (
    CANARY_FINDINGS_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_canary_findings,
    validate_execution_grant,
    validate_operational_run,
    validate_test_manifest,
)
from heel.crypto import verify_envelope
from heel.runner.adapters import evaluate_pair, prepare_action
from heel.runner.companion import validate_disclosure_preview, validate_local_result_view
from heel.runner.containment import ContainmentLog, operational_containment_codes
from heel.runner.http_transport import CancellationToken, TransportFailure
from heel.runner.identity import RunnerIdentity, SecureSigner
from heel.runner.store import RunnerStore, RunnerStoreError
from heel.runner.vault import EphemeralVault, VaultUnavailable, validate_credential_secret


@dataclass(frozen=True, slots=True)
class ExecutionGate:
    active: bool
    runner_state: str
    proof_state: str
    proof_expires_at_ms: int
    kill_switch_generation: int
    stop_reason: str
    server_time_ms: int

    def __post_init__(self) -> None:
        if type(self.active) is not bool:
            raise ValueError("execution gate active flag must be boolean")
        if self.runner_state not in {"active", "revoked", "replaced"}:
            raise ValueError("invalid execution gate runner state")
        if self.proof_state not in {"valid", "expired", "revoked"}:
            raise ValueError("invalid execution gate proof state")
        if self.stop_reason not in {
            "none", "local_emergency_stop", "cloud_stop", "runner_revoked",
            "target_revoked", "kill_switch",
        }:
            raise ValueError("invalid execution gate stop reason")
        for name in ("proof_expires_at_ms", "kill_switch_generation", "server_time_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("invalid execution gate timestamp or generation")


@dataclass(frozen=True, slots=True)
class ExecutionBundle:
    manifest: Mapping[str, Any]
    projection: Mapping[str, Any]
    grant: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ValidatedExecutionBundle:
    manifest: dict[str, Any]
    projection: dict[str, Any]
    grant: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    assessment_outcome: str
    execution_disposition: str
    operational_projection: dict[str, Any]
    findings_projection: dict[str, Any]
    local_view: dict[str, Any]
    disclosure_preview: dict[str, Any]


def _verify_runner_projection(projection: Mapping[str, Any], identity: RunnerIdentity) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        public_bytes = base64.b64decode(identity.public_key_b64, validate=True)
    except (TypeError, ValueError):
        raise ValueError("runner identity public key is invalid") from None
    unsigned = {
        key: value for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    verify_envelope(
        {identity.key_id: Ed25519PublicKey.from_public_bytes(public_bytes)},
        {
            "signing_key_id": projection["signing_key_id"],
            "signature_b64": projection["signature_b64"],
        },
        canonical_bytes(unsigned),
    )


def _gate_failure(gate: ExecutionGate, generation: int) -> tuple[str, str] | None:
    if gate.runner_state in {"revoked", "replaced"}:
        return "runner_fault", "runner_revoked"
    if gate.proof_state == "revoked":
        return "proof_expired", "target_revoked"
    if gate.proof_state != "valid" or gate.proof_expires_at_ms <= gate.server_time_ms:
        return "proof_expired", "none"
    if gate.kill_switch_generation != generation:
        return "platform_fault", "kill_switch"
    if not gate.active:
        return "platform_fault", "kill_switch"
    if gate.stop_reason != "none":
        return "none", gate.stop_reason
    return None


def validate_execution_bundle(
    bundle: ExecutionBundle,
    *,
    store: RunnerStore,
    identity: RunnerIdentity,
    trusted_grant_keys: Mapping[str, object],
    now_ms: int,
    gate: ExecutionGate,
) -> ValidatedExecutionBundle:
    """Verify every exact immutable binding before target transport can be constructed."""
    if not isinstance(bundle, ExecutionBundle):
        raise ValueError("ExecutionBundle is required")
    if not isinstance(store, RunnerStore) or not isinstance(identity, RunnerIdentity):
        raise ValueError("bound runner store and identity are required")
    if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
        raise ValueError("execution time must be a non-negative integer")
    manifest = validate_test_manifest(bundle.manifest)
    projection = validate_approval_projection(bundle.projection)
    grant = validate_execution_grant(bundle.grant)
    stored_manifest, stored_projection = store.load_approved_pair(projection["projection_id"])
    if stored_manifest != manifest or stored_projection != projection:
        raise ValueError("execution artifacts differ from the immutable local pair")
    _verify_runner_projection(projection, identity)
    grant_unsigned = {
        key: value for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    verify_envelope(
        dict(trusted_grant_keys),
        {"signing_key_id": grant["signing_key_id"], "signature_b64": grant["signature_b64"]},
        canonical_bytes(grant_unsigned),
    )
    context = store.load_context()
    binding = store.load_binding()["identity"]
    exact_approval = {
        "projection_id": projection["projection_id"],
        "projection_digest": projection["projection_digest"],
        "manifest_digest": manifest["manifest_digest"],
    }
    exact_runner_binding = {
        "runner_id": identity.runner_id,
        "runner_key_id": identity.key_id,
        "public_key_digest": identity.fingerprint,
    }
    expected_environment = {
        "environment_id": context.environment_id,
        "verification_record_digest": context.verification_record_digest,
        "origin": context.origin,
        "environment_class": context.environment_class,
    }
    if (
        manifest["environment"] != expected_environment
        or projection["environment"] != expected_environment
        or grant["environment"] != expected_environment
        or expected_environment["environment_class"] not in {"staging", "sandbox"}
        or manifest["workspace_id"] != context.workspace_id
        or projection["workspace_id"] != context.workspace_id
        or grant["workspace_id"] != context.workspace_id
        or manifest["project_id"] != context.project_id
        or projection["project_id"] != context.project_id
        or grant["project_id"] != context.project_id
        or grant["approval"] != exact_approval
        or grant["runner_binding"] != exact_runner_binding
        or binding["runner_id"] != identity.runner_id
        or binding["runner_key_id"] != identity.key_id
        or binding["fingerprint"] != identity.fingerprint
        or manifest["runner"] != {
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "minimum_runner_version": identity.runner_version,
        }
        or projection["runner"]["runner_id"] != identity.runner_id
        or projection["runner"]["runner_key_id"] != identity.key_id
        or projection["runner"]["runner_version"] != identity.runner_version
    ):
        raise ValueError("execution bundle has a cross-binding mismatch")
    for field in ("budgets", "egress", "retry_policy"):
        if grant[field] != manifest[field] or projection[field] != manifest[field]:
            raise ValueError("execution grant cannot use different or lower approved limits")
    if manifest["compiler"] != projection["compiler"]:
        raise ValueError("execution compiler versions differ")
    expected_adapters = sorted({item["adapter_version"] for item in manifest["scenarios"]})
    if (
        projection["scenarios"] != manifest["scenarios"]
        or projection["runner"]["adapter_versions"] != expected_adapters
        or any(
            identity.adapter_versions.get(item["scenario_id"]) != item["adapter_version"]
            for item in manifest["scenarios"]
        )
    ):
        raise ValueError("execution adapter versions differ")
    if not grant["issued_at_ms"] <= now_ms < grant["expires_at_ms"]:
        raise ValueError("execution grant is expired or not yet valid")
    failure = _gate_failure(gate, grant["kill_switch_generation"])
    if failure is not None:
        raise ValueError("fresh execution gate rejected the grant")
    return ValidatedExecutionBundle(manifest, projection, grant)


def _sign_projection(unsigned: dict[str, Any], signer: SecureSigner, digest_field: str) -> dict[str, Any]:
    signature = signer.sign(canonical_bytes(unsigned))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("runner signer returned an invalid projection signature")
    return {
        **unsigned,
        digest_field: canonical_digest(unsigned),
        "signing_key_id": signer.key_id,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def _credential_value(profile: str, secret: bytes) -> object:
    if profile in {"bearer", "x_api_key"}:
        try:
            return secret.decode("ascii")
        except UnicodeError:
            raise VaultUnavailable("credential token is not transport-safe") from None
    if profile == "cookie_jar":
        value = json.loads(secret.decode("utf-8"))
        return {cookie["name"]: cookie["value"] for cookie in value["cookies"]}
    raise VaultUnavailable("invalid execution credential profile")


class LocalCanaryExecutor:
    """Prepare the complete action set, resolve all secrets, then run one request at a time."""

    def __init__(
        self,
        *,
        store: RunnerStore,
        identity: RunnerIdentity,
        signer: SecureSigner,
        trusted_grant_keys: Mapping[str, object],
        vaults: Mapping[str, object] | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not isinstance(store, RunnerStore) or not isinstance(identity, RunnerIdentity):
            raise ValueError("bound runner store and identity are required")
        if not isinstance(signer, SecureSigner) or signer.key_id != identity.key_id:
            raise ValueError("paired runner signer is required")
        self.store = store
        self.identity = identity
        self.signer = signer
        self.trusted_grant_keys = dict(trusted_grant_keys)
        self.vaults = dict(vaults or {})
        self.clock_ms = clock_ms
        self.monotonic = monotonic

    def _gate(self, source: Callable[[], ExecutionGate], generation: int) -> ExecutionGate:
        try:
            gate = source()
        except BaseException:
            raise TransportFailure("gate_rejected") from None
        if not isinstance(gate, ExecutionGate):
            raise TransportFailure("gate_rejected")
        failure = _gate_failure(gate, generation)
        if failure is not None:
            error, stop = failure
            code = "cancelled" if stop != "none" else "gate_rejected"
            raised = TransportFailure(code)
            raised.gate_error = error
            raised.stop_reason = stop
            raise raised
        return gate

    def _resolve_credentials(self, manifest: Mapping[str, Any]) -> dict[str, object]:
        records = {item["credential_handle_id"]: item for item in self.store.list_credentials()}
        result: dict[str, object] = {}
        origin = manifest["environment"]["origin"]
        for binding in manifest["credential_bindings"]:
            handle = binding["credential_handle_id"]
            record = records.get(handle)
            if (
                record is None
                or record["state"] != "active"
                or record["semantic_role"] != binding["semantic_role"]
                or record["auth_profile"] != binding["auth_profile"]
            ):
                raise VaultUnavailable("credential binding is unavailable")
            vault = self.vaults.get(record["backend"])
            if vault is None and record["backend"] in {"ephemeral_env", "ephemeral_fd"}:
                vault = EphemeralVault(handle, source_kind=record["source_kind"])
            if (
                vault is None
                or getattr(vault, "supported", False) is not True
                or getattr(vault, "backend_id", record["backend"]) != record["backend"]
            ):
                raise VaultUnavailable("credential backend is unavailable")
            normalized = validate_credential_secret(
                record["auth_profile"], vault.load(handle), origin,
            )
            result[record["semantic_role"]] = _credential_value(record["auth_profile"], normalized)
            normalized = b""
        return result

    @staticmethod
    def _failure_class(exc: BaseException) -> tuple[str, str, str]:
        if isinstance(exc, TransportFailure):
            stop = getattr(exc, "stop_reason", "none")
            gate_error = getattr(exc, "gate_error", None)
            if stop != "none":
                return "stopped", gate_error or "none", stop
            if exc.code == "cancelled" and gate_error is not None:
                return "incomplete", gate_error, "none"
            if exc.code == "cancelled":
                return "stopped", "none", "local_emergency_stop"
            if gate_error is not None:
                return "incomplete", gate_error, "none"
            if exc.code == "dns_changed":
                return "incomplete", "dns_changed", "none"
            if exc.code in {"connect_error", "timeout", "unsafe_dns", "peer_mismatch", "tls_error"}:
                return "incomplete", "target_unavailable", "none"
            if exc.code in {"response_too_large", "response_rejected", "invalid_route", "invalid_auth"}:
                return "failed", "containment_rejected", "none"
            return "failed", "runner_fault", "none"
        if isinstance(exc, VaultUnavailable):
            return "incomplete", "credential_unavailable", "none"
        if isinstance(exc, (ValueError, RunnerStoreError)):
            return "failed", "containment_rejected", "none"
        return "failed", "runner_fault", "none"

    def execute(
        self,
        bundle: ExecutionBundle,
        *,
        transport: Any,
        gate_source: Callable[[], ExecutionGate],
        cancellation: CancellationToken | None = None,
        on_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> ExecutionResult:
        initial_gate = gate_source()
        validated = validate_execution_bundle(
            bundle, store=self.store, identity=self.identity,
            trusted_grant_keys=self.trusted_grant_keys, now_ms=self.clock_ms(), gate=initial_gate,
        )
        manifest, projection, grant = validated.manifest, validated.projection, validated.grant
        # Compile every closed action before consuming the grant or allowing a target socket.
        prepared = [prepare_action(action) for action in manifest["actions"]]
        retention_expires = (
            self.clock_ms() + manifest["local_evidence_policy"]["retention_seconds"] * 1000
        )
        self.store.reserve_run(grant, retention_expires_at_ms=retention_expires)
        log = ContainmentLog(
            store=self.store, signer=self.signer, run_id=grant["run_id"],
            grant_id=grant["grant_id"], manifest_digest=manifest["manifest_digest"],
            clock_ms=self.clock_ms,
        )
        log.append("grant_verified", detail_code="grant_exact")
        cancellation = cancellation or CancellationToken()
        started_at = self.clock_ms()
        started_monotonic = self.monotonic()
        counters = {
            "requests_started": 0,
            "requests_completed": 0,
            "response_bytes_read": 0,
            "actions_contained": 0,
            "retries_used": 0,
        }
        observations: dict[str, list[dict[str, Any]]] = {
            item["scenario_id"]: [] for item in manifest["scenarios"]
        }
        scenario_codes: dict[str, set[str]] = {
            item["scenario_id"]: set() for item in manifest["scenarios"]
        }
        disposition = "completed"
        error_category = "none"
        stop_reason = "none"
        systemic_failure = False
        try:
            credentials = self._resolve_credentials(manifest)
            self._gate(gate_source, grant["kill_switch_generation"])
            self.store.transition_run(grant["run_id"], "running", now_ms=self.clock_ms())
            log.append("run_started", detail_code="all_preflight_valid", counters=counters)
            for source, action in zip(manifest["actions"], prepared, strict=True):
                cancellation.raise_if_cancelled()
                self._gate(gate_source, grant["kill_switch_generation"])
                elapsed_ms = int(max(0.0, self.monotonic() - started_monotonic) * 1000)
                if (
                    elapsed_ms >= manifest["budgets"]["wall_timeout_ms"]
                    or counters["requests_started"] >= manifest["budgets"]["maximum_requests"]
                ):
                    log.append(
                        "budget_exhausted", action_ordinal=source["ordinal"],
                        scenario_id=source["scenario_id"], semantic_role=source["semantic_auth_role"],
                        attempt=1, detail_code="budget_exhausted", counters=counters,
                    )
                    exhausted = TransportFailure("gate_rejected")
                    exhausted.gate_error = "budget_exhausted"
                    raise exhausted
                action_binding = {
                    "action_ordinal": source["ordinal"],
                    "scenario_id": source["scenario_id"],
                    "semantic_role": source["semantic_auth_role"],
                    "attempt": 1,
                }
                log.append("admitted", detail_code="exact_action", counters=counters, **action_binding)
                counters["actions_contained"] += 1
                counters["requests_started"] += 1
                log.append("action_started", detail_code="target_read", counters=counters, **action_binding)
                credential = None if action.auth_profile == "anonymous" else credentials[action.semantic_auth_role]
                try:
                    response = transport.request(
                        action, credential=credential, cancellation=cancellation,
                    )
                except TransportFailure as exc:
                    additional = max(0, exc.requests_made - 1)
                    counters["requests_started"] += additional
                    counters["retries_used"] += additional
                    code = "dns_changed" if exc.code == "dns_changed" else "action_rejected"
                    scenario_codes[source["scenario_id"]].add(code)
                    log.append(code, detail_code=exc.code, counters=counters, **action_binding)
                    raise
                attempts = getattr(response, "requests_made", 1)
                if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 2:
                    raise TransportFailure("response_rejected")
                counters["requests_started"] += attempts - 1
                counters["retries_used"] += attempts - 1
                counters["requests_completed"] += 1
                counters["response_bytes_read"] += response.response_bytes
                if (
                    counters["requests_started"] > manifest["budgets"]["maximum_requests"]
                    or counters["retries_used"] > manifest["retry_policy"]["maximum_retries"]
                    or response.response_bytes > manifest["budgets"]["maximum_response_bytes"]
                ):
                    raise TransportFailure("response_rejected")
                observations[source["scenario_id"]].append({
                    "semantic_role": source["semantic_auth_role"],
                    "status_code": response.status_code,
                    "body_shape": response.body_shape,
                    "truncation_state": "complete",
                })
                scenario_codes[source["scenario_id"]].update({"admitted", "action_started", "action_completed"})
                log.append("action_completed", detail_code="bounded_response", counters=counters, **action_binding)
                if on_progress is not None:
                    on_progress(self._running_projection(
                        manifest, projection, grant, started_at, counters, log.load(),
                    ))
        except BaseException as exc:
            if isinstance(exc, TransportFailure) and exc.code == "cancelled":
                control_error = getattr(cancellation, "control_error", None)
                control_stop = getattr(cancellation, "stop_reason", None)
                if control_error is not None:
                    exc.gate_error = control_error
                if control_stop is not None:
                    exc.stop_reason = control_stop
            systemic_failure = True
            disposition, error_category, stop_reason = self._failure_class(exc)
            if disposition == "stopped":
                try:
                    state = self.store.load_run(grant["run_id"])["state"]
                    if state == "running":
                        self.store.transition_run(
                            grant["run_id"], "stop_requested", now_ms=self.clock_ms(),
                        )
                    log.append("stop_observed", detail_code=stop_reason, counters=counters)
                except BaseException:
                    disposition, error_category, stop_reason = "failed", "runner_fault", "none"
            elif error_category == "dns_changed":
                pass
            elif error_category == "credential_unavailable" and not log.load():
                log.append("grant_verified", detail_code="grant_exact", counters=counters)
        return self._finalize(
            manifest, projection, grant, log, observations, scenario_codes, counters,
            started_at=started_at, disposition=disposition, error_category=error_category,
            stop_reason=stop_reason, systemic_failure=systemic_failure,
        )

    def _running_projection(
        self, manifest, projection, grant, started_at, counters, events,
    ) -> dict[str, Any]:
        now = self.clock_ms()
        unsigned = {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
            "manifest_digest": manifest["manifest_digest"],
            "approval_projection_digest": projection["projection_digest"],
            "grant_digest": grant["grant_digest"],
            "event_sequence": events[-1]["sequence"] if events else 0,
            "lifecycle_phase": "running", "execution_disposition": None,
            "timestamps": {
                "claimed_at_ms": started_at, "started_at_ms": started_at,
                "updated_at_ms": now, "stop_requested_at_ms": None,
                "stop_acknowledged_at_ms": None, "terminal_at_ms": None,
            },
            "counters": {
                **counters,
                "remaining_requests": max(0, manifest["budgets"]["maximum_requests"] - counters["requests_started"]),
                "remaining_wall_ms": manifest["budgets"]["wall_timeout_ms"],
            },
            "versions": {
                "runner_version": self.identity.runner_version,
                "engine_version": manifest["compiler"]["engine_version"],
                "adapter_versions": sorted({item["adapter_version"] for item in manifest["scenarios"]}),
            },
            "error_category": "none", "stop_reason": "none",
            "containment_codes": operational_containment_codes(events), "redaction_count": 0,
        }
        return validate_operational_run(_sign_projection(unsigned, self.signer, "projection_digest"))

    def _finalize(
        self,
        manifest,
        projection,
        grant,
        log,
        observations,
        scenario_codes,
        counters,
        *,
        started_at,
        disposition,
        error_category,
        stop_reason,
        systemic_failure,
    ) -> ExecutionResult:
        state = self.store.load_run(grant["run_id"])["state"]
        if state in {"verified", "running", "stop_requested"}:
            self.store.transition_run(grant["run_id"], "finalizing", now_ms=self.clock_ms())
        log.append("run_finalized", detail_code=disposition, counters=counters)
        scenario_results = []
        outcomes = []
        actions_by_scenario: dict[str, list[Mapping[str, Any]]] = {}
        for action in manifest["actions"]:
            actions_by_scenario.setdefault(action["scenario_id"], []).append(action)
        for ordinal, scenario in enumerate(manifest["scenarios"]):
            scenario_id = scenario["scenario_id"]
            scenario_observations = observations[scenario_id]
            source_actions = actions_by_scenario[scenario_id]
            if systemic_failure or len(scenario_observations) != len(source_actions):
                outcome = "inconclusive"
            else:
                pair = evaluate_pair(
                    scenario_id,
                    scenario_observations[0]["status_code"],
                    scenario_observations[1]["status_code"],
                    method=source_actions[0]["method"],
                    first_body_shape=scenario_observations[0]["body_shape"],
                    second_body_shape=scenario_observations[1]["body_shape"],
                )
                outcome = pair.outcome
            outcomes.append(outcome)
            finding = None
            if outcome == "observed":
                finding = {
                    "title": "Canary authorization boundary was crossed",
                    "reachability_rationale": "Both isolated canary roles received the approved read response.",
                    "confidence": "high",
                    "recommended_control": "Enforce the selected authorization boundary on every object read.",
                    "regression_suggestion": "Repeat this exact catalog scenario with a new one-shot grant.",
                }
            scenario_results.append({
                "ordinal": ordinal,
                "scenario_id": scenario_id,
                "adapter_version": scenario["adapter_version"],
                "assessment_outcome": outcome,
                "route": {
                    "method": source_actions[0]["method"],
                    "route_template": source_actions[0]["route_template"],
                },
                "observations": sorted(
                    scenario_observations,
                    key=lambda item: (
                        item["semantic_role"], item["status_code"], item["body_shape"],
                        item["truncation_state"],
                    ),
                ),
                "finding": finding,
                "containment_codes": sorted(scenario_codes[scenario_id]),
                "redaction_count": 0,
                "local_evidence_refs": [],
            })
        aggregate = (
            "inconclusive" if systemic_failure
            else "observed" if "observed" in outcomes
            else "blocked" if outcomes and all(item == "blocked" for item in outcomes)
            else "inconclusive"
        )
        finished_at = self.clock_ms()
        findings_unsigned = {
            "schema_version": CANARY_FINDINGS_SCHEMA,
            "projection_id": "findings_" + hashlib.sha256(grant["run_id"].encode()).hexdigest()[:24],
            "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
            "environment_id": grant["environment"]["environment_id"],
            "manifest_digest": manifest["manifest_digest"],
            "approval_projection_digest": projection["projection_digest"],
            "grant_digest": grant["grant_digest"],
            "engine_version": manifest["compiler"]["engine_version"],
            "adapter_versions": sorted({item["adapter_version"] for item in manifest["scenarios"]}),
            "started_at_ms": started_at, "finished_at_ms": finished_at,
            "assessment_outcome": aggregate, "scenario_results": scenario_results,
            "containment_codes": operational_containment_codes(log.load()),
            "redaction_count": 0,
        }
        findings = validate_canary_findings(
            _sign_projection(findings_unsigned, self.signer, "projection_digest")
        )
        stop_time = finished_at if stop_reason != "none" else None
        operational_unsigned = {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
            "manifest_digest": manifest["manifest_digest"],
            "approval_projection_digest": projection["projection_digest"],
            "grant_digest": grant["grant_digest"],
            "event_sequence": log.load()[-1]["sequence"],
            "lifecycle_phase": "terminal", "execution_disposition": disposition,
            "timestamps": {
                "claimed_at_ms": started_at, "started_at_ms": started_at,
                "updated_at_ms": finished_at,
                "stop_requested_at_ms": stop_time,
                "stop_acknowledged_at_ms": stop_time,
                "terminal_at_ms": finished_at,
            },
            "counters": {
                **counters,
                "remaining_requests": max(0, manifest["budgets"]["maximum_requests"] - counters["requests_started"]),
                "remaining_wall_ms": 0,
            },
            "versions": {
                "runner_version": self.identity.runner_version,
                "engine_version": manifest["compiler"]["engine_version"],
                "adapter_versions": sorted({item["adapter_version"] for item in manifest["scenarios"]}),
            },
            "error_category": error_category, "stop_reason": stop_reason,
            "containment_codes": operational_containment_codes(log.load()), "redaction_count": 0,
        }
        operational = validate_operational_run(
            _sign_projection(operational_unsigned, self.signer, "projection_digest")
        )
        policy = grant["operational_receipt_policy"]
        if (
            len(canonical_bytes(operational)) > policy["maximum_bytes"]
            or error_category not in policy["allowed_error_categories"]
            or stop_reason not in policy["allowed_stop_reasons"]
            or any(code not in policy["allowed_containment_codes"] for code in operational["containment_codes"])
        ):
            raise ValueError("operational projection exceeds the approved receipt policy")
        log.append("local_result_ready", detail_code="safe_projection", counters=counters)
        events = log.load()
        summary = {
            "event_count": len(events),
            "head_digest": events[-1]["event_digest"],
            "codes": sorted({item["event_code"] for item in events}),
            "redaction_count": 0,
        }
        local_view = validate_local_result_view({
            "schema_version": "heel.local-result-view.v1",
            "operational_projection": operational,
            "findings_projection": findings,
            "containment_summary": summary,
        })
        disclosure = validate_disclosure_preview({
            "schema_version": "heel.local-disclosure-preview.v1",
            "projection": findings,
            "projection_digest": findings["projection_digest"],
            "projection_bytes": len(canonical_bytes(findings)),
            "scenario_count": len(findings["scenario_results"]),
            "finding_count": sum(item["finding"] is not None for item in findings["scenario_results"]),
        })
        self.store.save_final_projections(
            grant["run_id"], operational, findings, local_view, disclosure,
        )
        self.store.transition_run(grant["run_id"], "terminal", now_ms=self.clock_ms())
        return ExecutionResult(
            aggregate, disposition, operational, findings, local_view, disclosure,
        )

    def recover(self, run_id: str, *, transport: Any = None) -> ExecutionResult:
        """Finalize an interrupted run without ever replaying a started target action."""
        del transport
        try:
            stored = self.store.load_final_projections(run_id)
        except RunnerStoreError:
            stored = None
        if stored is not None:
            return ExecutionResult(
                stored["findings_projection"]["assessment_outcome"],
                stored["operational_projection"]["execution_disposition"],
                stored["operational_projection"], stored["findings_projection"],
                stored["local_view"], stored["disclosure_preview"],
            )
        grant = self.store.load_run_grant(run_id)
        manifest = self.store.load_manifest(grant["approval"]["manifest_digest"])
        projection = self.store.load_projection(grant["approval"]["projection_id"])
        log = ContainmentLog(
            store=self.store, signer=self.signer, run_id=run_id, grant_id=grant["grant_id"],
            manifest_digest=manifest["manifest_digest"], clock_ms=self.clock_ms,
        )
        events = log.load()
        started = {
            event["action_ordinal"] for event in events if event["event_code"] == "action_started"
        }
        completed = {
            event["action_ordinal"] for event in events if event["event_code"] == "action_completed"
        }
        if not started - completed:
            raise RunnerStoreError("local run has no interrupted target action")
        counters = copy.deepcopy(events[-1]["counters"])
        observations = {item["scenario_id"]: [] for item in manifest["scenarios"]}
        codes = {item["scenario_id"]: set() for item in manifest["scenarios"]}
        return self._finalize(
            manifest, projection, grant, log, observations, codes, counters,
            started_at=events[0]["occurred_at_ms"], disposition="incomplete",
            error_category="runner_fault", stop_reason="none", systemic_failure=True,
        )


__all__ = [
    "ExecutionBundle", "ExecutionGate", "ExecutionResult", "LocalCanaryExecutor",
    "ValidatedExecutionBundle", "validate_execution_bundle",
]
