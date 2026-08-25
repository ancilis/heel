"""Bounded, deterministic execution of an exact customer-local canary grant."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import copy
from dataclasses import dataclass
import hashlib
import json
import threading
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
from heel.runner.http_transport import (
    AttemptPermit,
    BoundedResponseEvidence,
    CancellationToken,
    EvidenceContext,
    RetryPolicy,
    TransportFailure,
)
from heel.runner.identity import RunnerIdentity, SecureSigner
from heel.runner.redaction import Redactor
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


_MAX_GATE_STALE_SECONDS = 0.5


class _LiveAuthority:
    """Monotonic, non-renewable authority derived from the first server clock sample."""

    def __init__(
        self,
        *,
        grant: Mapping[str, Any],
        initial_gate: ExecutionGate,
        now: float,
    ):
        self._grant = grant
        self._lock = threading.Lock()
        self._last_server_time_ms = initial_gate.server_time_ms
        self._last_advance = now
        self._grant_deadline = now + (
            grant["expires_at_ms"] - initial_gate.server_time_ms
        ) / 1000
        self._proof_deadline = now + (
            initial_gate.proof_expires_at_ms - initial_gate.server_time_ms
        ) / 1000

    @staticmethod
    def _rejected(error: str, stop: str = "none") -> TransportFailure:
        failure = TransportFailure("cancelled" if stop != "none" else "gate_rejected")
        failure.gate_error = error
        failure.stop_reason = stop
        return failure

    def check(
        self,
        source: Callable[[], ExecutionGate],
        *,
        generation: int,
        monotonic: Callable[[], float],
    ) -> float:
        try:
            gate = source()
        except BaseException:
            raise self._rejected("cloud_disconnected") from None
        now = monotonic()
        if not isinstance(gate, ExecutionGate):
            raise self._rejected("cloud_disconnected")
        failure = _gate_failure(gate, generation)
        if failure is not None:
            raise self._rejected(*failure)
        with self._lock:
            if gate.server_time_ms < self._last_server_time_ms:
                raise self._rejected("cloud_disconnected")
            if gate.server_time_ms == self._last_server_time_ms:
                if now - self._last_advance > _MAX_GATE_STALE_SECONDS:
                    raise self._rejected("cloud_disconnected")
            else:
                self._last_server_time_ms = gate.server_time_ms
                self._last_advance = now
            self._grant_deadline = min(
                self._grant_deadline,
                now + (self._grant["expires_at_ms"] - gate.server_time_ms) / 1000,
            )
            self._proof_deadline = min(
                self._proof_deadline,
                now + (gate.proof_expires_at_ms - gate.server_time_ms) / 1000,
            )
            deadline = min(self._grant_deadline, self._proof_deadline)
            if now >= deadline:
                raise self._rejected("proof_expired")
            return deadline


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
        self._active_lock = threading.Lock()
        self._active_ready = threading.Event()
        self._active_context: dict[str, Any] | None = None

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

    def _resolve_credentials(
        self, manifest: Mapping[str, Any],
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        records = {item["credential_handle_id"]: item for item in self.store.list_credentials()}
        result: dict[str, object] = {}
        redaction_secrets: set[str] = set()
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
            credential = _credential_value(record["auth_profile"], normalized)
            result[record["semantic_role"]] = credential
            if isinstance(credential, str):
                redaction_secrets.add(credential)
            elif isinstance(credential, Mapping):
                redaction_secrets.update(
                    value for value in credential.values()
                    if isinstance(value, str) and len(value.encode("utf-8")) >= 4
                )
            normalized = b""
        return result, tuple(sorted(redaction_secrets))

    def _set_active_context(self, value: dict[str, Any] | None) -> None:
        with self._active_lock:
            self._active_context = value
            if value is None:
                self._active_ready.clear()
            else:
                self._active_ready.set()

    def prepare_stop_ack(
        self, run_id: str, *, stop_reason: str, proposed_at_ms: int,
    ) -> dict[str, Any]:
        """Build the signed stop receipt while target execution unwinds separately."""
        if type(run_id) is not str or not run_id:
            raise ValueError("stop acknowledgement run ID is invalid")
        if stop_reason not in {
            "local_emergency_stop", "cloud_stop", "runner_revoked",
            "target_revoked", "kill_switch",
        }:
            raise ValueError("stop acknowledgement reason is invalid")
        if isinstance(proposed_at_ms, bool) or not isinstance(proposed_at_ms, int) or proposed_at_ms < 0:
            raise ValueError("stop acknowledgement timestamp is invalid")
        if not self._active_ready.wait(1.0):
            raise RunnerStoreError("active run is unavailable for stop acknowledgement")
        with self._active_lock:
            context = self._active_context
            if context is None or context["grant"]["run_id"] != run_id:
                raise RunnerStoreError("active run does not match stop acknowledgement")
            manifest = context["manifest"]
            projection = context["projection"]
            grant = context["grant"]
            started_at = context["started_at"]
            started_monotonic = context["started_monotonic"]
            counters = dict(context["counters"])
            redaction_count = context["redaction_state"]["count"]
            log = context["log"]
        events = log.load()
        requested_at = max(started_at, proposed_at_ms)
        remaining_wall = max(
            0,
            manifest["budgets"]["wall_timeout_ms"]
            - int(max(0.0, self.monotonic() - started_monotonic) * 1000),
        )
        unsigned = {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
            "manifest_digest": manifest["manifest_digest"],
            "approval_projection_digest": projection["projection_digest"],
            "grant_digest": grant["grant_digest"],
            "event_sequence": events[-1]["sequence"] if events else 0,
            "lifecycle_phase": "stop_requested", "execution_disposition": None,
            "timestamps": {
                "claimed_at_ms": started_at, "started_at_ms": started_at,
                "updated_at_ms": requested_at, "stop_requested_at_ms": requested_at,
                "stop_acknowledged_at_ms": None, "terminal_at_ms": None,
            },
            "counters": {
                **counters,
                "remaining_requests": max(
                    0, manifest["budgets"]["maximum_requests"] - counters["requests_started"],
                ),
                "remaining_wall_ms": remaining_wall,
            },
            "versions": {
                "runner_version": self.identity.runner_version,
                "engine_version": manifest["compiler"]["engine_version"],
                "adapter_versions": sorted({
                    item["adapter_version"] for item in manifest["scenarios"]
                }),
            },
            "error_category": "none", "stop_reason": stop_reason,
            "containment_codes": operational_containment_codes(events),
            "redaction_count": redaction_count,
        }
        return validate_operational_run(
            _sign_projection(unsigned, self.signer, "projection_digest")
        )

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
        initial_gate_monotonic = self.monotonic()
        validated = validate_execution_bundle(
            bundle, store=self.store, identity=self.identity,
            trusted_grant_keys=self.trusted_grant_keys, now_ms=self.clock_ms(), gate=initial_gate,
        )
        manifest, projection, grant = validated.manifest, validated.projection, validated.grant
        authority = _LiveAuthority(
            grant=grant, initial_gate=initial_gate, now=initial_gate_monotonic,
        )
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
        scenario_evidence: dict[str, list[str]] = {
            item["scenario_id"]: [] for item in manifest["scenarios"]
        }
        scenario_redactions: dict[str, int] = {
            item["scenario_id"]: 0 for item in manifest["scenarios"]
        }
        redaction_state = {"count": 0}
        budget_lock = threading.Lock()
        disposition = "completed"
        error_category = "none"
        stop_reason = "none"
        systemic_failure = False
        stop_requested_at_ms = None
        stop_acknowledged_at_ms = None
        self._set_active_context({
            "manifest": manifest,
            "projection": projection,
            "grant": grant,
            "started_at": started_at,
            "started_monotonic": started_monotonic,
            "counters": counters,
            "redaction_state": redaction_state,
            "log": log,
        })
        try:
            credentials, configured_secrets = self._resolve_credentials(manifest)
            redactor = Redactor(configured_secrets)
            retry_policy = RetryPolicy.from_mapping(manifest["retry_policy"])
            authority.check(
                gate_source, generation=grant["kill_switch_generation"],
                monotonic=self.monotonic,
            )
            self.store.transition_run(grant["run_id"], "running", now_ms=self.clock_ms())
            log.append("run_started", detail_code="all_preflight_valid", counters=counters)
            for source, action in zip(manifest["actions"], prepared, strict=True):
                cancellation.raise_if_cancelled()
                action_binding = {
                    "action_ordinal": source["ordinal"],
                    "scenario_id": source["scenario_id"],
                    "semantic_role": source["semantic_auth_role"],
                    "attempt": 1,
                }
                log.append("admitted", detail_code="exact_action", counters=counters, **action_binding)
                credential = None if action.auth_profile == "anonymous" else credentials[action.semantic_auth_role]
                action_attempts = [0]

                def before_attempt(
                    attempt: int, previous_failure_code: str | None,
                ) -> AttemptPermit:
                    cancellation.raise_if_cancelled()
                    authority_deadline = authority.check(
                        gate_source, generation=grant["kill_switch_generation"],
                        monotonic=self.monotonic,
                    )
                    with budget_lock:
                        cancellation.raise_if_cancelled()
                        now = self.monotonic()
                        if now >= authority_deadline:
                            expired = TransportFailure("gate_rejected")
                            expired.gate_error = "proof_expired"
                            raise expired
                        if attempt != action_attempts[0] + 1 or attempt not in {1, 2}:
                            raise TransportFailure("gate_rejected")
                        if attempt == 1:
                            if previous_failure_code is not None:
                                raise TransportFailure("gate_rejected")
                        elif previous_failure_code not in retry_policy.retryable_failure_codes:
                            raise TransportFailure("gate_rejected")
                        elapsed_ms = int(max(0.0, now - started_monotonic) * 1000)
                        budget_failure = (
                            elapsed_ms >= manifest["budgets"]["wall_timeout_ms"]
                            or counters["requests_started"] >= manifest["budgets"]["maximum_requests"]
                            or (
                                attempt > 1
                                and counters["retries_used"] >= retry_policy.maximum_retries
                            )
                        )
                        if budget_failure:
                            log.append(
                                "budget_exhausted", action_ordinal=source["ordinal"],
                                scenario_id=source["scenario_id"],
                                semantic_role=source["semantic_auth_role"], attempt=attempt,
                                detail_code="budget_exhausted", counters=counters,
                            )
                            exhausted = TransportFailure("gate_rejected")
                            exhausted.gate_error = "budget_exhausted"
                            raise exhausted
                        counters["requests_started"] += 1
                        if attempt == 1:
                            counters["actions_contained"] += 1
                        else:
                            counters["retries_used"] += 1
                        action_attempts[0] = attempt
                        log.append(
                            "action_started", action_ordinal=source["ordinal"],
                            scenario_id=source["scenario_id"],
                            semantic_role=source["semantic_auth_role"], attempt=attempt,
                            detail_code="target_read", counters=counters,
                        )
                        action_deadline = now + manifest["budgets"]["action_timeout_ms"] / 1000
                        wall_deadline = (
                            started_monotonic + manifest["budgets"]["wall_timeout_ms"] / 1000
                        )
                        return AttemptPermit(min(
                            action_deadline, wall_deadline, authority_deadline,
                        ))

                def evidence_sink(evidence: BoundedResponseEvidence) -> str:
                    if (
                        not isinstance(evidence, BoundedResponseEvidence)
                        or evidence.action_ordinal != source["ordinal"]
                        or evidence.scenario_id != source["scenario_id"]
                        or evidence.semantic_auth_role != source["semantic_auth_role"]
                        or evidence.method != source["method"]
                        or evidence.route_template != source["route_template"]
                        or evidence.attempt != action_attempts[0]
                    ):
                        raise ValueError("response evidence differs from the frozen action")
                    return self.store.store_response_evidence(
                        grant["run_id"], action_ordinal=evidence.action_ordinal,
                        attempt=evidence.attempt, status_code=evidence.status_code,
                        raw_headers=evidence.raw_headers, raw_body=evidence.raw_body,
                        expires_at_ms=retention_expires,
                    )

                try:
                    response = transport.request(
                        action,
                        credential=credential,
                        cancellation=cancellation,
                        retry_policy=retry_policy,
                        remaining_requests=max(
                            0,
                            manifest["budgets"]["maximum_requests"]
                            - counters["requests_started"],
                        ),
                        before_attempt=before_attempt,
                        evidence_context=EvidenceContext(
                            source["ordinal"], source["route_template"],
                        ),
                        evidence_sink=evidence_sink,
                        redactor=redactor,
                    )
                except TransportFailure as exc:
                    code = "dns_changed" if exc.code == "dns_changed" else "action_rejected"
                    scenario_codes[source["scenario_id"]].add(code)
                    log.append(
                        code, detail_code=exc.code, counters=counters,
                        **{**action_binding, "attempt": max(1, action_attempts[0])},
                    )
                    raise
                attempts = getattr(response, "requests_made", 1)
                if (
                    isinstance(attempts, bool)
                    or not isinstance(attempts, int)
                    or attempts != action_attempts[0]
                ):
                    raise TransportFailure("response_rejected")
                counters["requests_completed"] += 1
                counters["response_bytes_read"] += response.response_bytes
                if (
                    counters["requests_started"] > manifest["budgets"]["maximum_requests"]
                    or counters["retries_used"] > manifest["retry_policy"]["maximum_retries"]
                    or response.response_bytes > manifest["budgets"]["maximum_response_bytes"]
                    or type(response.evidence_ref) is not str
                    or not response.evidence_ref.startswith("ev1_")
                ):
                    raise TransportFailure("response_rejected")
                scenario_evidence[source["scenario_id"]].append(response.evidence_ref)
                scenario_redactions[source["scenario_id"]] += response.redaction_count
                redaction_state["count"] += response.redaction_count
                if response.redaction_count:
                    scenario_codes[source["scenario_id"]].add("redacted")
                    log.append(
                        "redacted", action_ordinal=source["ordinal"],
                        scenario_id=source["scenario_id"],
                        semantic_role=source["semantic_auth_role"], attempt=attempts,
                        detail_code="response_secret", counters=counters,
                    )
                observations[source["scenario_id"]].append({
                    "semantic_role": source["semantic_auth_role"],
                    "status_code": response.status_code,
                    "body_shape": response.body_shape,
                    "truncation_state": "complete",
                })
                scenario_codes[source["scenario_id"]].update({"admitted", "action_started", "action_completed"})
                log.append(
                    "action_completed", detail_code="bounded_response", counters=counters,
                    **{**action_binding, "attempt": attempts},
                )
                if on_progress is not None:
                    on_progress(self._running_projection(
                        manifest, projection, grant, started_at, started_monotonic,
                        counters, log.load(), redaction_state["count"],
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
                acknowledgement = getattr(cancellation, "stop_ack_event", None)
                if isinstance(acknowledgement, threading.Event):
                    deadline = getattr(cancellation, "stop_ack_deadline", self.monotonic())
                    acknowledgement.wait(max(0.0, deadline - self.monotonic()))
                stop_requested_at_ms = getattr(cancellation, "stop_requested_at_ms", self.clock_ms())
                stop_acknowledged_at_ms = getattr(
                    cancellation, "stop_acknowledged_at_ms", None,
                )
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
        try:
            return self._finalize(
                manifest, projection, grant, log, observations, scenario_codes,
                scenario_evidence, scenario_redactions, counters,
                redaction_count=redaction_state["count"], started_at=started_at,
                disposition=disposition, error_category=error_category,
                stop_reason=stop_reason, systemic_failure=systemic_failure,
                stop_requested_at_ms=stop_requested_at_ms,
                stop_acknowledged_at_ms=stop_acknowledged_at_ms,
            )
        finally:
            self._set_active_context(None)

    def _running_projection(
        self, manifest, projection, grant, started_at, started_monotonic, counters,
        events, redaction_count,
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
                "remaining_wall_ms": max(
                    0,
                    manifest["budgets"]["wall_timeout_ms"]
                    - int(max(0.0, self.monotonic() - started_monotonic) * 1000),
                ),
            },
            "versions": {
                "runner_version": self.identity.runner_version,
                "engine_version": manifest["compiler"]["engine_version"],
                "adapter_versions": sorted({item["adapter_version"] for item in manifest["scenarios"]}),
            },
            "error_category": "none", "stop_reason": "none",
            "containment_codes": operational_containment_codes(events),
            "redaction_count": redaction_count,
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
        scenario_evidence,
        scenario_redactions,
        counters,
        *,
        redaction_count,
        started_at,
        disposition,
        error_category,
        stop_reason,
        systemic_failure,
        stop_requested_at_ms,
        stop_acknowledged_at_ms,
    ) -> ExecutionResult:
        state = self.store.load_run(grant["run_id"])["state"]
        if state in {"verified", "running", "stop_requested"}:
            self.store.transition_run(grant["run_id"], "finalizing", now_ms=self.clock_ms())
        existing_events = log.load()
        if not existing_events or existing_events[-1]["event_code"] != "run_finalized":
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
                "redaction_count": scenario_redactions[scenario_id],
                "local_evidence_refs": sorted(scenario_evidence[scenario_id]),
            })
        aggregate = (
            "inconclusive" if systemic_failure
            else "observed" if "observed" in outcomes
            else "blocked" if outcomes and all(item == "blocked" for item in outcomes)
            else "inconclusive"
        )
        finished_at = max(
            self.clock_ms(), started_at,
            stop_requested_at_ms or 0, stop_acknowledged_at_ms or 0,
        )
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
            "redaction_count": redaction_count,
        }
        findings = validate_canary_findings(
            _sign_projection(findings_unsigned, self.signer, "projection_digest")
        )
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
                "stop_requested_at_ms": stop_requested_at_ms,
                "stop_acknowledged_at_ms": stop_acknowledged_at_ms,
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
            "containment_codes": operational_containment_codes(log.load()),
            "redaction_count": redaction_count,
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
            "redaction_count": redaction_count,
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
            self.store.load_run(run_id)
        except RunnerStoreError:
            self.store.recover_run_reservation(run_id)
        try:
            stored = self.store.load_final_projections(run_id)
        except RunnerStoreError:
            stored = None
        if stored is not None:
            state = self.store.load_run(run_id)["state"]
            if state != "terminal":
                if state in {"verified", "running", "stop_requested"}:
                    self.store.transition_run(run_id, "finalizing", now_ms=self.clock_ms())
                self.store.transition_run(run_id, "terminal", now_ms=self.clock_ms())
            return ExecutionResult(
                stored["findings_projection"]["assessment_outcome"],
                stored["operational_projection"]["execution_disposition"],
                stored["operational_projection"], stored["findings_projection"],
                stored["local_view"], stored["disclosure_preview"],
            )
        grant = self.store.load_run_grant(run_id)
        manifest = self.store.load_manifest(grant["approval"]["manifest_digest"])
        projection = self.store.load_projection(grant["approval"]["projection_id"])
        validate_execution_bundle(
            ExecutionBundle(manifest, projection, grant),
            store=self.store,
            identity=self.identity,
            trusted_grant_keys=self.trusted_grant_keys,
            now_ms=grant["issued_at_ms"],
            gate=ExecutionGate(
                active=True,
                runner_state="active",
                proof_state="valid",
                proof_expires_at_ms=max(grant["expires_at_ms"], grant["issued_at_ms"] + 1),
                kill_switch_generation=grant["kill_switch_generation"],
                stop_reason="none",
                server_time_ms=grant["issued_at_ms"],
            ),
        )
        log = ContainmentLog(
            store=self.store, signer=self.signer, run_id=run_id, grant_id=grant["grant_id"],
            manifest_digest=manifest["manifest_digest"], clock_ms=self.clock_ms,
        )
        events = log.load()
        if not events:
            log.append("grant_verified", detail_code="recovery_verified")
            events = log.load()
        counters = copy.deepcopy(events[-1]["counters"])
        observations = {item["scenario_id"]: [] for item in manifest["scenarios"]}
        codes = {item["scenario_id"]: set() for item in manifest["scenarios"]}
        evidence = {item["scenario_id"]: [] for item in manifest["scenarios"]}
        redactions = {item["scenario_id"]: 0 for item in manifest["scenarios"]}
        return self._finalize(
            manifest, projection, grant, log, observations, codes, evidence, redactions, counters,
            redaction_count=0,
            started_at=events[0]["occurred_at_ms"], disposition="incomplete",
            error_category="runner_fault", stop_reason="none", systemic_failure=True,
            stop_requested_at_ms=None, stop_acknowledged_at_ms=None,
        )


__all__ = [
    "ExecutionBundle", "ExecutionGate", "ExecutionResult", "LocalCanaryExecutor",
    "ValidatedExecutionBundle", "validate_execution_bundle",
]
