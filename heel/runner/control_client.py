"""Fixed-route runner control and recovery client."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from heel.canary_contracts import (
    canonical_bytes,
    validate_approval_projection,
    validate_canary_findings,
    validate_disclosure_permit,
    validate_execution_grant,
    validate_runner_claim_request,
    validate_runner_heartbeat_request,
    validate_runner_progress_request,
    validate_runner_result_request,
    validate_runner_stop_ack_request,
    validate_runner_context_list,
    validate_runner_context_claim,
    validate_runner_approval_projection_submit,
    validate_runner_context_binding,
)
from heel.crypto import ed25519_key_id, verify_envelope
from heel.runner.runtime import RunnerRuntimeState


_CAPS = {"claim": "runner_claim", "heartbeat": "runner_heartbeat", "progress": "runner_progress", "result": "runner_result", "stop-ack": "runner_heartbeat"}
_RUN_OPERATIONS = frozenset({"heartbeat", "progress", "result", "stop-ack"})
_REQUEST_VALIDATORS = {
    "heartbeat": validate_runner_heartbeat_request,
    "progress": validate_runner_progress_request,
    "result": validate_runner_result_request,
    "stop-ack": validate_runner_stop_ack_request,
}


@dataclass(frozen=True)
class _Call:
    path: str; headers: dict[str, str]; body: bytes; capability: str
    chain: str; sequence: int; generation: int


@dataclass(frozen=True, slots=True)
class _CallDiagnostic:
    """Bounded, deliberately non-sensitive local control observability."""

    operation: str
    status: int
    sequence: int
    generation: int


@dataclass(frozen=True, slots=True)
class _RunGuard:
    """One lifecycle lock and nominal token for an authenticated active run."""

    lock: threading.Lock
    token: object


@dataclass(frozen=True)
class PendingRunnerResync:
    challenge_id: str; operation: str; run_id: str | None; client_nonce_b64: str
    server_challenge_b64: str; next_sequence: int; expires_at_ms: int; generation: int


@dataclass(frozen=True)
class RecoveredRunnerChain:
    operation: str; run_id: str | None; next_nonce_b64: str
    next_sequence: int; expires_at_ms: int; generation: int


@dataclass(frozen=True)
class RunnerRotationActivated:
    schema_version: str
    workspace_id: str
    runner_id: str
    initial_claim_nonce: str
    initial_claim_sequence: int
    initial_claim_generation: int


_GATE_FIELDS = {
    "active", "runner_state", "proof_state", "proof_expires_at_ms",
    "kill_switch_generation", "stop_reason", "server_time_ms",
}
_STATUS_FIELDS = {
    "schema_version", "run_id", "approval_id", "grant_id", "status",
    "execution_disposition", "error_category", "stop_reason",
    "source_event_sequence", "quota_state", "kill_switch_generation",
    "stop_generation", "stop_deadline_ms", "stop_acknowledged_at_ms",
    "stop_ack_late",
}
_RUN_STATUSES = {
    "prepared", "awaiting_execution_approval", "approved", "claimed", "running",
    "stop_requested", "finalizing", "terminal", "cancelled", "expired",
}
_DISPOSITIONS = {"completed", "incomplete", "failed", "stopped"}
_ERRORS = {
    "none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired",
    "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted",
    "containment_rejected", "cloud_disconnected",
}
_STOPS = {
    "none", "local_emergency_stop", "cloud_stop", "runner_revoked",
    "target_revoked", "kill_switch",
}
_MAX_FINDINGS_UPLOAD_BYTES = 272 * 1024
_CALL_DIAGNOSTIC_OPERATIONS = frozenset({
    "claim", "heartbeat", "progress", "result", "stop-ack", "upload-findings",
    "list-contexts", "claim-context", "submit-context-approval-projection",
})
_MAX_CALL_DIAGNOSTICS = 128
_MAX_TRACKED_RUNS = 64
_FINDINGS_RECEIPT_FIELDS = {
    "schema_version", "receipt_id", "workspace_id", "project_id", "run_id",
    "grant_id", "permit_id", "projection_id", "projection_digest", "byte_count",
    "scenario_count", "finding_count", "accepted_at_ms", "status",
}
_ROLLOVER_RECEIPT_CONSTRUCTOR = object()
_ROLLOVER_RECEIPT_REGISTRY: dict[bytes, tuple["RunnerControlClient", "_RunnerContextRolloverReceipt", object]] = {}
_ROLLOVER_RECEIPT_REGISTRY_LOCK = threading.Lock()


class _RunnerContextRolloverReceipt:
    """Opaque, one-use evidence emitted only after this client's list/claim pair."""

    __slots__ = (
        "_client_instance", "_store", "_used", "_receipt_id", "_evidence",
    )

    def __init__(self, token: object, *, client_instance: object, evidence: Mapping[str, object]):
        if token is not _ROLLOVER_RECEIPT_CONSTRUCTOR:
            raise TypeError("runner context rollover receipts are internal")
        self._client_instance = client_instance
        self._store: object | None = None
        self._used = False
        self._receipt_id = secrets.token_bytes(32)
        self._evidence = dict(evidence)

    def _bind_store(self, store: object) -> None:
        if self._used or self._store is not None:
            raise ValueError("runner context rollover receipt is not reusable")
        self._store = store

    def _assert_bound_for(self, store: object) -> None:
        if self._used or self._store is not store:
            raise ValueError("runner context rollover receipt is not valid for this store")

    def _consume_for(
        self, store: object, *, old_binding_id: str, old_binding_digest: str,
        new_binding_id: str, new_binding_digest: str,
    ) -> dict[str, object]:
        self._assert_bound_for(store)
        evidence = self._evidence
        if (
            evidence.get("old_binding_id") != old_binding_id
            or evidence.get("old_binding_digest") != old_binding_digest
            or evidence.get("new_binding_id") != new_binding_id
            or evidence.get("new_binding_digest") != new_binding_digest
            or not isinstance(evidence.get("observed_server_time_ms"), int)
            or not isinstance(evidence.get("list_request_digest"), str)
            or not isinstance(evidence.get("claim_request_digest"), str)
            or not isinstance(evidence.get("list_generation"), int)
            or not isinstance(evidence.get("claim_generation"), int)
        ):
            raise ValueError("runner context rollover receipt is inconsistent")
        self._used = True
        return dict(evidence)


def _registered_rollover_receipt(receipt: object, store: object) -> _RunnerContextRolloverReceipt:
    if not isinstance(receipt, _RunnerContextRolloverReceipt):
        raise ValueError("runner context rollover receipt is invalid")
    with _ROLLOVER_RECEIPT_REGISTRY_LOCK:
        registered = _ROLLOVER_RECEIPT_REGISTRY.get(receipt._receipt_id)
        if registered is None or registered[1] is not receipt or registered[2] is not store:
            raise ValueError("runner context rollover receipt is not registered")
    return receipt


def _consume_registered_rollover_receipt(
    receipt: object, store: object, *, old_binding_id: str, old_binding_digest: str,
    new_binding_id: str, new_binding_digest: str,
) -> dict[str, object]:
    checked = _registered_rollover_receipt(receipt, store)
    with _ROLLOVER_RECEIPT_REGISTRY_LOCK:
        registered = _ROLLOVER_RECEIPT_REGISTRY.pop(checked._receipt_id, None)
        if registered is None or registered[1] is not checked or registered[2] is not store:
            raise ValueError("runner context rollover receipt is not registered")
        registered[0]._rollover_receipts.pop(checked._receipt_id, None)
        return checked._consume_for(
            store, old_binding_id=old_binding_id, old_binding_digest=old_binding_digest,
            new_binding_id=new_binding_id, new_binding_digest=new_binding_digest,
        )


class RunnerControlClient:
    """Emit only named closed control/recovery envelopes; no generic request API exists."""

    def __init__(self, *, origin, workspace_id, runner_id, signer, clock, transport, nonce_source,
                 resync_random_source=secrets.token_bytes,
                 trusted_disclosure_keys: Mapping[str, object] | None = None,
                 runtime: RunnerRuntimeState | None = None):
        parsed = urlsplit(origin)
        if origin != f"{parsed.scheme}://{parsed.netloc}" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("origin must be one exact pathless origin")
        if not all(type(value) is str and value for value in (workspace_id, runner_id)):
            raise ValueError("workspace and runner IDs are required")
        if not isinstance(runtime, RunnerRuntimeState):
            raise TypeError("authenticated runner runtime state is required")
        if (
            runtime.identity.workspace_id != workspace_id
            or runtime.identity.runner_id != runner_id
            or runtime.identity.key_id != signer.key_id
            or runtime.signer is not signer
        ):
            raise ValueError("runner runtime state identity binding is invalid")
        self.origin, self.workspace_id, self.runner_id = origin, workspace_id, runner_id
        self.signer, self.clock, self.transport, self.nonce_source = signer, clock, transport, nonce_source
        self.runtime = runtime
        self.resync_random_source = resync_random_source
        if trusted_disclosure_keys is not None and not isinstance(
            trusted_disclosure_keys, Mapping,
        ):
            raise ValueError("trusted disclosure keys must be a mapping")
        self._trusted_disclosure_keys = MappingProxyType(
            dict(trusted_disclosure_keys or {})
        )
        self._chains: dict[str, tuple[str, int, int]] = {}
        claim_cursor = runtime.load_chain("claim", None)
        if claim_cursor is not None:
            self._chains["claim"] = (
                claim_cursor.next_nonce_b64, claim_cursor.next_sequence, claim_cursor.generation,
            )
        self._state_lock = threading.Lock()
        self._claim_lock = threading.Lock()
        self._run_guards: dict[str, _RunGuard] = {}
        self._tracked_runs: set[str] = set()
        self._terminal_runs: set[str] = set()
        self._terminal_bindings: dict[str, tuple[str, str, str, str]] = {}
        self._context_receipt_client_instance = object()
        self._rollover_receipts: dict[bytes, _RunnerContextRolloverReceipt] = {}
        self._calls: deque[_CallDiagnostic] = deque(maxlen=_MAX_CALL_DIAGNOSTICS)
        self._calls_dropped = 0

    @property
    def calls(self) -> list[_CallDiagnostic]:
        """A fresh, chronological bounded diagnostic snapshot with no request material."""
        with self._state_lock:
            return list(self._calls)

    @property
    def calls_dropped(self) -> int:
        with self._state_lock:
            return self._calls_dropped

    def _append_call_diagnostic_locked(self, operation: str, status: int, call: _Call) -> None:
        if operation not in _CALL_DIAGNOSTIC_OPERATIONS:
            raise RuntimeError("invalid runner control diagnostic operation")
        if len(self._calls) == _MAX_CALL_DIAGNOSTICS:
            self._calls_dropped += 1
        self._calls.append(_CallDiagnostic(
            operation=operation, status=status, sequence=call.sequence, generation=call.generation,
        ))

    @staticmethod
    def _chain(operation: str, run_id: str | None) -> str:
        return "claim" if operation == "claim" else f"{operation}:{run_id}"

    @staticmethod
    def _validate_chain(operation: str, run_id: str | None) -> None:
        if operation == "claim":
            if run_id is not None: raise ValueError("claim chain must not have a run ID")
        elif operation in _RUN_OPERATIONS:
            if type(run_id) is not str or not run_id: raise ValueError("run ID is required")
        else: raise ValueError("invalid runner chain operation")

    def _next_chain(self, operation: str, run_id: str | None) -> tuple[str, int, int, str]:
        self._validate_chain(operation, run_id)
        chain = self._chain(operation, run_id)
        if operation != "claim":
            with self._state_lock:
                if run_id not in self._tracked_runs:
                    raise ValueError("active runner claim is required")
        current = self._chains.get(chain)
        if current is None:
            raise ValueError("active runner claim is required")
        return current[0], current[1], current[2], chain

    def _control_path(self, operation: str, run_id: str | None) -> str:
        if operation == "claim": return f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/claim"
        self._validate_chain(operation, run_id)
        return f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/runs/{run_id}/{operation}"

    def _timestamp(self) -> int:
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0: raise ValueError("runner clock must return a non-negative integer timestamp")
        return value

    def _signature(self, payload: bytes) -> str:
        signature = self.signer.sign(payload)
        if not isinstance(signature, bytes) or len(signature) != 64: raise ValueError("runner signer returned an invalid Ed25519 signature")
        return base64.b64encode(signature).decode("ascii")

    def _headers(self, signature: str, timestamp_ms: int, *, nonce: str | None = None, sequence: int | None = None) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "X-Heel-Runner-Id": self.runner_id, "X-Heel-Runner-Key-Id": self.signer.key_id, "X-Heel-Runner-Timestamp-Ms": str(timestamp_ms), "X-Heel-Runner-Signature": signature}
        if nonce is not None:
            headers["X-Heel-Runner-Nonce"] = nonce; headers["X-Heel-Runner-Sequence"] = str(sequence)
        return headers

    def _post_closed(
        self, call: _Call, operation: str, run_id: str | None,
        *, upload_binding: tuple[dict[str, Any], dict[str, Any], int, int] | None = None,
        projection_binding: tuple[str, str, str, str] | None = None,
        guard_token: object | None = None,
        include_response_metadata: bool = False,
        runtime_pending: object | None = None,
        runtime_disclosure_lease: object | None = None,
    ):
        """Decode one closed coordinator response before atomically advancing any cursor."""
        response = self.transport.post(call.path, headers=call.headers, body=call.body)
        if (
            not isinstance(response, tuple) or len(response) != 3
            or isinstance(response[0], bool) or not isinstance(response[0], int)
            or not isinstance(response[1], dict)
            or any(type(key) is not str or type(value) is not str
                   for key, value in response[1].items())
        ):
            raise ValueError("invalid runner control response")
        status, headers, body = response
        next_nonce = headers.get("X-Heel-Runner-Next-Nonce")
        if not self._b64_32(next_nonce):
            raise ValueError("invalid runner control response")
        run_states: dict[str, tuple[str, int, int]] = {}
        if operation == "claim":
            body, run_states = self._decode_claim(status, body)
        elif operation == "heartbeat":
            if status != 200:
                raise ValueError("invalid runner heartbeat response")
            body = self._decode_gate(body, "invalid runner heartbeat response")
        elif operation in {"progress", "result"}:
            if status != 200:
                raise ValueError(f"invalid runner {operation} response")
            body = self._decode_status(body, run_id, operation)
            if projection_binding is None or body["grant_id"] != projection_binding[2]:
                raise ValueError(f"invalid runner {operation} response")
        elif operation == "stop-ack":
            if (
                status != 200 or not isinstance(body, dict)
                or set(body) != {"accepted", "deadline_met", "late"}
                or any(type(body[field]) is not bool for field in body)
                or body["accepted"] is not True
                or body["deadline_met"] is body["late"]
            ):
                raise ValueError("invalid runner stop acknowledgement response")
            body = dict(body)
        elif operation == "upload-findings":
            if status != 200:
                raise ValueError("invalid runner findings receipt")
            body = self._decode_findings_receipt(body, run_id)
            if upload_binding is None:
                raise ValueError("invalid runner findings receipt")
            permit_value, findings, projection_bytes, finding_count = upload_binding
            if (
                body["project_id"] != permit_value["project_id"]
                or body["grant_id"] != permit_value["grant_id"]
                or body["permit_id"] != permit_value["permit_id"]
                or body["projection_id"] != findings["projection_id"]
                or body["projection_digest"] != findings["projection_digest"]
                or body["byte_count"] != projection_bytes
                or body["scenario_count"] != len(findings["scenario_results"])
                or body["finding_count"] != finding_count
            ):
                raise ValueError("invalid runner findings receipt")
        else:
            raise ValueError("invalid runner control operation")

        if runtime_pending is not None:
            installed = ()
            if operation == "claim" and body is not None:
                installed = tuple(
                    (name, body["run_id"], *run_states[self._chain(name, body["run_id"])])
                    for name in ("heartbeat", "progress", "result", "stop-ack")
                )
            try:
                if operation == "result" and body["status"] == "terminal":
                    self.runtime.commit_terminal_response(
                        runtime_pending.call_id, next_nonce_b64=next_nonce,
                        now_ms=self._timestamp(),
                    )
                elif operation == "upload-findings":
                    if runtime_disclosure_lease is None or upload_binding is None:
                        raise ValueError("runtime disclosure lease is required")
                    permit_value, findings, _projection_bytes, _finding_count = upload_binding
                    self.runtime.commit_disclosure(
                        runtime_pending.call_id, runtime_disclosure_lease,
                        next_nonce_b64=next_nonce, permit_id=permit_value["permit_id"],
                        findings_projection_digest=findings["projection_digest"],
                        receipt_digest=hashlib.sha256(canonical_bytes(body)).hexdigest(),
                        disclosed_at_ms=body["accepted_at_ms"],
                    )
                else:
                    self.runtime.commit_call(
                        runtime_pending.call_id, next_nonce_b64=next_nonce,
                        now_ms=self._timestamp(), installed_chains=installed,
                    )
            except (TypeError, ValueError) as exc:
                raise ValueError("runner runtime state did not commit control response") from exc

        with self._state_lock:
            if operation not in {"claim", "upload-findings"}:
                guard = self._run_guards.get(run_id)
                if (
                    guard is None or guard.token is not guard_token
                    or run_id not in self._tracked_runs
                ):
                    raise ValueError("active runner claim is required")
            staged = dict(self._chains)
            if operation == "upload-findings":
                self._append_call_diagnostic_locked(operation, status, call)
                if include_response_metadata:
                    return body, status, dict(headers)
                return body
            current = staged.get(call.chain)
            expected = (
                call.headers["X-Heel-Runner-Nonce"], call.sequence, call.generation,
            )
            if (operation != "claim" and current != expected) or (
                operation == "claim" and current is not None and current != expected
            ):
                raise ValueError("runner control chain changed during request")
            staged[call.chain] = (next_nonce, call.sequence + 1, call.generation)
            if operation == "claim" and body is not None:
                claimed_run_id = body["run_id"]
                if (
                    claimed_run_id in self._tracked_runs
                    or claimed_run_id in self._terminal_runs
                    or claimed_run_id in self._terminal_bindings
                    or any(name.endswith(":" + claimed_run_id) for name in staged)
                ):
                    raise ValueError("runner returned an already active claim")
                if len(self._tracked_runs) >= _MAX_TRACKED_RUNS:
                    raise ValueError("active runner claim capacity is exhausted")
                for chain_name, state in run_states.items():
                    self._stage_chain(staged, chain_name, state)
                self._tracked_runs.add(claimed_run_id)
                self._run_guards[claimed_run_id] = _RunGuard(threading.Lock(), object())
            else:
                for chain_name, state in run_states.items():
                    self._stage_chain(staged, chain_name, state)
            if operation == "result" and body["status"] == "terminal":
                if run_id not in self._tracked_runs or projection_binding is None:
                    raise ValueError("active runner claim is required")
                for retired_operation in ("heartbeat", "progress", "result", "stop-ack"):
                    staged.pop(self._chain(retired_operation, run_id), None)
                self._tracked_runs.discard(run_id)
                self._terminal_runs.discard(run_id)
                self._terminal_bindings.pop(run_id, None)
                if self._run_guards.get(run_id) is not None and self._run_guards[run_id].token is guard_token:
                    self._run_guards.pop(run_id, None)
            self._chains = staged
            self._append_call_diagnostic_locked(operation, status, call)
        if include_response_metadata:
            return body, status, dict(headers)
        return body

    @contextmanager
    def _run_guard(self, run_id: str):
        """Serialize every control/resync/findings action for one live run."""
        with self._state_lock:
            guard = self._run_guards.get(run_id)
            if guard is None or run_id not in self._tracked_runs:
                raise ValueError("active runner claim is required")
        with guard.lock:
            with self._state_lock:
                if self._run_guards.get(run_id) is not guard or run_id not in self._tracked_runs:
                    raise ValueError("active runner claim is required")
            yield guard.token

    @staticmethod
    def _stage_chain(
        states: dict[str, tuple[str, int, int]],
        chain_name: str,
        state: tuple[str, int, int],
    ) -> None:
        current = states.get(chain_name)
        if current is not None:
            if state[2] < current[2] or (state[2] == current[2] and state != current):
                raise ValueError("runner chain generation did not advance")
            if state[2] == current[2]:
                return
        states[chain_name] = state

    def _decode_claim(
        self, status: int, body: object,
    ) -> tuple[dict[str, Any] | None, dict[str, tuple[str, int, int]]]:
        if status == 204 and body is None:
            return None, {}
        fields = {
            "schema_version", "run_id", "approval_projection", "grant",
            "chain_states", "gate",
        }
        if status != 200 or not isinstance(body, dict) or set(body) != fields:
            raise ValueError("invalid runner claim response")
        try:
            projection = validate_approval_projection(body["approval_projection"])
            grant = validate_execution_grant(body["grant"])
        except (TypeError, ValueError):
            raise ValueError("invalid runner claim response") from None
        run_id = body["run_id"]
        if (
            body["schema_version"] != "heel.runner-claim-response.v1"
            or type(run_id) is not str or not run_id
            or run_id != grant["run_id"]
            or projection["workspace_id"] != self.workspace_id
            or grant["workspace_id"] != self.workspace_id
            or projection["project_id"] != grant["project_id"]
            or projection["runner"]["runner_id"] != self.runner_id
            or projection["runner"]["runner_key_id"] != self.signer.key_id
            or grant["runner_binding"]["runner_id"] != self.runner_id
            or grant["runner_binding"]["runner_key_id"] != self.signer.key_id
            or grant["approval"] != {
                "projection_id": projection["projection_id"],
                "projection_digest": projection["projection_digest"],
                "manifest_digest": projection["manifest_digest"],
            }
        ):
            raise ValueError("invalid runner claim response")
        try:
            self._verify_projection_signature(projection)
        except (TypeError, ValueError):
            raise ValueError("invalid runner claim response") from None
        gate = self._decode_gate(body["gate"], "invalid runner claim response")
        if (
            gate["active"] is not True or gate["runner_state"] != "active"
            or gate["proof_state"] != "valid" or gate["stop_reason"] != "none"
            or gate["proof_expires_at_ms"] <= gate["server_time_ms"]
            or gate["kill_switch_generation"] != grant["kill_switch_generation"]
        ):
            raise ValueError("invalid runner claim response")
        chains = body["chain_states"]
        if not isinstance(chains, dict) or set(chains) != _RUN_OPERATIONS:
            raise ValueError("invalid runner claim response")
        states: dict[str, tuple[str, int, int]] = {}
        for operation, value in chains.items():
            if (
                not isinstance(value, dict)
                or set(value) != {"next_nonce_b64", "next_sequence", "generation"}
                or not self._b64_32(value["next_nonce_b64"])
                or not self._positive_int(value["next_sequence"])
                or not self._generation(value["generation"])
            ):
                raise ValueError("invalid runner claim response")
            states[self._chain(operation, run_id)] = (
                value["next_nonce_b64"], value["next_sequence"], value["generation"],
            )
        return {
            "schema_version": body["schema_version"], "run_id": run_id,
            "approval_projection": projection, "grant": grant,
            "chain_states": {
                operation: dict(chains[operation]) for operation in sorted(chains)
            },
            "gate": gate,
        }, states

    @staticmethod
    def _decode_gate(body: object, error: str) -> dict[str, Any]:
        if not isinstance(body, dict) or set(body) != _GATE_FIELDS:
            raise ValueError(error)
        if (
            type(body["active"]) is not bool
            or body["runner_state"] not in {"active", "revoked", "replaced"}
            or body["proof_state"] not in {"valid", "expired", "revoked"}
            or body["stop_reason"] not in _STOPS
            or any(isinstance(body[field], bool) or not isinstance(body[field], int)
                   or body[field] < 0 for field in (
                       "proof_expires_at_ms", "kill_switch_generation", "server_time_ms",
                   ))
        ):
            raise ValueError(error)
        return dict(body)

    def _decode_findings_receipt(
        self, body: object, run_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(body, dict) or set(body) != _FINDINGS_RECEIPT_FIELDS:
            raise ValueError("invalid runner findings receipt")
        if (
            body["schema_version"] != "heel.canary-findings-receipt.v1"
            or body["workspace_id"] != self.workspace_id
            or body["run_id"] != run_id
            or any(type(body[field]) is not str or not body[field] for field in (
                "receipt_id", "workspace_id", "project_id", "run_id", "grant_id",
                "permit_id", "projection_id",
            ))
            or not (
                type(body["projection_digest"]) is str
                and len(body["projection_digest"]) == 64
                and all(char in "0123456789abcdef" for char in body["projection_digest"])
            )
            or any(isinstance(body[field], bool) or not isinstance(body[field], int)
                   or body[field] < 0 for field in (
                       "byte_count", "scenario_count", "finding_count", "accepted_at_ms",
                   ))
            or body["byte_count"] > 256 * 1024
            or body["scenario_count"] > 4
            or body["finding_count"] > body["scenario_count"]
            or body["status"] != "synchronized"
        ):
            raise ValueError("invalid runner findings receipt")
        return dict(body)

    @staticmethod
    def _decode_status(body: object, run_id: str | None, operation: str) -> dict[str, Any]:
        error = f"invalid runner {operation} response"
        if not isinstance(body, dict) or set(body) != _STATUS_FIELDS:
            raise ValueError(error)
        integers = ("source_event_sequence", "kill_switch_generation", "stop_generation")
        optional_integers = ("stop_deadline_ms", "stop_acknowledged_at_ms")
        if (
            body["schema_version"] != "heel.canary-run-status.v1"
            or body["run_id"] != run_id
            or any(type(body[field]) is not str or not body[field]
                   for field in ("run_id", "approval_id", "grant_id"))
            or body["status"] not in _RUN_STATUSES
            or (body["execution_disposition"] is not None
                and body["execution_disposition"] not in _DISPOSITIONS)
            or (body["status"] == "terminal") != (body["execution_disposition"] is not None)
            or body["error_category"] not in _ERRORS
            or body["stop_reason"] not in _STOPS
            or body["quota_state"] not in {
                "unreserved", "reserved", "consumed", "refunded", "compensated",
            }
            or any(isinstance(body[field], bool) or not isinstance(body[field], int)
                   or body[field] < (-1 if field == "source_event_sequence" else 0)
                   for field in integers)
            or any(value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ) for value in (body[field] for field in optional_integers))
            or type(body["stop_ack_late"]) is not bool
        ):
            raise ValueError(error)
        return dict(body)

    def _closed_control_locked(
        self, operation: str, run_id: str | None,
        operational_projection: object | None = None,
        *, guard_token: object | None = None, include_response_metadata: bool = False,
    ):
        projection_binding = None
        if operation == "claim":
            with self._state_lock:
                if len(self._tracked_runs) >= _MAX_TRACKED_RUNS:
                    raise ValueError("active runner claim capacity is exhausted")
            request = validate_runner_claim_request({
                "schema_version": "heel.runner-claim-request.v1",
            })
        else:
            self._validate_chain(operation, run_id)
            request = _REQUEST_VALIDATORS[operation]({
                "schema_version": f"heel.runner-{operation}-request.v1",
                "run_id": run_id,
                "operational_projection": operational_projection,
            })
            self._verify_projection_signature(request["operational_projection"])
            projection = request["operational_projection"]
            projection_binding = (
                projection["workspace_id"], projection["project_id"],
                projection["grant_id"], projection["approval_projection_digest"],
            )
        nonce, sequence, generation, chain = self._next_chain(operation, run_id)
        path, body, timestamp_ms = (
            self._control_path(operation, run_id), canonical_bytes(request), self._timestamp()
        )
        proof = {
            "schema_version": "heel.runner-request-proof.v1", "workspace_id": self.workspace_id,
            "runner_id": self.runner_id, "key_id": self.signer.key_id,
            "capability": _CAPS[operation], "method": "POST", "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
            "server_nonce": nonce, "sequence": sequence,
        }
        call = _Call(
            path,
            self._headers(
                self._signature(b"heel.runner-pop.v1\0" + canonical_bytes(proof)),
                timestamp_ms, nonce=nonce, sequence=sequence,
            ),
            body, _CAPS[operation], chain, sequence, generation,
        )
        runtime_cursor = self.runtime.load_chain(operation, run_id)
        if runtime_cursor is None:
            raise ValueError("active runner claim is required")
        if runtime_cursor is not None and (
            runtime_cursor.next_nonce_b64, runtime_cursor.next_sequence, runtime_cursor.generation,
        ) != (nonce, sequence, generation):
            raise ValueError("runner runtime state chain differs from control client")
        try:
            runtime_pending = self.runtime.stage_call(
                request_operation=operation, chain_operation=operation, run_id=run_id,
                path=path, capability=_CAPS[operation], headers=call.headers, body=body,
                expected_state_digest=runtime_cursor.state_digest,
                now_ms=timestamp_ms,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("runner runtime state did not stage control call") from exc
        return self._post_closed(
            call, operation, run_id, projection_binding=projection_binding,
            guard_token=guard_token,
            include_response_metadata=include_response_metadata,
            runtime_pending=runtime_pending,
        )

    def _closed_control(
        self, operation: str, run_id: str | None,
        operational_projection: object | None = None,
        *, include_response_metadata: bool = False,
        before_transport: Callable[[], None] | None = None,
    ):
        self._validate_chain(operation, run_id)
        if operation == "claim":
            with self._claim_lock:
                return self._closed_control_locked(
                    operation, run_id, operational_projection,
                    include_response_metadata=include_response_metadata,
                )
        with self._run_guard(run_id) as guard_token:
            if operation == "result":
                with self._state_lock:
                    if run_id in self._terminal_runs:
                        raise ValueError("terminal runner result is already recorded")
            if before_transport is not None:
                before_transport()
            with self._state_lock:
                guard = self._run_guards.get(run_id)
                if (
                    guard is None or guard.token is not guard_token
                    or run_id not in self._tracked_runs
                ):
                    raise ValueError("active runner claim is required")
            return self._closed_control_locked(
                operation, run_id, operational_projection,
                guard_token=guard_token,
                include_response_metadata=include_response_metadata,
            )

    def _claim_closed(self):
        return self._closed_control("claim", None)

    def _context_control(
        self, path: str, request: dict, *, expected_status: int, schema: str,
        diagnostic_operation: str,
        include_call: bool = False,
    ) -> dict | tuple[dict, _Call]:
        """Use the existing claim PoP chain for the three fixed pairing-only calls."""
        with self._claim_lock:
            nonce, sequence, generation, chain = self._next_chain("claim", None)
            body, timestamp_ms = canonical_bytes(request), self._timestamp()
            proof = {
                "schema_version": "heel.runner-request-proof.v1", "workspace_id": self.workspace_id,
                "runner_id": self.runner_id, "key_id": self.signer.key_id,
                "capability": "runner_claim", "method": "POST", "path": path,
                "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
                "server_nonce": nonce, "sequence": sequence,
            }
            headers = self._headers(
                self._signature(b"heel.runner-pop.v1\0" + canonical_bytes(proof)), timestamp_ms,
                nonce=nonce, sequence=sequence,
            )
            response = self.transport.post(path, headers=headers, body=body)
            if (not isinstance(response, tuple) or len(response) != 3 or response[0] != expected_status
                    or not isinstance(response[1], dict) or not isinstance(response[2], dict)
                    or set(response[2]) == set() or response[2].get("schema_version") != schema):
                raise ValueError("invalid runner context response")
            payload = response[2]
            try:
                if schema == "heel.runner-context-list-result.v1":
                    if set(payload) != {"schema_version", "server_time_ms", "contexts", "has_more"}:
                        raise ValueError
                    if type(payload["server_time_ms"]) is not int or payload["server_time_ms"] < 0 or type(payload["has_more"]) is not bool:
                        raise ValueError
                    contexts = payload["contexts"]
                    if not isinstance(contexts, list) or len(contexts) > 16:
                        raise ValueError
                    for item in contexts:
                        if not isinstance(item, dict) or set(item) != {"binding_id", "binding_digest", "project_id", "environment_id", "origin", "environment_class", "verification_record_digest", "expires_at_ms", "claimed"}:
                            raise ValueError
                        validate_runner_context_claim({"schema_version": "heel.runner-context-claim.v1", "binding_id": item["binding_id"], "binding_digest": item["binding_digest"]})
                        if (type(item["project_id"]) is not str or not item["project_id"] or type(item["environment_id"]) is not str or not item["environment_id"]
                                or type(item["origin"]) is not str or not item["origin"] or item["environment_class"] not in {"staging", "sandbox"}
                                or type(item["verification_record_digest"]) is not str or len(item["verification_record_digest"]) != 64
                                or type(item["expires_at_ms"]) is not int or item["expires_at_ms"] < 0 or type(item["claimed"]) is not bool):
                            raise ValueError
                elif schema == "heel.runner-context-claim-result.v1":
                    if set(payload) != {"schema_version", "context_binding", "claimed_at_ms"} or type(payload["claimed_at_ms"]) is not int or payload["claimed_at_ms"] < 0:
                        raise ValueError
                    binding = validate_runner_context_binding(payload["context_binding"])
                    if (binding["workspace_id"] != self.workspace_id or binding["runner_binding"]["runner_id"] != self.runner_id
                            or binding["runner_binding"]["runner_key_id"] != self.signer.key_id
                            or binding["binding_id"] != request["binding_id"] or binding["binding_digest"] != request["binding_digest"]):
                        raise ValueError
                elif schema == "heel.canary-projection-submitted.v1":
                    if set(payload) != {"schema_version", "approval_id", "run_id", "status", "projection_digest"} or payload["status"] not in {"awaiting_execution_approval", "approved", "cancelled", "expired"}:
                        raise ValueError
                    submitted = request["approval_projection"]
                    if (type(payload["approval_id"]) is not str or payload["approval_id"] != submitted["projection_id"]
                            or type(payload["projection_digest"]) is not str or payload["projection_digest"] != submitted["projection_digest"]
                            or type(payload["run_id"]) is not str or re.fullmatch(r"crun_[0-9a-f]{32}", payload["run_id"]) is None):
                        raise ValueError
            except (KeyError, TypeError, ValueError):
                raise ValueError("invalid runner context response") from None
            next_nonce = response[1].get("X-Heel-Runner-Next-Nonce")
            if not self._b64_32(next_nonce):
                raise ValueError("invalid runner context response")
            call = _Call(path, headers, body, "runner_claim", chain, sequence, generation)
            with self._state_lock:
                current = self._chains.get(chain)
                if current is not None and current != (nonce, sequence, generation):
                    raise ValueError("runner control chain changed during request")
                self._chains[chain] = (next_nonce, sequence + 1, generation)
                self._append_call_diagnostic_locked(diagnostic_operation, response[0], call)
            payload = dict(response[2])
            return (payload, call) if include_call else payload

    def list_contexts(self) -> dict:
        request = validate_runner_context_list({"schema_version": "heel.runner-context-list.v1"})
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/list",
            request, expected_status=200, schema="heel.runner-context-list-result.v1", diagnostic_operation="list-contexts",
        )

    def claim_context(self, binding_id: str, binding_digest: str) -> dict:
        request = validate_runner_context_claim({"schema_version": "heel.runner-context-claim.v1", "binding_id": binding_id, "binding_digest": binding_digest})
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/{binding_id}/claim",
            request, expected_status=200, schema="heel.runner-context-claim-result.v1", diagnostic_operation="claim-context",
        )

    @staticmethod
    def _context_call_digest(call: _Call) -> str:
        return hashlib.sha256(canonical_bytes({
            "path": call.path, "body_sha256": hashlib.sha256(call.body).hexdigest(),
            "headers": call.headers, "chain": call.chain, "sequence": call.sequence,
            "generation": call.generation,
        })).hexdigest()

    def _claim_single_context_for_rollover(
        self, old_binding_id: str, old_binding_digest: str,
    ) -> tuple[dict, _RunnerContextRolloverReceipt] | None | bool:
        """Produce a private receipt only from this fresh authenticated list→claim pair."""
        listed_request = validate_runner_context_list({"schema_version": "heel.runner-context-list.v1"})
        listed, list_call = self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/list",
            listed_request, expected_status=200, schema="heel.runner-context-list-result.v1", diagnostic_operation="list-contexts", include_call=True,
        )
        contexts = listed["contexts"]
        if len(contexts) == 0:
            return None
        if len(contexts) != 1 or listed["has_more"]:
            raise ValueError("ambiguous cloud runner contexts")
        item = contexts[0]
        if (item["binding_id"], item["binding_digest"]) == (old_binding_id, old_binding_digest):
            return False
        claim_request = validate_runner_context_claim({
            "schema_version": "heel.runner-context-claim.v1", "binding_id": item["binding_id"],
            "binding_digest": item["binding_digest"],
        })
        claimed, claim_call = self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/{item['binding_id']}/claim",
            claim_request, expected_status=200, schema="heel.runner-context-claim-result.v1", diagnostic_operation="claim-context", include_call=True,
        )
        binding = validate_runner_context_binding(claimed["context_binding"])
        environment = binding["environment"]
        if (
            binding["binding_id"] != item["binding_id"]
            or binding["binding_digest"] != item["binding_digest"]
            or binding["project_id"] != item["project_id"]
            or environment["environment_id"] != item["environment_id"]
            or environment["origin"] != item["origin"]
            or environment["environment_class"] != item["environment_class"]
            or environment["verification_record_digest"] != item["verification_record_digest"]
            or binding["expires_at_ms"] != item["expires_at_ms"]
        ):
            raise ValueError("invalid runner context rollover claim")
        receipt = _RunnerContextRolloverReceipt(
            _ROLLOVER_RECEIPT_CONSTRUCTOR,
            client_instance=self._context_receipt_client_instance,
            evidence={
                "old_binding_id": old_binding_id, "old_binding_digest": old_binding_digest,
                "new_binding_id": binding["binding_id"], "new_binding_digest": binding["binding_digest"],
                "observed_server_time_ms": listed["server_time_ms"],
                "list_request_digest": self._context_call_digest(list_call),
                "claim_request_digest": self._context_call_digest(claim_call),
                "list_generation": list_call.generation, "claim_generation": claim_call.generation,
            },
        )
        self._rollover_receipts[receipt._receipt_id] = receipt
        return claimed, receipt

    def _bind_rollover_receipt_to_store(self, receipt: object, store: object) -> None:
        if (
            not isinstance(receipt, _RunnerContextRolloverReceipt)
            or receipt._client_instance is not self._context_receipt_client_instance
            or self._rollover_receipts.get(receipt._receipt_id) is not receipt
        ):
            raise ValueError("runner context rollover receipt belongs to another control client")
        receipt._bind_store(store)
        with _ROLLOVER_RECEIPT_REGISTRY_LOCK:
            _ROLLOVER_RECEIPT_REGISTRY[receipt._receipt_id] = (self, receipt, store)

    def _discard_rollover_receipt(self, receipt: object, store: object) -> None:
        """Idempotently drop a genuine receipt after every coordinator install attempt."""
        if not isinstance(receipt, _RunnerContextRolloverReceipt):
            return
        with _ROLLOVER_RECEIPT_REGISTRY_LOCK:
            registered = _ROLLOVER_RECEIPT_REGISTRY.get(receipt._receipt_id)
            if registered is not None and registered[0] is self and registered[1] is receipt and registered[2] is store:
                _ROLLOVER_RECEIPT_REGISTRY.pop(receipt._receipt_id, None)
            self._rollover_receipts.pop(receipt._receipt_id, None)

    def submit_context_approval_projection(self, binding_id: str, binding_digest: str, approval_projection: object) -> dict:
        request = validate_runner_approval_projection_submit({
            "schema_version": "heel.runner-approval-projection-submit.v1",
            "context_binding_id": binding_id, "context_binding_digest": binding_digest,
            "approval_projection": approval_projection,
        })
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/{binding_id}/approval-projections",
            request, expected_status=201, schema="heel.canary-projection-submitted.v1", diagnostic_operation="submit-context-approval-projection",
        )

    def _heartbeat_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("heartbeat", run_id, operational_projection)

    def _progress_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("progress", run_id, operational_projection)

    def _result_closed(
        self, run_id: str, operational_projection: object,
        *, before_transport: Callable[[], None] | None = None,
    ):
        return self._closed_control(
            "result", run_id, operational_projection, before_transport=before_transport,
        )

    def _register_runtime_local_terminal(self, anchor: object):
        """Persist the store-verified terminal anchor before its result request.

        This is intentionally a coordinator-only bridge: a terminal result may
        retire its live chains only after the signed local run authority has
        supplied every immutable disclosure field.
        """
        fields = {
            "run_id", "project_id", "grant_id", "approval_projection_digest",
            "terminal_projection_digest", "terminal_record_digest", "terminal_at_ms",
            "retention_expires_at_ms",
        }
        if not isinstance(anchor, dict) or set(anchor) != fields:
            raise ValueError("local terminal runtime authority is invalid")
        try:
            return self.runtime.register_local_terminal(**anchor)
        except (TypeError, ValueError) as exc:
            raise ValueError("local terminal runtime authority is invalid") from exc

    def _stop_ack_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("stop-ack", run_id, operational_projection)

    def _upload_findings_closed(
        self, *, run_id: str, permit: object, findings_projection: object,
    ):
        try:
            permit_value = validate_disclosure_permit(permit)
            findings = validate_canary_findings(findings_projection)
        except (TypeError, ValueError):
            raise ValueError("invalid runner findings upload") from None
        projection_bytes = canonical_bytes(findings)
        finding_count = sum(
            item["finding"] is not None for item in findings["scenario_results"]
        )
        if (
            permit_value["workspace_id"] != self.workspace_id
            or permit_value["run_id"] != run_id
            or findings["workspace_id"] != self.workspace_id
            or findings["run_id"] != run_id
            or findings["project_id"] != permit_value["project_id"]
            or findings["grant_id"] != permit_value["grant_id"]
            or permit_value["runner_binding"] != {
                "runner_id": self.runner_id, "runner_key_id": self.signer.key_id,
            }
            or permit_value["projection"] != {
                "schema_version": findings["schema_version"],
                "projection_digest": findings["projection_digest"],
                "maximum_bytes": len(projection_bytes),
                "scenario_count": len(findings["scenario_results"]),
                "finding_count": finding_count,
            }
        ):
            raise ValueError("invalid runner findings upload")
        try:
            self._verify_projection_signature(findings)
        except (TypeError, ValueError):
            raise ValueError("invalid runner findings upload") from None
        request = {
            "schema_version": "heel.runner-findings-upload.v1", "run_id": run_id,
            "permit": permit_value, "findings_projection": findings,
        }
        body = canonical_bytes(request)
        if len(body) > _MAX_FINDINGS_UPLOAD_BYTES:
            raise ValueError("invalid runner findings upload")
        pending = tuple(
            item for item in self.runtime.load_pending_calls()
            if item.chain_operation == "result" and item.run_id == run_id
        )
        if pending:
            if len(pending) != 1 or pending[0].request_operation != "upload-findings":
                raise ValueError("terminal runner result is required before disclosure")
            return self._replay_pending_disclosure(
                pending[0], permit_value=permit_value, findings=findings,
                projection_bytes=len(projection_bytes), finding_count=finding_count,
                expected_body=body,
            )
        timestamp_ms = self._timestamp()
        unsigned_permit = {
            key: value for key, value in permit_value.items()
            if key not in {"permit_digest", "signing_key_id", "signature_b64"}
        }
        if not permit_value["issued_at_ms"] <= timestamp_ms < permit_value["expires_at_ms"]:
            raise ValueError("disclosure permit is expired or not yet valid")
        try:
            verify_envelope(
                dict(self._trusted_disclosure_keys),
                {
                    "signing_key_id": permit_value["signing_key_id"],
                    "signature_b64": permit_value["signature_b64"],
                },
                canonical_bytes(unsigned_permit),
            )
        except (TypeError, ValueError):
            raise ValueError("invalid disclosure permit authority") from None
        try:
            disclosure_lease = self.runtime.lease_terminal_disclosure(
                run_id, expected_project_id=permit_value["project_id"],
                expected_grant_id=permit_value["grant_id"],
                expected_approval_projection_digest=findings["approval_projection_digest"],
                now_ms=timestamp_ms,
            )
            cursor = self.runtime._disclosure_result_cursor(disclosure_lease)
        except (TypeError, ValueError) as exc:
            raise ValueError("terminal runner result is required before disclosure") from exc
        nonce, sequence, generation = (
            cursor["next_nonce_b64"], cursor["next_sequence"], cursor["generation"],
        )
        path = (
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/runs/"
            f"{run_id}/result-projection"
        )
        proof = {
            "schema_version": "heel.runner-request-proof.v1",
            "workspace_id": self.workspace_id, "runner_id": self.runner_id,
            "key_id": self.signer.key_id, "capability": "runner_result",
            "method": "POST", "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp_ms": timestamp_ms, "server_nonce": nonce,
            "sequence": sequence,
        }
        call = _Call(
            path,
            self._headers(
                self._signature(b"heel.runner-pop.v1\0" + canonical_bytes(proof)),
                timestamp_ms, nonce=nonce, sequence=sequence,
            ),
            body, "runner_result", self._chain("result", run_id), sequence, generation,
        )
        try:
            runtime_pending = self.runtime.stage_disclosure_call(
                disclosure_lease, path=path, headers=call.headers, body=body,
                now_ms=timestamp_ms,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("terminal runner result is required before disclosure") from exc
        return self._post_closed(
            call, "upload-findings", run_id,
            upload_binding=(permit_value, findings, len(projection_bytes), finding_count),
            runtime_pending=runtime_pending, runtime_disclosure_lease=disclosure_lease,
        )

    def _replay_pending_disclosure(
        self, pending: object, *, permit_value: dict[str, Any], findings: dict[str, Any],
        projection_bytes: int, finding_count: int, expected_body: bytes,
    ) -> dict[str, Any]:
        """Replay only the sealed, byte-identical disclosure request after restart."""
        if (
            not hasattr(pending, "run_id") or pending.run_id is None
            or pending.body != expected_body or pending.request_operation != "upload-findings"
            or pending.chain_operation != "result"
        ):
            raise ValueError("terminal runner result is required before disclosure")
        try:
            decoded = json.loads(pending.body)
        except (TypeError, ValueError):
            raise ValueError("terminal runner result is required before disclosure") from None
        if canonical_bytes(decoded) != pending.body:
            raise ValueError("terminal runner result is required before disclosure")
        now_ms = self._timestamp()
        try:
            disclosure_lease = self.runtime.lease_terminal_disclosure(
                pending.run_id, expected_project_id=permit_value["project_id"],
                expected_grant_id=permit_value["grant_id"],
                expected_approval_projection_digest=findings["approval_projection_digest"],
                now_ms=now_ms,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("terminal runner result is required before disclosure") from exc
        call = _Call(
            pending.path, dict(pending.headers), pending.body, pending.capability,
            self._chain("result", pending.run_id), pending.sequence, pending.generation,
        )
        return self._post_closed(
            call, "upload-findings", pending.run_id,
            upload_binding=(permit_value, findings, projection_bytes, finding_count),
            runtime_pending=pending, runtime_disclosure_lease=disclosure_lease,
        )

    def claim(self):
        _, status, headers = self._closed_control(
            "claim", None, include_response_metadata=True,
        )
        return status, headers

    def heartbeat(self, *, run_id, operational_projection):
        _, status, headers = self._closed_control(
            "heartbeat", run_id, operational_projection,
            include_response_metadata=True,
        )
        return status, headers

    def progress(self, *, run_id, operational_projection):
        _, status, headers = self._closed_control(
            "progress", run_id, operational_projection,
            include_response_metadata=True,
        )
        return status, headers

    def result(self, *, run_id, operational_projection):
        _, status, headers = self._closed_control(
            "result", run_id, operational_projection,
            include_response_metadata=True,
        )
        return status, headers

    def stop_ack(self, *, run_id, operational_projection):
        _, status, headers = self._closed_control(
            "stop-ack", run_id, operational_projection,
            include_response_metadata=True,
        )
        return status, headers

    def upload_findings(self, *, run_id, permit, findings_projection):
        return self._upload_findings_closed(
            run_id=run_id, permit=permit, findings_projection=findings_projection,
        )

    def _verify_projection_signature(self, projection: dict[str, Any]) -> None:
        public_key = getattr(self.signer, "public_key", None)
        if (not isinstance(public_key, bytes) or len(public_key) != 32
                or self.signer.key_id != ed25519_key_id(public_key)
                or projection["signing_key_id"] != self.signer.key_id):
            raise ValueError("operational projection signing key does not match the runner")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        payload = {
            key: value for key, value in projection.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        verify_envelope(
            {self.signer.key_id: Ed25519PublicKey.from_public_bytes(public_key)},
            {"signing_key_id": projection["signing_key_id"],
             "signature_b64": projection["signature_b64"]},
            canonical_bytes(payload),
        )

    def install_rotation_claim(self, response: object) -> RunnerRotationActivated:
        fields = {
            "schema_version", "workspace_id", "runner_id", "initial_claim_nonce",
            "initial_claim_sequence", "initial_claim_generation",
        }
        if not isinstance(response, dict) or set(response) != fields:
            raise ValueError("invalid runner rotation activation response")
        if (response["schema_version"] != "heel.runner-rotation-activated.v2"
                or response["workspace_id"] != self.workspace_id
                or response["runner_id"] != self.runner_id
                or not self._b64_32(response["initial_claim_nonce"])
                or not self._positive_int(response["initial_claim_sequence"])
                or not self._generation(response["initial_claim_generation"])):
            raise ValueError("invalid runner rotation activation response")
        state = (
            response["initial_claim_nonce"], response["initial_claim_sequence"],
            response["initial_claim_generation"],
        )
        with self._claim_lock:
            try:
                self.runtime._install_rotation_claim(
                    next_nonce_b64=state[0], next_sequence=state[1], generation=state[2],
                    now_ms=self._timestamp(),
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("runner runtime state did not install rotation claim") from exc
            self._install_chain_state("claim", state)
        return RunnerRotationActivated(
            response["schema_version"], response["workspace_id"], response["runner_id"],
            response["initial_claim_nonce"], response["initial_claim_sequence"],
            response["initial_claim_generation"],
        )

    def start_resync(self, *, operation: str, run_id: str | None = None) -> PendingRunnerResync:
        self._validate_chain(operation, run_id)
        if operation == "claim":
            with self._claim_lock:
                return self._start_resync_locked(operation, run_id)
        with self._run_guard(run_id):
            return self._start_resync_locked(operation, run_id)

    def _start_resync_locked(self, operation: str, run_id: str | None) -> PendingRunnerResync:
        client_nonce, chain = self._random_b64(), {"operation": operation, "run_id": run_id}
        path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/resync/start"
        body = canonical_bytes({"schema_version": "heel.runner-resync-start.v2", "chain": chain, "client_nonce_b64": client_nonce})
        timestamp_ms = self._timestamp()
        proof = {"schema_version": "heel.runner-resync-start-proof.v2", "workspace_id": self.workspace_id, "runner_id": self.runner_id, "key_id": self.signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms}
        response = self.transport.post(path, headers=self._headers(self._signature(b"heel.runner-resync-start-pop.v2\0" + canonical_bytes(proof)), timestamp_ms), body=body)
        data = self._response_data(
            response,
            "heel.runner-resync-challenge.v2",
            {"schema_version", "challenge_id", "chain", "server_challenge_b64",
             "next_sequence", "expires_at_ms", "generation"},
        )
        challenge_id, next_sequence = data["challenge_id"], data["next_sequence"]
        expires, generation = data["expires_at_ms"], data["generation"]
        if (data["chain"] != chain or not self._b64_32(data["server_challenge_b64"])
                or type(challenge_id) is not str or not challenge_id.startswith("rrs_")
                or len(challenge_id) != 36 or not self._positive_int(next_sequence)
                or not self._positive_int(expires) or not self._generation(generation)):
            raise ValueError("invalid runner resync challenge")
        return PendingRunnerResync(
            challenge_id, operation, run_id, client_nonce, data["server_challenge_b64"],
            next_sequence, expires, generation,
        )

    def complete_resync(self, pending: PendingRunnerResync) -> RecoveredRunnerChain:
        if not isinstance(pending, PendingRunnerResync): raise ValueError("pending runner resync is required")
        self._validate_chain(pending.operation, pending.run_id)
        if pending.operation == "claim":
            with self._claim_lock:
                return self._complete_resync_locked(pending)
        with self._run_guard(pending.run_id) as guard_token:
            return self._complete_resync_locked(pending, guard_token=guard_token)

    def _complete_resync_locked(
        self, pending: PendingRunnerResync, *, guard_token: object | None = None,
    ) -> RecoveredRunnerChain:
        chain = {"operation": pending.operation, "run_id": pending.run_id}
        path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/resync/complete"
        body = canonical_bytes({"schema_version": "heel.runner-resync-complete.v2", "challenge_id": pending.challenge_id, "chain": chain, "client_nonce_b64": pending.client_nonce_b64, "server_challenge_b64": pending.server_challenge_b64, "generation": pending.generation})
        timestamp_ms = self._timestamp()
        proof = {"schema_version": "heel.runner-resync-complete-proof.v2", "workspace_id": self.workspace_id, "runner_id": self.runner_id, "key_id": self.signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms}
        response = self.transport.post(path, headers=self._headers(self._signature(b"heel.runner-resync-complete-pop.v2\0" + canonical_bytes(proof)), timestamp_ms), body=body)
        data = self._response_data(
            response,
            "heel.runner-resync-completed.v2",
            {"schema_version", "chain", "next_sequence", "next_nonce_b64",
             "expires_at_ms", "generation"},
        )
        next_sequence, expires = data["next_sequence"], data["expires_at_ms"]
        generation, next_nonce = data["generation"], data["next_nonce_b64"]
        if (data["chain"] != chain or not self._b64_32(next_nonce)
                or not self._positive_int(next_sequence) or not self._positive_int(expires)
                or not self._generation(generation) or generation != pending.generation + 1):
            raise ValueError("invalid runner resync completion")
        chain_name = self._chain(pending.operation, pending.run_id)
        recovered = (next_nonce, next_sequence, generation)
        try:
            self.runtime._commit_resync_chain(
                operation=pending.operation, run_id=pending.run_id,
                next_nonce_b64=next_nonce, next_sequence=next_sequence,
                generation=generation, now_ms=self._timestamp(),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("runner runtime state did not install resync") from exc
        self._install_chain_state(
            chain_name, recovered, run_id=pending.run_id, guard_token=guard_token,
        )
        return RecoveredRunnerChain(
            pending.operation, pending.run_id, next_nonce, next_sequence, expires, generation,
        )

    def _install_chain_state(
        self, chain_name: str, state: tuple[str, int, int], *,
        run_id: str | None = None, guard_token: object | None = None,
    ) -> None:
        with self._state_lock:
            if run_id is not None:
                guard = self._run_guards.get(run_id)
                if (
                    guard is None or guard.token is not guard_token
                    or run_id not in self._tracked_runs
                ):
                    raise ValueError("active runner claim is required")
            staged = dict(self._chains)
            if run_id is not None and staged.get(chain_name) is None:
                raise ValueError("active runner claim is required")
            self._stage_chain(staged, chain_name, state)
            self._chains = staged

    def _random_b64(self) -> str:
        raw = self.resync_random_source(32)
        if not isinstance(raw, bytes) or len(raw) != 32: raise ValueError("runner resync source must return 32 bytes")
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _positive_int(value: Any) -> bool: return not isinstance(value, bool) and isinstance(value, int) and value >= 1

    @staticmethod
    def _generation(value: Any) -> bool:
        return not isinstance(value, bool) and isinstance(value, int) and value >= 0

    @staticmethod
    def _b64_32(value: Any) -> bool:
        if type(value) is not str: return False
        try: decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError): return False
        return len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == value

    @staticmethod
    def _response_data(response: Any, schema: str, fields: set[str]) -> dict[str, Any]:
        if (not isinstance(response, tuple) or len(response) != 3
                or isinstance(response[0], bool) or not isinstance(response[0], int)
                or not 200 <= response[0] <= 299 or not isinstance(response[2], dict)
                or set(response[2]) != fields or response[2].get("schema_version") != schema):
            raise ValueError("runner resync response is invalid")
        return response[2]
