"""Fixed-route runner control and recovery client."""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping
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
_FINDINGS_RECEIPT_FIELDS = {
    "schema_version", "receipt_id", "workspace_id", "project_id", "run_id",
    "grant_id", "permit_id", "projection_id", "projection_digest", "byte_count",
    "scenario_count", "finding_count", "accepted_at_ms", "status",
}


class RunnerControlClient:
    """Emit only named closed control/recovery envelopes; no generic request API exists."""

    def __init__(self, *, origin, workspace_id, runner_id, signer, clock, transport, nonce_source,
                 resync_random_source=secrets.token_bytes,
                 trusted_disclosure_keys: Mapping[str, object] | None = None):
        parsed = urlsplit(origin)
        if origin != f"{parsed.scheme}://{parsed.netloc}" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("origin must be one exact pathless origin")
        if not all(type(value) is str and value for value in (workspace_id, runner_id)):
            raise ValueError("workspace and runner IDs are required")
        self.origin, self.workspace_id, self.runner_id = origin, workspace_id, runner_id
        self.signer, self.clock, self.transport, self.nonce_source = signer, clock, transport, nonce_source
        self.resync_random_source = resync_random_source
        if trusted_disclosure_keys is not None and not isinstance(
            trusted_disclosure_keys, Mapping,
        ):
            raise ValueError("trusted disclosure keys must be a mapping")
        self._trusted_disclosure_keys = MappingProxyType(
            dict(trusted_disclosure_keys or {})
        )
        self._chains: dict[str, tuple[str, int, int]] = {}
        self._state_lock = threading.Lock()
        self._chain_locks: dict[str, threading.Lock] = {}
        self._terminal_runs: set[str] = set()
        self._terminal_bindings: dict[str, tuple[str, str, str, str]] = {}
        self.calls: list[_Call] = []

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
        current = self._chains.get(chain)
        if current is None:
            nonce = self.nonce_source((operation, run_id))
            if type(nonce) is not str or not nonce: raise ValueError("a non-empty next nonce is required")
            # Do not persist speculative state. A malformed or rejected response must leave
            # every local cursor exactly as it was before the request.
            current = (nonce, 1, 0)
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
        include_response_metadata: bool = False,
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

        with self._state_lock:
            staged = dict(self._chains)
            current = staged.get(call.chain)
            if current is not None and current != (
                call.headers["X-Heel-Runner-Nonce"], call.sequence, call.generation,
            ):
                raise ValueError("runner control chain changed during request")
            staged[call.chain] = (next_nonce, call.sequence + 1, call.generation)
            for chain_name, state in run_states.items():
                self._stage_chain(staged, chain_name, state)
            self._chains = staged
            if operation == "result" and body["status"] == "terminal":
                self._terminal_runs.add(run_id)
                self._terminal_bindings[run_id] = projection_binding
            self.calls.append(call)
        if include_response_metadata:
            return body, status, dict(headers)
        return body

    def _operation_lock(self, operation: str, run_id: str | None) -> threading.Lock:
        chain = self._chain(operation, run_id)
        with self._state_lock:
            lock = self._chain_locks.get(chain)
            if lock is None:
                lock = threading.Lock()
                self._chain_locks[chain] = lock
            return lock

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
        *, include_response_metadata: bool = False,
    ):
        projection_binding = None
        if operation == "claim":
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
        return self._post_closed(
            call, operation, run_id, projection_binding=projection_binding,
            include_response_metadata=include_response_metadata,
        )

    def _closed_control(
        self, operation: str, run_id: str | None,
        operational_projection: object | None = None,
        *, include_response_metadata: bool = False,
    ):
        self._validate_chain(operation, run_id)
        with self._operation_lock(operation, run_id):
            return self._closed_control_locked(
                operation, run_id, operational_projection,
                include_response_metadata=include_response_metadata,
            )

    def _claim_closed(self):
        return self._closed_control("claim", None)

    def _context_control(self, path: str, request: dict, *, expected_status: int, schema: str) -> dict:
        """Use the existing claim PoP chain for the three fixed pairing-only calls."""
        with self._operation_lock("claim", None):
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
                    previous = None
                    for item in contexts:
                        if not isinstance(item, dict) or set(item) != {"binding_id", "binding_digest", "project_id", "environment_id", "origin", "environment_class", "verification_record_digest", "expires_at_ms", "claimed"}:
                            raise ValueError
                        validate_runner_context_claim({"schema_version": "heel.runner-context-claim.v1", "binding_id": item["binding_id"], "binding_digest": item["binding_digest"]})
                        if (type(item["project_id"]) is not str or not item["project_id"] or type(item["environment_id"]) is not str or not item["environment_id"]
                                or type(item["origin"]) is not str or not item["origin"] or item["environment_class"] not in {"staging", "sandbox"}
                                or type(item["verification_record_digest"]) is not str or len(item["verification_record_digest"]) != 64
                                or type(item["expires_at_ms"]) is not int or item["expires_at_ms"] < 0 or type(item["claimed"]) is not bool):
                            raise ValueError
                        order = (item["expires_at_ms"], item["binding_id"])
                        if previous is not None and order < previous:
                            raise ValueError
                        previous = order
                elif schema == "heel.runner-context-claim-result.v1":
                    if set(payload) != {"schema_version", "context_binding", "claimed_at_ms"} or type(payload["claimed_at_ms"]) is not int or payload["claimed_at_ms"] < 0:
                        raise ValueError
                    binding = validate_runner_context_binding(payload["context_binding"])
                    if binding["workspace_id"] != self.workspace_id or binding["runner_binding"]["runner_id"] != self.runner_id:
                        raise ValueError
                elif schema == "heel.canary-projection-submitted.v1":
                    if set(payload) != {"schema_version", "approval_id", "run_id", "status", "projection_digest"} or payload["status"] != "awaiting_execution_approval":
                        raise ValueError
                    if not all(type(payload[key]) is str and payload[key] for key in ("approval_id", "run_id", "projection_digest")):
                        raise ValueError
            except (KeyError, TypeError, ValueError):
                raise ValueError("invalid runner context response") from None
            next_nonce = response[1].get("X-Heel-Runner-Next-Nonce")
            if not self._b64_32(next_nonce):
                raise ValueError("invalid runner context response")
            with self._state_lock:
                current = self._chains.get(chain)
                if current is not None and current != (nonce, sequence, generation):
                    raise ValueError("runner control chain changed during request")
                self._chains[chain] = (next_nonce, sequence + 1, generation)
                self.calls.append(_Call(path, headers, body, "runner_claim", chain, sequence, generation))
            return dict(response[2])

    def list_contexts(self) -> dict:
        request = validate_runner_context_list({"schema_version": "heel.runner-context-list.v1"})
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/list",
            request, expected_status=200, schema="heel.runner-context-list-result.v1",
        )

    def claim_context(self, binding_id: str, binding_digest: str) -> dict:
        request = validate_runner_context_claim({"schema_version": "heel.runner-context-claim.v1", "binding_id": binding_id, "binding_digest": binding_digest})
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/{binding_id}/claim",
            request, expected_status=200, schema="heel.runner-context-claim-result.v1",
        )

    def submit_context_approval_projection(self, binding_id: str, binding_digest: str, approval_projection: object) -> dict:
        request = validate_runner_approval_projection_submit({
            "schema_version": "heel.runner-approval-projection-submit.v1",
            "context_binding_id": binding_id, "context_binding_digest": binding_digest,
            "approval_projection": approval_projection,
        })
        return self._context_control(
            f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/contexts/{binding_id}/approval-projections",
            request, expected_status=201, schema="heel.canary-projection-submitted.v1",
        )

    def _heartbeat_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("heartbeat", run_id, operational_projection)

    def _progress_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("progress", run_id, operational_projection)

    def _result_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("result", run_id, operational_projection)

    def _stop_ack_closed(self, run_id: str, operational_projection: object):
        return self._closed_control("stop-ack", run_id, operational_projection)

    def _upload_findings_closed(
        self, *, run_id: str, permit: object, findings_projection: object,
    ):
        self._validate_chain("result", run_id)
        with self._state_lock:
            if run_id not in self._terminal_runs:
                raise ValueError("terminal runner result is required before disclosure")
            terminal_binding = self._terminal_bindings.get(run_id)
        if terminal_binding is None:
            raise ValueError("terminal runner result is required before disclosure")
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
            or (
                permit_value["workspace_id"], permit_value["project_id"],
                permit_value["grant_id"], findings["approval_projection_digest"],
            ) != terminal_binding
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
        with self._operation_lock("result", run_id):
            timestamp_ms = self._timestamp()
            unsigned_permit = {
                key: value for key, value in permit_value.items()
                if key not in {"permit_digest", "signing_key_id", "signature_b64"}
            }
            if not (
                permit_value["issued_at_ms"] <= timestamp_ms
                < permit_value["expires_at_ms"]
            ):
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
            nonce, sequence, generation, chain = self._next_chain("result", run_id)
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
                body, "runner_result", chain, sequence, generation,
            )
            return self._post_closed(
                call, "upload-findings", run_id,
                upload_binding=(
                    permit_value, findings, len(projection_bytes), finding_count,
                ),
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
        with self._operation_lock("claim", None):
            self._install_chain_state("claim", state)
        return RunnerRotationActivated(
            response["schema_version"], response["workspace_id"], response["runner_id"],
            response["initial_claim_nonce"], response["initial_claim_sequence"],
            response["initial_claim_generation"],
        )

    def start_resync(self, *, operation: str, run_id: str | None = None) -> PendingRunnerResync:
        self._validate_chain(operation, run_id)
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
        with self._operation_lock(pending.operation, pending.run_id):
            return self._complete_resync_locked(pending)

    def _complete_resync_locked(
        self, pending: PendingRunnerResync,
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
        self._install_chain_state(chain_name, recovered)
        return RecoveredRunnerChain(
            pending.operation, pending.run_id, next_nonce, next_sequence, expires, generation,
        )

    def _install_chain_state(self, chain_name: str, state: tuple[str, int, int]) -> None:
        with self._state_lock:
            staged = dict(self._chains)
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
