"""Fixed-route runner control and recovery client."""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from heel.canary_contracts import canonical_bytes


_CAPS = {"claim": "runner_claim", "heartbeat": "runner_heartbeat", "progress": "runner_progress", "result": "runner_result", "stop-ack": "runner_heartbeat"}
_RUN_OPERATIONS = frozenset({"heartbeat", "progress", "result", "stop-ack"})


@dataclass(frozen=True)
class _Call:
    path: str; headers: dict[str, str]; body: bytes; capability: str; chain: str; sequence: int


@dataclass(frozen=True)
class PendingRunnerResync:
    challenge_id: str; operation: str; run_id: str | None; client_nonce_b64: str
    server_challenge_b64: str; next_sequence: int; expires_at_ms: int


@dataclass(frozen=True)
class RecoveredRunnerChain:
    operation: str; run_id: str | None; next_nonce_b64: str; next_sequence: int; expires_at_ms: int


class RunnerControlClient:
    """Emit only named closed control/recovery envelopes; no generic request API exists."""

    def __init__(self, *, origin, workspace_id, runner_id, signer, clock, transport, nonce_source,
                 resync_random_source=secrets.token_bytes):
        parsed = urlsplit(origin)
        if origin != f"{parsed.scheme}://{parsed.netloc}" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("origin must be one exact pathless origin")
        if not all(type(value) is str and value for value in (workspace_id, runner_id)):
            raise ValueError("workspace and runner IDs are required")
        self.origin, self.workspace_id, self.runner_id = origin, workspace_id, runner_id
        self.signer, self.clock, self.transport, self.nonce_source = signer, clock, transport, nonce_source
        self.resync_random_source = resync_random_source
        self._chains: dict[str, tuple[str, int]] = {}
        self._last: _Call | None = None
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

    def _next_chain(self, operation: str, run_id: str | None) -> tuple[str, int, str]:
        self._validate_chain(operation, run_id)
        chain = self._chain(operation, run_id)
        current = self._chains.get(chain)
        if current is None:
            nonce = self.nonce_source(_CAPS[operation])
            if type(nonce) is not str or not nonce: raise ValueError("a non-empty next nonce is required")
            current = (nonce, 1); self._chains[chain] = current
        return current[0], current[1], chain

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

    def _post_control(self, operation: str, body_payload: dict[str, Any], run_id: str | None, *, retry: bool = False):
        if retry:
            if self._last is None: raise ValueError("no request is available to retry")
            return self._post(self._last)
        nonce, sequence, chain = self._next_chain(operation, run_id)
        path, body, timestamp_ms = self._control_path(operation, run_id), canonical_bytes(body_payload), self._timestamp()
        proof = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": self.workspace_id, "runner_id": self.runner_id, "key_id": self.signer.key_id, "capability": _CAPS[operation], "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms, "server_nonce": nonce, "sequence": sequence}
        call = _Call(path, self._headers(self._signature(b"heel.runner-pop.v1\0" + canonical_bytes(proof)), timestamp_ms, nonce=nonce, sequence=sequence), body, _CAPS[operation], chain, sequence)
        self._last = call
        return self._post(call)

    def _post(self, call: _Call):
        response = self.transport.post(call.path, headers=call.headers, body=call.body)
        if not isinstance(response, tuple) or len(response) < 2: raise ValueError("runner transport returned an invalid response")
        status, headers = response[0], response[1]; self.calls.append(call)
        next_nonce = headers.get("X-Heel-Runner-Next-Nonce") if isinstance(headers, dict) else None
        if not isinstance(next_nonce, str) or not next_nonce: raise ValueError("control response omitted next nonce")
        self._chains[call.chain] = (next_nonce, call.sequence + 1)
        return status, headers

    def claim(self):
        return self._post_control("claim", {"schema_version": "heel.runner-claim-request.v1"}, None)

    def heartbeat(self, *, run_id, operational_projection): return self._run("heartbeat", run_id, operational_projection)
    def progress(self, *, run_id, operational_projection): return self._run("progress", run_id, operational_projection)
    def result(self, *, run_id, operational_projection): return self._run("result", run_id, operational_projection)
    def stop_ack(self, *, run_id, operational_projection): return self._run("stop-ack", run_id, operational_projection)

    def _run(self, operation: str, run_id: str, operational_projection: Any):
        self._validate_chain(operation, run_id)
        if not isinstance(operational_projection, dict): raise ValueError("operational projection must be an object")
        return self._post_control(operation, {"schema_version": f"heel.runner-{operation}-request.v1", "run_id": run_id, "operational_projection": operational_projection}, run_id)

    def retry_last(self):
        return self._post_control("claim", {}, None, retry=True)

    def start_resync(self, *, operation: str, run_id: str | None = None) -> PendingRunnerResync:
        self._validate_chain(operation, run_id)
        client_nonce, chain = self._random_b64(), {"operation": operation, "run_id": run_id}
        path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/resync/start"
        body = canonical_bytes({"schema_version": "heel.runner-resync-start.v1", "chain": chain, "client_nonce_b64": client_nonce})
        timestamp_ms = self._timestamp()
        proof = {"schema_version": "heel.runner-resync-start-proof.v1", "workspace_id": self.workspace_id, "runner_id": self.runner_id, "key_id": self.signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms}
        response = self.transport.post(path, headers=self._headers(self._signature(b"heel.runner-resync-start-pop.v1\0" + canonical_bytes(proof)), timestamp_ms), body=body)
        data = self._response_data(response, "heel.runner-resync-challenge.v1")
        challenge_id, next_sequence, expires = data.get("challenge_id"), data.get("next_sequence"), data.get("expires_at_ms")
        if data.get("chain") != chain or not self._b64_32(data.get("server_challenge_b64")) or type(challenge_id) is not str or not challenge_id.startswith("rrs_") or len(challenge_id) != 36 or not self._positive_int(next_sequence) or not self._positive_int(expires): raise ValueError("invalid runner resync challenge")
        return PendingRunnerResync(challenge_id, operation, run_id, client_nonce, data["server_challenge_b64"], next_sequence, expires)

    def complete_resync(self, pending: PendingRunnerResync) -> RecoveredRunnerChain:
        if not isinstance(pending, PendingRunnerResync): raise ValueError("pending runner resync is required")
        self._validate_chain(pending.operation, pending.run_id)
        chain = {"operation": pending.operation, "run_id": pending.run_id}
        path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/resync/complete"
        body = canonical_bytes({"schema_version": "heel.runner-resync-complete.v1", "challenge_id": pending.challenge_id, "chain": chain, "client_nonce_b64": pending.client_nonce_b64, "server_challenge_b64": pending.server_challenge_b64})
        timestamp_ms = self._timestamp()
        proof = {"schema_version": "heel.runner-resync-complete-proof.v1", "workspace_id": self.workspace_id, "runner_id": self.runner_id, "key_id": self.signer.key_id, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms}
        response = self.transport.post(path, headers=self._headers(self._signature(b"heel.runner-resync-complete-pop.v1\0" + canonical_bytes(proof)), timestamp_ms), body=body)
        data = self._response_data(response, "heel.runner-resync-completed.v1")
        next_sequence, expires = data.get("next_sequence"), data.get("expires_at_ms")
        if data.get("chain") != chain or not self._b64_32(data.get("next_nonce_b64")) or not self._positive_int(next_sequence) or not self._positive_int(expires): raise ValueError("invalid runner resync completion")
        self._chains[self._chain(pending.operation, pending.run_id)] = (data["next_nonce_b64"], next_sequence)
        return RecoveredRunnerChain(pending.operation, pending.run_id, data["next_nonce_b64"], next_sequence, expires)

    def _random_b64(self) -> str:
        raw = self.resync_random_source(32)
        if not isinstance(raw, bytes) or len(raw) != 32: raise ValueError("runner resync source must return 32 bytes")
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _positive_int(value: Any) -> bool: return not isinstance(value, bool) and isinstance(value, int) and value >= 1

    @staticmethod
    def _b64_32(value: Any) -> bool:
        if type(value) is not str: return False
        try: decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError): return False
        return len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == value

    @staticmethod
    def _response_data(response: Any, schema: str) -> dict[str, Any]:
        if not isinstance(response, tuple) or len(response) != 3 or not isinstance(response[2], dict) or response[2].get("schema_version") != schema:
            raise ValueError("runner resync response is invalid")
        return response[2]
