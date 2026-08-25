"""Fixed-route runner control client.

There deliberately is no generic request method.  The runner can only emit the
four proof-carrying control requests defined by the protocol.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from heel.canary_contracts import canonical_bytes


_CAPS = {
    "claim": "runner_claim",
    "heartbeat": "runner_heartbeat",
    "progress": "runner_progress",
    "result": "runner_result",
    "stop_ack": "runner_heartbeat",
}


@dataclass(frozen=True)
class _Call:
    path: str
    headers: dict[str, str]
    body: bytes
    capability: str
    chain: str
    sequence: int


class RunnerControlClient:
    def __init__(self, *, origin, workspace_id, runner_id, signer, clock, transport, nonce_source):
        parsed = urlsplit(origin)
        if origin != f"{parsed.scheme}://{parsed.netloc}" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("origin must be one exact pathless origin")
        if not all(type(value) is str and value for value in (workspace_id, runner_id)):
            raise ValueError("workspace and runner IDs are required")
        self.origin = origin
        self.workspace_id, self.runner_id = workspace_id, runner_id
        self.signer, self.clock, self.transport, self.nonce_source = signer, clock, transport, nonce_source
        self._chains: dict[str, tuple[str, int]] = {}
        self._last: _Call | None = None
        self.calls: list[_Call] = []

    def _chain(self, name: str, capability: str) -> tuple[str, int]:
        current = self._chains.get(name)
        if current is not None:
            return current
        nonce = self.nonce_source(capability)
        if type(nonce) is not str or not nonce:
            raise ValueError("a non-empty next nonce is required")
        current = (nonce, 1)
        self._chains[name] = current
        return current

    def _send(self, operation: str, payload: dict, run_id: str | None = None, *, retry: bool = False):
        cap = _CAPS[operation]
        chain = "claim" if operation == "claim" else f"{cap}:{run_id}"
        if retry:
            call = self._last
            if call is None:
                raise ValueError("no request is available to retry")
            return self._post(call, retry=True)
        if operation == "claim":
            path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/claim"
        else:
            if type(run_id) is not str or not run_id:
                raise ValueError("run ID is required")
            suffix = "stop-ack" if operation == "stop_ack" else operation
            path = f"/v1/workspaces/{self.workspace_id}/runners/{self.runner_id}/runs/{run_id}/{suffix}"
        nonce, sequence = self._chain(chain, cap)
        body_payload = dict(payload)
        if run_id is not None:
            body_payload["run_id"] = run_id
        body = canonical_bytes(body_payload)
        proof = {
            "schema_version": "heel.runner-request-proof.v1",
            "workspace_id": self.workspace_id, "runner_id": self.runner_id,
            "key_id": self.signer.key_id, "capability": cap, "method": "POST", "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": self.clock(),
            "server_nonce": nonce, "sequence": sequence,
        }
        signature = self.signer.sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("runner signer returned an invalid Ed25519 signature")
        headers = {
            "Content-Type": "application/json",
            "X-Heel-Runner-Id": self.runner_id,
            "X-Heel-Runner-Key-Id": self.signer.key_id,
            "X-Heel-Runner-Timestamp-Ms": str(proof["timestamp_ms"]),
            "X-Heel-Runner-Nonce": nonce,
            "X-Heel-Runner-Sequence": str(sequence),
            "X-Heel-Runner-Signature": base64.b64encode(signature).decode("ascii"),
        }
        call = _Call(path, headers, body, cap, chain, sequence)
        self._last = call
        return self._post(call)

    def _post(self, call: _Call, *, retry: bool = False):
        status, headers = self.transport.post(call.path, headers=call.headers, body=call.body)
        self.calls.append(call)
        next_nonce = headers.get("X-Heel-Runner-Next-Nonce") if isinstance(headers, dict) else None
        if not isinstance(next_nonce, str) or not next_nonce:
            raise ValueError("control response omitted next nonce")
        self._chains[call.chain] = (next_nonce, call.sequence + 1)
        return status, headers

    def claim(self, **payload): return self._send("claim", payload)
    def heartbeat(self, *, run_id, **payload): return self._send("heartbeat", payload, run_id)
    def progress(self, *, run_id, **payload): return self._send("progress", payload, run_id)
    def result(self, *, run_id, **payload): return self._send("result", payload, run_id)
    def stop_ack(self, *, run_id, **payload): return self._send("stop_ack", payload, run_id)

    def retry_last(self, payload=None):
        if self._last is None:
            raise ValueError("no request is available to retry")
        if payload is not None and canonical_bytes(payload) != self._last.body:
            raise ValueError("changed body cannot retry a signed request")
        return self._send("claim", {}, retry=True)
