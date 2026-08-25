import base64
import hashlib

import pytest

from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id
from heel.runner.control_client import RunnerControlClient

PUBLIC_KEY = b"0123456789abcdef0123456789abcdef"
KEY_ID = ed25519_key_id(PUBLIC_KEY)

class Transport:
    def __init__(self): self.requests = []
    def post(self, path, *, headers=None, body=b""):
        self.requests.append((path, dict(headers or {}), body))
        return 200, {"X-Heel-Runner-Next-Nonce": "next-" + str(len(self.requests))}

class Signer:
    key_id = KEY_ID
    def __init__(self): self.payloads = []
    def sign(self, payload): self.payloads.append(payload); return b"s" * 64

def client():
    transport, signer = Transport(), Signer()
    return RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="runner", signer=signer, clock=lambda: 1000, transport=transport, nonce_source=lambda capability: capability + "-first"), transport, signer

def test_named_methods_use_fixed_workspace_paths_and_exact_pop_headers():
    control, transport, signer = client()
    control.claim()
    path, headers, body = transport.requests[0]
    assert path == "/v1/workspaces/ws/runners/runner/claim"
    assert headers == {"Content-Type": "application/json", "X-Heel-Runner-Id": "runner", "X-Heel-Runner-Key-Id": KEY_ID, "X-Heel-Runner-Timestamp-Ms": "1000", "X-Heel-Runner-Nonce": "runner_claim-first", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": base64.b64encode(b"s" * 64).decode()}
    expected = {"schema_version": "heel.runner-request-proof.v1", "workspace_id": "ws", "runner_id": "runner", "key_id": KEY_ID, "capability": "runner_claim", "method": "POST", "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": 1000, "server_nonce": "runner_claim-first", "sequence": 1}
    assert signer.payloads == [b"heel.runner-pop.v1\0" + canonical_bytes(expected)]

def test_sequences_are_independent_per_run_capability_and_stop_ack_is_heartbeat():
    control, transport, _ = client()
    control.heartbeat(run_id="one")
    control.heartbeat(run_id="one")
    control.progress(run_id="one", progress=10)
    control.stop_ack(run_id="one")
    assert [h["X-Heel-Runner-Sequence"] for _, h, _ in transport.requests] == ["1", "2", "1", "3"]
    assert transport.requests[-1][0].endswith("/runs/one/stop-ack")
    assert canonical_bytes({"run_id": "one", "progress": 10}) == transport.requests[2][2]

def test_refuses_noncanonical_origin_bad_nonce_and_changed_retry():
    with pytest.raises(ValueError, match="pathless origin"):
        RunnerControlClient(origin="https://control.example?x=1", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "n")
    bad = RunnerControlClient(origin="https://control.example", workspace_id="ws", runner_id="r", signer=Signer(), clock=lambda: 0, transport=Transport(), nonce_source=lambda _: "")
    with pytest.raises(ValueError, match="nonce"):
        bad.claim()
    control, _, _ = client()
    control.progress(run_id="one", status="one")
    with pytest.raises(ValueError, match="changed body"):
        control.retry_last({"run_id": "one", "status": "two"})

def test_has_no_public_generic_request_api():
    control, _, _ = client()
    assert not hasattr(control, "request")
    public = {name for name, value in vars(RunnerControlClient).items() if callable(value) and not name.startswith("_")}
    assert public <= {"claim", "heartbeat", "progress", "result", "stop_ack", "retry_last"}
