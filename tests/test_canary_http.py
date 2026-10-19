from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.http_api import ControlPlane, serve
import heel.saas.http_api as http_api


def test_control_generation_bounds_untrusted_header_before_pattern_matching(monkeypatch):
    handler = object.__new__(http_api._Handler)
    handler._header_values = lambda _name: ["1" * 100_000]
    monkeypatch.setattr(http_api, "_is_control_generation", lambda _value: (_ for _ in ()).throw(
        AssertionError("unbounded request header reached validation")))
    with pytest.raises(http_api.ApiError, match="invalid canary control generation"):
        handler._expected_control_generation()
from heel.saas.canary_runs import CanaryRunService
from heel.saas.tenancy import Role

from canary_test_support import (
    NOW,
    approval_projection,
    operational_projection,
    seed_authority,
)
from test_canary_disclosure import _findings


class CanaryHttpFixture:
    def __init__(self, root: Path, *, authority: bool = True):
        root.mkdir(parents=True, exist_ok=True)
        self.cloud = SigningAuthority.generate() if authority else None
        self.cp = ControlPlane(
            str(root / "heel.sqlite3"),
            device_token_pepper=b"d" * 32,
            enable_device_auth=True,
            public_origin="https://heel.test",
            runner_auth_pepper=b"r" * 32,
            grant_authority=self.cloud,
            grant_trusted_keys=(
                {self.cloud.key_id: self.cloud.public_key} if self.cloud is not None else {}
            ),
        )
        org = self.cp.store.create_org("Canary")
        self.workspace = self.cp.store.create_workspace(
            org, "Canary", "free", CATALOG_VERSION,
        )
        self.user = self.cp.store.create_user("owner@canary.test")
        self.cp.store.add_member(self.workspace, self.user, Role.OWNER)
        self.project = self.cp.projects.create(
            self.workspace, "Canary", created_by=self.user,
        ).project_ref
        self.session = self.cp.auth.create_session(self.user)
        self.runner = seed_authority(
            self.cp.store.conn,
            workspace_id=self.workspace,
            project_ref=self.project,
            proof_expires_at=NOW + 3600,
        )
        self.runner_id = "runr_canary"
        self.claim_nonce = "claim-http-nonce"
        stamp = time.time()
        self.cp.store.conn.execute(
            "INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
            (
                self.workspace,
                self.runner_id,
                "claim",
                self.cp.runner_auth._hash("nonce", self.claim_nonce),
                1,
                stamp + 600,
            ),
        )
        self.cp.store.conn.execute(
            "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
            (self.workspace, self.runner_id, "claim", 1, 0, stamp),
        )
        # This fixture models an already activated executable runner.  Legacy
        # pairings intentionally lack this v3 protocol row and are exercised by
        # the dedicated upgrade-required tests.
        self.cp.store.conn.execute(
            "INSERT INTO canary_runner_execution_protocols("
            "workspace_id,runner_id,protocol_version,control_protocol,exchange_digest,activated_at"
            ") VALUES(?,?,?,?,?,?)",
            (self.workspace, self.runner_id, 3, "heel.runner-control.v2", "a" * 64, stamp),
        )
        self.cp.store.conn.commit()
        self.runner_sql: list[str] = []
        database_path = str(root / "heel.sqlite3")

        def runner_connection():
            connection = sqlite3.connect(database_path, check_same_thread=False)
            connection.set_trace_callback(self.runner_sql.append)
            return connection

        self.cp._runner_connection_factory = runner_connection
        self.cp.runner_connections_are_shared = False
        self.server = serve(self.cp)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def browser(self) -> dict[str, str]:
        return {
            "Cookie": f"heel_session={self.session.token}",
            "Origin": "https://heel.test",
            "X-Heel-Internal-Origin": "same-origin",
        }

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, method: str, path: str, body=None, headers=None, *, raw=None):
        payload = raw
        if payload is None and body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=5,
        )
        connection.request(method, path, payload, request_headers)
        response = connection.getresponse()
        raw_response = response.read()
        data = json.loads(raw_response) if raw_response else None
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def pop(self, path: str, body: bytes, *, capability: str, nonce: str, sequence: int):
        timestamp = int(time.time() * 1000)
        proof = {
            "schema_version": "heel.runner-request-proof.v1",
            "workspace_id": self.workspace,
            "runner_id": self.runner_id,
            "key_id": self.runner.key_id,
            "capability": capability,
            "method": "POST",
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp_ms": timestamp,
            "server_nonce": nonce,
            "sequence": sequence,
        }
        return {
            "Content-Type": "application/json",
            "X-Heel-Runner-Id": self.runner_id,
            "X-Heel-Runner-Key-Id": self.runner.key_id,
            "X-Heel-Runner-Timestamp-Ms": str(timestamp),
            "X-Heel-Runner-Nonce": nonce,
            "X-Heel-Runner-Sequence": str(sequence),
            "X-Heel-Runner-Signature": self.runner.sign(
                b"heel.runner-pop.v1\0" + canonical_bytes(proof)
            )["signature_b64"],
        }

    def operational(
        self,
        grant: dict,
        *,
        sequence: int,
        phase: str,
        requests_started: int = 0,
        requests_completed: int = 0,
        disposition: str | None = None,
        stop_reason: str = "none",
        stop_requested_at_ms: int | None = None,
        stop_acknowledged_at_ms: int | None = None,
        actions_contained: int | None = None,
    ) -> dict:
        value = operational_projection(
            self.runner,
            grant,
            sequence=sequence,
            phase=phase,
            requests_started=requests_started,
            requests_completed=requests_completed,
            disposition=disposition,
            stop_reason=stop_reason,
            stop_requested_at_ms=stop_requested_at_ms,
            stop_acknowledged_at_ms=stop_acknowledged_at_ms,
        )
        now_ms = int(time.time() * 1000)
        updated_at_ms = max(
            now_ms, stop_requested_at_ms or 0, stop_acknowledged_at_ms or 0,
        )
        value["timestamps"] = {
            "claimed_at_ms": now_ms - 200,
            "started_at_ms": now_ms - 100 if phase != "claimed" else None,
            "updated_at_ms": updated_at_ms,
            "stop_requested_at_ms": stop_requested_at_ms,
            "stop_acknowledged_at_ms": stop_acknowledged_at_ms,
            "terminal_at_ms": updated_at_ms if phase == "terminal" else None,
        }
        value["counters"]["actions_contained"] = (
            requests_started if actions_contained is None else actions_contained
        )
        unsigned = {
            key: item for key, item in value.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        value["projection_digest"] = canonical_digest(unsigned)
        value.update(self.runner.sign(canonical_bytes(unsigned)))
        return value


@pytest.fixture
def canary_http():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            yield fixture
        finally:
            fixture.close()


def test_runner_context_human_routes_reject_raw_path_aliases(canary_http):
    fixture = canary_http
    path = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/runner-context-bindings"
    create = {
        "schema_version": "heel.runner-context-binding-create.v1", "environment_id": "env_canary",
        "verification_record_digest": "a" * 64, "runner_id": fixture.runner_id,
        "runner_key_id": fixture.runner.key_id,
    }
    before = fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_runner_context_bindings"
    ).fetchone()[0]
    for suffix in ("?cursor=attacker", "#fragment"):
        status, _, _ = fixture.request("GET", path + suffix, headers=fixture.browser)
        assert status == 404
        status, _, _ = fixture.request("POST", path + suffix, headers=fixture.browser, raw=canonical_bytes(create))
        assert status == 404
    for suffix in ("%3Falias", "/"):
        status, _, _ = fixture.request("GET", path + suffix, headers=fixture.browser)
        assert status == 400
    status, _, _ = fixture.request("DELETE", path, headers=fixture.browser)
    assert status == 404
    assert fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_runner_context_bindings"
    ).fetchone()[0] == before


def test_context_dashboard_hides_runner_bound_in_another_project_until_revoke(canary_http):
    fixture = canary_http
    first_path = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/runner-context-bindings"
    create = {
        "schema_version": "heel.runner-context-binding-create.v1", "environment_id": "env_canary",
        "verification_record_digest": "a" * 64, "runner_id": fixture.runner_id,
        "runner_key_id": fixture.runner.key_id,
    }
    status, _, created = fixture.request("POST", first_path, headers=fixture.browser, raw=canonical_bytes(create))
    assert status == 201
    other = fixture.cp.projects.create(
        fixture.workspace, "Other", created_by=fixture.user,
    ).project_ref
    other_path = f"/v1/workspaces/{fixture.workspace}/projects/{other}/runner-context-bindings"

    status, _, current = fixture.request("GET", first_path, headers=fixture.browser)
    assert status == 200
    assert current["runners"] == []
    assert [item["binding_id"] for item in current["bindings"]] == [created["context_binding"]["binding_id"]]
    status, _, occupied = fixture.request("GET", other_path, headers=fixture.browser)
    assert status == 200
    assert occupied["runners"] == []
    assert occupied["bindings"] == []

    revoke = {"schema_version": "heel.runner-context-binding-revoke.v1", "reason_code": "operator_requested"}
    status, _, _ = fixture.request(
        "POST", f"{first_path}/{created['context_binding']['binding_id']}/revoke",
        headers=fixture.browser, raw=canonical_bytes(revoke),
    )
    assert status == 200
    status, _, available = fixture.request("GET", other_path, headers=fixture.browser)
    assert status == 200
    assert [item["runner_id"] for item in available["runners"]] == [fixture.runner_id]


def test_execution_approval_claim_heartbeat_progress_status_events_are_real(canary_http):
    fixture = canary_http
    projection = approval_projection(
        fixture.runner,
        workspace_id=fixture.workspace,
        project_ref=fixture.project,
    )
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    status, _, submitted = fixture.request(
        "POST", base + "/canary-approval-projections", projection, fixture.browser,
    )
    assert status == 201
    assert set(submitted) == {
        "schema_version", "approval_id", "run_id", "status", "projection_digest",
    }

    approval_headers = {
        **fixture.browser,
        "Idempotency-Key": "ca1-" + "a" * 64,
        "If-Heel-Control-Generation": "0",
    }
    approval_body = {
        "schema_version": "heel.canary-execution-approval.v1",
        "projection_digest": projection["projection_digest"],
        "hostname_retype": "canary.acme.dev",
        "reason": "Run the exact bounded staging rehearsal",
    }
    run_path = base + "/canary-runs/" + submitted["run_id"]
    status, _, approved = fixture.request(
        "POST", run_path + "/approve", approval_body, approval_headers,
    )
    assert status == 201 and approved["grant"]["run_id"] == submitted["run_id"]
    assert fixture.request(
        "POST", run_path + "/approve", approval_body, approval_headers,
    )[2] == approved
    status, _, dashboard = fixture.request("GET", run_path, headers=fixture.browser)
    assert status == 200
    assert set(dashboard) == {
        "schema_version", "approval_control_generation", "run", "progress",
    }
    assert dashboard["schema_version"] == "heel.canary-run-dashboard.v1"
    assert dashboard["run"]["status"] == "approved"
    assert dashboard["progress"] == {
        "schema_version": "heel.canary-run-progress.v1",
        "available": True,
        "current_scenario_id": None,
        "scenarios_completed": 0,
        "scenarios_total": 1,
        "requests_started": 0,
        "requests_completed": 0,
        "remaining_requests": 2,
        "remaining_wall_ms": 60000,
        "retries_used": 0,
        "redaction_count": 0,
        "local_result_ready": False,
    }

    claim_path = (
        f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/claim"
    )
    claim_body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    claim_headers = fixture.pop(
        claim_path, claim_body, capability="runner_claim",
        nonce=fixture.claim_nonce, sequence=1,
    )
    status, response_headers, claimed = fixture.request(
        "POST", claim_path, headers=claim_headers, raw=claim_body,
    )
    assert status == 200
    assert claimed["schema_version"] == "heel.runner-claim-response.v1"
    assert claimed["grant"] == approved["grant"]
    assert set(claimed["chain_states"]) == {
        "heartbeat", "progress", "result", "stop-ack",
    }
    next_claim_nonce = response_headers["X-Heel-Runner-Next-Nonce"]
    assert fixture.request(
        "POST", claim_path, headers=claim_headers, raw=claim_body,
    )[:1] == (200,)
    assert next_claim_nonce
    idle_headers = fixture.pop(
        claim_path, claim_body, capability="runner_claim",
        nonce=next_claim_nonce, sequence=2,
    )
    idle_status, idle_response_headers, idle = fixture.request(
        "POST", claim_path, headers=idle_headers, raw=claim_body,
    )
    assert idle_status == 204 and idle is None
    assert idle_response_headers["X-Heel-Runner-Next-Nonce"]

    heartbeat_projection = fixture.operational(
        approved["grant"], sequence=0, phase="claimed",
    )
    heartbeat_path = (
        f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/runs/"
        f"{submitted['run_id']}/heartbeat"
    )
    heartbeat_body = canonical_bytes({
        "schema_version": "heel.runner-heartbeat-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": heartbeat_projection,
    })
    chain = claimed["chain_states"]["heartbeat"]
    status, heartbeat_response_headers, gate = fixture.request(
        "POST", heartbeat_path,
        headers=fixture.pop(
            heartbeat_path, heartbeat_body, capability="runner_heartbeat",
            nonce=chain["next_nonce_b64"], sequence=chain["next_sequence"],
        ),
        raw=heartbeat_body,
    )
    assert status == 200
    assert set(gate) == {
        "active", "runner_state", "proof_state", "proof_expires_at_ms",
        "kill_switch_generation", "stop_reason", "server_time_ms",
    }
    assert gate["active"] is True

    running_projection = fixture.operational(
        approved["grant"], sequence=1, phase="running", requests_started=1,
    )
    progress_path = heartbeat_path.removesuffix("heartbeat") + "progress"
    progress_body = canonical_bytes({
        "schema_version": "heel.runner-progress-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": running_projection,
    })
    progress_chain = claimed["chain_states"]["progress"]
    status, progress_response_headers, progress = fixture.request(
        "POST", progress_path,
        headers=fixture.pop(
            progress_path, progress_body, capability="runner_progress",
            nonce=progress_chain["next_nonce_b64"],
            sequence=progress_chain["next_sequence"],
        ),
        raw=progress_body,
    )
    assert status == 200 and progress["status"] == "running"

    # A service-layer failure is part of the same transaction as PoP consumption.  An
    # equal sequence with a changed digest must leave both lifecycle and PoP untouched.
    invalid_progress = fixture.operational(
        approved["grant"], sequence=1, phase="running", requests_started=1,
        actions_contained=1,
    )
    invalid_progress_body = canonical_bytes({
        "schema_version": "heel.runner-progress-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": invalid_progress,
    })
    progress_retry_nonce = progress_response_headers["X-Heel-Runner-Next-Nonce"]
    invalid_progress_headers = fixture.pop(
        progress_path, invalid_progress_body, capability="runner_progress",
        nonce=progress_retry_nonce, sequence=2,
    )
    status, _, failure = fixture.request(
        "POST", progress_path, headers=invalid_progress_headers, raw=invalid_progress_body,
    )
    assert status == 409 and failure == {
        "schema_version": "heel.canary-error.v1", "code": "event_sequence_conflict",
    }
    stored = fixture.cp.store.conn.execute(
        "SELECT status,source_event_sequence FROM canary_runs WHERE run_id=?",
        (submitted["run_id"],),
    ).fetchone()
    assert tuple(stored) == ("running", 1)
    assert fixture.cp.store.conn.execute(
        "SELECT next_sequence FROM canary_runner_chain_cursors "
        "WHERE workspace_id=? AND runner_id=? AND chain_name=?",
        (fixture.workspace, fixture.runner_id, f"progress:{submitted['run_id']}"),
    ).fetchone()[0] == 2

    corrected_progress = fixture.operational(
        approved["grant"], sequence=3, phase="running", requests_started=1,
        actions_contained=1,
    )
    corrected_progress_body = canonical_bytes({
        "schema_version": "heel.runner-progress-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": corrected_progress,
    })
    corrected_progress_headers = fixture.pop(
        progress_path, corrected_progress_body, capability="runner_progress",
        nonce=progress_retry_nonce, sequence=2,
    )
    status, corrected_headers, corrected = fixture.request(
        "POST", progress_path,
        headers=corrected_progress_headers, raw=corrected_progress_body,
    )
    assert status == 200 and corrected["source_event_sequence"] == 3
    replay_status, replay_headers, replay_body = fixture.request(
        "POST", progress_path,
        headers=corrected_progress_headers, raw=corrected_progress_body,
    )
    assert replay_status == status and replay_body == corrected
    assert (
        replay_headers["X-Heel-Runner-Next-Nonce"]
        == corrected_headers["X-Heel-Runner-Next-Nonce"]
    )
    status, _, running_dashboard = fixture.request(
        "GET", run_path, headers=fixture.browser,
    )
    assert status == 200
    assert running_dashboard["progress"] == {
        "schema_version": "heel.canary-run-progress.v1",
        "available": True,
        "current_scenario_id": "anonymous_authenticated_read",
        "scenarios_completed": 0,
        "scenarios_total": 1,
        "requests_started": 1,
        "requests_completed": 0,
        "remaining_requests": 1,
        "remaining_wall_ms": corrected_progress["counters"]["remaining_wall_ms"],
        "retries_used": 0,
        "redaction_count": 0,
        "local_result_ready": False,
    }

    # Heartbeat and progress have independent PoP chains.  This delayed signed heartbeat
    # reports an older operational snapshot and must advance only liveness/the gate.
    heartbeat_events_before = fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? "
        "AND event_type='heartbeat_accepted'",
        (submitted["run_id"],),
    ).fetchone()[0]
    status, reordered_headers, reordered_gate = fixture.request(
        "POST", heartbeat_path,
        headers=fixture.pop(
            heartbeat_path, heartbeat_body, capability="runner_heartbeat",
            nonce=heartbeat_response_headers["X-Heel-Runner-Next-Nonce"], sequence=2,
        ),
        raw=heartbeat_body,
    )
    assert status == 200 and reordered_gate["active"] is True
    assert fixture.cp.store.conn.execute(
        "SELECT source_event_sequence FROM canary_runs WHERE run_id=?",
        (submitted["run_id"],),
    ).fetchone()[0] == 3
    assert fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? "
        "AND event_type='heartbeat_accepted'",
        (submitted["run_id"],),
    ).fetchone()[0] == heartbeat_events_before

    stop_status, _, stopped = fixture.request(
        "POST",
        run_path + "/stop",
        {
            "schema_version": "heel.canary-stop-request.v1",
            "reason_code": "operator_requested",
        },
        {**fixture.browser, "If-Heel-Control-Generation": "0"},
    )
    assert stop_status == 200 and stopped["reason"] == "cloud_stop"
    stop_requested_at = stopped["deadline_ms"] - 5000
    runner_local_stop_at = stop_requested_at + 25
    acknowledgement = fixture.operational(
        approved["grant"],
        sequence=4,
        phase="stop_requested",
        requests_started=1,
        stop_reason="cloud_stop",
        stop_requested_at_ms=runner_local_stop_at,
        stop_acknowledged_at_ms=stop_requested_at + 100,
    )
    stopped_heartbeat_body = canonical_bytes({
        "schema_version": "heel.runner-heartbeat-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": acknowledgement,
    })
    status, _, stopped_gate = fixture.request(
        "POST", heartbeat_path,
        headers=fixture.pop(
            heartbeat_path, stopped_heartbeat_body, capability="runner_heartbeat",
            nonce=reordered_headers["X-Heel-Runner-Next-Nonce"], sequence=3,
        ),
        raw=stopped_heartbeat_body,
    )
    assert status == 200 and stopped_gate["active"] is False
    assert stopped_gate["stop_reason"] == "cloud_stop"
    ack_path = heartbeat_path.removesuffix("heartbeat") + "stop-ack"
    ack_body = canonical_bytes({
        "schema_version": "heel.runner-stop-ack-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": acknowledgement,
    })
    # Exercise the server receipt clock without a wall-clock sleep: arrival after the
    # persisted Cloud deadline cannot be made timely by a backdated runner-local timestamp.
    fixture.cp.store.conn.execute(
        "UPDATE canary_runs SET stop_deadline_ms=? WHERE run_id=?",
        (int(time.time() * 1000) - 1, submitted["run_id"]),
    )
    fixture.cp.store.conn.commit()
    ack_chain = claimed["chain_states"]["stop-ack"]
    status, _, ack = fixture.request(
        "POST", ack_path,
        headers=fixture.pop(
            ack_path, ack_body, capability="runner_heartbeat",
            nonce=ack_chain["next_nonce_b64"], sequence=ack_chain["next_sequence"],
        ),
        raw=ack_body,
    )
    assert status == 200
    assert ack == {"accepted": True, "deadline_met": False, "late": True}

    terminal = fixture.operational(
        approved["grant"],
        sequence=5,
        phase="terminal",
        requests_started=1,
        requests_completed=1,
        disposition="stopped",
        stop_reason="cloud_stop",
        stop_requested_at_ms=runner_local_stop_at,
        stop_acknowledged_at_ms=stop_requested_at + 100,
    )
    result_path = heartbeat_path.removesuffix("heartbeat") + "result"
    result_chain = claimed["chain_states"]["result"]
    tampered_terminal = fixture.operational(
        approved["grant"],
        sequence=5,
        phase="terminal",
        requests_started=1,
        requests_completed=1,
        disposition="stopped",
        stop_reason="cloud_stop",
        stop_requested_at_ms=runner_local_stop_at,
        stop_acknowledged_at_ms=stop_requested_at + 101,
    )
    tampered_result_body = canonical_bytes({
        "schema_version": "heel.runner-result-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": tampered_terminal,
    })
    status, _, result_failure = fixture.request(
        "POST", result_path,
        headers=fixture.pop(
            result_path, tampered_result_body, capability="runner_result",
            nonce=result_chain["next_nonce_b64"], sequence=result_chain["next_sequence"],
        ),
        raw=tampered_result_body,
    )
    assert status == 409 and result_failure == {
        "schema_version": "heel.canary-error.v1", "code": "canary_state_conflict",
    }
    assert fixture.cp.store.conn.execute(
        "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
    ).fetchone()[0] != "terminal"

    result_body = canonical_bytes({
        "schema_version": "heel.runner-result-request.v1",
        "run_id": submitted["run_id"],
        "operational_projection": terminal,
    })
    result_headers = fixture.pop(
        result_path, result_body, capability="runner_result",
        nonce=result_chain["next_nonce_b64"], sequence=result_chain["next_sequence"],
    )
    status, result_response_headers, final = fixture.request(
        "POST", result_path, headers=result_headers, raw=result_body,
    )
    assert status == 200 and final["status"] == "terminal"

    findings = _findings(fixture.runner, approved["grant"], terminal)
    findings["workspace_id"] = fixture.workspace
    findings["project_id"] = fixture.project
    findings_unsigned = {
        key: item for key, item in findings.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    findings["projection_digest"] = canonical_digest(findings_unsigned)
    findings.update(fixture.runner.sign(canonical_bytes(findings_unsigned)))
    disclosure_body = {
        "schema_version": "heel.canary-disclosure-request.v1",
        "projection_digest": findings["projection_digest"],
        "projection_bytes": len(canonical_bytes(findings)),
        "scenario_count": len(findings["scenario_results"]),
        "finding_count": 1,
    }
    status, _, permit = fixture.request(
        "POST", run_path + "/disclosure-permits", disclosure_body, fixture.browser,
    )
    assert status == 201 and permit["run_id"] == submitted["run_id"]
    upload_path = result_path.removesuffix("result") + "result-projection"
    upload_body = canonical_bytes({
        "schema_version": "heel.runner-findings-upload.v1",
        "run_id": submitted["run_id"],
        "permit": permit,
        "findings_projection": findings,
    })
    status, _, receipt = fixture.request(
        "POST", upload_path,
        headers=fixture.pop(
            upload_path, upload_body, capability="runner_result",
            nonce=result_response_headers["X-Heel-Runner-Next-Nonce"], sequence=2,
        ),
        raw=upload_body,
    )
    assert status == 200 and receipt["status"] == "synchronized"
    status, _, synchronized = fixture.request(
        "GET", run_path + "/findings", headers=fixture.browser,
    )
    assert status == 200 and synchronized == findings
    forbidden_sql = (
        "CREATE ", "ALTER ", "DROP ", "PRAGMA JOURNAL_MODE",
    )
    assert not [
        statement for statement in fixture.runner_sql
        if statement.lstrip().upper().startswith(forbidden_sql)
        or statement.strip().upper() == "PRAGMA BUSY_TIMEOUT=5000"
    ]

    status, _, terminal_dashboard = fixture.request("GET", run_path, headers=fixture.browser)
    assert status == 200 and terminal_dashboard["run"]["status"] == "terminal"
    assert terminal_dashboard["progress"]["current_scenario_id"] is None
    assert terminal_dashboard["progress"]["local_result_ready"] is True
    assert set(terminal_dashboard["progress"]) == {
        "schema_version", "available", "current_scenario_id", "scenarios_completed",
        "scenarios_total", "requests_started", "requests_completed",
        "remaining_requests", "remaining_wall_ms", "retries_used", "redaction_count",
        "local_result_ready",
    }
    serialized_dashboard = json.dumps(terminal_dashboard, sort_keys=True)
    assert "/api/canary" not in serialized_dashboard
    assert "credential_bindings" not in serialized_dashboard
    assert "scenario_results" not in serialized_dashboard
    wrong_project_path = (
        f"/v1/workspaces/{fixture.workspace}/projects/proj_other/canary-runs/"
        f"{submitted['run_id']}"
    )
    assert fixture.request("GET", wrong_project_path, headers=fixture.browser)[0] == 404
    status, _, events = fixture.request(
        "GET", run_path + "/events", headers=fixture.browser,
    )
    assert status == 200 and events["schema_version"] == "heel.canary-run-events.v1"
    assert all("projection" not in item for item in events["events"])

    fixture.cp.store.conn.execute(
        "UPDATE canary_operational_receipts SET receipt_json='{}' WHERE run_id=?",
        (submitted["run_id"],),
    )
    fixture.cp.store.conn.commit()
    status, _, corrupt_dashboard = fixture.request("GET", run_path, headers=fixture.browser)
    assert status == 200
    assert corrupt_dashboard["run"]["status"] == "terminal"
    assert corrupt_dashboard["progress"] == {
        "schema_version": "heel.canary-run-progress.v1",
        "available": False,
        "current_scenario_id": None,
        "scenarios_completed": None,
        "scenarios_total": None,
        "requests_started": None,
        "requests_completed": None,
        "remaining_requests": None,
        "remaining_wall_ms": None,
        "retries_used": None,
        "redaction_count": None,
        "local_result_ready": False,
    }


def test_dashboard_exposes_refreshable_approval_control_generation(canary_http):
    fixture = canary_http
    connection = fixture.cp.store.conn
    connection.execute(
        "INSERT INTO kill_switches(scope,reason,actor,tripped_at) "
        "VALUES('global','historical','admin',?)",
        (time.time(),),
    )
    connection.execute("DELETE FROM kill_switches WHERE scope='global'")
    connection.commit()
    projection = approval_projection(
        fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project,
    )
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    status, _, submitted = fixture.request(
        "POST", base + "/canary-approval-projections", projection, fixture.browser,
    )
    assert status == 201
    run_path = base + "/canary-runs/" + submitted["run_id"]
    status, _, pending = fixture.request("GET", run_path, headers=fixture.browser)
    assert status == 200
    assert pending["approval_control_generation"] == 2
    assert "approval_control_generation" not in pending["run"]

    body = {
        "schema_version": "heel.canary-execution-approval.v1",
        "projection_digest": projection["projection_digest"],
        "hostname_retype": "canary.acme.dev",
        "reason": "Run the generation-bound staging rehearsal",
    }
    stale = fixture.request(
        "POST", run_path + "/approve", body,
        {
            **fixture.browser, "Idempotency-Key": "ca1-" + "8" * 64,
            "If-Heel-Control-Generation": "0",
        },
    )
    assert stale[0] == 409 and stale[2]["code"] == "canary_state_conflict"
    assert fixture.request("GET", run_path, headers=fixture.browser)[2][
        "approval_control_generation"
    ] == 2
    status, _, approved = fixture.request(
        "POST", run_path + "/approve", body,
        {
            **fixture.browser, "Idempotency-Key": "ca1-" + "9" * 64,
            "If-Heel-Control-Generation": "2",
        },
    )
    assert status == 201 and approved["grant"]["kill_switch_generation"] == 2

    connection.execute(
        "INSERT INTO kill_switches(scope,reason,actor,tripped_at) "
        "VALUES('global','later','admin',?)",
        (time.time(),),
    )
    connection.execute("DELETE FROM kill_switches WHERE scope='global'")
    connection.commit()
    dashboard = fixture.request("GET", run_path, headers=fixture.browser)[2]
    assert dashboard["approval_control_generation"] == 2
    assert dashboard["run"]["kill_switch_generation"] == 2


def test_canary_mutations_reject_non_browser_principals_and_missing_authority(tmp_path):
    fixture = CanaryHttpFixture(tmp_path / "available")
    unavailable = CanaryHttpFixture(tmp_path / "unavailable", authority=False)
    try:
        projection = approval_projection(
            fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project,
        )
        path = (
            f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/"
            "canary-approval-projections"
        )
        assert fixture.request("POST", path, projection)[0] == 403
        key = fixture.cp.store.issue_api_key(fixture.workspace, Role.VIEWER, "viewer")
        assert fixture.request(
            "POST", path, projection, {"Authorization": f"Bearer {key.secret}"},
        )[0] == 403
        other_org = fixture.cp.store.create_org("Other")
        other_workspace = fixture.cp.store.create_workspace(
            other_org, "Other", "free", CATALOG_VERSION,
        )
        other_user = fixture.cp.store.create_user("other@canary.test")
        fixture.cp.store.add_member(other_workspace, other_user, Role.OWNER)
        other_session = fixture.cp.auth.create_session(other_user)
        assert fixture.request(
            "POST",
            path,
            projection,
            {
                "Cookie": f"heel_session={other_session.token}",
                "Origin": "https://heel.test",
                "X-Heel-Internal-Origin": "same-origin",
            },
        )[0] == 403

        now = time.time()
        device_id = "dev_http_canary"
        fixture.cp.store.conn.execute(
            "INSERT INTO device_credentials VALUES(?,?,?,?,?,?,?,NULL)",
            (
                device_id, "dfm_http_canary", fixture.user, fixture.workspace,
                now, now + 3600, now,
            ),
        )
        device_tokens = fixture.cp.device_auth._mint_pair(
            device_id=device_id,
            workspace_id=fixture.workspace,
            absolute_expires_at=now + 3600,
            now=now,
        )
        fixture.cp.store.conn.commit()
        assert fixture.request(
            "POST", path, projection,
            {"Authorization": f"Bearer {device_tokens.access_token}"},
        )[0] == 403
        upload_path = (
            f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/runs/"
            "missing/result-projection"
        )
        # The server answers 413 from the declared Content-Length and closes without reading
        # the body, so only the headers are sent: writing the body would race that close
        # (BrokenPipe/reset) and could lose the very 413 this asserts.
        connection = http.client.HTTPConnection(
            "127.0.0.1", fixture.server.server_address[1], timeout=5,
        )
        try:
            connection.putrequest("POST", upload_path)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(272 * 1024 + 1))
            connection.endheaders()
            response = connection.getresponse()
            status, body = response.status, json.loads(response.read())
        finally:
            connection.close()
        assert status == 413 and body["error"] == "request body too large"

        unavailable_projection = approval_projection(
            unavailable.runner,
            workspace_id=unavailable.workspace,
            project_ref=unavailable.project,
        )
        unavailable_path = (
            f"/v1/workspaces/{unavailable.workspace}/projects/{unavailable.project}/"
            "canary-approval-projections"
        )
        status, _, body = unavailable.request(
            "POST", unavailable_path, unavailable_projection, unavailable.browser,
        )
        assert status == 503
        assert body == {
            "schema_version": "heel.canary-error.v1",
            "code": "canary_authority_unavailable",
        }
    finally:
        fixture.close()
        unavailable.close()


def test_disclosure_local_only_records_no_findings_payload(canary_http):
    fixture = canary_http
    projection = approval_projection(
        fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project,
    )
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    status, _, submitted = fixture.request(
        "POST", base + "/canary-approval-projections", projection, fixture.browser,
    )
    assert status == 201
    run_path = base + "/canary-runs/" + submitted["run_id"]
    status, _, approved = fixture.request(
        "POST",
        run_path + "/approve",
        {
            "schema_version": "heel.canary-execution-approval.v1",
            "projection_digest": projection["projection_digest"],
            "hostname_retype": "canary.acme.dev",
            "reason": "Keep this bounded result on the paired runner",
        },
        {
            **fixture.browser,
            "Idempotency-Key": "ca1-" + "c" * 64,
            "If-Heel-Control-Generation": "0",
        },
    )
    assert status == 201
    coordinator = CanaryRunService(
        fixture.cp.store.conn,
        signing=fixture.cloud,
        runner_auth=fixture.cp.runner_auth,
    )
    coordinator.claim(fixture.workspace, fixture.runner_id, fixture.runner.key_id)
    terminal = fixture.operational(
        approved["grant"], sequence=0, phase="terminal", disposition="completed",
    )
    coordinator.result(
        fixture.workspace, fixture.project, submitted["run_id"], fixture.runner_id,
        terminal,
    )
    findings = _findings(fixture.runner, approved["grant"], terminal)
    findings["workspace_id"] = fixture.workspace
    findings["project_id"] = fixture.project
    unsigned = {
        key: item for key, item in findings.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    findings["projection_digest"] = canonical_digest(unsigned)
    findings.update(fixture.runner.sign(canonical_bytes(unsigned)))
    status, _, decision = fixture.request(
        "POST",
        run_path + "/disclosure-local-only",
        {
            "schema_version": "heel.canary-disclosure-local-only.v1",
            "projection_digest": findings["projection_digest"],
            "projection_bytes": len(canonical_bytes(findings)),
            "scenario_count": 1,
            "finding_count": 1,
        },
        fixture.browser,
    )
    assert status == 200 and decision["status"] == "local_only"
    assert fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_findings_projections"
    ).fetchone()[0] == 0
    status, _, body = fixture.request(
        "GET", run_path + "/findings", headers=fixture.browser,
    )
    assert status == 404 and body == {
        "schema_version": "heel.canary-error.v1", "code": "canary_run_not_found",
    }


def test_runner_request_keeps_the_short_busy_timeout_when_human_writer_is_held(canary_http):
    fixture = canary_http
    claim_path = f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/claim"
    claim_body = canonical_bytes({"schema_version": "heel.runner-claim-request.v1"})
    headers = fixture.pop(
        claim_path,
        claim_body,
        capability="runner_claim",
        nonce=fixture.claim_nonce,
        sequence=1,
    )
    fixture.cp.store.conn.execute("BEGIN IMMEDIATE")
    fixture.cp.store.conn.execute(
        "UPDATE workspaces SET name=name WHERE workspace_id=?", (fixture.workspace,),
    )
    try:
        started = time.monotonic()
        status, _, _ = fixture.request(
            "POST", claim_path, headers=headers, raw=claim_body,
        )
        elapsed = time.monotonic() - started
    finally:
        fixture.cp.store.conn.rollback()
    assert status == 500
    assert elapsed < 1.5
    assert fixture.cp.store.conn.execute(
        "SELECT next_sequence FROM canary_runner_chain_cursors "
        "WHERE workspace_id=? AND runner_id=? AND chain_name='claim'",
        (fixture.workspace, fixture.runner_id),
    ).fetchone()[0] == 1
    assert fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_runner_request_ledger WHERE workspace_id=? "
        "AND runner_id=? AND chain_name='claim'",
        (fixture.workspace, fixture.runner_id),
    ).fetchone()[0] == 0
    assert any(
        statement.strip().upper() == "PRAGMA BUSY_TIMEOUT=250"
        for statement in fixture.runner_sql
    )
    assert not any(
        statement.strip().upper() == "PRAGMA BUSY_TIMEOUT=5000"
        for statement in fixture.runner_sql
    )


# --- C2: discovery authorization, inventory and plan-request routes (discovery contract §3, §6) ---

from heel.canary_contracts import DISCOVERY_ACKNOWLEDGEMENT, DISCOVERY_BOUND, DISCOVERY_SEED_DIGEST

ENV = "env_canary"


def _key(n: int) -> str:
    return "ca1-" + f"{n:064x}"


def _authorization_body(**overrides) -> dict:
    body = {"schema_version": "heel.discovery-authorization.v1", "environment_id": ENV,
            "identities_authorized": ["Admin user"], "login_exchange_authorized": False,
            "acknowledgement": DISCOVERY_ACKNOWLEDGEMENT}
    body.update(overrides)
    return body


def _env_base(fixture, environment: str = ENV, project: str | None = None) -> str:
    return f"/v1/workspaces/{fixture.workspace}/projects/{project or fixture.project}/environments/{environment}"


def _authorize(fixture, key: int = 1, body=None, headers=None, environment: str = ENV, project: str | None = None):
    request_headers = {**fixture.browser, "Idempotency-Key": _key(key)}
    request_headers.update(headers or {})
    return fixture.request(
        "POST", _env_base(fixture, environment, project) + "/discovery-authorizations",
        _authorization_body(environment_id=environment) if body is None else body, request_headers,
    )


def _session_for(fixture, role: Role, email: str) -> dict[str, str]:
    user = fixture.cp.store.create_user(email)
    fixture.cp.store.add_member(fixture.workspace, user, role)
    session = fixture.cp.auth.create_session(user)
    return {"Cookie": f"heel_session={session.token}", "Origin": "https://heel.test",
            "X-Heel-Internal-Origin": "same-origin"}


def _ledger(fixture) -> list[tuple[str, str]]:
    return [tuple(row) for row in fixture.cp.store.conn.execute(
        "SELECT kind,ref FROM usage_ledger WHERE meter='canary_runs' ORDER BY ts,entry_id")]


def test_discovery_authorization_requires_verified_environment_owner_admin_recent_auth_same_origin_and_idempotency_key(canary_http):
    fixture = canary_http
    member = _session_for(fixture, Role.MEMBER, "member@canary.test")
    admin = _session_for(fixture, Role.ADMIN, "admin@canary.test")
    stale = dict(fixture.browser)
    fixture.cp.store.conn.execute("UPDATE sessions SET created_at=created_at-901 WHERE user_id=?", (fixture.user,))
    fixture.cp.store.conn.commit()
    api_key = fixture.cp.store.issue_api_key(fixture.workspace, Role.OWNER, "ci").secret
    path = _env_base(fixture) + "/discovery-authorizations"
    body = _authorization_body()
    refusals = {
        "member": (member, 403),
        "stale owner session": (stale, 403),
        "cross origin": ({**admin, "Origin": "https://evil.test"}, 403),
        "missing internal same-origin marker": ({k: v for k, v in admin.items() if k != "X-Heel-Internal-Origin"}, 403),
        "api key": ({"Authorization": f"Bearer {api_key}"}, 404),
        "anonymous": ({}, 404),
    }
    for name, (headers, expected) in refusals.items():
        status, _, data = fixture.request("POST", path, body, {**headers, "Idempotency-Key": _key(9)})
        assert status == expected, name
    status, _, data = fixture.request("POST", path, body, admin)
    assert (status, data["code"]) == (400, "idempotency_key_required")
    status, _, data = fixture.request("POST", path, body, {**admin, "Idempotency-Key": "ca1-short"})
    assert (status, data["code"]) == (400, "idempotency_key_required")
    for bad in (_authorization_body(login_exchange_authorized=True), _authorization_body(environment_id="env_other"),
                _authorization_body(password="hunter2"), _authorization_body(acknowledgement="ok")):
        status, _, data = fixture.request("POST", path, bad, {**admin, "Idempotency-Key": _key(8)})
        assert (status, data["code"]) == (400, "invalid_discovery_authorization")
    assert _ledger(fixture) == []
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM discovery_authorizations").fetchone()[0] == 0

    fixture.cp.store.conn.execute("UPDATE canary_environments SET status='pending' WHERE environment_id=?", (ENV,))
    fixture.cp.store.conn.commit()
    status, _, data = fixture.request("POST", path, body, {**admin, "Idempotency-Key": _key(7)})
    assert (status, data["code"]) == (409, "environment_not_verified")
    fixture.cp.store.conn.execute("UPDATE canary_environments SET status='verified' WHERE environment_id=?", (ENV,))
    fixture.cp.store.conn.commit()
    status, _, data = fixture.request(
        "POST", _env_base(fixture, "env_missing") + "/discovery-authorizations",
        _authorization_body(environment_id="env_missing"), {**admin, "Idempotency-Key": _key(6)})
    assert (status, data["code"]) == (404, "environment_not_found")

    status, _, view = fixture.request("POST", path, body, {**admin, "Idempotency-Key": _key(1)})
    assert status == 201
    assert view["schema_version"] == "heel.discovery-authorization-view.v1"
    assert view["state"] == "open" and view["actor_role"] == "admin" and view["login_exchange_authorized"] is False
    assert view["bound"] == DISCOVERY_BOUND and view["seed_digest"] == DISCOVERY_SEED_DIGEST
    assert view["expires_at_ms"] == view["created_at_ms"] + 900_000
    assert (view["actions_remaining"], view["rounds_remaining"], view["execution_ms_remaining"]) == (100, 5, 120_000)
    assert "reservation_id" not in view and "idempotency_key" not in view
    assert _ledger(fixture) == [("reserve", view["authorization_id"])]
    # Members may read the exact project's authorization; API keys and other projects may not.
    status, _, read = fixture.request("GET", path + "/" + view["authorization_id"], headers=member)
    assert status == 200 and read == view
    status, _, _ = fixture.request("GET", path + "/" + view["authorization_id"], headers={"Authorization": f"Bearer {api_key}"})
    assert status == 404


def test_one_open_discovery_authorization_per_environment(canary_http):
    fixture = canary_http
    status, _, first = _authorize(fixture, 1)
    assert status == 201
    # Identical retry under the same key is the same row and the same single unit.
    assert _authorize(fixture, 1)[2] == first
    status, _, data = _authorize(fixture, 1, body=_authorization_body(identities_authorized=["Other"]))
    assert (status, data["code"]) == (409, "idempotency_conflict")
    status, _, data = _authorize(fixture, 2)
    assert (status, data["code"]) == (409, "authorization_open")
    assert _ledger(fixture) == [("reserve", first["authorization_id"])]

    # Concurrent identical creates and concurrent different-key creates: exactly one open row.
    status, _, revoked = fixture.request(
        "POST", _env_base(fixture) + "/discovery-authorizations/" + first["authorization_id"] + "/revoke",
        headers=fixture.browser)
    assert status == 200 and revoked["state"] == "revoked" and revoked["quota_state"] == "refunded"
    results: list[tuple[int, dict]] = []
    lock = threading.Lock()

    def create(key: int, identities: list[str]):
        status, _, data = _authorize(fixture, key, body=_authorization_body(identities_authorized=identities))
        with lock:
            results.append((status, data))

    threads = [threading.Thread(target=create, args=(10, ["A"])) for _ in range(3)]
    threads += [threading.Thread(target=create, args=(11 + index, ["B"])) for index in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    created = [data for status, data in results if status == 201]
    assert {data["authorization_id"] for data in created} and len({data["authorization_id"] for data in created}) == 1
    assert all(data["code"] == "authorization_open" for status, data in results if status != 201)
    rows = fixture.cp.store.conn.execute(
        "SELECT state,COUNT(*) FROM discovery_authorizations GROUP BY state ORDER BY state").fetchall()
    assert [tuple(row) for row in rows] == [("open", 1), ("revoked", 1)]
    reserves = [ref for kind, ref in _ledger(fixture) if kind == "reserve"]
    assert len(reserves) == 2 and len(set(reserves)) == 2


def test_discovery_authorization_revoke_requires_recent_owner_admin_and_closes_once(canary_http):
    fixture = canary_http
    status, _, view = _authorize(fixture, 1)
    revoke = _env_base(fixture) + "/discovery-authorizations/" + view["authorization_id"] + "/revoke"
    member = _session_for(fixture, Role.MEMBER, "member@canary.test")
    assert fixture.request("POST", revoke, headers=member)[0] == 403
    assert fixture.request("POST", revoke, {"reason": "x"}, fixture.browser)[0] == 400
    status, _, revoked = fixture.request("POST", revoke, headers=fixture.browser)
    assert status == 200 and revoked["state"] == "revoked" and revoked["close_reason"] == "revoked"
    assert revoked["revoked_by"] == fixture.user and revoked["closed_at_ms"] is not None
    status, _, data = fixture.request("POST", revoke, headers=fixture.browser)
    assert (status, data["code"]) == (409, "authorization_closed")
    assert _ledger(fixture) == [("reserve", view["authorization_id"]), ("refund", view["authorization_id"])]
    # Expiry is a server-clock fact: an aged open row reads as expired and refunds exactly once.
    status, _, second = _authorize(fixture, 2)
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
        "WHERE authorization_id=?", (second["authorization_id"],))
    fixture.cp.store.conn.commit()
    read = _env_base(fixture) + "/discovery-authorizations/" + second["authorization_id"]
    for _ in range(2):
        status, _, expired = fixture.request("GET", read, headers=fixture.browser)
        assert status == 200 and expired["state"] == "expired" and expired["quota_state"] == "refunded"
    assert _ledger(fixture)[-2:] == [("reserve", second["authorization_id"]), ("refund", second["authorization_id"])]


def test_identities_inventory_discovery_and_evidence_are_project_scoped(canary_http):
    """Project isolation for the C2 surfaces; identity and evidence routes are C5/C6 (not built)."""
    fixture = canary_http
    status, _, view = _authorize(fixture, 1)
    assert status == 201
    other = fixture.cp.projects.create(fixture.workspace, "Other", created_by=fixture.user).project_ref
    foreign_paths = (
        ("GET", _env_base(fixture, project=other) + "/discovery-authorizations/" + view["authorization_id"]),
        ("POST", _env_base(fixture, project=other) + "/discovery-authorizations/" + view["authorization_id"] + "/revoke"),
        ("GET", _env_base(fixture, project=other) + "/route-inventory"),
        ("GET", _env_base(fixture, project="prj_missing") + "/route-inventory"),
    )
    for method, path in foreign_paths:
        status, _, data = fixture.request(method, path, headers=fixture.browser)
        assert status == 404, path
        assert view["authorization_id"] not in json.dumps(data)
    status, _, data = _authorize(fixture, 2, project=other)
    assert (status, data["code"]) == (404, "environment_not_found")
    # Another workspace's session sees nothing of this project.
    org = fixture.cp.store.create_org("Elsewhere")
    elsewhere = fixture.cp.store.create_workspace(org, "Elsewhere", "free", CATALOG_VERSION)
    stranger = fixture.cp.store.create_user("stranger@else.test")
    fixture.cp.store.add_member(elsewhere, stranger, Role.OWNER)
    foreign_session = {"Cookie": f"heel_session={fixture.cp.auth.create_session(stranger).token}",
                       "Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"}
    for method, path in (("GET", _env_base(fixture) + "/discovery-authorizations/" + view["authorization_id"]),
                         ("GET", _env_base(fixture) + "/route-inventory")):
        assert fixture.request(method, path, headers=foreign_session)[0] == 404
    assert _authorize(fixture, 3, headers=foreign_session)[0] == 404
    status, _, inventory = fixture.request("GET", _env_base(fixture) + "/route-inventory", headers=fixture.browser)
    assert status == 200 and inventory["routes"] == [] and inventory["route_count"] == 0
    assert inventory["inventory_digest"] == canonical_digest([])


INVENTORY_ROUTES = (("GET", "/api/v1/orders"), ("GET", "/api/v1/orders/{p1}"), ("HEAD", "/api/v1/status"))


def _seed_inventory(fixture, routes=INVENTORY_ROUTES, *, environment: str = ENV) -> str:
    """Explicit seam: C2 writes inventories only from discovery reports; tests seed one directly."""
    rows = [{"method": method, "route_template": route,
             "provenance": [{"kind": "html_link", "round": 1, "source_ordinal": 11, "status_code": 200}],
             "first_seen_ms": 1, "state": "candidate"} for method, route in routes]
    digest = canonical_digest(rows)
    fixture.cp.store.conn.execute(
        "INSERT OR REPLACE INTO route_inventories VALUES(?,?,?,?,?,?,?,?)",
        (fixture.workspace, fixture.project, environment, digest, len(rows), 0,
         canonical_bytes(rows).decode(), int(time.time() * 1000)),
    )
    fixture.cp.store.conn.commit()
    return digest


class _RunnerClaimChain:
    """The runner's single PoP ``claim`` chain, shared by every context route."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.nonce = fixture.claim_nonce
        self.sequence = 1

    def post(self, path: str, body: dict):
        raw = canonical_bytes(body)
        status, headers, data = self.fixture.request(
            "POST", path, headers=self.fixture.pop(path, raw, capability="runner_claim",
                                                   nonce=self.nonce, sequence=self.sequence), raw=raw)
        if "X-Heel-Runner-Next-Nonce" in headers:
            self.nonce = headers["X-Heel-Runner-Next-Nonce"]
            self.sequence += 1
        return status, headers, data


def _binding(fixture) -> dict:
    path = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/runner-context-bindings"
    status, _, created = fixture.request("POST", path, headers=fixture.browser, raw=canonical_bytes({
        "schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENV,
        "verification_record_digest": "a" * 64, "runner_id": fixture.runner_id,
        "runner_key_id": fixture.runner.key_id,
    }))
    assert status == 201
    return created["context_binding"]


def _plan_request(fixture, binding: dict, routes=(INVENTORY_ROUTES[0],), *, max_ops: int = 2, headers=None):
    path = (f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/runner-context-bindings/"
            f"{binding['binding_id']}/plan-requests")
    return fixture.request("POST", path, {
        "schema_version": "heel.plan-request.v1", "plan_kind": "plan_differential", "max_ops": max_ops,
        "routes": [{"method": method, "route_template": route} for method, route in routes],
    }, headers or fixture.browser)


def _claim_plan_request(fixture, chain: _RunnerClaimChain, binding: dict):
    path = (f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/contexts/"
            f"{binding['binding_id']}/plan-requests/claim")
    return chain.post(path, {
        "schema_version": "heel.runner-plan-request-claim.v1", "binding_id": binding["binding_id"],
        "binding_digest": binding["binding_digest"],
        "credential_roles": [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}],
    })


def _signed_projection(fixture, *, projection_id: str, plan: dict | None, routes) -> dict:
    value = approval_projection(fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project)
    for key in ("projection_digest", "signing_key_id", "signature_b64"):
        value.pop(key)
    template = value["actions"][0]
    value["projection_id"] = projection_id
    value["actions"] = [{**template, "ordinal": index, "method": method, "route_template": route}
                        for index, (method, route) in enumerate(routes)]
    value["budgets"] = {**value["budgets"], "maximum_requests": len(routes)}
    if plan is not None:
        value["schema_version"] = "heel.approval-manifest-projection.v2"
        value["plan"] = plan
    value["projection_digest"] = canonical_digest(value)
    value.update(fixture.runner.sign(canonical_bytes({k: v for k, v in value.items() if k != "projection_digest"})))
    return value


def _scan_plan(snapshot: dict, **overrides) -> dict:
    plan = {"plan_kind": "plan_differential", "plan_request_id": snapshot["plan_request_id"],
            "plan_request_nonce": snapshot["plan_request_nonce"], "inventory_digest": snapshot["inventory_digest"],
            "selection_digest": snapshot["selection_digest"], "selected_count": len(snapshot["routes"]),
            "plan_labels": [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}],
            "max_ops": snapshot["max_ops"], "not_executed_count": 0, "not_executed_digest": canonical_digest([])}
    plan.update(overrides)
    return plan


def _submit(fixture, chain: _RunnerClaimChain, binding: dict, projection: dict):
    path = (f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/contexts/"
            f"{binding['binding_id']}/approval-projections")
    return chain.post(path, {
        "schema_version": "heel.runner-approval-projection-submit.v1", "context_binding_id": binding["binding_id"],
        "context_binding_digest": binding["binding_digest"], "approval_projection": projection,
    })


def _plan_rows(fixture):
    return [tuple(row) for row in fixture.cp.store.conn.execute(
        "SELECT plan_request_id,status,approval_id FROM canary_plan_requests ORDER BY created_at_ms,plan_request_id")]


def test_v2_projection_binds_plan_request_nonce_inventory_selection_and_labels(canary_http):
    fixture = canary_http
    inventory_digest = _seed_inventory(fixture)
    binding = _binding(fixture)
    chain = _RunnerClaimChain(fixture)
    assert _claim_plan_request(fixture, chain, binding)[0] == 204
    status, _, created = _plan_request(fixture, binding)
    assert status == 201 and created["inventory_digest"] == inventory_digest
    assert created["routes"] == [{"method": "GET", "route_template": "/api/v1/orders"}]
    assert created["selection_digest"] == canonical_digest(created["routes"])
    assert "plan_request_nonce" not in created
    status, _, snapshot = _claim_plan_request(fixture, chain, binding)
    assert status == 200 and snapshot["schema_version"] == "heel.runner-plan-request.v1"
    assert (snapshot["plan_request_id"], snapshot["routes"], snapshot["inventory_digest"], snapshot["selection_digest"]) == (
        created["plan_request_id"], created["routes"], inventory_digest, created["selection_digest"])
    projection = _signed_projection(fixture, projection_id="ap_plan_one", plan=_scan_plan(snapshot), routes=[("GET", "/api/v1/orders")])
    status, _, submitted = _submit(fixture, chain, binding, projection)
    assert status == 201 and submitted["status"] == "awaiting_execution_approval"
    assert _plan_rows(fixture) == [(created["plan_request_id"], "projected", "ap_plan_one")]

    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    status, _, listed = fixture.request("GET", base + "/canary-approval-requests", headers=fixture.browser)
    assert status == 200 and listed["requests"][0]["plan"] == projection["plan"]
    assert listed["requests"][0]["inventory_changed"] is False
    _seed_inventory(fixture, INVENTORY_ROUTES[:2])
    listed = fixture.request("GET", base + "/canary-approval-requests", headers=fixture.browser)[2]
    assert listed["requests"][0]["inventory_changed"] is True
    # The human still approves the exact signed digest; the snapshot, not the live inventory, binds.
    status, _, approved = fixture.request("POST", base + "/canary-runs/" + submitted["run_id"] + "/approve", {
        "schema_version": "heel.canary-execution-approval.v1", "projection_digest": projection["projection_digest"],
        "hostname_retype": "canary.acme.dev", "reason": "Run the selected plan pair",
    }, {**fixture.browser, "Idempotency-Key": _key(40), "If-Heel-Control-Generation": "0"})
    assert status == 201 and approved["grant"]["approval"]["projection_digest"] == projection["projection_digest"]
    assert _plan_rows(fixture) == [(created["plan_request_id"], "approved", "ap_plan_one")]


def test_projection_with_stale_inventory_or_selection_digest_is_rejected(canary_http):
    fixture = canary_http
    _seed_inventory(fixture)
    binding = _binding(fixture)
    chain = _RunnerClaimChain(fixture)
    created = _plan_request(fixture, binding, routes=INVENTORY_ROUTES[:2])[2]
    snapshot = _claim_plan_request(fixture, chain, binding)[2]
    selected = [("GET", "/api/v1/orders")]
    stale = {
        "inventory digest": (_scan_plan(snapshot, inventory_digest="f" * 64), selected),
        "selection digest": (_scan_plan(snapshot, selection_digest="f" * 64), selected),
        "nonce": (_scan_plan(snapshot, plan_request_nonce="x" * 43), selected),
        "selected count": (_scan_plan(snapshot, selected_count=1), selected),
        "route outside selection": (_scan_plan(snapshot), [("HEAD", "/api/v1/status")]),
        "more actions than max_ops": (_scan_plan(snapshot), [("GET", "/api/v1/orders"), ("GET", "/api/v1/orders/{p1}"), ("GET", "/api/v1/orders")]),
    }
    for index, (name, (plan, routes)) in enumerate(stale.items()):
        projection = _signed_projection(fixture, projection_id=f"ap_stale_{index}", plan=plan, routes=routes)
        status, _, data = _submit(fixture, chain, binding, projection)
        assert (status, data["code"]) == (409, "inventory_mismatch"), name
    assert _plan_rows(fixture) == [(created["plan_request_id"], "open", None)]
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_approval_projections").fetchone()[0] == 0


def test_same_projection_cannot_be_replayed_under_a_second_plan_request(canary_http):
    fixture = canary_http
    _seed_inventory(fixture)
    binding = _binding(fixture)
    chain = _RunnerClaimChain(fixture)
    first = _plan_request(fixture, binding)[2]
    first_snapshot = _claim_plan_request(fixture, chain, binding)[2]
    projection = _signed_projection(fixture, projection_id="ap_once", plan=_scan_plan(first_snapshot), routes=[("GET", "/api/v1/orders")])
    status, _, submitted = _submit(fixture, chain, binding, projection)
    assert status == 201
    assert _submit(fixture, chain, binding, projection)[2] == submitted  # identical replay is idempotent
    # The consumed request cannot bind a second projection.
    other = _signed_projection(fixture, projection_id="ap_twice", plan=_scan_plan(first_snapshot), routes=[("GET", "/api/v1/orders")])
    status, _, data = _submit(fixture, chain, binding, other)
    assert (status, data["code"]) == (409, "plan_request_consumed")
    second = _plan_request(fixture, binding)[2]
    second_snapshot = _claim_plan_request(fixture, chain, binding)[2]
    assert second_snapshot["plan_request_id"] == second["plan_request_id"]
    # The same projection identity re-signed under the second request is a projection conflict.
    replayed = _signed_projection(fixture, projection_id="ap_once", plan=_scan_plan(second_snapshot), routes=[("GET", "/api/v1/orders")])
    status, _, _ = _submit(fixture, chain, binding, replayed)
    # Pre-existing projection_id/digest uniqueness (``projection_conflict``); the context route
    # has always surfaced coordinator conflicts as the opaque runner-auth refusal.
    assert status == 401
    assert _plan_rows(fixture) == [(first["plan_request_id"], "projected", "ap_once"), (second["plan_request_id"], "open", None)]
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_approval_projections").fetchone()[0] == 1


def test_v1_projection_on_a_binding_with_an_open_plan_request_is_rejected_and_v2_catalog_is_rejected(canary_http):
    fixture = canary_http
    _seed_inventory(fixture)
    binding = _binding(fixture)
    chain = _RunnerClaimChain(fixture)
    _plan_request(fixture, binding)
    v1 = _signed_projection(fixture, projection_id="ap_v1", plan=None, routes=[("GET", "/api/v1/orders")])
    status, _, data = _submit(fixture, chain, binding, v1)
    assert (status, data["code"]) == (409, "plan_binding_required")
    snapshot = _claim_plan_request(fixture, chain, binding)[2]
    foreign = _signed_projection(fixture, projection_id="ap_v2_unknown",
                                 plan=_scan_plan(snapshot, plan_request_id="cpr_" + "9" * 32), routes=[("GET", "/api/v1/orders")])
    status, _, data = _submit(fixture, chain, binding, foreign)
    assert (status, data["code"]) == (409, "plan_binding_required")
    # A browser upload never carries a v2 plan.
    v2 = _signed_projection(fixture, projection_id="ap_v2_browser", plan=_scan_plan(snapshot), routes=[("GET", "/api/v1/orders")])
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    status, _, data = fixture.request("POST", base + "/canary-approval-projections", v2, fixture.browser)
    assert (status, data["code"]) == (400, "invalid_canary_projection")
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_approval_projections").fetchone()[0] == 0


def test_plan_request_creation_requires_recent_owner_admin_and_a_selection_inside_the_snapshot(canary_http):
    fixture = canary_http
    binding = _binding(fixture)
    status, _, data = _plan_request(fixture, binding)
    assert (status, data["code"]) == (409, "selection_outside_inventory")
    _seed_inventory(fixture)
    member = _session_for(fixture, Role.MEMBER, "member@canary.test")
    assert _plan_request(fixture, binding, headers=member)[0] == 403
    status, _, data = _plan_request(fixture, binding, routes=[("GET", "/api/v1/unknown")])
    assert (status, data["code"]) == (409, "selection_outside_inventory")
    assert _plan_request(fixture, binding)[0] == 201
    status, _, data = _plan_request(fixture, binding)
    assert (status, data["code"]) == (409, "plan_request_open")
