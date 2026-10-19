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


# --- C2 bounded discovery rounds (contract §4, §4a, §5, §6).  These tests prove the server's
# recorded relationships, budgets and authority; they never send target traffic and never
# claim that a candidate was really present in a target response body (trust boundary §2.6). ---

from heel.canary_contracts import DISCOVERY_SEED_PATHS, discovery_frontier_digest
from canary_test_support import NOW_MS, operational_projection as _base_operational


def _sign_record(signer, value: dict, digest_field: str) -> dict:
    unsigned = {k: v for k, v in value.items() if k not in {digest_field, "signing_key_id", "signature_b64"}}
    record = {**unsigned, digest_field: canonical_digest(unsigned)}
    record.update(signer.sign(canonical_bytes(unsigned)))
    return record


class DiscoveryDriver:
    """One authorization driven over real HTTP: browser routes plus runner PoP chains."""

    def __init__(self, fixture, *, key: int = 1, chain: _RunnerClaimChain | None = None, binding=None, signer=None,
                 runner_id: str | None = None):
        self.fixture = fixture
        self.signer = signer or fixture.runner
        self.runner_id = runner_id or fixture.runner_id
        status, _, self.view = _authorize(fixture, key)
        assert status == 201, self.view
        self.authorization_id = self.view["authorization_id"]
        self.binding = binding or _binding(fixture)
        self.chain = chain or _RunnerClaimChain(fixture)
        self.reports: dict[int, list[dict]] = {}

    # projections -------------------------------------------------------------------------
    def projection(self, round_number: int, references, *, projection_id: str | None = None, wall: int = 60_000,
                   cumulative: int | None = None, routes=None, body_bytes: int = 2_097_152, **plan_overrides) -> dict:
        """``references``: list of (source_round, candidate) pairs; round 1 uses the seed list."""
        if round_number == 1 and references is None:
            references = [(0, {"method": "GET", "route_template": path, "source_ordinal": index})
                          for index, path in enumerate(DISCOVERY_SEED_PATHS)]
        if routes is None:
            routes = [(candidate["method"], candidate["route_template"]) for _, candidate in references]
        sources = [{"ordinal": index, "round": source_round, "source_ordinal": candidate["source_ordinal"]}
                   for index, (source_round, candidate) in enumerate(references)]
        frontier = DISCOVERY_SEED_DIGEST if round_number == 1 else discovery_frontier_digest(
            [{"round": source_round, "candidate": candidate} for source_round, candidate in references])
        plan = {"plan_kind": "discovery", "authorization_id": self.authorization_id,
                "authorization_digest": self.view["authorization_digest"], "round": round_number,
                "frontier_digest": frontier,
                "cumulative_requests_before": self.issued_actions() if cumulative is None else cumulative,
                "transport_profile": "discovery", "action_count": len(routes), "sources": sources}
        plan.update(plan_overrides)
        value = approval_projection(self.signer, workspace_id=self.fixture.workspace, project_ref=self.fixture.project,
                                    runner_id=self.runner_id)
        for key in ("projection_digest", "signing_key_id", "signature_b64"):
            value.pop(key)
        template = value["actions"][0]
        value["schema_version"] = "heel.approval-manifest-projection.v2"
        value["projection_id"] = projection_id or f"ap_{self.authorization_id[-8:]}_r{round_number}_{len(routes)}"
        value["actions"] = [{**template, "ordinal": index, "method": method, "route_template": route}
                            for index, (method, route) in enumerate(routes)]
        value["budgets"] = {**value["budgets"], "maximum_requests": len(routes), "wall_timeout_ms": wall,
                            "maximum_response_bytes": body_bytes}
        value["plan"] = plan
        return _sign_record(self.signer, value, "projection_digest")

    def issued_actions(self) -> int:
        return self.row()["actions_issued"]

    def row(self):
        return self.fixture.cp.store.conn.execute(
            "SELECT * FROM discovery_authorizations WHERE authorization_id=?", (self.authorization_id,)).fetchone()

    def submit(self, projection: dict, *, chain=None, binding=None):
        return _submit(self.fixture, chain or self.chain, binding or self.binding, projection)

    # grants, results and reports -----------------------------------------------------------
    def claim(self, *, chain=None):
        chain = chain or self.chain
        path = f"/v1/workspaces/{self.fixture.workspace}/runners/{self.runner_id}/claim"
        status, _, claimed = chain.post(path, {"schema_version": "heel.runner-claim-request.v1"})
        assert status == 200, claimed
        return claimed

    def operational(self, grant: dict, *, sequence: int, phase: str, completed: int = 0, started: int | None = None,
                    stop_reason: str = "none", disposition: str | None = None, error_category: str = "none") -> dict:
        started = completed if started is None else started
        value = _base_operational(self.signer, grant, sequence=sequence, phase=phase)
        now_ms = int(time.time() * 1000)
        value["execution_disposition"] = disposition if phase == "terminal" else None
        value["stop_reason"] = stop_reason
        stop_at = now_ms - 50 if stop_reason != "none" else None
        value["timestamps"] = {
            "claimed_at_ms": now_ms - 200, "started_at_ms": None if phase == "claimed" else now_ms - 100,
            "updated_at_ms": now_ms, "stop_requested_at_ms": stop_at,
            "stop_acknowledged_at_ms": None,
            "terminal_at_ms": now_ms if phase == "terminal" else None,
        }
        maximum = grant["budgets"]["maximum_requests"]
        value["counters"] = {"requests_started": started, "requests_completed": completed,
                             "response_bytes_read": completed * 10, "actions_contained": started,
                             "retries_used": 0, "remaining_requests": maximum - started,
                             "remaining_wall_ms": grant["budgets"]["wall_timeout_ms"] - 1}
        value["containment_codes"] = ["admitted"] if started else []
        value["error_category"] = error_category
        return _sign_record(self.signer, value, "projection_digest")

    def report(self, round_number: int, grant: dict, candidates: list[dict], *, bytes_received: int = 1234,
               excluded: int = 0, truncated: int = 0) -> dict:
        return _sign_record(self.signer, {
            "schema_version": "heel.discovery-round-report.v1", "authorization_id": self.authorization_id,
            "round": round_number, "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "candidates": sorted(candidates, key=lambda c: (c["method"], c["route_template"])),
            "excluded_count": excluded, "truncated_count": truncated, "bytes_received": bytes_received,
        }, "report_digest")

    def run_path(self, run_id: str, operation: str) -> str:
        return f"/v1/workspaces/{self.fixture.workspace}/runners/{self.runner_id}/runs/{run_id}/{operation}"

    def post_chain(self, claimed: dict, operation: str, body: dict, *, capability: str):
        """Post on one of the run's own PoP chains, advancing it like the runner does."""
        state = claimed["chain_states"][operation]
        raw = canonical_bytes(body)
        path = self.run_path(claimed["run_id"], operation)
        headers = self.fixture.pop(path, raw, capability=capability, nonce=state["next_nonce_b64"],
                                   sequence=state["next_sequence"])
        status, response_headers, data = self.fixture.request("POST", path, headers=headers, raw=raw)
        if "X-Heel-Runner-Next-Nonce" in response_headers:
            state["next_nonce_b64"] = response_headers["X-Heel-Runner-Next-Nonce"]
            state["next_sequence"] += 1
        return status, data, (path, raw, headers)

    def heartbeat(self, claimed: dict, sequence: int, phase: str = "running", completed: int = 0):
        projection = self.operational(claimed["grant"], sequence=sequence, phase=phase, completed=completed)
        return self.post_chain(claimed, "heartbeat", {"schema_version": "heel.runner-heartbeat-request.v1",
                                                      "run_id": claimed["run_id"], "operational_projection": projection},
                               capability="runner_heartbeat")

    def finish(self, claimed: dict, candidates: list[dict] | None, *, completed: int | None = None, sequence: int = 50,
               report: dict | None = None, round_number: int | None = None, stop_reason: str = "none",
               started: int | None = None, error_category: str = "none", disposition: str | None = None):
        grant = claimed["grant"]
        completed = grant["budgets"]["maximum_requests"] if completed is None else completed
        disposition = disposition or ("stopped" if stop_reason != "none" else "completed")
        projection = self.operational(grant, sequence=sequence, phase="terminal", completed=completed, started=started,
                                      stop_reason=stop_reason, disposition=disposition, error_category=error_category)
        body = {"schema_version": "heel.runner-result-request.v1", "run_id": claimed["run_id"],
                "operational_projection": projection}
        if candidates is not None or report is not None:
            body["discovery_round_report"] = report or self.report(round_number, grant, candidates)
        return self.post_chain(claimed, "result", body, capability="runner_result")

    def run_round(self, round_number: int, references=None, candidates: list[dict] | None = None, *,
                  completed: int | None = None, **projection_options):
        status, _, submitted = self.submit(self.projection(round_number, references, **projection_options))
        assert status == 201, submitted
        claimed = self.claim()
        assert claimed["run_id"] == submitted["run_id"]
        status, result, _ = self.finish(claimed, candidates or [], completed=completed, round_number=round_number)
        assert status == 200, result
        self.reports[round_number] = sorted(candidates or [], key=lambda c: (c["method"], c["route_template"]))
        return submitted, claimed, result


def _candidates(round_number: int, count: int, *, start: int = 0) -> list[dict]:
    return [{"method": "GET", "route_template": f"/api/r{round_number}/item{index}", "provenance_kind": "html_link",
             "source_ordinal": index % 12, "status_code": 200} for index in range(start, start + count)]


def _refs(round_number: int, candidates: list[dict]):
    return [(round_number, candidate) for candidate in candidates]


def _code(response) -> tuple[int, str | None]:
    status, _, data = response
    return status, (data or {}).get("code")


def test_discovery_round_projection_is_auto_issued_only_within_the_recorded_bound_and_refused_after_it(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    ledger_before = _ledger(fixture)
    candidates = {round_number: _candidates(round_number, 20) for round_number in range(1, 5)}
    status, _, first = driver.submit(driver.projection(1, None))
    assert status == 201 and first["status"] == "approved"
    assert first["round_state"] == {"authorization_id": driver.authorization_id, "round": 1, "state": "issued",
                                    "grant_id": first["grant"]["grant_id"], "actions": 12, "wall_budget_ms": 60_000,
                                    "grant_status": "issued"}
    grant = first["grant"]
    assert grant["approval_actor"] == {"user_id": fixture.user, "role": "owner"}
    assert grant["approval_reason"] == "discovery_authorization:" + driver.authorization_id
    assert grant["budgets"]["maximum_requests"] == 12
    claimed = driver.claim()
    assert claimed["grant"] == grant
    # The executor completes only 3 of 12 issued actions: issued actions stay charged.
    status, result, _ = driver.finish(claimed, candidates[1], completed=3, round_number=1)
    assert status == 200 and result["round_state"]["state"] == "terminal"
    row = driver.row()
    assert (row["rounds_issued"], row["actions_issued"], row["requests_completed"]) == (1, 12, 3)
    for round_number in range(2, 6):
        driver.run_round(round_number, _refs(round_number - 1, candidates[round_number - 1][:20]),
                         candidates.get(round_number))
    row = driver.row()
    assert (row["rounds_issued"], row["actions_issued"], row["state"], row["close_reason"]) == (5, 92, "done", "budget")
    # No sixth grant can ever exist: round 6 is outside the closed contract and the row is done.
    status, _, data = driver.submit(driver.projection(5, _refs(4, candidates[4][:1]), projection_id="ap_after_done"))
    assert (status, data["code"]) == (409, "round_consumed")
    assert fixture.cp.store.conn.execute(
        "SELECT COUNT(*) FROM discovery_rounds WHERE authorization_id=?", (driver.authorization_id,)).fetchone()[0] == 5
    # Exactly one CANARY_RUNS unit, consumed once, for all five rounds.
    assert _ledger(fixture) == ledger_before + [("consume", driver.authorization_id)]

    # 95 issued + a 10-action round would pass 100: refused and the authorization is done.
    second = DiscoveryDriver(fixture, key=2, chain=driver.chain, binding=driver.binding)
    second.run_round(1, None, _candidates(1, 10))
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET actions_issued=95 WHERE authorization_id=?", (second.authorization_id,))
    fixture.cp.store.conn.commit()
    over = second.projection(2, _refs(1, second.reports[1][:10]), cumulative=95)
    assert _code(second.submit(over)) == (409, "bound_exceeded")
    row = second.row()
    assert (row["state"], row["close_reason"], row["rounds_issued"], row["actions_issued"]) == ("done", "budget", 1, 95)
    # A 21-action round is a contract failure (opaque runner refusal), never a grant.
    third = DiscoveryDriver(fixture, key=3, chain=driver.chain, binding=driver.binding)
    third.run_round(1, None, _candidates(1, 21))
    oversize = third.projection(2, _refs(1, third.reports[1][:20]) + [(1, third.reports[1][20])])
    assert driver.submit(oversize)[0] == 401
    assert third.row()["rounds_issued"] == 1


def test_discovery_global_execution_budget_is_server_measured_and_refuses_when_under_ten_seconds_remain(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    driver.run_round(1, None, _candidates(1, 5))
    used = driver.row()["execution_ms_used"]
    round_row = fixture.cp.store.conn.execute(
        "SELECT issued_at_ms,terminal_at_ms FROM discovery_rounds WHERE authorization_id=? AND round=1",
        (driver.authorization_id,)).fetchone()
    assert used == round_row["terminal_at_ms"] - round_row["issued_at_ms"] >= 0
    # Explicit seam: 95 s already measured.  The next grant gets exactly the remaining 25 s.
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET execution_ms_used=95000 WHERE authorization_id=?", (driver.authorization_id,))
    fixture.cp.store.conn.commit()
    too_long = driver.projection(2, _refs(1, driver.reports[1][:2]), wall=60_000)
    assert _code(driver.submit(too_long)) == (409, "bound_exceeded")
    assert driver.row()["state"] == "open"  # asking for more wall time than remains is not exhaustion
    status, _, issued = driver.submit(driver.projection(2, _refs(1, driver.reports[1][:2]), wall=25_000,
                                                        projection_id="ap_r2_fit"))
    assert status == 201 and issued["grant"]["budgets"]["wall_timeout_ms"] == 25_000
    assert issued["round_state"]["wall_budget_ms"] == 25_000
    # A round abandoned by its executor is closed by the reaper at grant expiry and charges its
    # whole issued window (server clock), not a runner-reported duration.
    fixture.cp.store.conn.execute(
        "UPDATE discovery_rounds SET issued_at_ms=issued_at_ms-601000 WHERE authorization_id=? AND round=2",
        (driver.authorization_id,))
    fixture.cp.store.conn.execute(
        "UPDATE canary_execution_grants SET issued_at=issued_at-601000,expires_at=expires_at-601000 WHERE grant_id=?",
        (issued["grant"]["grant_id"],))
    fixture.cp.store.conn.commit()
    fixture.cp.canary_runs.expire_and_reconcile()
    row = driver.row()
    window = fixture.cp.store.conn.execute(
        "SELECT g.expires_at-d.issued_at_ms FROM discovery_rounds d JOIN canary_execution_grants g ON g.grant_id=d.grant_id "
        "WHERE d.authorization_id=? AND d.round=2", (driver.authorization_id,)).fetchone()[0]
    assert window == 600_000
    assert row["execution_ms_used"] == 95000 + window and row["state"] == "done"
    assert fixture.cp.store.conn.execute(
        "SELECT state FROM discovery_rounds WHERE authorization_id=? AND round=2", (driver.authorization_id,)).fetchone()[0] == "terminal"
    # 115 s used leaves 5 s (< 10 s): a fresh authorization refuses the next round as exhausted.
    second = DiscoveryDriver(fixture, key=2, chain=driver.chain, binding=driver.binding)
    second.run_round(1, None, _candidates(1, 2))
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET execution_ms_used=115000 WHERE authorization_id=?", (second.authorization_id,))
    fixture.cp.store.conn.commit()
    assert _code(second.submit(second.projection(2, _refs(1, second.reports[1][:1]), wall=5_000))) == (409, "bound_exceeded")
    assert (second.row()["state"], second.row()["close_reason"]) == ("done", "budget")


def test_discovery_round_actions_must_be_recorded_candidates_of_an_earlier_round_of_the_same_authorization(canary_http):
    """Proves the server-recorded relationship only; target body content is executor-attested (§2.6)."""
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    seeds = [(0, {"method": "GET", "route_template": path, "source_ordinal": index})
             for index, path in enumerate(DISCOVERY_SEED_PATHS)]
    swapped = [(0, {"method": "GET", "route_template": "/admin", "source_ordinal": 0})] + seeds[1:]
    assert _code(driver.submit(driver.projection(1, swapped, projection_id="ap_seed_bad"))) == (409, "seed_mismatch")
    misordered = [(0, {**candidate, "source_ordinal": (candidate["source_ordinal"] + 1) % 12}) for _, candidate in seeds]
    assert _code(driver.submit(driver.projection(1, misordered, projection_id="ap_seed_order"))) == (409, "seed_mismatch")
    status, _, first = driver.submit(driver.projection(1, None))
    assert status == 201
    claimed = driver.claim()
    # Round 2 before round 1's report exists.
    early = driver.projection(2, [(1, _candidates(1, 1)[0])], projection_id="ap_early")
    assert _code(driver.submit(early))[1] in {"previous_round_active", "previous_report_missing"}
    recorded = _candidates(1, 3)
    assert driver.finish(claimed, recorded, round_number=1)[0] == 200
    driver.reports[1] = recorded
    never = {"method": "GET", "route_template": "/api/never/recorded", "provenance_kind": "html_link",
             "source_ordinal": 0, "status_code": 200}
    assert _code(driver.submit(driver.projection(2, [(1, never)], projection_id="ap_never"))) == (409, "candidate_not_recorded")
    forged = {**recorded[0], "source_ordinal": recorded[0]["source_ordinal"] + 5}
    assert _code(driver.submit(driver.projection(2, [(1, forged)], projection_id="ap_forged"))) == (409, "source_ordinal_mismatch")
    subset = driver.projection(2, _refs(1, recorded[:2]), projection_id="ap_subset",
                               frontier_digest=discovery_frontier_digest([{"round": 1, "candidate": recorded[0]}]))
    assert _code(driver.submit(subset)) == (409, "frontier_digest_mismatch")
    other = DiscoveryDriver.__new__(DiscoveryDriver)
    other.__dict__.update(driver.__dict__)
    other.view = {**driver.view, "authorization_digest": "e" * 64}
    assert _code(driver.submit(other.projection(2, _refs(1, recorded[:1]), projection_id="ap_digest"))) == (409, "authorization_digest_mismatch")
    off_host = driver.projection(2, _refs(1, recorded[:1]), projection_id="ap_offhost")
    off_host = {k: v for k, v in off_host.items() if k not in {"projection_digest", "signing_key_id", "signature_b64"}}
    off_host["environment"] = {**off_host["environment"], "origin": "https://elsewhere.acme.dev"}
    off_host["egress"] = {**off_host["egress"], "hostname": "elsewhere.acme.dev"}
    assert _code(driver.submit(_sign_record(fixture.runner, off_host, "projection_digest"))) == (409, "action_out_of_scope")
    assert driver.row()["rounds_issued"] == 1 and driver.row()["actions_issued"] == 12
    status, _, second = driver.submit(driver.projection(2, _refs(1, recorded[:2])))
    assert status == 201 and second["round_state"]["round"] == 2
    # A terminal round whose executor never delivered its signed report records nothing to draw on.
    claimed = driver.claim()
    assert driver.finish(claimed, None, round_number=2)[0] == 200
    assert _code(driver.submit(driver.projection(3, _refs(1, recorded[2:3])))) == (409, "previous_report_missing")


def test_discovery_round_submit_replays_identical_round_before_ordering_checks_and_refuses_a_different_projection_for_a_consumed_round(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    projection = driver.projection(1, None)
    status, _, first = driver.submit(projection)
    assert status == 201
    counters = tuple(driver.row())
    # rounds_issued is now 1, so round == rounds_issued + 1 would fail; replay precedes ordering.
    status, _, replay = driver.submit(projection)
    assert status == 201 and replay["grant"] == first["grant"] and replay["round_state"] == first["round_state"]
    assert tuple(driver.row()) == counters
    different = driver.projection(1, None, projection_id="ap_other_round_one", cumulative=0)
    assert _code(driver.submit(different)) == (409, "round_consumed")
    assert tuple(driver.row()) == counters
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_execution_grants").fetchone()[0] == 1


def _second_runner(fixture, runner_id: str, *, project: str | None = None, environment: str = ENV,
                   create_environment: bool = False) -> SigningAuthority:
    """An additional activated executable runner (same fixture seams as the primary runner)."""
    conn = fixture.cp.store.conn
    if create_environment:
        signer = seed_authority(conn, workspace_id=fixture.workspace, project_ref=project or fixture.project,
                                environment_id=environment, runner_id=runner_id, proof_expires_at=NOW + 3600)
    else:
        signer = SigningAuthority.generate()
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", (runner_id, fixture.workspace, "Second", "active", NOW))
        conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
                     (signer.key_id, fixture.workspace, runner_id, signer.canonical_public_key, "active", NOW))
        identity = json.loads(conn.execute(
            "SELECT identity_json FROM canary_runner_identity_records WHERE runner_id=?", (fixture.runner_id,)).fetchone()[0])
        identity.pop("identity_digest")
        identity.update(runner_id=runner_id, public_key={"algorithm": "Ed25519", "key_id": signer.key_id,
                                                          "public_key_b64": signer.canonical_public_key},
                        fingerprint=hashlib.sha256(signer.public_key_bytes).hexdigest())
        identity["identity_digest"] = canonical_digest(identity)
        conn.execute("INSERT INTO canary_runner_identity_records VALUES(?,?,?,?,?)",
                     (fixture.workspace, runner_id, canonical_bytes(identity).decode(), identity["identity_digest"], NOW))
    stamp = time.time()
    conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
                 (fixture.workspace, runner_id, "claim", fixture.cp.runner_auth._hash("nonce", "claim-" + runner_id), 1, stamp + 600))
    conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (fixture.workspace, runner_id, "claim", 1, 0, stamp))
    conn.execute("INSERT INTO canary_runner_execution_protocols(workspace_id,runner_id,protocol_version,control_protocol,"
                 "exchange_digest,activated_at) VALUES(?,?,?,?,?,?)",
                 (fixture.workspace, runner_id, 3, "heel.runner-control.v2", "a" * 64, stamp))
    conn.commit()
    return signer


class _OtherRunnerFixture:
    """The same HTTP fixture seen through another runner's identity and PoP chain."""

    def __init__(self, fixture, runner_id: str, signer, project: str | None = None):
        self.base, self.runner_id, self.runner = fixture, runner_id, signer
        self.workspace, self.project = fixture.workspace, project or fixture.project
        self.claim_nonce, self.cp, self.browser, self.user = "claim-" + runner_id, fixture.cp, fixture.browser, fixture.user

    def request(self, *args, **kwargs):
        return self.base.request(*args, **kwargs)

    def pop(self, path, body, *, capability, nonce, sequence):
        saved = (self.base.runner_id, self.base.runner)
        self.base.runner_id, self.base.runner = self.runner_id, self.runner
        try:
            return self.base.pop(path, body, capability=capability, nonce=nonce, sequence=sequence)
        finally:
            self.base.runner_id, self.base.runner = saved


def _bind(fixture, view: _OtherRunnerFixture, environment: str = ENV, project: str | None = None) -> dict:
    path = f"/v1/workspaces/{fixture.workspace}/projects/{project or fixture.project}/runner-context-bindings"
    status, _, created = fixture.request("POST", path, headers=fixture.browser, raw=canonical_bytes({
        "schema_version": "heel.runner-context-binding-create.v1", "environment_id": environment,
        "verification_record_digest": "a" * 64, "runner_id": view.runner_id, "runner_key_id": view.runner.key_id,
    }))
    assert status == 201, created
    return created["context_binding"]


def test_discovery_round_replay_requires_active_runner_pop_and_project_ownership_and_never_returns_another_projects_grant(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    projection = driver.projection(1, None)
    status, _, first = driver.submit(projection)
    assert status == 201
    grant_bytes = canonical_bytes(first["grant"]).decode()

    # A runner of project B replays project A's exact issued projection and authorization id.
    other_project = fixture.cp.projects.create(fixture.workspace, "B", created_by=fixture.user).project_ref
    signer_b = _second_runner(fixture, "runr_project_b", project=other_project, environment="env_b", create_environment=True)
    view_b = _OtherRunnerFixture(fixture, "runr_project_b", signer_b, other_project)
    binding_b = _bind(fixture, view_b, "env_b", other_project)
    chain_b = _RunnerClaimChain(view_b)
    status, _, data = _submit(view_b, chain_b, binding_b, projection)
    assert (status, data["code"]) == (404, "authorization_unknown")
    assert grant_bytes not in json.dumps(data) and first["grant"]["grant_id"] not in json.dumps(data)

    # A second active runner of project A, bound to the same environment, receives no grant.
    signer_a2 = _second_runner(fixture, "runr_second_a")
    view_a2 = _OtherRunnerFixture(fixture, "runr_second_a", signer_a2)
    binding_a2 = _bind(fixture, view_a2)
    status, _, data = _submit(view_a2, _RunnerClaimChain(view_a2), binding_a2, projection)
    assert (status, data["code"]) == (409, "round_consumed")
    assert first["grant"]["grant_id"] not in json.dumps(data)

    # Identical and different round-report retries after the round is terminal.
    claimed = driver.claim()
    report = driver.report(1, claimed["grant"], _candidates(1, 2))
    status, result, (_, raw, _) = driver.finish(claimed, None, report=report)
    assert status == 200
    counters = tuple(driver.row())
    sent = json.loads(raw)
    # The runner's identical retry: same signed terminal projection and report, next PoP nonce.
    status, again, _ = driver.post_chain(claimed, "result", sent, capability="runner_result")
    assert status == 200 and again["round_state"] == result["round_state"] and tuple(driver.row()) == counters
    changed = {**sent, "discovery_round_report": driver.report(1, claimed["grant"], _candidates(1, 3))}
    status, data, _ = driver.post_chain(claimed, "result", changed, capability="runner_result")
    assert (status, data["code"]) == (409, "report_consumed")
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM discovery_round_reports").fetchone()[0] == 1
    assert tuple(driver.row()) == counters

    # A revoked key presenting the same digest is refused at PoP, before any replay lookup.
    fixture.cp.store.conn.execute("UPDATE canary_runner_keys SET status='revoked',revoked_at=? WHERE key_id=?",
                                  (NOW, fixture.runner.key_id))
    fixture.cp.store.conn.commit()
    assert driver.submit(projection)[0] == 401


def test_discovery_round_terminal_aggregation_applies_exactly_once_under_concurrent_duplicate_reports(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    status, _, _ = driver.submit(driver.projection(1, None))
    claimed = driver.claim()
    grant = claimed["grant"]
    projection = driver.operational(grant, sequence=9, phase="terminal", completed=12, disposition="completed")
    body = canonical_bytes({"schema_version": "heel.runner-result-request.v1", "run_id": claimed["run_id"],
                            "operational_projection": projection,
                            "discovery_round_report": driver.report(1, grant, _candidates(1, 4), bytes_received=4096)})
    path = driver.run_path(claimed["run_id"], "result")
    state = claimed["chain_states"]["result"]
    headers = fixture.pop(path, body, capability="runner_result", nonce=state["next_nonce_b64"],
                          sequence=state["next_sequence"])
    outcomes = []
    lock = threading.Lock()

    def send():
        response = fixture.request("POST", path, headers=headers, raw=body)
        with lock:
            outcomes.append(response)

    def reap():
        fixture.cp.canary_runs.expire_and_reconcile()

    threads = [threading.Thread(target=send), threading.Thread(target=send), threading.Thread(target=reap)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert [status for status, _, _ in outcomes] == [200, 200]
    assert outcomes[0][2] == outcomes[1][2]
    row = driver.row()
    round_row = fixture.cp.store.conn.execute(
        "SELECT * FROM discovery_rounds WHERE authorization_id=?", (driver.authorization_id,)).fetchone()
    assert round_row["state"] == "terminal"
    assert row["execution_ms_used"] == round_row["terminal_at_ms"] - round_row["issued_at_ms"]
    assert (row["requests_completed"], row["bytes_received"]) == (12, 4096)
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM discovery_round_reports").fetchone()[0] == 1
    fixture.cp.canary_runs.expire_and_reconcile()
    assert tuple(driver.row()) == tuple(row)


def test_discovery_authorization_expiry_or_revoke_stops_an_in_flight_round_at_the_next_heartbeat_or_attempt_gate(canary_http):
    fixture = canary_http
    attempts: list[str] = []

    def executor_stub_next_socket(gate: dict) -> None:
        """Minimal stand-in for the executor's per-attempt live gate (bridge §4 row 8)."""
        attempts.append("socket" if gate["active"] else gate["stop_reason"])

    for closing in ("expire", "revoke"):
        attempts.clear()
        driver = DiscoveryDriver(fixture, key=1 if closing == "expire" else 2,
                                 chain=None if closing == "expire" else shared_chain,
                                 binding=None if closing == "expire" else shared_binding)
        shared_chain, shared_binding = driver.chain, driver.binding
        assert driver.submit(driver.projection(1, None))[0] == 201
        claimed = driver.claim()
        status, gate, _ = driver.heartbeat(claimed, 1)
        assert status == 200 and gate["active"] is True
        executor_stub_next_socket(gate)
        if closing == "expire":
            # The grant itself is still valid; only the authorization's server-clock TTL passed.
            fixture.cp.store.conn.execute(
                "UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
                "WHERE authorization_id=?", (driver.authorization_id,))
            fixture.cp.store.conn.commit()
        else:
            revoke = _env_base(fixture) + "/discovery-authorizations/" + driver.authorization_id + "/revoke"
            assert fixture.request("POST", revoke, headers=fixture.browser)[0] == 200
        status, gate, _ = driver.heartbeat(claimed, 2)
        assert status == 200 and gate["active"] is False and gate["stop_reason"] == "cloud_stop"
        executor_stub_next_socket(gate)
        assert attempts == ["socket", "cloud_stop"]
        run = fixture.cp.store.conn.execute("SELECT status,stop_reason FROM canary_runs WHERE run_id=?",
                                            (claimed["run_id"],)).fetchone()
        assert tuple(run) == ("stop_requested", "cloud_stop")
        reasons = [row[0] for row in fixture.cp.store.conn.execute(
            "SELECT reason_code FROM canary_run_events WHERE run_id=? AND event_type='stop_requested'", (claimed["run_id"],))]
        assert reasons == ["authorization_expired" if closing == "expire" else "authorization_revoked"]
        assert driver.row()["state"] == ("expired" if closing == "expire" else "revoked")
        # Closing after a round issued never refunds the authorization's unit.
        assert driver.row()["quota_state"] == "consumed"
        status, result, _ = driver.finish(claimed, _candidates(1, 1), completed=1, round_number=1, stop_reason="cloud_stop")
        assert status == 200 and result["round_state"]["state"] == "terminal"


def test_discovery_rounds_are_strictly_sequential_and_previous_round_must_be_terminal(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    assert _code(driver.submit(driver.projection(2, [(1, _candidates(1, 1)[0])], cumulative=0))) == (409, "round_out_of_order")
    assert driver.submit(driver.projection(1, None))[0] == 201
    claimed = driver.claim()
    early = driver.projection(2, [(1, _candidates(1, 1)[0])])
    assert _code(driver.submit(early)) == (409, "previous_round_active")
    assert driver.finish(claimed, _candidates(1, 3), round_number=1)[0] == 200
    driver.reports[1] = _candidates(1, 3)
    assert _code(driver.submit(driver.projection(3, _refs(1, _candidates(1, 1))))) == (409, "round_out_of_order")
    assert _code(driver.submit(driver.projection(2, _refs(1, _candidates(1, 1)), cumulative=11,
                                                 projection_id="ap_cumulative"))) == (409, "cumulative_mismatch")
    assert driver.row()["rounds_issued"] == 1
    assert driver.submit(driver.projection(2, _refs(1, _candidates(1, 1))))[0] == 201


def test_discovery_authorization_expiry_and_revoke_close_it_and_stop_the_active_round_within_five_seconds(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    assert driver.submit(driver.projection(1, None))[0] == 201
    claimed = driver.claim()
    revoke = _env_base(fixture) + "/discovery-authorizations/" + driver.authorization_id + "/revoke"
    started = time.monotonic()
    status, _, view = fixture.request("POST", revoke, headers=fixture.browser)
    assert status == 200 and view["state"] == "revoked"
    observed = None
    for sequence in range(1, 40):
        status, gate, _ = driver.heartbeat(claimed, sequence)
        if not gate["active"]:
            observed = time.monotonic() - started
            break
        time.sleep(0.25)
    assert observed is not None and observed <= 5.0
    run = fixture.cp.store.conn.execute(
        "SELECT stop_requested_at_ms,stop_deadline_ms FROM canary_runs WHERE run_id=?", (claimed["run_id"],)).fetchone()
    assert run["stop_deadline_ms"] - run["stop_requested_at_ms"] == 5000
    # An issued but unclaimed round loses its grant at once; expiry closes the authorization.
    second = DiscoveryDriver(fixture, key=2, chain=driver.chain, binding=driver.binding)
    status, _, issued = second.submit(second.projection(1, None))
    assert status == 201
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
        "WHERE authorization_id=?", (second.authorization_id,))
    fixture.cp.store.conn.commit()
    fixture.cp.canary_runs.expire_and_reconcile()
    assert second.row()["state"] == "expired"
    grant = fixture.cp.store.conn.execute("SELECT status FROM canary_execution_grants WHERE grant_id=?",
                                          (issued["grant"]["grant_id"],)).fetchone()[0]
    assert grant in {"revoked", "expired"}
    claim_path = f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/claim"
    assert driver.chain.post(claim_path, {"schema_version": "heel.runner-claim-request.v1"})[0] == 204


def test_discovery_plan_kind_and_scan_plan_request_cannot_be_mixed_on_one_binding(canary_http):
    fixture = canary_http
    _seed_inventory(fixture)
    binding = _binding(fixture)
    chain = _RunnerClaimChain(fixture)
    assert _plan_request(fixture, binding)[0] == 201
    driver = DiscoveryDriver(fixture, chain=chain, binding=binding)
    assert _code(driver.submit(driver.projection(1, None))) == (409, "plan_kind_mismatch")
    assert driver.row()["rounds_issued"] == 0
    # Vice versa: while discovery is open, no scan plan request can be prepared on the binding.
    revoke = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/runner-context-bindings/{binding['binding_id']}/revoke"
    assert fixture.request("POST", revoke, headers=fixture.browser, raw=canonical_bytes(
        {"schema_version": "heel.runner-context-binding-revoke.v1", "reason_code": "operator_requested"}))[0] == 200
    fresh = _binding(fixture)
    assert _code(_plan_request(fixture, fresh)) == (409, "plan_kind_mismatch")


def test_discovery_route_inventory_view_shows_provenance_states_and_truncated_count_without_values(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    first = _candidates(1, 200)
    driver.run_round(1, None, first)
    overlap = [{**first[0], "provenance_kind": "js_literal", "source_ordinal": 3}]
    # Round 2 issues four actions, so source ordinal 3 names one of its actual actions (C2R1 F1).
    driver.run_round(2, _refs(1, first[:4]), _candidates(2, 1) + overlap)
    status, _, view = fixture.request("GET", _env_base(fixture) + "/route-inventory", headers=fixture.browser)
    assert status == 200
    assert (view["route_count"], view["truncated_count"]) == (200, 1)
    assert view["inventory_digest"] == canonical_digest(view["routes"])
    first_row = next(row for row in view["routes"] if row["route_template"] == first[0]["route_template"])
    assert first_row["state"] == "candidate" and first_row["provenance"] == [
        {"kind": "html_link", "round": 1, "source_ordinal": first[0]["source_ordinal"], "status_code": 200},
        {"kind": "js_literal", "round": 2, "source_ordinal": 3, "status_code": 200},
    ]
    assert all(set(row) == {"method", "route_template", "provenance", "first_seen_ms", "state"} for row in view["routes"])
    serialized = json.dumps(view)
    for forbidden in ("https://", "?", "@", "canary.acme.dev", "Bearer", "token="):
        assert forbidden not in serialized


def test_discovery_reports_and_inventory_refuse_value_canaries_and_runner_forged_kinds(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    assert driver.submit(driver.projection(1, None))[0] == 201
    claimed = driver.claim()
    for canary in ("/users/alice@example.com", "/k/sk_live_abc123", "/objects/0123456789abcdef0123456789abcdef",
                   "/t/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "/reset?token=abc"):
        bad = driver.report(1, claimed["grant"], [{"method": "GET", "route_template": canary, "provenance_kind": "html_link",
                                                   "source_ordinal": 0, "status_code": 200}])
        status, _, _ = driver.finish(claimed, None, report=bad)
        assert status == 401, canary
    forged = driver.report(1, claimed["grant"], [{**_candidates(1, 1)[0], "provenance_kind": "imported_openapi"}])
    assert driver.finish(claimed, None, report=forged)[0] == 401
    assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM discovery_round_reports").fetchone()[0] == 0
    stored = json.dumps([tuple(r) for r in fixture.cp.store.conn.execute("SELECT * FROM route_inventories")])
    assert "alice" not in stored and "sk_live" not in stored


def test_discovery_rounds_never_create_a_human_approval_or_scan_bypass(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    status, _, issued = driver.submit(driver.projection(1, None))
    assert status == 201
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    listed = fixture.request("GET", base + "/canary-approval-requests", headers=fixture.browser)[2]
    assert listed["requests"] == []
    status, _, data = fixture.request("POST", base + "/canary-runs/" + issued["run_id"] + "/approve", {
        "schema_version": "heel.canary-execution-approval.v1", "projection_digest": issued["projection_digest"],
        "hostname_retype": "canary.acme.dev", "reason": "try to approve discovery",
    }, {**fixture.browser, "Idempotency-Key": _key(77), "If-Heel-Control-Generation": "0"})
    assert status == 409
    # A discovery-shaped projection with a non-GET/HEAD action never parses, so never issues.
    post = driver.projection(1, None, projection_id="ap_post", routes=[("POST", path) for path in DISCOVERY_SEED_PATHS])
    assert driver.submit(post)[0] == 401
    # A discovery projection uploaded by a browser is refused like every v2 plan.
    status, _, data = fixture.request("POST", base + "/canary-approval-projections",
                                      driver.projection(1, None, projection_id="ap_browser"), fixture.browser)
    assert (status, data["code"]) == (400, "invalid_canary_projection")
    assert [kind for kind, _ in _ledger(fixture)] == ["reserve", "consume"]


def test_discovery_round_is_refused_while_the_kill_switch_is_tripped(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    fixture.cp.store.conn.execute("INSERT INTO kill_switches VALUES('global','incident','ops',?)", (NOW,))
    fixture.cp.store.conn.commit()
    assert _code(driver.submit(driver.projection(1, None))) == (409, "kill_switch")
    assert driver.row()["rounds_issued"] == 0 and driver.row()["state"] == "open"


# --- C2D D3/D4 and durable closing-refusal gates ---

import re as _re

_ROUND_REF = _re.compile(r"^dauth:dau_[0-9a-f]{32}:r[1-5]$")


def _round_key(authorization_id: str, round_number: int) -> str:
    return "ca1-" + hashlib.sha256(
        f"heel.discovery-round-grant.v1|{authorization_id}|{round_number}".encode()).hexdigest()


def _database_path(fixture) -> str:
    return next(row[2] for row in fixture.cp.store.conn.execute("PRAGMA database_list") if row[1] == "main")


def test_discovery_transient_refusal_leaves_no_rows_and_the_round_resubmits(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    assert driver.submit(driver.projection(1, None))[0] == 201
    claimed = driver.claim()
    recorded = _candidates(1, 2)
    round_two = driver.projection(2, _refs(1, recorded))
    counts = lambda: tuple(fixture.cp.store.conn.execute(
        "SELECT (SELECT COUNT(*) FROM discovery_rounds),(SELECT COUNT(*) FROM canary_approval_projections),"
        "(SELECT COUNT(*) FROM canary_runs),(SELECT COUNT(*) FROM canary_execution_grants)").fetchone())
    before = counts()
    assert _code(driver.submit(round_two)) == (409, "previous_round_active")
    assert counts() == before == (1, 1, 1, 1)
    assert driver.finish(claimed, recorded, round_number=1)[0] == 200
    status, _, issued = driver.submit(round_two)  # the very same signed projection now issues
    assert status == 201 and issued["round_state"]["round"] == 2 and counts() == (2, 2, 2, 2)


def test_discovery_projection_and_round_grant_key_are_never_human_approvable(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    status, _, issued = driver.submit(driver.projection(1, None))
    assert status == 201
    grant_row = fixture.cp.store.conn.execute(
        "SELECT reservation_id,idempotency_key,meter FROM canary_execution_grants WHERE grant_id=?",
        (issued["grant"]["grant_id"],)).fetchone()
    assert _ROUND_REF.fullmatch(grant_row["reservation_id"])
    assert grant_row["reservation_id"] == f"dauth:{driver.authorization_id}:r1"
    assert grant_row["idempotency_key"] == _round_key(driver.authorization_id, 1)
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    assert fixture.request("GET", base + "/canary-approval-requests", headers=fixture.browser)[2]["requests"] == []
    body = {"schema_version": "heel.canary-execution-approval.v1", "projection_digest": issued["projection_digest"],
            "hostname_retype": "canary.acme.dev", "reason": "approve a discovery round"}
    headers = {**fixture.browser, "Idempotency-Key": _key(91), "If-Heel-Control-Generation": "0"}
    status, _, data = fixture.request("POST", base + "/canary-runs/" + issued["run_id"] + "/approve", body, headers)
    assert (status, data["code"]) == (409, "canary_state_conflict")
    # A scan approval presenting the derived round key can never adopt the round's grant.
    projection = approval_projection(fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project)
    status, _, scan = fixture.request("POST", base + "/canary-approval-projections", projection, fixture.browser)
    assert status == 201
    status, _, data = fixture.request("POST", base + "/canary-runs/" + scan["run_id"] + "/approve", {
        **body, "projection_digest": projection["projection_digest"], "reason": "scan"},
        {**headers, "Idempotency-Key": grant_row["idempotency_key"]})
    assert (status, data["code"]) == (400, "invalid_canary_approval")
    assert [kind for kind, _ in _ledger(fixture)] == ["reserve", "consume"]


def test_discovery_round_grant_is_v2_discovery_profile_and_scan_grants_remain_v1(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    status, _, issued = driver.submit(driver.projection(1, None))
    assert status == 201
    grant = issued["grant"]
    assert (grant["schema_version"], grant["budget_profile"]) == ("heel.execution-grant.v2", "discovery")
    assert grant["budgets"]["maximum_response_bytes"] == 2_097_152
    assert driver.claim()["grant"] == grant
    # A scan approval still issues the byte-compatible v1 grant ...
    base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
    projection = approval_projection(fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project)
    status, _, scan = fixture.request("POST", base + "/canary-approval-projections", projection, fixture.browser)
    status, _, approved = fixture.request("POST", base + "/canary-runs/" + scan["run_id"] + "/approve", {
        "schema_version": "heel.canary-execution-approval.v1", "projection_digest": projection["projection_digest"],
        "hostname_retype": "canary.acme.dev", "reason": "scan"},
        {**fixture.browser, "Idempotency-Key": _key(92), "If-Heel-Control-Generation": "0"})
    assert status == 201 and approved["grant"]["schema_version"] == "heel.execution-grant.v1"
    assert "budget_profile" not in approved["grant"]
    # ... and a validly signed v2 grant hand-swapped onto that scan approval is refused at claim.
    swapped = {k: v for k, v in approved["grant"].items() if k not in {"grant_digest", "signing_key_id", "signature_b64"}}
    swapped.update(schema_version="heel.execution-grant.v2", budget_profile="discovery")
    swapped = _sign_record(fixture.cloud, swapped, "grant_digest")
    fixture.cp.store.conn.execute("UPDATE canary_execution_grants SET grant_json=?,grant_digest=? WHERE grant_id=?",
                                  (canonical_bytes(swapped).decode(), swapped["grant_digest"], swapped["grant_id"]))
    fixture.cp.store.conn.commit()
    claim_path = f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/claim"
    status, _, data = driver.chain.post(claim_path, {"schema_version": "heel.runner-claim-request.v1"})
    assert status == 503 and data["code"] == "canary_authority_unavailable"
    assert fixture.cp.store.conn.execute("SELECT status FROM canary_execution_grants WHERE grant_id=?",
                                         (swapped["grant_id"],)).fetchone()[0] == "issued"


def test_discovery_round_submit_refuses_a_projection_whose_body_budget_exceeds_the_authorization_bound(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    assert driver.submit(driver.projection(1, None, body_bytes=2_097_153))[0] == 401
    bound = json.loads(driver.row()["bound_json"])
    fixture.cp.store.conn.execute("UPDATE discovery_authorizations SET bound_json=? WHERE authorization_id=?",
                                  (canonical_bytes({**bound, "max_body_bytes": 1_048_576}).decode(), driver.authorization_id))
    fixture.cp.store.conn.commit()
    assert _code(driver.submit(driver.projection(1, None))) == (409, "bound_exceeded")
    assert driver.row()["rounds_issued"] == 0
    assert driver.submit(driver.projection(1, None, body_bytes=1_048_576, projection_id="ap_fits"))[0] == 201


def test_discovery_closing_refusals_persist_the_close_across_a_reopened_database(canary_http):
    """Refusal returns 409, yet the close it implies is committed (Astra C-4 clarification)."""
    fixture = canary_http
    path = _database_path(fixture)
    exhausted = DiscoveryDriver(fixture)
    exhausted.run_round(1, None, _candidates(1, 10))
    fixture.cp.store.conn.execute("UPDATE discovery_authorizations SET actions_issued=95 WHERE authorization_id=?",
                                  (exhausted.authorization_id,))
    fixture.cp.store.conn.commit()
    refused = exhausted.projection(2, _refs(1, exhausted.reports[1]), cumulative=95)
    assert _code(exhausted.submit(refused)) == (409, "bound_exceeded")
    expired = DiscoveryDriver(fixture, key=2, chain=exhausted.chain, binding=exhausted.binding)
    fixture.cp.store.conn.execute(
        "UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
        "WHERE authorization_id=?", (expired.authorization_id,))
    fixture.cp.store.conn.commit()
    assert _code(expired.submit(expired.projection(1, None))) == (409, "authorization_expired")
    reopened = sqlite3.connect(path)
    try:
        rows = dict(reopened.execute(
            "SELECT authorization_id,state||'/'||close_reason||'/'||quota_state FROM discovery_authorizations").fetchall())
        assert rows[exhausted.authorization_id] == "done/budget/consumed"
        assert rows[expired.authorization_id] == "expired/expired/refunded"
        assert reopened.execute("SELECT COUNT(*) FROM discovery_rounds").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM canary_approval_projections WHERE approval_id=?",
                                (refused["projection_id"],)).fetchone()[0] == 0
        assert [row[0] for row in reopened.execute(
            "SELECT kind FROM usage_ledger WHERE ref=? ORDER BY ts,entry_id", (expired.authorization_id,))] == ["reserve", "refund"]
    finally:
        reopened.close()
    assert _code(exhausted.submit(refused)) == (409, "authorization_closed")


# --- C2R1: recorded provenance, live-role issue, semantic replay and seed bounds (ASTRA-C2R decisions) ---

def _discovery_snapshot(fixture, driver) -> tuple:
    """Every row a report, settlement, inventory merge or round issue could touch."""
    conn = fixture.cp.store.conn
    return (
        tuple(driver.row()),
        tuple(tuple(row) for row in conn.execute("SELECT * FROM discovery_rounds ORDER BY round_id")),
        tuple(tuple(row) for row in conn.execute("SELECT * FROM discovery_round_reports ORDER BY report_id")),
        tuple(tuple(row) for row in conn.execute("SELECT * FROM route_inventories")),
        tuple(tuple(row) for row in conn.execute("SELECT run_id,status,stop_reason,quota_state FROM canary_runs ORDER BY run_id")),
        tuple(tuple(row) for row in conn.execute("SELECT grant_id,status FROM canary_execution_grants ORDER BY grant_id")),
        tuple(_ledger(fixture)),
    )


def test_report_source_ordinal_must_name_an_action_of_the_actual_originating_round(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    status, _, submitted = driver.submit(driver.projection(1, None))
    assert status == 201 and submitted["round_state"]["actions"] == 12
    claimed = driver.claim()
    before = _discovery_snapshot(fixture, driver)
    for ordinal in (12, 19):  # == actions, and the schema maximum on a 12-action round
        forged = [{"method": "GET", "route_template": "/api/forged/item", "provenance_kind": "html_link",
                   "source_ordinal": ordinal, "status_code": 200}]
        status, data, _ = driver.finish(claimed, forged, round_number=1)
        assert (status, data["code"]) == (400, "invalid_discovery_report"), ordinal
        # No report, inventory, settlement, counter, run, grant or ledger effect.
        assert _discovery_snapshot(fixture, driver) == before
    # Corrected retry on the same chain: the last valid ordinal of a 12-action round is accepted.
    recorded = _candidates(1, 19) + [{"method": "GET", "route_template": "/api/r1/last", "provenance_kind": "html_link",
                                      "source_ordinal": 11, "status_code": 200}]
    status, result, _ = driver.finish(claimed, recorded, round_number=1)
    assert status == 200 and result["round_state"]["state"] == "terminal"
    driver.reports[1] = sorted(recorded, key=lambda c: (c["method"], c["route_template"]))
    inventory = json.loads(fixture.cp.store.conn.execute("SELECT routes_json FROM route_inventories").fetchone()[0])
    last = next(row for row in inventory if row["route_template"] == "/api/r1/last")
    assert last["provenance"] == [{"kind": "html_link", "round": 1, "source_ordinal": 11, "status_code": 200}]
    # A 20-action later round keeps its full capacity: ordinal 19 is the last valid one there.
    status, _, second = driver.submit(driver.projection(2, _refs(1, recorded)))
    assert status == 201 and second["round_state"]["actions"] == 20
    claimed = driver.claim()
    highest = [{"method": "GET", "route_template": "/api/r2/highest", "provenance_kind": "html_link",
                "source_ordinal": 19, "status_code": 200}]
    status, result, _ = driver.finish(claimed, highest, round_number=2)
    assert status == 200 and result["round_state"]["state"] == "terminal"
    status, _, third = driver.submit(driver.projection(3, _refs(2, highest)))
    assert status == 201 and third["round_state"]["round"] == 3


def test_round_issue_refuses_stored_provenance_whose_ordinal_exceeds_its_recorded_source_round(canary_http):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    candidates = _candidates(1, 3)
    driver.run_round(1, None, candidates)
    conn = fixture.cp.store.conn
    # A legacy/corrupted stored row: the signed report row is left as found, never edited back or re-signed.
    stored = json.loads(conn.execute("SELECT candidates_json FROM discovery_round_reports").fetchone()[0])
    stored[0]["source_ordinal"] = 15
    conn.execute("UPDATE discovery_round_reports SET candidates_json=?", (canonical_bytes(stored).decode(),))
    conn.commit()
    corrupted = conn.execute("SELECT * FROM discovery_round_reports").fetchone()
    before = _discovery_snapshot(fixture, driver)
    refused = driver.projection(2, _refs(1, stored[:1]))
    for _ in range(2):  # the refusal and its fresh-nonce retry are both denied, with no grant
        status, _, data = driver.submit(refused)
        assert (status, data["code"]) == (409, "source_ordinal_mismatch") and "grant" not in data
        assert _discovery_snapshot(fixture, driver) == before
    assert tuple(conn.execute("SELECT * FROM discovery_round_reports").fetchone()) == tuple(corrupted)
    # Candidates whose recorded provenance is intact still issue the next round.
    status, _, issued = driver.submit(driver.projection(2, _refs(1, stored[1:])))
    assert status == 201 and issued["round_state"]["round"] == 2


@pytest.mark.parametrize("ordinal", [12, 19])
def test_round_one_seed_ordinal_beyond_the_seed_list_is_seed_mismatch_without_side_effects(canary_http, ordinal):
    fixture = canary_http
    driver = DiscoveryDriver(fixture)
    references = [(0, {"method": "GET", "route_template": path, "source_ordinal": ordinal if index == 0 else index})
                  for index, path in enumerate(DISCOVERY_SEED_PATHS)]
    before = _discovery_snapshot(fixture, driver)
    status, _, data = driver.submit(driver.projection(1, references))
    assert (status, data) == (409, {"schema_version": "heel.discovery-error.v1", "code": "seed_mismatch"})
    assert _discovery_snapshot(fixture, driver) == before
    assert driver.row()["quota_state"] == "reserved" and driver.row()["state"] == "open"
    status, _, issued = driver.submit(driver.projection(1, None, projection_id="ap_seed_corrected"))
    assert status == 201 and issued["round_state"]["actions"] == 12


def _exact_submit(driver, projection):
    """Send one round submit on the claim chain and return its exact signed request for raw replay."""
    fixture, chain = driver.fixture, driver.chain
    path = (f"/v1/workspaces/{fixture.workspace}/runners/{fixture.runner_id}/contexts/"
            f"{driver.binding['binding_id']}/approval-projections")
    raw = canonical_bytes({
        "schema_version": "heel.runner-approval-projection-submit.v1", "context_binding_id": driver.binding["binding_id"],
        "context_binding_digest": driver.binding["binding_digest"], "approval_projection": projection,
    })
    headers = fixture.pop(path, raw, capability="runner_claim", nonce=chain.nonce, sequence=chain.sequence)
    status, response_headers, data = fixture.request("POST", path, headers=headers, raw=raw)
    chain.nonce = response_headers["X-Heel-Runner-Next-Nonce"]
    chain.sequence += 1
    return status, data, (path, headers, raw)


def _claim_status(driver) -> int:
    path = f"/v1/workspaces/{driver.fixture.workspace}/runners/{driver.runner_id}/claim"
    return driver.chain.post(path, {"schema_version": "heel.runner-claim-request.v1"})[0]


def _age_discovery(fixture, driver, grant_id: str) -> None:
    conn = fixture.cp.store.conn
    conn.execute("UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
                 "WHERE authorization_id=?", (driver.authorization_id,))
    conn.execute("UPDATE canary_execution_grants SET issued_at=issued_at-900001,expires_at=expires_at-900001 WHERE grant_id=?",
                 (grant_id,))
    conn.commit()


def test_semantic_round_replay_returns_a_grant_only_while_grant_and_authorization_are_live(canary_http):
    fixture = canary_http
    revoke_path = _env_base(fixture) + "/discovery-authorizations/{}/revoke"
    driver = None
    for closing in ("revoke", "expire"):
        driver = DiscoveryDriver(fixture, key=1 if closing == "revoke" else 2,
                                 chain=driver and driver.chain, binding=driver and driver.binding)
        projection = driver.projection(1, None)
        status, _, first = driver.submit(projection)
        assert status == 201 and first["round_state"]["grant_status"] == "issued"
        # Live fresh-nonce replay: the same grant, no counter, grant or ledger duplication.
        before = _discovery_snapshot(fixture, driver)
        status, _, live = driver.submit(projection)
        assert status == 201 and live["grant"] == first["grant"] and live["round_state"] == first["round_state"]
        assert _discovery_snapshot(fixture, driver) == before
        if closing == "revoke":
            assert fixture.request("POST", revoke_path.format(driver.authorization_id), headers=fixture.browser)[0] == 200
        else:
            _age_discovery(fixture, driver, first["grant"]["grant_id"])
        status, _, replay = driver.submit(projection)
        assert status == 201 and "grant" not in replay
        assert replay["round_state"]["grant_status"] == "revoked"
        assert replay["round_state"]["grant_id"] == first["grant"]["grant_id"]
        assert driver.row()["state"] == ("revoked" if closing == "revoke" else "expired")
        assert driver.row()["quota_state"] == "consumed" and driver.row()["rounds_issued"] == 1
        assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_execution_grants WHERE run_id=?",
                                             (first["run_id"],)).fetchone()[0] == 1
        assert [kind for kind, ref in _ledger(fixture) if ref == driver.authorization_id] == ["reserve", "consume"]
        assert _claim_status(driver) == 204


def test_exact_raw_round_replay_keeps_its_historical_receipt_but_confers_no_authority(canary_http):
    fixture = canary_http
    revoke_path = _env_base(fixture) + "/discovery-authorizations/{}/revoke"
    driver = None
    for closing in ("revoke", "expire"):
        driver = DiscoveryDriver(fixture, key=1 if closing == "revoke" else 2,
                                 chain=driver and driver.chain, binding=driver and driver.binding)
        status, first, (path, headers, raw) = _exact_submit(driver, driver.projection(1, None))
        assert status == 201 and "grant" in first
        if closing == "revoke":
            assert fixture.request("POST", revoke_path.format(driver.authorization_id), headers=fixture.browser)[0] == 200
        else:
            _age_discovery(fixture, driver, first["grant"]["grant_id"])
        before = _discovery_snapshot(fixture, driver)
        status, _, cached = fixture.request("POST", path, headers=headers, raw=raw)
        # The durable PoP receipt replays byte-for-byte history; it is not a fresh issue.
        assert status == 201 and cached == first
        assert _discovery_snapshot(fixture, driver) == before
        # The historical bytes are never claimable.
        assert _claim_status(driver) == 204
    # In-flight: once the claim advanced the chain, the superseded submit is no longer the cursor's
    # replayable receipt (existing protocol), and the gate stops the claimed round after revoke.
    driver = DiscoveryDriver(fixture, key=3, chain=driver.chain, binding=driver.binding)
    status, first, (path, headers, raw) = _exact_submit(driver, driver.projection(1, None))
    assert status == 201
    claimed = driver.claim()
    assert fixture.request("POST", revoke_path.format(driver.authorization_id), headers=fixture.browser)[0] == 200
    status, _, superseded = fixture.request("POST", path, headers=headers, raw=raw)
    assert status == 401 and "grant" not in superseded
    status, gate, _ = driver.heartbeat(claimed, 1)
    assert status == 200 and gate["active"] is False and gate["stop_reason"] == "cloud_stop"

