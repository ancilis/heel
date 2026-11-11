"""GAP-4: ``runner prepare --live`` queues one compiled projection; only the serve owner submits it.

A running ``serve`` owns the signed claim chain (``RunnerDaemon._status_locked``: "a second client
would fork it"), so ``prepare`` never builds a control client or opens the runtime ledger. It
compiles and saves the immutable pair, then writes one context-bound pending-submit record under
the store's exclusive lock. The serve owner submits that record through the existing
``RunnerCoordinator.submit_cloud_context_approval`` on an idle poll and records the answer.

These tests drive the real Python control plane behind the TLS edge (``EdgeTLSHarness``), the
real ``heel.cli.main`` in child processes for every customer command, and the real serve loop.
"""
from __future__ import annotations

import json
import subprocess
import time

import pytest

from heel.canary_contracts import canonical_bytes
from heel.runner import daemon as daemon_module
from heel.runner.store import RunnerStore
from tests.test_runner_daemon import (  # noqa: F401 - fixtures are used by name
    _STAGING, _authorize_binding, _child_argv, _child_env, _child_seeds, _daemon, _daemon_record,
    _fault_daemon, _owner, _pair_runner, _serve_in_thread, _serve_once, _wait_serve_state,
    serve_harness,
)

FIXTURE = __import__("pathlib").Path(__file__).resolve().parent / "fixtures/canary/staging-openapi.json"
TOKEN = "local-canary-token-0123456789"


def _cli(tmp_path, harness, home, seeds, *argv, env=None):
    workdir, child_env = _child_env(home, tmp_path)
    child_env.update(env or {})
    completed = subprocess.run(
        _child_argv(harness, home, seeds, {}, *argv), cwd=workdir, env=child_env,
        capture_output=True, text=True, timeout=60,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _configure(tmp_path, harness, home, seeds):
    """Customer CLI: import routes, add one ephemeral credential and map one scenario."""
    assert _cli(tmp_path, harness, home, seeds, "runner", "import-openapi", str(FIXTURE))[0] == 0
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "credential", "add", "--role",
                          "authenticated", "--profile", "bearer", "--label", "local", "--backend", "ephemeral-env")
    assert code == 0, err
    variable = json.loads(out)["credential_source"]["variable"]
    code, _out, err = _cli(tmp_path, harness, home, seeds, "runner", "map", "--scenario",
                           "anonymous_authenticated_read", "--method", "HEAD", "--route", "/health")
    assert code == 0, err
    return {variable: TOKEN}


def _submit_path(workspace_id, runner_id, binding_id):
    return f"/v1/workspaces/{workspace_id}/runners/{runner_id}/contexts/{binding_id}/approval-projections"


def _server_approvals(harness, workspace_id):
    return [tuple(row) for row in harness.control_plane.store.conn.execute(
        "SELECT approval_id,run_id,projection_digest,status FROM canary_approval_projections WHERE workspace_id=?",
        (workspace_id,),
    )]


def _wait_submission(home, predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = RunnerStore(home).load_projection_submission()
        if record is not None and predicate(record):
            return record
        time.sleep(0.05)
    raise AssertionError(f"submission not reached: {RunnerStore(home).load_projection_submission()}")


def _bound_runner(tmp_path, harness, zone, name):
    workspace_id, cookie = harness.signup_owner(f"owner-{name}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, name)
    record = _daemon_record(home)
    base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    result = _serve_once(_daemon(home, harness, backend))
    assert not isinstance(result, BaseException) and result["binding_id"] == binding["binding_id"], result
    return workspace_id, cookie, home, backend, runner_id, base, binding


def test_prepare_live_queues_one_projection_that_the_active_serve_owner_submits(tmp_path, serve_harness):
    """GAP-4 gate: pair → serve → bind → prepare --live (separate process) → one approval request."""
    harness, zone = serve_harness
    workspace_id, cookie = harness.signup_owner("owner-plan-submit@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "plan-submit")
    record = _daemon_record(home)
    seeds = _child_seeds(tmp_path, backend)
    daemon = _daemon(home, harness, backend)
    thread, _events, outcome = _serve_in_thread(daemon)
    _wait_serve_state(home, lambda state: state["state"] == "online")

    # Unbound: prepare refuses locally and nothing reaches the control plane.
    forwarded = len(harness.forwarded)
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live")
    assert (code, out) == (2, "") and "unavailable" in err
    assert not [path for _m, path in harness.forwarded[forwarded:] if "approval-projections" in path]

    base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    _wait_serve_state(home, lambda state: state["binding_id"] == binding["binding_id"])
    env = _configure(tmp_path, harness, home, seeds)
    submit = ("POST", _submit_path(workspace_id, runner_id, binding["binding_id"]))
    assert submit not in harness.forwarded

    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live", env=env)
    assert (code, err) == (0, ""), err
    prepared = json.loads(out)
    projection_id = prepared["submission"]["projection_id"]
    assert prepared["submission"] == {"state": "pending", "projection_id": projection_id}
    assert set(prepared) == {"manifest_digest", "projection_digest", "scenario_ids", "submission"}

    submitted = _wait_submission(home, lambda value: value["state"] == "submitted")
    assert harness.forwarded.count(submit) == 1
    assert submitted["projection_id"] == projection_id == submitted["approval_id"]
    assert submitted["projection_digest"] == prepared["projection_digest"]
    assert submitted["status"] == "awaiting_execution_approval"

    # The browser sees exactly one approval request with the unchanged hostname/route review.
    status, listed = _owner(harness, "GET", f"{base}/canary-approval-requests", None, cookie)
    assert status == 200 and listed["has_more"] is False
    (request,) = listed["requests"]
    assert (request["approval_id"], request["run_id"], request["projection_digest"]) == (
        projection_id, submitted["run_id"], prepared["projection_digest"])
    assert (request["hostname"], request["routes"], request["scenarios"]) == (
        _STAGING, ["HEAD /health", "HEAD /health"], ["anonymous_authenticated_read"])  # anonymous + authenticated

    # Later idle polls never resubmit the recorded projection.
    claims = len([p for _m, p in harness.forwarded if p.endswith(f"/runners/{runner_id}/claim")])
    deadline = time.monotonic() + 15
    while len([p for _m, p in harness.forwarded if p.endswith(f"/runners/{runner_id}/claim")]) < claims + 2:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert harness.forwarded.count(submit) == 1
    assert len(_server_approvals(harness, workspace_id)) == 1

    # Status (while serving, offline) shows only safe identifiers.
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "status", "--offline")
    assert code == 0, err
    shown = json.loads(out)["projection_submission"]
    assert shown == {key: submitted[key] for key in (
        "state", "projection_id", "projection_digest", "approval_id", "run_id", "status")}

    daemon.request_stop()
    thread.join(10)
    assert not thread.is_alive() and outcome["result"]["state"] == "stopped", outcome
    exposed = json.dumps([prepared, shown, harness.forwarded, listed])
    assert TOKEN not in exposed and "credential_handle" not in exposed


@pytest.mark.parametrize("fault", ["drop_before", "drop_after"])
def test_a_lost_submission_answer_is_retried_by_serve_without_a_duplicate_approval(tmp_path, serve_harness, fault):
    harness, zone = serve_harness
    workspace_id, _cookie, home, backend, runner_id, _base, binding = _bound_runner(
        tmp_path, harness, zone, f"lost-{fault}")
    seeds = _child_seeds(tmp_path, backend)
    env = _configure(tmp_path, harness, home, seeds)
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live", env=env)
    assert code == 0, err
    projection_id = json.loads(out)["submission"]["projection_id"]

    first = _fault_daemon(_daemon(home, harness, backend), {"/approval-projections": [fault]})
    error = _serve_once(first)
    assert isinstance(error, daemon_module.RunnerServeError) and error.state == "offline", error
    assert RunnerStore(home).load_projection_submission()["state"] == "pending"
    assert len(_server_approvals(harness, workspace_id)) == (1 if fault == "drop_after" else 0)

    result = _serve_once(_daemon(home, harness, backend))
    assert not isinstance(result, BaseException), (result.state, result.code)
    record = RunnerStore(home).load_projection_submission()
    assert record["state"] == "submitted" and record["approval_id"] == projection_id
    (approval,) = _server_approvals(harness, workspace_id)
    assert approval[:2] == (projection_id, record["run_id"])
    # A further serve with the record already submitted sends nothing for it.
    forwarded = len(harness.forwarded)
    assert not isinstance(_serve_once(_daemon(home, harness, backend)), BaseException)
    assert not [p for _m, p in harness.forwarded[forwarded:] if "approval-projections" in p]
    assert binding["binding_id"] in _submit_path(workspace_id, runner_id, binding["binding_id"])


def test_only_the_latest_queued_projection_is_submitted_and_a_changed_context_fails_closed(tmp_path, serve_harness):
    harness, zone = serve_harness
    workspace_id, _cookie, home, backend, _runner_id, _base, _binding = _bound_runner(
        tmp_path, harness, zone, "single-slot")
    seeds = _child_seeds(tmp_path, backend)
    env = _configure(tmp_path, harness, home, seeds)
    prepared = []
    for _ in range(2):
        code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live", env=env)
        assert code == 0, err
        prepared.append(json.loads(out))
    assert prepared[0]["projection_digest"] != prepared[1]["projection_digest"]
    assert not isinstance(_serve_once(_daemon(home, harness, backend)), BaseException)
    (approval,) = _server_approvals(harness, workspace_id)
    assert approval[0] == prepared[1]["submission"]["projection_id"]

    # A queued record whose binding no longer matches the verified context is never sent.
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live", env=env)
    assert code == 0, err
    store = RunnerStore(home)
    path = store.root / "runner" / "contexts" / store.namespace / "projection-submission.json"
    value = json.loads(path.read_text())
    value["submission"]["binding_digest"] = "f" * 64
    path.write_bytes(canonical_bytes(value))
    forwarded = len(harness.forwarded)
    assert not isinstance(_serve_once(_daemon(home, harness, backend)), BaseException)
    assert not [p for _m, p in harness.forwarded[forwarded:] if "approval-projections" in p]
    refused = RunnerStore(home).load_projection_submission()
    assert (refused["state"], refused["reason"], refused["approval_id"]) == ("refused", "context_changed", None)
    assert len(_server_approvals(harness, workspace_id)) == 1


def test_a_failed_compile_queues_nothing_and_sends_nothing(tmp_path, serve_harness):
    harness, zone = serve_harness
    _workspace_id, _cookie, home, backend, _runner_id, _base, _binding = _bound_runner(
        tmp_path, harness, zone, "compile-fail")
    seeds = _child_seeds(tmp_path, backend)
    _configure(tmp_path, harness, home, seeds)
    # The ephemeral credential is absent from the environment: the live check fails before compile.
    code, out, err = _cli(tmp_path, harness, home, seeds, "runner", "prepare", "--live")
    assert (code, out) == (2, "") and err.strip() == "Heel runner live preparation is unavailable."
    assert RunnerStore(home).load_projection_submission() is None
    forwarded = len(harness.forwarded)
    assert not isinstance(_serve_once(_daemon(home, harness, backend)), BaseException)
    assert not [p for _m, p in harness.forwarded[forwarded:] if "approval-projections" in p]
