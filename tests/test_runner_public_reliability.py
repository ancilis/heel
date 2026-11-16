"""RC6 public reliability (B1): a mixed configured plan over a real-latency control link.

Real: the control plane behind the TLS edge, owner pairing/binding, private custom revisions, the
configured plan request, ``RunnerDaemon.serve`` -> ``RunnerService`` -> ``RunnerCoordinator`` ->
``RunnerControlClient`` (heartbeat, progress, result and disclosure chains), ``LocalCanaryExecutor``
and ``TargetHTTPSClient``, signed findings, and both disclosure choices (share and keep local).

Seams (as ``tests/test_configured_live_product_e3.py``): secret backend/CA, in-memory OS vault,
scripted target socket, browser-equivalent owner calls.  The ONE added seam is
SEAM-CONTROL-LATENCY: every runner->Cloud POST waits a fixed delay before reaching the real edge,
standing in for a public internet round trip to a hosted control plane.  It never alters bytes.
"""
from __future__ import annotations

import json
import time

import pytest

from tests.test_configured_live_product_e3 import (
    E3Customer, OPENAPI, TOKENS, _assertion, _body, _results,
)
from tests.test_runner_daemon import _STAGING, serve_harness  # noqa: F401 - fixture
from tests.test_runner_regression_replay import response

EDITED_FIELD = _assertion({"kind": "json_field_present", "path": ["export", "not_a_record_field"]})
NUMERIC_TOTAL = _assertion({"kind": "json_scalar_equals_fixture", "path": ["export", "total"],
                            "expected_fixture": "expected_total"})
ORIGINAL_FIELD = _assertion({"kind": "json_field_present", "path": ["export", "record_id"]})

# Measured threshold: the post-progress gate age equals that progress call's own round trip;
# 0.45 s per control call (a plausible public RTT to the hosted edge) crosses the 0.5 s bound.
CONTROL_DELAY_SECONDS = 0.45


class _LatentTransport:
    """SEAM-CONTROL-LATENCY: the real HTTPS control transport, delayed, bytes untouched."""

    def __init__(self, transport, delay):
        self._transport, self._delay = transport, delay

    def post(self, path, *, headers=None, body=b""):
        time.sleep(self._delay)
        return self._transport.post(path, headers=headers, body=body)

    def post_bounded(self, path, **kwargs):
        time.sleep(self._delay)
        return self._transport.post_bounded(path, **kwargs)

    def __getattr__(self, name):
        return getattr(self._transport, name)


class _Target:
    """SEAM-TARGET: ordinary plan-gated reads by bearer token, no marker."""

    def __init__(self):
        self.mode = "vulnerable"
        self.requests: list[bytes] = []

    def answer(self, request: bytes) -> bytes:
        line = request.split(b"\r\n", 1)[0].decode()
        pro = f"Bearer {TOKENS['higher_plan']}".encode() in request
        assert pro or f"Bearer {TOKENS['lower_plan']}".encode() in request
        if not pro and self.mode == "patched":
            return response(403, b"")
        body = json.loads(_body("pro" if pro else "free"))
        body["export"].update({"total": 42, "record_id": "r-1"})
        return response(200, json.dumps(body).encode())

    def lines(self):
        return [item.split(b"\r\n", 1)[0] for item in self.requests]

    def network(self):
        from tests.test_configured_live_product_e3 import BillingTarget
        return BillingTarget.network(self)


class LatentCustomer(E3Customer):
    def __init__(self, tmp_path, serve_harness, monkeypatch, name, delay):
        self.delay = 0.0
        super().__init__(tmp_path, serve_harness, monkeypatch, name)
        self.target = _Target()
        self.delay = delay
        self.transport_class = _LatentTransport

    def serve(self, faults=None):
        from tests.test_runner_daemon import _daemon, _serve_once
        daemon = _daemon(self.home, self.harness, self.backend,
                         vault_factory=lambda backend: self.vault, target_network=self.target.network())
        if self.delay:
            real = daemon._transport
            daemon._transport = lambda origin: self.transport_class(real(origin), self.delay)
        return _serve_once(daemon)

    def keep_local(self, run_id):
        assert not isinstance(self.serve(), BaseException)  # the runner registers the metadata
        status, shown = self.browser("GET", f"{self.base}/canary-runs/{run_id}/disclosure")
        assert status == 200, shown
        status, kept = self.browser("POST", f"{self.base}/canary-runs/{run_id}/disclosure-local-only", {
            "schema_version": "heel.canary-disclosure-local-only.v1",
            "projection_digest": shown["projection"]["projection_digest"],
            "projection_bytes": shown["projection"]["byte_count"],
            "scenario_count": shown["projection"]["scenario_count"],
            "finding_count": shown["projection"]["finding_count"]})
        assert status == 200 and kept["status"] == "local_only", kept
        return kept


def _local_operational(c, run_id):
    return c.store.load_final_projections(run_id)["local_view"]["operational_projection"]


@pytest.fixture
def customer(tmp_path, serve_harness, monkeypatch):
    c = LatentCustomer(tmp_path, serve_harness, monkeypatch, "rc6", CONTROL_DELAY_SECONDS)
    c.spec.write_text(json.dumps(OPENAPI))
    c.setup_runner()
    c.add_input("export_ok", "ok")
    c.add_input("expected_total", "42")
    return c


LABELS = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]


def _run(c, tests):
    status, created = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                      "plan_kind": "configured_live_read", "tests": tests,
                                      "plan_labels": LABELS})
    assert status == 201, created
    assert not isinstance(c.serve(), BaseException)
    request = c.approval_request()
    assert c.approve_configured(request)[0] == 201
    before = len(c.target.requests)
    outcome = c.serve()
    assert not isinstance(outcome, BaseException), (outcome.state, outcome.code)
    return request["run_id"], len(c.target.requests) - before


def test_mixed_edited_field_and_numeric_plan_completes_over_public_latency_and_survives_both_choices(customer):
    c = customer
    assert c.save_test("astra-record", ORIGINAL_FIELD)[0] == 201
    assert c.save_test("astra-record", EDITED_FIELD, supersedes=1)[0] == 201
    assert c.save_test("astra-numeric", NUMERIC_TOTAL)[0] == 201
    tests = [{"source_scenario_id": "sc.internal.astra-record", "source_revision": 2},
             {"source_scenario_id": "sc.internal.astra-numeric", "source_revision": 1}]

    # Run A: all four approved reads, a meaningful signed outcome, then KEEP LOCAL.
    run_a, reads = _run(c, tests)
    assert reads == 4
    operational = _local_operational(c, run_a)
    assert (operational["execution_disposition"], operational["error_category"]) == ("completed", "none"), operational
    c.keep_local(run_a)
    for _ in range(3):  # normal serve keeps running after the owner's local-only choice
        outcome = c.serve()
        assert not isinstance(outcome, BaseException), (outcome.state, outcome.code)

    # Run B: the same plan again, then SHARE; outcomes are meaningful, not run_incomplete.
    run_b, reads = _run(c, tests)
    assert reads == 4
    findings = c.disclose(run_b)
    results = _results(findings)
    assert results["sc.internal.astra-record"]["reason"] != "run_incomplete"
    assert results["sc.internal.astra-numeric"]["reason"] != "run_incomplete"
    assert results["sc.internal.astra-record"]["source"]["source_revision"] == 2
    assert not isinstance(c.serve(), BaseException)


class _OfflineAfterFirstProgress(_LatentTransport):
    """SEAM-CONTROL-OUTAGE: after the first accepted progress, every runner->Cloud call is refused."""

    def __init__(self, transport, delay):
        super().__init__(transport, delay)
        self.offline = False

    def _gate(self, path):
        from heel.runner.control_transport import ControlTransportError
        if self.offline:
            raise ControlTransportError("connection_failed")
        return path.endswith("/progress")

    def post(self, path, *, headers=None, body=b""):
        went_offline = self._gate(path)
        answer = super().post(path, headers=headers, body=body)
        self.offline = self.offline or went_offline
        return answer

    def post_bounded(self, path, **kwargs):
        went_offline = self._gate(path)
        answer = super().post_bounded(path, **kwargs)
        self.offline = self.offline or went_offline
        return answer


def test_a_genuine_cloud_outage_after_progress_fails_closed_before_more_target_traffic(customer):
    c = customer
    assert c.save_test("astra-record", EDITED_FIELD)[0] == 201
    assert c.save_test("astra-numeric", NUMERIC_TOTAL)[0] == 201
    status, created = c.request_plan({
        "schema_version": "heel.configured-plan-request.v1", "plan_kind": "configured_live_read",
        "tests": [{"source_scenario_id": "sc.internal.astra-record", "source_revision": 1},
                  {"source_scenario_id": "sc.internal.astra-numeric", "source_revision": 1}],
        "plan_labels": LABELS})
    assert status == 201, created
    assert not isinstance(c.serve(), BaseException)
    request = c.approval_request()
    assert c.approve_configured(request)[0] == 201
    c.transport_class = _OfflineAfterFirstProgress
    before = len(c.target.requests)
    outcome = c.serve()
    reads = len(c.target.requests) - before
    assert isinstance(outcome, BaseException) and outcome.state == "offline", outcome
    assert reads == 1  # the action that preceded the outage; nothing after it
    operational = _local_operational(c, request["run_id"])
    assert (operational["execution_disposition"], operational["error_category"]) == (
        "incomplete", "cloud_disconnected"), operational
