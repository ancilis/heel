"""T3 red-team tests for the plan-differential runner (docs/REDTEAM_PLAN_DIFFERENTIAL.md).

Tests named ``test_redteam_break_*`` demonstrate a break and are EXPECTED TO FAIL until a
T4 remediation fixes product code. They are not skipped or xfailed on purpose. Tests named
``test_redteam_holds_*`` are adversarial regressions for boundaries that held and that no
other test covers.

Every request goes only to the loopback synthetic listener, bound to port 0 per test,
through the one seam ``heel.runner.plan_differential._build_client``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket

import pytest

from heel.runner.http_transport import TargetHTTPSClient
from heel.runner.plan_differential import ExecutorOutcome, PlanObservation, evaluate_plan_pair

from plan_differential_support import (
    FREE_TOKEN,
    PRO_TOKEN,
    PUBLIC_ADDRESS,
    SYNTHETIC_HOST,
    Journey,
    LoopbackFactory,
    SecondListener,
    _Listener,
    home_contains,
    install,
    scope_path,
)


class _Target(_Listener):
    """A loopback listener whose responses come from one function of (plan, method, path, token)."""

    def __init__(self, responder, tokens: tuple[str, str]) -> None:
        super().__init__({tokens[0]: "free", tokens[1]: "pro"})
        self._responder = responder

    def respond(self, method: str, path: str, token: str):
        status, headers, body = self._responder(self.sessions.get(token), method, path, token)
        return status, {"Content-Type": "application/json", **headers}, body


class _World:
    def __init__(self, tmp_path, monkeypatch, responder, routes: dict[str, tuple[str, ...]], *,
                 tokens: tuple[str, str] = (FREE_TOKEN, PRO_TOKEN), factory=None) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        document = {
            "openapi": "3.1.0",
            "info": {"title": "Plan-differential red team", "version": "1.0.0"},
            "paths": {
                route: {
                    method.lower(): {
                        "operationId": f"op{index}{method.lower()}",
                        "responses": {"200": {"description": "ok"}},
                    }
                    for method in methods
                }
                for index, (route, methods) in enumerate(routes.items())
            },
        }
        fixture = tmp_path / "openapi.json"
        fixture.write_text(json.dumps(document), encoding="utf-8")
        self.second = SecondListener().start()
        self.target = _Target(responder, tokens).start()
        self.factory = (factory or LoopbackFactory)(self.target.port)
        install(monkeypatch, self.factory)
        try:
            self.journey = Journey(tmp_path, monkeypatch, tokens=tokens, fixture=fixture)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.target.stop()
        self.second.stop()

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _ok(_plan, _method, _path, _token):
    return 200, {}, b'{"value": 1}'


# --------------------------------------------------------------------------- #
# BREAK D1 (brief 1.5, R11): a 2xx denial body yields an `observed` finding
# --------------------------------------------------------------------------- #
_HIGHER = {"ok": True, "success": True, "status": "ok", "export_url": "https://files/x.csv", "rows": 3}
_DENIED = {"ok": True, "success": True, "status": "ok", "export_url": None, "rows": None}
DENIAL_BODIES = {
    "ok_zero": {**_DENIED, "ok": 0},
    "ok_string_false": {**_DENIED, "ok": "false"},
    "success_zero": {**_DENIED, "success": 0},
    "denied_one": {**_DENIED, "denied": 1},
    "forbidden_string_true": {**_DENIED, "forbidden": "true"},
    "upgrade_required_one": {**_DENIED, "upgrade_required": 1},
    "payment_required_one": {**_DENIED, "payment_required": 1},
    "jsend_status_error": {**_DENIED, "status": "error", "message": "Upgrade required"},
    "jsend_status_fail": {**_DENIED, "status": "fail", "message": "Upgrade required"},
}


@pytest.mark.parametrize("name", sorted(DENIAL_BODIES))
def test_redteam_break_d1_two_xx_denial_body_never_yields_observed(name):
    """EXPECTED TO FAIL (D1). The lower plan answers 200 with a body that says it was denied
    and carries no data, in the same key shape as the higher plan's body. The verdict is
    `finding` / `observed` / `body_superset`; it must be inconclusive."""
    verdict = evaluate_plan_pair(
        PlanObservation(200, json.dumps(DENIAL_BODIES[name]).encode()),
        PlanObservation(200, json.dumps(_HIGHER).encode()),
        method="GET", marker=None, executor_outcome=ExecutorOutcome("completed", "inconclusive"),
    )
    assert verdict.body_superset is not True, verdict
    assert verdict.status_parity is not True, verdict
    assert (verdict.verdict, verdict.evidence_state) == ("inconclusive", "inconclusive"), verdict


def test_redteam_break_d1_denial_body_observed_finding_through_the_cli(tmp_path, monkeypatch):
    """EXPECTED TO FAIL (D1). The same false positive end to end: stored finding, exit 1."""
    def responder(plan, _method, _path, _token):
        body = {"ok": 1, "export_url": "https://files/x.csv", "rows": 3} if plan == "pro" else {
            "ok": 0, "export_url": None, "rows": 0,
        }
        return 200, {}, json.dumps(body).encode()

    with _World(tmp_path, monkeypatch, responder, {"/api/export": ("GET",)}) as world:
        code, result, error = world.journey.run()
        assert error == "" and result["requests_sent"] == 2
        states = [
            finding["reproduction"]["evidence_state"]
            for finding in world.journey.findings(result["run_id"])
        ]
        assert "observed" not in states, states
        assert code == 0


# --------------------------------------------------------------------------- #
# BREAK D1, T3 rerun after T4 loop 1 (REDTEAM_PLAN_DIFFERENTIAL.md section 9)
# --------------------------------------------------------------------------- #
# Each body is inside the contract of the loop-1 remediation (the spec vocabulary under
# JSON truthiness, a 4xx/5xx status number, a denial word in a status or code string) and
# differs from a recognized envelope only in value type or word separator.
RERUN_DENIAL_BODIES = {
    # JSON-falsy values of the allow flags.
    "ok_null": {**_DENIED, "ok": None},
    "ok_empty_string": {**_DENIED, "ok": ""},
    "success_empty_string": {**_DENIED, "success": ""},
    # JSON-truthy values of the deny flags that are not a yes-word.
    "denied_reason_string": {**_DENIED, "denied": "plan does not include exports"},
    "upgrade_required_plan_name": {**_DENIED, "upgrade_required": "pro"},
    "forbidden_reason_list": {**_DENIED, "forbidden": ["exports"]},
    "payment_required_object": {**_DENIED, "payment_required": {"url": "https://x/upgrade"}},
    # A 4xx status number that is not a JSON integer literal.
    "status_float_403": {**_DENIED, "status": 403.0},
    "status_code_exponent_402": (
        b'{"ok": true, "success": true, "status": "ok", "status_code": 4.02e2, '
        b'"export_url": null, "rows": null}'
    ),
    # A denial word or status number without a separator around it.
    "code_pascal_case_payment_required": {**_DENIED, "code": "PaymentRequired"},
    "code_pascal_case_access_denied": {**_DENIED, "code": "AccessDenied"},
    "code_prefixed_e403": {**_DENIED, "code": "E403"},
}


def _body(value) -> bytes:
    return value if isinstance(value, bytes) else json.dumps(value).encode()


@pytest.mark.parametrize("name", sorted(RERUN_DENIAL_BODIES))
def test_redteam_break_d1_rerun_denial_value_spellings_never_yield_observed(name):
    """EXPECTED TO FAIL (D1, rerun). Same pair as the D1 test above, with a denial value the
    loop-1 remediation does not read. The verdict is `finding` / `observed`."""
    verdict = evaluate_plan_pair(
        PlanObservation(200, _body(RERUN_DENIAL_BODIES[name])),
        PlanObservation(200, json.dumps(_HIGHER).encode()),
        method="GET", marker=None, executor_outcome=ExecutorOutcome("completed", "inconclusive"),
    )
    assert verdict.body_superset is not True, verdict
    assert verdict.status_parity is not True, verdict
    assert (verdict.verdict, verdict.evidence_state) == ("inconclusive", "inconclusive"), verdict


@pytest.mark.parametrize("name", [
    "code_pascal_case_payment_required", "status_float_403", "upgrade_required_plan_name",
])
def test_redteam_break_d1_rerun_observed_finding_through_the_cli(name, tmp_path, monkeypatch):
    """EXPECTED TO FAIL (D1, rerun). The same false positive end to end: stored finding, exit 1."""
    def responder(plan, _method, _path, _token):
        return 200, {}, json.dumps(_HIGHER).encode() if plan == "pro" else _body(
            RERUN_DENIAL_BODIES[name]
        )

    with _World(tmp_path, monkeypatch, responder, {"/api/export": ("GET",)}) as world:
        code, result, error = world.journey.run()
        assert error == "" and result["requests_sent"] == 2
        states = [
            finding["reproduction"]["evidence_state"]
            for finding in world.journey.findings(result["run_id"])
        ]
        assert "observed" not in states, states
        assert code == 0


@pytest.mark.parametrize("body", [
    {"ok": "yes", "rows": 3}, {"ok": 1.0, "rows": 3}, {"success": "true", "rows": 3},
    {"denied": "no", "rows": 3}, {"denied": "", "rows": 3}, {"denied": None, "rows": 3},
    {"forbidden": 0, "upgrade_required": "false", "rows": 3},
    {"error": None, "errors": [], "rows": 3},
    {"status": 200.0, "rows": 3}, {"status": "ok", "code": "OK", "rows": 3},
    # status, code and flags inside list rows are data, not an envelope.
    {"items": [{"status": "error", "code": 403, "denied": True, "ok": False}], "total": 1},
], ids=lambda body: "+".join(sorted(body)))
def test_redteam_holds_affirmative_bodies_keep_the_positive_control(body):
    """Guard for the D1 fix: a body that affirms access, or carries the vocabulary only in
    list rows, is not an envelope, so the same body for both plans is still `observed`."""
    raw = json.dumps(body).encode()
    verdict = evaluate_plan_pair(
        PlanObservation(200, raw), PlanObservation(200, raw),
        method="GET", marker=None, executor_outcome=ExecutorOutcome("completed", "inconclusive"),
    )
    assert verdict.positive_control is True, verdict
    assert (verdict.verdict, verdict.evidence_state) == ("finding", "observed"), verdict


# --------------------------------------------------------------------------- #
# BREAK D2 (spec 7, I5): an echoed credential in another JSON escaping is persisted
# --------------------------------------------------------------------------- #
ESCAPED_LOWER = "redteam+free/session=0001"
ESCAPED_HIGHER = "redteam+pro/session=0001"
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _json_escapes_resolved(data: bytes) -> str:
    text = data.decode("utf-8", "replace").replace("\\/", "/")
    return _UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), text)


ECHO_ESCAPINGS = {
    # System.Text.Json's default encoder writes "+" as +.
    "plus_as_u002b": lambda token: token.replace("+", "\\u002B"),
    "equals_as_u003d": lambda token: token.replace("=", "\\u003d"),
    "every_character": lambda token: "".join(f"\\u{ord(character):04x}" for character in token),
}


@pytest.mark.parametrize("escaping", sorted(ECHO_ESCAPINGS))
def test_redteam_break_d2_json_escaped_credential_echo_is_not_persisted(escaping, tmp_path, monkeypatch):
    """EXPECTED TO FAIL (D2). The target echoes the credential as a valid JSON string that
    uses \\uXXXX escapes. The plain byte scan of I5 is clean, but the stored evidence decodes
    to the credential with any JSON parser."""
    tokens = (ESCAPED_LOWER, ESCAPED_HIGHER)

    def responder(_plan, _method, _path, token):
        return 200, {}, ('{"echo":"' + ECHO_ESCAPINGS[escaping](token) + '"}').encode("ascii")

    with _World(tmp_path, monkeypatch, responder, {"/api/echo": ("GET",)}, tokens=tokens) as world:
        code, result, error = world.journey.run()
        assert error == "" and result["pairs"][0]["execution_disposition"] == "completed"
        home = world.journey.home
        # The literal scan of I5 holds.
        assert [home_contains(home, token.encode()) for token in tokens] == [[], []]
        leaked = sorted(
            str(Path(directory, name).relative_to(home))
            for directory, _, names in os.walk(home) for name in names
            if any(
                token in _json_escapes_resolved(Path(directory, name).read_bytes())
                for token in tokens
            )
        )
        assert leaked == [], leaked


# --------------------------------------------------------------------------- #
# Boundaries that held (not covered elsewhere)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redteam_holds_every_redirect_status_is_refused_for_get_and_head(status, tmp_path, monkeypatch):
    world: _World

    def responder(_plan, _method, _path, _token):
        return status, {"Location": f"http://127.0.0.1:{world.second.port}/landing"}, b""

    with _World(tmp_path, monkeypatch, responder, {"/api/moved": ("GET", "HEAD")}) as world:
        code, result, error = world.journey.run()
        assert (code, error) == (0, "")
        assert [
            (pair["method"], pair["reason"], pair["finding_id"]) for pair in result["pairs"]
        ] == [
            ("GET", "transport:response_rejected", None),
            ("HEAD", "transport:response_rejected", None),
        ]
        # One lower-plan request per pair, no higher-plan request, nothing off the allowlist.
        assert world.target.seen() == [
            ("GET", "/api/moved", "free"), ("HEAD", "/api/moved", "free"),
        ]
        assert world.second.seen() == []
        assert set(world.factory.sockets.addresses) == {(PUBLIC_ADDRESS, 443)}
        assert {item["host"] for item in world.target.requests} == {SYNTHETIC_HOST}


@pytest.mark.parametrize("edit", ["widen", "expire", "delete"])
def test_redteam_holds_scope_tamper_between_lower_and_higher_request(edit, tmp_path, monkeypatch):
    with _World(tmp_path, monkeypatch, _ok, {"/api/a": ("GET",), "/api/b": ("GET",)}) as world:
        journey = world.journey
        path = scope_path(journey.home, journey.scope_id)

        def tamper(index: int) -> None:
            if index != 0:
                return
            if edit == "delete":
                path.unlink()
                return
            body = json.loads(path.read_text())
            if edit == "widen":
                body["target_allowlist"].append("other-staging.heel.dev")
            else:
                body["expiry"] = 1.0
            path.write_text(json.dumps(body))

        world.target.on_request = tamper
        code, result, error = journey.run()
        # The lower-plan request that triggered the edit is the last request of the run.
        assert world.target.seen() == [("GET", "/api/a", "free")]
        assert (code, error, result["findings"]) == (0, "", [])
        assert result["pairs"][0]["reason"] == "transport:gate_rejected"
        assert all(pair["execution_disposition"] == "not_started" for pair in result["pairs"][1:])
        assert result["chain_valid"] is True


class _Resolver:
    def __init__(self, answers: list[list[str]]) -> None:
        self.answers = answers
        self.calls = 0

    def __call__(self, hostname: str, *, deadline: float) -> list[str]:
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer


class _Sockets:
    def __init__(self, port: int, *, peer: str | None, fail_first: bool) -> None:
        self.port = port
        self.peer = peer
        self.fail_first = fail_first
        self.addresses: list[tuple[str, int]] = []

    def connect(self, address, timeout, cancellation):
        self.addresses.append(tuple(address))
        if self.fail_first and len(self.addresses) == 1:
            raise ConnectionRefusedError("synthetic connect failure")
        raw = socket.create_connection(("127.0.0.1", self.port), timeout)
        peer = self.peer or address[0]

        class Pinned:
            def getpeername(self):
                return (peer, 443)

            def __getattr__(self, name: str):
                return getattr(raw, name)

        return Pinned()


class _PassThroughTLS:
    def wrap(self, raw_socket, hostname: str, timeout: float):
        raw_socket.settimeout(timeout)
        return raw_socket


REBINDING = {
    # name: (resolver answers per call, reported peer, first connect fails, reason, requests seen)
    "mixed_public_private_on_first_attempt": ([[PUBLIC_ADDRESS, "10.0.0.5"]], None, False, "transport:unsafe_dns", 0),
    "superset_of_public_answers": ([[PUBLIC_ADDRESS, "93.184.216.35"]], None, False, "transport:dns_changed", 0),
    "ipv4_mapped_form_of_the_pinned_address": ([["::ffff:" + PUBLIC_ADDRESS]], None, False, "transport:unsafe_dns", 0),
    "private_answer_between_lower_and_higher": ([[PUBLIC_ADDRESS], ["127.0.0.1"]], None, False, "transport:unsafe_dns", 1),
    "mixed_answer_on_the_retry": ([[PUBLIC_ADDRESS], [PUBLIC_ADDRESS, "192.168.1.1"]], None, True, "transport:unsafe_dns", 0),
    "peer_is_not_the_pinned_address": ([[PUBLIC_ADDRESS]], "127.0.0.1", False, "transport:peer_mismatch", 0),
}


@pytest.mark.parametrize("name", sorted(REBINDING))
def test_redteam_holds_dns_rebinding_between_preflight_retry_and_peer_check(name, tmp_path, monkeypatch):
    answers, peer, fail_first, reason, seen = REBINDING[name]

    class Factory:
        def __init__(self, port: int) -> None:
            self.resolver = _Resolver(answers)
            self.sockets = _Sockets(port, peer=peer, fail_first=fail_first)

        def __call__(self, origin: str) -> TargetHTTPSClient:
            return TargetHTTPSClient(
                origin=origin, preflight_addresses=[PUBLIC_ADDRESS], resolver=self.resolver,
                sockets=self.sockets, tls=_PassThroughTLS(),
            )

    with _World(tmp_path, monkeypatch, _ok, {"/api/a": ("GET",), "/api/b": ("GET",)},
                factory=Factory) as world:
        code, result, error = world.journey.run()
        assert (code, error, result["findings"]) == (0, "", [])
        assert result["pairs"][0]["reason"] == reason
        assert result["pairs"][1]["execution_disposition"] == "not_started"
        # No request bytes after the answer changed, and only the pinned address was dialed.
        assert len(world.target.seen()) == seen
        assert set(world.factory.sockets.addresses) <= {(PUBLIC_ADDRESS, 443)}
        assert world.second.seen() == []


@pytest.mark.parametrize("credential", [
    "token\r\nHost: evil.example.com",
    "token\nX-Injected: 1234567",
    "token with space 1234567",
    "token-1234567\r\n",
])
def test_redteam_holds_credential_material_cannot_inject_a_header(credential, tmp_path, monkeypatch):
    with _World(tmp_path, monkeypatch, _ok, {"/api/a": ("GET",)},
                tokens=(credential, PRO_TOKEN)) as world:
        code, result, error = world.journey.run()
        assert (code, error) == (0, "")
        assert world.target.requests == [] and result["requests_sent"] == 0
        assert result["findings"] == []
        assert home_contains(world.journey.home, credential.encode()) == []


# --------------------------------------------------------------------------- #
# BREAK D1, final rerun after T4 loop 2 (REDTEAM_PLAN_DIFFERENTIAL.md section 10)
# --------------------------------------------------------------------------- #
# Concrete 2xx denial bodies outside the loop-2 vocabulary. Each stored an `observed`
# finding through the CLI in the final rerun; brief 1.5 says none may count as parity.
FINAL_DENIAL_BODIES = {
    "status_false_with_message": {**_DENIED, "status": False, "message": "Upgrade required"},
    "message_only_denial": {**_DENIED, "message": "Upgrade required"},
    "code_run_on_PAYMENTREQUIRED": {**_DENIED, "code": "PAYMENTREQUIRED"},
    "status_run_on_accessdenied": {**_DENIED, "status": "accessdenied"},
}


@pytest.mark.parametrize("name", sorted(FINAL_DENIAL_BODIES))
def test_redteam_break_d1_final_unrecognized_denial_body_yields_observed(name):
    """EXPECTED TO FAIL (D1, final rerun). Same pair as the D1 tests above with a denial body
    the loop-2 recognizer does not read. The verdict is `finding` / `observed`."""
    verdict = evaluate_plan_pair(
        PlanObservation(200, _body(FINAL_DENIAL_BODIES[name])),
        PlanObservation(200, json.dumps(_HIGHER).encode()),
        method="GET", marker=None, executor_outcome=ExecutorOutcome("completed", "inconclusive"),
    )
    assert verdict.body_superset is not True, verdict
    assert verdict.status_parity is not True, verdict
    assert (verdict.verdict, verdict.evidence_state) == ("inconclusive", "inconclusive"), verdict
