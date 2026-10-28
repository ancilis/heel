"""Safety invariants I1-I8 and requirements R9-R25 of the plan-differential runner.

Every test that sends a request sends it only to the loopback synthetic target, bound to
port 0 per test. The one seam is ``heel.runner.plan_differential._build_client``; it proves
nothing about TLS, DNS answers or address selection (see ``plan_differential_support``).
"""
from __future__ import annotations

import ast
import base64
import getpass
import inspect
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import types

import pytest

from heel import mcp_server
from heel import scope as scope_module
from heel.containment import verify_chain
from heel.runner import compiler as compiler_module
from heel.runner import http_transport, plan_differential
from heel.runner.catalog import CATALOG_BY_ID
from heel.runner.compiler import CanaryCompiler, plan_differential_pairs
from heel.runner.containment import verify_containment_chain
from heel.runner.execution import LocalCanaryExecutor
from heel.runner.http_transport import TLSTransport, TransportFailure
from heel.saas.network_guard import TLSTransport as NetworkTLSTransport
from heel.runner.redaction import Redactor
from heel.runner.store import RunnerStore
from heel.store import Store

from plan_differential_support import (
    FREE_TOKEN,
    MARKER,
    PRO_TOKEN,
    PUBLIC_ADDRESS,
    SYNTHETIC_HOST,
    SYNTHETIC_ORIGIN,
    Journey,
    TLSLoopbackServer,
    World,
    bulk_openapi,
    home_contains,
    invoke,
    make_test_ca,
    pairs_by_route,
    pricing,
    scope_path,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE_SOURCE = ROOT / "heel/runner/plan_differential.py"
REJECTED = "Heel runner command was rejected.\n"
CALLER = "cli:" + getpass.getuser()
# Canonical order of the fixture inventory with no mapping: ten planned pairs.
PLANNED = [
    ("GET", "/api/billing"), ("GET", "/api/echo"), ("GET", "/api/empty"),
    ("GET", "/api/export"), ("HEAD", "/api/export"), ("GET", "/api/pricing"),
    ("GET", "/api/redirect"), ("GET", "/api/reports"), ("GET", "/api/summary"),
    ("GET", "/api/text"),
]
# A response-level refusal after the first response: the higher-plan request is never sent.
REFUSED = {("GET", "/api/redirect"), ("GET", "/api/text")}


def no_network(monkeypatch) -> list[str]:
    """Make every socket and name lookup fail loudly and record the attempt."""
    attempts: list[str] = []

    def refuse(name):
        def raiser(*_args, **_keywords):
            attempts.append(name)
            raise AssertionError("network use: " + name)
        return raiser

    monkeypatch.setattr(socket, "socket", refuse("socket"))
    monkeypatch.setattr(socket, "create_connection", refuse("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse("getaddrinfo"))
    return attempts


def entries(journey: Journey, run_id: str, action: str | None = None) -> list[dict]:
    rows = journey.containment(run_id)["entries"]
    return [
        {**row, "detail": json.loads(row["detail"])}
        for row in rows if action is None or row["action"] == action
    ]


def attempt_store(journey: Journey, result: dict) -> RunnerStore:
    return RunnerStore(journey.home / "plan-runs" / result["attempt_id"])


def requests_started(journey: Journey, result: dict) -> int:
    store = attempt_store(journey, result)
    total = 0
    for pair in result["pairs"]:
        for runner_run_id in pair["runner_run_ids"]:
            try:
                events = store.load_run_events(runner_run_id)
            except Exception:
                continue  # the run was never reserved, so it started nothing
            total += events[-1]["counters"]["requests_started"]
    return total


def tamper_scope(journey: Journey) -> None:
    """Hand-edit the signed scope file: the signature no longer matches."""
    path = scope_path(journey.home, journey.scope_id)
    body = json.loads(path.read_text())
    body["target_allowlist"].append("widened.example.com")
    path.write_text(json.dumps(body, indent=2))


def assert_no_credentials(world: World, *texts: str) -> None:
    for token in world.journey.tokens:
        forms = {token.encode(), json.dumps(token)[1:-1].encode()}
        for form in forms:
            assert home_contains(world.journey.home, form) == []
            for text in texts:
                assert form.decode() not in text


def run_result(world: World, *extra: str, **keywords):
    code, result, error = world.journey.run(*extra, **keywords)
    assert error == "" and result is not None, (code, error)
    return code, result


# --------------------------------------------------------------------------- #
# I1 host confinement
# --------------------------------------------------------------------------- #
def test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding(tmp_path, monkeypatch):
    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        # (a) A verified scope that does not list the host: forced dry-run, exit 3, with or
        # without --dry-run, and nothing is sent anywhere.
        other_scope = journey.create_scope("other-staging.heel.dev")
        for extra in ((), ("--dry-run",)):
            code, result, error = journey.run(*extra, scope=other_scope)
            assert (code, error) == (3, "")
            assert result["mode"] == "dry_run" and result["authorized"] is False
            assert result["requests_sent"] == 0
        assert world.target.seen() == [] and world.second.seen() == []
        assert world.factory.origins == [] and world.factory.sockets.addresses == []
        assert not (journey.home / "plan-runs").exists()
        rejected = [
            json.loads(row["detail"]) for row in journey.containment("security")["entries"]
            if row["action"] == "reject_run"
        ]
        assert len(rejected) == 2
        assert all(item["requested_host"] == SYNTHETIC_HOST for item in rejected)

        # (b) A route answering 302 to the second listener: never followed.
        code, result = run_result(world)
        redirect = pairs_by_route(result)[("GET", "/api/redirect")]
        assert (redirect["verdict"], redirect["reason"], redirect["finding_id"]) == (
            "inconclusive", "transport:response_rejected", None,
        )
        assert world.second.seen() == []
        assert [item for item in world.target.seen() if item[1] == "/api/redirect"] == [
            ("GET", "/api/redirect", "free"),
        ]
        # Every connection went to the one pinned address on 443.
        assert set(world.factory.sockets.addresses) == {(PUBLIC_ADDRESS, 443)}
        sent = len(world.target.seen())

        # (c) Unsafe base URLs are rejected before any socket or lookup.
        with monkeypatch.context() as patch:
            attempts = no_network(patch)
            for base_url in (
                "https://93.184.216.34",
                "https://[2606:2800:220:1:248:1893:25c8:1946]",
                "http://" + SYNTHETIC_HOST,
                SYNTHETIC_ORIGIN + ":8443",
                "https://operator@" + SYNTHETIC_HOST,
                SYNTHETIC_ORIGIN + ".",
                "https://xn--bcher-kva.example",
                SYNTHETIC_ORIGIN + "/path",
                SYNTHETIC_ORIGIN + "?next=1",
                "https://localhost",
                "https://127.0.0.1",
            ):
                for extra in ((), ("--dry-run",)):
                    code, result, error = journey.run(*extra, origin=base_url)
                    assert (code, result, error) == (2, None, REJECTED), base_url
            assert attempts == []
        assert len(world.target.seen()) == sent and world.second.seen() == []

    # (d) The resolver's answer changes after the first pair: the run ends, nothing further.
    with World(tmp_path / "b", monkeypatch, change_after=2) as world:
        code, result = run_result(world)
        assert world.target.seen() == [
            ("GET", "/api/billing", "free"), ("GET", "/api/billing", "pro"),
        ]
        second = result["pairs"][1]
        assert (second["reason"], second["execution_disposition"], second["finding_id"]) == (
            "transport:dns_changed", "incomplete", None,
        )
        assert all(
            (pair["reason"], pair["execution_disposition"]) == ("stopped", "not_started")
            for pair in result["pairs"][2:]
        )
        assert {
            item["reason"] for item in result["not_executed"]
            if item["reason"] != "unbound_placeholder"
        } == {"run_stopped"}
        # The changed address was never dialed.
        assert set(world.factory.sockets.addresses) == {(PUBLIC_ADDRESS, 443)}
        assert result["chain_valid"] is True and world.second.seen() == []


def test_i1_host_header_is_always_the_normalized_host(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch, marker=MARKER) as world:
        code, result = run_result(world)
        assert len(world.target.requests) == result["requests_sent"] > 0
        assert {item["host"] for item in world.target.requests} == {SYNTHETIC_HOST}
        assert set(world.factory.tls.hostnames) == {SYNTHETIC_HOST}
        assert world.factory.origins == [SYNTHETIC_ORIGIN]
        # The fixture value reaches the path only; it never becomes a host.
        assert ("GET", "/exports/" + MARKER, "free") in world.target.seen()


# --------------------------------------------------------------------------- #
# I2 GET/HEAD and inventoried-route confinement, in the compiler
# --------------------------------------------------------------------------- #
def test_i2_post_inventory_is_rejected_at_compile(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        artifact = json.loads((journey.home / "runner").joinpath(
            *Path(journey.bootstrap["inventory"]["path"]).parts[-3:]
        ).read_text())
        assert all(route["method"] in {"GET", "HEAD"} for route in artifact["inventory"]["routes"])
        post = {
            "method": "POST", "route_template": "/api/export", "operation_id": "createExport",
            "placeholders": [],
        }
        artifact["inventory"]["routes"].append(post)
        hostile = tmp_path / "hostile-routes.json"
        hostile.write_text(json.dumps(artifact))

        assert plan_differential.plan_differential_pairs is compiler_module.plan_differential_pairs
        order: list[str] = []
        received: list[list] = []

        def recording_pairs(routes, *, mapping):
            order.append("compiler")
            received.append(list(routes))
            return compiler_module.plan_differential_pairs(routes, mapping=mapping)

        real_inventory = RunnerStore.route_inventory

        def recording_inventory(self, artifact=None):
            order.append("store")
            return real_inventory(self, artifact)

        monkeypatch.setattr(plan_differential, "plan_differential_pairs", recording_pairs)
        monkeypatch.setattr(RunnerStore, "route_inventory", recording_inventory)
        for extra in ((), ("--dry-run",)):
            order.clear()
            received.clear()
            code, result, error = journey.run("--routes", str(hostile), *extra)
            assert (code, result, error) == (2, None, REJECTED)
            # The compiler saw the raw list, POST included, and refused it before the store
            # was asked to validate the artifact.
            assert order == ["compiler"]
            assert post in received[0] and len(received[0]) == 13
        assert world.target.seen() == [] and not (journey.home / "plan-runs").exists()

    # The compiler function alone refuses every non-GET/HEAD method and every open record.
    good = {"method": "GET", "route_template": "/a", "operation_id": "a", "placeholders": []}
    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "get", "", None, 7):
        with pytest.raises(ValueError):
            plan_differential_pairs([{**good, "method": method}], mapping=None)
    for bad in (
        [{**good, "extra": 1}], [{"method": "GET", "route_template": "/a"}], "routes", None,
        [good, good], [{**good, "route_template": "/a/../b"}],
        [{**good, "route_template": "/a?x=1"}], [{**good, "placeholders": ["id"]}],
        [{**good, "route_template": "/a/{id}", "placeholders": []}],
        [dict(good, route_template=f"/r{index}") for index in range(2001)],
    ):
        with pytest.raises(ValueError):
            plan_differential_pairs(bad, mapping=None)
    planned, skipped = plan_differential_pairs(
        [{**good, "route_template": "/z/{id}", "placeholders": ["id"]},
         {**good, "method": "HEAD"}, good],
        mapping=None,
    )
    assert [(item["method"], item["route_template"]) for item in planned] == [
        ("GET", "/a"), ("HEAD", "/a"),
    ]
    assert skipped == [{"method": "GET", "route_template": "/z/{id}", "reason": "unbound_placeholder"}]


def _bound_compiler(root: Path, routes: list[dict]) -> CanaryCompiler:
    signer = plan_differential._EphemeralSigner()
    identity = plan_differential._ephemeral_identity(signer)
    store = RunnerStore(root)
    store.bind_context(
        plan_differential._context(SYNTHETIC_ORIGIN, SYNTHETIC_HOST), identity=identity,
        signer=signer, signer_label="plan-differential-test",
    )
    store.replace_routes(routes, source_digest="0" * 64)
    for role in ("lower_plan", "higher_plan"):
        store.register_ephemeral_credential(
            semantic_role=role, auth_profile="bearer", source_kind="environment", label=role,
        )
    return CanaryCompiler(store=store, identity=identity, signer=signer, now_ms=1_800_000_000_000)


def test_i2_only_inventoried_get_and_head_reach_the_wire(tmp_path, monkeypatch):
    # (b) The compiler method: exactly two actions, lower then higher, for GET and for HEAD.
    routes = [
        {"method": "GET", "route_template": "/api/export", "operation_id": "g", "placeholders": []},
        {"method": "HEAD", "route_template": "/api/export", "operation_id": "h", "placeholders": []},
    ]
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "compiler-home"))
    compiler = _bound_compiler(tmp_path / "compiler-store", routes)
    for method in ("GET", "HEAD"):
        compiled = compiler.compile_plan_differential_pair(
            method=method, route_template="/api/export", fixture_bindings={},
        )
        actions = compiled.manifest["actions"]
        assert [
            (item["method"], item["route_template"], item["semantic_auth_role"]) for item in actions
        ] == [(method, "/api/export", "lower_plan"), (method, "/api/export", "higher_plan")]
        assert {item["scenario_id"] for item in actions} == {"plan_entitlement_read"}
    for method, route in (
        ("GET", "/api/absent"), ("HEAD", "/api/absent"), ("POST", "/api/export"),
        ("DELETE", "/api/export"), ("get", "/api/export"), ("GET", "/api/export/"),
        ("GET", "/api/../export"),
    ):
        with pytest.raises(Exception):
            compiler.compile_plan_differential_pair(
                method=method, route_template=route, fixture_bindings={},
            )

    # (c) Across a full run the target sees only GET and HEAD on planned paths.
    with World(tmp_path / "run", monkeypatch, marker=MARKER) as world:
        code, result = run_result(world)
        planned = {
            (pair["method"], pair["route_template"].replace("{id}", MARKER))
            for pair in result["pairs"]
        }
        seen = world.target.seen()
        assert seen and {method for method, _, _ in seen} == {"GET", "HEAD"}
        assert {(method, path) for method, path, _ in seen} <= planned
        assert not any(path.startswith("/items/") for _, path, _ in seen)
        assert result["not_executed"] == [
            {"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"},
        ]


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def request(self, action, **keywords):
        self.calls.append({"action": action, **keywords})
        return "response"


class _RecordingLog:
    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    def append(self, action: str, detail: dict) -> None:
        self.entries.append((action, detail))


def _compiled(method: str = "GET", route: str = "/api/export"):
    return types.SimpleNamespace(manifest={"actions": [
        {"method": method, "route_template": route, "semantic_auth_role": role}
        for role in ("lower_plan", "higher_plan")
    ]})


def _scoped(client, *, reservation, budget=None, log=None, authorize=lambda: True):
    budget = budget or plan_differential._Budget(10)
    log = log or _RecordingLog()
    transport = plan_differential._ScopedTransport(
        client, compiled=_compiled(), reservation=reservation, authorize=authorize,
        budget=budget, log=log, labels={"lower_plan": "free", "higher_plan": "pro"},
        runner_run_id="crun_test_00", secrets=lambda: (FREE_TOKEN, PRO_TOKEN),
    )
    return transport, budget, log


def _action(*, scenario="plan_entitlement_read", method="GET", role="lower_plan"):
    return types.SimpleNamespace(scenario_id=scenario, method=method, semantic_auth_role=role)


def _request(transport, action, *, route="/api/export", before_attempt=None, redactor=None):
    return transport.request(
        action, credential=object(), cancellation=object(), retry_policy=object(),
        remaining_requests=2,
        before_attempt=before_attempt or (lambda attempt, previous: "permit"),
        evidence_context=types.SimpleNamespace(route_template=route, action_ordinal=0),
        evidence_sink=lambda evidence: "ev", redactor=redactor or Redactor(()),
    )


def test_i2_every_transport_action_is_the_compiled_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "home"))
    reservation = plan_differential._reserve_attempt("ab" * 16)

    # (d) Anything that is not the compiled pair is refused before budget, log or socket.
    refusals = (
        (_action(scenario="anonymous_authenticated_read"), "/api/export"),
        (_action(scenario="object_ownership_read"), "/api/export"),
        (_action(), "/api/reports"),
        (_action(method="HEAD"), "/api/export"),
        (_action(method="POST"), "/api/export"),
        (_action(role="anonymous"), "/api/export"),
        (_action(role="authenticated"), "/api/export"),
        (_action(role="owner"), "/api/export"),
        (types.SimpleNamespace(), "/api/export"),
    )
    for action, route in refusals:
        client = _RecordingClient()
        transport, budget, log = _scoped(client, reservation=reservation)
        with pytest.raises(TransportFailure) as failure:
            _request(transport, action, route=route)
        assert failure.value.code == "gate_rejected" and transport.failure_code == "gate_rejected"
        assert (client.calls, budget.used, log.entries) == ([], 0, [])

    # The compiled pair is admitted, with the tolerant redactor substituted and the gate
    # wrapped: scope, then budget, then the executor's own gate, then the log entry.
    client = _RecordingClient()
    order: list[str] = []
    transport, budget, log = _scoped(
        client, reservation=reservation, authorize=lambda: order.append("authorize") or True,
    )
    assert _request(
        transport, _action(role="higher_plan"),
        before_attempt=lambda attempt, previous: order.append("executor") or "permit",
    ) == "response"
    (call,) = client.calls
    assert type(call["redactor"]) is plan_differential._TolerantRedactor
    assert (budget.used, log.entries, order) == (0, [], [])
    assert call["before_attempt"](1, None) == "permit"
    assert order == ["authorize", "executor"] and budget.used == 1
    assert log.entries == [("plan_differential_request", {
        "method": "GET", "route_template": "/api/export", "label": "pro",
        "role": "higher_plan", "attempt": "ab" * 16, "request_attempt": 1,
        "runner_run_id": "crun_test_00", "op_index": 0,
    })]
    # A transport cannot be built from anything but one compiled two-action pair.
    for manifest in (
        {"actions": []}, {"actions": _compiled().manifest["actions"][:1]},
        {"actions": [_compiled().manifest["actions"][0], _compiled("HEAD").manifest["actions"][1]]},
    ):
        with pytest.raises(Exception):
            plan_differential._ScopedTransport(
                client, compiled=types.SimpleNamespace(manifest=manifest),
                reservation=reservation, authorize=lambda: True,
                budget=plan_differential._Budget(2), log=_RecordingLog(), labels={},
                runner_run_id="crun_test_01", secrets=lambda: (),
            )

    # (e) Structure of the new module, by AST.
    tree = ast.parse(MODULE_SOURCE.read_text())
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node, kind):
        while node in parents:
            node = parents[node]
            if isinstance(node, kind):
                return node
        return None

    def assigned_from(function, name):
        """The call expressions a local name is assigned from inside one function."""
        return [
            item.value for item in ast.walk(function)
            if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call)
            and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)
        ]

    def callee(call):
        function = call.func
        return function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)

    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    request_calls = [call for call in calls if callee(call) == "request"]
    assert len(request_calls) == 1
    assert enclosing(request_calls[0], ast.ClassDef).name == "_ScopedTransport"
    assert ast.unparse(request_calls[0].func) == "self._client.request"

    execute_calls = [call for call in calls if callee(call) == "execute"]
    assert len(execute_calls) == 1
    transport_argument = {item.arg: item.value for item in execute_calls[0].keywords}["transport"]
    function = enclosing(execute_calls[0], ast.FunctionDef)
    assert isinstance(transport_argument, ast.Name)
    sources = assigned_from(function, transport_argument.id)
    assert [callee(source) for source in sources] == ["_ScopedTransport"]

    scoped_calls = [call for call in calls if callee(call) == "_ScopedTransport"]
    assert scoped_calls == sources
    compiled_argument = {item.arg: item.value for item in scoped_calls[0].keywords}["compiled"]
    assert isinstance(compiled_argument, ast.Name)
    assert [callee(source) for source in assigned_from(function, compiled_argument.id)] == [
        "compile_plan_differential_pair",
    ]

    assert [node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_build_client"] == ["_build_client"]
    references = [
        node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "_build_client"
    ]
    assert len(references) == 1 and isinstance(parents[references[0]], ast.Call)
    client_calls = [call for call in calls if callee(call) == "TargetHTTPSClient"]
    assert len(client_calls) == 1
    assert enclosing(client_calls[0], ast.FunctionDef).name == "_build_client"
    assert sorted(item.arg for item in client_calls[0].keywords) == ["origin", "preflight_addresses"]
    # The module mutates no object of another runner module.
    source = MODULE_SOURCE.read_text()
    for forbidden in ("ADAPTER_REGISTRY", "CATALOG[", "CATALOG_BY_ID[SCENARIO] =", "setattr("):
        assert forbidden not in source

    # (f) The CLI handler passes the artifact through untouched and has no route logic.
    cli_tree = ast.parse((ROOT / "heel/cli.py").read_text())
    (handler,) = [
        node for node in ast.walk(cli_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_runner_run"
    ]
    constants = {
        node.value for node in ast.walk(handler)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert constants.isdisjoint({"method", "route_template", "routes", "placeholders", "operation_id"})
    cli_parents = {
        child: node for node in ast.walk(handler) for child in ast.iter_child_nodes(node)
    }
    uses = [
        node for node in ast.walk(handler)
        if isinstance(node, ast.Name) and node.id == "artifact" and isinstance(node.ctx, ast.Load)
    ]
    kinds = sorted(type(cli_parents[use]).__name__ for use in uses)
    assert kinds == ["Compare", "keyword"]
    assert [
        cli_parents[use].arg for use in uses if isinstance(cli_parents[use], ast.keyword)
    ] == ["routes_artifact"]
    stores = [
        cli_parents[node] for node in ast.walk(handler)
        if isinstance(node, ast.Name) and node.id == "artifact" and isinstance(node.ctx, ast.Store)
    ]
    assert len(stores) == 1
    assert ast.unparse(stores[0].value) == (
        "None if args.routes is None else _load_bounded_openapi(args.routes)"
    )


# --------------------------------------------------------------------------- #
# I3 verified signed scope
# --------------------------------------------------------------------------- #
def test_i3_no_request_without_verified_signed_scope(tmp_path, monkeypatch):
    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        widened = journey.create_scope("other-staging.heel.dev")
        path = scope_path(journey.home, widened)
        body = json.loads(path.read_text())
        body["target_allowlist"].append(SYNTHETIC_HOST)
        path.write_text(json.dumps(body, indent=2))
        expired = scope_module.create_scope(
            [SYNTHETIC_HOST], "plan-differential-test", ttl_seconds=-60,
        ).scope_id
        unbound = scope_module.create_scope([SYNTHETIC_HOST], "").scope_id
        for scope_id in ("scope-0000000000", widened, expired, unbound, "", "../" + journey.scope_id,
                         journey.scope_id + ".json", journey.scope_id.upper()):
            for extra in ((), ("--dry-run",)):
                code, result, error = journey.run(*extra, scope=scope_id)
                assert (code, result, error) == (2, None, REJECTED), scope_id
        assert world.target.seen() == [] and world.factory.origins == []
        assert not (journey.home / "plan-runs").exists()

    # A scope file edited after the first pair stops the run before the next request.
    with World(tmp_path / "b", monkeypatch) as world:
        journey = world.journey

        def edit_after_first_pair(index: int) -> None:
            if index == 1:
                tamper_scope(journey)

        world.target.on_request = edit_after_first_pair
        code, result = run_result(world)
        assert world.target.seen() == [
            ("GET", "/api/billing", "free"), ("GET", "/api/billing", "pro"),
        ]
        assert result["requests_sent"] == 2
        assert all(pair["execution_disposition"] == "not_started" for pair in result["pairs"][1:])
        assert {pair["reason"] for pair in result["pairs"][1:]} == {"stopped"}
        assert len([item for item in result["not_executed"] if item["reason"] == "run_stopped"]) == 9
        # And the tampered scope starts nothing afterwards.
        code, after, error = journey.run()
        assert (code, after, error) == (2, None, REJECTED)
        assert len(world.target.seen()) == 2


# --------------------------------------------------------------------------- #
# I4 one-shot reserved attempt
# --------------------------------------------------------------------------- #
def test_i4_no_request_without_one_shot_reserved_attempt(tmp_path, monkeypatch):
    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        plans = [("free", journey.handles[0]), ("pro", journey.handles[1])]
        attempt = "c0" * 16

        # (a) An attempt ID is consumed by the exclusive mkdir and can never run again.
        journey.supply_credentials()
        first = plan_differential.run_plan_differential(
            journey.scope_id, journey.origin, plans, caller=CALLER, max_ops=4, attempt=attempt,
        )
        assert first["attempt_id"] == attempt and first["requests_sent"] == 4
        sent = len(world.target.seen())
        journey.supply_credentials()
        with pytest.raises(plan_differential.PlanDifferentialRejected):
            plan_differential.run_plan_differential(
                journey.scope_id, journey.origin, plans, caller=CALLER, max_ops=4, attempt=attempt,
            )
        # A directory left by a crashed attempt is consumed too.
        crashed = "c1" * 16
        (journey.home / "plan-runs" / crashed).mkdir()
        for bad in (crashed, "not-hex", "C0" * 16, "c0" * 15):
            with pytest.raises(plan_differential.PlanDifferentialRejected):
                plan_differential.run_plan_differential(
                    journey.scope_id, journey.origin, plans, caller=CALLER, attempt=bad,
                )
        assert len(world.target.seen()) == sent
        # The CLI exposes no attempt option.
        code, result, error = journey.run("--attempt", "c2" * 16)
        assert (code, result, error) == (2, None, REJECTED)
        with pytest.raises(plan_differential.PlanDifferentialRejected):
            plan_differential._AttemptReservation("c3" * 16, journey.home, object())

        # (b) No reservation, or a reservation whose directory is gone: refused, no connection.
        gone = plan_differential._reserve_attempt("c4" * 16)
        os.rmdir(gone.root)
        for reservation in (None, gone, "c5" * 16):
            client = _RecordingClient()
            transport, budget, log = _scoped(client, reservation=reservation)
            with pytest.raises(TransportFailure) as failure:
                _request(transport, _action())
            assert failure.value.code == "gate_rejected"
            assert (client.calls, budget.used, log.entries) == ([], 0, [])
        # A reservation that disappears between admission and the attempt is refused too.
        held = plan_differential._reserve_attempt("c6" * 16)
        client = _RecordingClient()
        transport, budget, log = _scoped(client, reservation=held)
        _request(transport, _action())
        os.rmdir(held.root)
        with pytest.raises(TransportFailure):
            client.calls[0]["before_attempt"](1, None)
        assert (budget.used, log.entries) == (0, [])
        assert len(world.target.seen()) == sent

    # (c) If the one-shot grant reservation fails, nothing is sent.
    with World(tmp_path / "b", monkeypatch) as world:
        def refuse(self, grant, **_keywords):
            raise RuntimeError("synthetic reservation failure")

        monkeypatch.setattr(RunnerStore, "reserve_run", refuse)
        code, result = run_result(world)
        assert world.target.seen() == [] and result["requests_sent"] == 0
        assert result["findings"] == []
        assert all(pair["execution_disposition"] != "completed" for pair in result["pairs"])
        monkeypatch.undo()

    # (d) A consumed grant cannot be executed twice.
    with World(tmp_path / "c", monkeypatch) as world:
        replays: list[object] = []

        class ReplayingExecutor(LocalCanaryExecutor):
            def execute(self, bundle, **keywords):
                result = super().execute(bundle, **keywords)
                try:
                    replays.append(super().execute(bundle, **keywords).execution_disposition)
                except Exception as error:  # the grant was already consumed
                    replays.append(error)
                return result

        monkeypatch.setattr(plan_differential, "LocalCanaryExecutor", ReplayingExecutor)
        code, result = run_result(world, "--max-ops", "4")
        assert len(replays) == 2 and all(isinstance(item, Exception) for item in replays)
        assert world.target.seen() == [
            ("GET", "/api/billing", "free"), ("GET", "/api/billing", "pro"),
            ("GET", "/api/echo", "free"), ("GET", "/api/echo", "pro"),
        ]
        assert result["requests_sent"] == 4


# --------------------------------------------------------------------------- #
# I5 secret exclusion
# --------------------------------------------------------------------------- #
def test_i5_credential_plaintext_absent_from_heel_home_and_output(tmp_path, monkeypatch):
    def outputs(world: World, run_id: str | None, *texts: str) -> None:
        collected = list(texts)
        if run_id is not None:
            for arguments in (("findings", "--run", run_id), ("log", "--run", run_id)):
                code, output, error = invoke(*arguments)
                collected += [output, error]
        collected.append(invoke("log", "--run", "security")[1])
        assert_no_credentials(world, *collected)

    def cli_run(world: World, *extra: str) -> tuple[int, dict | None, str, str]:
        world.journey.supply_credentials()
        code, output, error = invoke(*world.journey.arguments(*extra))
        return code, (json.loads(output) if output else None), output, error

    # Successful run: /api/echo returns the credential in a header and in the body, and
    # /api/pricing echoes it next to floats and negative integers.
    with World(tmp_path / "ok", monkeypatch, marker=MARKER) as world:
        code, result, output, error = cli_run(world)
        by_route = pairs_by_route(result)
        assert by_route[("GET", "/api/echo")]["execution_disposition"] == "completed"
        assert by_route[("GET", "/api/pricing")]["execution_disposition"] == "completed"
        outputs(world, result["run_id"], output, error)
        # The scan is not vacuous: evidence exists, and the replacement marker is in it.
        assert home_contains(world.journey.home, b"[REDACTED:secret]")
        assert home_contains(world.journey.home, b"tier_299")
        report = Path(result["report_path"]).read_text()
        assert MARKER not in report and MARKER not in output
        assert all(MARKER not in json.dumps(item) for item in world.journey.findings(result["run_id"]))

    # Credentials whose JSON-escaped form differs from their raw form.
    awkward = ('synthetic-free-"quoted"/\\-0001', 'synthetic-pro-"quoted"/\\-0001')
    with World(tmp_path / "escaped", monkeypatch, tokens=awkward) as world:
        code, result, output, error = cli_run(world)
        assert pairs_by_route(result)[("GET", "/api/echo")]["execution_disposition"] == "completed"
        assert {plan for _, _, plan in world.target.seen()} == {"free", "pro"}
        outputs(world, result["run_id"], output, error)

    # Transport failure on every connect.
    with World(tmp_path / "transport", monkeypatch, fail_connects=range(200)) as world:
        code, result, output, error = cli_run(world)
        assert world.target.seen() == [] and result["findings"] == []
        assert result["pairs"][0]["reason"] == "transport:connect_error"
        outputs(world, result["run_id"], output, error)

    # Run stopped by scope tamper.
    with World(tmp_path / "tamper", monkeypatch) as world:
        world.target.on_request = lambda index: tamper_scope(world.journey) if index == 2 else None
        code, result, output, error = cli_run(world)
        assert len(world.target.seen()) <= 4
        outputs(world, result["run_id"], output, error)

    # Missing higher-plan credential.
    with World(tmp_path / "missing", monkeypatch) as world:
        world.journey.supply_credentials(skip_higher=True)
        code, output, error = invoke(*world.journey.arguments())
        result = json.loads(output)
        assert world.target.seen() == [] and result["findings"] == []
        assert result["pairs"][0]["reason"] == "credential_unavailable"
        assert result["pairs"][0]["execution_disposition"] == "incomplete"
        outputs(world, result["run_id"], output, error)

    # A credential too short to redact reliably is refused before any request.
    with World(tmp_path / "short", monkeypatch, tokens=("short", PRO_TOKEN)) as world:
        code, result, output, error = cli_run(world)
        assert world.target.seen() == [] and result["findings"] == []
        assert result["pairs"][0]["reason"] == "credential_unavailable"
        assert home_contains(world.journey.home, PRO_TOKEN.encode()) == []

    # An exception in the middle of a run leaves a terminal run row and no credential bytes.
    with World(tmp_path / "crash", monkeypatch) as world:
        def explode(*_args, **_keywords):
            raise RuntimeError("synthetic fault " + FREE_TOKEN)

        monkeypatch.setattr(plan_differential, "_finding", explode)
        code, result, output, error = cli_run(world)
        assert (code, result, error) == (2, None, REJECTED)
        monkeypatch.undo()
        connection = sqlite3.connect(world.journey.home / "heel.db")
        try:
            runs = connection.execute("SELECT run_id, status FROM runs").fetchall()
            actions = [row[0] for row in connection.execute("SELECT action FROM containment")]
        finally:
            connection.close()
        assert len(runs) == 1 and runs[0][1] == "rejected"
        assert actions[0] == "run_start" and actions[-1] == "run_failed"
        outputs(world, runs[0][0], output, error)


# --------------------------------------------------------------------------- #
# I6 every request logged
# --------------------------------------------------------------------------- #
def test_i6_every_request_is_logged_before_it_is_sent(tmp_path, monkeypatch):
    # The first connect fails, forcing one retry of the first request.
    with World(tmp_path / "a", monkeypatch, fail_connects={0}) as world:
        journey = world.journey
        logged_at_arrival: list[list[dict]] = []

        def snapshot(_index: int) -> None:
            connection = sqlite3.connect(journey.home / "heel.db")
            try:
                rows = connection.execute(
                    "SELECT detail FROM containment WHERE action = 'plan_differential_request' "
                    "ORDER BY seq",
                ).fetchall()
            finally:
                connection.close()
            logged_at_arrival.append([json.loads(row[0]) for row in rows])

        world.target.on_request = snapshot
        code, result = run_result(world)
        logged = entries(journey, result["run_id"], "plan_differential_request")
        seen = world.target.seen()
        assert len(seen) == 18 and len(logged) == 19
        assert len(logged) == requests_started(journey, result) == result["requests_sent"]
        assert len(logged) >= len(seen)
        assert [item["detail"]["op_index"] for item in logged] == list(range(19))
        assert [item["detail"]["request_attempt"] for item in logged[:3]] == [1, 2, 1]
        assert {item["detail"]["attempt"] for item in logged} == {result["attempt_id"]}
        # Each request the target saw maps to a distinct entry appended before it arrived:
        # the newest entry at arrival is that request, and no two arrivals share one.
        labels = {"lower_plan": "free", "higher_plan": "pro"}
        matched = []
        for (method, path, plan), at_arrival in zip(seen, logged_at_arrival, strict=True):
            newest = at_arrival[-1]
            assert (newest["method"], newest["route_template"], labels[newest["role"]]) == (
                method, path, plan,
            )
            assert newest["label"] == plan
            matched.append(newest["op_index"])
        assert len(set(matched)) == len(seen) and matched == sorted(matched)
        run_ids = {pair["runner_run_ids"][0] for pair in result["pairs"]}
        assert {item["detail"]["runner_run_id"] for item in logged} <= run_ids

    # A failing append sends nothing.
    with World(tmp_path / "b", monkeypatch) as world:
        real_append = plan_differential._RunLog.append

        def failing(self, action, detail):
            if action == "plan_differential_request":
                raise OSError("synthetic log failure")
            return real_append(self, action, detail)

        monkeypatch.setattr(plan_differential._RunLog, "append", failing)
        code, result = run_result(world)
        assert world.target.seen() == [] and world.factory.sockets.addresses == []
        assert result["findings"] == []
        assert result["pairs"][0]["reason"] == "transport:gate_rejected"
        assert result["pairs"][0]["execution_disposition"] != "completed"


# --------------------------------------------------------------------------- #
# I7 caller attribution
# --------------------------------------------------------------------------- #
def test_i7_every_containment_entry_carries_cli_caller(tmp_path, monkeypatch):
    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        code, result = run_result(world)
        journey.run(scope=journey.create_scope("other-staging.heel.dev"))
        connection = sqlite3.connect(journey.home / "heel.db")
        try:
            rows = connection.execute("SELECT run_id, caller, action FROM containment").fetchall()
        finally:
            connection.close()
        assert {row[0] for row in rows} == {result["run_id"], "security"}
        assert {row[1] for row in rows} == {CALLER}
        assert {"run_start", "plan_differential_request", "plan_differential_pair", "finding",
                "run_complete", "reject_run"} == {row[2] for row in rows}
        assert all(row["caller"] == CALLER for row in journey.containment(result["run_id"])["entries"])

    # A caller that is not the CLI is refused before any state is touched.
    home = tmp_path / "untouched"
    monkeypatch.setenv("HEEL_HOME", str(home))
    plans = [("free", "a" * 32), ("pro", "b" * 32)]
    for caller in ("", "cli:", "mcp:agent", "rest:client", "CLI:user", None, 7, b"cli:user"):
        for function in (plan_differential.run_plan_differential, plan_differential.plan_differential):
            with pytest.raises(plan_differential.PlanDifferentialRejected):
                function("scope-0000000000", SYNTHETIC_ORIGIN, plans, caller=caller)
        with pytest.raises(plan_differential.PlanDifferentialRejected):
            plan_differential.replay_plan_differential(
                object(), {}, scope_id="scope-0000000000", target=SYNTHETIC_ORIGIN, caller=caller,
            )
    assert not home.exists()


# --------------------------------------------------------------------------- #
# I8 chain integrity
# --------------------------------------------------------------------------- #
def test_i8_containment_chains_verify_and_detect_tamper(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def chain(home: Path) -> bool:
        db = Store(str(home / "heel.db"))
        try:
            return verify_chain(db)[0]
        finally:
            db.close()

    # After a failure the chain still verifies.
    with World(tmp_path / "failed", monkeypatch, fail_connects=range(200)) as world:
        code, result = run_result(world)
        assert result["findings"] == [] and result["chain_valid"] is True
        assert chain(world.journey.home) is True
        assert world.journey.containment(result["run_id"])["chain_valid"] is True

    with World(tmp_path / "ok", monkeypatch) as world:
        journey = world.journey
        code, result = run_result(world)
        assert result["chain_valid"] is True and chain(journey.home) is True

        # The runner's signed chain verifies for each crun_ run, against the attempt store's
        # bound runner key, and a mutated event does not.
        store = attempt_store(journey, result)
        identity = store.load_binding()["identity"]
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(identity["public_key_b64"]))
        verified = 0
        for pair in result["pairs"]:
            (runner_run_id,) = pair["runner_run_ids"]
            assert runner_run_id.startswith("crun_" + result["attempt_id"])
            events = store.load_run_events(runner_run_id)
            keywords = dict(
                public_key=public_key, runner_key_id=identity["runner_key_id"],
                run_id=runner_run_id, grant_id=events[0]["grant_id"],
                manifest_digest=events[0]["manifest_digest"],
            )
            verify_containment_chain(events, **keywords)
            mutated = [dict(event) for event in events]
            mutated[-1]["counters"] = {**mutated[-1]["counters"], "requests_started": 0}
            with pytest.raises(Exception):
                verify_containment_chain(mutated, **keywords)
            with pytest.raises(Exception):
                verify_containment_chain(events[:-1] + events[-2:-1], **keywords)
            verified += 1
        assert verified == 10

        # Mutating one stored HMAC row is detected.
        connection = sqlite3.connect(journey.home / "heel.db")
        try:
            seq, detail = connection.execute(
                "SELECT seq, detail FROM containment WHERE action = 'plan_differential_request' "
                "ORDER BY seq LIMIT 1",
            ).fetchone()
            connection.execute(
                "UPDATE containment SET detail = ? WHERE seq = ?",
                (detail.replace('"free"', '"pro"'), seq),
            )
            connection.commit()
        finally:
            connection.close()
        assert chain(journey.home) is False
        assert journey.containment(result["run_id"])["chain_valid"] is False


# --------------------------------------------------------------------------- #
# R9 total request budget
# --------------------------------------------------------------------------- #
def test_r9_max_ops_hard_caps_total_requests(tmp_path, monkeypatch):
    # Retries forced on the first and third connects; max_ops=5.
    with World(tmp_path / "a", monkeypatch, fail_connects={0, 3}) as world:
        code, result = run_result(world, "--max-ops", "5")
        assert result["effective_max_ops"] == 5
        assert len(world.target.seen()) <= 5 and len(world.factory.sockets.addresses) <= 5
        assert result["requests_sent"] <= 5
        assert len(entries(world.journey, result["run_id"], "plan_differential_request")) <= 5
        # Two pairs were planned (5 // 2); the rest never left planning.
        assert len(result["pairs"]) == 2
        assert [item["reason"] for item in result["not_executed"]].count("over_budget") == 8

        for bad in ("1", "0", "101", "-2", "5.0", "five", "", " 5", "0x10", "٥"):
            for extra in ((), ("--dry-run",)):
                code, rejected, error = world.journey.run("--max-ops", bad, *extra)
                assert (code, rejected, error) == (2, None, REJECTED), bad

    # A retry that would exceed the cap is refused by the invocation-wide counter.
    with World(tmp_path / "b2", monkeypatch, fail_connects={0}) as world:
        code, result = run_result(world, "--max-ops", "2")
        assert len(world.factory.sockets.addresses) == 2 == result["requests_sent"]
        assert world.target.seen() == [("GET", "/api/billing", "free")]
        (only,) = result["pairs"]
        assert (only["reason"], only["execution_disposition"], only["finding_id"]) == (
            "budget_exhausted", "incomplete", None,
        )
    # One retry leaves a single op: the next pair needs two and is not started.
    with World(tmp_path / "b", monkeypatch, fail_connects={0}) as world:
        code, result = run_result(world, "--max-ops", "4")
        assert len(world.factory.sockets.addresses) == 3 == result["requests_sent"]
        assert len(world.target.seen()) == 2
        second = result["pairs"][1]
        assert (second["reason"], second["execution_disposition"]) == ("budget_exhausted", "not_started")
        assert {"method": "GET", "route_template": "/api/echo", "reason": "budget_exhausted"} in result["not_executed"]

    # A lower scope max_requests wins over --max-ops.
    limits = {"max_requests": 4, "max_concurrency": 1, "backoff": True}
    with World(tmp_path / "c", monkeypatch, limits=limits) as world:
        code, plan, error = world.journey.run("--dry-run", "--max-ops", "50")
        assert (plan["max_ops"], plan["effective_max_ops"], plan["requests_planned"]) == (50, 4, 4)
        code, result = run_result(world, "--max-ops", "50")
        assert result["effective_max_ops"] == 4 and len(world.target.seen()) == 4
    with World(tmp_path / "d", monkeypatch, limits={"max_requests": 2}) as world:
        code, result = run_result(world)
        assert len(world.target.seen()) == 2
        # The scope's run count is now at its limit: the next invocation is rejected.
        code, _ = run_result(world)
        code, rejected, error = world.journey.run()
        assert (code, rejected, error) == (2, None, REJECTED)
        assert len(world.target.seen()) == 4

    # The ceiling: 50 pairs, 100 requests, 50 reserved runs in one attempt store.
    fixture = bulk_openapi(tmp_path / "bulk.json", 60)
    with World(tmp_path / "e", monkeypatch, fixture=fixture) as world:
        code, result = run_result(world, "--max-ops", "100")
        assert result["requests_sent"] == 100 == len(world.target.seen())
        assert len(result["pairs"]) == 50
        assert {pair["execution_disposition"] for pair in result["pairs"]} == {"completed"}
        # Each lower read is a 403 error envelope: undecided, never held.
        assert {(pair["verdict"], pair["reason"]) for pair in result["pairs"]} == {
            ("inconclusive", "lower_denial_envelope"),
        }
        assert [item["reason"] for item in result["not_executed"]] == ["over_budget"] * 10
        assert result["chain_valid"] is True


# --------------------------------------------------------------------------- #
# R10, R12, R13
# --------------------------------------------------------------------------- #
def test_r10_no_mcp_or_rest_entry():
    assert mcp_server.TOOL_NAMES == {
        "heel_cloud_projects", "heel_cloud_reviews", "heel_cloud_status",
        "heel_execute_reference", "heel_explain_finding", "heel_export_review",
        "heel_get_containment_log", "heel_get_coverage", "heel_get_findings",
        "heel_get_review", "heel_list_reviews", "heel_list_scenarios", "heel_list_scopes",
        "heel_prepare_reference", "heel_propose_control", "heel_review_openapi", "heel_run",
        "heel_run_status", "heel_status", "heel_sync_prepare", "heel_sync_preview",
        "heel_sync_receipt", "heel_sync_status",
    }
    for name in ("mcp_server.py", "rest.py"):
        source = (ROOT / "heel" / name).read_text()
        for needle in ("plan_differential", "plan-differential", "run_plan", "runner run"):
            assert needle not in source, (name, needle)
    assert not any("differential" in name for name in mcp_server.TOOL_NAMES)


def _scope_snapshot(home: Path) -> dict[str, tuple[bytes, int, int]]:
    directory = home / "scopes"
    return {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        for path in sorted(directory.iterdir())
    }


def test_r12_scope_files_are_never_written(tmp_path, monkeypatch):
    snapshots: list[dict] = []
    with World(
        tmp_path, monkeypatch, on_scope=lambda journey: snapshots.append(_scope_snapshot(journey.home)),
    ) as world:
        journey = world.journey
        before = snapshots[0]
        assert list(before) == [journey.scope_id + ".json"]
        assert _scope_snapshot(journey.home) == before          # bootstrap, credentials, import
        journey.run("--dry-run")
        assert _scope_snapshot(journey.home) == before          # dry-run
        code, result = run_result(world)
        assert _scope_snapshot(journey.home) == before          # run
        world.factory.sockets.fail_connects = frozenset(range(1000))
        code, failed = run_result(world)
        assert failed["findings"] == []
        assert _scope_snapshot(journey.home) == before          # failed run
        world.factory.sockets.fail_connects = frozenset()
        (finding,) = [item for item in result["findings"] if item["route_template"] == "/api/export"
                      and item["method"] == "GET"]
        assert invoke("regress", "add", "--run", result["run_id"], "--vector", finding["id"],
                      "--name", "export-gate")[0] == 0
        journey.supply_credentials()
        code, output, _ = invoke("regress", "run", "--target", journey.origin, "--scope", journey.scope_id)
        assert code == 0 and json.loads(output)["results"][0]["run_id"]
        assert _scope_snapshot(journey.home) == before          # replay
        # A forced dry-run and a rejection write no scope either.
        journey.run(origin="https://other-staging.heel.dev")
        journey.run(scope="scope-0000000000")
        assert _scope_snapshot(journey.home) == before

    tree = ast.parse(MODULE_SOURCE.read_text())
    imported = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert "create_scope" not in imported and "create_scope" not in MODULE_SOURCE.read_text()
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert names.isdisjoint({"create_scope", "_sign", "hmac_sign", "_signing_key"})


def test_r13_dry_run_sends_nothing(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch, seam=False, marker=MARKER) as world:
        journey = world.journey
        attempts = no_network(monkeypatch)
        resolver_calls: list[str] = []
        monkeypatch.setattr(
            http_transport.BoundedResolver, "__call__",
            lambda self, hostname, *, deadline: resolver_calls.append(hostname) or [PUBLIC_ADDRESS],
        )
        code, plan, error = journey.run("--dry-run")
        assert (code, error) == (0, "")
        assert plan["mode"] == "dry_run" and plan["authorized"] is True
        assert plan["requests_sent"] == 0 and plan["requests_planned"] == 22 == 2 * len(plan["pairs"])
        assert all(pair["requests"] == 2 for pair in plan["pairs"])
        assert plan["context"] == "already_bound" and len(plan["plan_sha256"]) == 64
        assert attempts == [] and resolver_calls == []
        assert world.target.seen() == [] and world.second.seen() == []
        assert not (journey.home / "plan-runs").exists()
        # No credential variable was consumed and none was read into the output.
        for handle, token in zip(journey.handles, journey.tokens, strict=True):
            assert os.environ["HEEL_RUNNER_CREDENTIAL_" + handle.upper()] == token
            assert token not in json.dumps(plan)
        # The dry-run started no run and logged no request.
        connection = sqlite3.connect(journey.home / "heel.db")
        try:
            assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
            assert connection.execute("SELECT COUNT(*) FROM containment").fetchone()[0] == 0
        finally:
            connection.close()
        # The bootstrap dry-run took no identity and planned nothing.
        assert journey.bootstrap["context"] == "bound"
        assert (journey.bootstrap["plans"], journey.bootstrap["pairs"]) == ([], [])


# --------------------------------------------------------------------------- #
# R17 exactly two requests per route
# --------------------------------------------------------------------------- #
def test_r17_every_route_sends_exactly_one_request_per_plan_credential(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch, marker=MARKER) as world:
        code, result = run_result(world)
        seen = world.target.seen()
        completed = [pair for pair in result["pairs"] if pair["execution_disposition"] == "completed"]
        assert len(completed) == 9
        for pair in completed:
            path = pair["route_template"].replace("{id}", MARKER)
            on_route = [item for item in seen if (item[0], item[1]) == (pair["method"], path)]
            # Exactly two, lower credential first, then higher.
            assert [plan for _, _, plan in on_route] == ["free", "pro"], pair
        # Refused first responses stop the pair: one request, never an anonymous second one.
        for method, route in REFUSED:
            assert [item for item in seen if item[:2] == (method, route)] == [(method, route, "free")]
        # Across the run nothing was sent without one of the two plan credentials.
        assert {plan for _, _, plan in seen} == {"free", "pro"}
        assert len(seen) == result["requests_sent"] == 2 * len(completed) + len(REFUSED)
        assert all(len(pair["runner_run_ids"]) == 1 for pair in result["pairs"])


def test_r17_head_pair_is_two_head_requests_and_no_anonymous_request(tmp_path, monkeypatch):
    assert CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"] == ("GET", "HEAD")
    assert CATALOG_BY_ID["plan_entitlement_read"]["semantic_roles"] == ("lower_plan", "higher_plan")
    assert "anonymous_authenticated_read" not in MODULE_SOURCE.read_text()

    for behavior, verdict, reason in (
        ("vulnerable", "inconclusive", "head_status_only"), ("hardened", "held", "lower_denied"),
    ):
        with World(tmp_path / behavior, monkeypatch, behavior=behavior) as world:
            journey = world.journey
            sent_before: list[int] = []
            original = plan_differential._run_pair

            def counting(plan, pair, ordinal, **keywords):
                sent_before.append(keywords["budget"].used)
                return original(plan, pair, ordinal, **keywords)

            monkeypatch.setattr(plan_differential, "_run_pair", counting)
            code, result = run_result(world)
            monkeypatch.setattr(plan_differential, "_run_pair", original)

            head = pairs_by_route(result)[("HEAD", "/api/export")]
            assert (head["verdict"], head["reason"], head["execution_disposition"]) == (
                verdict, reason, "completed",
            )
            # Never skipped, and never anything but held or inconclusive.
            assert ("HEAD", "/api/export") not in {
                (item["method"], item["route_template"]) for item in result["not_executed"]
            }
            seen = world.target.seen()
            assert [item for item in seen if item[0] == "HEAD"] == [
                ("HEAD", "/api/export", "free"), ("HEAD", "/api/export", "pro"),
            ]
            assert not [item for item in seen if item[2] in {"none", "unknown"}]
            assert len(head["runner_run_ids"]) == 1
            logged = [
                item["detail"] for item in entries(journey, result["run_id"], "plan_differential_request")
                if item["detail"]["method"] == "HEAD"
            ]
            assert [(item["role"], item["label"], item["route_template"]) for item in logged] == [
                ("lower_plan", "free", "/api/export"), ("higher_plan", "pro", "/api/export"),
            ]
            assert {item["runner_run_id"] for item in logged} == set(head["runner_run_ids"])
            # requests_sent grows by exactly 2 across the HEAD pair.
            ordinal = [(pair["method"], pair["route_template"]) for pair in result["pairs"]].index(
                ("HEAD", "/api/export"),
            )
            assert sent_before[ordinal + 1] - sent_before[ordinal] == 2
            # No attempt store holds an anonymous or authenticated credential record.
            roles = sorted(item["semantic_role"] for item in attempt_store(journey, result).list_credentials())
            assert roles == ["higher_plan", "lower_plan"]
            finding_states = {
                item["method"]: item["evidence_state"] for item in result["findings"]
                if item["route_template"] == "/api/export"
            }
            assert finding_states.get("HEAD") in {None, "inconclusive"}


# --------------------------------------------------------------------------- #
# R21 production client
# --------------------------------------------------------------------------- #
def test_r21_production_client_construction_is_unseamed(tmp_path, monkeypatch):
    assert list(inspect.signature(plan_differential._build_client).parameters) == ["origin"]
    lookups: list[tuple] = []

    def lookup(host, port, *args, **keywords):
        lookups.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *args, **keywords: (_ for _ in ()).throw(AssertionError("no handshake here")),
    )
    client = plan_differential._build_client(SYNTHETIC_ORIGIN)
    assert lookups and {host.rstrip(".") for host, _ in lookups} == {SYNTHETIC_HOST}
    assert type(client) is http_transport.TargetHTTPSClient
    assert type(client.resolver) is http_transport.BoundedResolver
    assert type(client.sockets) is http_transport.SocketTransport
    assert type(client.tls) is TLSTransport
    context = client.tls.context
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert client.origin == SYNTHETIC_ORIGIN

    # A private or loopback answer is refused at preflight; no client is built.
    for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.10"):
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda host, port, *args, _address=address, **keywords: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_address, port or 443)),
            ],
        )
        with pytest.raises(TransportFailure):
            plan_differential._build_client(SYNTHETIC_ORIGIN)


def test_r21_tls_transport_real_handshake_verifies_chain_and_hostname(tmp_path):
    ca, certificate, key = make_test_ca(SYNTHETIC_HOST)
    other_ca, _, _ = make_test_ca("unrelated.heel.dev")

    def handshake(server, hostname: str, authority: bytes | None):
        transport = TLSTransport()
        if authority is not None:
            transport.context.load_verify_locations(cadata=authority.decode("ascii"))
        raw = socket.create_connection(("127.0.0.1", server.port), 5)
        try:
            wrapped = transport.wrap(raw, hostname, 5)
            try:
                return wrapped.version(), wrapped.recv(1)
            finally:
                wrapped.close()
        finally:
            raw.close()

    with TLSLoopbackServer(tmp_path, certificate, key) as server:
        # A real handshake: matching chain and hostname are accepted at the highest
        # common version (TLS 1.2 or newer; see the protocol-bounds test below).
        assert handshake(server, SYNTHETIC_HOST, ca)[1] == b"k"
        # A wrong hostname is rejected.
        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(server, "wrong-host.heel.dev", ca)
        # An untrusted issuer is rejected: another CA, and the default trust store alone.
        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(server, SYNTHETIC_HOST, other_ca)
        if not any(
            "Heel plan-differential test CA" in json.dumps(item)
            for item in TLSTransport().context.get_ca_certs()
        ):
            with pytest.raises(ssl.SSLCertVerificationError):
                handshake(server, SYNTHETIC_HOST, None)


def _default_trust_handshake(transport_class, server, hostname: str):
    """Connect to the loopback server and wrap with a freshly constructed production transport."""
    raw = socket.create_connection(("127.0.0.1", server.port), 5)
    try:
        wrapped = transport_class().wrap(raw, hostname, 5)
        try:
            return wrapped.version(), wrapped.recv(1)
        finally:
            wrapped.close()
    finally:
        raw.close()


@pytest.mark.parametrize("transport_class", [TLSTransport, NetworkTLSTransport])
def test_r21_tls_transports_negotiate_tls12_and_tls13_through_default_trust(
    tmp_path, monkeypatch, transport_class,
):
    if ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE":
        pytest.skip("this TLS library does not read SSL_CERT_FILE")
    ca, certificate, key = make_test_ca(SYNTHETIC_HOST)
    other_ca, _, _ = make_test_ca("unrelated.heel.dev")
    ca_file, other_file = tmp_path / "test-ca.pem", tmp_path / "other-ca.pem"
    ca_file.write_bytes(ca)
    other_file.write_bytes(other_ca)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    v12, v13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3
    # The availability flags are not consulted: OpenSSL 4 builds report HAS_TLSv1_2 False
    # yet negotiate TLS 1.2 through the generic client method.
    for bounds, expected in (((v12, v12), "TLSv1.2"), ((v13, None), "TLSv1.3"), ((None, None), "TLSv1.3")):
        with TLSLoopbackServer(tmp_path, certificate, key, minimum=bounds[0], maximum=bounds[1]) as server:
            assert _default_trust_handshake(transport_class, server, SYNTHETIC_HOST) == (expected, b"k")
            assert server.handshakes == 1
            # Wrong hostname on the same chain is rejected; no byte is exchanged.
            with pytest.raises(ssl.SSLCertVerificationError):
                _default_trust_handshake(transport_class, server, "wrong-host.heel.dev")
            assert server.handshakes == 1
    with TLSLoopbackServer(tmp_path, certificate, key) as server:
        # Another CA in the default location, or no test CA at all, is rejected.
        monkeypatch.setenv("SSL_CERT_FILE", str(other_file))
        with pytest.raises(ssl.SSLCertVerificationError):
            _default_trust_handshake(transport_class, server, SYNTHETIC_HOST)
        monkeypatch.delenv("SSL_CERT_FILE")
        with pytest.raises(ssl.SSLCertVerificationError):
            _default_trust_handshake(transport_class, server, SYNTHETIC_HOST)
        assert server.handshakes == 0


@pytest.mark.parametrize("transport_class", [TLSTransport, NetworkTLSTransport])
def test_r21_tls_transports_refuse_a_legacy_only_server(tmp_path, monkeypatch, transport_class):
    if ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE":
        pytest.skip("this TLS library does not read SSL_CERT_FILE")
    ca, certificate, key = make_test_ca(SYNTHETIC_HOST)
    ca_file = tmp_path / "test-ca.pem"
    ca_file.write_bytes(ca)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    legacy = {
        "minimum": ssl.TLSVersion.TLSv1, "maximum": ssl.TLSVersion.TLSv1_1,
        "ciphers": "DEFAULT:@SECLEVEL=0",
    }
    try:
        server = TLSLoopbackServer(tmp_path, certificate, key, **legacy)
    except (ssl.SSLError, ValueError) as exc:
        pytest.skip(f"this build cannot host a TLS 1.0/1.1 server: {exc!r}")
    with server:
        # Control: a deliberately permissive test client proves the fixture really speaks
        # TLS 1.0/1.1 here; otherwise a refusal would prove nothing about the transport.
        permissive = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            permissive.set_ciphers("DEFAULT:@SECLEVEL=0")
            permissive.minimum_version = ssl.TLSVersion.TLSv1
            permissive.load_verify_locations(cadata=ca.decode("ascii"))
            raw = socket.create_connection(("127.0.0.1", server.port), 5)
            try:
                with permissive.wrap_socket(raw, server_hostname=SYNTHETIC_HOST) as control:
                    control_version = control.version()
            finally:
                raw.close()
        except (ssl.SSLError, ValueError, OSError) as exc:
            pytest.skip(f"this build cannot complete a TLS 1.0/1.1 handshake: {exc!r}")
        assert control_version in {"TLSv1", "TLSv1.1"} and server.handshakes == 1
        with pytest.raises(ssl.SSLError):
            _default_trust_handshake(transport_class, server, SYNTHETIC_HOST)
        assert server.handshakes == 1


# --------------------------------------------------------------------------- #
# R22 finding eligibility
# --------------------------------------------------------------------------- #
def test_r22_findings_only_for_completed_pairs_and_disposition_is_completed(tmp_path, monkeypatch):
    def check(world: World, result: dict) -> dict:
        journey = world.journey
        stored = {item["id"]: item for item in journey.findings(result["run_id"])}
        report = json.loads(Path(result["report_path"]).read_text())
        assert report["pairs"] == result["pairs"] and report["not_executed"] == result["not_executed"]
        assert report["uploaded"] is False
        assert sorted(stored) == sorted(item["id"] for item in result["findings"])
        for finding in stored.values():
            reproduction = finding["reproduction"]
            assert reproduction["execution_disposition"] == "completed"
            assert reproduction["evidence_state"] in {"verified", "observed"}
            assert reproduction["candidate"] is (reproduction["predicate"] == "status_parity")
            assert finding["scenario_id"] == "plan_differential." + reproduction["predicate"]
            assert reproduction["operator_declared"] is False
        with_finding = set()
        for pair in result["pairs"]:
            completed = pair["execution_disposition"] == "completed"
            # Stored: a completed finding only. Held and every inconclusive pair store nothing.
            eligible = completed and pair["verdict"] == "finding"
            assert (pair["finding_id"] is not None) is eligible, pair
            if eligible:
                with_finding.add(pair["finding_id"])
            if not completed:
                assert (pair["verdict"], pair["predicate"], pair["candidate"]) == (
                    "inconclusive", "inconclusive", False,
                )
            assert pair["candidate"] is (pair["verdict"] != "held" and pair["predicate"] == "status_parity")
        assert with_finding == set(stored)
        logged = entries(journey, result["run_id"], "plan_differential_pair")
        assert [
            (item["detail"]["method"], item["detail"]["route_template"],
             item["detail"]["execution_disposition"], item["detail"]["reason"])
            for item in logged
        ] == [
            (pair["method"], pair["route_template"], pair["execution_disposition"], pair["reason"])
            for pair in result["pairs"]
        ]
        return pairs_by_route(result)

    # Completed pairs, a refused body, a redirect and a held pair in one run.
    with World(tmp_path / "mixed", monkeypatch, marker=MARKER) as world:
        code, result = run_result(world)
        assert code == 1
        by_route = check(world, result)
        for route in REFUSED:
            assert (by_route[route]["execution_disposition"], by_route[route]["reason"]) == (
                "failed", "transport:response_rejected",
            )
        # A 403 error envelope keeps its pair but is undecided and stores no finding.
        denied = by_route[("GET", "/api/reports")]
        assert (denied["verdict"], denied["finding_id"], denied["reason"]) == (
            "inconclusive", None, "lower_denial_envelope",
        )
        states = {item["route_template"] + " " + item["method"]: item["evidence_state"]
                  for item in result["findings"]}
        assert states["/api/export GET"] == "observed"
        assert states["/exports/{id} GET"] == "verified"
        # Status parity alone (HEAD) and a 2xx lower denial envelope keep their pair but no
        # finding.
        assert "/api/export HEAD" not in states and "/api/billing GET" not in states
        assert (by_route[("HEAD", "/api/export")]["predicate"],
                by_route[("HEAD", "/api/export")]["reason"]) == ("status_parity", "head_status_only")
        assert by_route[("GET", "/api/billing")]["reason"] == "lower_denial_envelope"

    # A scope-tamper stop: the later pairs are inconclusive, not started, and unstored.
    with World(tmp_path / "tamper", monkeypatch) as world:
        world.target.on_request = lambda index: tamper_scope(world.journey) if index == 1 else None
        code, result = run_result(world)
        check(world, result)
        assert {pair["reason"] for pair in result["pairs"][1:]} == {"stopped"}
        assert len(result["findings"]) <= 1

    # Budget exhaustion in the middle of a run.
    with World(tmp_path / "budget", monkeypatch, fail_connects={0}) as world:
        code, result = run_result(world, "--max-ops", "4")
        check(world, result)
        assert result["pairs"][1]["reason"] == "budget_exhausted"

    # The closed reason lists.
    row_one = {"stopped", "budget_exhausted", "credential_unavailable", "executor_rejected",
               "evidence_unavailable"}
    with World(tmp_path / "closed", monkeypatch, fail_connects={5}, change_after=9) as world:
        code, result = run_result(world)
        check(world, result)
        for pair in result["pairs"]:
            if pair["execution_disposition"] != "completed":
                assert pair["reason"] in row_one or pair["reason"].startswith(("transport:", "executor:"))
        assert {item["reason"] for item in result["not_executed"]} <= {
            "unbound_placeholder", "over_budget", "budget_exhausted", "run_stopped",
        }


# --------------------------------------------------------------------------- #
# R23 CA trust boundary
# --------------------------------------------------------------------------- #
def test_r23_ca_trust_follows_openssl_default_locations(tmp_path, monkeypatch):
    if ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE":
        pytest.skip("this TLS library does not read SSL_CERT_FILE")
    ca, _, _ = make_test_ca()
    ca_file = tmp_path / "test-ca.pem"
    ca_file.write_bytes(ca)
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *args, **keywords: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port or 443)),
        ],
    )

    def trusted_test_ca() -> bool:
        context = plan_differential._build_client(SYNTHETIC_ORIGIN).tls.context
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        return any(
            (("commonName", "Heel plan-differential test CA"),) in item["subject"]
            for item in context.get_ca_certs()
        )

    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    assert trusted_test_ca() is False
    # The variable IS honoured: the operator's environment chooses the trust anchors.
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    assert trusted_test_ca() is True
    monkeypatch.delenv("SSL_CERT_FILE")
    assert trusted_test_ca() is False

    documentation = (ROOT / "docs/PLAN_DIFFERENTIAL_RUNNER.md").read_text()
    normalized = " ".join(documentation.split())
    for statement in (
        "`SSL_CERT_FILE`", "`SSL_CERT_DIR`",
        "The operator's process environment and `HEEL_HOME` are inside the trust boundary",
        "Heel does not defend against that",
        "no Heel argument, Heel variable, inventory file or scope field changes the transport, "
        "resolver, port or trust store",
        "certificate and hostname verification are always on",
    ):
        assert statement in normalized, statement


# --------------------------------------------------------------------------- #
# R25 numeric JSON
# --------------------------------------------------------------------------- #
def test_r25_numeric_json_bodies_complete_and_do_not_end_the_run(tmp_path, monkeypatch):
    # The inherited redaction count refuses this body; that is the failure being fixed.
    body = json.dumps(pricing(FREE_TOKEN)).encode()
    with pytest.raises((TypeError, ValueError)):
        Redactor((FREE_TOKEN,)).count_bytes(b"Content-Type: application/json", body)
    assert pricing(FREE_TOKEN)["big"] > 2 ** 53 and len(pricing(FREE_TOKEN)["tiers"]) == 300

    with World(tmp_path, monkeypatch) as world:
        code, result = run_result(world)
        assert code == 1
        routes = [(pair["method"], pair["route_template"]) for pair in result["pairs"]]
        assert routes == PLANNED
        by_route = pairs_by_route(result)
        numeric = by_route[("GET", "/api/pricing")]
        assert (numeric["execution_disposition"], numeric["verdict"], numeric["predicate"]) == (
            "completed", "finding", "body_superset",
        )
        (finding,) = [item for item in world.journey.findings(result["run_id"])
                      if item["id"] == numeric["finding_id"]]
        assert finding["reproduction"]["evidence_state"] == "observed"
        assert all(pair["reason"] != "transport:evidence_rejected" for pair in result["pairs"])
        # Pairs after it in canonical order ran.
        after = result["pairs"][routes.index(("GET", "/api/pricing")) + 1:]
        assert len(after) == 4
        assert all(pair["execution_disposition"] in {"completed", "failed"} for pair in after)
        assert by_route[("GET", "/api/reports")]["verdict"] == "inconclusive"
        assert ("GET", "/api/summary", "pro") in world.target.seen()
        assert_no_credentials(world, json.dumps(result))
        # The stored evidence is the numeric body, with the echoed credential replaced.
        assert home_contains(world.journey.home, b'"price": 1.5')
        assert home_contains(world.journey.home, b'"delta": -3')
        assert home_contains(world.journey.home, str(2 ** 60).encode())


def test_r25_tolerant_redactor_matches_base_when_base_succeeds():
    secrets = (FREE_TOKEN, PRO_TOKEN)
    base, tolerant = Redactor(secrets), plan_differential._TolerantRedactor(secrets)
    headers = b"Content-Type: application/json\r\nX-Echo: " + FREE_TOKEN.encode()
    accepted = (
        (b"{}",), (b"",), (headers, b'{"a": 1, "b": "text"}'),
        (headers, json.dumps({"echo": FREE_TOKEN, "token": "x", "n": 3}).encode()),
        (b"plain text " + PRO_TOKEN.encode(),), (b'{"list": [1, 2, {"password": "p"}]}',),
        (b"Authorization: Bearer abc.def.ghi", b'{"k": "sk_live_abcdefghijklmnop"}'),
    )
    for chunks in accepted:
        assert tolerant.count_bytes(*chunks) == base.count_bytes(*chunks)

    # Bodies the base refuses complete, counting exactly the registered secrets.
    numeric = json.dumps(pricing(FREE_TOKEN)).encode()
    for refused in ((b'{"price": 1.5}',), (b'{"n": -3}',), (b'{"big": %d}' % 2 ** 60,), (numeric,)):
        with pytest.raises((TypeError, ValueError)):
            base.count_bytes(*refused)
        assert tolerant.count_bytes(*refused) == sum(chunk.count(FREE_TOKEN.encode()) for chunk in refused)
    assert tolerant.count_bytes(headers, numeric) == 2
    escaped = plan_differential._TolerantRedactor(('needs"escape\\secret',))
    assert escaped.count_bytes(b'{"f": 1.5, "echo": "needs\\"escape\\\\secret"}') == 1
    assert tolerant.count_bytes(b'{"f": 0.5}' + (FREE_TOKEN.encode() + b" ") * 2000) == 1024

    # The inherited argument rules still raise, as the base does.
    for bad in ((), ("text",), (b"{}", "text"), (bytearray(b"{}"),), (b"x" * (256 * 1024 + 1),),
                (b'{"f": 1.5}', b"x" * (256 * 1024 + 1)), (b'{"f": 1.5}', None)):
        with pytest.raises((TypeError, ValueError)) as base_error:
            base.count_bytes(*bad)
        with pytest.raises(type(base_error.value)):
            tolerant.count_bytes(*bad)
    # It is a Redactor (the transport requires one) and overrides only the count.
    assert isinstance(tolerant, Redactor)
    overridden = {
        name for name in vars(plan_differential._TolerantRedactor)
        if name in vars(Redactor) and not name.startswith("__")
    }
    assert overridden == {"count_bytes"}
    assert tolerant.redact("Bearer abc.def.ghi") == base.redact("Bearer abc.def.ghi")
