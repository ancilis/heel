"""Public CLI behavior of ``heel runner run``: R14-R16, R18-R20 and R24.

Requests go only to the loopback synthetic target through the one disclosed seam.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time

from heel.runner import http_transport, plan_differential

from plan_differential_support import (
    FIXTURE,
    FREE_TOKEN,
    MARKER,
    PRO_TOKEN,
    PUBLIC_ADDRESS,
    SYNTHETIC_HOST,
    SYNTHETIC_ORIGIN,
    World,
    home_contains,
    invoke,
    pairs_by_route,
)


ROOT = Path(__file__).resolve().parents[1]
REJECTED = "Heel runner command was rejected.\n"
EXPORT = ("GET", "/api/export")


def finding_for(result: dict, route: tuple[str, str] = EXPORT) -> dict:
    (finding,) = [
        item for item in result["findings"] if (item["method"], item["route_template"]) == route
    ]
    return finding


def add_regression(world: World, result: dict, name: str, route: tuple[str, str] = EXPORT) -> dict:
    code, output, error = invoke(
        "regress", "add", "--run", result["run_id"], "--vector", finding_for(result, route)["id"],
        "--name", name,
    )
    assert code == 0, (output, error)
    return json.loads(output)["regression"]


def regress(world: World, *, target: str | None = None, scope: str | None = None) -> list[dict]:
    world.journey.supply_credentials()
    code, output, error = invoke(
        "regress", "run", "--target", target or world.journey.origin,
        "--scope", scope or world.journey.scope_id,
    )
    assert code == 0, (output, error)
    return json.loads(output)["results"]


def inventory_file(world: World) -> Path:
    return Path(world.journey.bootstrap["inventory"]["path"])


def assert_unstored_with_evidence(
    world: World, result: dict, reason: str, route: tuple[str, str] = EXPORT,
) -> None:
    """An undecided pair stores no finding, yet keeps its report, raw-evidence references
    and containment entry."""
    pair = pairs_by_route(result)[route]
    assert (pair["verdict"], pair["reason"], pair["finding_id"]) == ("inconclusive", reason, None)
    assert pair["execution_disposition"] == "completed"
    assert all(
        (item["method"], item["route_template"]) != route for item in result["findings"]
    )
    assert all(
        item["affordance_id"] != " ".join(route)
        for item in world.journey.findings(result["run_id"])
    )
    # Every stored finding of the run is a completed verified or observed finding.
    assert all(
        item["evidence_state"] in {"verified", "observed"} for item in result["findings"]
    )
    assert all(
        item["reproduction"]["evidence_state"] in {"verified", "observed"}
        for item in world.journey.findings(result["run_id"])
    )
    report = json.loads(Path(result["report_path"]).read_text())
    (observed,) = [
        item for item in report["observations"]
        if (item["method"], item["route_template"]) == route
    ]
    assert [item["role"] for item in observed["observations"]] == ["lower_plan", "higher_plan"]
    assert all(item["response_ref"] for item in observed["observations"])
    # The raw responses stay in the private attempt store.
    for item in observed["observations"]:
        assert len(list(world.journey.home.rglob(item["response_ref"] + ".meta"))) == 1
    assert report["uploaded"] is False
    code, output, _ = invoke("log", "--run", result["run_id"])
    log = json.loads(output)
    assert code == 0 and log["chain_valid"] is True
    logged = [
        json.loads(entry["detail"]) for entry in log["entries"]
        if entry["action"] == "plan_differential_pair"
    ]
    assert [
        item["reason"] for item in logged
        if (item["method"], item["route_template"]) == route
    ] == [reason]
    assert all(
        json.loads(entry["detail"]).get("evidence_state") in {"verified", "observed"}
        for entry in log["entries"] if entry["action"] == "finding"
    )


# --------------------------------------------------------------------------- #
# R14 no transport selection from the CLI
# --------------------------------------------------------------------------- #
def test_r14_cli_cannot_select_transport(tmp_path, monkeypatch):
    # The option set of `runner run` is exactly the six of the spec.
    tree = ast.parse((ROOT / "heel/cli.py").read_text())
    options = [
        node.args[0].value for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "runner_run.add_argument"
    ]
    assert sorted(options) == ["--as", "--base-url", "--dry-run", "--max-ops", "--routes", "--scope"]
    assert list(inspect.signature(plan_differential._build_client).parameters) == ["origin"]
    for function in (plan_differential.plan_differential, plan_differential.run_plan_differential):
        assert set(inspect.signature(function).parameters) <= {
            "scope_id", "base_url", "plans", "caller", "routes_artifact", "max_ops", "attempt",
        }

    with World(tmp_path, monkeypatch, seam=False) as world:
        for extra in (
            ("--transport", "http"), ("--ca-file", "/tmp/ca.pem"), ("--cafile", "/tmp/ca.pem"),
            ("--resolver", "127.0.0.1"), ("--port", "8443"), ("--insecure",), ("--header", "X: 1"),
            ("--method", "POST"), ("--attempt", "a" * 32), ("--caller", "cli:root"),
            ("--no-verify",), ("--proxy", "http://127.0.0.1:1"), ("--dry",), ("--max", "4"),
            ("--base", SYNTHETIC_ORIGIN), ("--route", "x"),
        ):
            code, result, error = world.journey.run(*extra)
            assert (code, result, error) == (2, None, REJECTED), extra
        assert world.target.seen() == []

    # Heel and common third-party variables do not change the constructed client.
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *args, **keywords: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port or 443)),
        ],
    )

    def shape() -> tuple:
        client = plan_differential._build_client(SYNTHETIC_ORIGIN)
        context = client.tls.context
        return (
            type(client.resolver), type(client.sockets), type(client.tls), client.origin,
            context.verify_mode, context.check_hostname, context.protocol,
            len(context.get_ca_certs()), context.cert_store_stats(),
        )

    baseline = shape()
    assert baseline[:3] == (
        http_transport.BoundedResolver, http_transport.SocketTransport, http_transport.TLSTransport,
    )
    hostile = tmp_path / "hostile-ca.pem"
    hostile.write_text("not a certificate")
    for name in (
        "HEEL_CA_BUNDLE", "HEEL_RUNNER_CA_FILE", "HEEL_RUNNER_TRANSPORT", "HEEL_RUNNER_RESOLVER",
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    ):
        for value in (str(hostile), "http", "127.0.0.1", "loopback"):
            monkeypatch.setenv(name, value)
            assert shape() == baseline, name
        monkeypatch.delenv(name)
    # This test makes no claim about SSL_CERT_FILE or SSL_CERT_DIR; see R23.
    source = (ROOT / "heel/runner/plan_differential.py").read_text()
    assert "os.environ" not in source and "getenv" not in source


# --------------------------------------------------------------------------- #
# R15 observed finding without declaration
# --------------------------------------------------------------------------- #
def test_r15_observed_finding_from_undeclared_route(tmp_path, monkeypatch):
    # No input declares a plan gate: the OpenAPI document carries no plan or control metadata.
    document = FIXTURE.read_text()
    for needle in ("x-heel", "x-plan", "entitlement", "security", "plan"):
        assert needle not in document.replace("Plan-differential synthetic staging API", "")

    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        code, plan, error = journey.run("--dry-run")
        assert (code, error) == (0, "")
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        assert result["mode"] == "executed" and result["plan_sha256"] == plan["plan_sha256"]
        assert result["chain_valid"] is True and result["run_id"] == "pdrun-" + result["attempt_id"]

        summary = finding_for(result)
        assert (summary["predicate"], summary["evidence_state"]) == ("body_superset", "observed")
        (finding,) = [item for item in journey.findings(result["run_id"]) if item["id"] == summary["id"]]
        reproduction = finding["reproduction"]
        assert reproduction["evidence_state"] == "observed"
        assert reproduction["operator_declared"] is False
        assert reproduction["execution_disposition"] == "completed"
        assert reproduction["hypothesis"] == "endpoint_without_plan_gate"
        assert finding["scenario_id"] == "plan_differential.body_superset"
        assert finding["category"] == "license_entitlement"
        assert finding["target_id"] == SYNTHETIC_ORIGIN and finding["affordance_id"] == "GET /api/export"
        assert finding["id"].startswith("pdv-") and finding["plausible"] is True
        assert "ungated by design" in finding["notes"]
        # The reproduction block is closed.
        assert set(reproduction) == {
            "contained", "sample", "evidence_state", "execution_disposition", "predicate",
            "reason", "candidate", "hypothesis", "operator_declared", "observations", "observed",
            "attempt_id", "runner_run_ids", "plan_sha256", "provenance",
        }
        assert reproduction["provenance"] == {
            "kind": "plan_differential_execution", "network_calls": True,
            "target_verification": "signed_local_scope_only",
        }
        assert [item["label"] for item in reproduction["observations"]] == ["free", "pro"]
        assert [item["role"] for item in reproduction["observations"]] == ["lower_plan", "higher_plan"]
        for observation in reproduction["observations"]:
            assert set(observation) == {
                "label", "role", "status_code", "body_shape", "key_path_count", "response_bytes",
                "request_ref", "response_ref",
            }
            assert observation["request_ref"] == {
                "method": "GET", "route_template": "/api/export", "host": SYNTHETIC_HOST,
                "credential": "[REDACTED:secret]",
            }
            assert observation["response_ref"].startswith("ev1_")
        assert reproduction["observed"]["plans"] == [
            {"label": "free", "role": "lower_plan", "credential_handle": journey.handles[0]},
            {"label": "pro", "role": "higher_plan", "credential_handle": journey.handles[1]},
        ]
        # No body text, key name or credential label reaches the finding.
        rendered = json.dumps(finding)
        for needle in ("acct_canary", "amount_cents", "PRIVATE", FREE_TOKEN, PRO_TOKEN):
            assert needle not in rendered

        # `heel findings --run` and `heel regress add` work on it unchanged.
        regression = add_regression(world, result, "export-plan-gate")
        assert regression["scenario_id"] == "plan_differential.body_superset"
        assert regression["original_vector_id"] == finding["id"]
        assert regression["success_criterion"] == {"observed": reproduction["observed"]}
        assert regression["safety_flags"]["canary_only"] is True
        code, output, _ = invoke("regress", "list")
        assert code == 0 and len(json.loads(output)["regressions"]) == 1
        code, output, _ = invoke("log", "--run", result["run_id"])
        assert code == 0 and json.loads(output)["chain_valid"] is True


# --------------------------------------------------------------------------- #
# R16 safe failure output
# --------------------------------------------------------------------------- #
def test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing(tmp_path, monkeypatch):
    source = (ROOT / "heel/cli.py").read_text()
    assert "_SAFE_RUNNER_RUN_FAILURE" not in source
    assert source.count('_SAFE_RUNNER_COMMAND_FAILURE = "Heel runner command was rejected."') == 1

    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        free, pro = journey.handles
        private = "private-marker-7f3a"
        post = json.loads(inventory_file(world).read_text())
        post["inventory"]["routes"].append({
            "method": "POST", "route_template": "/api/export", "operation_id": private,
            "placeholders": [],
        })
        post_file = tmp_path / (private + "-routes.json")
        post_file.write_text(json.dumps(post))
        base = ["runner", "run", "--scope", journey.scope_id, "--base-url", journey.origin]
        identities = ["--as", "free=" + free, "--as", "pro=" + pro]
        commands = (
            # argparse: unknown option, missing required options
            base + identities + ["--" + private, "x"],
            ["runner", "run", "--base-url", journey.origin] + identities,
            ["runner", "run", "--scope", journey.scope_id] + identities,
            ["runner", "run"],
            # handler: bad scope, bad URL, bad --as, bad --routes, POST inventory
            ["runner", "run", "--scope", private, "--base-url", journey.origin] + identities,
            ["runner", "run", "--scope", journey.scope_id, "--base-url", "https://" + private] + identities,
            ["runner", "run", "--scope", journey.scope_id, "--base-url", "http://" + SYNTHETIC_HOST] + identities,
            base + ["--as", private.upper() + "=" + free, "--as", "pro=" + pro],
            base + ["--as", "free=" + private, "--as", "pro=" + pro],
            base + ["--as", "free=" + free],
            base + identities + ["--routes", str(tmp_path / (private + "-missing.json"))],
            base + identities + ["--routes", str(post_file)],
            base + identities + ["--max-ops", private],
        )
        for command in commands:
            for extra in ([], ["--dry-run"]):
                journey.supply_credentials()
                code, output, error = invoke(*command, *extra)
                assert (code, output, error) == (2, "", REJECTED), command
        assert world.target.seen() == []
        assert not (journey.home / "plan-runs").exists()


# --------------------------------------------------------------------------- #
# R18 handles on --as
# --------------------------------------------------------------------------- #
def test_r18_as_accepts_only_registered_credential_handles(tmp_path, monkeypatch):
    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        free, pro = journey.handles
        rejected = (
            (("free", "PRIVATE lower_plan"), ("pro", pro)),      # a label in place of a handle
            (("free", "lower_plan"), ("pro", "higher_plan")),    # a role in place of a handle
            (("free", "0" * 32), ("pro", pro)),                  # unknown handle
            (("free", free), ("pro", "f" * 32)),
            (("pro", pro), ("free", free)),                      # swapped: higher first
            (("free", free), ("pro", free)),                     # same handle twice
            (("free", free), ("free", pro)),                     # same label twice
            (("free", free.upper()), ("pro", pro)),
            (("free", free[:-1]), ("pro", pro)),
            (("Free", free), ("pro", pro)),
            (("", free), ("pro", pro)),
            (("free", free),),
            (("free", free), ("pro", pro), ("max", pro)),
            (("free", free + "=x"), ("pro", pro)),
        )
        for identities in rejected:
            for extra in ((), ("--dry-run",)):
                code, result, error = journey.run(*extra, identities=identities)
                assert (code, result, error) == (2, None, REJECTED), identities
        # Zero --as executes nothing; it is only the bootstrap dry-run.
        code, result, error = journey.run(identities=())
        assert (code, result, error) == (2, None, REJECTED)
        assert world.target.seen() == []
        # The label is the human's plan name and has no effect on execution or ordering.
        code, plan, error = journey.run("--dry-run", identities=(("starter", free), ("enterprise", pro)))
        assert code == 0
        assert [(item["label"], item["role"], item["credential_handle"]) for item in plan["plans"]] == [
            ("starter", "lower_plan", free), ("enterprise", "higher_plan", pro),
        ]

    # Mismatched auth profiles are rejected.
    with World(tmp_path / "b", monkeypatch, profiles=("bearer", "x_api_key")) as world:
        for extra in ((), ("--dry-run",)):
            code, result, error = world.journey.run(*extra)
            assert (code, result, error) == (2, None, REJECTED)
        assert world.target.seen() == []


def test_r18_credential_add_prints_handle_never_label_or_secret(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        # The Journey registered both plan credentials; register a third role and inspect it.
        secret = "private-secret-value-0001"
        monkeypatch.setenv("HEEL_PRIVATE_SECRET", secret)
        code, output, error = invoke(
            "runner", "credential", "add", "--role", "authenticated", "--profile", "bearer",
            "--label", "VERY PRIVATE LABEL", "--backend", "ephemeral-env",
        )
        assert (code, error) == (0, "")
        printed = json.loads(output)
        handle = printed["credential_handle"]
        assert printed == {
            "credential_handle": handle,
            "credential_source": {
                "kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_" + handle.upper(),
            },
            "registered_count": 1,
        }
        assert len(handle) == 32 and set(handle) <= set("0123456789abcdef")
        assert handle not in journey.handles and len(set(journey.handles)) == 2
        for needle in ("VERY PRIVATE LABEL", "label", secret, "authenticated", "bearer"):
            assert needle not in output
        # The handle the operator was shown is the one the plan names for the credential.
        code, plan, _ = journey.run("--dry-run")
        assert [item["credential_source"] for item in plan["plans"]] == [
            {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_" + item.upper()}
            for item in journey.handles
        ]
        assert "PRIVATE" not in json.dumps(plan)
        # A second registration for a role is refused with the fixed credential line.
        code, output, error = invoke(
            "runner", "credential", "add", "--role", "lower_plan", "--profile", "bearer",
            "--label", "again", "--backend", "ephemeral-env",
        )
        assert (code, output) == (2, "") and "again" not in error


# --------------------------------------------------------------------------- #
# R19 imported inventory on --routes
# --------------------------------------------------------------------------- #
def test_r19_routes_consumes_persisted_inventory_artifact(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        stored = inventory_file(world)
        before = (stored.read_bytes(), stored.stat().st_mtime_ns)
        artifact = json.loads(stored.read_text())
        assert artifact["schema_version"] == "heel.runner-route-inventory.v1"
        assert artifact["origin"] == SYNTHETIC_ORIGIN

        # A saved copy of the import is accepted; every route is planned or listed.
        copy = tmp_path / "saved-routes.json"
        copy.write_bytes(stored.read_bytes())
        code, plan, error = journey.run("--dry-run", "--routes", str(copy))
        assert (code, error) == (0, "")
        assert plan["inventory"] == {
            "path": str(copy), "source": "file", "route_count": 12,
            "source_digest": artifact["inventory"]["source_digest"],
        }
        accounted = {(item["method"], item["route_template"]) for item in plan["pairs"]} | {
            (item["method"], item["route_template"]) for item in plan["not_executed"]
        }
        assert accounted == {
            (route["method"], route["route_template"]) for route in artifact["inventory"]["routes"]
        }
        code, default_plan, _ = journey.run("--dry-run")
        assert plan["plan_sha256"] == default_plan["plan_sha256"]

        # The file is the whole allowlist for the invocation.
        narrow = json.loads(stored.read_text())
        narrow["inventory"]["routes"] = [
            route for route in narrow["inventory"]["routes"]
            if route["route_template"] in {"/api/export", "/api/reports"}
        ]
        narrow_file = tmp_path / "narrow-routes.json"
        narrow_file.write_text(json.dumps(narrow))
        code, result, error = journey.run("--routes", str(narrow_file))
        assert (code, error) == (1, "")
        assert [(pair["method"], pair["route_template"]) for pair in result["pairs"]] == [
            ("GET", "/api/export"), ("HEAD", "/api/export"), ("GET", "/api/reports"),
        ]
        assert {path for _, path, _ in world.target.seen()} == {"/api/export", "/api/reports"}
        sent = len(world.target.seen())

        # Everything that is not a complete persisted envelope for this context is rejected.
        def write(name: str, value) -> Path:
            path = tmp_path / name
            path.write_text(value if isinstance(value, str) else json.dumps(value))
            return path

        other_origin = {**artifact, "origin": "https://other-staging.heel.dev"}
        other_namespace = {**artifact, "namespace": "0" * 64}
        reversed_routes = json.loads(stored.read_text())
        reversed_routes["inventory"]["routes"].reverse()
        duplicate = json.loads(stored.read_text())
        duplicate["inventory"]["routes"].append(duplicate["inventory"]["routes"][0])
        extra_field = json.loads(stored.read_text())
        extra_field["inventory"]["routes"][0]["plan"] = "pro"
        symlink = tmp_path / "linked-routes.json"
        symlink.symlink_to(copy)
        rejected = (
            write("selector.json", ["GET /api/export", "GET /api/reports"]),
            write("selector-object.json", {"routes": ["GET /api/export"]}),
            write("bare-inventory.json", artifact["inventory"]),
            write("bare-routes.json", artifact["inventory"]["routes"]),
            write("openapi.json", FIXTURE.read_text()),
            write("other-origin.json", other_origin),
            write("other-namespace.json", other_namespace),
            write("non-canonical.json", reversed_routes),
            write("duplicate.json", duplicate),
            write("extra-field.json", extra_field),
            write("not-json.json", "GET /api/export\n"),
            write("duplicate-keys.json", '{"schema_version": "a", "schema_version": "b"}'),
            write("empty.json", ""),
            symlink, tmp_path / "absent.json", tmp_path,
        )
        for path in rejected:
            for extra in ((), ("--dry-run",)):
                code, result, error = journey.run("--routes", str(path), *extra)
                assert (code, result, error) == (2, None, REJECTED), path.name
        assert len(world.target.seen()) == sent
        # The setup store's inventory was never rewritten.
        assert (stored.read_bytes(), stored.stat().st_mtime_ns) == before


def test_r19_routes_default_is_existing_imported_inventory(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        # Before the import the bootstrap dry-run had no inventory.
        assert journey.bootstrap["inventory"]["source"] == "default"
        assert journey.bootstrap["inventory"]["route_count"] == 0
        stored = Path(journey.bootstrap["inventory"]["path"])
        assert stored.name == "routes.json" and stored.is_file()
        assert journey.home in stored.parents
        before = (stored.read_bytes(), stored.stat().st_mtime_ns)
        artifact = json.loads(stored.read_text())

        code, plan, error = journey.run("--dry-run")
        assert (code, error) == (0, "")
        assert plan["inventory"] == {
            "path": str(stored), "source": "default", "route_count": 12,
            "source_digest": artifact["inventory"]["source_digest"],
        }
        # Canonical order (route_template, method, operation_id); POST was never imported.
        routes = [(pair["route_template"], pair["method"]) for pair in plan["pairs"]]
        assert routes == sorted(routes) and len(routes) == 10
        assert [pair["ordinal"] for pair in plan["pairs"]] == list(range(10))
        assert all(route["method"] in {"GET", "HEAD"} for route in artifact["inventory"]["routes"])
        assert plan["not_executed"] == [
            {"method": "GET", "route_template": "/exports/{id}", "reason": "unbound_placeholder"},
            {"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"},
        ]
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        assert [(pair["route_template"], pair["method"]) for pair in result["pairs"]] == routes
        assert not any(method == "POST" for method, _, _ in world.target.seen())
        assert (stored.read_bytes(), stored.stat().st_mtime_ns) == before

        # A human-supplied fixture plans exactly the mapped parameterized route.
        journey.map("GET", "/exports/{id}", {"id": MARKER})
        code, mapped, _ = journey.run("--dry-run")
        assert {"ordinal": 10, "method": "GET", "route_template": "/exports/{id}", "requests": 2,
                "marker_supplied": True} in mapped["pairs"]
        assert mapped["not_executed"] == [
            {"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"},
        ]
        assert mapped["plan_sha256"] != plan["plan_sha256"]
        assert MARKER not in json.dumps(mapped)
        # A HEAD mapping is accepted for the plan pair, and a HEAD pair never has a marker.
        journey.map("HEAD", "/api/export", {})
        code, head_mapped, _ = journey.run("--dry-run")
        assert {"ordinal": 4, "method": "HEAD", "route_template": "/api/export", "requests": 2,
                "marker_supplied": False} in head_mapped["pairs"]


# --------------------------------------------------------------------------- #
# R20 replay fidelity
# --------------------------------------------------------------------------- #
def _rewrite_saved(world: World, vector_id: str, edit) -> None:
    """Edit the stored finding the regression replays from (test-only database surgery)."""
    connection = sqlite3.connect(world.journey.home / "heel.db")
    try:
        (raw,) = connection.execute(
            "SELECT json FROM findings WHERE vector_id = ?", (vector_id,),
        ).fetchone()
        vector = json.loads(raw)
        edit(vector["reproduction"]["observed"])
        connection.execute(
            "UPDATE findings SET json = ? WHERE vector_id = ?", (json.dumps(vector), vector_id),
        )
        connection.commit()
    finally:
        connection.close()


def test_r20_regression_replay_reuses_saved_predicate_order_scope_origin(tmp_path, monkeypatch):
    def replay_log(run_id: str) -> dict:
        code, output, _ = invoke("log", "--run", run_id)
        assert code == 0
        return json.loads(output)

    def no_request(world: World, results: list[dict], sent: int) -> None:
        (item,) = results
        assert (item["result"], item["current_status"], item["run_id"]) == (
            "fail", "inconclusive", None,
        )
        assert item["matches_expected"] is False
        assert len(world.target.seen()) == sent

    with World(tmp_path / "a", monkeypatch) as world:
        journey = world.journey
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        add_regression(world, result, "export-plan-gate")
        sent = len(world.target.seen())

        # Vulnerable target: the saved predicate still holds.
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "still_reachable")
        assert item["run_id"].startswith("pdrun-") and item["run_id"] != result["run_id"]
        assert item["matches_expected"] is False and item["scope_id"] == journey.scope_id
        # The replay is one pair: the saved route, lower then higher, the saved handles.
        assert world.target.seen()[sent:] == [
            ("GET", "/api/export", "free"), ("GET", "/api/export", "pro"),
        ]
        (finding,) = journey.findings(item["run_id"])
        assert finding["reproduction"]["predicate"] == "body_superset"
        assert finding["reproduction"]["observed"]["plans"] == [
            {"label": "free", "role": "lower_plan", "credential_handle": journey.handles[0]},
            {"label": "pro", "role": "higher_plan", "credential_handle": journey.handles[1]},
        ]
        # A replay is capped at four ops, under a new attempt and the same scope.
        log = replay_log(item["run_id"])
        start = json.loads(log["entries"][0]["detail"])
        assert (start["effective_max_ops"], start["pairs_planned"]) == (4, 1)
        assert start["scope_id"] == journey.scope_id and start["target"] == journey.origin
        assert log["chain_valid"] is True
        assert "regression_result" in [entry["action"] for entry in log["entries"]]

        # Hardened target (403 for the lower plan): pass, blocked.
        world.target.behavior = "hardened"
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("pass", "blocked")
        assert item["matches_expected"] is True and item["control_likely"] == "present"
        assert journey.findings(item["run_id"]) == []
        sent = len(world.target.seen())

        # A different origin, a different scope: fail / inconclusive with zero requests.
        other_host = "other-staging.heel.dev"
        both = journey.create_scope(SYNTHETIC_HOST, other_host)
        no_request(world, regress(world, target="https://" + other_host, scope=both), sent)
        no_request(world, regress(world, scope=both), sent)
        no_request(world, regress(world, scope="scope-0000000000"), sent)
        # A non-https target never replays a plan-differential regression at all.
        code, output, _ = invoke("regress", "run", "--target", "reference-saas", "--scope", journey.scope_id)
        assert "plan_differential." not in output
        assert len(world.target.seen()) == sent

    # A marker regression: verified, then held when the marker is gone, and a changed
    # binding digest is a mismatch with zero requests.
    with World(tmp_path / "marker", monkeypatch, marker=MARKER) as world:
        journey = world.journey
        code, result, error = journey.run()
        regression = add_regression(world, result, "export-marker", ("GET", "/exports/{id}"))
        assert regression["scenario_id"] == "plan_differential.marker_leak"
        sent = len(world.target.seen())
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "still_reachable")
        assert world.target.seen()[sent:] == [
            ("GET", "/exports/" + MARKER, "free"), ("GET", "/exports/" + MARKER, "pro"),
        ]
        world.target.behavior = "hardened"
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("pass", "blocked")
        sent = len(world.target.seen())
        journey.map("GET", "/exports/{id}", {"id": "heel-canary-export-0002"})
        no_request(world, regress(world), sent)
        assert MARKER not in json.dumps(journey.findings(result["run_id"]))

    # Ephemeral environment credentials are consumed once per process: a second replay in
    # the same `regress run` cannot load them and is fail / inconclusive, never a pass.
    with World(tmp_path / "two", monkeypatch, behavior="vulnerable") as world:
        code, result, error = world.journey.run()
        add_regression(world, result, "export-plan-gate")
        add_regression(world, result, "pricing-plan-gate", ("GET", "/api/pricing"))
        world.target.behavior = "hardened"
        sent = len(world.target.seen())
        results = regress(world)
        assert sorted((item["result"], item["current_status"]) for item in results) == [
            ("fail", "inconclusive"), ("pass", "blocked"),
        ]
        assert len(world.target.seen()) == sent + 2

    # Saved handles, role order, predicate and route are reused exactly; an edit to any of
    # them is a mismatch, not a new instruction.
    edits = {
        "handle": lambda saved: saved["plans"][0].__setitem__("credential_handle", "0" * 32),
        "role_order": lambda saved: saved["plans"].reverse(),
        "same_role": lambda saved: saved["plans"][1].__setitem__("role", "lower_plan"),
        "predicate": lambda saved: saved.__setitem__("predicate", "status_parity"),
        "route": lambda saved: saved.__setitem__("route_template", "/api/absent"),
        "method": lambda saved: saved.__setitem__("method", "POST"),
        "bindings": lambda saved: saved.__setitem__("fixture_bindings_sha256", "0" * 64),
        "marker": lambda saved: saved.__setitem__("marker_supplied", True),
    }
    for name, edit in edits.items():
        with World(tmp_path / ("edit-" + name), monkeypatch) as world:
            code, result, error = world.journey.run("--max-ops", "8")
            regression = add_regression(world, result, "export-plan-gate")
            sent = len(world.target.seen())
            _rewrite_saved(world, regression["original_vector_id"], edit)
            (item,) = regress(world)
            assert (item["result"], item["current_status"], item["run_id"]) == (
                "fail", "inconclusive", None,
            ), name
            assert len(world.target.seen()) == sent, name

    # A handle that is no longer supplied: the replay does not complete and is not a pass.
    with World(tmp_path / "unsupplied", monkeypatch) as world:
        code, result, error = world.journey.run("--max-ops", "8")
        add_regression(world, result, "export-plan-gate")
        sent = len(world.target.seen())
        world.journey.supply_credentials(skip_higher=True)
        code, output, _ = invoke(
            "regress", "run", "--target", world.journey.origin, "--scope", world.journey.scope_id,
        )
        (item,) = json.loads(output)["results"]
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        assert len(world.target.seen()) == sent
        assert home_contains(world.journey.home, FREE_TOKEN.encode()) == []


# --------------------------------------------------------------------------- #
# R24 denial envelope never passes
# --------------------------------------------------------------------------- #
def test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay(tmp_path, monkeypatch):
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        assert finding_for(result)["evidence_state"] == "observed"
        add_regression(world, result, "export-plan-gate")

        def fresh() -> tuple[int, dict, dict]:
            code, result, error = journey.run()
            assert error == ""
            return code, pairs_by_route(result)[EXPORT], finding_for(result) if any(
                (item["method"], item["route_template"]) == EXPORT for item in result["findings"]
            ) else {}

        def replay() -> dict:
            (item,) = regress(world)
            assert item["result"] in {"pass", "fail"}
            return item

        # 200 {"error": "upgrade required"} for the lower plan.
        world.target.behavior = "envelope"
        code, pair, finding = fresh()
        assert (pair["verdict"], pair["predicate"], pair["reason"], pair["candidate"]) == (
            "inconclusive", "inconclusive", "lower_denial_envelope", False,
        )
        assert pair["execution_disposition"] == "completed"
        assert finding == {}
        assert_unstored_with_evidence(world, journey.run()[1], "lower_denial_envelope")
        item = replay()
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        assert item["matches_expected"] is False and item["run_id"].startswith("pdrun-")
        # The replay run records the undecided pair but stores no new finding.
        assert journey.findings(item["run_id"]) == []
        replayed = [
            json.loads(entry["detail"]) for entry in journey.containment(item["run_id"])["entries"]
            if entry["action"] == "plan_differential_pair"
        ]
        assert [entry["reason"] for entry in replayed] == ["lower_denial_envelope"]

        # 200 with fewer keys: the lower plan still received content.
        world.target.behavior = "subset"
        code, pair, finding = fresh()
        assert (pair["verdict"], pair["predicate"], pair["reason"], pair["candidate"]) == (
            "inconclusive", "status_parity", "lower_subset", True,
        )
        assert finding == {} and pair["finding_id"] is None
        item = replay()
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")

        # 403: an affirmative denial with the higher plan still succeeding.
        world.target.behavior = "hardened"
        code, pair, finding = fresh()
        assert (pair["verdict"], pair["reason"], pair["finding_id"]) == ("held", "lower_denied", None)
        assert finding == {}
        item = replay()
        assert (item["result"], item["current_status"]) == ("pass", "blocked")
        assert item["matches_expected"] is True

        # And back: the same regression fails again on the vulnerable target.
        world.target.behavior = "vulnerable"
        item = replay()
        assert (item["result"], item["current_status"]) == ("fail", "still_reachable")


# --------------------------------------------------------------------------- #
# Inconclusive pairs never become local findings
# --------------------------------------------------------------------------- #
def _json_response(status: int, value) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/json"}, json.dumps(value).encode("utf-8")


def _override(world: World, monkeypatch, responses: dict) -> None:
    """Answer ``(plan, path)`` from ``responses``; every other request is the target's own."""
    original = world.target.respond

    def respond(method: str, path: str, token: str):
        answer = responses.get((world.target.sessions.get(token), path))
        return original(method, path, token) if answer is None else answer

    # The listener looks `respond` up on the instance for every request.
    monkeypatch.setattr(world.target, "respond", respond)


def test_inconclusive_pairs_store_no_finding_and_keep_their_evidence(tmp_path, monkeypatch):
    export_path = EXPORT[1]
    marker_route = ("GET", "/exports/{id}")
    marker_path = "/exports/" + MARKER
    cases = [
        # (name, marker world, route, overrides, reason)
        ("higher_denied", False, EXPORT,
         {("pro", export_path): _json_response(403, {"error": "upgrade required"})},
         "no_positive_control"),
        ("higher_error", False, EXPORT,
         {("pro", export_path): _json_response(500, {"detail": "boom"})},
         "no_positive_control"),
        ("higher_2xx_envelope", False, EXPORT,
         {("pro", export_path): _json_response(200, {"error": "upgrade required"})},
         "no_positive_control"),
        ("lower_error", False, EXPORT,
         {("free", export_path): _json_response(500, {"detail": "boom"})},
         "unexpected_status"),
        ("higher_missing_marker", True, marker_route,
         {("pro", marker_path): _json_response(200, {"rows": []})},
         "positive_control_missing_marker"),
        ("unknown_marker", True, marker_route,
         {("free", marker_path): _json_response(200, {"rows": [1]})},
         "marker_undetermined"),
        ("other_marker", True, marker_route,
         {("free", marker_path): _json_response(
             200, {"protected_canary": "heel-canary-export-0009", "rows": [1]})},
         "marker_undetermined"),
        ("2xx_error_with_marker", True, marker_route,
         {("free", marker_path): _json_response(
             200, {"error": "upgrade required", "protected_canary": MARKER, "rows": []})},
         "marker_undetermined"),
    ]
    for name, marker, route, overrides, reason in cases:
        keywords = {"marker": MARKER} if marker else {}
        with World(tmp_path / name, monkeypatch, **keywords) as world:
            journey = world.journey
            _override(world, monkeypatch, overrides)
            code, result, error = journey.run()
            assert error == "", name
            pair = pairs_by_route(result)[route]
            assert (pair["verdict"], pair["reason"]) == ("inconclusive", reason), name
            assert_unstored_with_evidence(world, result, reason, route)
            # Nothing undecided is stored, counted or exposed as a finding of the run.
            assert [
                item for item in journey.findings(result["run_id"])
                if item["reproduction"]["evidence_state"] == "inconclusive"
            ] == [], name
            code, output, _ = invoke("findings", "--run", result["run_id"])
            assert code == 0
            listed = json.loads(output)["findings"]
            assert len(listed) == len(result["findings"]), name
            log = journey.containment(result["run_id"])
            (complete,) = [
                json.loads(entry["detail"]) for entry in log["entries"]
                if entry["action"] == "run_complete"
            ]
            assert complete["findings"] == len(result["findings"]), name
            assert complete["pairs"] == len(result["pairs"]), name
            # A genuine finding elsewhere in the same run is still stored.
            states = {item["route_template"]: item["evidence_state"] for item in result["findings"]}
            if route == EXPORT:
                assert "/api/export" not in states and states.get("/api/pricing") == "observed"
            else:
                assert "/exports/{id}" not in states and states["/api/export"] == "observed"


# --------------------------------------------------------------------------- #
# A status-only repair that leaves the paid payload in place never passes
# --------------------------------------------------------------------------- #
def test_status_only_repair_with_the_payload_is_never_a_regression_pass(tmp_path, monkeypatch):
    from plan_differential_support import DENIAL_ENVELOPE, EXPORT as export_body

    export_path = EXPORT[1]
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        # The initial 200 read with the same material payload is the observed finding.
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        finding = finding_for(result)
        assert (finding["predicate"], finding["evidence_state"]) == ("body_superset", "observed")
        regression = add_regression(world, result, "export-plan-gate")
        assert regression["scenario_id"] == "plan_differential.body_superset"

        responses: dict = {}
        _override(world, monkeypatch, responses)

        def fresh_and_replay(reason: str) -> dict:
            code, result, error = journey.run()
            assert error == ""
            pair = pairs_by_route(result)[EXPORT]
            assert (pair["verdict"], pair["predicate"], pair["reason"], pair["candidate"]) == (
                "inconclusive", "inconclusive", reason, False,
            )
            assert_unstored_with_evidence(world, result, reason)
            (item,) = regress(world)
            assert item["run_id"].startswith("pdrun-")
            assert item["scope_id"] == journey.scope_id and item["target"] == journey.origin
            assert item["scenario_id"] == "plan_differential.body_superset"
            assert journey.findings(item["run_id"]) == []
            replayed = [
                json.loads(entry["detail"]) for entry in journey.containment(item["run_id"])["entries"]
                if entry["action"] == "plan_differential_pair"
            ]
            assert [entry["reason"] for entry in replayed] == [reason]
            return item

        # Only the lower status changes to 403 (and 401, 402, 404); the paid body stays.
        for status in (403, 401, 402, 404):
            responses[("free", export_path)] = _json_response(status, export_body)
            item = fresh_and_replay("lower_denied_payload_present")
            assert (item["result"], item["current_status"]) == ("fail", "inconclusive"), status
            assert item["matches_expected"] is False and item["control_likely"] == "unknown"

        # An error envelope that still carries the same paid fields cannot pass either.
        responses[("free", export_path)] = _json_response(
            403, {**DENIAL_ENVELOPE, **export_body},
        )
        item = fresh_and_replay("lower_denied_payload_present")
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")

        # A missing or invalid higher body control is never a pass for a body regression.
        responses[("free", export_path)] = _json_response(403, DENIAL_ENVELOPE)
        for higher in (
            (200, {"Content-Type": "application/json"}, b""),
            _json_response(200, {}),
            _json_response(200, {"rows": [], "total": 0}),
        ):
            responses[("pro", export_path)] = higher
            item = fresh_and_replay("higher_control_unassessable")
            assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        # An opaque higher body is refused by the transport first: row 1, still no pass.
        for higher in (
            (200, {"Content-Type": "text/plain"}, b"plain text"), _json_response(200, [export_body]),
        ):
            responses[("pro", export_path)] = higher
            code, result, error = journey.run()
            pair = pairs_by_route(result)[EXPORT]
            assert (pair["verdict"], pair["reason"], pair["finding_id"]) == (
                "inconclusive", "transport:response_rejected", None,
            )
            (item,) = regress(world)
            assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        del responses[("pro", export_path)]

        # An unassessable lower body is not proof that the payload disappeared: one beyond
        # the key-path bounds, or one the transport refuses before any predicate.
        deep: dict = {"error": "upgrade required"}
        for _ in range(plan_differential.MAX_KEY_PATH_DEPTH + 2):
            deep = {"error": deep}
        wide = {f"k{index}": index for index in range(plan_differential.MAX_KEY_PATH_NODES + 1)}
        for lower in (deep, wide):
            responses[("free", export_path)] = _json_response(403, lower)
            item = fresh_and_replay("lower_denial_unassessable")
            assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        responses[("free", export_path)] = (
            403, {"Content-Type": "text/html"}, b"<html><body>Forbidden</body></html>",
        )
        code, result, error = journey.run()
        assert pairs_by_route(result)[EXPORT]["reason"] == "transport:response_rejected"
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")

        # A genuine denial without the payload still passes against a valid higher control.
        for lower in (
            _json_response(403, DENIAL_ENVELOPE),
            (403, {"Content-Type": "application/json"}, b""),
            _json_response(404, {"error": "not found"}),
        ):
            responses[("free", export_path)] = lower
            code, result, error = journey.run()
            pair = pairs_by_route(result)[EXPORT]
            assert (pair["verdict"], pair["reason"], pair["finding_id"]) == (
                "held", "lower_denied", None,
            )
            (item,) = regress(world)
            assert (item["result"], item["current_status"]) == ("pass", "blocked")
            assert item["matches_expected"] is True and item["control_likely"] == "present"

        # And back: the same regression fails again when the payload is served at 200.
        responses.clear()
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "still_reachable")


# --------------------------------------------------------------------------- #
# Records stored by earlier runs: readable, never a new regression, still undecided
# --------------------------------------------------------------------------- #
def _legacy_inconclusive_copy(world: World, source: dict, predicate: str, reason: str) -> dict:
    """Store, as an earlier version did, an undecided pair as a finding (test-only surgery)."""
    vector = json.loads(json.dumps(source))
    vector["id"] = "pdv-legacy" + predicate[:2]
    vector["scenario_id"] = "plan_differential." + predicate
    vector["plausible"] = False
    reproduction = vector["reproduction"]
    reproduction.update({
        "evidence_state": "inconclusive", "predicate": predicate, "reason": reason,
        "candidate": predicate == "status_parity",
    })
    reproduction["observed"]["predicate"] = predicate
    connection = sqlite3.connect(world.journey.home / "heel.db")
    try:
        (run_id,) = connection.execute(
            "SELECT run_id FROM findings WHERE vector_id = ?", (source["id"],),
        ).fetchone()
        connection.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?)",
            (run_id, vector["id"], vector["category"], 0.1, 0, json.dumps(vector)),
        )
        connection.commit()
    finally:
        connection.close()
    return vector


def test_legacy_inconclusive_records_are_readable_rejected_and_replay_undecided(tmp_path, monkeypatch):
    from heel.store import Store

    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        (observed,) = [
            item for item in journey.findings(result["run_id"])
            if item["affordance_id"] == " ".join(EXPORT)
        ]
        assert observed["reproduction"]["evidence_state"] == "observed"
        legacy = {
            "status_parity": _legacy_inconclusive_copy(world, observed, "status_parity", "lower_subset"),
            "inconclusive": _legacy_inconclusive_copy(
                world, observed, "inconclusive", "lower_denial_envelope",
            ),
        }
        before = {item["id"] for item in journey.findings(result["run_id"])}

        # Readable as before, but neither can become a new regression; nothing is deleted.
        for predicate, vector in legacy.items():
            assert vector["id"] in before
            code, output, _ = invoke(
                "regress", "add", "--run", result["run_id"], "--vector", vector["id"],
                "--name", "legacy-" + predicate,
            )
            assert code == 1
            assert output == (
                "REJECTED: an inconclusive plan-differential result cannot become a regression\n"
            )
        code, output, _ = invoke("regress", "list")
        assert code == 0 and json.loads(output)["regressions"] == []
        assert {item["id"] for item in journey.findings(result["run_id"])} == before
        # The observed runtime finding of the same run is still admitted.
        admitted = add_regression(world, result, "export-plan-gate")
        assert admitted["original_vector_id"] == observed["id"]

        def only_regression(regression: dict) -> None:
            # Ephemeral credentials serve one replay per process: keep one stored regression.
            store = Store(str(journey.home / "heel.db"))
            try:
                store.conn.execute("DELETE FROM regressions")
                store.conn.commit()
                store.add_regression(regression)
            finally:
                store.close()

        def replay(behavior: str) -> tuple[str, str]:
            world.target.behavior = behavior
            (item,) = regress(world)
            return item["result"], item["current_status"]

        # A regression an earlier version saved from each record still replays. Status
        # parity alone, a lower denial envelope, or a hollow lower body never passes and is
        # never still_reachable; only a pair that is itself a finding still holds.
        expected = {
            "status_parity": {
                "subset": ("fail", "inconclusive"), "envelope": ("fail", "inconclusive"),
                "vulnerable": ("fail", "still_reachable"), "hardened": ("pass", "blocked"),
            },
            "inconclusive": {
                "subset": ("fail", "inconclusive"), "envelope": ("fail", "inconclusive"),
                "vulnerable": ("fail", "inconclusive"), "hardened": ("pass", "blocked"),
            },
        }
        for predicate, vector in legacy.items():
            only_regression({
                **admitted,
                "regression_id": "reg-legacy-" + predicate[:6],
                "name": "legacy-" + predicate,
                "original_vector_id": vector["id"],
                "scenario_id": vector["scenario_id"],
                "success_criterion": {"observed": vector["reproduction"]["observed"]},
            })
            for behavior, outcome in expected[predicate].items():
                assert replay(behavior) == outcome, (predicate, behavior)


# --------------------------------------------------------------------------- #
# The synthetic harness that the documentation and T5 follow
# --------------------------------------------------------------------------- #
def test_synthetic_harness_runs_the_documented_journey(tmp_path):
    harness = [sys.executable, str(ROOT / "tests/plan_differential_harness.py")]
    port_file = tmp_path / "harness.port"
    environment = {
        **{name: value for name, value in os.environ.items()
           if not name.startswith("HEEL_RUNNER_CREDENTIAL_")},
        "HEEL_HOME": str(tmp_path / "heel-home"),
        "PLAN_DIFFERENTIAL_HARNESS_PORT_FILE": str(port_file),
        "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep),
    }
    environment.pop("HEEL_SIGNING_KEY", None)

    def heel(*arguments: str, extra: dict | None = None) -> tuple[int, str, str]:
        completed = subprocess.run(
            harness + ["heel", *arguments], env={**environment, **(extra or {})}, cwd=ROOT,
            capture_output=True, text=True, timeout=120,
        )
        return completed.returncode, completed.stdout, completed.stderr

    # Without a running target the harness refuses; it never falls back to the network.
    code, output, error = heel("runner", "run", "--scope", "x", "--base-url", SYNTHETIC_ORIGIN)
    assert (code, output) == (2, "") and "serve" in error

    server = subprocess.Popen(
        harness + ["serve"], env=environment, cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while not port_file.exists() and time.monotonic() < deadline:
            assert server.poll() is None
            time.sleep(0.05)
        assert port_file.exists()

        code, output, error = heel(
            "scope", "create", "--confirm", "--operator", "harness", "--target", SYNTHETIC_HOST,
        )
        assert code == 0, error
        scope_id = json.loads(output)["created_scope"]
        run = ["runner", "run", "--scope", scope_id, "--base-url", SYNTHETIC_ORIGIN]
        code, output, error = heel(*run, "--dry-run")
        assert (code, error) == (0, "") and json.loads(output)["context"] == "bound"
        handles = []
        for role in ("lower_plan", "higher_plan"):
            code, output, error = heel(
                "runner", "credential", "add", "--role", role, "--profile", "bearer",
                "--label", role, "--backend", "ephemeral-env",
            )
            assert (code, error) == (0, "")
            handles.append(json.loads(output)["credential_handle"])
        code, output, error = heel("runner", "import-openapi", str(FIXTURE))
        assert (code, error) == (0, "") and json.loads(output) == {"route_count": 12}
        identities = ["--as", "free=" + handles[0], "--as", "pro=" + handles[1]]
        credentials = {
            "HEEL_RUNNER_CREDENTIAL_" + handles[0].upper(): FREE_TOKEN,
            "HEEL_RUNNER_CREDENTIAL_" + handles[1].upper(): PRO_TOKEN,
        }

        code, output, error = heel(*run, *identities, "--dry-run", extra=credentials)
        assert (code, error) == (0, "")
        plan = json.loads(output)
        assert (plan["requests_planned"], plan["requests_sent"], len(plan["pairs"])) == (20, 0, 10)

        code, output, error = heel(*run, *identities, extra=credentials)
        assert (code, error) == (1, "")
        result = json.loads(output)
        assert result["plan_sha256"] == plan["plan_sha256"] and result["chain_valid"] is True
        finding = finding_for(result)
        assert finding["evidence_state"] == "observed"

        code, output, error = heel("findings", "--run", result["run_id"])
        assert code == 0 and len(json.loads(output)["findings"]) == len(result["findings"])
        code, output, error = heel(
            "regress", "add", "--run", result["run_id"], "--vector", finding["id"],
            "--name", "export-plan-gate",
        )
        assert code == 0, error
        code, output, error = heel(
            "regress", "run", "--target", SYNTHETIC_ORIGIN, "--scope", scope_id, extra=credentials,
        )
        assert code == 0, error
        (replayed,) = json.loads(output)["results"]
        assert (replayed["result"], replayed["current_status"]) == ("fail", "still_reachable")
    finally:
        server.terminate()
        try:
            log, _ = server.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            server.kill()
            log, _ = server.communicate()
    # The access log: the dry-runs sent nothing; the run and the replay sent 18 + 2, each
    # with a plan session, and the tokens themselves are never logged per request.
    requests = [line for line in log.splitlines() if line.startswith("request ")]
    assert len(requests) == 20 and "requests served: 20; redirect listener: 0" in log
    assert all(line.endswith((" as free", " as pro")) for line in requests)
    assert requests[-2:] == ["request 19: GET /api/export as free", "request 20: GET /api/export as pro"]
    assert not port_file.exists()
    for token in (FREE_TOKEN, PRO_TOKEN):
        assert home_contains(tmp_path / "heel-home", token.encode()) == []


# --------------------------------------------------------------------------- #
# D5 (spec §8.7): a literal alias key does not populate the nested path
# --------------------------------------------------------------------------- #
def test_d5_alias_lower_body_is_hollow_in_fresh_run_and_regression_replay(tmp_path, monkeypatch):
    from plan_differential_support import EXPORT as export_body

    # Hollow at `rows[].id` and `rows[].amount_cents`, with truthy literal keys spelled the
    # way the pre-D5 renderer wrote those two nested paths.
    alias_body = {
        **export_body,
        "rows": [{"id": None, "amount_cents": None}],
        "rows[].id": "row_1",
        "rows[].amount_cents": 1200,
    }
    with World(tmp_path, monkeypatch) as world:
        journey = world.journey
        code, result, error = journey.run()
        assert (code, error) == (1, "")
        assert finding_for(result)["evidence_state"] == "observed"
        add_regression(world, result, "export-plan-gate")

        original = world.target.respond
        alias = {"enabled": True}

        def respond(method: str, path: str, token: str):
            if alias["enabled"] and path == EXPORT[1] and world.target.sessions.get(token) == "free":
                return 200, {"Content-Type": "application/json"}, json.dumps(alias_body).encode("utf-8")
            return original(method, path, token)

        # The listener looks `respond` up on the instance for every request.
        monkeypatch.setattr(world.target, "respond", respond)

        code, result, error = journey.run()
        assert error == ""
        pair = pairs_by_route(result)[EXPORT]
        assert (pair["verdict"], pair["predicate"], pair["reason"], pair["candidate"]) == (
            "inconclusive", "inconclusive", "lower_hollow_shape", False,
        )
        assert pair["execution_disposition"] == "completed"
        assert_unstored_with_evidence(world, result, "lower_hollow_shape")
        assert [
            item for item in journey.findings(result["run_id"])
            if item["reproduction"].get("reason") == "lower_hollow_shape"
        ] == []

        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "inconclusive")
        assert item["matches_expected"] is False and item["run_id"].startswith("pdrun-")
        assert journey.findings(item["run_id"]) == []

        # Wrapper disabled: the same regression fails again on the vulnerable target.
        alias["enabled"] = False
        (item,) = regress(world)
        assert (item["result"], item["current_status"]) == ("fail", "still_reachable")
