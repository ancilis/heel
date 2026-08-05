"""Heel CLI over the shared review and abuse-rehearsal capabilities.

`heel scope create` is the only path that can mint an authorization scope. It requires
explicit human confirmation and remains unavailable through the MCP and REST surfaces.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys

from . import __version__
from . import scope as scopemod
from .contracts import DataHandlingMode
from .mcp_server import (
    MAX_OPENAPI_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
    HeelServer,
    _json_within_limit,
    _success_tool_result,
)
from .store import Store


_SAFE_REVIEW_FAILURE = (
    "Heel OpenAPI review failed: input could not be read or reviewed safely."
)
_OPENAPI_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load_bounded_openapi(path: str) -> dict:
    """Read one regular, non-symlink JSON file without exceeding the MCP limit."""
    descriptor = os.open(path, _OPENAPI_READ_FLAGS)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("OpenAPI input must be a regular file")
        if status.st_size > MAX_OPENAPI_PAYLOAD_BYTES:
            raise ValueError("OpenAPI input exceeds the local review limit")

        chunks = []
        remaining = MAX_OPENAPI_PAYLOAD_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_OPENAPI_PAYLOAD_BYTES:
            raise ValueError("OpenAPI input exceeds the local review limit")
    finally:
        os.close(descriptor)

    value = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    if type(value) is not dict:
        raise ValueError("OpenAPI input must be a JSON object")
    return value


def _review_openapi_file(path: str, *, as_json: bool) -> int:
    """Review a local file through the same pure service and exporters as MCP."""
    from .local_projects import LocalProjectStore
    from .review_export import review_to_json, review_to_markdown
    from .review_service import review_openapi

    try:
        specification = _load_bounded_openapi(path)
        review = review_openapi(specification, execution_mode="machine_local")
        if not _json_within_limit(
            _success_tool_result("heel_review_openapi", review),
            MAX_RESULT_BYTES,
        ):
            raise ValueError("review exceeds the shared MCP result limit")
        LocalProjectStore().save_review(review)
        rendered = review_to_json(review) if as_json else review_to_markdown(review)
    # This is the command's trust boundary: parser, analyzer, exporter, and storage errors
    # must fail closed without reflecting a path, OpenAPI value, or traceback.
    except Exception:
        print(_SAFE_REVIEW_FAILURE, file=sys.stderr)
        return 2

    sys.stdout.write(rendered)
    return 0


def _doctor() -> int:
    """Self-check: install, data dir, signing-key posture, scenario library, capability."""
    ok, warn = [], []
    ok.append(f"heel {__version__} · python ok")
    home = scopemod.heel_home()
    try:
        os.makedirs(home, exist_ok=True)
        t = os.path.join(home, ".doctor"); open(t, "w").close(); os.remove(t)
        ok.append(f"HEEL_HOME writable: {home}")
    except Exception as e:
        warn.append(f"HEEL_HOME not writable ({home}): {e}")
    if os.environ.get("HEEL_SIGNING_KEY"):
        ok.append("signing key: external (HEEL_SIGNING_KEY): production posture ✓")
    else:
        warn.append("signing key is co-located in HEEL_HOME. For production set HEEL_SIGNING_KEY to a "
                    "path OUTSIDE the data dir (key+data separation). See SECURITY.md.")
    from .scenarios import all_seed_scenarios
    scs = all_seed_scenarios()
    cats = {s.category.value for s in scs}
    (ok if len(cats) == 10 else warn).append(f"scenario library: {len(scs)} scenarios across {len(cats)}/10 categories")
    try:
        from .agents import run_adversarial
        from .backtest import score_target
        from .targets import get_target
        out = run_adversarial(get_target("synthetic-saas"), scs, lambda *a: None, "doctor")
        cov = score_target(get_target("synthetic-saas"), out)["coverage"]
        ok.append(f"capability self-check: synthetic backtest ran (coverage {cov})")
    except Exception as e:
        warn.append(f"capability self-check FAILED: {e}")
    for line in ok:
        print(f"  [ok]   {line}")
    for line in warn:
        print(f"  [warn] {line}")
    print(f"\nheel doctor: {'OK' if not any('FAILED' in w or 'not writable' in w for w in warn) else 'PROBLEMS'}"
          f" ({len(ok)} ok, {len(warn)} warnings)")
    return 0 if not any("FAILED" in w or "not writable" in w for w in warn) else 1


def _server():
    home = scopemod.ensure_home()
    return HeelServer(Store(os.path.join(home, "heel.db")))


def _caller():
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:operator"


def _import_validate(path: str) -> int:
    from .importers import ProductModelError, load_product_model, target_from_product_model, validate_product_model
    try:
        model = load_product_model(path)
    except ProductModelError as e:
        print(f"ProductModel validation: FAIL ({e})")
        return 1
    result = validate_product_model(model)
    print(f"ProductModel validation: {'PASS' if result.ok else 'FAIL'}")
    print(f"  schema: {result.schema_version}")
    print(f"  summary: {result.summary}")
    if result.errors:
        print("  errors:")
        for err in result.errors:
            print(f"    - {err}")
    if result.warnings:
        print("  warnings:")
        for warn in result.warnings:
            print(f"    - {warn}")
    if not result.ok:
        return 1
    target = target_from_product_model(model)
    print(f"  target id: {target.id}")
    print(f"  affordances: {len(target.affordances)}")
    print(f"  safety notes: {len(target.safety_notes)}")
    print("  mode: imported-model rehearsal only; no live probing or network calls")
    print("  authorization: signed human-created scope required before any run")
    return 0


def _openapi_import(path: str, out_path: str) -> int:
    from .openapi_import import OpenAPIImportError, import_openapi_file, write_product_model
    try:
        model = import_openapi_file(path)
        write_product_model(model, out_path)
    except OpenAPIImportError as e:
        print(f"OpenAPI import: FAIL ({e})")
        return 1
    warnings = model.get("import_warnings", [])
    print("OpenAPI import: PASS")
    print(f"  wrote: {out_path}")
    print(f"  product_id: {model['product_id']}")
    print(f"  affordance draft count: {sum(len(model.get(f, [])) for f in ('exports', 'identity_auth_flows', 'billing_objects', 'meters', 'roles', 'integration_oauth_apps', 'webhooks', 'support_admin_actions', 'agent_tools'))}")
    print(f"  warnings: {len(warnings)}")
    for warning in warnings:
        print(f"    - {warning}")
    print("  mode: local OpenAPI-to-ProductModel draft only; no live probing or network calls")
    return 0


def _scenario_validate(path: str) -> int:
    from .scenario_validate import render_validation_report, validate_scenario_file

    results = validate_scenario_file(path)
    print(render_validation_report(results))
    return 0 if results and all(result.ok for result in results) else 1


def _scenario_explain(scenario_id: str) -> int:
    from .scenario_validate import explain_scenario

    explanation = explain_scenario(scenario_id)
    if explanation is None:
        print(f"Scenario explain: FAIL (unknown scenario id '{scenario_id}')")
        return 1
    print(explanation)
    return 0


def _mode_payload(mode, target_source: str, resolved_target: str | None = None) -> dict:
    payload = mode.to_dict()
    payload["target_source"] = target_source
    if resolved_target:
        payload["resolved_target"] = resolved_target
    return payload


def _resolve_run_target_for_mode(mode, target_arg: str | None) -> tuple[str | None, str, dict | None, str | None]:
    if not target_arg:
        return None, "", None, f"Mode {mode.id} requires --target"
    if target_arg.lower().endswith(".json") and os.path.isfile(target_arg):
        from .importers import ProductModelError, load_product_model, target_from_product_model
        from .targets import register_imported_target

        try:
            model = load_product_model(target_arg)
            target = register_imported_target(target_from_product_model(model))
        except ProductModelError as e:
            return None, "", None, f"ProductModel validation: FAIL ({e})"
        except Exception as e:
            return None, "", None, f"ProductModel target registration: FAIL ({e})"
        return target.id, "ProductModel/EntitlementGraph import; no live probing", model, None
    if mode.id == "existing-imported":
        return None, "", None, "Mode existing-imported requires --target to be a ProductModel JSON file"
    if mode.id == "staging":
        return target_arg, "canary staging target", None, None
    return target_arg, "built-in synthetic target", None, None


def _scope_for_mode(mode, scope_id: str | None):
    if not mode.requires_scope:
        return None, None
    if not scope_id:
        return None, f"Mode {mode.id} requires --scope with a human-created signed AuthorizationScope"
    scope = scopemod.get_scope(scope_id)
    if scope is None:
        return None, f"Mode {mode.id} rejected: unknown scope_id '{scope_id}'"
    ok, reason = scopemod.verify(scope)
    if not ok:
        return None, f"Mode {mode.id} rejected: scope invalid: {reason}"
    if mode.id == "staging":
        from .modes import scope_limit_errors

        violations = scope_limit_errors(mode, scope.rate_and_resource_limits)
        if violations:
            return None, (
                "Mode staging requires stricter signed scope limits: "
                + ", ".join(violations)
            )
    return scope, None


def _canary_errors_for_mode(mode, model: dict | None, canary_accounts: list[str] | None) -> list[str]:
    if not mode.requires_canary_accounts:
        return []
    if canary_accounts:
        return []
    if model and model.get("canary_accounts"):
        return []
    return [f"Mode {mode.id} requires canary account metadata"]


def _run_with_mode(args) -> int:
    from .modes import get_mode

    try:
        mode = get_mode(args.mode)
    except ValueError as e:
        print(f"REJECTED: {e}")
        return 2

    if mode.id == "launch-review":
        if not args.before or not args.after:
            print("Mode launch-review requires --before and --after ProductModel JSON files")
            return 2
        print("mode: launch-review")
        print("safety: static ProductModel diff; no live probing")
        return _launch_review(args)

    scope, scope_error = _scope_for_mode(mode, args.scope)
    if scope_error:
        print(scope_error)
        return 2

    if mode.id == "incident-regression":
        if not args.target:
            print("Mode incident-regression requires --target")
            return 2
        from .regressions import resolve_target_argument, run_regressions

        srv = _server()
        caller = _caller()
        try:
            target = resolve_target_argument(args.target)
            results = run_regressions(srv.store, srv, args.scope, target, caller)
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1
        print(json.dumps({
            "mode": _mode_payload(mode, "stored abuse regressions", target),
            "results": results,
        }, indent=2, default=str))
        return 0

    target, target_source, model, target_error = _resolve_run_target_for_mode(mode, args.target)
    if target_error:
        print(target_error)
        return 2
    canary_errors = _canary_errors_for_mode(mode, model, args.canary_account)
    if canary_errors:
        print("; ".join(canary_errors))
        return 2

    srv = _server()
    caller = _caller()
    try:
        run_args = {"scope_id": args.scope, "target": target, "scenario_ids": args.scenario}
        if args.packs:
            run_args["packs"] = [p.strip() for p in args.packs.split(",") if p.strip()]
        r = srv.heel_run(run_args, caller)
        r = dict(r)
        r["mode"] = _mode_payload(mode, target_source, target)
        if args.economic:
            r["economic_report"] = _report(srv, r["run_id"], caller, economic=True,
                                           economic_assumptions=args.economic_assumptions)
        print(json.dumps(r, indent=2))
    except Exception as e:
        print(f"REJECTED: {e}")
        return 1
    return 0


def _launch_review(args) -> int:
    from .importers import ProductModelError
    from .launch_review import load_and_review, render_human_summary, review_git_diff, review_to_json
    try:
        if getattr(args, "diff", None):
            review = review_git_diff(args.diff)
        else:
            review = load_and_review(args.before, args.after)
    except ProductModelError as e:
        print(f"Launch review: FAIL ({e})")
        return 2
    print(render_human_summary(review))
    print("JSON report:")
    print(review_to_json(review))
    return 2 if review.launch_gate_status == "block" else 1 if review.launch_gate_status == "warn" else 0


def _report(srv: HeelServer, run_id: str, caller: str, economic: bool = False,
            economic_assumptions: str | None = None) -> dict:
    findings = srv.heel_get_findings({"run_id": run_id}, caller)["findings"]
    row = srv.store.get_run(run_id)
    report = {
        "run_id": run_id,
        "status": row["status"] if row else None,
        "target": row["target"] if row else None,
        "caller": row["caller"] if row else None,
        "economic": bool(economic),
        "findings": findings,
    }
    try:
        report["coverage"] = srv.heel_get_coverage({"run_id": run_id}, caller)["coverage"]
    except Exception:
        report["coverage"] = None
    if not economic:
        return report

    from .economics import estimate_economic_impact, load_assumptions, rank_by_economic_risk

    assumptions = load_assumptions(economic_assumptions)
    enriched = []
    for finding in findings:
        f = dict(finding)
        f["economic_impact"] = estimate_economic_impact(f, assumptions=assumptions).to_dict()
        enriched.append(f)
    ranked = rank_by_economic_risk(enriched)
    report["findings"] = ranked
    report["economic_summary"] = {
        "top_label": ranked[0]["economic_impact"]["label"] if ranked else None,
        "top_estimated_monthly_range": ranked[0]["economic_impact"]["estimated_monthly_range"] if ranked else None,
        "unknowns_present": any(f["economic_impact"]["unknowns"] for f in ranked),
        "note": "Economic impact is directional and separate from security severity; assumptions and unknowns are shown per finding.",
    }
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="heel", description="Heel: agent-native abuse-simulation tool")
    ap.add_argument("--version", action="version", version=f"heel {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("doctor", help="self-check: install, data dir, signing-key posture, capability")
    sub.add_parser("eval", help="run the honest held-out detection eval and print the headline")
    bench = sub.add_parser("bench", help="run or render the HeelBench public benchmark")
    bench_sub = bench.add_subparsers(dest="bcmd", required=True)
    bench_run = bench_sub.add_parser("run", help="run HeelBench and emit canonical JSON")
    bench_run.add_argument("--blind-targets", type=int, default=24, help="number of blind synthetic targets")
    bench_run.add_argument("--workers", type=int, default=6, help="blind-eval worker threads")
    bench_report = bench_sub.add_parser("report", help="render a HeelBench report")
    bench_report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    bench_report.add_argument("--blind-targets", type=int, default=24, help="number of blind synthetic targets")
    bench_report.add_argument("--workers", type=int, default=6, help="blind-eval worker threads")

    review = sub.add_parser(
        "review",
        help="review local product definitions without an account or network access",
    )
    review_sub = review.add_subparsers(dest="reviewcmd", required=True)
    review_openapi_parser = review_sub.add_parser(
        "openapi",
        help="review a local OpenAPI JSON file and save the result under HEEL_HOME",
    )
    review_openapi_parser.add_argument("path", metavar="PATH")
    review_openapi_parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="emit the canonical heel.review.v1 JSON envelope",
    )

    init = sub.add_parser("init", help="initialize local Heel artifacts")
    init.add_argument("--from-openapi", dest="from_openapi", help="local OpenAPI JSON/YAML file to convert into a ProductModel draft")
    init.add_argument("--out", required=True, help="ProductModel JSON output path")

    sc = sub.add_parser("scope", help="manage authorization scopes (creation is out-of-band, human-only)")
    scs = sc.add_subparsers(dest="scmd", required=True)
    sccreate = scs.add_parser("create", help="OUT-OF-BAND human scope creation (requires --confirm)")
    sccreate.add_argument("--target", action="append", required=True, help="allowlisted target id (repeatable)")
    sccreate.add_argument("--operator", default=None, help="approver identity (defaults to current user)")
    sccreate.add_argument("--ttl", type=int, default=7 * 24 * 3600)
    sccreate.add_argument("--confirm", action="store_true", help="explicit human confirmation (required)")
    scs.add_parser("list", help="list scopes (read; no secrets)")

    from .modes import MODES

    runp = sub.add_parser("run", help="run an abuse sim or static mode workflow")
    runp.add_argument("--mode", choices=sorted(MODES), default="synthetic")
    runp.add_argument("--scope")
    runp.add_argument("--target")
    runp.add_argument("--before", help="before ProductModel JSON for --mode launch-review")
    runp.add_argument("--after", help="after ProductModel JSON for --mode launch-review")
    runp.add_argument("--canary-account", action="append", help="canary account metadata for staging modes")
    runp.add_argument("--scenario", action="append")
    runp.add_argument("--packs", help="comma-separated scenario packs to run")
    runp.add_argument("--economic", action="store_true", help="include economic severity in the run output")
    runp.add_argument("--economic-assumptions", help="optional EconomicAssumptions JSON file")

    for name in ("findings", "coverage", "log"):
        p = sub.add_parser(name)
        p.add_argument("--run", required=True)
    report = sub.add_parser("report", help="print a run report with optional economic severity")
    report.add_argument("--run", required=True)
    report.add_argument("--economic", action="store_true")
    report.add_argument("--economic-assumptions", help="optional EconomicAssumptions JSON file")
    scn = sub.add_parser("scenarios")
    scn.add_argument("--filter")
    scn.add_argument("--pack")
    scenario = sub.add_parser("scenario", help="validate and explain declarative scenario pack entries")
    scenario_sub = scenario.add_subparsers(dest="scenariocmd", required=True)
    scenario_validate = scenario_sub.add_parser("validate", help="validate a scenario JSON object or list")
    scenario_validate.add_argument("path")
    scenario_explain = scenario_sub.add_parser("explain", help="explain a known scenario id")
    scenario_explain.add_argument("scenario_id")
    imp = sub.add_parser("import", help="validate sanitized target import models; no live probing")
    imps = imp.add_subparsers(dest="icmd", required=True)
    impv = imps.add_parser("validate", help="validate a ProductModel JSON file")
    impv.add_argument("path")
    impo = imps.add_parser("openapi", help="convert a local OpenAPI spec into a ProductModel JSON draft")
    impo.add_argument("path")
    impo.add_argument("--out", required=True, help="ProductModel JSON output path")
    incident = sub.add_parser("incident", help="turn sanitized abuse incidents into local scenario drafts")
    incidents = incident.add_subparsers(dest="incmd", required=True)
    incident_import = incidents.add_parser("import", help="validate and store a sanitized incident JSON file")
    incident_import.add_argument("path")
    incident_draft = incidents.add_parser("draft-scenario", help="write and print a local scenario draft")
    incident_draft.add_argument("incident_id")
    incident_reg = incidents.add_parser("add-regression", help="write and print a canary-only regression draft")
    incident_reg.add_argument("incident_id")
    incident_review = incidents.add_parser("review", help="print exactly what incident drafts would add")
    incident_review.add_argument("incident_id")
    launch = sub.add_parser("launch-review", help="compare ProductModel changes before launch")
    launch_inputs = launch.add_mutually_exclusive_group(required=True)
    launch_inputs.add_argument("--diff", help="git revision range containing a ProductModel JSON change")
    launch_inputs.add_argument("--before", help="ProductModel JSON before the launch change")
    launch.add_argument("--after", help="ProductModel JSON after the launch change")
    reg = sub.add_parser("regress", help="turn findings into reusable abuse regression tests")
    regs = reg.add_subparsers(dest="rcmd", required=True)
    regadd = regs.add_parser("add", help="create a regression from a stored finding")
    regadd.add_argument("--run", required=True)
    regadd.add_argument("--vector", required=True)
    regadd.add_argument("--name", required=True)
    regs.add_parser("list", help="list abuse regressions")
    regrun = regs.add_parser("run", help="run stored regressions within an existing signed scope")
    regrun.add_argument("--target", required=True)
    regrun.add_argument("--scope", required=True)
    regexp = regs.add_parser("export", help="export regression specs and results")
    regexp.add_argument("--format", choices=["json"], required=True)
    controls = sub.add_parser("controls", help="simulate candidate controls for stored or imported findings")
    control_sub = controls.add_subparsers(dest="ccmd", required=True)
    control_sim = control_sub.add_parser("simulate", help="offline control simulation; no live target is touched")
    control_input = control_sim.add_mutually_exclusive_group(required=True)
    control_input.add_argument("--vector", help="stored vector id to simulate")
    control_input.add_argument("--finding-json", help="path to one finding JSON object")
    control_input.add_argument("--run", help="stored run id to simulate")

    args = ap.parse_args(argv)
    if args.cmd is None:
        ap.print_help()
        return 0
    if args.cmd == "doctor":
        return _doctor()
    if args.cmd == "eval":
        from .heldout_eval import heldout_eval
        print(heldout_eval().get("headline", "(no held-out test set installed)"))
        return 0
    if args.cmd == "bench":
        from .bench import format_report, run_benchmark
        report = run_benchmark(blind_targets=args.blind_targets, blind_workers=args.workers)
        output_format = "json" if args.bcmd == "run" else args.format
        print(format_report(report, output_format))
        return 0
    if args.cmd == "review" and args.reviewcmd == "openapi":
        return _review_openapi_file(args.path, as_json=args.as_json)
    if args.cmd == "init":
        if not args.from_openapi:
            print("OpenAPI import: FAIL (--from-openapi is required for init)")
            return 2
        return _openapi_import(args.from_openapi, args.out)
    if args.cmd == "launch-review":
        if not args.diff and not args.after:
            print("Launch review: FAIL (--after is required with --before)")
            return 2
        return _launch_review(args)
    if args.cmd == "import" and args.icmd == "validate":
        return _import_validate(args.path)
    if args.cmd == "import" and args.icmd == "openapi":
        return _openapi_import(args.path, args.out)
    if args.cmd == "scenario" and args.scenariocmd == "validate":
        return _scenario_validate(args.path)
    if args.cmd == "scenario" and args.scenariocmd == "explain":
        return _scenario_explain(args.scenario_id)

    if args.cmd == "incident":
        from .incident import IncidentError, add_regression_draft, draft_scenario, import_incident, review_incident
        try:
            if args.incmd == "import":
                print(json.dumps(import_incident(args.path), indent=2, default=str))
                return 0
            if args.incmd == "draft-scenario":
                print(json.dumps(draft_scenario(args.incident_id), indent=2, default=str))
                return 0
            if args.incmd == "add-regression":
                print(json.dumps(add_regression_draft(args.incident_id), indent=2, default=str))
                return 0
            if args.incmd == "review":
                print(json.dumps(review_incident(args.incident_id), indent=2, default=str))
                return 0
        except IncidentError as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "regress":
        from .regressions import (
            add_regression_from_finding,
            export_regressions,
            resolve_target_argument,
            run_regressions,
        )
        srv = _server()
        caller = _caller()
        try:
            if args.rcmd == "add":
                reg = add_regression_from_finding(srv.store, args.run, args.vector, args.name)
                print(json.dumps({"regression": reg}, indent=2, default=str))
                return 0
            if args.rcmd == "list":
                print(json.dumps({"regressions": srv.store.list_regressions()}, indent=2, default=str))
                return 0
            if args.rcmd == "run":
                target = resolve_target_argument(args.target)
                results = run_regressions(srv.store, srv, args.scope, target, caller)
                print(json.dumps({"results": results}, indent=2, default=str))
                return 0
            if args.rcmd == "export":
                print(json.dumps(export_regressions(srv.store), indent=2, default=str))
                return 0
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "controls" and args.ccmd == "simulate":
        from .control_simulator import load_finding_json, simulate_finding, simulate_run
        srv = _server()
        try:
            if args.finding_json:
                finding, options = load_finding_json(args.finding_json)
                print(json.dumps(simulate_finding(finding, **options), indent=2, default=str))
                return 0
            if args.vector:
                vector = srv.store.find_vector(args.vector)
                if not vector:
                    raise ValueError(f"unknown vector_id '{args.vector}'")
                print(json.dumps(simulate_finding(vector), indent=2, default=str))
                return 0
            if args.run:
                if not srv.store.get_run(args.run):
                    raise ValueError(f"unknown run_id '{args.run}'")
                print(json.dumps(simulate_run(srv.store.get_findings(args.run), run_id=args.run), indent=2, default=str))
                return 0
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "scope" and args.scmd == "create":
        if not args.confirm:
            print("REFUSED: scope creation is an out-of-band human action and requires --confirm.")
            print("This is intentional (§10.1): no agent/MCP/REST path can create or widen a scope.")
            return 2
        operator = args.operator or _caller()
        s = scopemod.create_scope(args.target, operator, ttl_seconds=args.ttl,
                                  data_mode=DataHandlingMode.SYNTHETIC_ONLY)
        print(json.dumps({"created_scope": s.scope_id, "allowlist": s.target_allowlist,
                          "operator": s.operator_confirmation, "expiry": s.expiry}, indent=2))
        return 0

    if args.cmd == "scope" and args.scmd == "list":
        srv = _server()
        print(json.dumps(srv.heel_list_scopes({}, _caller()), indent=2))
        return 0

    if args.cmd == "run":
        return _run_with_mode(args)

    srv = _server()
    caller = _caller()
    if args.cmd == "report":
        try:
            print(json.dumps(_report(srv, args.run, caller, economic=args.economic,
                                     economic_assumptions=args.economic_assumptions),
                             indent=2, default=str))
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1
        return 0
    if args.cmd == "findings":
        print(json.dumps(srv.heel_get_findings({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "coverage":
        print(json.dumps(srv.heel_get_coverage({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "log":
        print(json.dumps(srv.heel_get_containment_log({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "scenarios":
        print(json.dumps(srv.heel_list_scenarios({"filter": args.filter, "pack": args.pack}, caller), indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
