"""
HEEL — CLI (spec §2: a thin client over the same capability; PLUS the out-of-band
human-only scope path). `heel scope create` is the ONLY way to mint a scope, requires
explicit `--confirm`, and writes a signed scope file. Everything else calls the MCP capability.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os

from . import __version__
from . import scope as scopemod
from .contracts import DataHandlingMode
from .mcp_server import HeelServer
from .store import Store


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
        ok.append("signing key: external (HEEL_SIGNING_KEY) — production posture ✓")
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
    home = scopemod.heel_home()
    os.makedirs(home, exist_ok=True)
    return HeelServer(Store(os.path.join(home, "heel.db")))


def _caller():
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:operator"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="heel", description="HEEL — agent-native abuse-simulation tool")
    ap.add_argument("--version", action="version", version=f"heel {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("doctor", help="self-check: install, data dir, signing-key posture, capability")
    sub.add_parser("eval", help="run the honest held-out detection eval and print the headline")

    sc = sub.add_parser("scope", help="manage authorization scopes (creation is out-of-band, human-only)")
    scs = sc.add_subparsers(dest="scmd", required=True)
    sccreate = scs.add_parser("create", help="OUT-OF-BAND human scope creation (requires --confirm)")
    sccreate.add_argument("--target", action="append", required=True, help="allowlisted target id (repeatable)")
    sccreate.add_argument("--operator", default=None, help="approver identity (defaults to current user)")
    sccreate.add_argument("--ttl", type=int, default=7 * 24 * 3600)
    sccreate.add_argument("--confirm", action="store_true", help="explicit human confirmation (required)")
    scs.add_parser("list", help="list scopes (read; no secrets)")

    runp = sub.add_parser("run", help="run an abuse sim within a scope (thin client over MCP)")
    runp.add_argument("--scope", required=True)
    runp.add_argument("--target", required=True)
    runp.add_argument("--scenario", action="append")

    for name in ("findings", "coverage", "log"):
        p = sub.add_parser(name)
        p.add_argument("--run", required=True)
    scn = sub.add_parser("scenarios"); scn.add_argument("--filter")

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

    srv = _server()
    caller = _caller()
    if args.cmd == "run":
        try:
            r = srv.heel_run({"scope_id": args.scope, "target": args.target, "scenario_ids": args.scenario}, caller)
            print(json.dumps(r, indent=2))
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
        print(json.dumps(srv.heel_list_scenarios({"filter": args.filter}, caller), indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
