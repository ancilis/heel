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

from . import scope as scopemod
from .contracts import DataHandlingMode
from .mcp_server import HeelServer
from .store import Store


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
    ap = argparse.ArgumentParser(prog="heel", description="HEEL — abuse-simulation tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

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
