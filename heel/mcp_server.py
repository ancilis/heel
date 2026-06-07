"""
HEEL — MCP server (spec §2). The CANONICAL surface; everything else is a thin client.

Exposes the §2 tools (consumption + execution only). **No scope-mutation tool exists** —
scope creation/widening/limit-relaxation are human-only out-of-band actions (scope.create_scope,
CLI). The server only READS and VERIFIES scopes. This is the agent-caller safety model (§10.1):
the calling agent is treated as a possibly-prompt-injected confused deputy.

Enforcement (all server-side, regardless of what the caller requests):
  * `heel_run` rejects an unknown `scope_id`, an invalid/expired/tampered scope, or a `target`
    not in that scope's signed allowlist — and LOGS the rejection with the caller identity.
  * Any call to a tool that is not in the registry (e.g. a forged `heel_create_scope` /
    `heel_widen_scope`) returns "unknown tool" AND is logged as a security event.
  * Injected instructions in arguments are DATA, never executed: `target` is matched literally
    against the allowlist; extra/unknown arguments are ignored; the allowlist + limits come
    ONLY from the stored signed scope.
  * Every run records the invoking CallerContext in the immutable ContainmentLog.
"""
from __future__ import annotations

import json
import sys
import time

from . import scope as scopemod
from .containment import ContainmentLog, run_is_logged, verify_chain
from .contracts import CallerContext
from .control import propose_control
from .orchestrator import run_abuse
from .scenarios import list_scenarios
from .store import Store

SERVER_INFO = {"name": "heel", "version": "1.1.0"}

# Tools exposed over MCP. Scope-mutation tools are ABSENT by construction (§10.1).
TOOL_SCHEMAS = [
    {"name": "heel_list_scenarios", "description": "List the abuse scenario library (read).",
     "inputSchema": {"type": "object", "properties": {"filter": {"type": "string"}}}},
    {"name": "heel_list_scopes", "description": "List authorized scopes (read; never returns secrets). Scopes are created out-of-band by a human; agents cannot mint or widen them.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "heel_run", "description": "Start an abuse run WITHIN an existing scope. Rejected if scope_id is unknown or target is not in the scope allowlist.",
     "inputSchema": {"type": "object", "required": ["scope_id", "target"],
                     "properties": {"scope_id": {"type": "string"}, "target": {"type": "string"},
                                    "scenario_ids": {"type": "array", "items": {"type": "string"}},
                                    "agent_classes": {"type": "array", "items": {"type": "string"}},
                                    "budget": {"type": "object"}}}},
    {"name": "heel_run_status", "description": "Run progress.",
     "inputSchema": {"type": "object", "required": ["run_id"], "properties": {"run_id": {"type": "string"}}}},
    {"name": "heel_get_findings", "description": "The AbuseVectors for a run.",
     "inputSchema": {"type": "object", "required": ["run_id"], "properties": {"run_id": {"type": "string"}}}},
    {"name": "heel_get_coverage", "description": "Coverage, false-positive rate, severity calibration (meaningful vs synthetic targets).",
     "inputSchema": {"type": "object", "required": ["run_id"], "properties": {"run_id": {"type": "string"}}}},
    {"name": "heel_propose_control", "description": "Recommended control + estimated exploitability reduction for a vector.",
     "inputSchema": {"type": "object", "required": ["vector_id"], "properties": {"vector_id": {"type": "string"}}}},
    {"name": "heel_get_containment_log", "description": "The immutable audit trail of what HEEL did (with caller).",
     "inputSchema": {"type": "object", "required": ["run_id"], "properties": {"run_id": {"type": "string"}}}},
]
TOOL_NAMES = {t["name"] for t in TOOL_SCHEMAS}


class ToolError(Exception):
    def __init__(self, message, code="rejected"):
        super().__init__(message)
        self.code = code


class HeelServer:
    def __init__(self, store: Store | None = None, classify_enabled: bool = False):
        self.store = store or Store()
        self.runs: dict[str, object] = {}
        self.classify_enabled = classify_enabled

    def _security_log(self, caller: str, action: str, detail: dict):
        ContainmentLog(self.store, "security", caller).append(action, detail)

    # -- tool handlers (caller identity always passed in) -------------------- #
    def heel_list_scenarios(self, args, caller):
        scs = list_scenarios(args.get("filter"))
        return {"scenarios": [{"id": s.id, "category": s.category.value, "objective": s.objective,
                               "applies_when": s.applies_when.value, "source": s.source.value} for s in scs]}

    def heel_list_scopes(self, args, caller):
        return {"scopes": [s.public_view() for s in scopemod.load_scopes()]}

    def heel_run(self, args, caller):
        scope_id = args.get("scope_id")
        target = args.get("target")
        # 1) scope must exist (human-created, out-of-band)
        scope = scopemod.get_scope(scope_id) if scope_id else None
        if scope is None:
            self._security_log(caller, "reject_run", {"reason": "unknown scope", "scope_id": scope_id, "target": target})
            raise ToolError(f"unknown scope_id '{scope_id}': scopes are created out-of-band by a human and cannot be minted via this API")
        # 2) scope must verify (signature intact / bound / not expired)
        ok, reason = scopemod.verify(scope)
        if not ok:
            self._security_log(caller, "reject_run", {"reason": reason, "scope_id": scope_id})
            raise ToolError(f"scope invalid: {reason}")
        # 3) target must be in the SIGNED allowlist — injected/forged targets are rejected here
        if not scopemod.target_in_scope(scope, target):
            self._security_log(caller, "reject_run",
                               {"reason": "target not in scope allowlist", "scope_id": scope_id,
                                "requested_target": target, "allowlist": scope.target_allowlist})
            raise ToolError(f"target '{target}' is not in scope '{scope_id}' allowlist {scope.target_allowlist}; "
                            f"this server cannot widen a scope (human-only, out-of-band)")
        # 4) ENFORCE the signed scope's resource limits server-side (not just store them)
        limits = scope.rate_and_resource_limits or {}
        maxreq = limits.get("max_requests")
        if maxreq is not None and self.store.scope_run_count(scope_id) >= maxreq:
            self._security_log(caller, "reject_run", {"reason": "scope max_requests exhausted",
                                                      "scope_id": scope_id, "limit": maxreq})
            raise ToolError(f"scope '{scope_id}' resource limit (max_requests={maxreq}) exhausted; "
                            f"a new scope must be created out-of-band")
        # accountability: log any caller args we deliberately ignore (cannot widen scope)
        ignored = [k for k in args if k not in ("scope_id", "target", "scenario_ids", "agent_classes", "budget")]
        if ignored:
            self._security_log(caller, "ignored_args", {"scope_id": scope_id, "ignored": ignored,
                                                        "note": "extra args cannot affect scope/limits"})
        # authorized → run within the scope's limits
        cc = CallerContext(caller_identity=caller, scope_id=scope_id, ts=time.time())
        rr = run_abuse(scope, target, args.get("scenario_ids"), cc, self.store,
                       classify_enabled=self.classify_enabled, agent_classes=args.get("agent_classes"))
        self.runs[rr.run_id] = rr
        return {"run_id": rr.run_id, "status": rr.status}

    def heel_run_status(self, args, caller):
        row = self.store.get_run(args.get("run_id"))
        if not row:
            raise ToolError("unknown run_id")
        return {"run_id": row["run_id"], "status": row["status"], "target": row["target"], "caller": row["caller"]}

    def heel_get_findings(self, args, caller):
        return {"findings": self.store.get_findings(args.get("run_id"))}

    def heel_get_coverage(self, args, caller):
        row = self.store.get_run(args.get("run_id"))
        if not row or not row["coverage"]:
            raise ToolError("no coverage for run (synthetic-target backtest only)")
        return {"coverage": json.loads(row["coverage"])}

    def heel_propose_control(self, args, caller):
        v = self.store.find_vector(args.get("vector_id"))
        if not v:
            raise ToolError("unknown vector_id")
        return propose_control(v)

    def heel_get_containment_log(self, args, caller):
        run_id = args.get("run_id")
        ok, msg = verify_chain(self.store, run_id)
        return {"entries": self.store.containment_log(run_id), "chain_valid": ok, "chain_status": msg,
                "run_is_logged": run_is_logged(self.store, run_id)}

    # -- MCP dispatch -------------------------------------------------------- #
    def call_tool(self, name, args, caller):
        if name not in TOOL_NAMES:
            # an unknown tool (e.g. a forged scope-mutation tool) — reject + log a security event
            self._security_log(caller, "reject_unknown_tool",
                               {"requested_tool": name, "reason": "tool not in registry; scope mutation is human-only out-of-band"})
            raise ToolError(f"unknown tool '{name}': HEEL exposes no scope-creation/widening tool; "
                            f"scopes are human-only and out-of-band", code="unknown_tool")
        return getattr(self, name)(args or {}, caller)

    def dispatch(self, method, params, session):
        params = params or {}
        if method == "initialize":
            # caller identity is the transport's SELF-ASSERTED clientInfo (not a verified identity);
            # the auth gate never depends on it — it only attributes runs (red-team accountability note).
            session["caller"] = "mcp:" + (params.get("clientInfo") or {}).get("name", "unnamed-client")
            return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return {"tools": TOOL_SCHEMAS}
        if method == "tools/call":
            caller = session.get("caller", "unauthenticated:no-handshake")
            name = params.get("name")
            try:
                result = self.call_tool(name, params.get("arguments") or {}, caller)
                return {"content": [{"type": "text", "text": json.dumps(result, default=str)}],
                        "structuredContent": result}
            except ToolError as e:
                return {"content": [{"type": "text", "text": f"REJECTED: {e}"}],
                        "isError": True, "structuredContent": {"error": str(e), "code": e.code}}
        raise ToolError(f"unknown method {method}", code="method_not_found")


# --------------------------------------------------------------------------- #
# stdio JSON-RPC loop for real MCP clients (Claude Desktop / Cursor / CI)
# --------------------------------------------------------------------------- #
def handle_line(server, session, line: str):
    """Process one JSON-RPC line; return a response dict (or None for a handled notification).
    NEVER raises — a malformed or hostile request yields a JSON-RPC error, never a crashed server."""
    line = line.strip()
    if not line:
        return None
    try:
        req = json.loads(line)
    except Exception:
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
    if not isinstance(req, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    rid = req.get("id")
    try:
        result = server.dispatch(req.get("method"), req.get("params") or {}, session)
        if result is None and rid is None:
            return None  # notification
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    except ToolError as e:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": str(e), "data": {"code": e.code}}}
    except Exception as e:  # never let one bad request take down the server
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": f"internal error: {e}"}}


def main():  # pragma: no cover - exercised via real MCP clients
    import os
    scopemod.ensure_home()
    store = Store(os.path.join(scopemod.heel_home(), "heel.db"))
    server = HeelServer(store)
    session = {"caller": "stdio-client"}
    for line in sys.stdin:
        resp = handle_line(server, session, line)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
