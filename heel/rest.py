"""
HEEL — thin REST API beneath the MCP server (spec §2). For non-MCP automation.

This is a THIN CLIENT over the SAME `HeelServer` capability the MCP server uses — so the §10
authorization gate is IDENTICAL (build the capability once). There is **no scope-creation/widening
route** (POST /scopes returns 405 + a security log); scopes are human-only, out-of-band. The
caller identity is the self-asserted `X-Heel-Caller` header (the auth gate never depends on it).
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import scope as scopemod
from .mcp_server import HeelServer, ToolError
from .store import Store


def make_handler(server: HeelServer):
    class Handler(BaseHTTPRequestHandler):
        def _caller(self):
            return "rest:" + (self.headers.get("X-Heel-Caller") or "unnamed-client")

        def _send(self, code, obj):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def _call(self, tool, args):
            try:
                self._send(200, server.call_tool(tool, args, self._caller()))
            except ToolError as e:
                self._send(403, {"error": str(e), "code": e.code})  # rejection already logged by the tool

        def log_message(self, *a):  # quiet
            pass

        def do_GET(self):
            p = self.path.split("?")[0].strip("/").split("/")
            if p == ["scenarios"]:
                return self._call("heel_list_scenarios", {})
            if p == ["scopes"]:
                return self._call("heel_list_scopes", {})
            if len(p) == 2 and p[0] == "runs":
                return self._call("heel_run_status", {"run_id": p[1]})
            if len(p) == 3 and p[0] == "runs":
                tool = {"findings": "heel_get_findings", "coverage": "heel_get_coverage",
                        "containment": "heel_get_containment_log"}.get(p[2])
                if tool:
                    return self._call(tool, {"run_id": p[1]})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            p = self.path.split("?")[0].strip("/").split("/")
            if p == ["scopes"]:
                # scope creation/widening is NEVER reachable via an API — human-only, out-of-band
                server._security_log(self._caller(), "reject_rest_scope_mutation",
                                     {"path": self.path, "reason": "scope creation is out-of-band, human-only"})
                return self._send(405, {"error": "scope creation is out-of-band and human-only; "
                                                 "use the CLI with --confirm. No API can mint or widen a scope."})
            if p == ["runs"]:
                return self._call("heel_run", self._body())
            if len(p) == 3 and p[0] == "vectors" and p[2] == "control":
                return self._call("heel_propose_control", {"vector_id": p[1]})
            self._send(404, {"error": "not found"})

    return Handler


def serve(port: int = 8780):  # pragma: no cover - exercised via real HTTP clients
    os.makedirs(scopemod.heel_home(), exist_ok=True)
    server = HeelServer(Store(os.path.join(scopemod.heel_home(), "heel.db")))
    httpd = HTTPServer(("127.0.0.1", port), make_handler(server))
    print(f"HEEL REST API on http://127.0.0.1:{port}  (thin client over the MCP capability; same auth gate)")
    httpd.serve_forever()


if __name__ == "__main__":
    serve()
