# HEEL — Production launch-readiness red-team (v1.0.0)

3-agent security review of the packaged tool. **Launch blockers: NONE — verdict SHIP.**
Packaging/supply-chain clean (zero deps verified); auth gate has no bypass; HMAC sound + fail-closed.
The REST-surface HIGH/MEDIUM findings (DNS-rebinding, CSRF, data-dir perms) were FIXED pre-tag.

## Release engineer + supply-chain auditor

**launch_blocker:** False  ·  **Verdict:** SHIP. The release is packaging-correct and supply-chain-clean: the wheel ships all required runtime data (scenarios_lib + both heldout JSONs) and zero secrets/tests, all three entry points resolve and run, metadata/license/version are fully consistent, the zero-deps claim is verified true (all stdlib), and the build is reproducible. No launch-blocking findings. Two low-severity CI hardening gaps noted below; recommend addressing post-launch.

### [LOW] CI smoke test does not exercise heel-mcp / heel-rest entry points

**Evidence:** .github/workflows/ci.yml:42-43 — the `package` job, after installing the wheel into a clean venv, only runs `/tmp/v/bin/heel scenarios` and a heldout_eval import. It never invokes the heel-mcp or heel-rest console scripts, so a regression that broke those entry points (e.g. a bad import in rest.py/mcp_server.py reachable only at script startup) could pass CI. (Mitigated: I manually verified both import/resolve cleanly this build, and unittest covers HeelServer via the dispatch path.)

**Recommendation:** Add to the package job smoke step: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | /tmp/v/bin/heel-mcp` (assert it returns the 8 tools) and a backgrounded `heel-rest` + curl /scenarios with a kill, to exercise both console_scripts against the installed wheel. Non-blocking; post-launch.

### [LOW] Unit tests run against source tree, not the installed wheel

**Evidence:** .github/workflows/ci.yml:22-23 — the `test` job runs `python -m unittest discover -s tests` with no `pip install`, so the 52 tests execute against the repo source, not the built wheel. A packaging defect that only manifests post-install (e.g. a data file missing from package-data, or a relative-import-vs-namespace issue) would not be caught by the test job; only the separate `package` job's narrow smoke test would. The package-data correctness is currently guarded solely by the single heldout_eval assertion at ci.yml:43.

**Recommendation:** Either run the test suite once against the installed wheel in the `package` job (e.g. `/tmp/v/bin/python -m unittest discover -s tests`), or add explicit assertions in the smoke step that both heldout JSONs and community.json load from importlib.resources. Non-blocking; raises confidence that package-data stays correct as files are added.

## Offensive security engineer — pre-launch pentest of AUTH model + network surfaces (HEEL v1.0.0)

**launch_blocker:** False  ·  **Verdict:** The non-negotiable safety spine holds: the capability/authorization gate has no scope create/widen/escape bypass on any caller path, and the HMAC scheme is cryptographically sound and fail-closed against a no-key attacker. Ship the core. However, the heel-rest surface ships with browser-reachable DNS-rebinding + CSRF + no per-run authorization, and current SECURITY.md guidance ('front it with a gateway') is necessary but understates these specific browser vectors. Recommend gating the launch on a small REST hardening pass (Host allowlist + reject non-simple/disallowed Origins + a loopback bind note) OR shipping heel-rest opt-in/off-by-default with an expanded warning. The MCP server (canonical surface) and CLI are launch-ready as-is.

### [HIGH] heel-rest has no Host-header validation → DNS-rebinding lets any web page read every route
*Location:* `/Users/hellohelloalbus/heel/heel/rest.py:20-75 (Handler.do_GET/do_POST; serve() binds 127.0.0.1:81)`

**Evidence:** Live: `curl -H 'Host: attacker.example.com' http://127.0.0.1:8799/scopes` returned the full scope list unchanged. No code path inspects self.headers['Host'] or Origin. A malicious page that rebinds a hostname it controls to 127.0.0.1 becomes same-origin with heel-rest and can read /scopes, /runs/<id>/findings, /coverage, /containment from the victim's browser. SECURITY.md mentions 'no transport auth, front it with a gateway' but does not call out the DNS-rebinding/browser vector specifically.

**Recommendation:** Reject requests whose Host header is not in {127.0.0.1[:port], localhost[:port]} (return 421/403). Optionally reject requests carrying an Origin header (a CLI/automation client never sends one). Add an explicit DNS-rebinding note to the SECURITY.md REST bullet.

### [HIGH] POST /runs is CSRF-able and triggers state-changing, resource-consuming runs from any origin
*Location:* `/Users/hellohelloalbus/heel/heel/rest.py:69-70 (do_POST → heel_run); _body() at rest.py:33-35`

**Evidence:** Live: `curl -X POST -H 'Content-Type: text/plain' -H 'Host: evil.example.com' http://127.0.0.1:8799/runs -d '{"scope_id":...,"target":"synthetic-ai"}'` returned {"run_id":...,"status":"complete"}. text/plain is a CORS 'simple request' → no preflight, so a cross-origin <form>/fetch from any web page triggers a run with no token/auth. The returned run_id then unlocks the read routes. Confined to synthetic targets in v1, but is a launch-time foothold + the pattern carries forward to real-target adapters.

**Recommendation:** Require a non-simple content type or a CSRF/double-submit token on POST /runs, and apply the same Host/Origin checks as above. At minimum document that heel-rest must never be reachable by a browser context.

### [MEDIUM] No per-run/per-caller authorization on read routes — any caller reads any run by run_id
*Location:* `/Users/hellohelloalbus/heel/heel/mcp_server.py:131-150 (heel_get_findings/coverage/containment); /Users/hellohelloalbus/heel/heel/rest.py:52-58`

**Evidence:** Live: `curl -H 'X-Heel-Caller: totally-different-agent' http://127.0.0.1:8799/runs/<otherCallersRunId>/findings` returned the other caller's findings. The handlers take only run_id and never check it against the requesting caller. X-Heel-Caller / MCP clientInfo are self-asserted (acknowledged at mcp_server.py:166-167) and used only for attribution, so there is effectively no read-authz. Future real-target findings would be cross-readable by any local caller.

**Recommendation:** Treat run results as caller-scoped where it matters, or explicitly document that all local callers share one trust domain and run data is not confidential between them. Reassess before real-target adapters land.

### [MEDIUM] Default co-located signing key collapses the trust boundary to filesystem-write on .heel/
*Location:* `/Users/hellohelloalbus/heel/heel/scope.py:32-50 (_signing_key auto-creates HEEL_HOME/signing.key)`

**Evidence:** Live full forge: read HEEL_HOME/signing.key off disk → create_scope(['synthetic-ai',...], 'human:kevin') → verify() ok → MCP heel_run accepted it end-to-end (status complete), with no human and no --confirm. This is documented as expected (scope.py:33-37 D-009, SECURITY.md hardening checklist), so it is residual risk, not a new bypass — but the default ships co-located and `heel doctor` only warns.

**Recommendation:** Keep the warning, and additionally: enforce os.chmod(HEEL_HOME, 0o700) on create (SECURITY.md asks for it but nothing enforces it), and consider making `heel doctor` exit non-zero (or refusing real-target modes) when the key is co-located so the production posture is opt-out, not opt-in.

### [LOW] Auto-minting a signing key on absence weakens 'fail-closed on missing key' expectations (availability/forgery footgun)
*Location:* `/Users/hellohelloalbus/heel/heel/scope.py:42-50`

**Evidence:** _signing_key() silently creates a fresh random key whenever signing.key is absent. Confirmed: deleting the key makes all existing scopes fail verification (safe direction — they become unrunnable), but it also means an attacker with write access can delete + regenerate + re-sign scopes and re-chain the log under a new key with no error surfaced anywhere. If HEEL_SIGNING_KEY points to a path that is temporarily unavailable, the co-located fallback (HEEL_HOME/signing.key) silently engages.

**Recommendation:** When HEEL_SIGNING_KEY is set but its path is missing, fail closed (raise) rather than falling back to the co-located default. Log/emit a one-time warning when a new key is auto-generated so silent key rotation is detectable.

### [LOW] REST error responses reflect attacker-controlled input verbatim
*Location:* `/Users/hellohelloalbus/heel/heel/mcp_server.py:92 (and rest.py:41 passes str(e) through)`

**Evidence:** Live: POST /runs with scope_id '<script>alert(1)</script>' returned {"error":"unknown scope_id '<script>alert(1)</script>': ..."}. Content-Type is application/json so it is not an XSS sink by itself, but a downstream UI that renders the error as HTML would inherit a stored/reflected XSS.

**Recommendation:** Truncate/sanitize the echoed identifier in error strings, or note that consumers must not render API errors as HTML. Low priority given the JSON content type.

## auditor

**launch_blocker:** False  ·  **Verdict:** holds

### [LOW] held out descriptive

**Evidence:** zero exploit signatures

**Recommendation:** ship as is
