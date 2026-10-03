# Red-team report: plan-differential runner (T3)

Date: 2026-10-02. Branch `feat/plan-differential-runner` at `17ffd0e` (base `main` @ `844fc1f`).
Reviewer: Claude Fable 5.1, fresh session, adversarial review only. No product code, existing
test, other doc or artifact was edited. Blast radius: medium (network egress under scope).

Inputs read in full: the controlling brief, the run log, the final spec
(`docs/superpowers/specs/2026-10-02-plan-differential-runner.md`), `git diff main...HEAD`
for every product file, `heel/runner/plan_differential.py`, the transport, and the test
support and harness.

## 1. Result

Two breaks need T4. Every egress, scope, reservation, logging and attribution boundary
held under attack.

| # | Invariant / requirement | Verdict | Basis |
|---|---|---|---|
| I1 | Host confinement, redirects included | **PASS** | §4.1–4.4 |
| I2 | GET/HEAD and inventoried-route confinement, in the compiler | **PASS** | §4.9 (see D5, D8) |
| I3 | Verified signed scope | **PASS** | §4.5 |
| I4 | One-shot reserved attempt | **PASS** | §4.6 (see D3) |
| I5 | Credentials absent from reports, logs, findings, containment, and as plaintext bytes in `HEEL_HOME` | **PASS** as written | §4.7 (see D2) |
| I6 | Every request logged before the wire | **PASS** | §4.10 |
| I7 | Caller attribution | **PASS** | §4.10 |
| I8 | Chain integrity | **PASS** | §4.10 (see D7) |
| R9 | Total request budget | **PASS** | §4.10 (see D6) |
| R10 | CLI-only entry, no MCP or REST | **PASS** | §4.12 |
| R11 | Fail-closed predicates; a 2xx denial body is never parity (brief §1.5) | **FAIL** | D1 |
| R17 | Exactly two credential-bound requests per route, none anonymous | **PASS** | §4.11 |
| Spec §7 | Redacting store removes the credential "in raw form and in JSON-string-escaped form" | **FAIL** | D2 |
| R26/R27 | Release artifacts and package freshness | **PASS** | §4.12 |

I5 is marked PASS because the invariant as written (brief §1.8, spec §12) holds: no
report, log, finding or containment entry carries a credential, and a byte scan of
`HEEL_HOME`, stdout and stderr never found one on any path tried. D2 is the same area and
is a break of the storage contract behind it; the orchestrator may prefer to read that as
an I5 failure.

## 2. Defects

### D1 — A 2xx denial body yields an `observed` finding (MEDIUM, FAIL, needs T4)

`is_denial_envelope` (`heel/runner/plan_differential.py:155-166`) recognizes only
`error`/`errors` truthy, `ok`/`success` **identical to** `false`, and four flags
**identical to** `true`. A lower-plan 200 body that says "denied" any other way and keeps
the higher plan's key shape passes `body_superset`, which compares key paths only.

CONFIRMED, unit (`evaluate_plan_pair`), all return `finding / observed / body_superset`:

- spec vocabulary with non-boolean JSON: `"ok": 0`, `"ok": "false"`, `"success": 0`,
  `"denied": 1`, `"forbidden": "true"`, `"upgrade_required": 1`, `"payment_required": 1`
- JSend: `"status": "error"` or `"status": "fail"` with `"message": "Upgrade required"`
- also observed, not in the failing test: `"status": 402`, `{"code": "PLAN_REQUIRED",
  "message": …}`, nested `{"data": {"error": …}}`, `{"result": {"ok": false}}`,
  `"allowed": false`, `"Error"`/`"ERROR"` (case), `{"error": false, "error_code": "E402"}`

CONFIRMED, end to end through the CLI, transport, executor and store: lower
`{"ok": 0, "export_url": null, "rows": 0}` against higher
`{"ok": 1, "export_url": "https://…", "rows": 3}` stored a finding with
`evidence_state: observed`, `operator_declared: false`, exit 1. The same happened for
`success: 0`, `denied: 1`, `status: "error"` and nested `data.error`. The two canonical
forms (`"error": "…"`, `"ok": false`) were correctly `inconclusive / lower_denial_envelope`.

This contradicts brief §1.5 ("Error envelopes (2xx with denial body) must not count as
parity"). The spec's own tests pass because spec §8.3 defines the envelope by the same
closed list. `regress add` accepted the false finding; a later replay against such a body
would report `fail / still_reachable`.

Reproduction: `tests/test_runner_plan_differential_redteam.py`,
`test_redteam_break_d1_two_xx_denial_body_never_yields_observed` (9 cases) and
`test_redteam_break_d1_denial_body_observed_finding_through_the_cli`. 10 failing.

### D2 — An echoed credential in another JSON escaping is persisted (MEDIUM, FAIL, needs T4)

`_secret_forms` (`plan_differential.py:820-829`) redacts four serializations: raw,
`json.dumps`, `json.dumps` with `\/`, and `ensure_ascii=False`. JSON permits any character
as `\uXXXX`. When the target echoes the credential with such escapes, the evidence `.bin`
under `plan-runs/<attempt>/…/evidence/` holds a string that every JSON parser decodes to
the credential.

CONFIRMED with tokens `redteam+free/session=0001` / `redteam+pro/session=0001`:

| Echo form | Realistic source | Literal byte scan | Evidence decodes to credential |
|---|---|---|---|
| `+` written `+` | System.Text.Json default encoder | clean | yes, 2 files |
| `=` written `=` | HTML-safe encoders | clean | yes, 2 files |
| every character `\uXXXX` | ASCII-only encoders | clean | yes, 2 files |

With a token of only `[a-z0-9-]` just the last form applies. Reports, findings, both
containment logs, stdout and stderr stayed clean in all cases, which is why I5 as written
passes. Base64, hex, percent-encoded, reversed, split and truncated echoes also persist;
spec §16 already lists those as a known limit, so they are not counted as a break.

Reproduction: `test_redteam_break_d2_json_escaped_credential_echo_is_not_persisted`
(3 cases). 3 failing.

### D3 — An attempt ID is reusable after its reservation directory is removed (LOW)

CONFIRMED. `run_plan_differential(..., attempt="ab"*16)` ran; a plain replay raised
`PlanDifferentialRejected` with no request. After `shutil.rmtree(HEEL_HOME/plan-runs/<id>)`
the same call was accepted: two more requests, the `runs` row was replaced
(`Store.add_run` is `INSERT OR REPLACE`, `heel/store.py:41`; `ts` changed), the `findings`
table held two rows with the same `pdv-` id, and the containment log showed two
`run_start … run_complete` sequences under one run id (chain valid, 12 entries).
`_reserve_attempt` consults only the directory, not the existing run row.

Not reachable from the CLI (`attempt` is never passed) and it needs write access inside
`HEEL_HOME`, which the spec places inside the trust boundary. No test added. T4 optional.

### D4 — `body_superset` structural false positives (LOW–MEDIUM, design limit)

CONFIRMED, unit. All yield `observed`; all conform to spec §8.2, so none is in a failing test:

- lower has the same keys with every value `null`
- lower `{"rows": []}` against higher `{"rows": [1, 2, 3]}` (an empty array still adds `rows[]`)
- higher `{"a.b": "data"}` against lower `{"a": {"b": null}}` (dotted key collides with a path)
- higher `{"token": {…}}` against lower `{"token": null}` (no descent below secret-named keys)

The docs already say `observed` means "received every field". Field-level gating by
nulling values is common, so this deserves a decision before Phase 2, not a T4 fix.

### D5 — `_ScopedTransport` pins the route template, not the concrete route (LOW)

CONFIRMED by direct Python call with a real client over the loopback seam. For a compiled
pair `GET /exports/{id}`, a forged `PreparedAction` with route
`/exports/another-tenant-id` was sent (budget taken, request logged). A different
template, a path with an extra segment, `HEAD` on a `GET` pair, `POST`, an anonymous role
and another scenario were all `gate_rejected` with no connection; a missing credential was
`invalid_auth`. Reachable only by in-process code that bypasses the executor.

### D6 — Accounting labels can overstate or understate (INFO)

- CONFIRMED. `requests_sent` is the budget counter, not wire requests. With
  `--max-ops 5` and connects 0, 2, 4 failing: `requests_sent` 4, containment request
  entries 3, connect attempts 3, target requests 1. It also counts attempts that failed
  DNS before any connect. The error is always on the safe side of the cap.
- CONFIRMED. When the reservation directory was swapped for a symlink after the first
  request, the pair was reported `executor_rejected` / `not_started` although one request
  had been sent and logged.

### D7 — Chain limits (INFO, inherited)

- CONFIRMED. Deleting the newest row of the HMAC chain still verifies (17 of 18 entries).
  Truncating the tail of the runner's signed event chain also verifies. Edits, middle
  deletions and reordering are detected in both.
- CONFIRMED. The HMAC log records neither the runner key id nor any event digest, so the
  per-run Ed25519 chain is anchored only by `binding.json` in the same directory.

### D8 — `--routes` accepts a hand-written envelope (INFO, accepted by spec §3.3)

CONFIRMED. A copy of `routes.json` with an added `GET /admin/never-imported`, inserted in
canonical order, was planned and requested (two requests, correct `Host`). The file
cannot name another origin, method or unsafe template; see §4.9.

## 3. Method

All network probes used the loopback listener classes of `tests/plan_differential_support.py`
and the single seam `plan_differential._build_client`. Probe scripts were scratch files in
the session scratchpad and are not committed; the ones worth keeping are in the red-team
test file. Interpreter: `.venv/bin/python` (3.12.13), `TMPDIR` resolved to
`/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`.

Run of the committed file:

```
TMPDIR="$(cd "$(.venv/bin/python -c 'import tempfile; print(tempfile.gettempdir())')" && pwd -P)" \
    .venv/bin/python -m pytest -q tests/test_runner_plan_differential_redteam.py
```

Result: 13 failed (the D1 and D2 tests), 18 passed.

## 4. Attempts

Every row is CONFIRMED by a run in this session unless marked INFERRED.

### 4.1 Redirect to a second listener (required attack) — PASS

| Probe | Observed |
|---|---|
| Routes answering 301, 302, 303, 307, 308 with `Location: http://127.0.0.1:<second>/landing`, each for `GET` and `HEAD` | Every pair `inconclusive / transport:response_rejected`, disposition `failed`, no finding. One lower-plan request per pair, no higher-plan request. Second listener: 0 requests. Only `93.184.216.34:443` dialed. |
| 200 with `Refresh`, `Link`, `Location`, `Content-Location` pointing at the second listener | Treated as ordinary 200; second listener: 0 requests. |

Kept as `test_redteam_holds_every_redirect_status_is_refused_for_get_and_head`.

### 4.2 Host-header injection (required attack) — PASS

| Vector | Probe | Observed |
|---|---|---|
| Base URL | 62 forms, each with and without `--dry-run`, with `socket.getaddrinfo` patched to fail | See 4.3. No form produced a request with another `Host`. |
| OpenAPI operation data | 17 path keys (CRLF + `Host:`, request-line smuggle, `//evil/x`, absolute URL, `?`, `#`, `%0d%0a`, `..`, `\`, tab, space, non-ASCII, U+2028) plus root and operation `servers` naming another host | 11 rejected at `import-openapi`. Space, non-ASCII and U+2028 imported but refused before the wire (`transport:invalid_route`). `/api/@evil.example.com`, `/api/x;param`, `/api/x:80` were sent as plain paths. `servers` ignored. `Host` was the synthetic host on every request. |
| Route binding | 17 fixture values through `runner map` | CRLF, `/`, `?`, `#`, `%`, space, `\`, `@`, NUL, non-ASCII, `{id}`, `;`, empty: rejected at `map`. `.` and `..` mapped but never sent. `a:b` sent as `/items/a:b`. |
| Credential material | Tokens with `\r\nHost:`, `\n`, space, tab, DEL, non-ASCII, trailing CRLF, empty, 5 bytes | 0 requests in every case; pair `executor:containment_rejected` or `credential_unavailable`. |
| Direct Python seam | `TargetHTTPSClient.request` with forged `PreparedAction` routes and methods; constructor with CRLF, IPv6 and IPv4 origins | `invalid_route` / `invalid_origin`; no socket dialed. `_ScopedTransport` direct calls: see D5. |

Kept as `test_redteam_holds_credential_material_cannot_inject_a_header`.

### 4.3 Literals and normalization (required attack: IPv6 literal) — PASS

Rejected with exit 2, empty stdout, the fixed stderr line, no lookup and no request:
IPv4 dotted, decimal, hex and octal forms, `127.1`; bracketed IPv6 including
`[::1]`, `[::ffff:127.0.0.1]`, a global literal and a zone id; unbracketed `::1`;
`http://`; `HTTPS://`; `https:/`; `https:`; `https:///`; ports `:443`, `:8443`, `:`;
every userinfo form including `host@evil` and `evil@host`; trailing dot, double dot,
leading dot; punycode in any label; raw IDN; full-width letter; ideographic full stop;
zero-width space; trailing `/`, path, query, fragment; backslash; `%2e`; CRLF, tab,
leading and trailing space, NUL; `localhost`, `.localhost`, `.internal`, `.local`,
single label, `.test`, `.example`, `.invalid`, `.onion`; leading hyphen; underscore.

Accepted by the normalizer, and correct: an upper-case spelling of the allowlisted host
(lower-cased, executed); `1.1.1.dev`, `127.0.0.1.nip.io` and
`<allowlisted-host>.evil.example.com` (valid public names, not in the allowlist, so
forced dry-run, exit 3, 0 requests).

Allowlist entries `HOST` in upper case, with trailing dot, `*.heel.dev`, `heel.dev`,
a URL, `host:443`, `*` and `""` never matched the normalized host: forced dry-run, exit 3.

### 4.4 DNS rebinding (required attack) — PASS

Seam client with a scripted resolver, recording socket layer and scripted `getpeername`.

| Case | Reason | Requests seen | Dialed |
|---|---|---|---|
| Preflight set mixed public + `10.0.0.5`; loopback; metadata address; IPv4-mapped | `transport:unsafe_dns`, pair `not_started` | 0 | none |
| Attempt answer mixed public + private | `transport:unsafe_dns` | 0 | none |
| Attempt answer private only, NAT64, IPv4-mapped form of the pinned address, empty, resolver raises, decimal-integer form | `transport:unsafe_dns` | 0 | none |
| Attempt answer another public address; superset of public addresses | `transport:dns_changed` | 0 | none |
| Change to `127.0.0.1` between lower and higher | `transport:unsafe_dns` | 1 (lower only) | pinned only |
| Change to another public address between lower and higher | `transport:dns_changed` | 1 | pinned only |
| First connect fails, retry answer private or mixed | `transport:unsafe_dns` | 0 | pinned only, once |
| Change, then change back | stopped at the first change | 1 | pinned only |
| `getpeername` reports `127.0.0.1`; reports another address on the second connection | `transport:peer_mismatch` | 0; 1 | pinned only |

In every case the run stopped, later pairs were `not_started`, and `chain_valid` was
true. A peer mismatch is detected before any request byte is written. The unseamed
`_build_client` with `getaddrinfo` patched rejected mixed, private, loopback, mapped,
CGNAT, metadata, zero, ULA, 6to4 and Teredo answers with `unsafe_dns` and built the
default resolver, socket and TLS classes for a public answer.

INFERRED: behavior of a real resolver and real sockets. The seam proves nothing about
them; a run against a public staging host would.

Kept as `test_redteam_holds_dns_rebinding_between_preflight_retry_and_peer_check`.

### 4.5 Scope tamper (required attack) — PASS

Before the run, each gave exit 2, the fixed line and 0 requests: allowlist widened;
widened plus a signature copied from another scope; expiry extended, `Infinity`, string,
`null`; signature empty, `0`, `true`, `[]`, missing; limits raised; allowlist as a bare
string; a duplicate `target_allowlist` key; a valid scope copied over another scope's
file and requested by the other id; an unsigned shadow file with the same id sorted
first; scope file deleted. Restoring the original executed normally.

During the run:

| Edit | When | Requests after the edit |
|---|---|---|
| Widen allowlist, delete file, set expiry in the past, remove the host | on arrival of the first lower-plan request | 0: the higher-plan request was not sent |
| Widen | after the first pair's higher request | 0 |
| Corrupt signature | after the third request | 0 |
| A validly signed scope with a 1-second lifetime, slow target | expires between lower and higher | 0 |

Kept as `test_redteam_holds_scope_tamper_between_lower_and_higher_request` (the existing
I3 test edits only between pairs).

### 4.6 Attempt and grant replay, reservation (required attack) — PASS, see D3

- Same attempt ID twice: second call `PlanDifferentialRejected`, 0 requests.
- Reservation directory removed, renamed, or replaced by a file on arrival of the first
  request: 1 request total, exit 2, run row `rejected`, fixed stderr line.
- Replaced by a symlink to the moved directory: 1 request total, run stopped (D6).
- Removed after the run, then the same ID again: accepted (D3).
- `_ScopedTransport` with no reservation and grant replay are covered by the existing I4
  test, which I re-read and re-ran; I did not duplicate them.

### 4.7 Credential leaks (required attack) — I5 PASS as written, see D2

Tokens with `/ + = " \ & < > '` and the plain synthetic tokens. 28 pairs on routes echoing the
credential: 16 body encodings, a header, `Set-Cookie`, a 403 body, a 500 body, a
`text/plain` body, a JSON array, a 300 KB body, invalid UTF-8, a 302 `Location`, and the
other session's token.

- Plaintext bytes of either credential: found in **no** file under `HEEL_HOME` (database,
  WAL files, evidence, metadata, reports, both containment logs) and not in stdout,
  stderr, `heel findings --run`, `heel log --run` or `report.json`.
- Cross-echo of the other plan's token was redacted (both secrets are registered before
  the first request).
- Error paths, each scanned the same way and clean: missing higher credential (0
  requests); every connect failing; HMAC append failing after evidence was written (exit
  2, run `rejected`, `run_failed` logged); request-log append failing (0 requests);
  evidence write raising an exception whose text contained the raw body and headers
  (not surfaced); signed-event append failing; scope tamper after an echo.
- `x_api_key` and `cookie_jar` profiles: clean. A cookie value shorter than 8 bytes was
  refused with 0 requests.
- Non-plaintext forms that persist: D2 and the known limit of spec §16.

### 4.8 Predicate false positives (required attack) — FAIL, D1

Held: `NaN`/`Infinity` (unit: no finding; end to end: `transport:response_rejected`);
duplicate keys; empty bodies; non-JSON; BOM; invalid UTF-8; nesting depth 17 and 3000;
5000 keys; `HEAD` in every combination (only `held` or `inconclusive`, never a marker);
higher plan 403, 500 or denial envelope (`no_positive_control`); marker missing from the
higher body; marker in another field or as a superstring; executor outcome disagreeing
with the marker; non-completed dispositions; `executor_outcome=None`; an exception
raised inside `is_denial_envelope`, `_parsed`, `protected_content` or `key_paths`
(`predicate_error`, inconclusive).

Not held: D1 and D4. One note: `{"a": 1e999}` parses to a non-finite float and is accepted
by the transport and the predicate; it only affects a value, not a key path.

### 4.9 Compiler and CLI route confusion — PASS

35 `--routes` inputs. Rejected with exit 2 and 0 requests: `POST` and `DELETE`
entries; `get`; `"GET "`; a request-line smuggle in `method`; a route appended out of
canonical order; selector-shaped lists and objects; the bare `inventory` block; changed
`origin`, `namespace`, `verification_record_digest`, `schema_version`; extra envelope or
route keys; placeholders declared empty or invented; templates with CRLF, an absolute
URL, `//`, `..`, `?`; a duplicate route; an empty list; 2001 routes; a duplicate JSON key;
a `NaN` literal; a symlink; a directory; a missing file; `/dev/null`. A hard link to a
valid copy was accepted (regular file). The stored inventory was unchanged throughout.
Only `GET` and `HEAD` reached the target. A mapping saved for `GET /items/{id}` did not
bind an artifact's `HEAD /items/{id}` (`unbound_placeholder`).

CLI: `--max-ops` 1, 101, negative, float, full-width digits, `+50`, hex, leading space
rejected; `0050` accepted as 50. Abbreviations and `--transport`, `--resolve`, `--header`,
`--method`, `--insecure`, an extra positional and a third `--as` rejected. A second
`--base-url` replaces the first (argparse); the unlisted host gave a forced dry-run.
`--as` swapped, duplicated, label-for-handle, upper-case handle, CRLF in label and a
single `--as` rejected.

### 4.10 Budget, retries, attribution, logging, chains — PASS

| `--max-ops`, failing connects | `requests_sent` | Request entries | Connects | Target |
|---|---|---|---|---|
| 5; 0, 2, 4 | 4 | 3 | 3 | 1 |
| 2; 0 | 2 | 2 | 2 | 1 |
| 3; 1 | 3 | 3 | 3 | 2 |
| 4; all | 2 | 2 | 2 | 0 |
| 50; 0, 1 | 2 | 2 | 2 | 0 |
| 100; none | 8 | 8 | 8 | 8 |

Connects never exceeded the effective cap. On each arrival the target handler read the
database and found at least as many `plan_differential_request` rows as requests received
so far. Every containment row had `caller == "cli:<user>"`. With the request-log append
failing, nothing was sent. `verify_chain` was true after success and failure; an edited
`detail`, an edited `caller` and a deleted middle row were detected. The runner's signed
chain verified offline against the stored public key and rejected an edited event, a
deleted event and a reordering. Limits: D7.

### 4.11 Exactly two credential-bound requests, zero anonymous — PASS

Across every completed pair in these runs the target saw one request with the lower
credential then one with the higher, for `GET` and `HEAD`, and no request with no or an
unknown credential. A `HEAD` mapping for `plan_entitlement_read` executed as
`HEAD /items/abc` twice.

### 4.12 MCP/REST absence and release freshness — PASS

- `heel/mcp_server.py` and `heel/rest.py` contain neither `plan_differential` nor
  `runner`. `mcp_server.TOOL_NAMES` has 23 tools, none for this feature.
  `run_plan_differential` and `plan_differential` are called only from `heel/cli.py:355-366`;
  `replay_plan_differential` only from `heel/regressions.py:155-157`, whose only callers
  are `heel/cli.py:914` and `:1419`.
- `.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`
  printed `open-core release artifacts are current`, exit 0.
- The checked-in wheel's `plan_differential.py`, `catalog.py`, `compiler.py`, `store.py`,
  `http_transport.py`, `cli.py` and `regressions.py` are byte-identical to the tree; the
  wheel holds no test file. Manifest hashes equal the files
  (wheel `fe41c60e…a012`, sdist `cb2b87bc…2ccd`).
- `grep -rn "TLSTransport(\|TargetHTTPSClient(" heel` outside `heel/saas`: only the
  default in `http_transport.py:682` and `plan_differential.py:744` (spec F33 re-checked).

## 5. The widened HEAD catalog

The catalog entry `plan_entitlement_read` now allows `HEAD`. Readers of
`allowed_methods`: `compiler.py:91`, `:122`, `:235`, `:383`; `adapters.py:46`, `:92`,
`:186`; `http_transport.py:480`. Nothing outside `heel/runner/` reads it.

- CONFIRMED (behavior). `runner map --scenario plan_entitlement_read --method HEAD` exits
  0 and `runner prepare` exits 0 with counts only. `CanaryCompiler` now compiles a `HEAD`
  plan pair; before, `compile` raised "GET only" for it.
- CONFIRMED (behavior). The compiled approval projection carries two `HEAD` actions with
  assertion class `plan_entitlement`, and `canary_contracts.validate_approval_projection`
  accepts it. So a cloud-disclosed projection for this scenario can now contain `HEAD`.
- CONFIRMED (source). `canary_contracts._method` accepts `GET` and `HEAD` for every
  assertion class (`heel/canary_contracts.py:271`, `:388`, `:415`). `heel/saas`,
  `apps/heel-cloud/src` and `web` contain no `plan_entitlement` or `allowed_methods`
  reference; `heel/saas/canary_runs.py:1908` only renders `method` for the approval list.
- CONFIRMED (behavior). The other two scenarios are unchanged: compiling a `HEAD` mapping
  for `object_ownership_read` or `role_bound_read` still raises "scenario mapping permits
  GET only". The reference rehearsal and `heel_execute_reference` use a fixed `GET`.
- INFERRED. The hosted cloud accepts and displays a `HEAD` plan pair. `runner prepare
  --live` exits 2 locally ("live preparation is unavailable") without a cloud pairing, so
  the approval round trip was not exercised. A paired run would confirm it.

Conclusion: the widening changes one thing outside this feature. The existing
`runner prepare --live` path can now submit a `HEAD` `plan_entitlement` pair for cloud
approval, where it previously failed to compile. A `HEAD` pair still always evaluates
`inconclusive` in the executor, and no other command or scenario changes.

## 6. Suite, package and path gates

Full suite with the red-team file present, command of spec §17.2 (resolved `TMPDIR`
`/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`):
**13 failed, 1555 passed, 5 skipped.** The 13 failures are exactly the
`test_redteam_break_*` tests (10 for D1, 3 for D2). Against the T2 final of 1537 passed,
5 skipped: +18 passed, +13 failed, all 31 from the new file; no earlier test changed
result.

- Package: `--check` current, exit 0 (§4.12).
- Changed paths in T3: `docs/REDTEAM_PLAN_DIFFERENTIAL.md` and
  `tests/test_runner_plan_differential_redteam.py` only.
- `git diff --name-only 844fc1f HEAD -- apps/`: the three authorized artifacts.
- `git diff --name-only 844fc1f HEAD -- heel/runner/`: `catalog.py`, `compiler.py`,
  `http_transport.py`, `plan_differential.py`, `store.py`.

## 7. For T4

1. D1: make a 2xx lower body that states denial undetermined for `status_parity` and
   `body_superset`, at least for the spec vocabulary under JSON truthiness and the JSend
   `status` values, and turn the 10 D1 tests green.
2. D2: redact the credential in any JSON string escaping, and turn the 3 D2 tests green.
3. Both fixes are in `heel/runner/plan_differential.py`, a shipped file, so the three
   release artifacts must be regenerated by spec §14.5 afterwards.
4. D3–D8 are not required for the gate. D4 needs a product decision.

## 8. Least-certain claims

- That D2 should be scored outside I5. The invariant's wording passes; its purpose
  arguably does not.
- That the hosted cloud accepts a `HEAD` plan pair (§5, INFERRED).
- Everything about real TLS, real DNS and real address selection: no probe here touches
  them, by instruction.

## 9. Remediation rerun after T4 loop 1 (fresh T3 session)

Date: 2026-10-02. Branch at `3cb0af1` (T4 commits `93521ed`, `3cb0af1`). Reviewer: Claude
Fable 5.1, fresh session. No product code, existing test, spec or artifact was edited.
Sections 1–8 above describe `17ffd0e` and are kept as written.

### 9.1 Result

**FAIL: D1 is not closed. T4 loop 2 is required.** D2 survived every adaptive attack.
Every egress, scope, reservation, logging, caller and chain boundary held again.

| Item | Verdict | Basis |
|---|---|---|
| I1 host confinement | **PASS** | §9.5 |
| I2 GET/HEAD and inventoried routes, in the compiler | **PASS** | §9.5 |
| I3 verified signed scope | **PASS** | §9.5 |
| I4 one-shot reserved attempt | **PASS** | §9.5 (D3 unchanged) |
| I5 secret exclusion, including JSON-escaped forms (D2) | **PASS** | §9.4 |
| I6 every request logged first | **PASS** | §9.5 |
| I7 caller attribution | **PASS** | §9.5 |
| I8 chain integrity | **PASS** | §9.5 (D7 unchanged) |
| Two requests per route, none anonymous; budget | **PASS** | §9.5 |
| MCP/REST absence, package `--check` | **PASS** | §9.5 |
| R11 fail-closed predicates (D1) | **FAIL** | §9.3 |
| D2 escaped-credential storage | **PASS** | §9.4 |

### 9.2 Committed red-team file first

`.venv/bin/python -m pytest -q tests/test_runner_plan_differential_redteam.py` with
`TMPDIR=/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`, before any edit:
**31 passed**.

### 9.3 D1 — still open (MEDIUM, FAIL, needs T4 loop 2)

The loop-1 `is_denial_envelope` (`heel/runner/plan_differential.py:155-217`) closes every
shape named in §2. It does not hold its own stated contract ("the denial vocabulary under
JSON truthiness", "a 4xx/5xx number", "a denial word") for nearby value spellings. Each
body below is a 200 lower-plan response with the higher plan's key shape and null data,
against a normal higher body. All are CONFIRMED `finding / observed / body_superset`.

| Class | Cause in the code | Bodies that still yield `observed` |
|---|---|---|
| JSON-falsy allow flag | `_says_no` (`:169-172`) accepts only `false`, numeric zero and the strings `false/0/no` | `"ok": null`, `"ok": ""`, `"success": ""`, `"success": null`, `"allowed": null`, `"ok": []`, `"ok": {}` |
| JSON-truthy deny flag | `_says_yes` (`:175-178`) accepts only `true`, non-zero numbers and `true/1/yes` | `"denied": "plan does not include exports"`, `"upgrade_required": "pro"`, `"forbidden": ["exports"]`, `"payment_required": {"url": …}` |
| Status number type | `_denial_status` (`:181-183`) requires `type(value) is int` | `"status": 403.0`, `"status_code": 4.02e2` |
| Word separators | `_denial_status` (`:186-189`) splits only on non-alphanumerics | `"code": "PaymentRequired"`, `"AccessDenied"`, `"UpgradeRequired"`, `"E403"`, `"HTTP403"`, `"403x"` |

CONFIRMED end to end through the CLI, transport, executor and store for
`"code": "PaymentRequired"`, `"status": 403.0` and `"upgrade_required": "pro"`: a stored
finding with `evidence_state: observed`, exit 1.

Reproduction, added to `tests/test_runner_plan_differential_redteam.py` and left failing:
`test_redteam_break_d1_rerun_denial_value_spellings_never_yield_observed` (12 cases) and
`test_redteam_break_d1_rerun_observed_finding_through_the_cli` (3 cases). 15 failing.

What held (unit, 166 lower bodies and 23 higher bodies probed):

- Every §2 shape; key case and `_`/`-` variants (`OK`, `Error-Code`, `ERROR__CODE`,
  `statusCode`); `0.0`, `-0.0`, `" FALSE "`, `"denied": 2`; status strings with
  punctuation (`"Error!"`, `"[error]"`, `"ERROR: plan"`, `"403 Forbidden"`,
  `"access.denied"`, `"ERR_403"`).
- Wrappers: `data`/`result`/`response` are followed at one and two levels (the code's
  bound is two, the docstring says one). A third level, a list under a wrapper and a JSON
  document inside a string are not followed.
- Conflicting fields: any deny signal wins over an allow signal
  (`ok: true` + `denied: true`, `ok: false` + `allowed: true`).
- Rows in arrays (`{"items": [{"status": "error", "code": 403}]}`) are data, not an
  envelope.
- An envelope never produces a finding or `held`; from the higher plan it gives
  `no_positive_control`. Row 7 (`held`) still requires a lower 401/402/403/404 status.

Higher-plan loss of positive control (CONFIRMED, fail-closed, not a break): a top-level
or wrapped record whose own `status` or `code` is ordinary data is now an envelope, so the
pair is `inconclusive / no_positive_control` and a real gating gap on that route is not
reported. Examples: `{"code": 450, "name": "Widget"}`, a job `"status": "failed"`, an
invoice `"status": "payment_required"`, `"status": "action_required"`,
`"status": "No error"`, `"errors": 3`, `{"success": 0, "failure": 0}`,
`{"data": {"id": 1, "status": "failed"}}`. With a supplied marker the same loss hides a
`verified` leak. This is the cost of the wider vocabulary and needs stating in the docs.

Outside the loop-1 contract, recorded and not counted as the break (all `observed`):
other key names (`is_allowed`, `access_denied`, `error_message`, `err`, `http_status`,
`entitled`, `authorized`), other words (`unauthorised`, `rejected`, `blocked`, `invalid`,
`not_allowed`), other wrappers (`meta`, `body`, `payload`, `d`), a message-only body, and
look-alike characters. Each needs the shape-preserving null body of D4 to become
`observed`; a denial body that drops the data keys is `inconclusive / lower_subset`.

For T4 loop 2, the bounded closure this report will test: (1) an allow flag denies on any
JSON-falsy value or no-word; (2) a deny flag denies on any JSON-truthy value that is not a
no-word; (3) a status number denies as an integer or integral float in 400–599; (4) denial
words and 4xx/5xx digit groups are found across camel-case and letter/digit boundaries.
The 11 cases of `test_redteam_holds_affirmative_bodies_keep_the_positive_control` (new,
passing) must stay green: affirmative values and list rows are not envelopes.

### 9.4 D2 — closed (PASS)

`_secret_pattern` (`plan_differential.py:886-908`) matches each credential character as
UTF-8, `\uXXXX` in either hex case, or its short escape.

CONFIRMED end to end, two token pairs (one with `+ / = " \`), 28 routes per run, 52
requests. After each run every file under `HEEL_HOME` (652 files), stdout, stderr,
`findings --run`, `log --run` and `report --run` were scanned raw, after one exact JSON
string decode, as parsed JSON strings and keys, and as UTF-16/32.

| Echo form | Stored evidence decodes to a credential |
|---|---|
| `\u` lower, upper and per-digit mixed case; raw and escaped characters alternating | no |
| short escapes `\/`, `\"`, `\\` | no |
| credential as a JSON key; nested in arrays and objects; inside a longer string | no |
| float body (tolerant redactor path); 200 KB body with the echo at the end | no |
| three spellings adjacent; both credentials in one body in different spellings | no |
| response header and `Set-Cookie`, raw and escaped | no |
| 403, 404 and 500 bodies | no |
| non-JSON and truncated JSON bodies, UTF-16 bodies | not stored (`transport:response_rejected`) |

CONFIRMED, unit: 7 secrets (ASCII punctuation, control characters, BMP and non-BMP
characters, U+2028) in 8 spellings each, including surrogate pairs in both hex cases, as
value, key and adjacent pair: all 56 redacted. Overlapping and nested credentials leave
at most a fragment of one. The redaction count agrees between the float and plain paths.

Limits, not counted as a break (spec §16 class, "other encodings"):

- A JSON document embedded as a string inside the body (double encoding) still decodes to
  the credential after two decodes, when the inner document escaped a credential
  character (4 evidence files in the probe). A credential of only `[A-Za-z0-9-]` is
  redacted at any nesting depth.
- A credential split across two strings, and the base64, hex and percent forms of §2.
- INFO: matching is quadratic for a self-repeating credential (a 4 KB run of one
  character against a 1 MB near-miss body took 11.9 s). An ordinary token is linear.

### 9.5 Original attacks and I1–I8 probes rerun

The 56 scratch probes of the first T3 session were rerun unchanged against `3cb0af1`
(56 ran, no error); observations match §4 unless noted.

- I1: redirects 301/302/303/307/308 for GET and HEAD sent nothing to the second
  listener; only `93.184.216.34:443` was dialed; 62 base-URL forms and the 24 DNS and
  peer cases gave the same codes as §4.3–4.4; `Host` was always the synthetic host.
- I2: 35 `--routes` inputs and the direct compiler calls gave the same results; `POST`
  is refused at compile ("route inventory permits GET or HEAD only"); only GET and HEAD
  reached the target; forged `_ScopedTransport` actions were `gate_rejected` except D5.
- I3: 17 pre-run scope edits exit 2 with 0 requests; 7 mid-run edits sent nothing further.
- I4: plain replay rejected; reservation removed, renamed or replaced mid-run stopped
  after 1 request.
- I5: 28 echo forms and 7 error paths, no plaintext credential anywhere; `x_api_key` and
  `cookie_jar` clean. The first session's decoded-evidence scan now finds 0 files.
- I6–I8, budget: connects never exceeded the cap in the six retry cases; the entry was
  present on each arrival; every row carried `cli:<user>`; edits and middle deletions
  were detected in both chains.
- Two requests per route: the `--max-ops 100` case logged ops as lower then higher per
  route, 8 requests for 4 pairs, none anonymous.
- MCP/REST: 23 MCP tools, none for this feature; `heel/mcp_server.py` and `heel/rest.py`
  contain no reference.
- Package: `.venv/bin/python scripts/build_open_core_release.py --output
  apps/heel-cloud/public/downloads --check` printed `open-core release artifacts are
  current`, exit 0.
- D3–D8: unchanged and not promoted. Reuse after `rmtree` still accepted (D3); all-null
  same-key body still `observed` (D4); another fixture under the same template still sent
  by a forged action (D5); accounting as before (D6); tail truncation still verifies
  (D7); a hand-written sorted route still planned (D8).

### 9.6 Suite and path gates

- Full suite, `TMPDIR` as above: **15 failed, 1579 passed, 5 skipped.** The 15 failures
  are exactly the two `test_redteam_break_d1_rerun_*` tests. Against the T4 final of 1568
  passed, 5 skipped: +11 passed (the new guard test), +15 failed, all from the red-team
  file; no earlier test changed result.
- `git diff --name-only 844fc1f HEAD -- apps/`: the three authorized artifacts.
- `git diff --name-only 844fc1f HEAD -- heel/runner/`: the same five modules.
- Changed paths in this rerun: this report and
  `tests/test_runner_plan_differential_redteam.py`.
- Spec sync: not done. The rerun instruction allows it only if D1 and D2 both survive.
  Spec §8.3 and the §7 secret-form text still describe the pre-T4 code.

### 9.7 Least-certain claims

- That the four classes in §9.3 are a break and the "outside the contract" list is not.
  The line is drawn at the remediation's own stated contract; a stricter reader could
  count the other key names too, a looser one could accept `"ok": null` as not a denial.
- That the closure in §9.3 ends the D1 loop. Denial vocabularies are open-ended, and
  every residual case depends on D4 (a null body in the higher plan's shape counts as a
  superset). A decision on D4 would remove the whole class; a longer word list will not.
- Real TLS, DNS and address selection remain untested, as in §8.

## 10. Final rerun after T4 loop 2 (fresh T3 session)

Date: 2026-10-02. Branch at `000d0b2` (T4 loop-2 commits `a1c2acd`, `000d0b2`). Reviewer:
Claude Fable 5.1, fresh session. No product code, existing test or artifact was edited.
Sections 1–9 describe earlier commits and are kept as written.

### 10.1 Result

**FAIL: D1 is a third R11 break. The run stops and escalates to Kevin.** The loop-2
recognizer holds its §9.3 closure exactly, and D2 holds, but four concrete 2xx denial
bodies outside that closure are still stored as `observed` findings through the CLI
(§10.3). The controlling brief (§1.5) says a 2xx denial body must not count as parity; a
vocabulary bound does not narrow that rule. Every egress, scope, reservation, logging,
caller and chain boundary held again.

| Item | Verdict | Basis |
|---|---|---|
| I1 host confinement, redirects included | **PASS** | §10.5 |
| I2 GET/HEAD and inventoried routes, in the compiler | **PASS** | §10.5 |
| I3 verified signed scope | **PASS** | §10.5 |
| I4 one-shot reserved attempt | **PASS** | §10.5 (D3 unchanged) |
| I5 secret exclusion, including JSON-escaped forms | **PASS** | §10.4, §10.5 |
| I6 every request logged first | **PASS** | §10.5 |
| I7 caller attribution | **PASS** | §10.3, §10.5 |
| I8 chain integrity | **PASS** | §10.5 (D7 unchanged) |
| D1 / R11 fail-closed predicates | **FAIL** (third break) | §10.3 |
| D2 escaped-credential storage | **PASS** | §10.4 |
| Exactly two requests per route, none anonymous; budget | **PASS** | §10.3, §10.5 |
| Compiler confinement | **PASS** | §10.5 |
| MCP/REST absence | **PASS** | §10.6 |
| Package freshness | **PASS** | §10.6 |

The §9.3 closure itself passed every probe; the break is that the closure is not the
requirement. §10.3 separates the two.

### 10.2 Committed red-team file first

`.venv/bin/python -m pytest -q tests/test_runner_plan_differential_redteam.py` with
`TMPDIR=/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`, at `000d0b2`, before
any edit: **57 passed**. CONFIRMED.

### 10.3 D1 — the §9.3 closure holds; the requirement does not (FAIL, third break)

Code read: `is_denial_envelope` and helpers, `heel/runner/plan_differential.py:155-228`;
loop-2 diff `git diff 11638e4 HEAD -- heel/` (one file, 22 insertions, 11 deletions).

**Unit probe** (`evaluate_plan_pair`, scratch script, not committed). Each lower body is a
200 response in the higher plan's key shape with null data, against the normal higher
body of the committed tests. All results CONFIRMED.

| Closure item (§9.3) | Bodies probed | Result |
|---|---|---|
| 1. Allow flag denies on JSON-falsy or no-word | 147: `ok`/`success`/`allowed` in 9 key spellings × `null`, `false`, `0`, `0.0`, `""`, `[]`, `{}`, `"false"`, `"False"`, `" FALSE "`, `"0"`, `"no"`, `"NO"`, blank and no-break-space strings; literals `-0.0`, `0e0`, `0E-5` | all `inconclusive / lower_denial_envelope` |
| 2. Deny flag denies on JSON-truthy non-no-word | 198: four deny keys in 9 spellings × `true`, `1`, `2`, `-1`, `0.5`, `1e-9`, reason strings, `["exports"]`, `{"url": …}`, `[null]`, `[0]`, `{"a": null}`, `"none"`, `"null"`, `"0.0"`, `"00"` | all inconclusive |
| 3. Status number as integer or integral float in 400–599 | 100: `status`/`status_code`/`statusCode`/`code` in 7 spellings × 13 values; literals `4.02e2`, `4.03E+2`, `40300e-2`, `403.000`, `0.403e3`, `4030E-1`, `5.99e2`, `4e2` | all inconclusive |
| 4. Words and 4xx/5xx digit groups across camel-case and letter/digit boundaries | 152: `PaymentRequired`, `AccessDenied`, `HTTPError`, `IOError`, `OAuthError`, `S3AccessDenied`, `ERRORCode`, `errorCODE`, `PaymentREQUIRED`, `E403`, `e403`, `HTTP403`, `403x`, `x403y`, `403Forbidden`, `Error403Forbidden`, `Http403Error`, `PERMISSION_DENIED`, `AuthFailed`, `Error2`, `2Error`, `HTTP/1.1 403 Forbidden` and others, under `status` and `code` | all inconclusive |
| Wrappers, one and two levels | 35 | all inconclusive |
| Conflicting fields | 10: `ok: true` + `denied: true`, `success: true` + `status: 403`, `status: "ok"` + `code: "PaymentRequired"`, `code: 200` + `status_code: 402.0`, `denied: "no"` + `forbidden: ["x"]` and others | any deny signal wins; all inconclusive |

Two further strings in my item-4 list, `aErrorb` under `status` and `code`, gave
`observed`. They are my error, not a break: `Errorb` has no boundary after `Error`.

**Positive control kept** (CONFIRMED, unit): 53 affirmative bodies, the same for both
plans, all `finding / observed`. They include the 11 committed guard cases and `ok: "OK"`,
`allowed: ["read"]`, `denied: " No "`, `denied: 0.0`, `status: "200 OK"`, `status: 204.0`,
`status: 399`, `status: 600`, `status: true`, `status: "terror"`, `status: "Failing"`,
`code: "4030"`, `code: 4030`, `code: "0"`, `error: false`, `error_code: 0`, wrapped
affirmative objects.

**Envelope never becomes a finding or `held`** (CONFIRMED, unit, four loop-2 envelopes):
lower envelope at 200, 201, 204, 206, 299 → `inconclusive / lower_denial_envelope`; from
the higher plan or both → `no_positive_control`; lower 403 with the same body → `held`.
Top-level list, string, `null`, empty, duplicate-key, `NaN` and invalid-UTF-8 lower bodies
→ `inconclusive / lower_subset`.

**End to end through the CLI, transport, executor and store** (CONFIRMED, one run, 27
routes, `--max-ops 100`, 54 requests): 22 closure bodies, including `ok: null`, `ok: []`,
`allowed: {}`, blank `success`, `Success: "NO"`, `forbidden: [null]`,
`payment_required: 0.5`, `status: 403.0`, literal `40300e-2`, `statusCode: 599.0`,
`PaymentRequired`, `HTTPError`, `e403`, `403Forbidden`, `AccessDeniedException`,
`PERMISSION_DENIED`, two wrapper depths and two conflicts. Every one was stored
`inconclusive / lower_denial_envelope`, `candidate: false`. The control route (same body
for both plans) was `observed`, exit 1.

**Regression replay** (CONFIRMED, same run): the control finding was added with
`regress add`; `regress run` then gave `fail / still_reachable` for the unchanged target,
`fail / inconclusive` when the lower plan answered 200 with `code: "PaymentRequired"`,
`ok: null`, `status: 403.0` or a `denied` reason string, and `pass / blocked` for a 403.
Two requests per replay.

**Accounting in that run** (CONFIRMED): the target saw exactly lower then higher for each
of the 27 routes, 54 requests, none anonymous; `Host` was always the synthetic host; only
`93.184.216.34:443` was dialed; the second listener saw nothing; 54
`plan_differential_request` entries, every row `cli:<user>`; `chain_valid` true.

**Change against §9 caused by loop 2** (CONFIRMED): four first-session probe bodies that
null every higher key, `ok` included, are now envelopes through `ok: null`
(`message_only`, `graphql_errors_empty_data_null`, `entitled_false`,
`all_null_same_keys`). The D4 all-null body is therefore `inconclusive` whenever the
higher shape contains `ok`, `success` or `allowed`, and still `observed` when it does not.

**Still unrecognized, outside the closure** (CONFIRMED, unit; the last four also end to
end, stored `observed`).

- No boundary around the word: `PAYMENTREQUIRED`, `paymentrequired`, `ACCESSDENIED`,
  `accessdenied`, `Accessdenied`, `HTTPERROR`; an upper-case word run into lower case
  (`ERRORcode`, `DENIEDx`, `UNAUTHORIZEDuser`).
- Other words: `errors` (as a status string), `unauthorised`, `UNAUTHENTICATED`,
  `NOT_FOUND`, `rejected`, `blocked`.
- Other value readings: `status: false`, `status: 0`, `status: "false"`, `status: 403.5`,
  `status: "4.02e2"`, `code: 40301`, `code: "4031"`, `ok: "off"`, `ok: "n"`,
  `ok: "null"`, `ok: "failed"`, `ok: "0.0"`, a zero-width-space `ok`.
- Other keys and shapes: `message` alone, `is_allowed`, `error_message`, a key with a
  space, a Cyrillic look-alike key, a `meta` wrapper, a third wrapper level, a list under
  a wrapper, JSON inside a string.
- End to end: `code: "PAYMENTREQUIRED"`, `status: "accessdenied"`, `status: false` and a
  message-only body each stored an `observed` finding.

**Why this is a third R11 break.** The four end-to-end bodies are concrete denial
envelopes, not speculative spellings:

| Lower 200 body (data keys null) | Why it is a denial envelope |
|---|---|
| `{"status": false, "message": "Upgrade required", …}` | a boolean `status` that is false, with a denial message; the common PHP/Node envelope shape |
| `{"message": "Upgrade required", …}` | the body's only content is a denial statement |
| `{"code": "PAYMENTREQUIRED", …}` | the HTTP 402 reason phrase as an upper-case code, with no boundary for the camel split |
| `{"status": "accessdenied", …}` | the AWS `AccessDenied` code in lower case |

Each was stored as a finding with `evidence_state: observed`, `operator_declared: false`,
exit 1, by the unmodified CLI against the loopback target (`regress add` would accept
it, as in §2). The brief says "Error envelopes (2xx with denial body) must not count as
parity"; the loop-2 recognizer meets its §9.3 closure but a closure drawn from a finite
word list is not that rule, and the final rerun instruction forbids narrowing the rule to
the recognizer. I first drafted this section as a bounded PASS and was asked to
reconcile it with the brief; this is the reconciliation. The structural reason is D4: a
denial body in the higher plan's key shape with null values is a key-path superset, so
anything the recognizer misses becomes `observed`. A word list cannot close that;
a D4 decision (null-valued or empty data is not a superset) or a product decision to
report such pairs as `candidate` only would.

Reproduction, added to `tests/test_runner_plan_differential_redteam.py` and left
failing: `test_redteam_break_d1_final_unrecognized_denial_body_yields_observed`
(4 cases, unit). The end-to-end form is the committed `_World` journey of the earlier D1
CLI tests with the same bodies; it was run in this session and not duplicated as a test.

**Higher-plan loss of positive control** (CONFIRMED, fail-closed, not a break). The same
body for both plans gives `inconclusive / no_positive_control` for ordinary data under a
recognized key: the §9.3 examples, and with loop 2 also `code: "ROOM404"`,
`code: "SKU450B"`, `code: "Item500"`, `code: "PROMO-500"`, `code: "v500"`,
`status: "NoError"`, `status: "ErrorFree"`, `status: "requiredFieldsComplete"`,
`code: 500.0`, `forbidden: ["x"]`, `{"allowed": [], "denied": ["write"]}`,
`denied: "none"`, `ok: null`, `allowed: {}`, `success: ""`. Unchanged from loop 1 and
newly noted: `error_code: "0"`, `errorCode: "SUCCESS"`, `error: "false"` and
`error: {"code": 0, "message": ""}` are read as errors, because the error keys use plain
truthiness with no no-word list. A target that puts such a field on every response makes
every route inconclusive. No finding is produced, so R11 holds; a real gap on those routes
is not reported.

INFO, contrived: redaction runs before the predicate, so a registered credential that
equals the denial text of a `status` or `code` value replaces it with
`[REDACTED:secret]` and the envelope is no longer read (unit only, credential
`forbidden-plan-1`). It needs a credential that is itself a denial phrase echoed in that
field.

### 10.4 D2 — still closed (PASS)

Code read: `_secret_pattern`, `_TolerantRedactor`, `_RedactingRunnerStore`,
`plan_differential.py:882-999`. `git diff 11638e4 HEAD` does not touch them. CONFIRMED.

- CONFIRMED. The §9.4 end-to-end probe rerun unchanged: two token pairs, 28 routes, 52
  requests each, 652 files scanned per run, plus stdout, stderr, `findings --run`,
  `log --run`, `report --run`. No credential in the raw, single-decode, parsed-JSON,
  UTF-16 or UTF-32 views. The only hits are the 4 double-encoded evidence files of the
  known limit in §9.4, in the two-decode view.
- CONFIRMED. A new end-to-end probe with a token containing `+ / = " \`, at response
  status 200, 403 and 500 (24 requests and 306 files each): the credential inside an
  `error` value, a `status` value, an object key above a denial `code`, five levels of
  nesting, key and value together, a float body, raw, non-ASCII-safe, `\/` and three
  adjacent spellings, an echoed header and `Set-Cookie`. No leak in the raw, one-decode,
  two-decode, UTF-16 or UTF-32 views of any file or command output; the literal I5 scan
  is empty.
- CONFIRMED, unit: 7 secrets × 8 spellings, 0 missed; overlap, containment and
  self-overlap behave as in §9.4; the count agrees between float and plain bodies (2 and
  2). The quadratic case is unchanged (11.94 s).
- The limits of §9.4 stand: double encoding, split strings, base64, hex, percent forms.

### 10.5 Original attacks rerun

The 56 scratch probes of the first session were run unchanged at `000d0b2`: 56 ran, no
error. Their output was compared line by line with the §9.5 run after masking random
IDs, ports, paths and times. The only differences are the four D1 lines of §10.3 and
shifted source line numbers. Everything below is CONFIRMED by that run.

| Attack | Observed |
|---|---|
| Redirect 301/302/303/307/308, GET and HEAD | `transport:response_rejected`; second listener 0 requests; only `93.184.216.34:443` dialed |
| Host header | `Host` was the synthetic host on every request across base-URL, OpenAPI, binding and credential vectors |
| IPv6 and other literals | `https://[::1]`, `https://[::ffff:127.0.0.1]` and the other literal forms rejected `invalid_origin`, exit 2, 0 requests, with and without `--dry-run` |
| DNS rebinding | preflight loopback, metadata, mixed, mapped → `unsafe_dns`, 0 requests; change between lower and higher → 1 request, pinned address only; other public or superset → `dns_changed`; peer mismatch → `peer_mismatch` |
| Scope tamper | pre-run edits exit 2 with 0 requests; widen, delete, expire, drop-host and real expiry on the first lower request → 1 request total, `transport:gate_rejected`; signature corrupted after the third request → nothing further |
| Attempt replay | same attempt ID → `PlanDifferentialRejected`, 0 new requests; reservation removed, renamed or replaced mid-run → 1 request, exit 2; reuse after `rmtree` still accepted (D3) |
| Credential leak on error paths | missing higher credential, connect failure, HMAC append failure, request-log failure, evidence write failure, signed-event failure, scope tamper after an echo: no plaintext and no decoded credential in any file or output |
| Error envelope | §10.3 |
| Budget and logging order | connects never exceeded the cap in the six retry cases; entries present on each arrival; `--max-ops 100` logged ops lower then higher per route, none anonymous |
| Caller attribution | every row `cli:<user>` |
| Chains | HMAC chain verified; edited detail and edited caller detected; signed chain verified offline, edited, deleted-middle and reordered events rejected; tail truncation still verifies (D7) |
| Compiler confinement | 35 `--routes` inputs as in §4.9; `POST` refused at compile; only `GET` and `HEAD` reached the target; forged `_ScopedTransport` actions `gate_rejected` except D5 |

The committed `test_redteam_holds_*` cases (redirect, scope tamper, DNS rebinding, header
injection) are part of the 57 passing tests of §10.2. D3–D8 are unchanged and not
promoted.

### 10.6 MCP/REST absence, package freshness, path gates

- CONFIRMED. `heel/mcp_server.py` and `heel/rest.py` contain neither `plan_differential`
  nor `runner`; `TOOL_NAMES` has 23 tools, none for this feature. The only callers are
  `heel/cli.py:355-366` and `heel/regressions.py:155-157`. `TLSTransport(` and
  `TargetHTTPSClient(` outside `heel/saas`: `http_transport.py:682` and
  `plan_differential.py:806`.
- CONFIRMED. `.venv/bin/python scripts/build_open_core_release.py --output
  apps/heel-cloud/public/downloads --check` printed `open-core release artifacts are
  current`, exit 0, before and after this commit's edits.
- CONFIRMED. The checked-in wheel's `plan_differential.py`, `catalog.py`, `compiler.py`,
  `store.py`, `http_transport.py`, `cli.py` and `regressions.py` are byte-identical to
  the tree; the wheel holds no test file. Manifest hashes equal the files (wheel
  `093425c6…7021`, sdist `ae7690e9…d462`).
- CONFIRMED. `git diff --name-only 844fc1f HEAD -- apps/`: the three authorized
  artifacts. `-- heel/runner/`: `catalog.py`, `compiler.py`, `http_transport.py`,
  `plan_differential.py`, `store.py`. Since `17ffd0e` the only product file changed is
  `heel/runner/plan_differential.py`.

### 10.7 Suite and spec sync

- Full suite, `TMPDIR` as above, before the new test: **1594 passed, 5 skipped,
  0 failed**, unchanged from the T4 loop-2 final. With the new test: see §10.9.
- Spec sync: not done. A drafted sync of §8.3 and the §7/§16 redaction wording was
  reverted when the verdict became FAIL; the spec still describes the pre-T4 envelope and
  secret forms. Noted for whoever resumes: the §8.5 bullet "never yields `verified`" also
  disagrees with row 3 and the committed test (a marker present inside an envelope body
  is `verified`).
- Changed paths in this rerun: this report and
  `tests/test_runner_plan_differential_redteam.py`.

### 10.8 Least-certain claims

- That the four bodies are a break of R11 rather than a documented limit. I count them
  as a break because the brief's rule is about denial bodies, not about a vocabulary, and
  each body plainly states denial. The opposite reading (the §9.3 closure was the agreed
  contract and it passed) is in §10.3 too; on that reading D1 would be PASS and only the
  D4 decision would remain. Either way no word list ends this: the orchestrator's choice
  is a D4 decision, not a third T4.
- That the positive-control losses are acceptable for Phase 1. They fail closed, but a
  target with `error_code: "0"` on every response yields no finding at all.
- Real TLS, DNS and address selection remain untested, as in §8.

### 10.9 Final counts

- Red-team file after adding the regression: **4 failed, 57 passed**; the 4 are
  `test_redteam_break_d1_final_unrecognized_denial_body_yields_observed`.
- Full suite, `TMPDIR=/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`:
  **4 failed, 1594 passed, 5 skipped**; delta from the T4 loop-2 final is the 4 new
  failing cases only.
- Package `--check` current; `git diff --check` clean; path gates unchanged (§10.6).
