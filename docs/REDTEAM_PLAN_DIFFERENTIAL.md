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
