# Plan-differential runner — Phase 1 design spec

Date: 2026-10-02. Branch: `feat/plan-differential-runner` (base `main` @ `844fc1f`).
Blast radius: **medium — adds network egress under a signed scope.**
Role: design only (T1 apps-exception revision; fourth revision). It replaces the revision
committed at `1c6b324` in full. This document is the contract for T2 (implementation), T3 (red team),
T4 (remediation) and T5 (acceptance). It makes no acceptance claim and contains no product
code.

Normative words: **MUST**, **MUST NOT**, **MAY**. Where this spec and the controlling brief
(`.heel/plan-differential-run/brief.md`) disagree, the brief wins and the implementer stops
and reports.

---

## 0. Correction record (why this revision exists)

Three revisions precede this one.

- `cdf0411` extended four existing runner modules. T2 then found that a release test
  byte-compares 17 `heel/runner/*.py` files with the wheel and sdist checked in under
  `apps/`, and the brief forbade `apps/` (F22).
- `1c6b324` therefore changed no existing runner module. The price was that every `HEAD`
  route sent four requests, two of them with no credential. The orchestrator rejected
  that: the brief requires one request per supplied plan identity and nothing else.
- On 2026-10-02 Kevin authorized one narrow exception, now recorded in the brief: Opus may
  regenerate and commit **exactly** the three tracked release artifacts
  `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`,
  `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` and
  `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`, with the existing release
  builder. Every other `apps/` path stays forbidden.

With that exception the blocker of F22 is gone (F35), so this revision restores the
extension architecture of `cdf0411` and removes the anonymous-control workaround.

| # | Change in this revision | Where |
|---|---|---|
| A1 | **Exactly one `GET` or `HEAD` request per supplied plan credential for every planned route: two wire requests per route before retries, and no request without a plan credential.** `plan_entitlement_read` is widened to `HEAD` in the catalog; a `HEAD` pair is one run of that scenario | §6.1, R17 |
| A2 | The route and method allowlist is back in `heel/runner/compiler.py`. The private in-module compiler and its tickets are withdrawn | §6.2, I2 |
| A3 | Inventory reads are back in `heel/runner/store.py` as two read-only methods | §6.3 |
| A4 | Trust loading is back in `TLSTransport.__init__` | §6.4 |
| A5 | The three release artifacts are regenerated last, checked, and confined by path gates | §14.5, §17, R27 |

Corrections from `1c6b324` that remain valid and are kept unchanged:

| # | Correction | Where |
|---|---|---|
| C3 | Common numeric JSON (float, negative and large integer) completes through a redactor seam in the **new module**; evidence redaction is unchanged and the whole-`HEEL_HOME` credential scan stays clean | §7.4, R25, I5 |
| C4 | The real `SSL_CERT_FILE`/`SSL_CERT_DIR` trust boundary is stated and tested; Heel adds no CA or transport option | §7.2, R23, R14 |
| C5 | The existing fixed runner rejection text is reused; no new constant | §3.6, R16 |
| C6 | A 2xx denial envelope is inconclusive in a fresh run and in replay, never a regression pass | §8, §10, R24 |
| C7 | The row-1 reason list is closed and complete | §8.5 |
| — | Findings are stored only for completed pairs; `--as` takes handles; `--routes` takes a complete imported inventory; all eight invariants keep named tests; no scope creation or mutation path; no MCP or REST entry | §11, §3.2, §3.3, §12 |

C1 and C2 of `1c6b324` (no runner module may change; `HEAD` under
`anonymous_authenticated_read`) are **withdrawn**.

## 1. What ships

One new public command, CLI only:

```
heel runner run --scope <scope-id> --base-url https://<host> \
    --as <lower-label>=<credential-handle> --as <higher-label>=<credential-handle> \
    [--routes <imported-inventory>] [--max-ops 50] [--dry-run]
```

For every route in the imported GET/HEAD inventory it sends the request **once per canary
identity** (lower plan, then higher plan) through `heel/runner/http_transport.py` and
compares the two responses. That is exactly two wire requests per planned route before
retries, for `GET` and `HEAD` alike. No request is ever sent without one of the two
supplied plan credentials. Where the lower plan receives what the higher plan receives it
records a finding with `evidence_state: observed` that no input declared.

One existing command changes its output: `heel runner credential add` now prints the
opaque handle it created (§3.2). No other command is added. Nothing else ships: no HAR
import, tenant differential, limit probing, writes, lifecycle sequences, MCP or REST
exposure, cloud, static-reviewer, pricing or site changes, and no scope creation or
mutation path.

## 2. Verified facts that shape the design

F1–F20 were read or run on 2026-10-02 at `844fc1f`. F22–F32 were read or run at `cdf0411`
(product code identical to `844fc1f`). F33–F39 were read or run for this revision on
2026-10-02 at `1c6b324` with the uncommitted T2 tree in place (the "dirty tree", §14.3),
or on a scratch copy of it. Line numbers cite files as committed at `HEAD` unless a row
says "dirty tree". F21 stays withdrawn; F34 replaces it with a measurement.

| # | Fact | Evidence |
|---|------|----------|
| F1 | `heel runner import-openapi` and `heel runner credential add` exit 2 in a fresh `HEEL_HOME`. Every `RunnerStore` read or write needs a bound context and no public command binds one. | Ran both in an empty `HEEL_HOME`; `heel/runner/store.py:5203-5206`, `:5276-5288` |
| F2 | A credential handle is `secrets.token_hex(16)`: random, 32 hex, not derived from the secret. One handle per semantic role per context; a second registration for a role raises. | `heel/runner/store.py:6998`, `:7025`, `:6961-6979` |
| F3 | `credential add` prints only `{"registered_count": 1}`. An ephemeral credential is read from `HEEL_RUNNER_CREDENTIAL_<HANDLE>`, so an operator who is never shown the handle cannot supply it. | `heel/cli.py:199`; `heel/runner/vault.py:186-192`, `:252-270`; `tests/test_runner_cli.py:75` |
| F4 | The existing privacy boundary is: handle and label never enter the cloud-disclosed approval projection (they are in the local manifest), and `runner prepare` stdout is counts only. The label is treated as possibly sensitive operator text. | `tests/test_runner_compiler.py:291-292`; `tests/test_runner_cli.py:76`, `:96-98` |
| F5 | The imported inventory is persisted as `routes.json` in the bound context directory, in the envelope `heel.runner-route-inventory.v1` (`schema_version`, `namespace`, `origin`, `verification_record_digest`, `inventory: {source_digest, routes}`). Each route is `{method, route_template, operation_id, placeholders}` with method `GET` or `HEAD` only, in canonical order. | `heel/runner/store.py:6839-6904`, `:808-826`; `heel/cli.py:142-154` |
| F6 | At `844fc1f`, `plan_entitlement_read` permits `GET` only (§6.1 widens it), roles `lower_plan`, `higher_plan`. `anonymous_authenticated_read` permits `GET` and `HEAD`, roles `anonymous`, `authenticated`. No other entry permits `HEAD`. | `heel/runner/catalog.py:60-93` |
| F7 | The transport and the manifest contract carry `HEAD`: HEAD framing is parsed, a HEAD body is refused, and a HEAD pair always evaluates `inconclusive`. | `heel/runner/http_transport.py:594-595`, `:612-613`, `:801`; `heel/canary_contracts.py:270-271`; `heel/runner/adapters.py:189-195` |
| F8 | The transport is HTTPS only, port 443, public addresses only, exact IANA-TLD hostname; no IP literal, port, userinfo, path, punycode or reserved suffix. | `heel/runner/http_transport.py:98-142`, `:46-53`, `:157-175` |
| F9 | Any 3xx raises `response_rejected`; no redirect is followed. `Host` is always the normalized hostname; no caller input reaches a header. | `heel/runner/http_transport.py:571-572`, `:906-912` |
| F10 | DNS is pinned. Each attempt re-resolves, requires set equality with the preflight set, connects to the pinned numeric address and re-checks the peer address. | `heel/runner/http_transport.py:695-716`, `:734-737`, `:760-761` |
| F11 | `TLSTransport` builds `ssl.SSLContext(PROTOCOL_TLSv1_2)` with `CERT_REQUIRED` and `check_hostname` but loads no trust store (zero CA certificates). `TargetHTTPSClient` accepts a `tls` object and exposes the context as `tls.context`. | `heel/runner/http_transport.py:233-243`, `:681`; ran `cert_store_stats()` |
| F12 | A test pins `TLSTransport().context.protocol == PROTOCOL_TLSv1_2` and forbids `ssl.create_default_context`, for the runner class and the `heel/saas` twin. | `tests/test_runner_http_transport.py:30-38` |
| F13 | The transport refuses `Transfer-Encoding` and `Content-Encoding`, bodies over 256 KiB, and any non-empty body that is not one JSON object. Evidence is stored before the body-shape refusal. | `heel/runner/http_transport.py:591-592`, `:604-605`, `:609-633`, `:845-863` |
| F14 | The executor reserves the grant before any transport call, calls `before_attempt` before every socket, and writes **raw** response headers and body to the private store. | `heel/runner/execution.py:579`, `:651-710`, `:716-736` |
| F15 | One manifest holds at most 20 actions and `maximum_requests` ≤ 20; evidence ordinals are < 20; the store keeps one mapping per scenario and at most four. | `heel/canary_contracts.py:309`, `:377`; `heel/runner/store.py:9270`, `:6932`, `:6953` |
| F16 | The marker contract: exactly one fixture binding beginning `heel-canary-` opts the route into `protected_canary`. | `heel/runner/execution.py:712-714`; `heel/runner/content_assertion.py:7-37`; `docs/EXPORT_DEMO.md:32` |
| F17 | `heel findings --run`, `heel log --run` and `heel regress add` read the SQLite `Store` and the HMAC containment chain, which carries `caller`. The runner's Ed25519 chain has no caller field. | `heel/cli.py:1423-1428`; `heel/containment.py:24-65`; `heel/runner/containment.py:25-29` |
| F18 | `heel regress run` re-executes through `HeelServer.heel_run`, which only knows registered synthetic targets. | `heel/regressions.py:142-203` |
| F19 | The wheel's module list is pinned twice. `tests/` is pruned from the wheel. | `release/open-core-v1.json`; `tests/test_open_core_release.py:107-206`, `:223` |
| F20 | `reference_rehearsal.run_reference` is the proven safe sequence: verify scope → exclusive attempt directory → ephemeral signer and identity → private `RunnerStore` → compile → locally signed grant → `LocalCanaryExecutor` → read private evidence → report. | `heel/reference_rehearsal.py:107-184` |
| F22 | `test_checked_in_runner_artifacts_match_the_current_public_pairing_and_recovery_api` requires 17 `heel/runner/*.py` files (`__init__`, `adapters`, `catalog`, `companion`, `compiler`, `containment`, `control_client`, `coordinator`, `execution`, `http_transport`, `identity`, `openapi_routes`, `redaction`, `runtime`, `service`, `store`, `vault`) to be byte-identical to the wheel and sdist under `apps/heel-cloud/public/downloads`. `content_assertion.py` is not in the list but is not changed either. | `tests/test_open_core_release.py:955-984` |
| F23 | On the dirty tree the full suite has exactly one failure, the artifact byte-compare of F22, on `catalog.py`. | Ran `TMPDIR=<resolved> .venv/bin/python -m pytest -q tests`: 1 failed, 1485 passed, 5 skipped. Baseline is 1486 passed, 5 skipped (F38) |
| F24 | The CI `package` job runs `scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`. It rebuilds the wheel from source and fails with `generated artifact is stale` if any shipped file differs. | `.github/workflows/ci.yml:85-87`; `scripts/build_open_core_release.py:1086-1092`. Ran on a pristine export of `HEAD`: `artifacts are current`, exit 0. Appended one comment line to `heel/cli.py`: `generated artifact is stale: heel_sim-1.2.0-py3-none-any.whl`, exit 1 |
| F25 | A `HEAD` action under `plan_entitlement_read` is refused today in three places, and all three read the permitted methods from the catalog or from the adapter registry derived from it. Widening the one catalog entry is the only change they need. | `heel/runner/compiler.py:147-149`; `heel/runner/adapters.py:46`, `:92`, `:186`; `heel/runner/http_transport.py:473-486` |
| F26 | The executor keeps one credential per semantic role per manifest and evaluates observations `[0]` and `[1]` of each scenario, so one `plan_entitlement_read` manifest is exactly one lower-plan and one higher-plan action. | `heel/runner/execution.py:421`, `:948-960` |
| F27 | The inherited failure: the transport calls `redactor.count_bytes(raw_headers, raw_body)` and maps any exception to `evidence_rejected`. `count_bytes` parses a JSON body and `_safe_json` raises on a float, a negative integer, an integer above 2^53−1, more than 1024 nodes, more than 256 members, or depth above 16. The executor classifies `evidence_rejected` as `failed` / `runner_fault`. The count is used only as a number; stored evidence is the raw bytes. | `heel/runner/http_transport.py:833`, `:851-856`; `heel/runner/redaction.py:141-155`, `:158-193`; `heel/runner/execution.py:548`. Ran `Redactor(()).count_bytes(b'{"price": 1.5}')` → `TypeError`; `b'{"n": -3}'` → `ValueError` |
| F28 | The transport accepts any `Redactor` instance (`isinstance`), and receives it as a `request()` argument from the executor. | `heel/runner/http_transport.py:899`; `heel/runner/execution.py:631`, `:754` |
| F29 | `ssl.SSLContext.load_default_certs()` honours `SSL_CERT_FILE`. On this build (OpenSSL 3.5.5) an unset environment loaded 128 CAs; `SSL_CERT_FILE=<test CA>` loaded exactly 1 and the test CA was trusted. | Ran on `TLSTransport().context` in two subprocesses; `ssl.get_default_verify_paths().openssl_cafile_env == "SSL_CERT_FILE"` |
| F30 | A scratch prototype through the real `CanaryCompiler`, `LocalCanaryExecutor` and `TargetHTTPSClient` over a loopback seam showed: (b) a GET body `{"price": 1.5, "n": -3, "big": 2**60, "echo": <Authorization>}` gave `failed`/`runner_fault` with the inherited redactor and `completed` with a tolerant `Redactor` subclass substituted at the transport seam; (c) with a `RunnerStore` subclass redacting before `store_response_evidence`, no file under `HEEL_HOME` contained either credential. Part (a) of this row in `1c6b324` measured the rejected four-request path and is withdrawn. Repeated on the dirty tree in F34. | Ran; script not committed |
| F31 | The runner parser already prints the fixed line `Heel runner command was rejected.` for every argparse error under `runner`. | `heel/cli.py:42`, `:1199-1207` |
| F33 | Outside `heel/saas`, `TLSTransport()` is constructed in exactly one place, the default of `TargetHTTPSClient`, and no product code constructs `TargetHTTPSClient` except the new module. So loading default trust in `TLSTransport.__init__` changes behavior only for this feature. | `grep -rn "TLSTransport(\|TargetHTTPSClient(" heel` excluding `heel/saas`: `heel/runner/http_transport.py:681` and the new module only |
| F34 | **Two requests per route, measured.** On the dirty tree (catalog widened), through the public CLI and the loopback seam, a full run planned 10 pairs. For `HEAD /api/export` the target log held exactly one `HEAD` with the lower credential, one with the higher, and none without a credential. Across the run no request arrived without a plan credential. 18 requests in total (two pairs stopped after a refused first response), chain valid, second listener untouched, no credential bytes under `HEEL_HOME`. With a route returning a float, a negative integer, `2**60`, 300 keys and the echoed credential listed first: the inherited redactor ended the run after 1 request (`transport:evidence_rejected`); with a tolerant redactor substituted in `_ScopedTransport` the pair was `completed`/`body_superset`, later pairs ran, and the `HEEL_HOME` scan stayed clean. | Ran two scratch scripts on a scratch copy; not committed |
| F35 | **The exception removes the blocker, measured.** On a scratch copy of the dirty tree: `--check` printed `generated artifact is stale: heel_sim-1.2.0-py3-none-any.whl`, exit 1; the builder without `--check` rewrote the artifacts; `git status --short -- apps` then listed exactly the three authorized files; `--check` printed `open-core release artifacts are current`, exit 0; the full suite gave 1486 passed, 5 skipped, 0 failed. | Ran `scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads` with and without `--check`, then the full suite, in the copy |
| F36 | The builder reads the working tree, not a commit, and is deterministic. The manifest holds only `name`, `sha256`, `size`, `schema_version`, `version`. The artifact hashes appear in no other tracked file; the `apps/` tests and `prepare-runtime.mjs` read them from the manifest. | `scripts/build_open_core_release.py:925-950`; `git grep` of both current hashes matches only the manifest; `apps/heel-cloud/scripts/prepare-runtime.mjs:212-220`; `apps/heel-cloud/tests/production-artifact.test.mjs:1078-1083` |
| F37 | The separate browser-engine wheel under `apps/heel-cloud/browser-engine` packages ten modules, none of which this feature changes, so its CI `--check` is unaffected. | `scripts/build_browser_engine.py:27-36`; `.github/workflows/ci.yml:183` |
| F38 | **Baseline record** (T2 session, at `cdf0411`, product code identical to `844fc1f`; Python 3.12.13, pytest 9.0.2, dnspython 2.8.0, repo-local `.venv`). Raw macOS `python -m pytest -q tests`: 35 failed, 1451 passed, 5 skipped; the 35 are 16 in `tests/test_runner_control_http.py` and 19 in `tests/test_runner_public_client.py`, all `RunnerRuntimeCorrupt: runtime state parent is unsafe`, because the default `TMPDIR` passes through the `/var` symlink. CI-equivalent, with `TMPDIR` resolved to its real path: **1486 passed, 5 skipped, 0 failed**. | `.heel/plan-differential-run/T2-baseline.txt`; `heel/runner/runtime.py:810-811` |
| F39 | The CI `package` job also runs `HEEL_REQUIRE_STANDARD_BUILD=1 python -m unittest tests.test_open_core_release -v` and installs the committed wheel. The strict mode needs the PyPA build frontend from `release/requirements-release.txt`, which is not in the local `.venv`; locally two of its tests fail for that reason alone. It has not been run for this feature. | `.github/workflows/ci.yml:79-93`; ran the strict command on the scratch copy |
| F32 | `RunnerStore` exposes `root`, `namespace`, `load_context()`, `list_routes()`, `replace_routes()`, `save_mapping()`, `list_mappings()`, `list_credentials()`. `list_routes()` validates the stored envelope and canonical order but does not return `source_digest`. | `heel/runner/store.py:878`, `:5203`, `:6831-6959` |

Consequence: Phase 1 is `run_reference` with the fixture transport replaced by the real
`TargetHTTPSClient`. Where an existing runner interface is too narrow, that interface is
**extended in place** (§6) and the file is listed in §14; nothing is worked around.
Restrictions that are properties of the inherited transport are kept and stated in §15.

## 3. CLI surface (exact)

### 3.1 Arguments

| Argument | Required | Rule |
|---|---|---|
| `--scope ID` | always | Existing signed scope. Loaded with `scope.get_scope`, checked with `scope.verify`. |
| `--base-url URL` | always | MUST pass `http_transport.normalize_target_origin`. `http://`, ports, paths, queries, userinfo, IPv4 and IPv6 literals, trailing dot, punycode and reserved suffixes are rejected. |
| `--as LABEL=HANDLE` | exactly twice to execute or to plan; zero only for the bootstrap dry-run (§4) | §3.2 |
| `--routes PATH` | no | §3.3 |
| `--max-ops N` | no, default `50` | Integer, `2 ≤ N ≤ 100`. §9 |
| `--dry-run` | no | Compile and print the plan. No DNS, socket, credential load or attempt reservation. |

The subparser uses `_RunnerArgumentParser` (no abbreviations) and inherits the `runner`
argv guard (`heel/cli.py:960-964`). No other option exists. There is **no** Heel option,
`HEEL_*` environment variable, config key or scope field that selects a transport, scheme,
port, resolver, CA bundle, header, method, attempt ID or caller identity. The one
environment influence that does exist, OpenSSL's default trust locations, is stated in
§7.2.

### 3.2 `--as`: credential handles and plan ordering

`HANDLE` is the opaque 32-hex credential handle ID created by `heel runner credential add`.
It is not the label and no label is accepted in its place.

- `LABEL` matches `[a-z0-9][a-z0-9_-]{0,31}`. `HANDLE` matches `[0-9a-f]{32}`. The two
  labels MUST differ and the two handles MUST differ.
- Each handle MUST resolve to exactly one `active` record in the setup store. Otherwise
  reject.
- **Tier comes from the role the human chose at `credential add`.** One handle MUST have
  role `lower_plan` and the other `higher_plan` (F6). The first `--as` MUST be the
  `lower_plan` handle and the second the `higher_plan` handle. Any other combination is
  rejected. Heel never reorders, never infers tier from a label's spelling and never
  infers it from a response.
- Both records MUST share one auth profile (`heel/runner/compiler.py:160-162`).
- The label is the human's plan name. It is carried into the plan, the containment
  entries, the report and the findings. It has no effect on execution.

**Obtaining a handle.** `heel runner credential add` MUST print:

```json
{"credential_handle": "<32 hex>", "credential_source": {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_<HANDLE>"}, "registered_count": 1}
```

`credential_source.kind` is `environment`, `inherited_fd` (with `variable`) or `os_vault`
(no `variable`). The label, the role's secret and the secret's length MUST NOT be printed.

Why this is safe, and what stays private:

- A handle is random and not derived from the secret (F2). It is an index into the vault,
  not a credential. Knowing it grants nothing without the vault or the environment.
- Without it, an ephemeral credential cannot be supplied at all (F3).
- The existing boundary (F4) is unchanged: handles and labels still never enter the
  cloud-disclosed approval projection, `runner prepare` stdout stays counts only, and the
  label is still never printed by any command.
- Handles appear only in local output of `credential add` and `runner run`, in the local
  report and in local findings. They are never sent to the target.

### 3.3 `--routes`: the imported inventory

`--routes` names an **imported inventory**: a file in exactly the persisted format that
`heel runner import-openapi` writes (F5). It is not a selector and no other format is
accepted.

- Omitted (default): the setup store's current inventory, the file returned by
  `RunnerStore.route_inventory_path()` (§6.3). The dry-run prints that path, its
  `source_digest` and its route count so the operator can copy or archive it.
- Given: `PATH` is read with the existing bounded loader `_load_bounded_openapi` (regular
  file, no symlink, size-limited, duplicate keys rejected). It MUST be a complete
  `heel.runner-route-inventory.v1` envelope for the bound setup context, validated by
  `RunnerStore.route_inventory(artifact)` (§6.3). Typical
  use is a saved copy of an earlier import for the same origin.
- The file is the whole allowlist for that invocation. **Every** route in it is handed to
  the compiler (§6.2) and every route the compiler plans is executed. The CLI never
  removes, selects or rewrites a route. Execution order is the inventory's canonical order
  `(route_template, method, operation_id)`.
- An inventory file carries no signature. It is operator input at the same trust level as
  the OpenAPI document it was derived from. It can never name another origin (envelope
  check), a non-GET/HEAD method or an unsafe template (§6.2).

`--routes` never writes to the setup store and never changes the default inventory.

### 3.4 Per-route planning

Decided in the compiler (§6.2), for every route of the chosen inventory:

| Route | Decision |
|---|---|
| `GET` or `HEAD`, no placeholders | planned: 2 requests |
| `GET` or `HEAD`, placeholders, and the setup store holds a `plan_entitlement_read` mapping for exactly this `(method, route_template)` | planned with those fixture bindings: 2 requests |
| placeholders, no such mapping | `not_executed`, reason `unbound_placeholder`; never sent |
| any other method, or a route failing template rules | compile error for the whole command |

`HEAD` routes are executed exactly like `GET` routes: once with the lower-plan credential,
then once with the higher-plan credential, and never skipped. Heel never invents a path
parameter value; a human supplies one through the existing
`heel runner map --scenario plan_entitlement_read --method M --route T --fixture-fd N`.

### 3.5 Human-supplied marker

There is no marker flag. The marker is supplied through the existing channel (F16): one
fixture value beginning `heel-canary-` in the `plan_entitlement_read` mapping opts that
route into the `protected_canary` contract. Heel never generates, guesses or
extracts a marker from a response. The fixture value is never written to a finding, report
or log; only `marker_supplied: true` and the SHA-256 of the canonical binding list are. A
`HEAD` pair never has a marker (`marker_supplied: false`), whatever its fixture value.

### 3.6 Modes, output, exit codes

Mode selection, in order:

1. Scope unknown, signature invalid, unbound or expired → **reject**.
2. `--base-url` invalid, or argument rules of §3.1–3.2 violated → **reject**.
3. Normalized host is not exactly equal to an entry of `scope.target_allowlist` → **forced
   dry-run**: print the plan with `"authorized": false`, send nothing, bind nothing, append
   a `reject_run` security entry, exit `3`. This holds with or without `--dry-run`.
4. `--dry-run` → **dry-run**, exit `0`.
5. Otherwise → **execute**.

Allowlist matching is string equality between the normalized lowercase hostname and an
allowlist entry. No wildcard, suffix, scheme or port form matches.

Stdout is one JSON object. On rejection, stdout is empty and stderr is the **existing**
fixed line `Heel runner command was rejected.` (`_SAFE_RUNNER_COMMAND_FAILURE`, F31), the
same line argparse errors already produce. No new rejection constant is added. No path,
URL, label, handle, route or exception text is reflected. All exceptions are caught at the
command boundary.

| Exit | Meaning |
|---|---|
| 0 | Dry-run printed, or executed with no `observed`/`verified` finding |
| 1 | Executed; at least one `observed` or `verified` finding |
| 2 | Rejected before any request |
| 3 | Forced dry-run: host not in the scope allowlist |

Dry-run object:

```json
{"mode": "dry_run", "authorized": true, "scope_id": "...", "origin": "https://...",
 "context": "bound|already_bound|mismatch|unbound",
 "inventory": {"path": "...", "source_digest": "<64 hex>", "route_count": 9, "source": "default|file"},
 "plans": [{"label": "free", "role": "lower_plan", "credential_handle": "<32 hex>",
            "credential_source": {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_<HANDLE>"}},
           {"label": "pro", "role": "higher_plan", "...": "..."}],
 "max_ops": 50, "effective_max_ops": 50,
 "pairs": [{"ordinal": 0, "method": "GET", "route_template": "/api/export",
            "requests": 2, "marker_supplied": false},
           {"ordinal": 1, "method": "HEAD", "route_template": "/api/export",
            "requests": 2, "marker_supplied": false}],
 "not_executed": [{"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"}],
 "requests_planned": 4, "requests_sent": 0, "plan_sha256": "<64 hex>"}
```

`requests` is every request the pair sends before retries and is always `2`: one per plan
credential. `plan_sha256` is the canonical digest of origin, scope ID, both plan
entries, inventory `source_digest`, the ordered pairs with their binding digests, and
`effective_max_ops`. The executed result repeats it so an operator can compare a run with
its dry-run.

Executed object: `mode: "executed"`, `run_id`, `attempt_id`, `scope_id`, `origin`,
`plan_sha256`, `requests_sent`, `effective_max_ops`, `pairs` (one entry per planned pair:
`method`, `route_template`, `verdict`, `predicate`, `reason`, `execution_disposition`,
`candidate`, `finding_id` or `null`, `runner_run_ids`), `not_executed`, `findings` (`id`, `predicate`, `evidence_state`,
`method`, `route_template`), `chain_valid`, `report_path`. `pairs` is the truthful record
of every planned pair, including pairs that did not complete; `findings` lists only stored
findings (§11).

## 4. Operator journey and state

Two `RunnerStore` roots under `HEEL_HOME`, both private (0700/0600, no symlinks):

- **Setup store**: the default `RunnerStore()`. Holds the inventory, credential metadata
  and the optional mappings. It never executes.
- **Attempt store**: `HEEL_HOME/plan-runs/<attempt_id>/`, created per execution exactly as
  `reference/<attempt>` is today (F20). Holds manifests, grants, reservations, the
  runner's signed containment chains, redacted evidence and `report.json`.

**Bootstrap dry-run.** Because of F1 the setup store must be bound before
`import-openapi` or `credential add` can work, and `run` is the only new command. So a
dry-run that is authorized (mode 4) and finds no bound setup context binds one and
reports `"context": "bound"`. This dry-run MAY be given with zero `--as` (handles cannot
exist yet); it then prints `plans: []`, `pairs: []` and the inventory block. Binding uses
the existing `RunnerStore.bind_context` with:

- `RunnerContext("workspace_local", "project_plan_differential", "env_" +
  sha256(host)[:16], <normalized origin>, sha256(canonical{"kind":
  "heel.local-plan-differential-context.v1", "host": host}), "staging")`
- an ephemeral in-process Ed25519 identity whose private key is discarded.

This is an implementation necessity. It reads the existing signed scope, writes only
runner state, and creates, edits or re-signs no scope. The context digest is a local
label, not a cloud verification record; authorization is always the live scope check.

If the setup store is already bound to a different origin or to any cloud context, the
command MUST NOT rebind, roll over or overwrite: dry-run reports `"context": "mismatch"`
with an empty plan and execute rejects. One `HEEL_HOME` serves one staging origin.
A forced dry-run (mode 3) never binds.

Documented order (the T5 path):

```
scope create → runner run --dry-run (binds) → runner credential add ×2 (prints handles) →
runner import-openapi → [runner map] → runner run --dry-run --as … --as … (plan) →
runner run → findings --run → regress add → regress run
```

## 5. Reused modules

`heel.scope` (`get_scope`, `verify`, `heel_home`, `ensure_home`), `heel.contracts`
(`AbuseVector`, `Severity`, `Category`), `heel.store.Store`, `heel.containment`
(`ContainmentLog`, `verify_chain`), `heel.crypto.SigningAuthority`, `heel.canary_contracts`,
`heel.runner.catalog` (`CATALOG_BY_ID`), `heel.runner.compiler` (`CanaryCompiler`,
`plan_differential_pairs`), `heel.runner.http_transport` (`TargetHTTPSClient`,
`BoundedResolver`, `TLSTransport`, `normalize_target_origin`, `CancellationToken`,
`TransportFailure`), `heel.runner.execution` (`LocalCanaryExecutor`, `ExecutionBundle`,
`ExecutionGate`), `heel.runner.store` (`RunnerStore`, `RunnerContext`), `heel.runner.vault`
(`EphemeralVault`, `select_vault`, `ephemeral_environment_name`), `heel.runner.redaction`
(`Redactor`, `_secret_key`), `heel.runner.content_assertion.protected_content`,
`heel.runner.openapi_routes` (`normalize_route_template`), `heel.runner.identity`,
`heel.runner.containment` (`verify_containment_chain`).

Four existing runner modules are extended, each by the smallest change that §6 names:
`catalog.py`, `compiler.py`, `store.py`, `http_transport.py`. **Every other existing file
under `heel/runner/` MUST be byte-identical to `844fc1f` at the end of T2** — in
particular `adapters.py`, `execution.py`, `redaction.py` and `vault.py` (path gate P2,
§17).

## 6. Extensions to existing modules

Each subsection is the complete permitted change to that file. The uncommitted T2 tree
already contains hunks for all six files; §14.3 says which are reused and which reworked.

### 6.1 `heel/runner/catalog.py` — `HEAD` for the plan pair

`plan_entitlement_read`: `allowed_methods` becomes `("GET", "HEAD")`. Nothing else
changes: roles stay `("lower_plan", "higher_plan")`, statuses stay `(200, 402, 403, 404)`,
`adapter_version` stays `"1"`.

This is what makes the two-request rule possible. One `plan_entitlement_read` manifest is
exactly two actions, `lower_plan` then `higher_plan` (F26), and after the widening the
compiler, `prepare_action` and the transport's `_valid_route` accept `HEAD` for it because
all three read the catalog (F25). So a planned `HEAD` route is **one run with two
actions: one `HEAD` carrying the lower-plan credential, then one `HEAD` carrying the
higher-plan credential.** There is no `anonymous` action, no third credential record and
no second run. `anonymous_authenticated_read` is not used by this feature at all.
Measured in F34.

The change is additive inside the already closed read-only `GET`/`HEAD` set. A `HEAD` pair
still always assesses `inconclusive` in the executor (F7). Consequence the docs MUST
state: `heel runner map` and `heel runner prepare` now accept a `HEAD` mapping for
`plan_entitlement_read`.

### 6.2 `heel/runner/compiler.py` — the route and method allowlist

Add one module-level pure function and one `CanaryCompiler` method. Change nothing else
in the file except the import they need.

```python
def plan_differential_pairs(
    inventory_routes: Sequence[Mapping[str, Any]],
    *, mapping: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:      # (planned, not_executed)

class CanaryCompiler:
    def compile_plan_differential_pair(
        self, *, method: str, route_template: str,
        fixture_bindings: Mapping[str, str],
    ) -> CompileResult:
```

`plan_differential_pairs` is the per-route allowlist of brief §1.2. It takes the **raw**
route list of the chosen inventory. For a `--routes` file that is the list as parsed from
the file, **before** the store or any other code has validated or filtered it. `mapping`
is the setup store's `plan_entitlement_read` mapping or `None`. It MUST:

- raise `ValueError` if any entry's method is not in
  `CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"]`, so a `POST` (or any other)
  inventory entry is a compile error for the whole command;
- raise `ValueError` if the argument is not a list of closed `{method, route_template,
  operation_id, placeholders}` records, if `normalize_route_template` rejects or changes a
  template, if placeholders disagree, if a `(method, route_template)` repeats, or if there
  are more than 2000 entries;
- return planned and not-executed routes per §3.4 in canonical order
  `(route_template, method, operation_id)`. It never adds, rewrites or derives a route.

`compile_plan_differential_pair` compiles one pair in the attempt store. It MUST:

- raise unless `method` is in the catalog's allowed methods for `plan_entitlement_read`;
- raise unless `(method, NFC route_template)` is exactly in `self.store.list_routes()`.
  This is an independent membership check against the persisted inventory of the store
  the compiler is bound to, not against the caller's list;
- call `self.store.save_mapping("plan_entitlement_read", …)` (which re-checks membership,
  `heel/runner/store.py:6924-6930`), then `self.compile(["plan_entitlement_read"])`;
- raise unless the result has **exactly two actions**, both with that method and
  template, roles `lower_plan` then `higher_plan`.

### 6.3 `heel/runner/store.py` — read-only inventory access

Add two read-only public methods to `RunnerStore`. No existing method changes behavior.

- `route_inventory(artifact: Mapping[str, Any] | None = None) -> dict` returns
  `{"source_digest", "routes"}`. With `None` it reads `routes.json` and raises if there is
  none. With a parsed artifact it applies the same `_validate_envelope` (schema,
  namespace, origin, verification-record digest of the bound context) and the same route
  and canonical-order checks used for the stored file. The body of the existing
  `_routes_locked` is factored into one private validator so both paths share it;
  `list_routes()` returns what it returned before (F32).
- `route_inventory_path() -> Path` returns the `routes.json` path of the bound context.

Neither method writes. A supplied artifact never replaces the stored inventory.

### 6.4 `heel/runner/http_transport.py` — trust loading

`TLSTransport.__init__` additionally calls `self.context.load_default_certs()`. Protocol,
`CERT_REQUIRED` and `check_hostname` are unchanged, so the pinned test (F12) still holds.
Without this the production client cannot complete any handshake (F11). Nothing else in
the file changes, and no constructor gains a parameter. Only this feature constructs the
class in product code (F33). The trust boundary this creates is stated in §7.2.

### 6.5 `heel/cli.py`

- `runner run` subparser, handler `_runner_run(args)`, one dispatch line. Rejections print
  `_SAFE_RUNNER_COMMAND_FAILURE`. No new constant.
- `_runner_credential_add` prints the object of §3.2 using the record returned by the
  store. No other command's behavior or output changes.
- `_runner_run` passes the parsed `--routes` object through untouched; it contains no
  route or method logic.

### 6.6 `heel/regressions.py`

The replay branch of §10 in `run_regressions`.

### 6.7 Why every wire request is a compiled, allowlisted action

1. Planning calls `plan_differential_pairs` on the raw route list (§7.1 step 2). A
   non-`GET`/`HEAD` entry stops the command there.
2. Each planned pair is compiled by `compile_plan_differential_pair`, which re-checks the
   method and the attempt store's own inventory and returns exactly two actions.
3. `_ScopedTransport` (§7) is constructed for that one compiled pair and refuses any
   action whose scenario is not `plan_entitlement_read`, whose method is not `GET` or
   `HEAD`, whose role is not `lower_plan` or `higher_plan`, or whose `(method,
   route_template)` is not that pair, with `TransportFailure("gate_rejected")` before any
   budget, log or socket activity.
4. `_ScopedTransport.request` is the only call site of `TargetHTTPSClient.request` in the
   new module, and `LocalCanaryExecutor.execute` is only ever given a `_ScopedTransport`.
5. Behind these, the unmodified `prepare_action` and the transport's `_valid_route`
   remain as independent checks (F25), and the transport refuses a non-anonymous role
   without a credential.

Tests prove each numbered sentence (I2).

## 7. New module `heel/runner/plan_differential.py`

Public functions (everything else underscore-private):

| Function | Purpose |
|---|---|
| `plan_differential(scope_id, base_url, plans, *, caller, routes_artifact=None, max_ops=50) -> dict` | Verify scope, normalize origin, decide mode, bind the setup store when allowed, build the plan. No network. |
| `run_plan_differential(scope_id, base_url, plans, *, caller, routes_artifact=None, max_ops=50, attempt=None) -> dict` | Execute. Returns the executed object of §3.6. |
| `replay_plan_differential(store, regression, *, scope_id, target, caller) -> dict` | One-pair replay for `heel regress run` (§10). |
| `evaluate_plan_pair(lower, higher, *, method, marker, executor_outcome) -> PairVerdict` | Pure function implementing §8. No I/O. |
| `key_paths(value) -> frozenset[str]` | Pure, bounded (§8.2). |
| `is_denial_envelope(value) -> bool` | Pure (§8.3). |

`plans` is `[(label, handle), (label, handle)]`, lower first. `routes_artifact` is the
parsed JSON of `--routes` or `None`. `caller` MUST be a non-empty string beginning `cli:`;
anything else raises before any state is touched. `attempt` is **not reachable from the
CLI**: the CLI always passes `None`, meaning `secrets.token_hex(16)`.

Private pieces:

| Name | Purpose |
|---|---|
| `_authorize(scope_id, host)` | `get_scope` + `verify` + exact allowlist equality. Re-reads the scope file from disk on every call. Used at entry and inside the gate. |
| `_prepare(...)` | Builds the plan for both public entry points: steps 1–3 of §7.1. Calls `plan_differential_pairs` and `RunnerStore.route_inventory` (§6.2, §6.3). No network. |
| `_Budget` | The invocation-wide op counter of §9. |
| `_build_client(origin) -> TargetHTTPSClient` | The only client constructor. One bounded `BoundedResolver()` preflight, then `TargetHTTPSClient(origin=origin, preflight_addresses=answers)` with **no** `resolver`, `sockets` or `tls` argument, so the defaults `BoundedResolver`, `SocketTransport` and `TLSTransport` (with §6.4 trust loading) are used. It takes no other parameter and reads no Heel environment variable, file or config. |
| `_AttemptReservation` | Result of the exclusive `os.mkdir`. Holds attempt ID and root. Constructed only by `_reserve_attempt`. |
| `_PlanVault` | `supported=True`, `backend_id="ephemeral_env"`. Maps each of the two attempt-store handles to its setup-store record. Loads each real secret **once per invocation** from its real vault (`EphemeralVault` or `select_vault(backend)`), keeps it in memory only, registers it with the redacting store and the tolerant redactor, and clears it at exit. Refuses (`VaultUnavailable`) a bearer or API-key value, or any cookie value, shorter than 8 bytes, because it cannot be redacted reliably. |
| `_RedactingRunnerStore(RunnerStore)` | Overrides only `store_response_evidence`: before delegating, replaces every registered secret, in raw form and in JSON-string-escaped form, in `raw_headers` and `raw_body` with `b"[REDACTED:secret]"`. Needed because the executor stores raw bytes (F14). |
| `_TolerantRedactor(Redactor)` | §7.4. |
| `_ScopedTransport` | Wraps the client for **one compiled pair**. Requires an `_AttemptReservation` whose directory exists, else raises `TransportFailure("gate_rejected")`. Refuses any action that is not that pair (§6.7 item 3). Replaces the `redactor` argument with the `_TolerantRedactor` (§7.4). Wraps the executor's `before_attempt` as in §9. |
| `_gate(scope_id, host)` | `gate_source` for the executor. Calls `_authorize` each time; inactive if the scope no longer verifies or no longer lists the host. |
| `_grant(...)` | As `reference_rehearsal._grant`, with `approval_actor {"user_id": "local_operator", "role": "owner"}` and a reason naming the scope ID. Ephemeral `SigningAuthority`, trusted only in this process. |
| `_finding(...)` | Builds one `AbuseVector` (§11). |

### 7.1 Execute sequence

1. `caller` check. `_authorize`. Normalize origin. Host not in allowlist → forced dry-run
   result, stop. Setup context MUST be bound to this origin, else reject.
2. Resolve both handles (§3.2). Take the raw route list: for a `--routes` artifact,
   `artifact["inventory"]["routes"]` exactly as parsed; otherwise
   `setup.route_inventory()["routes"]`. Call `plan_differential_pairs(raw, mapping=…)`
   **first**, then `setup.route_inventory(artifact)` for the envelope and
   `source_digest`. Either failing → reject. Zero planned pairs → reject.
3. Budget (§9). Planned pairs beyond `effective_max_ops // 2` become `not_executed`
   (`over_budget`).
4. **Reserve the attempt**: `os.mkdir(HEEL_HOME/plan-runs/<attempt>, 0o700)`, exclusive. An
   existing directory is a replay and is rejected. Nothing above this line touches the
   network; nothing below runs without it.
5. Open `Store(HEEL_HOME/heel.db)`; `add_run("pdrun-<attempt>", scope_id, origin, caller,
   "running", …)`; containment `run_start`.
6. Build the attempt store (`_RedactingRunnerStore`), ephemeral signer and identity, bind
   the same context values as the setup store, `replace_routes(<whole inventory>,
   source_digest=…)`. Register exactly two ephemeral credential records, `lower_plan` and
   `higher_plan`, served by `_PlanVault`. No other credential record exists in an attempt
   store.
7. `_build_client(origin)` once: one DNS preflight pins the address set for the invocation.
8. For each planned pair in order: skip as `not_executed` (`budget_exhausted`) if fewer
   than 2 ops remain; else `compile_plan_differential_pair` → `_grant`
   (`run_id="crun_<attempt>_<nn>"`, 30 s expiry) → `LocalCanaryExecutor.execute(bundle,
   transport=_ScopedTransport, gate_source=_gate, cancellation=token)`. The executor
   reserves the grant and sends lower then higher: two requests, the same for `GET` and
   `HEAD`.
9. After each pair: read both evidence records from the attempt store, matched by
   `action_ordinal` as `reference_rehearsal.py:160-167` does; run `evaluate_plan_pair`;
   append a `plan_differential_pair` containment entry carrying the verdict, reason and
   the executor's true `execution_disposition`. Then, **only when the executor disposition
   is `completed` and the verdict is not `held`** (§8.5 rows 2, 3,
   5, 6, 8, 9), `add_finding` plus a `finding` containment entry. A pair that did not
   complete (row 1) stays in the result and `report.json` as `inconclusive` with its true
   disposition and reason, and creates **no** `AbuseVector`.
10. Continue to the next pair only when the pair completed or failed with executor
    `error_category == "containment_rejected"` (a response-level refusal). On any other
    failure or a stop, mark the pair `inconclusive` and all later pairs `not_executed`
    (`run_stopped`).
11. `set_run_status("complete")`, containment `run_complete`, `verify_chain`, write
    `report.json` (`O_EXCL|O_NOFOLLOW`, 0600), return.

Any exception after step 4 MUST leave the run row with a terminal status (`complete` or
`rejected`) and a `run_complete` or `run_failed` containment entry, and MUST NOT leave
credential bytes anywhere under `HEEL_HOME`.

### 7.2 Network decisions and the real trust boundary

| Topic | Decision |
|---|---|
| Scheme | HTTPS only. No HTTP, loopback, private-address or custom-port capability exists in product code and no switch enables one. |
| TLS | Certificate required, hostname checked, SNI = normalized host. TLS 1.2 only (inherited, F12). A TLS failure ends the invocation (`transport:tls_error`). |
| Trust anchors | `load_default_certs()` in `TLSTransport.__init__` (§6.4): the default trust locations of the Python build's TLS library. **`SSL_CERT_FILE` and `SSL_CERT_DIR` in the process environment change those locations (F29).** Heel adds no option, `HEEL_*` variable, config key or scope field for trust. |
| DNS | One bounded preflight per invocation; every answer must be public; the set is pinned. Each attempt re-resolves and requires set equality, connects to the pinned numeric address and re-checks the peer (F10). A change ends the invocation (`dns_changed`). A replay re-preflights and never reuses stored addresses. |
| Host header | Always the normalized hostname, built by the transport (F9). |
| Redirects | Never followed, on or off the allowlist (F9). The pair is `inconclusive` (`transport:response_rejected`). |
| Encodings | `Accept-Encoding: identity`. Chunked or content-encoded responses are refused (F13). |

**Trust boundary, stated plainly.** The operator's process environment and `HEEL_HOME`
are inside the trust boundary: the environment already supplies the credentials
(`HEEL_RUNNER_CREDENTIAL_<HANDLE>`), the data directory and the user name. Someone who
controls that environment can also choose the CA set through `SSL_CERT_FILE` or
`SSL_CERT_DIR`. Heel does not defend against that and the docs MUST say so. What Heel
guarantees is narrower and is tested: no Heel argument, Heel variable, inventory file or
scope field changes the transport, resolver, port or trust store, and certificate and
hostname verification are always on.

### 7.3 Test seams versus the unmodified public CLI

There is exactly one seam: tests replace the module attribute
`heel.runner.plan_differential._build_client`. It is not a parameter of any public
function and no argv, environment variable, file or scope field can set it.

| What | How it is tested | What it proves and does not prove |
|---|---|---|
| Argument rules, rejection, forced dry-run, bootstrap, plan, `credential add` output | `heel.cli.main(argv)` with **no** seam, with `socket.socket` and `socket.getaddrinfo` patched to fail | The unmodified public CLI, and that these paths open no socket. |
| Execution, findings, containment, regression replay | `heel.cli.main(argv)` with `_build_client` replaced by a factory returning a real `TargetHTTPSClient` whose injected `resolver` returns a fixed public address, whose `sockets` connects to the loopback synthetic target and reports the pinned address from `getpeername`, and whose `tls` is a pass-through | Request construction, `Host`, framing, 3xx refusal, body rules, compiler checks, gate, budget, reservation, evidence, redaction, predicates and logging are product code. **It proves nothing about TLS, DNS answers or address selection.** |
| Production client construction | `_build_client` unreplaced, with only `socket.getaddrinfo` patched to return a public address | The production path builds `BoundedResolver`, `SocketTransport` and the default `TLSTransport` with certificate verification, hostname checking and default trust loading, and passes no seam object. No handshake is performed. |
| Trust environment | `_build_client` unreplaced, `SSL_CERT_FILE` set to a CA generated in the test | That the stated boundary of §7.2 is accurate (R23). |
| Real TLS verification | A real `TLSTransport` wraps a real socket to a loopback `ssl` server whose certificate is issued by a test CA generated in the test. The test adds that CA to `transport.context` | The real class performs a real handshake, accepts a matching chain and hostname, and rejects a wrong hostname and an untrusted issuer. It does not prove the contents of the system trust store or a public PKI handshake. |

No CI test performs a real public HTTPS request through the full client. No test in this
feature may be described as proving real TLS behavior unless it is the real-handshake test
above.

### 7.4 Numeric and large JSON bodies: the redaction-count seam

The failure (F27) is in a **count**, not in redaction of stored data. The inherited
`Redactor.count_bytes` parses a JSON body with rules meant for outbound projections and
raises on ordinary values; the transport turns that into `evidence_rejected`, which the
executor classifies as a runner fault, which §7.1 step 10 treats as the end of the run.

Seam (F28, proven in F30): the executor hands its `Redactor` to `transport.request()`.
`_ScopedTransport` replaces that argument with a `_TolerantRedactor`, a subclass of
`Redactor` constructed with the invocation's registered secret strings.

`_TolerantRedactor.count_bytes(*chunks)`:

1. Return `super().count_bytes(*chunks)` when it succeeds. Behavior is unchanged for every
   body the inherited redactor accepts.
2. If it raises `TypeError` or `ValueError`, re-check the inherited argument rules itself
   (at least one chunk, every chunk `bytes`, every chunk ≤ 256 KiB) and re-raise if they
   fail. Otherwise return `min(1024, n)` where `n` is the number of occurrences of the
   registered secrets (raw and JSON-string-escaped) in the chunks.
3. It overrides nothing else and reads no private attribute of the base class.

Why this is safe:

- What is stored is decided by `_RedactingRunnerStore`, which removes every registered
  credential from headers and body before the bytes reach disk, for every body shape. The
  count plays no part in that (F27, F30c).
- The count only feeds `redaction_count` in local results and the signed `redacted` event.
  In the fallback it counts exactly what was replaced on disk.
- No bound is lifted: the 256 KiB body limit, the one-JSON-object rule and the header
  limits are the transport's and are unchanged.

Bodies containing floats, negative integers, large integers, more than 256 members, more
than 1024 nodes or depth above 16 therefore complete normally and are judged by §8. The
predicate parser of §8.1 is the module's own and accepts all finite JSON numbers.

If the store itself refuses evidence, the pair is still `transport:evidence_rejected` and
the run stops (step 10): that is a local storage fault, not a response property.

## 8. Predicates

### 8.1 Inputs

For lower (`L`) and higher (`H`): `status`, `body` (the stored, redacted bytes), `json`
(parsed with duplicate-key rejection and `NaN`/`Infinity` rejection; `None` if empty or
unparseable). Plus `method`, `marker` (the supplied `heel-canary-` value or `None`) and
the executor's `execution_disposition` and `assessment_outcome`.

`2xx` = 200–299. `denial status` = 401, 402, 403, 404.
`P(x) = protected_content(x.body, marker=marker, status=x.status, method=method)`.

### 8.2 `key_paths`

Computed on the parsed, redacted body. For an object, each key `k` at path `p` adds
`p.k`; recursion continues into the value unless `redaction._secret_key(k)` is true. For
an array at path `p`, add `p[]` and recurse into every element, unioning results. Scalars
add nothing. Bounds: depth ≤ 16, visited nodes ≤ 4096; exceeding either makes
`body_superset` undetermined (`body_too_complex`).

### 8.3 Denial envelope

A parsed top-level object is a denial envelope when any of: `error` or `errors` is truthy;
`ok` or `success` is exactly `false`; any of `upgrade_required`, `payment_required`,
`denied`, `forbidden` is exactly `true`. The list is closed and small. It only ever
**withholds** parity; it never creates a finding, never creates a `held` verdict and never
creates a regression pass.

### 8.4 Three-valued predicates

Each is `True`, `False` or `None` (undetermined).

`completed` := the pair's run has executor disposition `completed` and both evidence
records load and verify.

`positive_control` := `completed` ∧ `H.status` is 2xx ∧ `H.json` is not a denial envelope
∧ (`marker` supplied ⇒ `H.status == 200` ∧ `P(H)` is `True`).

| Predicate | `None` when | `True` when | `False` when |
|---|---|---|---|
| `status_parity` | no `positive_control`; or `L.status` is neither 2xx nor a denial status; or `L.status` is 2xx and `L.json` is a denial envelope | `L.status` is 2xx and `L.json` is not a denial envelope | `L.status` is a denial status |
| `body_superset` | no `positive_control`; or `method` is `HEAD`; or `H.json` is not an object; or `key_paths(H)` is empty; or a bound is exceeded; or `L.json` is a denial envelope | `L.status` is 2xx, `L.json` is an object, not a denial envelope, and `key_paths(L) ⊇ key_paths(H)` | otherwise (lower denied by status, lower empty, or lower lacks a higher key path) |
| `marker_leak` | no marker; or `method` is `HEAD`; or no `positive_control`; or `P(L)` is `None`; or the executor's `assessment_outcome` disagrees | `P(L)` is `True` and executor outcome is `observed` | `P(L)` is `False` and executor outcome is `blocked` |

A 2xx denial envelope therefore makes `status_parity` and `body_superset` undetermined,
never true and never false.

### 8.5 Verdict table — first matching row wins

| # | Condition | Verdict | `evidence_state` | Predicate / reason |
|---|---|---|---|---|
| 1 | not `completed` | inconclusive, **no finding stored** | — (report only) | `inconclusive` / one of the closed list below |
| 2 | no `positive_control` | inconclusive | `inconclusive` | `inconclusive` / `no_positive_control` or `positive_control_missing_marker` |
| 3 | `marker_leak` is `True` | finding | `verified` | `marker_leak` |
| 4 | `marker_leak` is `False` | held | — | `marker_absent` |
| 5 | marker supplied (and `marker_leak` is `None`) | inconclusive | `inconclusive` | `inconclusive` / `marker_undetermined` |
| 6 | `body_superset` is `True` | finding | `observed` | `body_superset` |
| 7 | `status_parity` is `False` | held | — | `lower_denied` |
| 8 | `status_parity` is `True` | inconclusive, `candidate: true` | `inconclusive` | `status_parity` / `head_status_only`, `status_only` (no comparable bodies) or `lower_subset` |
| 9 | otherwise | inconclusive | `inconclusive` | `inconclusive` / `lower_denial_envelope`, `unexpected_status` or `body_too_complex` |

Row-1 reasons (closed): `transport:<code>` where `<code>` is the transport failure code
recorded by the runner's signed log; `stopped`; `budget_exhausted`;
`credential_unavailable`; `executor:<error_category>` for any other executor error
category; `executor_rejected` when `execute` raised before producing a result;
`evidence_unavailable` when a completed run's evidence cannot be loaded or verified.
`not_executed` reasons (closed): `unbound_placeholder`, `over_budget`,
`budget_exhausted`, `run_stopped`.

Fail-closed requirements (tested, R11):

- Status parity alone never yields `observed`, `verified` or `held`.
- A 2xx denial envelope never yields `observed`, `verified` or, without a marker, `held`.
- A HEAD pair can only be `held` (row 7) or `inconclusive`.
- `verified` is reachable only through row 3; `observed` only through row 6.
- An exception inside evaluation yields `inconclusive` (`predicate_error`), never a pass.
- `candidate` is `true` on row 8 (`status_parity`) and `false` on every other row.
- Row 1 never stores a finding; rows 4 and 7 (`held`) never store a finding.
- Heel never derives the tier, the marker or the expected result from a response.

Empty and non-JSON bodies: an empty 2xx body has `json = None`, so `body_superset` is
`None` (higher) or `False` (lower) and the pair lands on row 7, 8 or 9. A non-empty body
that is not one JSON object is refused by the transport (F13) and is row 1
(`transport:response_rejected`), as is a body over 256 KiB (`transport:response_too_large`).

Honest scope of `observed`: row 6 says the lower plan received every field the higher plan
received on that one read. Heel holds no declaration that the route is plan-gated, so a
route that is ungated by design will also be reported. The finding text MUST say this.
`held` (row 7) says only that the lower plan was refused by status on this one read while
the higher plan succeeded.

## 9. Requests, budget, reservation, logging

- **Unit**: one op is one request attempt on the wire, including a retry. Every op carries
  one of the two plan credentials.
- `effective_max_ops = min(--max-ops, scope.rate_and_resource_limits["max_requests"])` when
  the scope defines an integer `max_requests`, else `--max-ops`. If the result is < 2, or
  `Store.scope_run_count(scope_id) >= max_requests` (the rule `heel_run` already applies),
  reject.
- Every pair, `GET` or `HEAD`, needs exactly 2 ops before retries.
- **Per-attempt order**, inside the wrapped `before_attempt`, before any socket:
  1. `_authorize` again; failure raises `gate_rejected`.
  2. take one unit from the invocation-wide counter, or raise `gate_rejected` with
     `gate_error="budget_exhausted"`;
  3. call the executor's own `before_attempt` (grant authority, per-manifest budget,
     retry rules, signed `action_started` event);
  4. append one HMAC containment entry `plan_differential_request` with `method`,
     `route_template`, plan `label`, `role` (`lower_plan` or `higher_plan`), `attempt`,
     `runner_run_id`, `op_index`. If the append fails the attempt is refused.
  Only then does the transport resolve and connect. So total wire requests never exceed
  `effective_max_ops`, and no request exists without an earlier entry. An entry MAY exist
  for an attempt that then failed in DNS or connect.
- The per-manifest `BUDGETS` and `RETRY_POLICY` (one retry, `connect_error`/`timeout`)
  apply unchanged inside each run. Concurrency is one.
- `--max-ops ≤ 100` keeps one attempt at ≤ 50 reserved runs (one run per pair), below the
  store's 64-run tracking bound
  (`heel/runner/store.py:190`).
- **Attempt ID**: generated by Heel, reserved by exclusive `mkdir`, never reusable. Each
  run additionally consumes its own one-shot grant through `RunnerStore.reserve_run`
  (F14). A crashed or cancelled attempt stays consumed.
- **Scope reuse**: one scope serves many invocations until it expires or its run count is
  exhausted. Heel never extends, re-signs or rewrites it.

## 10. Regression replay

`heel regress add --run <pdrun-…> --vector <pdv-…> --name N` works unchanged: the vector
has a `scenario_id`, and `add_regression_from_finding` falls back to
`_affordance_pattern_from_vector` and `{"observed": reproduction["observed"]}`
(`heel/regressions.py:64-78`).

`heel regress run --target <origin> --scope <scope-id>`: one branch at the top of the loop
in `run_regressions`.

- A regression whose `scenario_id` starts with `plan_differential.` is handled by
  `replay_plan_differential` and never reaches `server.heel_run`.
- When `--target` starts with `https://`, regressions of other kinds are skipped. When it
  does not, plan-differential regressions are skipped.

`replay_plan_differential` loads the original vector with `store.find_vector(
original_vector_id, run_id=source_run_id)` and reuses, exactly as saved:

| Saved value | Replay rule |
|---|---|
| `base_origin` | `target` MUST equal it |
| `scope_id` | `--scope` MUST equal it, and the scope MUST still verify and list the host |
| `plans` (labels, roles, handles, in order) | the same two handles MUST still be `active` with the same roles; same order |
| `predicate` | the same predicate is re-evaluated |
| `method`, `route_template` | MUST still be in the current default inventory; planned and compiled through §6.2 |
| `fixture_bindings_sha256`, `marker_supplied` | the current mapping's binding digest MUST equal it |

Any mismatch produces result `fail` with `current_status: "inconclusive"` and **no
request**. Otherwise the full execute sequence of §7.1 runs for that one pair with a new
attempt ID and `max_ops=4` (two requests and at most one retry of each). The saved predicate `p` is re-evaluated on the new responses
and the result is decided by the first matching row:

| # | Fresh evaluation | `result` | `current_status` |
|---|---|---|---|
| 1 | `p` is `True` | `fail` | `still_reachable` |
| 2 | verdict is `held` (§8.5 row 4 or 7): the positive control succeeded and the lower plan was denied by status, or the marker was absent | `pass` | `blocked` |
| 3 | anything else | `fail` | `inconclusive` |

So a pass needs an affirmative denial. In particular:

- **A 2xx denial envelope is `fail` / `inconclusive`.** With an envelope, `body_superset`
  and `status_parity` are undetermined (§8.4), the verdict is `inconclusive`
  (`lower_denial_envelope`), and row 3 applies. `body_superset` becoming not-true is never
  a pass by itself.
- A lower response that is 2xx with fewer fields (`lower_subset`) is `fail` /
  `inconclusive`: the lower plan still received content.
- A replay pair that does not complete is `fail` / `inconclusive` and stores no finding.
- For a saved predicate of `inconclusive` there is no `p`; rows 2 and 3 decide.

`result` is only ever `pass` or `fail`. The result record keeps the existing fields
(`matches_expected = current_status == expected_status`) plus `result`, and is stored with
`add_regression_result` and a `regression_result` containment entry.

## 11. Finding schema

**Eligibility.** One `AbuseVector` is stored with `Store.add_finding` for a pair if and
only if the pair's run has executor `execution_disposition` exactly `completed` and the
verdict is not `held`. Pairs that did not complete (`incomplete`, `failed`,
`stopped`, or never started) and `held` pairs create no `AbuseVector`; they are recorded
in the result `pairs`, in `report.json` and in the containment log only. Every stored
finding therefore has `reproduction.execution_disposition == "completed"` (brief §1.6).

| Field | Value |
|---|---|
| `id` | `"pdv-" + sha256(f"{run_id}:{method}:{route_template}")[:12]` |
| `scenario_id` | `"plan_differential." + predicate` (`body_superset`, `marker_leak`, `status_parity`, `inconclusive`) |
| `category` | `Category.LICENSE_ENTITLEMENT` |
| `target_id` | normalized origin |
| `affordance_id` | `method + " " + route_template` |
| `severity` | `verified`: 0.9 × 0.7, uncertainty 0.1. `observed`: 0.6 × 0.6, uncertainty 0.3. `inconclusive`: 0.2 × 0.4, uncertainty 0.5. Fixed priors, not measured. |
| `reachability_score` / `plausible` | 1.0 / `True` for `verified` and `observed`; 0.3 / `False` for `inconclusive` |
| `recommended_control` | "Enforce the plan entitlement check server-side on this read before the response is serialized." |
| `verification_status` | `PREDICTED` |
| `notes` | For `observed`: the honest-scope sentence of §8.5 |

`reproduction` (closed; no other keys):

```json
{"contained": true, "sample": "canary_only",
 "evidence_state": "observed|verified|inconclusive",
 "execution_disposition": "completed",
 "predicate": "body_superset|marker_leak|status_parity|inconclusive",
 "reason": "<reason code>", "candidate": false,
 "hypothesis": "endpoint_without_plan_gate|export_without_entitlement",
 "operator_declared": false,
 "observations": [
   {"label": "free", "role": "lower_plan", "status_code": 200, "body_shape": "json_object",
    "key_path_count": 7, "response_bytes": 412,
    "request_ref": {"method": "GET", "route_template": "/api/export",
                    "host": "staging.example.com", "credential": "[REDACTED:secret]"},
    "response_ref": "ev1_<64 hex>"},
   {"label": "pro", "role": "higher_plan", "...": "..."}],
 "observed": {"predicate": "...", "method": "GET", "route_template": "...",
              "base_origin": "https://staging.example.com", "scope_id": "...",
              "plans": [{"label": "free", "role": "lower_plan", "credential_handle": "<32 hex>"},
                        {"label": "pro", "role": "higher_plan", "credential_handle": "<32 hex>"}],
              "marker_supplied": false, "fixture_bindings_sha256": "<64 hex>",
              "inventory_source_digest": "<64 hex>",
              "lower_status": 200, "higher_status": 200},
 "attempt_id": "...", "runner_run_ids": ["crun_<attempt>_<nn>"], "plan_sha256": "<64 hex>",
 "provenance": {"kind": "plan_differential_execution", "network_calls": true,
                "target_verification": "signed_local_scope_only"}}
```

- `execution_disposition` is always the literal `completed`, and it is always true: it is
  copied from the executor result, and a pair with any other disposition is never stored
  as a finding. The implementation MUST NOT write `completed` for a pair that did not
  complete; it writes no finding instead.
- `candidate` is a JSON boolean: `true` if and only if `predicate == "status_parity"`
  (§8.5 row 8); `false` for `body_superset`, `marker_leak` and `inconclusive`.
- `inconclusive` findings exist only for completed pairs (rows 2, 5, 9 and
  `predicate_error`).
- `observations[].role` is the plan role (`lower_plan`, `higher_plan`) for `GET` and
  `HEAD` alike. `runner_run_ids` has exactly one entry.
- `hypothesis` is `export_without_entitlement` when a marker was supplied for the route,
  else `endpoint_without_plan_gate`. It is not inferred from route names.
- `observed` is the block `regress add` copies; it is everything replay needs (§10).
- Raw headers and bodies stay in the attempt store. No key-path names, body text, fixture
  value or credential appear in a finding. Handles appear (§3.2); labels of credentials do
  not.

## 12. Safety invariants → named tests

All in `tests/test_runner_plan_differential_safety.py` unless a file is named. Every test
that sends a request sends it only to the loopback synthetic target, bound to port 0 per
test. Each brief §1.8 bullet is mapped in the last column.

| # | Invariant | Named tests | Must prove | §1.8 bullet |
|---|---|---|---|---|
| I1 | **Host confinement.** No connection to any host outside the scope allowlist, including through a redirect. | `test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`; `test_i1_host_header_is_always_the_normalized_host` | (a) host not in allowlist → forced dry-run, exit 3, zero connections on the target and on a second listener; (b) a route answering `302 Location:` the second listener yields zero connections there and an `inconclusive` pair; (c) IPv4 literal, IPv6 literal, `http://`, port, userinfo, trailing dot and punycode base URLs are rejected before any socket; (d) a resolver whose answer changes after preflight ends the run with `dns_changed` and no further request; (e) every request seen by the target has `Host` equal to the normalized host. | No request to a host outside the scope allowlist, ever, including redirects |
| I2 | **GET/HEAD and inventoried-route confinement, enforced in the compiler.** | `test_i2_only_inventoried_get_and_head_reach_the_wire`; `test_i2_post_inventory_is_rejected_at_compile`; `test_i2_every_transport_action_is_the_compiled_pair` | (a) an inventory artifact with a `POST` entry reaches `heel.runner.compiler.plan_differential_pairs` unfiltered (the test wraps the function and records its argument) and is rejected there before `RunnerStore.route_inventory` is called; the command exits 2 with zero requests; (b) `CanaryCompiler.compile_plan_differential_pair` refuses a route absent from the bound store's inventory and a non-GET/HEAD method, and returns exactly two actions `lower_plan`, `higher_plan` for a `GET` and for a `HEAD` route; (c) across a full run the target's log contains only `GET` and `HEAD` and only planned paths; (d) `_ScopedTransport.request` with a well-formed action of another scenario, another route, another method, or a role other than `lower_plan`/`higher_plan` raises `gate_rejected` with zero connections, zero budget use and zero log entries; (e) by AST of the new module: `TargetHTTPSClient.request` is called only inside `_ScopedTransport`, `execute(` is called only with a `_ScopedTransport`, every `_ScopedTransport` is constructed from a `compile_plan_differential_pair` result, and `_build_client` is referenced only at its definition and one call site; (f) by AST of `heel/cli.py`: `_runner_run` passes the loaded artifact to the module unmodified and contains no reference to `method`, `route_template` or `routes` keys. | No method other than GET/HEAD |
| I3 | **Verified signed scope.** | `test_i3_no_request_without_verified_signed_scope` | Unknown scope, hand-edited scope file (allowlist widened), expired scope and unbound scope each give exit 2 and zero requests; a scope file edited after the first pair stops the run before the next request. | No request without a signed scope … |
| I4 | **One-shot reserved attempt.** | `test_i4_no_request_without_one_shot_reserved_attempt` | (a) reusing an attempt ID is refused with zero requests; (b) `_ScopedTransport` built without a reservation, or whose directory is gone, refuses with zero connections; (c) with `reserve_run` forced to fail, zero requests are sent; (d) a consumed grant cannot be executed twice. | … and a reserved attempt ID |
| I5 | **Secret exclusion.** | `test_i5_credential_plaintext_absent_from_heel_home_and_output` | After a successful run, a run against a route echoing the credential in a header and in the body, a run whose echoing body also contains floats and negative integers, a run failing in transport, a run stopped by scope tamper, and a run with a missing credential: a byte scan of every file under `HEEL_HOME` (`heel.db`, evidence `.bin`, reports, both containment logs) finds neither credential, and stdout, stderr, findings and containment rows contain neither. | Credentials never appear in reports, logs, findings, or containment entries |
| I6 | **Every request logged.** | `test_i6_every_request_is_logged_before_it_is_sent` | In a run with no append failure, count of `plan_differential_request` entries == sum of runner `requests_started` ≥ requests counted by the target, including a forced retry; each target request maps to a distinct entry appended before it arrived; a failing append sends nothing. | Containment log records every request … |
| I7 | **Caller attribution.** | `test_i7_every_containment_entry_carries_cli_caller` | Every containment row for the run has `caller == "cli:<user>"`; `run_plan_differential` raises for an empty or non-`cli:` caller before any state change. | … with caller attribution |
| I8 | **Chain integrity.** | `test_i8_containment_chains_verify_and_detect_tamper` | `containment.verify_chain` is true after success and after failure; mutating one stored row makes it false; the runner's signed chain verifies for each `crun_` run with `verify_containment_chain`. | chain verifies |

Independent requirements:

| # | Requirement | Named test | File and proof |
|---|---|---|---|
| R9 | Total request budget | `test_r9_max_ops_hard_caps_total_requests` | safety — with `max_ops=5` and retries forced the target sees ≤ 5 requests; `--max-ops` 1, 101 and non-integer are rejected; a lower scope `max_requests` wins. |
| R10 | CLI-only entry | `test_r10_no_mcp_or_rest_entry` | safety — `mcp_server.TOOL_NAMES` equals an explicit expected set; nothing in `mcp_server.py` or `rest.py` references `plan_differential`. |
| R11 | Fail-closed predicates | `test_r11_verdict_table_rows` (one case per §8.5 row), `test_r11_predicates_fail_closed`, `test_error_envelope_never_counts_as_parity` | `tests/test_runner_plan_differential_predicates.py` — status-only, 2xx denial envelope, empty, HEAD, missing positive control, executor disagreement, exception in evaluation; `candidate` is `true` on row 8 only; an envelope makes `body_superset` `None`, not `False`. |
| R12 | No scope creation or mutation | `test_r12_scope_files_are_never_written` | safety — the scopes directory's file list, bytes and mtimes are identical before and after bootstrap, dry-run, run, failed run and replay; the new module does not import `create_scope`. |
| R13 | Dry-run sends nothing | `test_r13_dry_run_sends_nothing` | safety, no seam — zero sockets, no resolver call, no attempt directory, no credential variable consumed. |
| R14 | No transport selection from the CLI | `test_r14_cli_cannot_select_transport` | `tests/test_runner_plan_differential_cli.py` — the `run` option set equals the six of §3.1; `_build_client` takes only `origin`; setting `HEEL_CA_BUNDLE`, `HEEL_RUNNER_CA_FILE`, `HEEL_RUNNER_TRANSPORT`, `HEEL_RUNNER_RESOLVER`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` leaves the constructed client's resolver, socket and TLS classes and its CA count unchanged. It makes no claim about `SSL_CERT_FILE` (see R23). |
| R15 | Observed finding without declaration | `test_r15_observed_finding_from_undeclared_route` | cli — with an OpenAPI carrying no plan metadata the run yields a `body_superset` finding with `evidence_state == "observed"` and `operator_declared is False`; `heel findings --run` and `heel regress add` work on it unchanged. |
| R16 | Safe failure output, existing text | `test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` | cli — an unknown option, a missing required option, and each handler rejection (bad scope, bad URL, bad `--as`, bad `--routes`, POST inventory) all print exactly `Heel runner command was rejected.` on stderr with empty stdout and exit 2; `heel/cli.py` defines no `_SAFE_RUNNER_RUN_FAILURE`. |
| R17 | **Exactly two requests per route, `GET` and `HEAD`** | `test_r17_every_route_sends_exactly_one_request_per_plan_credential`, `test_r17_head_pair_is_two_head_requests_and_no_anonymous_request` | safety — in a full run with no forced retry, for **every** completed pair the target log holds exactly two requests on that path with that method: the first carries the lower credential, the second the higher. For every planned `HEAD` route specifically: exactly one `HEAD` with the lower credential, exactly one with the higher, **zero** with no credential or an unknown one, one `runner_run_id`, exactly two `plan_differential_request` containment entries with roles `lower_plan` and `higher_plan`, and `requests_sent` grows by exactly 2. Across the whole run the count of requests that carry no plan credential is 0, and no attempt store holds a credential record with role `anonymous` or `authenticated`. The `HEAD` pair is `held` or `inconclusive`, never skipped. `CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"] == ("GET", "HEAD")`; the new module contains no reference to `anonymous_authenticated_read`. |
| R18 | Handles on `--as` | `test_r18_as_accepts_only_registered_credential_handles`, `test_r18_credential_add_prints_handle_never_label_or_secret` | cli — a label, an unknown handle, swapped order, same handle twice and mismatched profiles are rejected; `credential add` prints the §3.2 object and nothing sensitive. |
| R19 | Imported inventory on `--routes` | `test_r19_routes_consumes_persisted_inventory_artifact`, `test_r19_routes_default_is_existing_imported_inventory` | cli — a copy of `routes.json` is accepted and every route in it is planned or listed `not_executed`; a selector-style array, another origin's envelope, a non-canonical or symlinked file are rejected; omitted means the stored inventory; the setup store is never rewritten. |
| R20 | Replay fidelity | `test_r20_regression_replay_reuses_saved_predicate_order_scope_origin` | cli — replay is `fail` on the vulnerable target and `pass` on the hardened (403) one; a different origin, scope, handle, role order or binding digest gives `fail`/`inconclusive` with zero requests. |
| R21 | Production client | `test_r21_production_client_construction_is_unseamed`, `test_r21_tls_transport_real_handshake_verifies_chain_and_hostname` | safety — as described in §7.3, with the stated limits. |
| R22 | Finding eligibility | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` | safety — in a run mixing completed pairs, a `transport:response_rejected` pair, a redirect pair, a scope-tamper stop and budget exhaustion: every row in `heel findings --run` has `reproduction.execution_disposition == "completed"`; each non-completed pair has no `AbuseVector` but appears in the result `pairs` and `report.json` as `inconclusive` with its true disposition and reason; `held` pairs have no finding; `candidate` is `true` exactly for `status_parity` findings. |
| R23 | CA trust boundary is as stated | `test_r23_ca_trust_follows_openssl_default_locations` | safety — with `_build_client` unreplaced and `getaddrinfo` patched: with `SSL_CERT_FILE` pointing at a CA generated in the test, `client.tls.context.get_ca_certs()` contains that CA; with it unset, it does not; in both cases `verify_mode == CERT_REQUIRED`, `check_hostname is True` and the protocol is TLS 1.2. The test asserts that the variable **is** honoured; it MAY skip only when `ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE"`. `docs/PLAN_DIFFERENTIAL_RUNNER.md` contains the trust-boundary statement of §7.2 (asserted by text). |
| R24 | Denial envelope never passes | `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay` | cli — a `body_superset` finding is recorded on the vulnerable target and added as a regression. The target is switched so the lower plan gets `200 {"error": "upgrade required"}`: a fresh run gives `inconclusive` / `lower_denial_envelope` with no `observed` finding, and `regress run` gives `result == "fail"`, `current_status == "inconclusive"`. Switched to a subset 200 body: `fail` / `inconclusive`. Switched to 403: `pass` / `blocked`. |
| R25 | Common numeric JSON completes | `test_r25_numeric_json_bodies_complete_and_do_not_end_the_run`, `test_r25_tolerant_redactor_matches_base_when_base_succeeds` | safety — a route whose body has a float, a negative integer, an integer above 2^53, an object of 300 keys and the echoed credential is planned with other routes after it in canonical order; its pair has disposition `completed` and a §8 verdict (`observed` on the vulnerable target), no pair has reason `transport:evidence_rejected`, later pairs execute, and the `HEEL_HOME` scan of I5 is clean. Unit: for bodies the base accepts, `_TolerantRedactor.count_bytes` equals `Redactor.count_bytes`; for a non-`bytes` or oversized chunk it raises as the base does. |
| R26 | Runner-module packaging | `test_r26_shipped_runner_modules_match_the_checked_in_wheel` | `tests/test_runner_plan_differential_release.py` — every `heel/runner/*.py` named in `release/open-core-v1.json`, including `plan_differential.py` and the four extended modules, is byte-identical to the member of the same name in `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` and in the sdist (read only); the new module imports nothing outside the contract's `python_modules` and the standard library except lazily imported `cryptography`. |

| R27 | Release artifacts are current and are the only files there | `test_r27_release_artifacts_are_current_and_exactly_three` | `tests/test_runner_plan_differential_release.py` — `build_release()` of `scripts/build_open_core_release.py`, run in-process on the working tree, returns bytes equal to the three checked-in files (the same comparison as the CI `--check`); the manifest's `sha256` and `size` equal the checked-in wheel and sdist; the wheel contains `heel/runner/plan_differential.py` and an entry point `heel = heel.cli:main`; `git ls-files apps/heel-cloud/public/downloads` is exactly the three authorized names. The test never writes under `apps/`. It reads the tree only, so it stays valid after merge. |

Path gates P1–P3 and the release commands that complete R27 are in §17. They are command
gates, not pytest tests, because they compare against the base commit `844fc1f`, which a
permanent test must not pin.

## 13. Synthetic target and harness (tests only)

`tests/plan_differential_support.py`: a stdlib `http.server` on `127.0.0.1`, port 0,
started and stopped per test, with two bearer sessions carrying a plan flag (`free`,
`pro`). Every response sends `Content-Length`, closes the connection and uses no transfer
or content encoding. It records every request: method, path, `Host`, arrival order and
which session it carried (`free`, `pro`, `none` or `unknown`), never the token. A
constructor argument selects the lower-plan behavior: `vulnerable`, `hardened` (403),
`envelope` (200 denial body) or `subset` (200 with fewer keys). The module also holds the
loopback seam objects and the test CA helper of §7.3.

| Route | Free | Pro | Expected verdict |
|---|---|---|---|
| `GET /api/export` | 200 same object (vulnerable) / 403 (hardened) / 200 envelope / 200 subset | 200 object | `observed` `body_superset` / `held` / `inconclusive` `lower_denial_envelope` / `inconclusive` `status_parity` |
| `HEAD /api/export` | 200 / 403 | 200 | `inconclusive` `status_parity` (`head_status_only`) / `held`. A request with no credential would get 401; the run never sends one (R17) |
| `GET /api/pricing` | 200, floats, negative and large integers, 300 keys, echoes the credential | same | `observed` `body_superset` (vulnerable); used by R25 and I5 |
| `GET /api/reports` | 403 | 200 object | `held` `lower_denied` |
| `GET /api/billing` | 200 `{"error": "upgrade required"}` | 200 object | `inconclusive` `lower_denial_envelope` |
| `GET /api/summary` | 200, subset of pro's keys | 200 object | `inconclusive` `status_parity` |
| `GET /api/empty` | 204 | 204 | `inconclusive` `status_parity` |
| `GET /api/text` | 200 `text/plain` | same | `inconclusive` `transport:response_rejected` |
| `GET /api/redirect` | 302 to a second listener | same | `inconclusive`; second listener untouched |
| `GET /api/echo` | 200, echoes the credential in a header and the body | same | used by I5 |
| `GET /exports/{id}` | marker present (vulnerable) or absent | marker present | `verified` / `held` |
| `GET /items/{id}` | | | `not_executed` `unbound_placeholder` |
| `POST /api/export` | in the OpenAPI document only | | never imported, never sent |

`tests/fixtures/plan_differential/openapi.json` describes these routes with **no**
`x-heel-*` plan or control metadata.

`tests/plan_differential_harness.py` is the synthetic journey for T5. `serve` starts the
target and writes its port to a file. `heel <args…>` installs the loopback factory of
§7.3 as `_build_client` and calls `heel.cli.main(args)` in-process. The synthetic origin
is `https://plan-differential-synthetic.heel.dev`; the harness never resolves it. The
harness adds no option to the product CLI and is not in the wheel (F19).

## 14. Files the implementer may touch — exhaustive

### 14.1 Final diff (the only paths that may differ from `844fc1f` when T2 ends)

Besides this spec, which only Fable edits.

New:

1. `heel/runner/plan_differential.py`
2. `tests/test_runner_plan_differential_safety.py`
3. `tests/test_runner_plan_differential_predicates.py`
4. `tests/test_runner_plan_differential_cli.py`
5. `tests/test_runner_plan_differential_release.py` — R26 and R27 only.
6. `tests/plan_differential_support.py`
7. `tests/plan_differential_harness.py`
8. `tests/fixtures/plan_differential/openapi.json`
9. `docs/PLAN_DIFFERENTIAL_RUNNER.md` — **the runnable documentation T5 follows.** It MUST
   contain, as copy-pasteable commands in the order of §4, the real-staging journey and
   the synthetic journey through the harness, the seam disclosure of §7.3, the trust
   boundary of §7.2, the two-requests-per-route rule and the `HEAD` mapping consequence of
   §6.1, and the limits of §15.

Modified, with the only permitted change:

10. `heel/cli.py` — §6.5.
11. `heel/regressions.py` — §6.6.
12. `heel/runner/catalog.py` — §6.1: the one tuple.
13. `heel/runner/compiler.py` — §6.2: one function, one method, one import.
14. `heel/runner/store.py` — §6.3: two read-only methods and the shared validator.
15. `heel/runner/http_transport.py` — §6.4: one line.
16. `tests/test_runner_cli.py` — the `credential add` output assertion at line 75 only;
    the label assertion at line 76 stays.
17. `tests/test_runner_compiler.py` — the catalog pin at line 132 only: entries 1 and 2
    stay `("GET",)`, entry 3 becomes `("GET", "HEAD")`.
18. `release/open-core-v1.json` — add `heel/runner/plan_differential.py`.
19. `tests/test_open_core_release.py` — add the same path to `EXPECTED_CONTRACT`; nothing
    else.

Regenerated, never hand-edited, and only by the procedure of §14.5:

20. `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`
21. `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl`
22. `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`

These three are the whole of the user-authorized `apps/` exception. No other path under
`apps/` may be created, modified, deleted, renamed or have its mode changed.

### 14.2 General rules for the dirty tree

The uncommitted files in the working tree were written by the first T2 session (Opus).
They are evidence and a starting point, not accepted work. The next T2 session:

- MUST NOT run `git reset --hard`, `git checkout .`, `git restore .`, `git stash`,
  `git clean`, or any restoring command that names more than one path.
- First records `git status --short` and, for each path of §14.3, `git hash-object <path>`.
  The expected values are in the table. A different value means someone changed the file
  after this spec: do not discard it; diff it against the table's description and report
  the difference in the closing status before continuing.
- Reuses a hunk only after re-reading it against the section named in the table.
- Removes an obsolete hunk by editing that hunk. `git restore --source=HEAD --worktree --
  <one file>` is permitted only for a file whose **entire** diff is obsolete, one file per
  command, after saving it with
  `git diff -- <file> > .heel/plan-differential-run/T2-discarded-<basename>.patch`. With
  this design no file is expected to need it.
- Fable does not stage or commit any of these files; they are committed by Opus in small
  signed commits.

### 14.3 Disposition of every dirty path

`+/−` is `git diff --numstat` against `HEAD` at the time of this spec.

| Path | State now (`+/−`, worktree blob) | Disposition |
|---|---|---|
| `heel/runner/catalog.py` | modified, 1/1, `5e11c054…` | **Reuse as is.** It is exactly §6.1. |
| `heel/runner/compiler.py` | modified, 124/1, `0362fd14…` | **Reuse after re-check against §6.2.** `plan_differential_pairs`, `compile_plan_differential_pair` and one import; no other hunk. |
| `heel/runner/store.py` | modified, 21/2, `527836f5…` | **Reuse after re-check against §6.3.** `_inventory_locked`, `route_inventory`, `route_inventory_path`. |
| `heel/runner/http_transport.py` | modified, 1/0, `2d21503d…` | **Reuse as is.** It is exactly §6.4. |
| `tests/test_runner_compiler.py` | modified, 2/1, `8196c103…` | **Reuse as is** (§14.1 item 17). |
| `heel/cli.py` | modified, 65/4, `3d4b6c25…` | **Rework one hunk.** Keep the `_runner_credential_add` hunks, the `runner run` subparser, `_runner_run` and the dispatch line. Delete the added constant `_SAFE_RUNNER_RUN_FAILURE` and make `_runner_run` print `_SAFE_RUNNER_COMMAND_FAILURE` (C5, R16). |
| `heel/regressions.py` | modified, 27/0, `b3c01313…` | **Reuse as is** (the branch only delegates), subject to §10 being implemented in the module. |
| `release/open-core-v1.json` | modified, 1/1, `024db5aa…` | **Reuse as is.** |
| `tests/test_open_core_release.py` | modified, 1/0, `802323d4…` | **Reuse as is.** |
| `tests/test_runner_cli.py` | modified, 9/1, `21d8201d…` | **Reuse as is.** |
| `heel/runner/plan_differential.py` | untracked, 1652 lines, `db1e0807…` | **Rework, do not rewrite.** Its architecture is this design: it already calls `plan_differential_pairs`, `compile_plan_differential_pair`, `route_inventory` and `route_inventory_path`, runs one `plan_entitlement_read` run per pair, and sent exactly two requests per route in F34. Later evidence found these defects, each of which MUST be fixed and tested: (1) no redaction-count seam — add `_TolerantRedactor` and substitute it in `_ScopedTransport` (§7.4, R25); (2) regression replay must pass only on a `held` verdict (§10, R24) — re-check `replay_plan_differential` line by line; (3) row-1 and `not_executed` reasons must be exactly the closed lists of §8.5; (4) replay uses `max_ops=4`; (5) every other function re-checked against §7–§11 before it is committed. |
| `tests/plan_differential_support.py` | untracked, 486 lines, `fda2dc10…` | **Rework**: replace the `hardened` flag with the four lower-plan behaviors and add `/api/pricing` (§13). The loopback seam objects and the test CA helper are reusable. |
| `tests/fixtures/plan_differential/openapi.json` | untracked, `fb2b84db…` | **Rework**: add `/api/pricing`. |
| `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`, `launch/` | untracked, unrelated | **Do not touch, stage or commit.** |

The `1c6b324` revision listed five of these files as "cleanup-only, restore to `HEAD`".
That instruction is **withdrawn**: restoring them would remove the design. Nothing in the
current tree implements the withdrawn four-request path, so there is no obsolete hunk
from it to remove.

### 14.4 Out of bounds

Reserved for later tasks, not T2: `docs/REDTEAM_PLAN_DIFFERENTIAL.md` and
`tests/test_runner_plan_differential_redteam.py` (T3); `docs/CAPABILITIES.md` (T5, three
rows only).

Everything else is out of bounds, explicitly: every existing file under `heel/runner/`
other than the four of §6 (`__init__.py`, `adapters.py`, `companion.py`,
`containment.py`, `content_assertion.py`, `control_client.py`, `coordinator.py`,
`execution.py`, `identity.py`, `openapi_routes.py`, `redaction.py`, `runtime.py`,
`service.py`, `vault.py`), `heel/scope.py`, `heel/contracts.py`, `heel/containment.py`,
`heel/store.py`, `heel/canary_contracts.py`, `heel/mcp_server.py`, `heel/rest.py`,
`heel/static_review.py`, `heel/reference_rehearsal.py`, `heel/saas/`, **every path under
`apps/` except the three of §14.1 items 20–22**, `web/`, `scripts/`, `.github/`, `README`,
pricing docs, `pyproject.toml`, `MANIFEST.in`, `release/` other than item 18,
`tests/test_runner_http_transport.py`, Claude settings, hooks, and the untracked
`docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md` and `launch/`. If the implementation cannot be
completed without one of these, stop and report; do not edit it.

No new dependency. `cryptography` stays under the `runner` extra and is imported lazily.
The new module MUST NOT assign to, patch or mutate any object of another `heel.runner`
module at import or run time (for example `CATALOG`, `ADAPTER_REGISTRY`); it only
subclasses `RunnerStore` and `Redactor`.

### 14.5 Regenerating the three release artifacts

The artifacts are a function of the shipped files only: the paths named in
`release/open-core-v1.json` (F36). Tests and docs are not inputs. The builder reads the
working tree, so it must run on the final tree.

Until this procedure has run, exactly three tests are expected to fail and no other:
the existing `test_checked_in_runner_artifacts_match_the_current_public_pairing_and_recovery_api`
(F22), R26 and R27. Commits before the artifact commit therefore carry those known
failures; the T2 gate is evaluated on the final commit.

Procedure, in this order, **only after** all source, test and doc changes of §14.1 items
1–19 are committed and no further edit to a shipped file is planned:

1. `git status --porcelain` MUST list only `?? docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`
   and `?? launch/`. Run the final test command of §17; the failures MUST be exactly the
   three named above.
2. Build with the existing builder, unmodified:
   `.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads`
   It MUST print `built heel_sim-1.2.0-py3-none-any.whl, heel_sim-1.2.0.tar.gz, and heel-open-core-manifest.json`.
3. Check with the existing command the CI `package` job runs:
   `.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`
   It MUST print `open-core release artifacts are current` and exit 0.
4. `git status --porcelain -- apps/` MUST print exactly three lines, each ` M` followed by
   one of the three authorized paths. Anything else: stop, do not commit, report.
5. Stage the three paths by explicit path (never `git add -A`, `git add .` or
   `git add apps`) and commit them alone, `git commit -s` with the Opus trailer last.
   `git show --stat --format= HEAD` MUST list exactly those three paths.
6. Run the final test command of §17 again: zero failures. Run path gates P1–P3 (§17).

The builder, `MANIFEST.in`, `pyproject.toml`, the CI workflow and the `--check` step MUST
NOT be changed, weakened or skipped. Version stays `1.2.0`; the file names do not change.

If any shipped file changes after step 5 — in T2, or in a T4 remediation — steps 1–6 are
repeated in that same task before its closing status, and the artifact commit again
contains only the three paths.

## 15. Limits the docs must state

Inherited from the existing transport and contracts, unchanged by this work:

- Public HTTPS staging hosts only: port 443, public addresses, an IANA-TLD hostname.
  Private-network, loopback and custom-port staging are not reachable.
- TLS 1.2 only. No redirect is followed.
- Responses must carry `Content-Length`, no transfer or content encoding, and be empty or
  one JSON object of at most 256 KiB. Chunked, compressed, array and non-JSON responses
  make the pair `inconclusive`.
- One mapping per scenario, so at most one parameterized route (`GET` or `HEAD`) can be
  given fixture values; other parameterized routes are listed as `not_executed`.

Chosen for Phase 1:

- One staging origin per `HEEL_HOME`. Two plans. One credential per plan role.
- Every route, `GET` or `HEAD`, costs exactly two requests before retries: one per plan
  credential. Heel sends no unauthenticated request. A `HEAD` pair compares statuses only.
- `heel runner map` and `heel runner prepare` accept a `HEAD` mapping for
  `plan_entitlement_read` (§6.1).
- Trust anchors are the TLS library's default locations and follow `SSL_CERT_FILE` /
  `SSL_CERT_DIR`; the operator's environment is trusted (§7.2).
- `observed` means the lower plan received every field the higher plan received on one
  read. It is a hypothesis about a missing plan gate; ungated-by-design routes will appear.
- A 2xx denial body is never counted as parity, never as `held` without a marker, and
  never as a regression pass.
- A regression passes only when the lower plan is denied by status (or the marker is
  absent) while the higher plan still succeeds.
- Target ownership is asserted only by the operator's signed local scope.
- A regression replays only under the same, still-valid scope.
- Nothing is uploaded.

## 16. Open risks for T2 and T3 to confirm

| Risk | What would confirm or refute it |
|---|---|
| The default trust locations may hold zero CAs on some Python builds; the run then fails closed with `tls_error`. | A real run against a public staging host. Not covered by CI. |
| TLS 1.2 only and no chunked decoding may make many real targets `inconclusive`. | First real-staging run. Lifting either is a transport change outside Phase 1. |
| Widening `plan_entitlement_read` to `HEAD` under adapter version `"1"` also changes what `runner map`, `runner prepare` and any cloud-approved manifest of that scenario may carry. Grep found no reader of `allowed_methods` outside `heel/runner/` and no mirror of it in `heel/saas`, `apps/` or `web/`, and the full suite passes with it (F35). | T3 to check the cloud projection and approval path for a `HEAD` plan pair. |
| `load_default_certs()` now runs for every `TLSTransport`. Only this feature constructs one in product code today (F33). | T3 to re-run the grep of F33 on the final tree. |
| The sdist is gzip-compressed, so its bytes depend on the zlib of the Python that builds it. The artifacts are built locally (Python 3.12, macOS) and checked in CI (Python 3.13, Linux). The artifacts at `HEAD` pass `--check` locally, which is evidence, not proof, that the two agree. | The CI `package` job on the T6 pull request. If it reports `generated artifact is stale` for the sdist only, stop and report to Kevin; do not edit the builder. |
| CI strict mode (`HEEL_REQUIRE_STANDARD_BUILD=1`), the wheel install step and the `apps/` Node tests have not been run for this feature (F39). They read the manifest and the wheel; nothing they read is pinned elsewhere (F36). | T2 SHOULD install `release/requirements-release.txt` into a throwaway venv outside the repo and run the strict command; otherwise the T6 CI run. |
| The frozen-pair check in `_ScopedTransport` is enforcement inside one module, not a separate trust domain. The compiler and the transport's own route check stand behind it. | I2 (b), (d), (e); T3 to attack `_ScopedTransport` directly. |
| The HMAC append inside `before_attempt` runs under the transport's attempt deadline; a slow disk becomes `gate_rejected`. Fails closed, may be flaky. | I6 under repeated runs. |
| Up to 50 reserved runs in one attempt store against the 64-run bound. | R9 at `--max-ops 100`. |
| Redaction matches raw and JSON-escaped forms only; other encodings of an echoed secret are not matched. | I5 echo cases; T3 to attack. |
| Credentials registered before this change have handles that were never displayed. | Operator uses a fresh `HEEL_HOME`. |
| `SYNTHETIC_ONLY` is the only data mode `heel scope create` issues; this design relies on canary accounts holding synthetic data. | Operator decision; not testable in code. |
| Whether the `apps/` exception lets a T4 remediation regenerate the artifacts again. The brief says "after the product implementation is final"; §14.5 reads that as "whenever a shipped file last changed". | Orchestrator to confirm before any T4. |

## 17. Baseline, final commands and T2 gates

### 17.1 Baseline record

Recorded by the first T2 session before any edit (F38), saved in
`.heel/plan-differential-run/T2-baseline.txt`:

| Run | Command | Result |
|---|---|---|
| Raw macOS | `.venv/bin/python -m pytest -q tests` | **35 failed**, 1451 passed, 5 skipped. All 35 are `RunnerRuntimeCorrupt: runtime state parent is unsafe` in `tests/test_runner_control_http.py` (16) and `tests/test_runner_public_client.py` (19): the default `TMPDIR` is under `/var`, a symlink to `/private/var`. Environment, not product. |
| CI-equivalent | the same command with `TMPDIR` set to its resolved real path | **1486 passed, 5 skipped, 0 failed** |

All deltas are reported against the CI-equivalent line. The raw macOS failures are not a
regression and MUST NOT be "fixed" in product code.

### 17.2 Final test command

```
TMPDIR="$(cd "$(.venv/bin/python -c 'import tempfile; print(tempfile.gettempdir())')" && pwd -P)" \
    .venv/bin/python -m pytest -q tests
```

On this machine the resolved value is
`/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`. The closing status MUST print
the resolved value used. Required result on the final commit: **0 failed**; passed =
1486 + the number of new tests; skipped = 5, plus R23 only under its stated skip
condition; no baseline test missing. Report the exact counts and the delta.

### 17.3 Package build and check commands

```
.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads
.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
```

Run only as steps 2 and 3 of §14.5. The second is the command of the CI `package` job
(F24) and MUST end with `open-core release artifacts are current`, exit 0.

### 17.4 Path gates (commands, run on the final commit)

| Gate | Command | Required output |
|---|---|---|
| P1 **three artifacts only** | `git diff --name-only 844fc1f HEAD -- apps/` | exactly the three lines `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`, `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl`, `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`, and nothing else |
| P1 (working tree) | `git status --porcelain -- apps/` | empty: no modified, staged or untracked path under `apps/` |
| P2 runner modules | `git diff --name-only 844fc1f HEAD -- heel/runner/` | exactly `catalog.py`, `compiler.py`, `http_transport.py`, `plan_differential.py`, `store.py` under `heel/runner/` |
| P3 whole diff | `git diff --name-only 844fc1f HEAD` | a subset of §14.1 items 1–22 plus this spec |

### 17.5 Named tests the T2 gate reads first

| Requirement | Test |
|---|---|
| Exactly two requests per route, `HEAD` included, none anonymous | `test_r17_every_route_sends_exactly_one_request_per_plan_credential`, `test_r17_head_pair_is_two_head_requests_and_no_anonymous_request` |
| Numeric JSON completes and the whole-`HEEL_HOME` secret scan is clean | `test_r25_numeric_json_bodies_complete_and_do_not_end_the_run`, `test_r25_tolerant_redactor_matches_base_when_base_succeeds`, `test_i5_credential_plaintext_absent_from_heel_home_and_output` |
| Denial envelope in fresh run and in replay | `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay`, `test_error_envelope_never_counts_as_parity` |
| Release artifacts current, three files only | `test_r27_release_artifacts_are_current_and_exactly_three`, `test_r26_shipped_runner_modules_match_the_checked_in_wheel`, the `--check` command of §17.3 and gate P1 |
| Trust boundary | `test_r23_ca_trust_follows_openssl_default_locations`, `test_r14_cli_cannot_select_transport` |
| Existing rejection text | `test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` |
| Completed-only findings | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` |
| Eight invariants | the I1–I8 tests of §12 |

The T2 closing status MUST list: baseline → final delta, every changed file, the
invariant → test map, the output of §17.3 and of each gate of §17.4, the dry-run plan
against the synthetic target, and its least-certain claim.
