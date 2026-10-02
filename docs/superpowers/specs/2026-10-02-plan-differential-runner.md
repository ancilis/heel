# Plan-differential runner — Phase 1 design spec

Date: 2026-10-02. Branch: `feat/plan-differential-runner` (base `main` @ `844fc1f`).
Blast radius: **medium — adds network egress under a signed scope.**
Role: design only (T1 correction; third revision). It replaces the revision committed at
`cdf0411` in full. This document is the contract for T2 (implementation), T3 (red team),
T4 (remediation) and T5 (acceptance). It makes no acceptance claim and contains no product
code.

Normative words: **MUST**, **MUST NOT**, **MAY**. Where this spec and the controlling brief
(`.heel/plan-differential-run/brief.md`) disagree, the brief wins and the implementer stops
and reports.

---

## 0. Correction record (why this revision exists)

The `cdf0411` revision required edits to `heel/runner/catalog.py`, `compiler.py`,
`store.py` and `http_transport.py`. That is impossible under the brief: a release test
byte-compares 17 `heel/runner/*.py` files with the wheel and sdist checked in under
`apps/`, and `apps/` is forbidden (F22). This revision changes **no existing
`heel/runner/` module**. Everything new lives in `heel/runner/plan_differential.py`, with
integration only in `heel/cli.py` and `heel/regressions.py`.

| # | T2 evidence | Correction | Where |
|---|---|---|---|
| C1 | Four runner modules cannot change | Route allowlist and pair compilation move to a private compiler in the new module that drives the unmodified `CanaryCompiler`; inventory loading moves to the new module; trust loading is done on the `TLSTransport` instance | §6, §7 |
| C2 | `plan_entitlement_read` is GET-only and cannot be widened | HEAD runs under the existing HEAD-capable catalog entry `anonymous_authenticated_read`, one run per identity | §6.3 |
| C3 | A body with a float or negative integer ended the run as `evidence_rejected` | A `Redactor` subclass passed at the transport seam makes the redaction **count** tolerant; evidence redaction is unchanged | §7.4 |
| C4 | "No environment variable selects a CA bundle" was false | The real trust boundary is stated and tested | §7.2, R23 |
| C5 | A new rejection line was specified without need | The existing fixed line is used | §3.6, R16 |
| C6 | A 2xx denial envelope could pass a regression | A replay passes only on an affirmative `held` verdict | §10, R24 |
| C7 | Extra reason codes existed in code but not in the spec | The row-1 reason list is closed and complete | §8.5 |

One conflict is **not** resolvable inside this run and is reported, not designed around:
the CI `package` job (§17).

## 1. What ships

One new public command, CLI only:

```
heel runner run --scope <scope-id> --base-url https://<host> \
    --as <lower-label>=<credential-handle> --as <higher-label>=<credential-handle> \
    [--routes <imported-inventory>] [--max-ops 50] [--dry-run]
```

For every route in the imported GET/HEAD inventory it sends the request **once per canary
identity** (lower plan, then higher plan) through `heel/runner/http_transport.py` and
compares the two responses. Where the lower plan receives what the higher plan receives it
records a finding with `evidence_state: observed` that no input declared.

One existing command changes its output: `heel runner credential add` now prints the
opaque handle it created (§3.2). No other command is added. Nothing else ships: no HAR
import, tenant differential, limit probing, writes, lifecycle sequences, MCP or REST
exposure, cloud, static-reviewer, pricing or site changes, and no scope creation or
mutation path.

## 2. Verified facts that shape the design

F1–F20 were read or run on 2026-10-02 at `844fc1f`. F22–F32 were read or run for this
correction at `cdf0411` (product code identical to `844fc1f`). F21 of the previous
revision is withdrawn: it argued that widening the catalog was safe.

| # | Fact | Evidence |
|---|------|----------|
| F1 | `heel runner import-openapi` and `heel runner credential add` exit 2 in a fresh `HEEL_HOME`. Every `RunnerStore` read or write needs a bound context and no public command binds one. | Ran both in an empty `HEEL_HOME`; `heel/runner/store.py:5203-5206`, `:5276-5288` |
| F2 | A credential handle is `secrets.token_hex(16)`: random, 32 hex, not derived from the secret. One handle per semantic role per context; a second registration for a role raises. | `heel/runner/store.py:6998`, `:7025`, `:6961-6979` |
| F3 | `credential add` prints only `{"registered_count": 1}`. An ephemeral credential is read from `HEEL_RUNNER_CREDENTIAL_<HANDLE>`, so an operator who is never shown the handle cannot supply it. | `heel/cli.py:199`; `heel/runner/vault.py:186-192`, `:252-270`; `tests/test_runner_cli.py:75` |
| F4 | The existing privacy boundary is: handle and label never enter the cloud-disclosed approval projection (they are in the local manifest), and `runner prepare` stdout is counts only. The label is treated as possibly sensitive operator text. | `tests/test_runner_compiler.py:291-292`; `tests/test_runner_cli.py:76`, `:96-98` |
| F5 | The imported inventory is persisted as `routes.json` in the bound context directory, in the envelope `heel.runner-route-inventory.v1` (`schema_version`, `namespace`, `origin`, `verification_record_digest`, `inventory: {source_digest, routes}`). Each route is `{method, route_template, operation_id, placeholders}` with method `GET` or `HEAD` only, in canonical order. | `heel/runner/store.py:6839-6904`, `:808-826`; `heel/cli.py:142-154` |
| F6 | `plan_entitlement_read` permits `GET` only, roles `lower_plan`, `higher_plan`. `anonymous_authenticated_read` permits `GET` and `HEAD`, roles `anonymous`, `authenticated`. No other entry permits `HEAD`. | `heel/runner/catalog.py:60-93` |
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
| F23 | With the five cleanup files (§14) at `HEAD` and the remaining T2 edits in place (`cli.py`, `regressions.py`, contract entry, new module), the release test files pass. With the catalog edit present, exactly one test fails (F22). | Ran `tests/test_open_core_release.py`, `test_release_automation.py`, `test_release_version.py` on the dirty tree: 1 failed, 22 passed, 2 skipped (both skips need release tooling not installed locally). Full suite on a scratch copy of the tree with the five cleanup files at `HEAD`: 1483 passed, 5 skipped, 3 failed; the 3 are `tests/test_heel_branding.py` calling `git ls-files` in a copy that has no `.git`, and all 8 tests of that file pass in the repository. Baseline is 1486 passed, 5 skipped |
| F24 | The CI `package` job runs `scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`. It rebuilds the wheel from source and fails with `generated artifact is stale` if any shipped file differs. | `.github/workflows/ci.yml:85-87`; `scripts/build_open_core_release.py:1086-1092`. Ran on a pristine export of `HEAD`: `artifacts are current`, exit 0. Appended one comment line to `heel/cli.py`: `generated artifact is stale: heel_sim-1.2.0-py3-none-any.whl`, exit 1 |
| F25 | A `HEAD` action under `plan_entitlement_read` is refused in three unmodifiable places: the compiler, `prepare_action`, and the transport's own `_valid_route`. An `anonymous` action that carries a credential is refused by the transport. | `heel/runner/compiler.py:147-149`; `heel/runner/adapters.py:92-95`; `heel/runner/http_transport.py:473-486`, `:520-524` |
| F26 | The executor keeps one credential per semantic role per manifest and evaluates observations `[0]` and `[1]` of each scenario, so a completed run needs at least two actions per scenario and can carry one non-anonymous identity in `anonymous_authenticated_read`. | `heel/runner/execution.py:421`, `:948-960` |
| F27 | The inherited failure: the transport calls `redactor.count_bytes(raw_headers, raw_body)` and maps any exception to `evidence_rejected`. `count_bytes` parses a JSON body and `_safe_json` raises on a float, a negative integer, an integer above 2^53−1, more than 1024 nodes, more than 256 members, or depth above 16. The executor classifies `evidence_rejected` as `failed` / `runner_fault`. The count is used only as a number; stored evidence is the raw bytes. | `heel/runner/http_transport.py:833`, `:851-856`; `heel/runner/redaction.py:141-155`, `:158-193`; `heel/runner/execution.py:548`. Ran `Redactor(()).count_bytes(b'{"price": 1.5}')` → `TypeError`; `b'{"n": -3}'` → `ValueError` |
| F28 | The transport accepts any `Redactor` instance (`isinstance`), and receives it as a `request()` argument from the executor. | `heel/runner/http_transport.py:899`; `heel/runner/execution.py:631`, `:754` |
| F29 | `ssl.SSLContext.load_default_certs()` honours `SSL_CERT_FILE`. On this build (OpenSSL 3.5.5) an unset environment loaded 128 CAs; `SSL_CERT_FILE=<test CA>` loaded exactly 1 and the test CA was trusted. | Ran on `TLSTransport().context` in two subprocesses; `ssl.get_default_verify_paths().openssl_cafile_env == "SSL_CERT_FILE"` |
| F30 | A scratch prototype against the **unmodified** runner modules, through the real `CanaryCompiler`, `LocalCanaryExecutor` and `TargetHTTPSClient` over a loopback seam, showed: (a) two `anonymous_authenticated_read` HEAD runs completed, and the target saw four HEAD requests — two without `Authorization`, one with each plan credential; (b) a GET body `{"price": 1.5, "n": -3, "big": 2**60, "echo": <Authorization>}` gave `failed`/`runner_fault` with the inherited redactor and `completed` with a tolerant `Redactor` subclass substituted at the transport seam; (c) with a `RunnerStore` subclass redacting before `store_response_evidence`, no file under `HEEL_HOME` contained either credential. | Ran; script not committed |
| F31 | The runner parser already prints the fixed line `Heel runner command was rejected.` for every argparse error under `runner`. | `heel/cli.py:42`, `:1199-1207` |
| F32 | `RunnerStore` exposes `root`, `namespace`, `load_context()`, `list_routes()`, `replace_routes()`, `save_mapping()`, `list_mappings()`, `list_credentials()`. `list_routes()` validates the stored envelope and canonical order but does not return `source_digest`. | `heel/runner/store.py:878`, `:5203`, `:6831-6959` |

Consequence: Phase 1 is `run_reference` with the fixture transport replaced by the real
`TargetHTTPSClient`. Where an existing runner interface is too narrow, the new module
**composes** the existing public interfaces instead of changing them. Restrictions that are
properties of the inherited transport are kept and stated in §15.

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

- Omitted (default): the setup store's current inventory, the file
  `<setup.root>/runner/contexts/<setup.namespace>/routes.json`. The dry-run prints that
  path, its `source_digest` and its route count so the operator can copy or archive it.
- Given: `PATH` is read with the existing bounded loader `_load_bounded_openapi` (regular
  file, no symlink, size-limited, duplicate keys rejected). It MUST be a complete
  `heel.runner-route-inventory.v1` envelope for the bound setup context (§6.1). Typical
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
| `GET`, no placeholders | planned: 2 requests |
| `HEAD`, no placeholders | planned: 4 requests (§6.3) |
| `GET`, placeholders, and the setup store holds a `plan_entitlement_read` mapping for exactly this `(GET, route_template)` | planned with those fixture bindings |
| `HEAD`, placeholders, and the setup store holds an `anonymous_authenticated_read` mapping for exactly this `(HEAD, route_template)` | planned with those fixture bindings |
| placeholders, no such mapping | `not_executed`, reason `unbound_placeholder`; never sent |
| any other method, or a route failing template rules | compile error for the whole command |

`HEAD` routes are executed like `GET` routes, once per identity, and are never skipped.
Heel never invents a path parameter value; a human supplies one through the existing
`heel runner map --scenario <scenario> --method M --route T --fixture-fd N`, where the
scenario is `plan_entitlement_read` for a `GET` route and `anonymous_authenticated_read`
for a `HEAD` route (the only catalog entry whose mapping may be `HEAD`, F6).

### 3.5 Human-supplied marker

There is no marker flag. The marker is supplied through the existing channel (F16): one
fixture value beginning `heel-canary-` in the `plan_entitlement_read` mapping opts that
`GET` route into the `protected_canary` contract. Heel never generates, guesses or
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
            "requests": 2, "control_requests": 0, "marker_supplied": false},
           {"ordinal": 1, "method": "HEAD", "route_template": "/api/export",
            "requests": 4, "control_requests": 2, "marker_supplied": false}],
 "not_executed": [{"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"}],
 "requests_planned": 6, "requests_sent": 0, "plan_sha256": "<64 hex>"}
```

`requests` is every request the pair sends; `control_requests` is how many of them carry
no credential (§6.3). `plan_sha256` is the canonical digest of origin, scope ID, both plan
entries, inventory `source_digest`, the ordered pairs with their binding digests, and
`effective_max_ops`. The executed result repeats it so an operator can compare a run with
its dry-run.

Executed object: `mode: "executed"`, `run_id`, `attempt_id`, `scope_id`, `origin`,
`plan_sha256`, `requests_sent`, `effective_max_ops`, `pairs` (one entry per planned pair:
`method`, `route_template`, `verdict`, `predicate`, `reason`, `execution_disposition`,
`candidate`, `finding_id` or `null`, `runner_run_ids`, and for `HEAD`
`control_statuses`), `not_executed`, `findings` (`id`, `predicate`, `evidence_state`,
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

## 5. Reused modules — all unmodified

`heel.scope` (`get_scope`, `verify`, `heel_home`, `ensure_home`), `heel.contracts`
(`AbuseVector`, `Severity`, `Category`), `heel.store.Store`, `heel.containment`
(`ContainmentLog`, `verify_chain`), `heel.crypto.SigningAuthority`, `heel.canary_contracts`,
`heel.runner.catalog` (`CATALOG_BY_ID`), `heel.runner.compiler` (`CanaryCompiler`),
`heel.runner.http_transport` (`TargetHTTPSClient`, `BoundedResolver`, `SocketTransport`,
`TLSTransport`, `normalize_target_origin`, `CancellationToken`, `TransportFailure`),
`heel.runner.execution` (`LocalCanaryExecutor`, `ExecutionBundle`, `ExecutionGate`),
`heel.runner.store` (`RunnerStore`, `RunnerContext`), `heel.runner.vault` (`EphemeralVault`,
`select_vault`, `ephemeral_environment_name`), `heel.runner.redaction` (`Redactor`,
`_secret_key`), `heel.runner.content_assertion.protected_content`,
`heel.runner.openapi_routes` (`normalize_route_template`), `heel.runner.identity`,
`heel.runner.containment` (`verify_containment_chain`).

**No file under `heel/runner/` other than the new `plan_differential.py` may differ from
`HEAD` at the end of T2** (F22, R26).

## 6. Compiler-level enforcement inside the new module

The new module owns one private class, `_PlanDifferentialCompiler`. It is the only code
that decides which routes are planned and the only code that produces something the
transport will accept. It is built from existing public interfaces only.

### 6.1 Inventory loading (replaces the `store.py` extension)

`_load_inventory(setup_store, artifact) -> {"source_digest", "routes", "path", "source"}`:

- `artifact is None`: read `<setup.root>/runner/contexts/<setup.namespace>/routes.json`
  with the module's own bounded read (`O_NOFOLLOW`, regular file, size limit, duplicate
  keys rejected), then apply the envelope check below. Its `routes` MUST equal
  `setup_store.list_routes()`, which is the store's own validation of the same file
  (F32); a difference is a rejection.
- `artifact` given: it MUST be a mapping with exactly the five envelope fields, with
  `schema_version == "heel.runner-route-inventory.v1"`, `namespace == setup.namespace`,
  and `origin` and `verification_record_digest` equal to `setup.load_context()`. Its
  `inventory` MUST be exactly `{source_digest, routes}`, `source_digest` 64 lowercase hex,
  `routes` a list.
- This function checks the envelope only. It MUST NOT filter, sort or rewrite `routes`;
  the raw list goes to the compiler.

### 6.2 `_PlanDifferentialCompiler`

```python
class _PlanDifferentialCompiler:
    @staticmethod
    def plan_routes(inventory_routes, *, mappings) -> tuple[list[dict], list[dict]]:  # (planned, not_executed)
    def __init__(self, *, store, identity, signer, clock_ms): ...                     # attempt store
    def compile_pair(self, pair, *, credentials) -> _CompiledPair: ...
    def admits(self, action, evidence_context, credential) -> _Ticket | None: ...
```

`plan_routes` is the per-route allowlist of brief §1.2. It takes the **raw** route list of
the chosen inventory and the setup store's `list_mappings()`. It MUST:

- raise if any entry's method is not `GET` or `HEAD`, so a `POST` (or any other) inventory
  entry is a compile error for the whole command;
- raise if any entry is not a closed `{method, route_template, operation_id,
  placeholders}` record, if `normalize_route_template` rejects or changes the template,
  if placeholders disagree, if the list is not in canonical order, if a `(method,
  route_template)` repeats, or if there are more than 2000 entries;
- map each method to its scenario with a closed table — `GET` → `plan_entitlement_read`,
  `HEAD` → `anonymous_authenticated_read` — and raise unless the method is in
  `CATALOG_BY_ID[scenario]["allowed_methods"]`;
- return planned and not-executed routes per §3.4 in canonical order. It never adds,
  rewrites or derives a route.

`compile_pair` compiles one planned pair in the attempt store. It MUST:

- raise unless `(method, NFC route_template)` is exactly in `self.store.list_routes()`.
  This is an independent membership check against the persisted inventory of the attempt
  store, not against the caller's list;
- call `self.store.save_mapping(scenario, method=…, route_template=…, fixture_bindings=…)`
  (which re-checks membership, `heel/runner/store.py:6924-6930`), then
  `CanaryCompiler(store, identity, signer, now_ms).compile([scenario], projection_id=…)`.
  `now_ms` MUST be strictly greater than for the previous compile and `projection_id`
  unique per run, so no two manifests share a digest;
- for `GET`: one run. Raise unless the manifest has exactly two actions, both `GET` with
  that template, roles `lower_plan` then `higher_plan`;
- for `HEAD`: two runs (§6.3). Raise unless each manifest has exactly two actions, both
  `HEAD` with that template, roles `anonymous` then `authenticated`;
- return the runs with their manifests and projections, and record one **ticket** per
  action: `(run, ordinal, scenario_id, method, route_template, semantic_role,
  credential_expected)`. Tickets of earlier pairs are discarded.

`admits` returns the unused ticket matching an action exactly, or `None`. A ticket is
consumed by its first transport call (a retry of the same call stays inside it).

**Boundary.** `_ScopedTransport` (§7) holds the compiler and calls `admits` for every
`request()`. Without a matching unused ticket it raises `TransportFailure("gate_rejected")`
before any budget, log or socket activity. `_ScopedTransport.request` is the only call
site of `TargetHTTPSClient.request` in the module, and `LocalCanaryExecutor.execute` is
only ever given a `_ScopedTransport`. Therefore every request that can reach the wire is
an action of a manifest returned by `compile_pair` for a route that `plan_routes`
accepted. The CLI handler passes the parsed `--routes` object through untouched; it
contains no route or method logic. Tests prove each sentence of this paragraph (I2).

The unmodified `CanaryCompiler`, `prepare_action` and the transport's `_valid_route`
remain as further independent checks behind this one (F25).

### 6.3 HEAD execution path

`plan_entitlement_read` cannot carry `HEAD` and cannot be widened (F22, F25). The only
catalog entry that permits `HEAD` is `anonymous_authenticated_read`, whose manifest is
`[anonymous, authenticated]` (F6). A completed run needs two actions and holds one
non-anonymous identity (F26). So each planned `HEAD` route runs as **two runs of the
existing scenario, one per plan identity**:

| Run | Action 0 | Action 1 |
|---|---|---|
| `…_0` (lower) | `HEAD` route, `anonymous`, no credential | `HEAD` route, `authenticated`, **lower-plan** credential |
| `…_1` (higher) | `HEAD` route, `anonymous`, no credential | `HEAD` route, `authenticated`, **higher-plan** credential |

- The attempt store registers a third ephemeral credential record, role `authenticated`,
  same auth profile as the plans, only when at least one `HEAD` pair is planned. Each run
  gets its own `LocalCanaryExecutor` whose vault view maps that handle to exactly one
  plan's secret for the life of the run (§7).
- Each plan identity sends the `HEAD` request **exactly once**. Each run also sends one
  request with no credential. These two unauthenticated control requests per `HEAD` route
  are a property of the only HEAD-capable contract; they are the same method, host and
  route, are counted in the budget, logged, and reported as `control_requests` and
  `control_statuses`. They take part in no predicate.
- The lower run executes first. If it does not complete, the higher run is not started
  and the pair is row 1 (§8.5). The pair is `completed` only when both runs completed.
- The pair's `L` and `H` observations are the `authenticated` action (ordinal 1) of the
  lower and higher run. The executor's own assessment of these runs is always
  `inconclusive` (F7) and is not used.

Rejected alternatives, with the reason each fails: a `HEAD` action under
`plan_entitlement_read` (refused by compiler, adapter and transport, F25); a hand-built
manifest with one action (the executor indexes two observations, F26); sending a plan
credential on the `anonymous` action (refused by the transport, and the signed log would
mislabel the request, F25); fabricating a response for the anonymous action instead of
sending it (false evidence in a signed chain); a separate executor written for HEAD
(discards the inherited caps, backoff, reservation and signed log the brief requires).
Batching several `HEAD` routes of one identity into one manifest would avoid the control
requests but cannot run a single route, which regression replay always needs; one path is
kept.

### 6.4 `heel/cli.py`

- `runner run` subparser, handler `_runner_run(args)`, one dispatch line. Rejections print
  `_SAFE_RUNNER_COMMAND_FAILURE`. No new constant.
- `_runner_credential_add` prints the object of §3.2 using the record returned by the
  store. No other command's behavior or output changes.

### 6.5 `heel/regressions.py`

The replay branch of §10 in `run_regressions`.

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
| `_load_inventory` | §6.1. |
| `_PlanDifferentialCompiler` | §6.2. |
| `_build_client(origin) -> TargetHTTPSClient` | The only client constructor. One bounded `BoundedResolver()` preflight; `tls = TLSTransport()`; `tls.context.load_default_certs()`; then `TargetHTTPSClient(origin=origin, preflight_addresses=answers, tls=tls)` with **no** `resolver` or `sockets` argument. The `tls` object is the unmodified production class; only its trust store is populated (F11). It takes no other parameter and reads no Heel environment variable, file or config. |
| `_AttemptReservation` | Result of the exclusive `os.mkdir`. Holds attempt ID and root. Constructed only by `_reserve_attempt`. |
| `_PlanVault` | Loads each real secret **once per invocation** from its real vault (`EphemeralVault` or `select_vault(backend)`), keeps it in memory only, registers it with the redacting store, and clears it at exit. `view(mapping)` returns an immutable per-run vault (`supported=True`, `backend_id="ephemeral_env"`) that serves exactly the handles in `mapping`. Refuses (`VaultUnavailable`) a bearer or API-key value, or any cookie value, shorter than 8 bytes, because it cannot be redacted reliably. |
| `_RedactingRunnerStore(RunnerStore)` | Overrides only `store_response_evidence`: before delegating, replaces every registered secret, in raw form and in JSON-string-escaped form, in `raw_headers` and `raw_body` with `b"[REDACTED:secret]"`. Needed because the executor stores raw bytes (F14). |
| `_TolerantRedactor(Redactor)` | §7.4. |
| `_ScopedTransport` | Wraps the client. Requires an `_AttemptReservation` whose directory exists, else raises `TransportFailure("gate_rejected")`. Requires a compiler ticket (§6.2). Replaces the `redactor` argument with the `_TolerantRedactor` (§7.4). Wraps the executor's `before_attempt` as in §9. |
| `_gate(scope_id, host)` | `gate_source` for the executor. Calls `_authorize` each time; inactive if the scope no longer verifies or no longer lists the host. |
| `_grant(...)` | As `reference_rehearsal._grant`, with `approval_actor {"user_id": "local_operator", "role": "owner"}` and a reason naming the scope ID. Ephemeral `SigningAuthority`, trusted only in this process. |
| `_finding(...)` | Builds one `AbuseVector` (§11). |

### 7.1 Execute sequence

1. `caller` check. `_authorize`. Normalize origin. Host not in allowlist → forced dry-run
   result, stop. Setup context MUST be bound to this origin, else reject.
2. Resolve both handles (§3.2). `_load_inventory`.
   `_PlanDifferentialCompiler.plan_routes`. Zero planned pairs → reject.
3. Budget (§9). Walking the planned pairs in order, the first pair whose requests do not
   fit in `effective_max_ops`, and every later pair, become `not_executed`
   (`over_budget`).
4. **Reserve the attempt**: `os.mkdir(HEEL_HOME/plan-runs/<attempt>, 0o700)`, exclusive. An
   existing directory is a replay and is rejected. Nothing above this line touches the
   network; nothing below runs without it.
5. Open `Store(HEEL_HOME/heel.db)`; `add_run("pdrun-<attempt>", scope_id, origin, caller,
   "running", …)`; containment `run_start`.
6. Build the attempt store (`_RedactingRunnerStore`), ephemeral signer and identity, bind
   the same context values as the setup store, `replace_routes(<whole inventory>,
   source_digest=…)` and require `list_routes()` to equal the compiler's validated list.
   Register ephemeral credential records `lower_plan`, `higher_plan` and, when a `HEAD`
   pair is planned, `authenticated`. Construct the compiler on this store.
7. `_build_client(origin)` once: one DNS preflight pins the address set for the invocation.
8. For each planned pair in order: skip as `not_executed` (`budget_exhausted`) if fewer
   ops remain than the pair needs; else `compile_pair`, then for each of its runs:
   `_grant` (`run_id="crun_<attempt>_<nn>"` for `GET`, `crun_<attempt>_<nn>_0` and `_1`
   for `HEAD`, 30 s expiry) → `LocalCanaryExecutor(…, vaults={"ephemeral_env":
   vault.view(…)}).execute(bundle, transport=_ScopedTransport, gate_source=_gate,
   cancellation=token)`. The executor reserves the grant and sends the actions in order.
9. After each pair: read the evidence records from the attempt store, matched by
   `action_ordinal` as `reference_rehearsal.py:160-167` does; run `evaluate_plan_pair`;
   append a `plan_differential_pair` containment entry carrying the verdict, reason and
   the executor's true `execution_disposition`. Then, **only when every run of the pair
   has executor disposition `completed` and the verdict is not `held`** (§8.5 rows 2, 3,
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
| Trust anchors | `load_default_certs()` on the unmodified `TLSTransport` context: the default trust locations of the Python build's TLS library. **`SSL_CERT_FILE` and `SSL_CERT_DIR` in the process environment change those locations (F29).** Heel adds no option, `HEEL_*` variable, config key or scope field for trust. |
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
| Execution, findings, containment, regression replay | `heel.cli.main(argv)` with `_build_client` replaced by a factory returning a real `TargetHTTPSClient` whose injected `resolver` returns a fixed public address, whose `sockets` connects to the loopback synthetic target and reports the pinned address from `getpeername`, and whose `tls` is a pass-through | Request construction, `Host`, framing, 3xx refusal, body rules, compiler tickets, gate, budget, reservation, evidence, redaction, predicates and logging are product code. **It proves nothing about TLS, DNS answers or address selection.** |
| Production client construction | `_build_client` unreplaced, with only `socket.getaddrinfo` patched to return a public address | The production path builds `BoundedResolver`, `SocketTransport` and a `TLSTransport` with certificate verification, hostname checking and default trust loading, and passes no seam object. No handshake is performed. |
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

`completed` := every run of the pair has executor disposition `completed` and both
evidence records load and verify.

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
- The unauthenticated HEAD control observations enter no predicate.

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

- **Unit**: one op is one request attempt on the wire, including a retry and including an
  unauthenticated HEAD control request.
- `effective_max_ops = min(--max-ops, scope.rate_and_resource_limits["max_requests"])` when
  the scope defines an integer `max_requests`, else `--max-ops`. If the result is < 2, or
  `Store.scope_run_count(scope_id) >= max_requests` (the rule `heel_run` already applies),
  reject.
- A `GET` pair needs 2 ops and a `HEAD` pair 4, before retries.
- **Per-attempt order**, inside the wrapped `before_attempt`, before any socket:
  1. `_authorize` again; failure raises `gate_rejected`.
  2. take one unit from the invocation-wide counter, or raise `gate_rejected` with
     `gate_error="budget_exhausted"`;
  3. call the executor's own `before_attempt` (grant authority, per-manifest budget,
     retry rules, signed `action_started` event);
  4. append one HMAC containment entry `plan_differential_request` with `method`,
     `route_template`, plan `label`, `role`, `attempt`, `runner_run_id`, `op_index`. For
     a control request `role` is `anonymous` and `label` is the plan label of the run it
     belongs to, with `control: true`. If the append fails the attempt is refused.
  Only then does the transport resolve and connect. So total wire requests never exceed
  `effective_max_ops`, and no request exists without an earlier entry. An entry MAY exist
  for an attempt that then failed in DNS or connect.
- The per-manifest `BUDGETS` and `RETRY_POLICY` (one retry, `connect_error`/`timeout`)
  apply unchanged inside each run. Concurrency is one.
- `--max-ops ≤ 100` keeps one attempt at ≤ 50 reserved runs (50 `GET` pairs, or 25 `HEAD`
  pairs of two runs), below the store's 64-run tracking bound
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
attempt ID and `max_ops=8`. The saved predicate `p` is re-evaluated on the new responses
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
only if every run of the pair has executor `execution_disposition` exactly `completed` and
the verdict is not `held`. Pairs that did not complete (`incomplete`, `failed`,
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
  copied from the executor results, and a pair with any other disposition is never stored
  as a finding. The implementation MUST NOT write `completed` for a pair that did not
  complete; it writes no finding instead.
- `candidate` is a JSON boolean: `true` if and only if `predicate == "status_parity"`
  (§8.5 row 8); `false` for `body_superset`, `marker_leak` and `inconclusive`.
- `inconclusive` findings exist only for completed pairs (rows 2, 5, 9 and
  `predicate_error`).
- `observations[].role` is the plan role (`lower_plan`, `higher_plan`) for `GET` and
  `HEAD` alike. `runner_run_ids` has one entry for `GET` and two for `HEAD`.
  Unauthenticated control observations are not in a finding.
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
| I1 | **Host confinement.** No connection to any host outside the scope allowlist, including through a redirect. | `test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`; `test_i1_host_header_is_always_the_normalized_host` | (a) host not in allowlist → forced dry-run, exit 3, zero connections on the target and on a second listener; (b) a route answering `302 Location:` the second listener yields zero connections there and an `inconclusive` pair; (c) IPv4 literal, IPv6 literal, `http://`, port, userinfo, trailing dot and punycode base URLs are rejected before any socket; (d) a resolver whose answer changes after preflight ends the run with `dns_changed` and no further request; (e) every request seen by the target, including control requests, has `Host` equal to the normalized host. | No request to a host outside the scope allowlist, ever, including redirects |
| I2 | **GET/HEAD and inventoried-route confinement, enforced in the compiler.** | `test_i2_only_inventoried_get_and_head_reach_the_wire`; `test_i2_post_inventory_is_rejected_at_compile`; `test_i2_every_transport_action_passes_the_private_compiler` | (a) an inventory artifact with a `POST` entry reaches `_PlanDifferentialCompiler.plan_routes` unfiltered (the test records its argument), is rejected there, and the command exits 2 with zero requests; (b) `compile_pair` refuses a route absent from the attempt store inventory and a non-GET/HEAD method; (c) across a full run the target's log contains only `GET` and `HEAD` and only planned paths; (d) `_ScopedTransport.request` with a well-formed action that has no ticket, a consumed ticket, a different route, method, role or ordinal, or a credential on an `anonymous` action, raises `gate_rejected` with zero connections, zero budget use and zero log entries; (e) by AST of the module: `TargetHTTPSClient.request` is called only inside `_ScopedTransport`, `execute(` is called only with a `_ScopedTransport`, and `_build_client` is referenced only at its definition and one call site; (f) by AST of `heel/cli.py`: `_runner_run` passes the loaded artifact to the module unmodified and contains no reference to `method`, `route_template` or `routes` keys. | No method other than GET/HEAD |
| I3 | **Verified signed scope.** | `test_i3_no_request_without_verified_signed_scope` | Unknown scope, hand-edited scope file (allowlist widened), expired scope and unbound scope each give exit 2 and zero requests; a scope file edited after the first pair stops the run before the next request. | No request without a signed scope … |
| I4 | **One-shot reserved attempt.** | `test_i4_no_request_without_one_shot_reserved_attempt` | (a) reusing an attempt ID is refused with zero requests; (b) `_ScopedTransport` built without a reservation, or whose directory is gone, refuses with zero connections; (c) with `reserve_run` forced to fail, zero requests are sent; (d) a consumed grant cannot be executed twice. | … and a reserved attempt ID |
| I5 | **Secret exclusion.** | `test_i5_credential_plaintext_absent_from_heel_home_and_output` | After a successful run, a run against a route echoing the credential in a header and in the body, a run whose echoing body also contains floats and negative integers, a run failing in transport, a run stopped by scope tamper, and a run with a missing credential: a byte scan of every file under `HEEL_HOME` (`heel.db`, evidence `.bin`, reports, both containment logs) finds neither credential, and stdout, stderr, findings and containment rows contain neither. | Credentials never appear in reports, logs, findings, or containment entries |
| I6 | **Every request logged.** | `test_i6_every_request_is_logged_before_it_is_sent` | In a run with no append failure, count of `plan_differential_request` entries == sum of runner `requests_started` ≥ requests counted by the target, including a forced retry and the HEAD control requests; each target request maps to a distinct entry appended before it arrived; a failing append sends nothing. | Containment log records every request … |
| I7 | **Caller attribution.** | `test_i7_every_containment_entry_carries_cli_caller` | Every containment row for the run has `caller == "cli:<user>"`; `run_plan_differential` raises for an empty or non-`cli:` caller before any state change. | … with caller attribution |
| I8 | **Chain integrity.** | `test_i8_containment_chains_verify_and_detect_tamper` | `containment.verify_chain` is true after success and after failure; mutating one stored row makes it false; the runner's signed chain verifies for each `crun_` run with `verify_containment_chain`. | chain verifies |

Independent requirements:

| # | Requirement | Named test | File and proof |
|---|---|---|---|
| R9 | Total request budget | `test_r9_max_ops_hard_caps_total_requests` | safety — with `max_ops=5` and retries forced the target sees ≤ 5 requests, control requests included; `--max-ops` 1, 101 and non-integer are rejected; a lower scope `max_requests` wins. |
| R10 | CLI-only entry | `test_r10_no_mcp_or_rest_entry` | safety — `mcp_server.TOOL_NAMES` equals an explicit expected set; nothing in `mcp_server.py` or `rest.py` references `plan_differential`. |
| R11 | Fail-closed predicates | `test_r11_verdict_table_rows` (one case per §8.5 row), `test_r11_predicates_fail_closed`, `test_error_envelope_never_counts_as_parity` | `tests/test_runner_plan_differential_predicates.py` — status-only, 2xx denial envelope, empty, HEAD, missing positive control, executor disagreement, exception in evaluation; `candidate` is `true` on row 8 only; an envelope makes `body_superset` `None`, not `False`. |
| R12 | No scope creation or mutation | `test_r12_scope_files_are_never_written` | safety — the scopes directory's file list, bytes and mtimes are identical before and after bootstrap, dry-run, run, failed run and replay; the new module does not import `create_scope`. |
| R13 | Dry-run sends nothing | `test_r13_dry_run_sends_nothing` | safety, no seam — zero sockets, no resolver call, no attempt directory, no credential variable consumed. |
| R14 | No transport selection from the CLI | `test_r14_cli_cannot_select_transport` | `tests/test_runner_plan_differential_cli.py` — the `run` option set equals the six of §3.1; `_build_client` takes only `origin`; setting `HEEL_CA_BUNDLE`, `HEEL_RUNNER_CA_FILE`, `HEEL_RUNNER_TRANSPORT`, `HEEL_RUNNER_RESOLVER`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` leaves the constructed client's resolver, socket and TLS classes and its CA count unchanged. It makes no claim about `SSL_CERT_FILE` (see R23). |
| R15 | Observed finding without declaration | `test_r15_observed_finding_from_undeclared_route` | cli — with an OpenAPI carrying no plan metadata the run yields a `body_superset` finding with `evidence_state == "observed"` and `operator_declared is False`; `heel findings --run` and `heel regress add` work on it unchanged. |
| R16 | Safe failure output, existing text | `test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` | cli — an unknown option, a missing required option, and each handler rejection (bad scope, bad URL, bad `--as`, bad `--routes`, POST inventory) all print exactly `Heel runner command was rejected.` on stderr with empty stdout and exit 2; `heel/cli.py` defines no `_SAFE_RUNNER_RUN_FAILURE`. |
| R17 | HEAD executed once per identity | `test_r17_head_routes_execute_once_per_identity` | safety — for every planned `HEAD` route the target log holds exactly one request carrying the lower credential, exactly one carrying the higher credential and exactly two carrying none, all `HEAD` on that path; the pair is `held` or `inconclusive`, never skipped; `catalog.CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"] == ("GET",)` still holds. |
| R18 | Handles on `--as` | `test_r18_as_accepts_only_registered_credential_handles`, `test_r18_credential_add_prints_handle_never_label_or_secret` | cli — a label, an unknown handle, swapped order, same handle twice and mismatched profiles are rejected; `credential add` prints the §3.2 object and nothing sensitive. |
| R19 | Imported inventory on `--routes` | `test_r19_routes_consumes_persisted_inventory_artifact`, `test_r19_routes_default_is_existing_imported_inventory` | cli — a copy of `routes.json` is accepted and every route in it is planned or listed `not_executed`; a selector-style array, another origin's envelope, a non-canonical or symlinked file are rejected; omitted means the stored inventory; the setup store is never rewritten. |
| R20 | Replay fidelity | `test_r20_regression_replay_reuses_saved_predicate_order_scope_origin` | cli — replay is `fail` on the vulnerable target and `pass` on the hardened (403) one; a different origin, scope, handle, role order or binding digest gives `fail`/`inconclusive` with zero requests. |
| R21 | Production client | `test_r21_production_client_construction_is_unseamed`, `test_r21_tls_transport_real_handshake_verifies_chain_and_hostname` | safety — as described in §7.3, with the stated limits. |
| R22 | Finding eligibility | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` | safety — in a run mixing completed pairs, a `transport:response_rejected` pair, a redirect pair, a scope-tamper stop and budget exhaustion: every row in `heel findings --run` has `reproduction.execution_disposition == "completed"`; each non-completed pair has no `AbuseVector` but appears in the result `pairs` and `report.json` as `inconclusive` with its true disposition and reason; `held` pairs have no finding; `candidate` is `true` exactly for `status_parity` findings. |
| R23 | CA trust boundary is as stated | `test_r23_ca_trust_follows_openssl_default_locations` | safety — with `_build_client` unreplaced and `getaddrinfo` patched: with `SSL_CERT_FILE` pointing at a CA generated in the test, `client.tls.context.get_ca_certs()` contains that CA; with it unset, it does not; in both cases `verify_mode == CERT_REQUIRED`, `check_hostname is True` and the protocol is TLS 1.2. The test asserts that the variable **is** honoured; it MAY skip only when `ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE"`. `docs/PLAN_DIFFERENTIAL_RUNNER.md` contains the trust-boundary statement of §7.2 (asserted by text). |
| R24 | Denial envelope never passes | `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay` | cli — a `body_superset` finding is recorded on the vulnerable target and added as a regression. The target is switched so the lower plan gets `200 {"error": "upgrade required"}`: a fresh run gives `inconclusive` / `lower_denial_envelope` with no `observed` finding, and `regress run` gives `result == "fail"`, `current_status == "inconclusive"`. Switched to a subset 200 body: `fail` / `inconclusive`. Switched to 403: `pass` / `blocked`. |
| R25 | Common numeric JSON completes | `test_r25_numeric_json_bodies_complete_and_do_not_end_the_run`, `test_r25_tolerant_redactor_matches_base_when_base_succeeds` | safety — a route whose body has a float, a negative integer, an integer above 2^53, an object of 300 keys and the echoed credential is listed **before** other routes; its pair has disposition `completed` and a §8 verdict (`observed` on the vulnerable target), no pair has reason `transport:evidence_rejected`, later pairs execute, and the `HEEL_HOME` scan of I5 is clean. Unit: for bodies the base accepts, `_TolerantRedactor.count_bytes` equals `Redactor.count_bytes`; for a non-`bytes` or oversized chunk it raises as the base does. |
| R26 | Release-artifact compatibility | `test_r26_existing_runner_modules_are_byte_identical_to_checked_artifacts` | safety — each of the 17 files of F22 equals the member of the same name in `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` (read only); `heel/runner/plan_differential.py` is listed in `release/open-core-v1.json`; the module imports nothing outside the contract's `python_modules` and the standard library except lazily imported `cryptography`. |

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
| `HEAD /api/export` | 200 / 403; unauthenticated 401 | 200 | `inconclusive` `status_parity` / `held` |
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

### 14.1 Final diff (the only paths that may differ from `cdf0411` when T2 ends)

New:

1. `heel/runner/plan_differential.py`
2. `tests/test_runner_plan_differential_safety.py`
3. `tests/test_runner_plan_differential_predicates.py`
4. `tests/test_runner_plan_differential_cli.py`
5. `tests/plan_differential_support.py`
6. `tests/plan_differential_harness.py`
7. `tests/fixtures/plan_differential/openapi.json`
8. `docs/PLAN_DIFFERENTIAL_RUNNER.md` — **the runnable documentation T5 follows.** It MUST
   contain, as copy-pasteable commands in the order of §4, the real-staging journey and
   the synthetic journey through the harness, the seam disclosure of §7.3, the trust
   boundary of §7.2, the HEAD control requests of §6.3 and the limits of §15.

Modified, with the only permitted change:

9. `heel/cli.py` — §6.4.
10. `heel/regressions.py` — §6.5.
11. `tests/test_runner_cli.py` — the `credential add` output assertion at line 75 only;
    the label assertion at line 76 stays.
12. `release/open-core-v1.json` — add `heel/runner/plan_differential.py`.
13. `tests/test_open_core_release.py` — add the same path to `EXPECTED_CONTRACT`; nothing
    else.

### 14.2 Cleanup-only (must have **no** final diff)

The prior T2 session left uncommitted hunks in five files that this design forbids. The
fresh T2 session restores exactly these files to `HEAD` and does nothing else to them.

| File | Uncommitted hunks to discard (`git diff --numstat` +/−) | Blob at `HEAD` |
|---|---|---|
| `heel/runner/catalog.py` | `plan_entitlement_read` methods widened to `("GET", "HEAD")` (1/1) | `2d0ed160431d685b35dc4a8cdd6e27e6ad56890e` |
| `heel/runner/compiler.py` | `plan_differential_pairs`, `compile_plan_differential_pair`, one import line (124/1) | `79ffa402d22fe694aa724d83b9c70605d511d139` |
| `heel/runner/http_transport.py` | `load_default_certs()` in `TLSTransport.__init__` (1/0) | `f543901629ff1c870c432bb23813403b33acc27d` |
| `heel/runner/store.py` | `_inventory_locked`, `route_inventory`, `route_inventory_path` (21/2) | `61751cbafe1a3e2b1168b04f8e54a79f2ec2e47f` |
| `tests/test_runner_compiler.py` | catalog pin changed at line 132 (2/1) | `049b0a5107c27cd0fe45482801b6a025ceaa7251` |

Procedure, per file, one file at a time. No `git reset --hard`, `git checkout .`,
`git restore .`, `git stash`, `git clean` or any command naming more than one path:

1. `git diff --numstat -- <file>` MUST print the counts above. If it prints anything
   else, stop and report; someone changed the file since this spec.
2. Save the hunk as evidence:
   `git diff -- <file> > .heel/plan-differential-run/T2-discarded-<basename>.patch`
   (`.heel/` is ignored).
3. `git restore --source=HEAD --worktree -- <file>`.
4. Verify: `git diff --quiet -- <file>` exits 0 and `git hash-object <file>` equals the
   blob above.

After all five: `git status --short` MUST no longer list them, and
`tests/test_open_core_release.py` MUST pass.

### 14.3 What to do with the rest of the current dirty tree

| Path | State now | Disposition |
|---|---|---|
| `heel/cli.py` | modified | **Rework.** Keep the `_runner_credential_add` hunks and the `runner run` subparser and dispatch. Remove `_SAFE_RUNNER_RUN_FAILURE`; `_runner_run` prints `_SAFE_RUNNER_COMMAND_FAILURE`. |
| `heel/regressions.py` | modified | **Reusable as is** (the branch only delegates), subject to §10 being implemented in the module. |
| `release/open-core-v1.json` | modified | **Reusable as is.** |
| `tests/test_open_core_release.py` | modified | **Reusable as is** (one added line). |
| `tests/test_runner_cli.py` | modified | **Reusable as is.** |
| `heel/runner/plan_differential.py` | untracked, 1652 lines | **Rewrite.** It imports `plan_differential_pairs` from the compiler and calls `compile_plan_differential_pair`, `route_inventory` and `route_inventory_path`, none of which will exist. The pure predicate code (`key_paths`, `is_denial_envelope`, `evaluate_plan_pair`) and the scaffolding (`_authorize`, context, signer, grant, reservation, budget, redacting store) MAY be kept after being re-checked line by line against this spec. Everything touching inventory loading, planning, compilation, HEAD, the vault, client construction, the redactor, row-1 reasons and replay results MUST be written to §6, §7, §8.5 and §10. It is evidence, not a base to trust. |
| `tests/plan_differential_support.py` | untracked | **Rework**: add the session recording, the four lower-plan behaviors and `/api/pricing` of §13. |
| `tests/fixtures/plan_differential/openapi.json` | untracked | **Rework**: add `/api/pricing`. |
| `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`, `launch/` | untracked, unrelated | **Do not touch.** |

### 14.4 Out of bounds

Reserved for later tasks, not T2: `docs/REDTEAM_PLAN_DIFFERENTIAL.md` and
`tests/test_runner_plan_differential_redteam.py` (T3); `docs/CAPABILITIES.md` (T5, three
rows only).

Everything else is out of bounds, explicitly: **every existing file under `heel/runner/`**
(`__init__.py`, `adapters.py`, `catalog.py`, `companion.py`, `compiler.py`,
`containment.py`, `content_assertion.py`, `control_client.py`, `coordinator.py`,
`execution.py`, `http_transport.py`, `identity.py`, `openapi_routes.py`, `redaction.py`,
`runtime.py`, `service.py`, `store.py`, `vault.py`), `heel/scope.py`, `heel/contracts.py`,
`heel/containment.py`, `heel/store.py`, `heel/canary_contracts.py`, `heel/mcp_server.py`,
`heel/rest.py`, `heel/static_review.py`, `heel/reference_rehearsal.py`, `heel/saas/`,
`apps/`, `web/`, `scripts/`, `.github/`, `README`, pricing docs, `pyproject.toml`,
`MANIFEST.in`, `tests/test_runner_http_transport.py`, `tests/test_runner_compiler.py`, and
the untracked `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md` and `launch/`. If the
implementation cannot be completed without one of these, stop and report; do not edit it.

No new dependency. `cryptography` stays under the `runner` extra and is imported lazily.
The module MUST NOT assign to, patch or mutate any object of another `heel.runner`
module at import or run time (for example `CATALOG`, `ADAPTER_REGISTRY`); it only
subclasses `RunnerStore` and `Redactor` and populates the trust store of a `TLSTransport`
instance it created.

## 15. Limits the docs must state

Inherited from the existing transport and contracts, unchanged by this work:

- Public HTTPS staging hosts only: port 443, public addresses, an IANA-TLD hostname.
  Private-network, loopback and custom-port staging are not reachable.
- TLS 1.2 only. No redirect is followed.
- Responses must carry `Content-Length`, no transfer or content encoding, and be empty or
  one JSON object of at most 256 KiB. Chunked, compressed, array and non-JSON responses
  make the pair `inconclusive`.
- One mapping per scenario, so at most one parameterized `GET` route and one parameterized
  `HEAD` route can be given fixture values; other parameterized routes are listed as
  `not_executed`.

Chosen for Phase 1:

- One staging origin per `HEEL_HOME`. Two plans. One credential per plan role.
- Each `HEAD` route costs four requests: one per plan identity and two unauthenticated
  control requests (§6.3).
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
| The two unauthenticated control requests per `HEAD` route are more traffic than "once per identity" strictly needs. They cannot be removed without a catalog edit (§6.3). | Orchestrator judgment at the T1 gate; R17 pins the exact count. |
| The private compiler is enforcement by construction inside one module, not a separate trust domain. | I2 (d), (e), (f); T3 to attack `_ScopedTransport` directly. |
| The HMAC append inside `before_attempt` runs under the transport's attempt deadline; a slow disk becomes `gate_rejected`. Fails closed, may be flaky. | I6 under repeated runs. |
| Up to 50 reserved runs in one attempt store against the 64-run bound. | R9 at `--max-ops 100`. |
| Redaction matches raw and JSON-escaped forms only; other encodings of an echoed secret are not matched. | I5 echo cases; T3 to attack. |
| The setup-store inventory path is computed from `root` and `namespace`, not returned by the store. | R19 default-inventory test; a layout change would fail closed (file not found → reject). |
| Credentials registered before this change have handles that were never displayed. | Operator uses a fresh `HEEL_HOME`. |
| `SYNTHETIC_ONLY` is the only data mode `heel scope create` issues; this design relies on canary accounts holding synthetic data. | Operator decision; not testable in code. |

## 17. Known conflict outside this run's authority: the CI `package` job

This is reported so nobody discovers it at T6. It does not block T2, T3, T4 or T5.

- The brief's gates are the pytest suite (`python -m pytest -q tests`). With §14 followed,
  the release tests in that suite pass (F23).
- The CI `package` job separately rebuilds the wheel from source and compares it with the
  artifacts checked in under `apps/heel-cloud/public/downloads` (F24). **Any** change to a
  file that ships in the wheel makes it fail. This feature must change `heel/cli.py` and
  add one module, both of which ship. No design can avoid that: a new CLI command cannot
  exist without a change to shipped code.
- Earlier runner commits regenerated those three artifacts in the same commit
  (`git log -- apps/heel-cloud/public/downloads`). The brief forbids editing `apps/` in
  this run.

Consequence: the T6 pull request will show the `package` job failing at "Check
deterministic Apache-only release artifacts" until someone with authority over `apps/`
regenerates the artifacts with
`python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads`.
That is a decision for the orchestrator and Kevin before merge. T2 MUST NOT regenerate
them and MUST NOT weaken or skip the check.
