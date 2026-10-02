# Plan-differential runner — Phase 1 design spec

Date: 2026-10-02. Branch: `feat/plan-differential-runner` (base `main` @ `844fc1f`).
Blast radius: **medium — adds network egress under a signed scope.**
Role: design only (T1, second attempt; the first draft was rejected and is superseded in
full). This document is the contract for T2 (implementation), T3 (red team), T4
(remediation) and T5 (acceptance). It makes no acceptance claim and contains no product
code.

Normative words: **MUST**, **MUST NOT**, **MAY**. Where this spec and the controlling brief
(`.heel/plan-differential-run/brief.md`) disagree, the brief wins and the implementer stops
and reports.

---

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

Each was read or run on 2026-10-02 at `844fc1f`.

| # | Fact | Evidence |
|---|------|----------|
| F1 | `heel runner import-openapi` and `heel runner credential add` exit 2 in a fresh `HEEL_HOME`. Every `RunnerStore` read or write needs a bound context and no public command binds one. | Ran both in an empty `HEEL_HOME`; `heel/runner/store.py:5203-5206`, `:5276-5288` |
| F2 | A credential handle is `secrets.token_hex(16)`: random, 32 hex, not derived from the secret. One handle per semantic role per context. | `heel/runner/store.py:6998`, `:7025`, `:6961-6979` |
| F3 | `credential add` prints only `{"registered_count": 1}`. An ephemeral credential is read from `HEEL_RUNNER_CREDENTIAL_<HANDLE>`, so an operator who is never shown the handle cannot supply it. | `heel/cli.py:199`; `heel/runner/vault.py:186-192`, `:252-270`; `tests/test_runner_cli.py:75` |
| F4 | The existing privacy boundary is: handle and label never enter the cloud-disclosed approval projection (they are in the local manifest), and `runner prepare` stdout is counts only. The label is treated as possibly sensitive operator text. | `tests/test_runner_compiler.py:291-292`; `tests/test_runner_cli.py:76`, `:96-98` |
| F5 | The imported inventory is persisted as `routes.json` in the bound context directory, in the envelope `heel.runner-route-inventory.v1` (`schema_version`, `namespace`, `origin`, `verification_record_digest`, `inventory: {source_digest, routes}`). Each route is `{method, route_template, operation_id, placeholders}` with method `GET` or `HEAD` only, in canonical order. | `heel/runner/store.py:6839-6904`, `:808-826`; `heel/cli.py:142-154` |
| F6 | `plan_entitlement_read` permits `GET` only; `anonymous_authenticated_read` already permits `GET` and `HEAD`. Roles are `lower_plan`, `higher_plan`, lower first. | `heel/runner/catalog.py:60-93` |
| F7 | The transport, the manifest contract and the adapter already carry `HEAD`: HEAD framing is parsed, a HEAD body is refused, and a HEAD pair always evaluates `inconclusive`. | `heel/runner/http_transport.py:473`, `:594-595`, `:612-613`, `:801`; `heel/canary_contracts.py:270-271`; `heel/runner/adapters.py:189-195`; `heel/runner/content_assertion.py:15` |
| F8 | The transport is HTTPS only, port 443, public addresses only, exact IANA-TLD hostname; no IP literal, port, userinfo, path, punycode or reserved suffix. | `heel/runner/http_transport.py:98-142`, `:46-53`, `:157-175` |
| F9 | Any 3xx raises `response_rejected`; no redirect is followed. `Host` is always the normalized hostname; no caller input reaches a header. | `heel/runner/http_transport.py:571-572`, `:906-912` |
| F10 | DNS is pinned. Each attempt re-resolves, requires set equality with the preflight set, connects to the pinned numeric address and re-checks the peer address. | `heel/runner/http_transport.py:695-716`, `:734-737`, `:760-761` |
| F11 | `TLSTransport` builds `ssl.SSLContext(PROTOCOL_TLSv1_2)` with `CERT_REQUIRED` and `check_hostname` but loads no trust store. `cert_store_stats()` on that context reports zero CA certificates, so a real handshake cannot verify any server. | `heel/runner/http_transport.py:233-243`; ran `cert_store_stats()` locally. Handshake failure is inferred, not run. |
| F12 | A test pins `TLSTransport().context.protocol == PROTOCOL_TLSv1_2` and forbids `ssl.create_default_context`, for the runner class and the `heel/saas` twin. | `tests/test_runner_http_transport.py:30-38` |
| F13 | The transport refuses `Transfer-Encoding` and `Content-Encoding`, bodies over 256 KiB, and any non-empty body that is not one JSON object. Evidence is stored before the body-shape refusal. | `heel/runner/http_transport.py:591-592`, `:604-605`, `:609-633`, `:845-863` |
| F14 | The executor reserves the grant before any transport call, calls `before_attempt` before every socket, and writes **raw** response headers and body to the private store. | `heel/runner/execution.py:579`, `:651-710`, `:716-736` |
| F15 | One manifest holds at most 20 actions and `maximum_requests` ≤ 20; evidence ordinals are < 20; the store keeps one mapping per scenario and at most four. | `heel/canary_contracts.py:309`, `:377`; `heel/runner/store.py:9270`, `:6932`, `:6953` |
| F16 | The marker contract: exactly one fixture binding beginning `heel-canary-` opts the route into `protected_canary`. | `heel/runner/execution.py:712-714`; `heel/runner/content_assertion.py:7-37`; `docs/EXPORT_DEMO.md:32` |
| F17 | `heel findings --run`, `heel log --run` and `heel regress add` read the SQLite `Store` and the HMAC containment chain, which carries `caller`. The runner's Ed25519 chain has no caller field. | `heel/cli.py:1423-1428`; `heel/containment.py:24-65`; `heel/runner/containment.py:25-29` |
| F18 | `heel regress run` re-executes through `HeelServer.heel_run`, which only knows registered synthetic targets. | `heel/regressions.py:142-203` |
| F19 | The wheel's module list is pinned twice. `tests/` is pruned from the wheel. | `release/open-core-v1.json`; `tests/test_open_core_release.py:107-206`, `:223` |
| F20 | `reference_rehearsal.run_reference` is the proven safe sequence: verify scope → exclusive attempt directory → ephemeral signer and identity → private `RunnerStore` → compile → locally signed grant → `LocalCanaryExecutor` → read private evidence → report. | `heel/reference_rehearsal.py:107-184` |
| F21 | Only `tests/test_runner_compiler.py:132` and the compiler error text at `heel/runner/compiler.py:149` depend on `plan_entitlement_read` being GET-only. No `heel/saas`, coordinator, runtime or app code reads `allowed_methods`. | repository grep for `allowed_methods`, `GET only` |

Consequence: Phase 1 is `run_reference` with the fixture transport replaced by the real
`TargetHTTPSClient`. Where an existing interface is too narrow for the brief it is
**extended** (catalog, compiler, store, TLS trust, credential output) and the file is
listed in §14. Restrictions that are properties of the inherited transport are kept and
stated in §15.

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
argv guard (`heel/cli.py:960-964`). No other option exists. There is **no** option,
environment variable, config key or scope field that selects a transport, scheme, port,
resolver, CA bundle, header, method, attempt ID or caller identity.

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
  `$HEEL_HOME/runner/contexts/<namespace>/routes.json`. The dry-run prints that path, its
  `source_digest` and its route count so the operator can copy or archive it.
- Given: `PATH` is read with the existing bounded loader `_load_bounded_openapi` (regular
  file, no symlink, size-limited, duplicate keys rejected). It MUST be a complete
  `heel.runner-route-inventory.v1` envelope whose `namespace`, `origin` and
  `verification_record_digest` equal the bound setup context, and whose routes pass the
  store's `_route_record(require_canonical=True)` and canonical-order checks. Typical use
  is a saved copy of an earlier import for the same origin.
- The file is the whole allowlist for that invocation. Every route in it is planned.
  Execution order is the inventory's canonical order `(route_template, method,
  operation_id)`.
- An inventory file carries no signature. It is operator input at the same trust level as
  the OpenAPI document it was derived from. It can never name another origin (envelope
  check), a non-GET/HEAD method or an unsafe template (§6.2).

`--routes` never writes to the setup store and never changes the default inventory.

### 3.4 Per-route planning

Decided in the compiler (§6.2), for every route of the chosen inventory:

| Route | Decision |
|---|---|
| `GET` or `HEAD`, no placeholders | planned: 2 requests |
| `GET` or `HEAD`, placeholders, and the setup store holds a `plan_entitlement_read` mapping for exactly this `(method, route_template)` | planned with those fixture bindings |
| placeholders, no such mapping | `not_executed`, reason `unbound_placeholder`; never sent |
| any other method, or a route failing template rules | compile error for the whole command |

`HEAD` routes are executed like `GET` routes, once per identity. Heel never invents a path
parameter value; a human supplies one through the existing `heel runner map --scenario
plan_entitlement_read --method M --route T --fixture-fd N`.

### 3.5 Human-supplied marker

There is no marker flag. The marker is supplied through the existing channel (F16): one
fixture value beginning `heel-canary-` in the mapping above opts that route into the
`protected_canary` contract. Heel never generates, guesses or extracts a marker from a
response. The fixture value is never written to a finding, report or log; only
`marker_supplied: true` and the SHA-256 of the canonical binding list are.

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

Stdout is one JSON object. On rejection, stderr is the fixed line
`Heel runner run was rejected.` and stdout is empty. No path, URL, label, handle, route or
exception text is reflected. All exceptions are caught at the command boundary.

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
            "requests": 2, "marker_supplied": false}],
 "not_executed": [{"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"}],
 "requests_planned": 2, "requests_sent": 0, "plan_sha256": "<64 hex>"}
```

`plan_sha256` is the canonical digest of origin, scope ID, both plan entries, inventory
`source_digest`, the ordered pairs with their binding digests, and `effective_max_ops`.
The executed result repeats it so an operator can compare a run with its dry-run.

Executed object: `mode: "executed"`, `run_id`, `attempt_id`, `scope_id`, `origin`,
`plan_sha256`, `requests_sent`, `effective_max_ops`, `pairs` (one entry per planned pair:
`method`, `route_template`, `verdict`, `predicate`, `reason`, `execution_disposition`,
`candidate`, `finding_id` or `null`, `runner_run_id`), `not_executed`, `findings` (`id`,
`predicate`, `evidence_state`, `method`, `route_template`), `chain_valid`, `report_path`.
`pairs` is the truthful record of every planned pair, including pairs that did not
complete; `findings` lists only stored findings (§11).

## 4. Operator journey and state

Two `RunnerStore` roots under `HEEL_HOME`, both private (0700/0600, no symlinks):

- **Setup store**: the default `RunnerStore()`. Holds the inventory, credential metadata
  and the optional mapping. It never executes.
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
`heel.runner.http_transport` (`TargetHTTPSClient`, `BoundedResolver`, `SocketTransport`,
`TLSTransport`, `normalize_target_origin`, `CancellationToken`, `TransportFailure`),
`heel.runner.execution` (`LocalCanaryExecutor`, `ExecutionBundle`, `ExecutionGate`),
`heel.runner.store` (`RunnerStore`, `RunnerContext`), `heel.runner.vault` (`EphemeralVault`,
`select_vault`, `ephemeral_environment_name`), `heel.runner.redaction` (`_secret_key`),
`heel.runner.content_assertion.protected_content`, `heel.runner.openapi_routes`
(`normalize_route_template`), `heel.runner.identity`, `heel.runner.containment`
(`verify_containment_chain`). `heel.runner.adapters` and `heel.runner.execution` are used
unmodified.

## 6. Extensions to existing modules

### 6.1 `heel/runner/catalog.py`

`plan_entitlement_read`: `allowed_methods` becomes `("GET", "HEAD")`. Nothing else
changes; `adapter_version` stays `"1"`. This is additive inside the already closed
read-only GET/HEAD set, the adapter registry derives from the catalog, and a HEAD pair
still always assesses `inconclusive` (F7). Consequence to state in docs: `runner map` and
`runner prepare --live` now accept a HEAD mapping for this scenario.

### 6.2 `heel/runner/compiler.py`

Add one module-level pure function and one `CanaryCompiler` method. Change nothing else.

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

`plan_differential_pairs` is the per-route allowlist of brief §1.2. It takes the raw
route list of the chosen inventory **before** the store sees it. It MUST:

- raise `ValueError` if any entry's method is not in
  `CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"]`, so a `POST` (or any other)
  inventory entry is a compile error for the whole command;
- raise `ValueError` if any entry is not a closed `{method, route_template, operation_id,
  placeholders}` record, if `normalize_route_template` rejects or changes the template,
  if placeholders disagree, if a `(method, route_template)` repeats, or if there are more
  than 2000 entries;
- return planned and not-executed routes per §3.4 in canonical order. It never adds,
  rewrites or derives a route.

`compile_plan_differential_pair` compiles one pair in the attempt store. It MUST:

- raise unless `method` is in the catalog's allowed methods for `plan_entitlement_read`;
- raise unless `(method, NFC route_template)` is exactly in `self.store.list_routes()`.
  This is an independent membership check against the persisted inventory of the store
  the compiler is bound to, not against the caller's list;
- call `self.store.save_mapping("plan_entitlement_read", …)` (which re-checks membership,
  `heel/runner/store.py:6924-6930`) then `self.compile(["plan_entitlement_read"])`;
- raise unless the result has exactly two actions, both with that method and template,
  roles `lower_plan` then `higher_plan`.

Every request that can reach the transport is an action in a manifest returned by this
method.

### 6.3 `heel/runner/store.py`

Add two read-only public methods to `RunnerStore`. No existing method changes.

- `route_inventory(artifact: Mapping[str, Any] | None = None) -> dict` returns
  `{"source_digest", "routes"}`. With `None` it reads `routes.json`. With a parsed
  artifact it applies the same `_validate_envelope` and route checks used for the stored
  file. The existing `_routes_locked` body is factored so both paths share one validator.
- `route_inventory_path() -> Path` returns the `routes.json` path of the bound context.

### 6.4 `heel/runner/http_transport.py`

`TLSTransport.__init__` additionally calls `self.context.load_default_certs()`. Protocol,
`CERT_REQUIRED` and `check_hostname` are unchanged, so the pinned test (F12) still holds.
Without this the production client cannot complete any handshake (F11). Nothing else in
the file changes.

### 6.5 `heel/cli.py`

- `runner run` subparser, handler `_runner_run(args)`, one dispatch line, one constant
  `_SAFE_RUNNER_RUN_FAILURE = "Heel runner run was rejected."`.
- `_runner_credential_add` prints the object of §3.2 using the record returned by the
  store. No other command's behavior or output changes.

### 6.6 `heel/regressions.py`

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
| `_build_client(origin) -> TargetHTTPSClient` | The only client constructor. One bounded `BoundedResolver()` preflight, then `TargetHTTPSClient(origin=origin, preflight_addresses=answers)` with **no** `resolver`, `sockets` or `tls` argument, so the defaults `BoundedResolver`, `SocketTransport`, `TLSTransport` are used. It takes no other parameter and reads no environment, file or config. |
| `_AttemptReservation` | Result of the exclusive `os.mkdir`. Holds attempt ID and root. Constructed only by `_reserve_attempt`. |
| `_PlanVault` | `supported=True`, `backend_id="ephemeral_env"`. Maps each attempt-store handle to the setup-store record. Loads each real secret **once per invocation** from its real vault (`EphemeralVault` or `select_vault(backend)`), keeps it in memory only, registers it with the redacting store, and clears it at exit. Refuses (`VaultUnavailable`) a bearer or API-key value, or any cookie value, shorter than 8 bytes, because it cannot be redacted reliably. |
| `_RedactingRunnerStore(RunnerStore)` | Overrides only `store_response_evidence`: before delegating, replaces every registered secret, in raw form and in JSON-string-escaped form, in `raw_headers` and `raw_body` with `b"[REDACTED:secret]"`. Needed because the executor stores raw bytes (F14). |
| `_ScopedTransport` | Wraps the client. Requires an `_AttemptReservation` whose directory exists, else raises `TransportFailure("gate_rejected")`. Refuses any action whose scenario is not `plan_entitlement_read`, whose method is not `GET`/`HEAD`, or whose `(method, route_template)` is not the frozen current pair. Wraps the executor's `before_attempt` as in §9. |
| `_gate(scope_id, host)` | `gate_source` for the executor. Calls `_authorize` each time; inactive if the scope no longer verifies or no longer lists the host. |
| `_grant(...)` | As `reference_rehearsal._grant`, with `approval_actor {"user_id": "local_operator", "role": "owner"}` and a reason naming the scope ID. Ephemeral `SigningAuthority`, trusted only in this process. |
| `_finding(...)` | Builds one `AbuseVector` (§11). |

### 7.1 Execute sequence

1. `caller` check. `_authorize`. Normalize origin. Host not in allowlist → forced dry-run
   result, stop. Setup context MUST be bound to this origin, else reject.
2. Resolve both handles (§3.2). Load the inventory with `route_inventory(routes_artifact)`.
   `plan_differential_pairs`. Zero planned pairs → reject.
3. Budget (§9). Planned pairs beyond `effective_max_ops // 2` become `not_executed`
   (`over_budget`).
4. **Reserve the attempt**: `os.mkdir(HEEL_HOME/plan-runs/<attempt>, 0o700)`, exclusive. An
   existing directory is a replay and is rejected. Nothing above this line touches the
   network; nothing below runs without it.
5. Open `Store(HEEL_HOME/heel.db)`; `add_run("pdrun-<attempt>", scope_id, origin, caller,
   "running", …)`; containment `run_start`.
6. Build the attempt store (`_RedactingRunnerStore`), ephemeral signer and identity, bind
   the same context values as the setup store, `replace_routes(<whole inventory>,
   source_digest=…)`, register two ephemeral credential records (`lower_plan`,
   `higher_plan`) served by `_PlanVault`.
7. `_build_client(origin)` once: one DNS preflight pins the address set for the invocation.
8. For each planned pair in order: skip as `not_executed` (`budget_exhausted`) if fewer
   than 2 ops remain; else `compile_plan_differential_pair` → `_grant`
   (`run_id="crun_<attempt>_<nn>"`, 30 s expiry) → `LocalCanaryExecutor.execute(bundle,
   transport=_ScopedTransport, gate_source=_gate, cancellation=token)`. The executor
   reserves the grant and sends lower then higher.
9. After each pair: read both evidence records from the attempt store, matched by
   `action_ordinal` as `reference_rehearsal.py:160-167` does; run `evaluate_plan_pair`; append
   a `plan_differential_pair` containment entry carrying the verdict, reason and the
   executor's true `execution_disposition`. Then, **only when the executor disposition is
   `completed` and the verdict is not `held`** (§8.5 rows 2, 3, 5, 6, 8, 9), `add_finding`
   plus a `finding` containment entry. A pair that did not complete (row 1) stays in the
   result and `report.json` as `inconclusive` with its true disposition and reason, and
   creates **no** `AbuseVector`.
10. Continue to the next pair only when the pair completed or failed with executor
    `error_category == "containment_rejected"` (a response-level refusal). On any other
    failure or a stop, mark the pair `inconclusive` and all later pairs `not_executed`.
11. `set_run_status("complete")`, containment `run_complete`, `verify_chain`, write
    `report.json` (`O_EXCL|O_NOFOLLOW`, 0600), return.

Any exception after step 4 MUST leave the run row with a terminal status (`complete` or
`rejected`) and a `run_complete` or `run_failed` containment entry, and MUST NOT leave
credential bytes anywhere under `HEEL_HOME`.

### 7.2 Network decisions

| Topic | Decision |
|---|---|
| Scheme | HTTPS only. No HTTP, loopback, private-address, custom-port or custom-CA capability exists in product code and no switch enables one. |
| TLS | System trust store (§6.4), certificate required, hostname checked, SNI = normalized host. TLS 1.2 only (inherited, F12). A TLS failure ends the invocation (`transport:tls_error`). |
| DNS | One bounded preflight per invocation; every answer must be public; the set is pinned. Each attempt re-resolves and requires set equality, connects to the pinned numeric address and re-checks the peer (F10). A change ends the invocation (`dns_changed`). A replay re-preflights and never reuses stored addresses. |
| Host header | Always the normalized hostname, built by the transport (F9). |
| Redirects | Never followed, on or off the allowlist (F9). The pair is `inconclusive` (`transport:response_rejected`). |
| Encodings | `Accept-Encoding: identity`. Chunked or content-encoded responses are refused (F13). |

### 7.3 Test seams versus the unmodified public CLI

There is exactly one seam: tests replace the module attribute
`heel.runner.plan_differential._build_client`. It is not a parameter of any public
function and no argv, environment variable, file or scope field can set it.

| What | How it is tested | What it proves and does not prove |
|---|---|---|
| Argument rules, rejection, forced dry-run, bootstrap, plan, `credential add` output | `heel.cli.main(argv)` with **no** seam, with `socket.socket` and `socket.getaddrinfo` patched to fail | The unmodified public CLI, and that these paths open no socket. |
| Execution, findings, containment, regression replay | `heel.cli.main(argv)` with `_build_client` replaced by a factory returning a real `TargetHTTPSClient` whose injected `resolver` returns a fixed public address, whose `sockets` connects to the loopback synthetic target and reports the pinned address from `getpeername`, and whose `tls` is a pass-through | Request construction, `Host`, framing, 3xx refusal, body rules, gate, budget, reservation, evidence, redaction, predicates and logging are product code. **It proves nothing about TLS, DNS answers or address selection.** |
| Production client construction | `_build_client` unreplaced, with only `socket.getaddrinfo` patched to return a public address | The production path builds `BoundedResolver`, `SocketTransport` and `TLSTransport` with certificate verification, hostname checking and default trust loading, and passes no seam object. No handshake is performed. |
| Real TLS verification | A real `TLSTransport` wraps a real socket to a loopback `ssl` server whose certificate is issued by a test CA generated in the test. The test adds that CA to `transport.context` | The real class performs a real handshake, accepts a matching chain and hostname, and rejects a wrong hostname and an untrusted issuer. It does not prove the contents of the system trust store or a public PKI handshake. |

No CI test performs a real public HTTPS request through the full client. No test in this
feature may be described as proving real TLS behavior unless it is the real-handshake test
above.

## 8. Predicates

### 8.1 Inputs

For lower (`L`) and higher (`H`): `status`, `body` (the stored, redacted bytes), `json`
(parsed with duplicate-key rejection; `None` if empty or unparseable). Plus `method`,
`marker` (the supplied `heel-canary-` value or `None`) and the executor's
`execution_disposition` and `assessment_outcome`.

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
**withholds** parity; it never creates a finding and never creates a `held` verdict.

### 8.4 Three-valued predicates

Each is `True`, `False` or `None` (undetermined).

`completed` := executor disposition is `completed` and both evidence records load and
verify.

`positive_control` := `completed` ∧ `H.status` is 2xx ∧ `H.json` is not a denial envelope
∧ (`marker` supplied ⇒ `H.status == 200` ∧ `P(H)` is `True`).

| Predicate | `None` when | `True` when | `False` when |
|---|---|---|---|
| `status_parity` | no `positive_control`; or `L.status` is neither 2xx nor a denial status; or `L.status` is 2xx and `L.json` is a denial envelope | `L.status` is 2xx and `L.json` is not a denial envelope | `L.status` is a denial status |
| `body_superset` | no `positive_control`; or `method` is `HEAD`; or `H.json` is not an object; or `key_paths(H)` is empty; or a bound is exceeded; or `L.json` is a denial envelope that also contains every higher key path | `L.status` is 2xx, `L.json` is an object, not a denial envelope, and `key_paths(L) ⊇ key_paths(H)` | otherwise (lower denied, lower empty, or lower lacks a higher key path) |
| `marker_leak` | no marker; or `method` is `HEAD`; or no `positive_control`; or `P(L)` is `None`; or the executor's `assessment_outcome` disagrees | `P(L)` is `True` and executor outcome is `observed` | `P(L)` is `False` and executor outcome is `blocked` |

A 2xx denial envelope therefore never makes `status_parity` or `body_superset` true.

### 8.5 Verdict table — first matching row wins

| # | Condition | Verdict | `evidence_state` | Predicate / reason |
|---|---|---|---|---|
| 1 | not `completed` | inconclusive, **no finding stored** | — (report only) | `inconclusive` / `transport:<code>`, `stopped`, `budget_exhausted` or `evidence_unavailable` |
| 2 | no `positive_control` | inconclusive | `inconclusive` | `inconclusive` / `no_positive_control` or `positive_control_missing_marker` |
| 3 | `marker_leak` is `True` | finding | `verified` | `marker_leak` |
| 4 | `marker_leak` is `False` | held | — | `marker_absent` |
| 5 | marker supplied (and `marker_leak` is `None`) | inconclusive | `inconclusive` | `inconclusive` / `marker_undetermined` |
| 6 | `body_superset` is `True` | finding | `observed` | `body_superset` |
| 7 | `status_parity` is `False` | held | — | `lower_denied` |
| 8 | `status_parity` is `True` | inconclusive, `candidate: true` | `inconclusive` | `status_parity` / `head_status_only`, `status_only` (no comparable bodies) or `lower_subset` |
| 9 | otherwise | inconclusive | `inconclusive` | `inconclusive` / `lower_denial_envelope`, `unexpected_status` or `body_too_complex` |

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

- **Unit**: one op is one request attempt on the wire, including a retry.
- `effective_max_ops = min(--max-ops, scope.rate_and_resource_limits["max_requests"])` when
  the scope defines an integer `max_requests`, else `--max-ops`. If the result is < 2, or
  `Store.scope_run_count(scope_id) >= max_requests` (the rule `heel_run` already applies),
  reject.
- **Per-attempt order**, inside the wrapped `before_attempt`, before any socket:
  1. `_authorize` again; failure raises `gate_rejected`.
  2. take one unit from the invocation-wide counter, or raise `gate_rejected` with
     `gate_error="budget_exhausted"`;
  3. call the executor's own `before_attempt` (grant authority, per-manifest budget,
     retry rules, signed `action_started` event);
  4. append one HMAC containment entry `plan_differential_request` with `method`,
     `route_template`, plan `label`, `role`, `attempt`, `runner_run_id`, `op_index`.
     If the append fails the attempt is refused.
  Only then does the transport resolve and connect. So total wire requests never exceed
  `effective_max_ops`, and no request exists without an earlier entry. An entry MAY exist
  for an attempt that then failed in DNS or connect.
- The per-manifest `BUDGETS` and `RETRY_POLICY` (one retry, `connect_error`/`timeout`)
  apply unchanged inside each pair. Concurrency is one.
- `--max-ops ≤ 100` keeps one attempt at ≤ 50 reserved runs, below the store's 64-run
  tracking bound (`heel/runner/store.py:190`).
- **Attempt ID**: generated by Heel, reserved by exclusive `mkdir`, never reusable. Each
  pair additionally consumes its own one-shot grant through `RunnerStore.reserve_run`
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
| `method`, `route_template` | MUST still be in the current default inventory; compiled through §6.2 |
| `fixture_bindings_sha256`, `marker_supplied` | the current mapping's binding digest MUST equal it |

Any mismatch produces result `fail` with `current_status: "inconclusive"` and **no
request**. Otherwise the full execute sequence of §7.1 runs for that one pair with a new
attempt ID and `max_ops=4`, and the saved predicate `p` decides:

| Re-evaluation | `result` | `current_status` |
|---|---|---|
| `positive_control` and `p` is `False` | `pass` | `blocked` |
| `p` is `True` | `fail` | `still_reachable` |
| anything else | `fail` | `inconclusive` |

Envelope detection never produces a pass by itself: a pass needs a valid positive control
and the saved predicate re-evaluating to `False` on the new responses. A replay pair that
does not complete is `fail` / `inconclusive` and, like any incomplete pair, stores no new
finding. For a saved predicate of `inconclusive` there is no `p`; the result is `pass` only when
the verdict is `held`. `result` is only ever `pass` or `fail`. The result record keeps the
existing fields (`matches_expected = current_status == expected_status`) plus `result`,
and is stored with `add_regression_result` and a `regression_result` containment entry.

## 11. Finding schema

**Eligibility.** One `AbuseVector` is stored with `Store.add_finding` for a pair if and
only if the executor's `execution_disposition` for that pair is exactly `completed` and
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
 "attempt_id": "...", "runner_run_id": "crun_<attempt>_<nn>", "plan_sha256": "<64 hex>",
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
| I2 | **GET/HEAD and inventoried-route confinement.** | `test_i2_only_inventoried_get_and_head_reach_the_wire`; `test_i2_post_inventory_is_rejected_at_compile` | (a) an inventory artifact with a `POST` entry is rejected by `plan_differential_pairs` and the command exits 2 with zero requests; (b) `compile_plan_differential_pair` refuses a route absent from the store inventory and a non-GET/HEAD method; (c) across a full run the target's log contains only `GET` and `HEAD` and only planned paths; (d) `_ScopedTransport` refuses an action outside the frozen pair. | No method other than GET/HEAD |
| I3 | **Verified signed scope.** | `test_i3_no_request_without_verified_signed_scope` | Unknown scope, hand-edited scope file (allowlist widened), expired scope and unbound scope each give exit 2 and zero requests; a scope file edited after the first pair stops the run before the next request. | No request without a signed scope … |
| I4 | **One-shot reserved attempt.** | `test_i4_no_request_without_one_shot_reserved_attempt` | (a) reusing an attempt ID is refused with zero requests; (b) `_ScopedTransport` built without a reservation, or whose directory is gone, refuses with zero connections; (c) with `reserve_run` forced to fail, zero requests are sent; (d) a consumed grant cannot be executed twice. | … and a reserved attempt ID |
| I5 | **Secret exclusion.** | `test_i5_credential_plaintext_absent_from_heel_home_and_output` | After a successful run, a run against a route echoing the credential in a header and in the body, a run failing in transport, a run stopped by scope tamper, and a run with a missing credential: a byte scan of every file under `HEEL_HOME` (`heel.db`, evidence `.bin`, reports, both containment logs) finds neither credential, and stdout, stderr, findings and containment rows contain neither. | Credentials never appear in reports, logs, findings, or containment entries |
| I6 | **Every request logged.** | `test_i6_every_request_is_logged_before_it_is_sent` | In a run with no append failure, count of `plan_differential_request` entries == sum of runner `requests_started` ≥ requests counted by the target, including a forced retry; each target request maps to a distinct entry appended before it arrived; a failing append sends nothing. | Containment log records every request … |
| I7 | **Caller attribution.** | `test_i7_every_containment_entry_carries_cli_caller` | Every containment row for the run has `caller == "cli:<user>"`; `run_plan_differential` raises for an empty or non-`cli:` caller before any state change. | … with caller attribution |
| I8 | **Chain integrity.** | `test_i8_containment_chains_verify_and_detect_tamper` | `containment.verify_chain` is true after success and after failure; mutating one stored row makes it false; the runner's signed chain verifies for each `crun_` run with `verify_containment_chain`. | chain verifies |

Independent requirements:

| # | Requirement | Named test | File and proof |
|---|---|---|---|
| R9 | Total request budget | `test_r9_max_ops_hard_caps_total_requests` | safety — with `max_ops=5` and retries forced the target sees ≤ 5 requests; `--max-ops` 1, 101 and non-integer are rejected; a lower scope `max_requests` wins. |
| R10 | CLI-only entry | `test_r10_no_mcp_or_rest_entry` | safety — `mcp_server.TOOL_NAMES` equals an explicit expected set; nothing in `mcp_server.py` or `rest.py` references `plan_differential`. |
| R11 | Fail-closed predicates | `test_r11_verdict_table_rows` (one case per §8.5 row), `test_r11_predicates_fail_closed`, `test_error_envelope_never_counts_as_parity` | `tests/test_runner_plan_differential_predicates.py` — status-only, 2xx denial envelope, empty, HEAD, missing positive control, executor disagreement, exception in evaluation; `candidate` is `true` on row 8 only. |
| R12 | No scope creation or mutation | `test_r12_scope_files_are_never_written` | safety — the scopes directory's file list, bytes and mtimes are identical before and after bootstrap, dry-run, run, failed run and replay; the new module does not import `create_scope`. |
| R13 | Dry-run sends nothing | `test_r13_dry_run_sends_nothing` | safety, no seam — zero sockets, no resolver call, no attempt directory, no credential variable consumed. |
| R14 | No transport selection from the CLI | `test_r14_cli_cannot_select_transport` | `tests/test_runner_plan_differential_cli.py` — the `run` option set equals the six of §3.1; plausible override environment variables change nothing; `_build_client` takes only `origin`. |
| R15 | Observed finding without declaration | `test_r15_observed_finding_from_undeclared_route` | cli — with an OpenAPI carrying no plan metadata the run yields a `body_superset` finding with `evidence_state == "observed"` and `operator_declared is False`; `heel findings --run` and `heel regress add` work on it unchanged. |
| R16 | Safe failure output | `test_r16_rejections_do_not_reflect_input` | cli — rejected commands print only the fixed stderr line. |
| R17 | HEAD executed | `test_r17_head_routes_execute_once_per_identity` | safety — every planned `HEAD` route appears exactly twice in the target log (once per identity) and its pair is `held` or `inconclusive`, never skipped. |
| R18 | Handles on `--as` | `test_r18_as_accepts_only_registered_credential_handles`, `test_r18_credential_add_prints_handle_never_label_or_secret` | cli — a label, an unknown handle, swapped order, same handle twice and mismatched profiles are rejected; `credential add` prints the §3.2 object and nothing sensitive. |
| R19 | Imported inventory on `--routes` | `test_r19_routes_consumes_persisted_inventory_artifact`, `test_r19_routes_default_is_existing_imported_inventory` | cli — a copy of `routes.json` is accepted; a selector-style array, another origin's envelope, a non-canonical or symlinked file are rejected; omitted means the stored inventory; the setup store is never rewritten. |
| R20 | Replay fidelity | `test_r20_regression_replay_reuses_saved_predicate_order_scope_origin` | cli — replay is `fail` on the vulnerable target and `pass` on the hardened one; a different origin, scope, handle, role order or binding digest gives `fail`/`inconclusive` with zero requests. |
| R22 | Finding eligibility | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` | safety — in a run mixing completed pairs, a `transport:response_rejected` pair, a redirect pair, a scope-tamper stop and budget exhaustion: every row in `heel findings --run` has `reproduction.execution_disposition == "completed"`; each non-completed pair has no `AbuseVector` but appears in the result `pairs` and `report.json` as `inconclusive` with its true disposition and reason; `held` pairs have no finding; `candidate` is `true` exactly for `status_parity` findings. |
| R21 | Production client | `test_r21_production_client_construction_is_unseamed`, `test_r21_tls_transport_real_handshake_verifies_chain_and_hostname` | safety — as described in §7.3, with the stated limits. |

## 13. Synthetic target and harness (tests only)

`tests/plan_differential_support.py`: a stdlib `http.server` on `127.0.0.1`, port 0,
started and stopped per test, with two bearer sessions carrying a plan flag (`free`,
`pro`). Every response sends `Content-Length`, closes the connection and uses no transfer
or content encoding. It records every request (method, path, `Host`, arrival order). A
constructor flag switches between vulnerable and hardened. The module also holds the
loopback seam objects and the test CA helper of §7.3.

| Route | Free | Pro | Expected verdict |
|---|---|---|---|
| `GET /api/export` | 200, same object (vulnerable) / 403 (hardened) | 200 object | `observed` `body_superset` / `held` |
| `HEAD /api/export` | 200 / 403 | 200 | `inconclusive` `status_parity` / `held` |
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
   the synthetic journey through the harness, the seam disclosure of §7.3 and the limits
   of §15.

Modified, with the only permitted change:

9. `heel/runner/catalog.py` — §6.1.
10. `heel/runner/compiler.py` — §6.2.
11. `heel/runner/store.py` — §6.3.
12. `heel/runner/http_transport.py` — §6.4.
13. `heel/cli.py` — §6.5.
14. `heel/regressions.py` — §6.6.
15. `tests/test_runner_compiler.py` — the catalog pin at line 132 only.
16. `tests/test_runner_cli.py` — the `credential add` output assertion at line 75 only;
    the label assertion at line 76 stays.
17. `release/open-core-v1.json` — add `heel/runner/plan_differential.py`.
18. `tests/test_open_core_release.py` — add the same path to `EXPECTED_CONTRACT`.

Reserved for later tasks, not T2: `docs/REDTEAM_PLAN_DIFFERENTIAL.md` and
`tests/test_runner_plan_differential_redteam.py` (T3); `docs/CAPABILITIES.md` (T5, three
rows only).

Everything else is out of bounds, explicitly: `heel/runner/execution.py`, `adapters.py`,
`vault.py`, `redaction.py`, `containment.py`, `content_assertion.py`, `openapi_routes.py`,
`heel/scope.py`, `heel/contracts.py`, `heel/containment.py`, `heel/store.py`,
`heel/canary_contracts.py`, `heel/mcp_server.py`, `heel/rest.py`, `heel/static_review.py`,
`heel/reference_rehearsal.py`, `heel/saas/`, `apps/`, `web/`, `README`, pricing docs,
`pyproject.toml`, `MANIFEST.in`, `tests/test_runner_http_transport.py`, and the untracked
`docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md` and `launch/`. If the implementation cannot be
completed without one of these, stop and report; do not edit it.

No new dependency. `cryptography` stays under the `runner` extra and is imported lazily.

## 15. Limits the docs must state

Inherited from the existing transport and contracts, unchanged by this work:

- Public HTTPS staging hosts only: port 443, public addresses, an IANA-TLD hostname.
  Private-network, loopback, custom-port and custom-CA staging are not reachable.
- TLS 1.2 only. No redirect is followed.
- Responses must carry `Content-Length`, no transfer or content encoding, and be empty or
  one JSON object of at most 256 KiB. Chunked, compressed, array and non-JSON responses
  make the pair `inconclusive`.
- One mapping per scenario, so at most one parameterized `(method, route)` can be given
  fixture values; other parameterized routes are listed as `not_executed`.

Chosen for Phase 1:

- One staging origin per `HEEL_HOME`. Two plans. One credential per plan role.
- `observed` means the lower plan received every field the higher plan received on one
  read. It is a hypothesis about a missing plan gate; ungated-by-design routes will appear.
- A 2xx denial body is never counted as parity and, without a marker, never as `held`.
  On replay it can pass only because the saved predicate re-evaluates to false (§10).
- Target ownership is asserted only by the operator's signed local scope.
- A regression replays only under the same, still-valid scope.
- Nothing is uploaded.

## 16. Open risks for T2 and T3 to confirm

| Risk | What would confirm or refute it |
|---|---|
| The system trust store may load zero CAs on some Python builds; the run then fails closed with `tls_error`. | A real run against a public staging host. Not covered by CI. |
| TLS 1.2 only and no chunked decoding may make many real targets `inconclusive`. | First real-staging run. Lifting either is a transport change outside Phase 1. |
| Widening `plan_entitlement_read` to HEAD under adapter version `"1"`. | T3 review of the cloud projection path; F21 found no other reader. |
| The HMAC append inside `before_attempt` runs under the transport's attempt deadline; a slow disk becomes `gate_rejected`. Fails closed, may be flaky. | I6 under repeated runs. |
| Up to 50 reserved runs in one attempt store against the 64-run bound. | R9 at `--max-ops 100`. |
| Redaction matches raw and JSON-escaped forms only; other encodings of an echoed secret are not matched. | I5 echo cases; T3 to attack. |
| Credentials registered before this change have handles that were never displayed. | Operator uses a fresh `HEEL_HOME`. |
| `SYNTHETIC_ONLY` is the only data mode `heel scope create` issues; this design relies on canary accounts holding synthetic data. | Operator decision; not testable in code. |
