# Heel self-serve discovery contract (C2 server scope) — finite schemas, states, authz, budgets, tests

Date: 2026-10-19. Branch `feat/self-serve-product`. Author: Claude Fable 5.1, fresh independent
design review session (T3SR). **Specification only; nothing here exists in code.** This document
is the exact server-side contract that task **C2** of
`2026-10-19-customer-ready-self-serve-launch.md` §7.1 implements, and nothing else. It narrows
the draft C2 row, which Astra judged an under-defined "giant mixed API/contracts/quota" surface.
C2 MUST NOT start until Astra accepts this document. Identity/credential routes are **not** in
C2 (they are C5, gated by the §2.4 custody decision).

Evidence tags: **CONFIRMED** (`file:line` at `f6a79ee`) or **INFERRED** (with confirming action).
Normative words: **MUST**, **MUST NOT**, **MAY**. Every schema is a closed object: unknown keys
are rejected, and the forbidden key sets of `heel/canary_contracts.py` (`_FORBIDDEN_APPROVAL_KEYS`,
CONFIRMED `:42-48`) apply to every new schema plus `password`, `secret`, `token`, `cookie`,
`authorization`, `url`, `query`, `body`.

## 1. Scope of C2 (exhaustive)

| In C2 | Not in C2 |
|---|---|
| `heel.discovery-authorization.v1` create/read/revoke routes and table | any route that receives a credential (C5) |
| `discovery_rounds` and `discovery_round_reports` tables, the bounded auto-issue check inside the existing projection-submit path, and the recorded-provenance check of §4a | the discovery engine, transport profile, frontier extraction from bodies (C3, runner side) |
| v2 `plan` object variant `plan_kind: discovery` in `canary_contracts.py` | `login_exchange` action type (C5) and its compiler rule |
| `route_inventories` provenance/state columns and the `GET …/route-inventory` view | the managed executor, pairing actor, egress (C4) |
| plan requests with user selection ⊆ snapshot (bridge spec §4 rows 2–3, 5–6, unchanged) | UI (C7) |
| one `CANARY_RUNS` unit per authorization with idempotency and refund rule | pricing, new meters |

Allowed files (exhaustive): `heel/saas/http_api.py`, `heel/saas/runner_contexts.py`,
`heel/saas/canary_runs.py`, `heel/saas/migrate.py`, `heel/canary_contracts.py`,
`tests/test_canary_http.py`, `tests/test_canary_migrations.py`, `tests/test_canary_contracts.py`,
`tests/test_canary_quota.py`; mechanical regeneration of the three download artifacts because
`canary_contracts.py` is shipped. No runner file, no Worker file (the Worker allowlist rows for
the two new routes are a one-line C7/C4 follow-up, listed in §7).

## 2. Schemas (closed objects, exact)

### 2.1 `heel.discovery-authorization.v1` (request body, ≤2 KiB)

```
{ schema_version: "heel.discovery-authorization.v1",
  environment_id: id,
  identities_authorized: [label]        # 0–2 labels, printable ASCII 1–32, customer's own words
  login_exchange_authorized: bool,      # MUST be false in C2 (C5 may set true); true is rejected until C5 ships
  acknowledgement: "I authorize Heel to send up to 100 GET/HEAD requests to this origin" }
```

### 2.2 Stored authorization row (`discovery_authorizations`, migration 32)

```
authorization_id TEXT PK, workspace_id, project_id, environment_id (FK verified env),
actor_user_id, actor_role ∈ {owner, admin},
bound_json  = {max_rounds: 5, max_actions_per_round: 20, max_requests: 100,
               max_total_execution_ms: 120000, max_wall_ms_per_round: 60000,
               max_body_bytes: 2097152}                     # constants, not client-settable; TTL is expires_at_ms
seed_digest TEXT (sha256 of canonical DISCOVERY_SEED_PATHS, constant exported by canary_contracts),
identities_json, login_exchange_authorized INTEGER,
authorization_digest TEXT = canonical_digest(all fields above),
reservation_id TEXT (ledger), idempotency_key TEXT UNIQUE per workspace,
state TEXT ∈ {open, done, failed, revoked, expired},
rounds_issued INTEGER DEFAULT 0, actions_issued INTEGER DEFAULT 0,        # server-counted at issue (enforcement)
execution_ms_used INTEGER DEFAULT 0,                                      # server-measured Σ(terminal_at − issued_at)
requests_completed INTEGER DEFAULT 0, bytes_received INTEGER DEFAULT 0,  # runner-reported, informational only
created_at_ms, expires_at_ms = created_at_ms + 900000, closed_at_ms, close_reason TEXT
UNIQUE(environment_id) WHERE state='open'     # one open authorization per environment
```

Read view `heel.discovery-authorization-view.v1` returns the row minus `reservation_id` and
`idempotency_key`, plus `actions_remaining`, `rounds_remaining`, `execution_ms_remaining`.

### 2.3 `discovery_rounds` (migration 32)

```
round_id TEXT PK, authorization_id FK, round INTEGER 1..5, run_id (nullable until issued),
grant_id (nullable), projection_id, projection_digest, frontier_digest,
actions INTEGER 1..20, cumulative_requests_before INTEGER, wall_budget_ms INTEGER,
state ∈ {projected, issued, terminal, refused}, refuse_reason TEXT,
issued_at_ms, terminal_at_ms, requests_completed INTEGER, bytes_received INTEGER, created_at_ms, closed_at_ms
UNIQUE(authorization_id, round)
```

### 2.4 v2 `plan` object variant (`canary_contracts.py`, `validate_approval_projection` v2)

Existing variant (bridge spec §4.1) unchanged. New closed variant:

```
plan = { plan_kind: "discovery", authorization_id: id, authorization_digest: hash,
         round: 1..5, frontier_digest: hash, cumulative_requests_before: 0..99,
         transport_profile: "discovery", action_count: 1..20,
         sources: [{ordinal: 0..19, round: 0..4, source_ordinal: 0..19}] }   # round 0 = seed list; see §4 step 9a
```

Rules: `action_count == len(actions)`; every action `method ∈ {GET, HEAD}`; every
`route_template` passes `normalize_route_template` (CONFIRMED `openapi_routes.py:18-45`); for
`round == 1`, `frontier_digest == seed_digest` and the action templates are exactly the 12 seeds
(digest check, order-independent); no `fixture_bindings` values beyond `bindings_sha256`
(CONFIRMED forbidden keys). A `plan_kind: discovery` projection on a binding with an open
**scan** plan request is rejected (`plan_kind_mismatch`), and vice versa.

### 2.5 `route_inventories` additive columns (migration 32)

`routes_json` rows become `{method, route_template, provenance: [{kind, round, source_ordinal,
status_code}], first_seen_ms, state ∈ {candidate, selected, excluded}, excluded_reason?}`;
`provenance.kind ∈ {customer_url, imported_openapi, well_known_spec, robots, sitemap, html_link,
script_src, js_literal, html_link_auth, js_literal_auth, redirect_location, discovered_openapi}`;
`excluded_reason ∈ {method_not_allowed, off_origin, side_effect_risk, static_asset, truncated}`.
Row cap 200 (existing reject-never-truncate for import, CONFIRMED launch spec §7.1); a discovery
write over 200 keeps the first 200 by phase order and sets `truncated_count`. No URL, query,
body or header value may appear in `routes_json` (byte test, §6).

### 2.6 `heel.discovery-round-report.v1` (runner → server, on the existing result path; ≤64 KiB)

```
{ schema_version: "heel.discovery-round-report.v1", authorization_id, round, run_id, grant_id,
  candidates: [ { method: GET|HEAD, route_template, provenance_kind, source_ordinal: 0..19,
                  status_code: 100..599 } ]      # ≤200 entries, templates only, no URL/query/body/header value
  excluded_count, truncated_count, bytes_received, report_digest, signing_key_id, signature_b64 }
```

Signed by the runner key like every other projection (`sign_envelope`). Stored in
`discovery_round_reports` (migration 32): `report_id PK, authorization_id FK, round, run_id,
report_digest, candidates_json, created_at_ms, UNIQUE(authorization_id, round)`. The report is
the **only** thing a later round may draw its actions from (§4a). It is immutable once written;
a second report for the same round is `report_consumed`. Forbidden keys and the §2.5 byte rules
apply.

**Trust boundary, stated plainly.** Target response bodies stay on the executor and never reach
the server, so the server cannot verify that a candidate was really present in a page. What the
server **does** enforce is the recorded relationship: every later-round action must be a
candidate that the same authorization's earlier round recorded in its signed report, with an
immutable `source_ordinal` naming the action that produced it, inside the method/host/budget
bounds. A compromised executor could record a fabricated same-origin GET/HEAD candidate; it still
could not change host, method, round count, action count or execution time, and every request
it sends is one-shot, signed-scope and containment-logged exactly as today. No test in this
document claims response-content proof.

**Source ordinal bound (C2R1 F1).** The generic schema range stays `source_ordinal: 0..19`, but a
stored candidate's ordinal must name an action the originating round actually issued:
`source_ordinal < discovery_rounds.actions` of that round (12 for round 1, up to 20 later, so 19
stays valid on a 20-action round). A report with any candidate outside that range is refused
`invalid_discovery_report` before report storage, inventory merge or round settlement (the whole
result transaction rolls back; a corrected retry on the same chain is accepted). This validates
recorded lineage only, never body contents, and does not assume an ordinal equals completion
order: a partial or zero-request round may still report candidates for any issued ordinal.

## 3. Routes and authorization (all `/v1/workspaces/{ws}/projects/{prj}/…`)

| Route | Actor | Checks | Response |
|---|---|---|---|
| `POST …/environments/{env}/discovery-authorizations` | owner/admin, recent-auth, same-origin (`_recent_owner_admin_context`, CONFIRMED `http_api.py:2279-2301`), `Idempotency-Key` required (`ca1-[0-9a-f]{64}`, CONFIRMED `:133,2030-2037`) | environment `verified` and not revoked; no open authorization for the environment; quota `CANARY_RUNS` reserve 1 in the same transaction (`ledger.reserve_in_transaction`, CONFIRMED `ledger.py:157`); same key → same row (idempotent), different body under same key → 409 `idempotency_conflict` | 201 view |
| `GET …/environments/{env}/discovery-authorizations/{id}` | owner/admin/member, same-origin | project scope | 200 view |
| `POST …/environments/{env}/discovery-authorizations/{id}/revoke` | owner/admin, recent-auth | state `open` | 200 view (`state: revoked`); any issued round's run receives cloud stop (existing path, ≤5 s) |
| `GET …/environments/{env}/route-inventory` | member+, same-origin | — | rows with provenance/state, `truncated_count`, `inventory_digest` |
| projection submit (`…/contexts/{rcb}/approval-projections`, existing PoP route) | paired runner key | §4 round check when `plan.plan_kind == "discovery"` | existing responses plus `round_state` (including the round grant's current `grant_status`, §4 step 0) |

No new runner-facing route is added in C2: the round grant is issued on the existing
submit path and claimed on the existing claim path (CONFIRMED `http_api.py:850,978,1367-1444`).

## 4. Bounded auto-issue (server check, in one transaction with the projection submit)

When a submitted v2 projection has `plan.plan_kind == "discovery"`, the server MUST, in the
same transaction and in this order, refuse with the closed reason on the first failure.
**Authentication and ownership come before everything, including replay**: a replayed digest is
never answered until the caller has proven it is the owning runner of the owning project.

A. **Authenticate and scope (unconditional, existing code paths).** The request is on the
   existing PoP route with a valid signature, nonce and sequence from an **active** runner key
   with the `runner_claim` capability (existing `runner_auth` checks, CONFIRMED
   `http_api.py:1367-1444`); the binding `{rcb}` belongs to this `{ws}/{prj}` and is bound to
   this runner (existing `_operational_context_matches` check); the authorization row named by
   `plan.authorization_id` exists **and** has the same `workspace_id`, `project_id` and
   `environment_id` as the binding → else the existing 401/403/404 (`authorization_unknown` for a
   row in another project, indistinguishable from non-existence). A revoked or rotated-out runner
   key fails here regardless of digest.
0. **Replay, only after A.** If a `discovery_rounds` row exists for `(authorization_id,
   plan.round)` **in this project**: same `projection_digest` and state ≠ `refused` → return that
   row's current state and, if `issued`, the same grant (idempotent replay, no counter change, no
   further checks); different `projection_digest` → `round_consumed`. **C2R1 F3:** this fresh
   (new-nonce) semantic replay first applies a due expiry close, then includes the grant only
   while the grant row is `issued` and unexpired **and** the authorization is `open` and
   unexpired; `round_state.grant_status` reports the grant's current status (`issued`, `claimed`,
   `revoked`, `terminal`, or `expired` once its expiry passed), so a revoked or expired round is
   replayed without usable grant data and never as resurrected authority. An **exact raw PoP
   retry** of the original request is different: the durable receipt/cursor protocol answers it
   byte-for-byte from history (which may contain the old grant bytes and `state: issued`), and is
   unchanged; those historical bytes confer nothing, because claim, the live gate and the
   authorization close are evaluated on current rows (claim returns 204, a claimed round is
   stopped `cloud_stop`). A grant is returned only to
   the runner key named in it (`runner_binding.runner_key_id`, CONFIRMED grant schema); a
   different active runner of the **same** project presenting the same digest receives
   `round_consumed`, never the grant. Only when no row exists continue.
1. (merged into A; kept as the reason code `authorization_unknown`)
2. `state == open` → else `authorization_closed`
2a. **C2R1 F2:** the recorded authorizer (`actor_user_id`) still holds a current `owner` or
   `admin` membership of the workspace (owner→admin or admin→owner stays valid) → else
   `authorization_closed`; the refusing transaction rolls back, and a separate transaction
   re-derives the membership fact and closes the row `revoked`/`close_reason: revoked` with
   `revoked_by: "membership:<actor_user_id>"` (a non-secret system marker; the original
   `actor_user_id`, `actor_role` and `authorization_digest` stay immutable). Quota follows §5: a
   zero-issued authorization is refunded, a consumed unit stays consumed. Logout or session expiry
   is not membership loss.
3. `now < expires_at_ms` → else `authorization_expired` (row → `expired`, refund rule §5)
4. `plan.authorization_digest == authorization_digest` → else `authorization_digest_mismatch`
5. `plan.round == rounds_issued + 1` → else `round_out_of_order`
6. previous round (if any) `state == terminal` **and** its `discovery_round_reports` row exists → else `previous_round_active` / `previous_report_missing`
7. `plan.cumulative_requests_before == actions_issued` → else `cumulative_mismatch`
8. `actions_issued + action_count ≤ 100` and `round ≤ 5` and `execution_ms_used + 10 000 ≤ 120 000` → else `bound_exceeded` (row → `done`, `close_reason: budget`); the round's grant wall budget is `min(60 000, 120 000 − execution_ms_used)`
9. round 1: `frontier_digest == seed_digest` and the action templates are exactly the 12 seeds, each `source.source_ordinal` bounds-checked against the 12-entry seed list before it is looked up (12..19 are schema-valid but name no seed) → else `seed_mismatch`
9a. **round > 1, recorded provenance (§4a):** every action's `(method, route_template)` with its `fixture_bindings`-free template and the projection's `source: {round, source_ordinal}` for that action must equal a candidate entry in a stored report of the same authorization with `report.round < plan.round`, and `plan.frontier_digest` must equal the canonical digest of exactly those referenced candidate entries as stored → else `candidate_not_recorded` (route never recorded), `source_ordinal_mismatch` (recorded candidate with a different source, **or** a stored candidate whose ordinal is not below its recorded source round's `actions`, including a legacy or corrupted stored row, which is refused and never edited or re-signed; C2R1 F1), or `frontier_digest_mismatch`
10. every action GET/HEAD on `egress.hostname == environment hostname` → else `action_out_of_scope`
11. kill switch generation current → else `kill_switch`

### 4a. What the recorded-provenance check proves and does not prove

It proves that the server never grants a later-round action that the same authorization's own
signed earlier report did not record, that the source ordinal is immutable, and that the
frontier the executor froze is byte-identical to the recorded candidates it names. It does not
prove the candidate was really in a response body (§2.6 trust boundary). The v2 `plan` object
therefore gains `sources: [{ordinal, round, source_ordinal}]` (≤20 entries) so the relationship
is signed into the projection.

On success the server writes the `discovery_rounds` row (`issued`), issues the grant exactly
as `approve` does today (`canary_runs.approve`, CONFIRMED `:636`) with `approval_actor` =
the authorization's actor and `approval_reason: "discovery_authorization:<id>"`, increments
`rounds_issued`, and returns the grant on the existing claim path. The grant budgets are the
round's: `maximum_requests = action_count ≤ 20`, wall budget as in step 8, expiry ≤10 min (contract
rule, CONFIRMED `canary_contracts.py` grant expiry), and increments `actions_issued +=
action_count` **at issue time** (enforcement counter; a run that sends fewer requests does not
give actions back). When the run reaches terminal (result path, cloud stop, or the existing
reaper at grant expiry), the server sets `terminal_at_ms`, adds `execution_ms_used +=
terminal_at_ms − issued_at_ms` (server clock, durable), records runner-reported
`requests_completed`/`bytes_received` as informational, and marks the round `terminal`; if
`rounds_issued == 5`, `actions_issued ≥ 100` or `execution_ms_used ≥ 110 000` the authorization
becomes `done`. A refused submit never changes `rounds_issued` or `actions_issued`.

**Exactly-once aggregation.** The terminal transition is one conditional statement
(`UPDATE discovery_rounds SET state='terminal', terminal_at_ms=? WHERE round_id=? AND
state='issued'`); the authorization counters are updated in the same transaction **only if that
statement changed one row**. A duplicate or concurrent result/stop/reaper report for the same
round finds `state='terminal'`, adds nothing, and returns the stored terminal state. The round
report of §2.6 is written under the same guard (`UNIQUE(authorization_id, round)`) after the same
step-A authentication and ownership checks: an **identical** retry (same `report_digest`, same
runner key) returns the stored report acknowledgement with no counter change; only a report with
a **different** `report_digest` for an already-recorded round is `report_consumed`.

**Expiry and revoke are rechecked on every attempt gate, not only at submit.** The executor
already rechecks the live gate before each socket opens (CONFIRMED bridge spec §4 row 8,
`execution.py:651-713`) and heartbeats every 0.25 s; the server's heartbeat/permit handler MUST
answer `stop` (`cloud_stop`, reason `authorization_expired` or `authorization_revoked`) whenever
the authorization is no longer `open` or `now ≥ expires_at_ms`, so an in-flight round stops
within the existing ≤5 s bound even though its grant is still unexpired. The reaper applies the
same check to issued rounds with no heartbeat.

**No widening**: the server never accepts an action whose host differs from the environment, a
method other than GET/HEAD, a round beyond 5, or a cumulative count beyond 100, regardless of
what any target page contained. The frontier content is the executor's (C3) responsibility;
the server bounds its size and provenance digest only.

## 5. Quota and idempotency

- Exactly one `Meter.CANARY_RUNS` unit per authorization, reserved at create (§3). Retried
  create with the same `Idempotency-Key` returns the same row and charges once
  (`test_discovery_authorization_reserves_one_unit_for_all_rounds_under_retry`).
- Refund (`ledger.refund_consumed_in_transaction`, CONFIRMED `ledger.py:269`) only when the
  authorization closes with `rounds_issued == 0` (expired or revoked before any round). Once a
  round has issued, the unit is consumed even if later rounds are refused.
- Round submits are idempotent by `(authorization_id, round)` uniqueness plus the existing
  `projection_id`/`projection_digest` uniqueness (CONFIRMED `canary_runs.py:482-500`); a replayed
  identical projection returns the existing round state, a different projection for the same
  round is `round_consumed`.
- Free plan `CANARY_RUNS=10` (launch spec §9) therefore allows 10 discovery authorizations
  **or** scan runs per period in total; the UI shows the shared counter (C7).

## 6. Named tests (red-first; all in C2's allowed files)

| Test | Asserts |
|---|---|
| `tests/test_canary_contracts.py::test_discovery_plan_variant_is_closed_get_head_only_and_round1_matches_seed_digest` | §2.4 rules, unknown key rejected, POST action rejected, round 1 digest |
| `tests/test_canary_contracts.py::test_inventory_rows_with_provenance_reject_urls_queries_bodies_and_forbidden_keys` | §2.5 byte-level: an e-mail, a `?token=`, a JWT and a 32-hex id in any row field are rejected |
| `tests/test_canary_migrations.py::test_migration_32_adds_discovery_tables_and_inventory_columns_additively` | forward migration on the launch fixture DB; existing rows readable |
| `tests/test_canary_http.py::test_discovery_authorization_requires_verified_environment_owner_admin_recent_auth_same_origin_and_idempotency_key` | §3 row 1 authz matrix (member 403, stale auth 403, cross-origin 403, missing key 400) |
| `tests/test_canary_http.py::test_one_open_discovery_authorization_per_environment` | second create 409 `authorization_open` |
| `tests/test_canary_http.py::test_discovery_round_projection_is_auto_issued_only_within_the_recorded_bound_and_refused_after_it` | rounds 1–5 issue; after the fifth round issues the authorization closes `done`/`budget` at that round's settlement; a sixth-round projection fails contract validation (`round ∈ 1..5`, no sixth grant) and, once closed, any further submit is `authorization_closed` (or `round_consumed` for a replayed round number); `bound_exceeded` names only the valid-shape step-8 counter refusals; 21 actions → contract failure; issued 95 + 10 → `bound_exceeded` with state `done`; a round whose runner reports 3 completed of 20 issued still consumes 20 |
| `tests/test_canary_http.py::test_discovery_global_execution_budget_is_server_measured_and_refuses_when_under_ten_seconds_remain` | execution_ms_used 115 000 → `bound_exceeded`; round grant wall budget equals `min(60 000, remaining)`; reaper-terminated round counts its full grant window |
| `tests/test_canary_http.py::test_discovery_round_actions_must_be_recorded_candidates_of_an_earlier_round_of_the_same_authorization` | round 1 with a non-seed path → `seed_mismatch`; round 2 action never present in any stored report → `candidate_not_recorded`; recorded route with a forged `source_ordinal` → `source_ordinal_mismatch`; frontier digest over a different subset → `frontier_digest_mismatch`; another authorization's digest → `authorization_digest_mismatch`; off-host action → `action_out_of_scope`; round 2 before round 1's report exists → `previous_report_missing`. The test states that it proves the recorded relationship, not body content |
| `tests/test_canary_http.py::test_discovery_round_submit_replays_identical_round_before_ordering_checks_and_refuses_a_different_projection_for_a_consumed_round` | identical re-submit by the same runner of an issued round returns the same grant with unchanged counters; different digest → `round_consumed`; neither path yields `round_out_of_order` |
| `tests/test_canary_http.py::test_discovery_round_replay_requires_active_runner_pop_and_project_ownership_and_never_returns_another_projects_grant` | a runner in project B submitting project A's exact issued `projection_digest` and `authorization_id` → 404 `authorization_unknown`, no grant bytes; a revoked key with the same digest → 401; a second active runner of project A with the same digest → `round_consumed`, no grant; identical round-report retry → stored ack, counters unchanged; different `report_digest` → `report_consumed` |
| `tests/test_canary_http.py::test_discovery_round_terminal_aggregation_applies_exactly_once_under_concurrent_duplicate_reports` | two concurrent result reports plus a reaper tick → one `execution_ms_used` increment, one report row, same returned state |
| `tests/test_canary_http.py::test_discovery_authorization_expiry_or_revoke_stops_an_in_flight_round_at_the_next_heartbeat_or_attempt_gate` | expiry during an issued round → heartbeat answers `stop`, executor stub records `cloud_stop` before its next socket |
| `tests/test_canary_http.py::test_discovery_rounds_are_strictly_sequential_and_previous_round_must_be_terminal` | `round_out_of_order`, `previous_round_active`, `cumulative_mismatch` |
| `tests/test_canary_http.py::test_discovery_authorization_expiry_and_revoke_close_it_and_stop_the_active_round_within_five_seconds` | expiry → `expired`; revoke → cloud stop observed by the runner stub ≤5 s (reuses `test_canary_stop.py` harness) |
| `tests/test_canary_http.py::test_discovery_plan_kind_and_scan_plan_request_cannot_be_mixed_on_one_binding` | `plan_kind_mismatch` both directions |
| `tests/test_canary_http.py::test_identities_inventory_discovery_and_evidence_are_project_scoped` | cross-project read/write 404 (existing isolation harness) |
| `tests/test_canary_quota.py::test_discovery_authorization_reserves_one_unit_for_all_rounds_under_retry` | one reservation across 5 rounds and a retried create |
| `tests/test_canary_quota.py::test_discovery_authorization_refunds_only_when_no_round_issued` | refund on revoke-before-round, no refund after round 1 |
| `tests/test_canary_http.py::test_discovery_route_inventory_view_shows_provenance_states_and_truncated_count_without_values` | 201 rows written → 200 kept, `truncated_count: 1`, no value bytes |

Gate for C2: all tests above green plus the four bridge-spec §4.1 binding tests, the existing
`tests/test_canary_*` files unchanged in outcome, full suite under the shared `full-suite.lock`
on Python 3.11 with true exits recorded, artifacts regenerated, DCO + `Co-Authored-By: Claude
Opus 5.5 <noreply@anthropic.com>`, fresh Fable review.

## 7. Follow-ups this contract creates for other tasks (not C2)

- C3: executor builds the round-1 manifest from `DISCOVERY_SEED_PATHS` (imported from
  `canary_contracts`), emits the signed `heel.discovery-round-report.v1` at round end, selects
  the next frontier **only from its own recorded reports** and signs `sources` into the plan,
  computes `frontier_digest` exactly as the server does, applies the §3.3 classifier and deny
  list, discards bodies at round end.
- C4: the managed executor polls the existing claim path; Worker allowlist rows for the two
  new browser routes (`discovery-authorizations`, `route-inventory` GET) and their body caps.
- C5: `login_exchange_authorized: true` acceptance, the `login_exchange` action type, and the
  compiler rule that it is the only non-GET/HEAD action.
- C7: copy for `discovery.authorize`, counters, `discovery.partial` reasons.

## 8. Open items (INFERRED, with confirming action)

| Item | Confirming action |
|---|---|
| The existing `approve` path can be called with a service actor without a `hostname_retype` (needed for auto-issue) | C2 Opus reads `canary_runs.approve` (`:636-879`) and either reuses it with an internal actor or extracts `_issue_grant`; the review confirms no new human-approval bypass for scan runs |
| Current latest migration number is 31 (bridge spec) so this is 32 | C2 Opus reads `heel/saas/migrate.py` at task start and renumbers if needed |
| `runner_contexts.submit_projection_from_runner_in_transaction` is the single submit entry for v2 | CONFIRMED `canary_runs.py:456`; C2 extends it, no second entry |

## 9. Implementation deltas recorded by C2 (2026-10-19, Opus; after Astra D1/D2 and C2D decisions)

The sections above are kept as the accepted design text. These are the factual deltas the C2
implementation made, each authorized in `ASTRA-C2-deviation-decisions.md` or
`ASTRA-C2D-decisions.md` (C2D design `C2D-design.md`):

- **Migration number.** The repository was at migration 29 with no T3a-s substrate, so C2's one
  additive migration is **30** (`self_serve_discovery_and_plan_requests`). It *creates*
  `route_inventories` (with the §2.5 provenance/state shape and `truncated_count`),
  `discovery_authorizations`, `discovery_rounds`, `discovery_round_reports` and
  `canary_plan_requests`; nothing is altered. The §6 test named
  `test_migration_32_adds_discovery_tables_and_inventory_columns_additively` is implemented as
  `tests/test_canary_migrations.py::test_migration_30_adds_discovery_tables_and_inventory_columns_additively`
  (plus an atomic-failure and a direct-construction parity test). No schema 32 exists.
- **Plan-request link.** The plan request ↔ projection link lives on `canary_plan_requests`
  (`approval_id`, `run_id`, `projection_digest`, all UNIQUE) instead of a new column on
  `canary_runner_context_projection_links`, whose frozen v16 definition is verified at startup.
- **`discovery_rounds.state='refused'` is reserved and unused in C2.** Refusals are returned
  (`heel.discovery-error.v1`), never stored, so a transient refusal cannot burn its round number.
  A closing refusal (`authorization_expired`, `bound_exceeded` from the step-8 counters) creates no
  projection, run or round; its close is committed in a separate transaction that re-derives it
  from server state, and is durable across a reopened database.
- **Round 1 seed membership** is the server's step 9 (`seed_mismatch`); the contract validator
  binds the round-1 frontier digest, `action_count == 12`, `cumulative_requests_before == 0` and
  `source.round == 0`.
- **A projection asking for more than the server-computed round budget** (wall time above
  `min(60 000, remaining)`, body bytes above the recorded bound) is refused `bound_exceeded`
  without closing the authorization; only the step-8 counter conditions close it.
- **Quota (D3).** One ledger reservation per authorization, consumed in the transaction that
  issues round 1 (row-count and ledger-proof guarded) and refunded only when the authorization
  closes with `rounds_issued == 0`. Round grants carry the parent reference
  `dauth:<authorization_id>:r<round>` (never a ledger id) and a deterministic `ca1-` key; round runs
  have `reservation_id NULL` and `quota_state 'unreserved'`, so no per-run consume/refund/
  compensation path touches the ledger. There is **no platform-fault compensation after a round
  issued** in C2 (free-launch quota policy, not a price). C7 must display the parent
  authorization's consumed unit; a round's `unreserved` state does not mean discovery was free.
  A refunded authorization's `Idempotency-Key` is never replayed (409 `idempotency_conflict`).
  Expiry and round settlement are also reaper-driven in `expire_and_reconcile`.
- **Body profile (D4).** `SCAN_BODY_BYTES = 256 KiB` and `DISCOVERY_BODY_BYTES = 2 MiB` are
  exported. v1 records and scan plans keep 256 KiB; a v2 projection whose signed plan is
  `plan_kind: discovery` with `transport_profile: discovery` may carry up to 2 MiB, and its
  round grant is `heel.execution-grant.v2` with `budget_profile: discovery`. Scan approvals still
  issue byte-compatible v1 grants; `claim()` refuses any grant/projection profile mismatch. The
  recorded bound's `max_body_bytes` is checked at issue. This prepares contracts only: 2 MiB target
  reads need **C3** (manifest v2 + discovery transport profile; C3's allowed files are expanded to
  `heel/canary_contracts.py` and `tests/test_canary_contracts.py`), **C4** (executor wiring) and
  **C7** (browser validators/views for v2 ids).
- **C2R1 role-loss policy (F2) and its limits.** Live owner/admin membership of the recorded
  authorizer is required before each **new** round issue only (§4 step 2a). An already-issued
  grant is not stopped automatically by role loss: it keeps its bounded expiry (≤10 min, ≤ the
  authorization TTL), the live gate, explicit revoke by any current owner/admin and the kill
  switch. The demoted or removed actor can no longer revoke (they fail the existing
  owner/admin check); a current different owner/admin can. A semantic replay of an already-issued
  round is not a new issue and is governed by step 0, not 2a.
- **Not built in C2:** inventory PUT/OpenAPI import, the §3.3 label-liveness report (labels in the
  runner plan-request claim are validated, not stored), the four §5.1 identity/evidence routes.
