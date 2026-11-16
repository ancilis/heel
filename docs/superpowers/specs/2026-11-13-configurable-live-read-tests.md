# Configurable live read tests: E1 assertion semantics

Status: E1 semantics plus E2 runner integration (source only; see "E2" below). Pure functions in `heel/runner/content_assertion.py`, tested by
`tests/test_runner_live_assertions.py`. **Not wired** into the canary contracts, compiler,
executor, API, UI or packaging. This is a leaf of the execution-extensibility workstream,
not its completion: no customer-authored live test can run until E2–E4 are done and accepted.

## Definition record (`heel.live-read-assertion.v1`)

```json
{
  "schema_version": "heel.live-read-assertion.v1",
  "success_witness": {"path": ["meta", "state"], "expected_fixture": "export_ok"},
  "condition": {"kind": "json_scalar_equals_fixture", "path": ["export", "rows", 0, "ssn_hint"],
                "expected_fixture": "secret_value"}
}
```

- `condition` is exactly `{kind: "json_field_present", path}` or
  `{kind: "json_scalar_equals_fixture", path, expected_fixture}`. Every object has fixed field
  names; unknown, missing or (in raw JSON) duplicate keys are rejected. No status, header,
  URL, literal, regex, wildcard, function, script or callback operand exists.
- `path`: a list of 1–8 segments. A string segment is a literal object key: non-empty, ≤128
  characters and ≤256 UTF-8 bytes, no control (`Cc`) or surrogate characters, and not one of
  the reserved `* ** . .. $ @` (rejected so they cannot be mistaken for patterns or traversal).
  An int segment is an exact list index 0–1023 (`bool` is not an int). Root/empty paths are invalid.
- `expected_fixture` is a reference, `[A-Za-z][A-Za-z0-9_-]{0,63}`, never a value or a path.
- Canonical form: sorted keys, no whitespace, UTF-8; ≤4096 bytes. Digest
  `sha256:<hex>` over the canonical bytes. Raw definitions are ≤8192 bytes, strict UTF-8, finite.

API: `parse_live_read_assertion(bytes)`, `validate_live_read_assertion(dict)` →
`LiveReadAssertion`; `canonical_live_read_assertion`, `live_read_assertion_digest`. Errors are
`LiveAssertionError` carrying only one closed code (`LIVE_READ_DEFINITION_ERRORS`), raised without
a chained cause, so input text is never echoed.

## Local expected values

`resolve_local_fixtures(assertion, fixtures)` takes an exact local `dict` of reference → JSON
scalar and snapshots only the referenced values before any response is evaluated. The result is
bound to the definition digest; using it with another definition is `fixture_unbound`. Valid values:
`null`, `bool`, `str` (≤2048 UTF-8 bytes, no surrogates), `int` within ±(2⁶³−1), finite `float`.
Missing, invalid or non-`dict` input makes the expectations unavailable, so every observation and
pair is `inconclusive`, never false/blocked/observed. Values never appear in `repr` or any output.
Expected values are never cloud configuration. E2 must seal immutable local input references
and bind the definition digest into a versioned signed manifest; E1 does not provide that gate.

## One response: `observe_live_read`

Order, first match wins; every result is a closed `state`/`reason` plus booleans:

1. Method other than exact `GET` (including `HEAD`): unknown.
2. Unbound or unavailable fixtures: unknown.
3. Status not an int 100–599, body not `bytes`, body >256 KiB: unknown.
4. Empty body: `empty_denial` at 401/402/403/404, otherwise unknown.
5. Strict JSON: strict UTF-8 (no BOM), no duplicate keys, no `NaN`/`Infinity`/overflowing
   numbers, no surrogate strings or keys, depth ≤32, ≤10 000 nodes; must be an object.
6. The existing, unchanged `is_denial_envelope` and then `is_ambiguous_message`: unknown at **any**
   status, overriding the condition.
7. Non-2xx with a non-empty body: unknown, even if the condition would match.
8. Success witness: the path must resolve to a scalar strictly equal to its fixture. Otherwise unknown.
9. Condition path: each container above the last segment must exist with the right type (a string
   segment reads only an object, an int only a list). A missing parent or wrong type is unknown. At
   the last segment a key/index that is not there is **absent**; a JSON `null` there is **present**.
   - `json_field_present`: present → true, absent → false.
   - `json_scalar_equals_fixture`: absent → false; an object/array value → unknown; otherwise strict equality.

Strict equality never coerces: `bool` is never a number, a string never equals a number or
boolean, strings compare by exact code points (no case folding or normalization). Numbers
compare by exact decimal value of the JSON text (`1`, `1.0`, `1e0` equal; `1.0000000000000000001`
≠ `1`). A float fixture means its shortest round-trip text. A body number with no exact decimal
representation is malformed.

Presence or equality is an observation of that configured field only, never a generic
protected-content claim.

## A pair: `evaluate_live_read_pair`

Inputs: an already captured `control` response (authenticated / higher plan) and `restricted`
response (anonymous / lower plan) of the same route. The module sends no traffic.

- `role_policy` must be `anonymous_authenticated_read` or `plan_entitlement_read`. Nothing else
  (no tenant, role, ownership or lifecycle pairs).
- Positive control: status exactly 200, witness matched, condition true. Otherwise `inconclusive`.
- Restricted condition true → `observed`; condition false with a valid 2xx success body → `blocked`;
  empty 401/402/403/404 (the existing bounded denial semantics, only behind a valid positive
  control) → `blocked`; anything unknown → `inconclusive`.
- Status alone never produces `observed`. Output is only `outcome`, a reason from
  `LIVE_READ_PAIR_REASONS`, `positive_control` and `restricted_condition`.

## Unchanged

`protected_content`, `is_denial_envelope` and `is_ambiguous_message` behave exactly as before
(additions only). The two existing catalog checks keep their current semantics.

## Next integration (not in E1)

- E2: signed configured instances. Several instances per primitive, binding route, role pair,
  definition digest, revision and sealed local fixture references before approval. Reuse
  transport, attempts and containment. Regression replays keep the exact definition.
- E3: workspace-private authoring and delivery through the existing control plane.
- E4: a new runner release. The released rc5 artifacts are immutable and are not rebuilt or
  relabelled. This module is in the open-core release source set, so frozen-release parity
  checks are expected to differ until E4 produces new-version artifacts.

## E2: signed configured instances in the paired runner (source only)

E2 binds the E1 definition into distinct closed versions; every v1 record and validator is
unchanged and refuses them (`validate_test_manifest`, `validate_approval_projection`,
`validate_canary_findings` reject the new schemas and any new field).

| Record | Schema | Change from v1 |
|---|---|---|
| Manifest | `heel.test-manifest.v2` | `scenarios` → `test_instances`; each action adds `test_instance_id`; compiler/engine `2`/`2` exactly |
| Approval projection | `heel.approval-manifest-projection.v3` | as manifest, instances show `local_input_refs` + `local_input_binding_digest` (digest of random handles), never handles or values |
| Findings | `heel.canary-findings-projection.v2` | `scenario_results` → `test_results`, engine `2` |

A test instance (1–4 per plan) freezes: `test_instance_id` (`lti_` + 32 hex, caller/E3 supplied,
stable across replays), catalog primitive `scenario_id` (`anonymous_authenticated_read` or
`plan_entitlement_read`, which is also the E1 role policy), `source` (`source_scenario_id`,
`source_revision`), inventoried `method`/`route_template` (no placeholders in E2), the canonical
E1 `assertion` and its `assertion_digest`, and `local_inputs` = exactly one
`{fixture_ref, input_handle_id}` per referenced fixture. Actions are exactly two per instance in
catalog role order (restricted, then control), ordinals contiguous; the contract checks each
action against its instance. Two instances may share primitive and route and are evaluated
independently on their own signed action ordinals. Runner-local code dispatches by schema
(`validate_runner_*`); cloud transport validators remain v1-only until E3.

Local values: `RunnerStore.create_live_input(name, value, vault)` stores one JSON scalar in the
OS vault (Keychain/Secret Service backends only) under a new random handle and makes it the
name's `current`; earlier handles stay `retained` until `revoke_live_input` (record revoked
first, then vault delete). Records hold handle, name, backend, state, selection and the bound
workspace/project/environment/runner; never a value or digest. Compilation resolves a name to
its current handle once; approvals and replays carry handles only. CLI: `heel runner input
add --name N --backend keychain|secret-service [--secret-fd FD]` (else TTY prompt), `revoke
--handle H`, `list`.

Execution reuses `LocalCanaryExecutor` (same grant, gate, attempts, budgets, transport,
containment, redaction). After activation and credentials, each instance's frozen handles are
loaded once; a missing/revoked/unreadable handle sends no request for that instance (containment
`action_rejected`, detail `local_input_unavailable`) and its result is inconclusive
`local_input_unavailable`. Responses of configured actions are held in memory only for
`evaluate_live_read_pair`; no catalog predicate or plan comparator is consulted. Each result
reports outcome, one closed `reason`, `positive_control` (`established`/`not_established`),
`restricted_condition` (`true`/`false`/`not_observed`), per-action observations and redacted
evidence refs; the contract enforces outcome/reason/finding consistency.

Regression: `add_saved_regression(run_id=..., test_instance_id=...)` stores a closed
`heel.runner-configured-regression.v1` record holding the exact instance (definition, revision,
handles). `CanaryCompiler.compile_configured_replay` recompiles it with the frozen handles
(never names); a revoked handle refuses. Replay still requires queueing, fresh approval and a
new one-shot grant; `record_regression_result` yields pass/fail/inconclusive as for v1.

Not in E2: browser authoring and authenticated delivery of definitions and v3 projection
submission/claim/upload through the control plane (E3); disclosure of v2 findings (E3); new
release artifacts (E4). Containment events keep schema v1: an event's signed action ordinal maps
to exactly one instance in the signed manifest.

## E3: browser authoring and authenticated delivery (source only)

- **Authoring.** A workspace-private custom revision may carry one `heel.custom-live-test.v1`
  (primitive, GET/HEAD, literal imported route, canonical E1 assertion) through
  `heel.custom-scenario.v2`. It is stored beside the immutable revision (`workspace_custom_live_tests`,
  migration 35); the static definition keeps its static meaning. Parameterized routes are refused
  with `live_test_route_unsupported`. The dashboard form needs no JSON; references are names only.
- **Request.** `POST …/runner-context-bindings/{rcb}/configured-plan-requests`
  (`heel.configured-plan-request.v1`) names exact private revisions (or one observed instance of a
  terminal configured run to replay). The control plane resolves them in the authenticated
  workspace, generates instance IDs and a single-use nonce, and freezes the snapshot
  (`canary_configured_plan_requests`; one open per binding; `GET`/`cancel` for the browser).
- **Runner.** Over its PoP claim chain the paired runner sends `heel.runner-configured-plan-sync.v1`
  (runner runtime state v7 registers this one operation) and receives the snapshot. It reports
  readiness for exactly the snapshot's instances (route, non-anonymous roles, named local inputs,
  or for a replay the frozen run and handles) as closed states, then compiles the v2 manifest/v3
  projection and submits `heel.runner-configured-approval-projection-submit.v1` with the nonce. The
  control plane admits it only if every signed instance equals the frozen snapshot. Old runners
  never claim the request; the dashboard says so.
- **Approval.** A v3 projection is approved only with `heel.canary-execution-approval.v2` carrying a
  `heel.configured-condition-review.v1` that restates every instance (source revision, primitive,
  route, role pair, request count, condition, reference names), the operator-supplied plan labels
  and the request ceiling; a v1 (digest-only) approval is refused (`configured_review_required`).
- **Results.** Disclosure tables admit `heel.canary-findings-projection.v2` (lossless rebuild,
  migration 36). The dashboard shows per-instance outcome, closed reason, control/restricted
  states, containment notes and local evidence references; inconclusive is stated as neither pass
  nor failure. "Save and replay" requests a configured regression of one observed instance; the
  runner saves it from its own verified finals and recompiles with the frozen handles.
- **Local values.** `heel runner input add --type text|number|boolean|null|json` (default `json`,
  the legacy entry); text needs no quotes; every kind ends in the strict decoder; values come only
  from the hidden prompt or `--secret-fd`.
