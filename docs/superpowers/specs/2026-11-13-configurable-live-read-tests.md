# Configurable live read tests: E1 assertion semantics

Status: E1 source only. Pure functions in `heel/runner/content_assertion.py`, tested by
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
