# Heel Modes

Heel modes make the adoption path explicit. Synthetic demos, launch review, staging
rehearsal, mature existing-product imports, and incident regressions all use the same
safety spine: no scope mutation, no credential use, no exploit payloads, no real
exfiltration, and no live production probing by default.

Every non-static run that touches a target still requires a human-created signed
AuthorizationScope. The MCP, REST, and agent-callable surfaces cannot create, widen,
or relax scopes.

## Mode Summary

| Mode | requires_scope | allows_live_probe | requires_canary_accounts | default_rate_limits | allowed_target_sources | output emphasis |
|---|---:|---:|---:|---|---|---|
| `synthetic` | true | false | false | `max_requests=200`, `max_concurrency=8`, `backoff=true` | built-in synthetic target | synthetic self-consistency backtest; no external product data |
| `launch-review` | false | false | false | `max_requests=0`, `max_concurrency=0`, `backoff=true` | before/after ProductModels | static ProductModel diff; no live probing by default |
| `staging` | true | false | true | `max_requests=20`, `max_concurrency=2`, `backoff=true` | staging ProductModel, canary staging target | canary-only staging rehearsal with stricter signed-scope limits |
| `existing-imported` | true | false | false | `max_requests=80`, `max_concurrency=4`, `backoff=true` | ProductModel, EntitlementGraph | mature products via imported ProductModel/EntitlementGraph; no live probing |
| `incident-regression` | true | false | true | `max_requests=50`, `max_concurrency=3`, `backoff=true` | stored abuse regressions, sanitized incidents, stored findings | canary-only rerun of stored incident/finding regressions |

## Synthetic

`heel run --mode synthetic --scope <scope_id> --target synthetic-saas`

Synthetic mode is the existing built-in target path. It uses no external product data
and remains the safest local demo and backtest path.

## Launch Review

`heel run --mode launch-review --before before.json --after after.json`

Launch-review mode compares two sanitized ProductModels. It is static by design: no
live probing, no target scope required, and no network calls. If the launch gate blocks,
the command returns the same non-zero status as `heel launch-review`.

## Staging

`heel run --mode staging --scope <scope_id> --target staging_model.json`

Staging mode is for canary-only rehearsal with stricter signed-scope limits. The scope
must already exist, must allow the resolved target, and must be at least as strict as
the mode defaults. The ProductModel or CLI must identify canary accounts.

## Existing Imported

`heel run --mode existing-imported --scope <scope_id> --target product_model.json`

Existing-imported mode is the first-class path for mature products. Operators provide
a sanitized ProductModel/EntitlementGraph instead of a live adapter. Heel registers an
in-process imported target, requires a signed scope for the resolved `imported:<id>`
target, and runs model-only rehearsal with no live probing.

## Incident Regression

`heel run --mode incident-regression --scope <scope_id> --target synthetic-saas`

Incident-regression mode reruns stored abuse regressions created from sanitized
incidents or previous findings. It uses the same signed scope and target allowlist
gate as normal runs, and outputs regression results rather than a new general report.

## Safety Constraints

- `allows_live_probe` is false for every mode in the stdlib core.
- `requires_scope` is true for every target-running mode except static `launch-review`.
- `requires_canary_accounts` is true for `staging` and `incident-regression`.
- `default_rate_limits` are mode defaults, not a permission to relax a signed scope.
- `allowed_target_sources` describe accepted local inputs; they do not authorize new targets.
- output emphasis is descriptive only and never changes the authorization gate.
- no scope mutation tools exist for any mode.
