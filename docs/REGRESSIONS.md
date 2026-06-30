# Abuse Regression Testing

Abuse regression tests are unit tests for product abuse controls. When a HEEL run finds a reachable
abuse path, you can save the finding as a reusable regression and re-run it in CI, staging, or an
imported ProductModel rehearsal to check whether the recommended control is now blocking the path.

Regressions do not store weaponized reproduction steps. A regression stores the finding's scenario,
target affordance pattern, declarative success criterion, recommended control, expected status,
source run id, creation time, and safety flags. Re-runs report whether the abuse was previously
reachable and is currently reachable, blocked, or inconclusive, plus a short evidence summary.

## Safety Model

Regression runs use the same safety spine as ordinary HEEL runs:

- A human-created, HMAC-signed `AuthorizationScope` is required.
- The target must be in the signed scope allowlist.
- MCP, REST, agent, and regression CLI flows cannot create, widen, relax, or mutate scopes.
- Findings remain contained and canary-only.
- Containment log entries are written for the underlying run and the regression result.
- True software vulnerabilities remain AppSec handoffs; pure jailbreaks remain model red-team
  handoffs.

## Create A Regression

Run HEEL against a scoped target, then save a finding by vector id:

```bash
heel run --scope scope-123 --target staging-saas
heel findings --run run-abc
heel regress add --run run-abc --vector av:run-abc:7 --name free_trial_serial_signup
```

New regressions default to `expected_status: blocked`, because the normal workflow is to add a
control and then keep the abuse path blocked permanently.

## List And Export

```bash
heel regress list
heel regress export --format json
```

The JSON export contains regression specs and stored regression results. It is safe to persist as a
CI artifact because it omits reproduction steps and secrets.

## Run In CI Or Staging

Create the scope out of band as a human operator, then have CI consume only that existing scope:

```bash
heel scope create --target staging-saas --operator security-reviewer --confirm
heel regress run --scope scope-123 --target staging-saas
```

For imported ProductModel rehearsals, authorize the converted target id and pass the sanitized JSON
model as the target argument:

```bash
heel import validate product_model.json
heel scope create --target imported:acme-crm --operator security-reviewer --confirm
heel regress run --scope scope-123 --target product_model.json
```

The run fails closed if the scope is missing, expired, tampered with, or does not allow the target.
CI should treat `current_status: still_reachable` as a failing abuse-control regression unless that
regression was intentionally recorded with `expected_status: still_reachable`.

## Result Fields

Each regression run result includes:

- `previously_reachable`: always true for regressions created from findings.
- `current_status`: `still_reachable`, `blocked`, or `inconclusive`.
- `control_likely`: `absent`, `present`, or `unknown`.
- `evidence_summary`: a non-weaponized summary of the canary-only observation.
- `matches_expected`: whether the current status equals the stored expected status.

Use the evidence summary to route the work. Use the original HEEL finding and recommended control to
decide the remediation; do not turn regression artifacts into exploit playbooks.
