# Incident-To-Scenario Workflow

HEEL can turn a sanitized abuse incident into a reusable scenario draft and a canary-only regression
draft. This lets Trust & Safety, Support, Product, and Security convert lessons from real abuse into
permanent abuse tests without storing customer-identifying data, secrets, credentials, tokens, raw
exploit payloads, or weaponized instructions.

HEEL's status remains **production-ready spine, beta adapters**. Incident import is part of the
spine's learning loop: it accepts only sanitized, operator-reviewed records and writes local drafts
for human review before anything can be added to the active scenario library.

## Safety Model

Incident commands are offline and local. They do not contact live targets, create scopes, widen
scopes, mutate scope files, run probes, or enable scenarios automatically.

The importer rejects records unless `prohibited_fields_removed_confirmed` is exactly `true`. It also
rejects secret-looking fields, token-like values, email addresses, customer-identifying evidence
fields, and raw payload markers. Treat the importer as a second check, not the primary sanitizer:
the incident owner must remove sensitive and weaponized detail before the file reaches HEEL.

Generated regressions are review artifacts only. They carry canary-only safety flags and expected
blocked status, and they are stored under the local HEEL data directory before any operator copies a
scenario into `heel/scenarios_lib/`.

## Roles

Trust & Safety can translate abuse operations into scenario families, expected blocked outcomes, and
controls that reduce repeat abuse.

Support can capture policy-gaming workflows, escalation bypasses, refund loops, and manual override
gaps using sanitized ticket metadata.

Product can preserve product-affordance lessons, such as promotion abuse, export abuse, entitlement
gaps, or workflow incentives that made abuse economically attractive.

Security can review the drafts for data-handling risk, scope boundaries, canary-only evidence, and
whether a case belongs in HEEL or should be handed off to appsec or model red-team work.

## Schema

An incident JSON object must include:

- `incident_id`
- `summary`
- `product_area`
- `affected_surfaces`
- `customer_type`
- `abuse_goal`
- `steps_observed`
- `business_impact`
- `controls_missing`
- `controls_added`
- `data_classes`
- `sanitized_evidence`
- `prohibited_fields_removed_confirmed`
- `source`
- `safety_notes`

`source` must be one of `manual`, `ticket`, `postmortem`, or `trust_safety`.

## Commands

Import a sanitized incident:

```bash
heel incident import examples/incidents/coupon_stacking.json
```

Create a local scenario draft:

```bash
heel incident draft-scenario inc-coupon-stacking-001
```

Create a local canary-only regression draft:

```bash
heel incident add-regression inc-coupon-stacking-001
```

Print exactly what would be added after review:

```bash
heel incident review inc-coupon-stacking-001
```

Drafts are written under `HEEL_HOME/drafts/`, for example
`.heel/drafts/inc-coupon-stacking-001.scenario.json` and
`.heel/drafts/inc-coupon-stacking-001.regression.json`.

## Safe Example

The repository includes `examples/incidents/coupon_stacking.json`. It uses a canary account,
sanitized ticket metadata, and aggregate business impact. It does not include customer names,
emails, account ids, payment details, credentials, tokens, payloads, or reproduction steps against a
real system.

Keep future examples at the same level of abstraction: enough context to map the abuse pattern to a
declarative scenario and recommended control, but not enough detail to identify a customer or repeat
the abuse against any live target.
