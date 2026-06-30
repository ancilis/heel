# Economic Severity

Economic severity ranks abuse findings by expected business exposure. It sits beside HEEL's existing
security severity; it does not replace AppSec severity, CVSS-style reasoning, or lane discipline.

AppSec severity asks whether a weakness is technically serious: exploitability, data class, isolation
failure, and vulnerability class. Economic severity asks a different operator question: if this
abuse path is reachable and repeatable, what business loss could it create per month, and how
uncertain is that estimate?

Examples:

- A usage-meter weakness may be medium AppSec severity but high economic severity if it allows
  repeatable unmetered AI-token or compute usage.
- A true SSRF or authz bug remains an AppSec handoff even if the estimated monthly business loss is
  small.
- A coupon-stacking issue may be high volume for a consumer product, or low economic impact for a
  narrow enterprise SKU. The assumptions decide the dollar range.

## Safety Boundary

Economic scoring is report-only. It reads existing contained `AbuseVector` findings and optional
operator-created assumptions. It does not probe targets, call third-party systems, exfiltrate data,
create accounts, exercise payments, mutate scopes, or relax limits.

All real-target or imported-target rehearsals still require a human-created signed
`AuthorizationScope`. MCP, REST, and agent surfaces still cannot create, widen, relax, or mutate
scopes.

## CLI Usage

Run normally and ask for economic reporting:

```bash
heel run --scope <scope_id> --target synthetic-saas --economic
```

Add operator assumptions when you want estimated monthly ranges:

```bash
heel report --run <run_id> --economic \
  --economic-assumptions docs/economic_assumptions.example.json
```

Without assumptions, HEEL returns a qualitative label only (`low`, `medium`, `high`, `critical`) and
lists unknowns such as missing monthly event volume or unit cost.

## Output Fields

`heel.economics.EconomicImpact` includes:

- `revenue_leakage`
- `cloud_cost`
- `support_cost`
- `data_exposure_value`
- `trust_safety_cost`
- `compliance_cost`
- `abuse_repeatability`
- `time_to_detection`
- `friction_cost_of_control`
- `confidence`

The report layer also includes:

- `label`: qualitative business-impact label.
- `score`: directional normalized score for ranking, not a precise financial metric.
- `estimated_monthly_range`: low/high monthly exposure when assumptions exist.
- `assumptions`: the specific assumptions used.
- `unknowns`: missing inputs that prevent a dollar estimate or lower confidence.
- `drivers`: short explanation of what is moving the estimate.

Example summary:

```text
Estimated monthly abuse exposure: $3k-$18k, driven by unmetered AI-token usage, cloud cost.
```

## Assumptions Schema

The assumptions file is intentionally simple JSON. Match by `affordances`, `scenarios`, `categories`,
or `defaults`; more specific entries override broader ones.

Supported range values may be a number, `[low, high]`, or `{"low": n, "high": n}`.

Common fields:

- `events_per_month`: estimated monthly abuse attempts or units.
- `unit_revenue_leakage`: lost revenue per event.
- `unit_cloud_cost`: infrastructure or token cost per event.
- `unit_support_cost`: support handling cost per event.
- `unit_data_exposure_value`: directional business value per canary record exposure.
- `unit_trust_safety_cost`: review, moderation, or trust operations cost per event.
- `unit_compliance_cost`: compliance handling cost per event.
- `abuse_repeatability`: normalized 0-1 repeatability.
- `time_to_detection`: normalized 0-1 detection lag risk, where higher means slower detection.
- `friction_cost_of_control`: normalized 0-1 operator/customer friction estimate.
- `confidence`: normalized 0-1 confidence in the assumptions.
- `driver`: short human explanation.

See [economic_assumptions.example.json](economic_assumptions.example.json).

## Control Bundle Ranking

`recommend_control_bundle(findings, control_candidates)` ranks controls by expected monthly risk
reduction after friction cost. A high-friction control is not automatically preferred just because
its exploitability reduction is large.

This is directional planning help, not automated enforcement. Operators should review the assumptions,
unknowns, and confidence before using the ranking to prioritize work.
