# Scenario Pack Authoring

Arceo scenario packs are declarative JSON. Authors describe an abuse pattern, the product
affordance it applies to, the observable success condition, the recommended control, and
the safety limits. The Python evaluator stays unchanged, so community, research,
internal, and incident-derived scenarios can be added without touching code.

Arceo keeps a production-ready spine, beta adapters posture: authored packs are local
artifacts, validated offline, and executed only through canary-only rehearsal with a
human-created signed AuthorizationScope.

## Workflow

Validate a single scenario object or a list:

```bash
arceo scenario validate my_scenarios.json
```

Explain a known scenario before authoring a related pack:

```bash
arceo scenario explain sc.community.csv_formula_injection
```

Validation does not probe products, call live targets, create scopes, relax scopes, or
run network traffic.

## Required Fields

Each authored scenario object must include:

```json
{
  "id": "sc.community.billing.coupon_stacking",
  "category": "license_entitlement",
  "objective": "Customer stacks promotional discounts beyond intended policy",
  "kind": "meter",
  "success_criterion": {"prop": "coupon_stacking", "equals": "allowed"},
  "severity_model": {"likelihood": 0.45, "impact": 0.55},
  "recommended_control": "enforce one active promotion per canary billing account",
  "containment_limits": {
    "canary_only": true,
    "no_live_targets": true,
    "max_examples": 3
  },
  "applies_when": "always"
}
```

Scenario IDs must start with one of:

- `sc.community.`
- `sc.research.`
- `sc.internal.`
- `sc.incident.`

`category` must be one of the taxonomy values in `arceo.contracts.Category`.
`applies_when` may be `always` or `has_agent_surface`.

## Operators

`success_criterion` must use the supported declarative operators:

- `guard_absent`: boolean check for a missing guard.
- `prop_exists`: property presence check, for example `{"prop_exists": "rate_limit"}`.
- `prop` with `equals`: exact observable property equality.
- `prop` with `in`: membership in a literal list.
- `prop` with `exists`: property presence or absence as a boolean.
- `prop_contains`: two-item list `[property, substring]`.
- `prop_neq`: two-item list `[property_a, property_b]` requiring both values to exist and differ.
- `all_of`: non-empty list of criteria, all must match.
- `any_of`: non-empty list of criteria, at least one must match.
- `not`: negates a single nested criterion.
- `semantic`: named semantic family recognized by Arceo.

Unsupported operator names are rejected so a scenario pack cannot smuggle executable
logic or payload instructions into the evaluator.

## Safe Examples

coupon stacking:

```json
{
  "id": "sc.community.billing.coupon_stacking",
  "category": "license_entitlement",
  "objective": "Customer stacks promotional discounts beyond intended policy",
  "kind": "promotion",
  "success_criterion": {"prop": "coupon_stacking", "equals": "allowed"},
  "severity_model": {"likelihood": 0.45, "impact": 0.55},
  "recommended_control": "allow one active promotion per canary billing account",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 3},
  "applies_when": "always"
}
```

trial farming:

```json
{
  "id": "sc.research.identity.trial_farming",
  "category": "identity_account",
  "objective": "Repeated trial creation is possible when durable eligibility checks are absent",
  "kind": "trial",
  "success_criterion": {"prop": "trial_eligibility_check", "equals": "email_only"},
  "severity_model": {"likelihood": 0.5, "impact": 0.45},
  "recommended_control": "deduplicate canary trial eligibility on durable identity signals",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 3},
  "applies_when": "always"
}
```

Export entitlement:

```json
{
  "id": "sc.internal.exports.entitlement_gate",
  "category": "data_harvesting",
  "objective": "Bulk export is available without a server-side entitlement check",
  "kind": "export",
  "success_criterion": {"guard_absent": true},
  "severity_model": {"likelihood": 0.55, "impact": 0.7},
  "recommended_control": "enforce server-side entitlement checks and canary export row caps",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 2},
  "applies_when": "always"
}
```

OAuth over-scope:

```json
{
  "id": "sc.community.integrations.oauth_over_scope",
  "category": "integration_extensibility",
  "objective": "OAuth app receives broader permissions than the declared integration purpose",
  "kind": "oauth_app",
  "success_criterion": {"prop": "scope_width", "equals": "broad"},
  "severity_model": {"likelihood": 0.45, "impact": 0.6},
  "recommended_control": "request least-privilege scopes and review canary app grants",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 2},
  "applies_when": "always"
}
```

agent tool over-scope:

```json
{
  "id": "sc.community.agent.tool_over_scope",
  "category": "agent_mcp_surface",
  "objective": "Agent tool grant exceeds the user intent for the canary task",
  "kind": "agent_tool",
  "success_criterion": {"prop_neq": ["granted_scope", "intended_scope"]},
  "severity_model": {"likelihood": 0.65, "impact": 0.75},
  "recommended_control": "bind tool permissions to caller intent, tenant, and approval state",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 2},
  "applies_when": "has_agent_surface"
}
```

## Rejected Examples

The validator rejects scenarios that include prohibited content or payload-looking strings.
Examples of rejected authoring intent include:

- real credential use or instructions to use real customer credentials.
- real exfiltration or instructions to move production data.
- exploit payload text, exploit tooling, or executable attack commands.
- high-volume scraping instruction or any plan to stress a live service.

A valid scenario should name the business abuse condition and the observable property that
would reveal it in a canary target. It should never include third-party targets, working
exploit details, credential material, production data handling, spam, resource exhaustion,
or instructions to mutate an AuthorizationScope.

## Containment Limits

Every authored scenario must state canary-only containment limits:

- `canary_only`: `true`
- `no_live_targets`: `true`
- one bounded cap such as `max_examples`, `max_probe_calls`, `max_requests`, or `sample_cap`

The cap must be a small integer. Arceo validation is offline and Arceo execution remains
bounded by signed scopes, run budgets, audit logging, and canary data handling.
