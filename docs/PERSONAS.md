# Abuse Personas

HEEL's opportunistic-human agent uses **customer incentive models**, not criminal personas.
They describe why an ordinary customer, agency, integration owner, or builder might game a normal
SaaS affordance when the product makes that path easy.

Personas do not create authorization, widen scope, attack third-party systems, or produce working
exploit payloads. Every rehearsal example is contained and canary-only. For staging, imported, or
production-like targets, the normal rule still applies: a human-created `AuthorizationScope` must
already exist before HEEL can run.

## Built-In Personas

Each persona defines motivation, sophistication, patience, risk tolerance, target affordance types,
preferred abuse chains, deterring controls, and canary-only rehearsal examples.

| persona | incentive model | primary affordances |
|---|---|---|
| `coupon_stacker` | reduce checkout or subscription cost with visible promotions | promo, coupon, checkout endpoint |
| `seat_sharer` | avoid per-seat pricing by sharing one paid seat | seats, sessions, concurrency |
| `agency_reseller` | serve multiple downstream clients from one account or plan | seats, region pricing, trial/account pooling |
| `data_broker` | build or enrich datasets from bulk and enumerable paths | exports, records, data pipelines |
| `trial_farmer` | keep receiving trial value by cycling eligibility markers | trial, signup |
| `integration_overreacher` | install integrations with broader access than needed | OAuth apps, MCP connectors, tools |
| `support_pressure_user` | obtain workflow exceptions through support or urgency | recovery, support/admin actions |
| `marketplace_reputation_gamer` | improve visible trust-economy standing | reviews, referrals |
| `usage_meter_optimizer` | reduce billable usage by timing or resetting meters | usage meters, rate windows |
| `ai_cost_amplifier` | shift AI-token/tool-call cost onto the product | agent tools, token-cost surfaces |
| `agent_wrapper_builder` | wrap agent/MCP surfaces into another product | agent tools, MCP connectors |

## Matching Rules

A persona emits evidence only when both conditions are true:

- The persona has the motivation and capability for that rule: motivation tags match, and
  sophistication, patience, and risk tolerance clear the rule threshold.
- The target exposes a matching observable affordance, such as `stackable=True` on a checkout route,
  `sharing_detection=none` on seats, `identity_check=email_only` on a trial, or
  `multi_step=unbounded` on an agent tool.

When an adversarial finding already exists for the same affordance, HEEL keeps that better-calibrated
finding as primary and attaches persona evidence to it. Persona-only findings are ranked by
persona severity, reachability, and stable scenario id. This lets reports explain both what is weak
and which customer archetype would try it without inflating calibrated adversarial severity.

## Report Evidence

Persona evidence is plain English and lives under `reproduction.persona_evidence` or, for
persona-primary findings, `reproduction.evidence`.

Example shape:

```json
{
  "persona_id": "data_broker",
  "motivation": "Acquire large or enumerable datasets for resale, benchmarking, or enrichment.",
  "why_this_customer_would_try_it": "A dataset-motivated customer would start with the highest-volume export path.",
  "affordance_match": "bulk export is reachable without an entitlement guard",
  "preferred_abuse_chain": "bulk export",
  "matched_affordance": "export_records"
}
```

All persona findings still use `sample: "canary_only"` and `contained: true`.

## Add a Custom Persona

Custom personas are ordinary Python data. Keep rules declarative, observable, and canary-only:

```python
from heel.contracts import Category
from heel.profiles import AbusePersona, PersonaRule

partner_plan_gamer = AbusePersona(
    id="partner_plan_gamer",
    motivation="Find partner-plan edges that grant more entitlement than the account should have.",
    motivation_tags=("plan_arbitrage", "entitlement_gain"),
    sophistication=0.55,
    patience=0.65,
    risk_tolerance=0.45,
    target_affordance_types=("flag", "meter"),
    preferred_abuse_chains=("partner entitlement drift",),
    deterring_controls=("server-side entitlement checks", "partner-plan audit", "plan-change regression tests"),
    canary_rehearsal_examples=("Use a canary partner account and stop after checking entitlement state.",),
    rules=(
        PersonaRule(
            id="partner_flag_drift",
            affordance_kind="flag",
            criterion={"prop": "gated_by", "equals": "client"},
            category=Category.LICENSE_ENTITLEMENT,
            preferred_chain="partner entitlement drift",
            motivation_tags=("plan_arbitrage", "entitlement_gain"),
            required_sophistication=0.35,
            required_patience=0.45,
            required_risk_tolerance=0.30,
            impact=0.50,
            recommended_control="gate partner entitlements on the server and audit plan transitions",
            affordance_match="partner-facing feature flag is gated by the client",
            why="A partner-plan customer would try a canary plan transition if entitlement state is client-visible.",
        ),
    ),
)
```

Pass it to `run_opportunistic(target, [partner_plan_gamer], log, run_id)` in tests or in an
authorized adapter harness. Do not add rules that require real data extraction, real payment actions,
credential abuse, spam, resource exhaustion, or third-party probing.
