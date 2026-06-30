# Prompt 7 — Expand opportunistic abuse personas

Task: Make opportunistic-human profiles a first-class abuse persona system.

Current state:
Heel already has an opportunistic-human class and motivation-gated profiles. Expand it into a richer persona library.

Create/update:

- heel/profiles.py
- heel/agents_human.py
- docs/PERSONAS.md
- tests

Add personas:

- coupon_stacker
- seat_sharer
- agency_reseller
- data_broker
- trial_farmer
- integration_overreacher
- support_pressure_user
- marketplace_reputation_gamer
- usage_meter_optimizer
- ai_cost_amplifier
- agent_wrapper_builder

Each persona should define:

- motivation
- sophistication
- patience
- risk_tolerance
- target affordance types
- preferred abuse chains
- controls that deter them
- examples of contained/canary-only rehearsal behavior

Behavior:

- Personas should add findings only when motivation and affordance match.
- They must not override better-calibrated adversarial findings for the same affordance unless there is a clear ranking rule.
- They should produce plain-English “why this customer would try it” evidence.

Tests:

- seat_sharer flags seats/concurrency issues
- coupon_stacker flags promo/coupon stacking
- data_broker prioritizes exports and enumeration
- trial_farmer prioritizes weak signup/trial eligibility
- ai_cost_amplifier prioritizes unbounded agent/tool/token cost surfaces
- persona findings are canary-only
- disabling opportunistic agent class removes persona findings
- all persona outputs are deterministic

Docs:

- Emphasize these are customer incentive models, not criminal personas.
- Show how to add a custom persona.

Acceptance criteria:

- Heel can explain not just “what is weak,” but “which motivated customer archetype would game it.”
