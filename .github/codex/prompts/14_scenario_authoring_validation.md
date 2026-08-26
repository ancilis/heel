# Prompt 14 — Add scenario-pack authoring guide and validation

Task: Make scenario-pack authoring a first-class workflow.

Create:

- docs/SCENARIO_AUTHORING.md
- heel/scenario_validate.py
- CLI:
  - heel scenario validate <file.json>
  - heel scenario explain <scenario_id>
- tests

Validator should check:

- required fields
- valid category
- valid applies_when
- valid affordance kind
- success_criterion only uses supported declarative operators
- no prohibited content
- no exploit payloads
- recommended_control present
- severity_model includes likelihood and impact
- scenario ID namespace:
  - sc.community.*
  - sc.research.*
  - sc.internal.*
  - sc.incident.*
- canary-only containment limits

Docs:

- Explain declarative operators:
  - guard_absent
  - prop_exists
  - prop equals/in/exists
  - prop_contains
  - prop_neq
  - all_of
  - any_of
  - not
  - semantic
- Include safe examples:
  - coupon stacking
  - trial farming
  - export entitlement
  - OAuth over-scope
  - agent tool over-scope
- Include unsafe examples that validator rejects:
  - real credential use
  - real exfiltration
  - exploit payload
  - high-volume scraping instruction

Tests:

- valid scenario passes
- missing control fails
- unknown operator fails
- unsafe payload-looking string fails
- scenario explain prints objective, category, controls, and safety limits

Acceptance criteria:

- Community/operator scenario packs can be authored safely without touching Python code.
