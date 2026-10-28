# Prompt 11 — Add incident-to-scenario

Task: Add an incident-to-scenario workflow that converts a sanitized abuse incident into a reusable Heel scenario and regression.

Create:

- heel/incident.py
- CLI:
  - heel incident import <incident.json>
  - heel incident draft-scenario <incident_id>
  - heel incident add-regression <incident_id>
- docs/INCIDENTS.md
- examples/incidents/
- tests

Incident schema:

- incident_id
- summary
- product_area
- affected_surfaces
- customer_type
- abuse_goal
- steps_observed
- business_impact
- controls_missing
- controls_added
- data_classes
- sanitized_evidence
- prohibited_fields_removed_confirmed: true
- source: manual | ticket | postmortem | trust_safety
- safety_notes

Behavior:

- Validate incident has been sanitized.
- Reject secrets, real PII, credentials, tokens, raw exploit payloads, or customer-identifying data.
- Map incident to:
  - scenario category
  - persona
  - affordance kind
  - declarative success criterion draft
  - recommended control draft
  - regression draft
- Do not auto-enable a scenario without operator confirmation.
- Store generated scenario under a local draft path first:
  - heel/scenarios_lib/drafts/<incident_id>.json
  - or .heel/drafts/<incident_id>.json
- Provide a review command that prints exactly what would be added.

Tests:

- sanitized coupon-stacking incident becomes license_entitlement scenario draft
- export scraping incident becomes data_harvesting scenario draft
- support workflow gaming becomes function/trust/compliance scenario draft
- secrets-looking evidence is rejected
- generated scenario is declarative JSON
- generated regression is canary-only
- no incident command can create/widen scope

Docs:

- Explain how Trust & Safety, Support, Product, and Security can turn incidents into permanent abuse tests.
- Include a safe sanitized example.

Acceptance criteria:

- Heel can learn from real incidents without storing sensitive data or weaponized details.
