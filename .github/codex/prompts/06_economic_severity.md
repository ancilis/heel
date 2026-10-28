# Prompt 6 — Add economic severity

Task: Add economic severity scoring alongside security severity.

Why:
Customer abuse is often a business-loss issue, not a CVSS-style vulnerability.

Create:

- heel/economics.py
- docs/ECONOMIC_SEVERITY.md
- tests

Add EconomicImpact model:

- revenue_leakage
- cloud_cost
- support_cost
- data_exposure_value
- trust_safety_cost
- compliance_cost
- abuse_repeatability
- time_to_detection
- friction_cost_of_control
- confidence

Add functions:

- estimate_economic_impact(vector, product_model=None, assumptions=None)
- rank_by_economic_risk(findings)
- recommend_control_bundle(findings, control_candidates)

Use safe defaults if product_model lacks numbers.

Integrate:

- Add optional economic_impact field to AbuseVector serialization or report layer.
- Add CLI flag:
  - heel run ... --economic
  - heel report --run <run_id> --economic
- Do not break existing tests.

Scoring:

- Produce both:
  - qualitative label: low | medium | high | critical
  - estimated monthly range when assumptions exist
- Be honest:
  - show assumptions
  - show unknowns
  - never pretend estimates are precise

Example:
“Estimated monthly abuse exposure: $3k–$18k, driven by unmetered AI-token usage and low time-to-detection.”

Tests:

- usage-meter abuse with token cost assumptions ranks above low-impact coupon issue
- high friction control is not automatically preferred
- missing assumptions produce qualitative score only
- economic score does not replace existing severity score
- output includes assumptions and confidence

Docs:

- Explain why economic severity differs from AppSec severity.
- Add sample assumptions file.

Acceptance criteria:

- Heel can rank findings by business impact without hiding uncertainty.
