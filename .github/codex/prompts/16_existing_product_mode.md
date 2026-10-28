# Prompt 16 — Add existing-product mode

Task: Add explicit existing-product mode to Heel.

Create:

- heel/modes.py
- CLI support:
  - heel run --mode synthetic
  - heel run --mode launch-review
  - heel run --mode staging
  - heel run --mode existing-imported
  - heel run --mode incident-regression
- docs/MODES.md
- tests

Mode behavior:

1. synthetic:
   - current built-in synthetic targets
   - no external product data
2. launch-review:
   - compares before/after ProductModels
   - no live probing by default
3. staging:
   - requires signed scope
   - canary-only
   - stricter limits
4. existing-imported:
   - runs against ProductModel/EntitlementGraph
   - no live probing
   - ideal for mature products
5. incident-regression:
   - runs stored regressions from sanitized incidents/findings

Each mode should define:

- requires_scope
- allows_live_probe
- requires_canary_accounts
- default_rate_limits
- allowed_target_sources
- output emphasis

Tests:

- existing-imported runs on ProductModel without live calls
- staging mode requires scope and canary metadata
- launch-review mode uses before/after ProductModels
- synthetic mode keeps existing behavior
- no mode allows scope mutation
- docs list safety constraints per mode

Acceptance criteria:

- Existing products become a first-class adoption path, not an afterthought.
