# Prompt 5 — Add launch review mode

Task: Add a launch-review mode that focuses Heel on changed product surfaces.

Create:

- heel/launch_review.py
- CLI:
  - heel launch-review --before <product_model_before.json> --after <product_model_after.json>
  - heel launch-review --diff main..feature/pricing-v2
- docs/LAUNCH_REVIEW.md
- tests

Behavior:

- Compare two ProductModel files.
- Identify added/changed:
  - endpoints
  - exports
  - billing meters
  - plans
  - coupons
  - feature flags
  - OAuth scopes
  - webhooks
  - support/admin actions
  - agent tools
  - MCP connectors
  - tenant/data controls
- Produce a LaunchReview report:
  - changed surfaces
  - new abuse affordances
  - high-risk missing controls
  - recommended controls
  - suggested regression tests
  - launch gate status: pass | warn | block
- The launch gate should block only on high-confidence, high-impact, reachable abuse paths.
- The output should be JSON plus human-readable CLI text.

Safety:

- This mode operates on imported models/diffs, not live probing.
- If it runs any scenario evaluation, it must use canary-only contained evaluation.
- For live/staging target runs, require signed scope.

Tests:

- new export route without entitlement check -> block
- new coupon with stackable=true and no redemption limit -> warn/block depending severity
- new OAuth scope=all -> warn/block
- new agent tool with granted_scope wider than intended -> block
- no risky changes -> pass
- generated suggested regressions match changed surfaces

Docs:

- Position launch-review as the pre-release wedge.
- Include PR comment example:
  “Blocker: new bulk export reachable by trial users without tenant quota.”

Acceptance criteria:

- Users can compare before/after product models and get an abuse-focused launch review.
