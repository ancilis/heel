# Launch Review

Launch review is HEEL's pre-release wedge for SaaS abuse rehearsal. It compares two sanitized
`ProductModel.v0.1` files and focuses the review on product surfaces that were added or changed
for a launch.

This is static model review, not live probing. It does not call routes, run agent tools, fetch
exports, touch payment flows, or inspect customer data. Any later live or staging validation still
requires a human-created signed `AuthorizationScope`, and findings must stay canary-only.

## Run A Review

Compare two ProductModel files:

```bash
heel launch-review --before product_model_before.json --after product_model_after.json
```

Or compare a ProductModel changed in a git range:

```bash
heel launch-review --diff main..feature/pricing-v2
```

The CLI prints a short human summary followed by a JSON report. Exit codes are:

- `0`: pass
- `1`: warn
- `2`: block

## What It Checks

Launch review identifies added or changed surfaces across endpoints, exports, billing meters,
plans, coupons, feature flags, OAuth apps, webhooks, support/admin actions, agent tools, MCP
connectors, tenants, data classes, and declared controls.

It then reports:

- changed surfaces
- new abuse affordances
- high-risk missing controls
- recommended controls
- suggested abuse regression tests
- launch gate status: `pass`, `warn`, or `block`

The launch gate blocks only high-confidence, high-impact, reachable abuse paths. Lower-confidence
or lower-impact issues warn so the launch team can decide whether to fix before release or track
with explicit acceptance.

## Example PR Comment

```text
Blocker: new bulk export reachable by trial users without tenant quota.
```

That comment should map to a JSON report item such as:

```json
{
  "surface_type": "exports",
  "surface_id": "bulk_records",
  "risk": "export_without_tenant_quota",
  "severity": "block",
  "control": "tenant quota"
}
```

Use suggested regression tests as safe, declarative checks for the product team. Do not turn launch
review output into exploit playbooks or live attack instructions.
