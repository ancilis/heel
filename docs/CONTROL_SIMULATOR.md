# Control Simulator

Heel identifies reachable abuse paths; the control simulator helps teams choose likely fixes. It
does not contact a live target and it does not prove a control works. It estimates which controls
would block or reduce a stored or imported finding, then ranks a small bundle for follow-up.

## Run It

```bash
heel controls simulate --vector <vector_id>
heel controls simulate --finding-json finding.json
heel controls simulate --run <run_id>
```

`--vector` and `--run` read findings already stored in Heel's local store. `--finding-json` accepts a
single finding object, or an object with a `finding` field plus optional `affordance_properties`,
`product_model`, or `control_bank` fields. All modes are offline report generation only.

## Proposed Controls vs Verified Controls

A proposed control is a simulator estimate. It is based on the finding fields, scenario category,
affordance properties, optional ProductModel or EntitlementGraph signals, and the local control
bank. Proposed controls include a confidence score, but confidence is capped below certainty because
Heel has not re-run the product with the fix.

A verified control is different: the team has implemented the fix and run a regression or launch
review against an authorized target or imported model. Verification still follows Heel's safety
spine: human-created scope, canary-only evidence, no real exfiltration, no credential/payment abuse,
no spam, and no resource exhaustion.

## Candidate Controls

The default control bank covers:

- `entitlement_check`
- `per_tenant_rate_limit`
- `quota`
- `proof_of_uniqueness`
- `session_concurrency_limit`
- `payment_verification`
- `audit_event`
- `tenant_filter`
- `oauth_scope_minimization`
- `human_approval`
- `agent_tool_scope_reduction`
- `per_action_authorization`
- `cost_ceiling`
- `step_bound`
- `webhook_signature/replay_protection`

Each candidate includes estimated exploitability reduction, estimated friction cost, confidence,
the part of the path it blocks, whether it should become a regression, and whether it preserves the
legitimate customer path.

Ranking is deterministic:

1. Highest estimated abuse reduction.
2. Lowest estimated friction.
3. Preserves legitimate customer path.
4. Highest confidence.
5. Stable control id tie-breaker.

## Example Before And After

Before simulation, a stored finding might only tell the team what was reachable:

```json
{
  "id": "av:run-123:1",
  "scenario_id": "sc.export.entitlement",
  "category": "data_harvesting",
  "affordance_id": "export_records",
  "reproduction": {
    "sample": "canary_only",
    "contained": true,
    "observed": {
      "affordance_properties": {
        "route": "/api/export",
        "entitlement_check": "missing"
      }
    }
  }
}
```

After simulation:

```json
{
  "evidence_level": "proposed_offline_estimate_not_verified_control",
  "verified": false,
  "input": {
    "vector_id": "av:run-123:1",
    "scenario_id": "sc.export.entitlement",
    "category": "data_harvesting",
    "affordance_id": "export_records"
  },
  "recommended_bundle": [
    {
      "control": "entitlement_check",
      "estimated_exploitability_reduction": 0.86,
      "estimated_friction_cost": 0.16,
      "confidence": 0.78,
      "blocks": "the authorization point before bulk export",
      "should_become_regression": true
    },
    {
      "control": "per_tenant_rate_limit",
      "estimated_exploitability_reduction": 0.65,
      "estimated_friction_cost": 0.12,
      "confidence": 0.72,
      "blocks": "repeat export attempts before large-scale collection",
      "should_become_regression": true
    },
    {
      "control": "audit_event",
      "estimated_exploitability_reduction": 0.38,
      "estimated_friction_cost": 0.05,
      "confidence": 0.68,
      "blocks": "post-control monitoring for export attempts and overrides",
      "should_become_regression": true
    }
  ]
}
```

The next step is not to treat this as proof. The next step is to implement the control and add or
run a regression that verifies the canary abuse path no longer succeeds.

## Safety Notes

The simulator is a read-only report layer. It adds no MCP, REST, or agent tool that can create,
widen, relax, or mutate authorization scopes. It does not generate exploit payloads, does not touch
third-party systems, and does not perform data exfiltration, credential abuse, payment abuse, spam,
or resource exhaustion.
