# Prompt 9 — Add control simulator

Task: Add a control simulator that estimates which controls would block or reduce an abuse path.

Create:

- heel/control_simulator.py
- CLI:
  - heel controls simulate --vector <vector_id>
  - heel controls simulate --finding-json <file>
  - heel controls simulate --run <run_id>
- docs/CONTROL_SIMULATOR.md
- tests

Behavior:
For a finding, propose and simulate candidate controls:

- entitlement_check
- per_tenant_rate_limit
- quota
- proof_of_uniqueness
- session_concurrency_limit
- payment_verification
- audit_event
- tenant_filter
- oauth_scope_minimization
- human_approval
- agent_tool_scope_reduction
- cost_ceiling
- webhook_signature/replay_protection

Output:

- candidate control
- estimated exploitability reduction
- estimated friction cost
- confidence
- what part of the path it blocks
- whether it should become a regression
- recommended bundle

The simulator should not need to touch a live target.
It should operate on:

- vector fields
- scenario category
- affordance properties
- optional ProductModel / EntitlementGraph
- control bank

Add ranking:

- highest abuse reduction
- lowest friction
- preserves legitimate customer path
- confidence

Tests:

- export abuse recommends entitlement + rate limit + audit
- trial farming recommends proof_of_uniqueness + payment verification
- agent over-scope recommends tool scope reduction + per-action authorization
- cost amplification recommends cost ceiling + step bound
- control bundle ranking is deterministic
- simulator does not claim certainty without evidence

Docs:

- Explain the difference between proposed controls and verified controls.
- Show example before/after report.

Acceptance criteria:

- Heel helps teams choose fixes, not just identify issues.
