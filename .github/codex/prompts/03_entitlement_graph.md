# Prompt 3 — Add the entitlement graph

Task: Add an EntitlementGraph primitive to Heel.

Why:
Most SaaS abuse is entitlement abuse: a customer gets more feature, data, quota, tenant reach, cost-shift, or agent power than intended.

Create:

- heel/entitlements.py
- tests for entitlement graph construction and queries
- docs/ENTITLEMENTS.md

Core types:

- Principal:
  - anonymous
  - user
  - admin
  - owner
  - service_account
  - integration
  - agent
- Scope:
  - tenant
  - workspace
  - org
  - global
  - external_integration
- Resource:
  - record
  - export
  - billing_meter
  - coupon
  - trial
  - feature
  - invite
  - webhook
  - oauth_scope
  - support_action
  - agent_tool
  - mcp_connector
- Control:
  - entitlement_check
  - tenant_filter
  - rate_limit
  - quota
  - audit_log
  - approval
  - proof_of_uniqueness
  - payment_verification
  - session_concurrency
  - human_review
  - cost_ceiling

Implement:

- EntitlementGraph.from_product_model(product_model)
- graph.find_cross_plan_edges()
- graph.find_cross_tenant_edges()
- graph.find_unmetered_cost_edges()
- graph.find_agent_overreach_edges()
- graph.find_missing_audit_edges()
- graph.to_affordances()

The graph should create affordances that existing declarative scenarios can evaluate.

Add initial abuse signals:

- free/pro/enterprise plan mismatch
- member/admin permission mismatch
- export reachable without entitlement
- agent tool scope wider than intended
- integration OAuth scope broader than needed
- billable meter missing server-side accounting
- support/admin action missing audit event
- tenant filter missing or ambiguous

Tests:

- a Free user reaching an Enterprise feature produces an affordance
- an export without entitlement check produces an affordance
- an agent tool with `granted_scope != intended_scope` maps to existing agent overscope scenario
- an OAuth app with `scope=all` maps to existing integration abuse scenario
- graph output is deterministic

Docs:

- Add examples showing pricing plans, seats, tenants, quotas, and agent tools.
- Make clear this is a model/import layer, not active exploitation.

Acceptance criteria:

- Existing scenario engine can run against affordances derived from EntitlementGraph.
