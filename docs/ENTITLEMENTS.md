# Entitlement Graph

The entitlement graph is HEEL's static model/import layer for SaaS entitlement abuse. It turns an
operator-authored `ProductModel.v0.1` into typed entitlement edges, then emits normal HEEL
`Affordance` objects that the existing declarative scenario engine can evaluate.

It is not active exploitation. It does not call routes, execute agent tools, fetch exports, create
payments, send webhooks, or touch a live SaaS product. Imported targets still require an explicit
human-created signed `AuthorizationScope` before a rehearsal run, and MCP/REST/agent callers still
cannot create, widen, relax, or mutate scopes.

## Core Types

`heel.entitlements` defines four enum families:

| type | values |
|---|---|
| `Principal` | `anonymous`, `user`, `admin`, `owner`, `service_account`, `integration`, `agent` |
| `Scope` | `tenant`, `workspace`, `org`, `global`, `external_integration` |
| `Resource` | `record`, `export`, `billing_meter`, `coupon`, `trial`, `feature`, `invite`, `webhook`, `oauth_scope`, `support_action`, `agent_tool`, `mcp_connector` |
| `Control` | `entitlement_check`, `tenant_filter`, `rate_limit`, `quota`, `audit_log`, `approval`, `proof_of_uniqueness`, `payment_verification`, `session_concurrency`, `human_review`, `cost_ceiling` |

Each `EntitlementEdge` records the modeled principal, resource, scope, missing or mismatched control,
source ProductModel field, and a stable signal name. `EntitlementGraph.to_affordances()` converts
those edges into scenario-ready affordances.

## Signals

The initial graph emits these signals:

| signal | example condition | scenario bridge |
|---|---|---|
| `plan_mismatch` | `reachable_by_plan: free` for `required_plan: enterprise` | feature/flag affordance |
| `permission_mismatch` | member role grants admin-like permissions | model signal and discovery input |
| `export_without_entitlement` | export has `entitlement_check: missing` | `sc.export.entitlement` |
| `agent_tool_overscope` | `granted_scope != intended_scope` | `sc.agent.overscope` |
| `mcp_connector_overscope` | connector scope exceeds intended scope | agent/MCP affordance |
| `oauth_scope_overbroad` | OAuth app has `scope: all` or granted scopes exceed needed scopes | `sc.integration.oauth` |
| `unmetered_billable_resource` | billable meter lacks server-side accounting or cost ceiling | cost/entitlement affordance |
| `missing_audit_event` | support/admin action has no audit event | `sc.audit.coverage` |
| `tenant_filter_missing` / `tenant_filter_ambiguous` | tenant filter is missing or ambiguous | tenant isolation scenarios |

Query helpers return the main edge families:

```python
from heel.entitlements import EntitlementGraph

graph = EntitlementGraph.from_product_model(product_model)
graph.find_cross_plan_edges()
graph.find_cross_tenant_edges()
graph.find_unmetered_cost_edges()
graph.find_agent_overreach_edges()
graph.find_missing_audit_edges()
affordances = graph.to_affordances()
```

## ProductModel Example

This is sanitized configuration metadata. It names plans, roles, tenants, quotas, and agent tools
without including secrets, real customer records, live payment data, or executable payloads.

```json
{
  "schema_version": "ProductModel.v0.1",
  "product_id": "acme-crm",
  "source": "operator-authored launch review model",
  "generated_at": "2026-06-30T12:00:00Z",
  "environments": ["staging"],
  "tenants": [{"id": "tenant-a"}, {"id": "tenant-b"}],
  "roles": [
    {"id": "member", "granted_permissions": ["invite:create"], "intended_permissions": ["record:read"]},
    {"id": "admin", "granted_permissions": ["invite:create", "support:impersonate"]}
  ],
  "plans": [{"id": "free"}, {"id": "pro"}, {"id": "enterprise"}],
  "features_flags": [
    {"id": "audit_vault", "required_plan": "enterprise", "reachable_by_plan": "free", "gated_by": "client"}
  ],
  "exports": [
    {"id": "bulk_records", "route": "/api/export", "entitlement_check": "missing", "data_class": "canary_records"}
  ],
  "meters": [
    {"id": "llm_tokens", "billable": true, "server_side_accounting": false, "quota": "missing"}
  ],
  "endpoints_routes": [
    {"id": "record_read", "route": "/api/records/{id}", "tenant_filter": "missing"}
  ],
  "integration_oauth_apps": [
    {"id": "crm_sync", "scope": "all", "needed_scopes": ["records:read"]}
  ],
  "support_admin_actions": [
    {"id": "impersonate_user", "required_role": "admin", "reachable_by_role": "member", "audit_logged": false}
  ],
  "agent_tools": [
    {"id": "assistant_export", "tool": "export_all", "granted_scope": "global", "intended_scope": "tenant"}
  ],
  "mcp_connectors": [],
  "coupons_promotions": [],
  "identity_auth_flows": [],
  "billing_objects": [],
  "webhooks": [],
  "data_classes": ["canary_records"],
  "audit_events": [],
  "declared_controls": [],
  "canary_accounts": ["canary-user-001"],
  "safety_notes": ["sanitized model; no live probing, secrets, customer data, or payment data"]
}
```

`target_from_product_model()` now includes entitlement-derived affordances automatically. A run
against `imported:acme-crm` still reports `metric_kind: imported_model_rehearsal`: there is no
planted ground truth, so HEEL does not claim coverage, precision, or calibration for the model.

## Safety Boundary

The graph answers, "what would be suspicious if this model is accurate?" It does not prove the issue
against a live system. Operators can use it before launch, for staging review, or against an existing
product model, but any live validation remains a separate scoped, canary-only decision.

Do not put credentials, customer contents, payment instruments, OAuth secrets, webhook secrets, raw
logs, exports, support transcripts, or exploit payloads into the ProductModel. Use canary ids,
configuration facts, aggregate metadata, and operator-written safety notes only.
