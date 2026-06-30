# Adapter Contract

HEEL adapters start with a product model, not a live connection. The first contract is
`ProductModel.v0.1`: an operator-authored JSON document that describes the observable affordances
of a SaaS product using sanitized metadata. Validation and conversion are local, stdlib-only, and
make no network calls.

During conversion, HEEL also builds an entitlement graph from the same sanitized metadata. The graph
derives scenario-ready affordances for plan, role, tenant, quota, audit, OAuth, and agent-tool scope
mismatches. See [ENTITLEMENTS.md](ENTITLEMENTS.md).

The purpose is abuse rehearsal before launch or against an existing product model while preserving
HEEL's safety boundary:

- Imported models are rehearsal inputs, not permission to probe a system.
- Every imported target run still requires a human-created, HMAC-signed `AuthorizationScope`.
- MCP, REST, and agent callers cannot create, widen, relax, or mutate scopes.
- Findings are predicted, contained, canary-only leads. They are not working exploits.

## ProductModel.v0.1

Use the canonical snake-case fields below. Unknown fields are allowed only when they contain
sanitized metadata and no secret-looking keys or values.

```json
{
  "schema_version": "ProductModel.v0.1",
  "product_id": "acme-crm",
  "source": "operator-authored launch review model",
  "generated_at": "2026-06-30T12:00:00Z",
  "environments": ["staging"],
  "tenants": [],
  "roles": [],
  "plans": [],
  "meters": [],
  "coupons_promotions": [],
  "features_flags": [],
  "endpoints_routes": [
    {"id": "records_export", "route": "/api/export", "entitlement_check": "missing"}
  ],
  "exports": [
    {"id": "bulk_records", "route": "/api/export", "guard_present": false, "data_class": "canary_records"}
  ],
  "identity_auth_flows": [],
  "billing_objects": [],
  "integration_oauth_apps": [],
  "webhooks": [],
  "support_admin_actions": [],
  "agent_tools": [],
  "mcp_connectors": [],
  "data_classes": ["canary_records"],
  "audit_events": [],
  "declared_controls": [],
  "canary_accounts": ["canary-user-001"],
  "safety_notes": ["sanitized canary-only staging model; no secrets or customer data"]
}
```

The converted target id is `imported:<product_id>`, for example `imported:acme-crm`. A human must
authorize that exact target id out of band before it can run:

```bash
heel scope create --target imported:acme-crm --operator you --confirm
```

## Safe Modeling

Model product affordances, not credentials or customer contents. A good ProductModel answers:

- What environments are represented: `production`, `staging`, `sandbox`, or `synthetic`.
- Which tenants, roles, plans, meters, promotions, flags, routes, exports, auth flows, billing
  objects, integrations, webhooks, support/admin actions, agent tools, and MCP connectors exist.
- Which data classes are touched, using class names such as `canary_records`, `billing_metadata`, or
  `support_ticket_metadata`, not raw records.
- Which controls are declared, such as entitlement checks, tenant filters, replay protection, rate
  limits, audit logging, and human approval gates.
- Which canary accounts and canary tenants are safe for rehearsal.
- What safety assumptions the operator made.

Use stable identifiers and configuration facts. Do not copy request bodies, response bodies,
access tokens, cookies, private keys, production customer records, or payment instruments.

## Source Mapping

OpenAPI or route catalogs can map to `endpoints_routes` and `exports`. Include route templates,
methods, documented status, entitlement expectations, rate-limit metadata, and tenant-filter
metadata. Do not include real headers, bearer tokens, examples with real customer data, or raw
responses.

Pricing and plan config can map to `plans`, `meters`, `coupons_promotions`, and `billing_objects`.
Model plan names, entitlement names, meter reset windows, coupon stacking rules, trial boundaries,
and billing object types. Do not import live payment methods, card details, customer invoices, or
processor API keys.

Auth roles and identity flows can map to `roles` and `identity_auth_flows`. Include role names,
permission group names, MFA/reset/recovery control metadata, and signup verification policy. Do not
include passwords, password hashes, recovery tokens, session cookies, or real user emails unless they
are canary accounts.

Stripe-like billing config can map to `billing_objects`, `plans`, `meters`, and
`coupons_promotions`. Use product ids, price ids, entitlement names, and sanitized test-mode object
references. Never import live secret keys, webhook signing secrets, payment instruments, or full
customer billing records.

Feature-flag config can map to `features_flags`. Include flag names, server/client gating metadata,
rollout environment, and declared entitlement dependencies. Do not import SDK keys or user targeting
lists containing real customer data.

MCP manifests and agent-tool catalogs can map to `agent_tools` and `mcp_connectors`. Include tool
names, intended scope, granted scope, context-isolation metadata, approval requirements, and whether
tools can act on untrusted content. Do not include connector credentials, OAuth refresh tokens, tool
secrets, or prompt/jailbreak payloads.

Telemetry can map to `audit_events`, `declared_controls`, and aggregate affordance properties.
Use counts, class names, and sanitized canary observations. Do not import logs with raw payloads,
customer identifiers, authentication material, message contents, or exported files.

## Data To Exclude

Never import:

- API keys, OAuth client secrets, refresh/access tokens, cookies, private keys, signing secrets, or
  authorization headers.
- Real customer records, raw PII, support transcripts, message bodies, files, exports, invoices,
  payment instruments, passwords, password hashes, recovery links, or session data.
- Working exploit payloads, jailbreak strings, third-party target details, spam content, credential
  material, or resource-exhaustion recipes.
- Anything whose disclosure would let an agent authenticate, exfiltrate, bill, spam, or attack.

The validator rejects common secret-looking keys and values. Treat that as a safety rail, not a
complete data-loss-prevention system. Operators are responsible for sanitizing the model before it is
given to HEEL.

## Canary And Environment Use

Prefer `staging`, `sandbox`, or `synthetic` models. If the model represents production-like
configuration, include `canary_accounts`, canary tenants, and explicit `safety_notes` describing why
the imported metadata is safe.

Canaries should be created by the operator, have no access to real customer data, and be easy to
identify in audit logs. Use canary records for exports, webhooks, agent tools, support/admin actions,
and integration tests. Imported rehearsal findings should remain predictions over the model until an
operator chooses a separate, scoped, canary-only validation path.

## Imported-Model Rehearsal Vs Live Probing

Imported-model rehearsal is static analysis over a sanitized ProductModel. HEEL converts the JSON
into affordances and runs its scenario engine over those affordances. It does not call routes, open
webhooks, execute agent tools, authenticate to SaaS systems, send messages, create payments, or fetch
data.

Live probing would mean interacting with a deployed system. This contract does not implement that.
Future live adapters must keep the same safety spine: explicit signed scope, canary-only data,
operator-approved limits, no third-party targets, no scope mutation from MCP/REST/agent surfaces, no
real exfiltration, no credential abuse, no payment abuse, no spam, and no resource exhaustion.

## Validate A Model

```bash
heel import validate product_model.json
```

The command validates required fields, environment names, list shapes, `safety_notes`, and
secret-looking keys or values. It prints a human-readable summary including the imported target id.
It does not register a persistent target, create a scope, or run a rehearsal.

## Conversion Notes

`heel.importers.target_from_product_model()` returns an `ImportedTarget` compatible with the existing
scenario engine. The target contains:

- affordances derived from the ProductModel lists,
- entitlement-graph affordances derived from the same static metadata,
- `planted_vectors: []` because imported models have no synthetic ground truth,
- `requires_scope: true`,
- safety metadata recording source, environments, canaries, data classes, declared controls, and
  `live_probing_disabled: true`.

Because no ground truth exists, imported runs report `metric_kind: imported_model_rehearsal` and do
not claim coverage, precision, or calibration.
