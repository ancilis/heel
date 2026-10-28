# Scenario Packs

Current evidence boundary (September 4, 2026): library matches are hypotheses or investigation prompts, not verified behavior. Relevant commercial mechanisms require a declared applicable rule and source. Coupon stacking, concurrent sessions, bulk access, sequential IDs, public documentation and versioned/admin routes alone do not establish abuse. Alternate encodings share mechanism IDs and do not multiply executed coverage. Persona characteristics and economic estimates are assumptions. The executable slice and broader gaps are documented in [CAPABILITIES.md](CAPABILITIES.md). Historical vocabulary scores below are not live detection accuracy and are not current after predicate changes.

Heel covers SaaS abuse broadly. Agent/MCP is a premium pack for products with agentic surfaces.

Scenario packs let operators focus a run without changing the safety model. Every run still requires
a human-created signed scope for non-synthetic targets, every finding remains canary-contained, and
MCP/REST/agent callers still cannot create, widen, or mutate scopes.

## Packs

| pack | purpose |
|---|---|
| `core_saas` | General SaaS abuse surfaces that do not fit a narrower pack. |
| `payments_billing` | License, entitlement, usage, billing, export, shadow-API/UI backing endpoint, and commercial abuse surfaces. |
| `trust_safety` | Signup, account, content, review, referral, and trust-economy abuse surfaces. |
| `integrations` | OAuth, webhook, and integration extensibility abuse surfaces. |
| `compliance` | Tenant isolation, audit, residency, retention, and admin/support workflow boundaries. |
| `agent_mcp` | Agent tools, MCP connectors, RAG/retrieval, tool authorization, and model-to-tool action surfaces. |

By default, Heel keeps current behavior: it loads all relevant packs, and Agent/MCP scenarios only
apply when the target declares an agentic surface. Explicit pack filters narrow the library.

## CLI Examples

List only Agent/MCP scenarios:

```bash
heel scenarios --pack agent_mcp
```

Run a scoped rehearsal with selected packs:

```bash
heel run --scope scope-123 --target imported:acme-crm --packs core_saas,agent_mcp
```

## Agent/MCP Examples

The `agent_mcp` pack covers agentic product abuse, including:

- over-scoped tools
- confused deputy tool calls
- cross-tenant retrieval
- indirect-injection-to-action
- cost amplification
- tool poisoning

This pack is not the whole product. It is one focused surface within broader SaaS abuse rehearsal.
