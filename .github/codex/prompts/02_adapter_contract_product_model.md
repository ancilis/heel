# Prompt 2 — Build the adapter contract: `docs/ADAPTERS.md` + core target-import schema

Task: Add the first real-target adapter contract for Heel.

Create:

- docs/ADAPTERS.md
- heel/importers.py
- tests covering the importer contract

Purpose:
Heel needs a stable way to turn a SaaS product description into Heel’s internal affordance model without touching real systems.

Add a versioned JSON schema-like contract named ProductModel v0.1. It should be plain Python dictionaries / dataclasses, no third-party JSON-schema dependency.

ProductModel fields:

- product_id
- source
- generated_at
- environments: production | staging | sandbox | synthetic
- tenants: list
- roles: list
- plans: list
- meters: list
- coupons/promotions: list
- features/flags: list
- endpoints/routes: list
- exports: list
- identity/auth flows
- billing objects
- integration/OAuth apps
- webhooks
- support/admin actions
- agent_tools
- mcp_connectors
- data_classes
- audit_events
- declared_controls
- canary_accounts
- safety_notes

Add conversion:
ProductModel -> SyntheticTarget-like object or a new ImportedTarget compatible with the existing agent/scenario engine.

Requirements:

- Imported targets must never include secrets.
- Imported targets must include safety metadata.
- Imported targets must require signed scope authorization to run.
- Keep it stdlib-only.
- Do not add real network calls yet.

Docs:
`docs/ADAPTERS.md` should explain:

- how to model a SaaS product safely
- how OpenAPI, pricing config, auth roles, Stripe-like billing config, feature flags, MCP manifests, and telemetry can map into ProductModel
- what data must never be imported
- how to use canary users and staging/sandbox targets
- the difference between imported-model rehearsal and live probing

CLI:
Add a placeholder command:

```bash
heel import validate <product_model.json>
```

It validates required fields and prints a human-readable summary.

Tests:

- valid minimal ProductModel passes
- missing required fields fail
- secrets-looking keys/values are rejected or warned on
- conversion produces affordances
- imported target cannot be run without a scope
- imported target has safety_notes

Acceptance criteria:

- A user can read docs/ADAPTERS.md and understand how to bring a real SaaS product into Heel safely.
- No actual live adapter or network probing exists yet.
