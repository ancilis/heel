# Prompt 13 — Add OpenAPI import MVP: `arceo init --from-openapi`

Task: Add a minimal OpenAPI importer that creates a ProductModel draft.

Create:

- arceo/openapi_import.py
- CLI:
  - arceo init --from-openapi openapi.yaml --out product_model.json
  - arceo import openapi openapi.yaml --out product_model.json
- docs/OPENAPI_IMPORT.md
- tests with example OpenAPI files

Constraints:

- stdlib-only.
- JSON OpenAPI support is required.
- YAML support may be limited:
  - If PyYAML is unavailable, print a clear error suggesting JSON export.
  - Do not add PyYAML as a runtime dependency.
- No network calls.
- Do not infer secrets.
- Do not store examples containing real credentials.

Mapping:

- paths with export/download/bulk -> export affordances
- paths with signup/trial -> trial/signup affordances
- paths with billing/subscription/usage/meter -> billing/meter affordances
- paths with invite/user/member/seat -> seat/identity affordances
- paths with oauth/integration/app/webhook -> integration affordances
- paths with admin/support -> admin_action/support affordances
- securitySchemes -> declared auth controls
- tags -> product areas
- x-arceo-* vendor extensions, if present:
  - x-arceo-plan
  - x-arceo-tenant-scope
  - x-arceo-meter
  - x-arceo-data-class
  - x-arceo-control
  - x-arceo-agent-tool

Output:

- ProductModel JSON draft
- warnings:
  - missing tenant metadata
  - missing entitlement metadata
  - export routes without declared rate/entitlement controls
  - broad OAuth scopes
  - agent-like endpoints lacking scope metadata

Tests:

- JSON OpenAPI import creates product_model
- export path maps to export surface
- OAuth path maps to integration surface
- missing metadata creates warnings
- x-arceo vendor extensions improve mapping
- no live calls are made

Docs:

- Include before/after example.
- Explain that OpenAPI import is a starting point and should be enriched with pricing, auth, telemetry, and canary data.

Acceptance criteria:

- A real SaaS team can run one command against an API spec and get a safe Arceo model draft.
