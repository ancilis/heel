# OpenAPI Import MVP

Heel can create a ProductModel draft from a local OpenAPI file:

```bash
heel init --from-openapi openapi.json --out product_model.json
heel import openapi openapi.json --out product_model.json
```

The importer is a starting point for SaaS abuse rehearsal. It turns API surface
metadata into a safe model draft that operators should enrich with pricing,
auth, telemetry, entitlement, and canary data before running Heel.

## Safety Posture

- Reads local files only. URLs are rejected; the importer makes no network calls.
- Does not probe the described API or any production system.
- Does not create, widen, relax, or mutate authorization scopes.
- Rejects secret-looking example values instead of copying them into the model.
- YAML is optional. If PyYAML is unavailable, export the OpenAPI spec as JSON.

The generated target still requires a human-created signed AuthorizationScope
before any imported-model rehearsal run.

## Mapping

The MVP uses route text, operation ids, tags, security schemes, and `x-heel-*`
vendor extensions:

- `export`, `download`, or `bulk` paths become export affordances.
- `signup` or `trial` paths become signup/auth-flow affordances.
- `billing`, `subscription`, `usage`, or `meter` paths become billing and meter affordances.
- `invite`, `user`, `member`, or `seat` paths become seat/identity affordances.
- `oauth`, `integration`, `app`, or `webhook` paths become integration affordances.
- `admin` or `support` paths become support/admin affordances.
- `securitySchemes` become declared auth controls.
- tags become `product_areas` metadata and are copied onto route-derived affordances.

Supported vendor extensions:

- `x-heel-plan`
- `x-heel-tenant-scope`
- `x-heel-meter`
- `x-heel-data-class`
- `x-heel-control`
- `x-heel-agent-tool`

## Before

```json
{
  "openapi": "3.1.0",
  "info": {"title": "Acme Platform API", "version": "2026-07"},
  "paths": {
    "/api/export/bulk": {
      "get": {
        "tags": ["Exports"],
        "operationId": "downloadBulkExport",
        "summary": "Download a bulk export"
      }
    }
  }
}
```

## After

```json
{
  "schema_version": "ProductModel.v0.1",
  "product_id": "acme-platform-api",
  "source": "openapi:openapi.json",
  "environments": ["staging"],
  "exports": [
    {
      "id": "downloadbulkexport",
      "route": "/api/export/bulk",
      "method": "GET",
      "product_area": "Exports",
      "entitlement_check": "missing",
      "rate_limit": "missing"
    }
  ],
  "import_warnings": [
    "missing tenant metadata for /api/export/bulk",
    "missing entitlement metadata for /api/export/bulk",
    "export route without declared rate or entitlement control: /api/export/bulk"
  ],
  "safety_notes": [
    "OpenAPI-derived draft; review and enrich before rehearsal. No live probing or customer data."
  ]
}
```

## Enrichment Checklist

After import, review the warnings and add:

- pricing plans, trial rules, and entitlement boundaries
- tenant-scope metadata for every sensitive route
- server-side metering and billing controls
- rate-limit, audit, and entitlement controls for exports
- canary accounts and canary data classes
- agent-tool intended scope and granted scope

OpenAPI import is not an adapter that calls your API. It is a local draft
generator for safe model rehearsal.
