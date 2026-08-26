# Heel Local SaaS Demo

This directory is a real-ish local SaaS adapter fixture. It shows how an operator can
describe a mature product with sanitized metadata, then run Heel's existing-product
mode without connecting to a real customer system.

The demo is local/canary-only: all tenants, users, records, exports, webhooks, OAuth
apps, agent tools, and MCP connector metadata are synthetic. The ProductModel path is
static imported-model rehearsal with no live probing and no external services.

## What It Models

- Free, Pro, and Enterprise plans.
- Seats, trial eligibility, a coupon/promo, a monthly usage meter, and an AI-token meter.
- Tenant records, bulk export, invite flow, OAuth app, webhook endpoint, support/admin action.
- One agent tool family and one MCP connector-like manifest.
- Canary users/accounts and declared controls, including both present and missing controls.

Intentional contained weaknesses are represented as metadata only: email-only trial eligibility,
export missing entitlement/quota checks, stackable coupons without a redemption cap, unbounded
AI-token tool work, OAuth `scope=all`, an agent tool granted wider scope than intended, and a
missing audit event for a support/admin action.

## Commands

Validate the sanitized model:

```bash
heel import validate examples/saas_demo/product_model.json
```

Authorize the imported target out of band:

```bash
heel scope create --target imported:heel-saas-demo --operator you --confirm
```

Run the existing-product imported mode inside that signed scope:

```bash
heel run --mode existing-imported --target examples/saas_demo/product_model.json --scope <scope>
```

Compare the demo model with itself to exercise the launch-review command shape:

```bash
heel launch-review --before examples/saas_demo/product_model.json --after examples/saas_demo/product_model.json
```

The OpenAPI file is a companion fixture for the same demo surface:

```bash
heel import openapi examples/saas_demo/openapi.json --out /tmp/heel-saas-demo-product-model.json
```

## Safety Notes

- The files contain no credentials, customer records, payment instruments, webhook signing
  material, request bodies, response bodies, or working exploit payloads.
- The imported target id is `imported:heel-saas-demo`; a human-created `AuthorizationScope`
  must allow exactly that target before a run can start.
- Heel reports predicted, contained findings over the static ProductModel. It does not call
  these routes, send webhooks, execute agent tools, install OAuth apps, or export data.
