# Prompt 17 — Add a real-ish local SaaS demo app adapter

Task: Add a realistic local demo target that behaves like a small SaaS product, without external services.

Create:

- examples/saas_demo/
- examples/saas_demo/product_model.json
- examples/saas_demo/openapi.json
- examples/saas_demo/README.md
- optional stdlib-only local HTTP demo if simple; otherwise keep it as imported model only

The demo should include:

- Free, Pro, Enterprise plans
- seats
- trial eligibility
- coupon/promo
- usage meter
- AI-token meter
- bulk export
- tenant records
- invite flow
- OAuth app
- webhook endpoint
- support/admin action
- one agent tool
- one MCP connector-like manifest
- canary users/accounts
- declared controls, some present and some missing

Include intentional contained weaknesses:

- trial eligibility email-only
- export missing entitlement or quota
- coupon stackable without redemption cap
- AI-token tool unbounded
- OAuth scope=all
- agent tool granted_scope wider than intended
- audit event missing for admin action

Add docs:
How to run:

```bash
heel import validate examples/saas_demo/product_model.json
heel run --mode existing-imported --target examples/saas_demo/product_model.json --scope <scope>
heel launch-review --before ... --after ...
```

Explain this is local/canary-only.

Tests:

- demo ProductModel validates
- demo produces expected categories
- demo has all 10 taxonomy categories represented where possible
- demo does not contain secrets
- demo docs commands are accurate

Acceptance criteria:

- A new user can understand Heel’s real-product story without needing a real customer system.
