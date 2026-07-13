# ARCEO SaaS — Owner Actions (external necessities only)

These require a human legal identity, ownership, or credentials a model cannot possess. Everything
else is built and testable locally without them. Ordered by launch criticality.

## Blocking production launch
1. **Legal counsel review** of Terms, Privacy, AUP, target-authorization policy, DPA, refund terms,
   and the open-core / commercial-license split (ADR-0001). Draft docs are in `docs/saas/legal/`
   (marked DRAFT — NOT LEGAL ADVICE).
2. **Stripe account** (live + test). Provide: `STRIPE_SECRET_KEY`, `STRIPE_TEST_KEY`,
   `STRIPE_WEBHOOK_SECRET`. Then run `python3 -m arceo.saas.billing sync` to create Products/Prices
   from the code catalog. Verify with the included test-clock lifecycle suite.
3. **Managed Postgres** (Neon/Supabase/RDS). Provide `DATABASE_URL`. Run migrations:
   `python3 -m arceo.saas.migrate up`.
4. **Auth vendor** (Clerk or WorkOS). Provide publishable/secret keys. Enterprise SSO/SCIM needs
   WorkOS org config.
5. **Domain + DNS** ownership (e.g. `arceo.dev`/`.com`) for the marketing site, app, and TLS.
6. **Hosting accounts**: web host (Vercel) + worker/container host. Provide deploy tokens.
7. **Secret manager** (cloud KMS/Secrets Manager) for the scope signing key and vendor secrets.
8. **Error tracking + status page** accounts (Sentry, statuspage/Better Stack) — provide DSN/keys.

## Blocking the mandatory independent review
12. **Upgrade Codex CLI/app** so the reviewer model `gpt-5.6-sol` resolves. Current installed Codex
    rejects it: `400 … "The 'gpt-5.6-sol' model requires a newer version of Codex."` Until upgraded,
    the four mandatory Sol adversarial gates (§17) cannot run and the build is **not launch-ratified**.
    Verify with: a `mcp__codex__codex` call using `model: gpt-5.6-sol` returns a normal response.

## Non-blocking but recommended
9. **GitHub repo rename** `ancilis/heel` → `ancilis/arceo` (badges/URLs already reference `arceo`).
10. Email/SMTP provider (Postmark/Resend) for lifecycle email — `RESEND_API_KEY`.
11. Analytics provider (privacy-aware, e.g. PostHog) — `POSTHOG_KEY`.

## What is NOT required to keep building
Local dev, all lifecycle/entitlement/ledger/tenancy tests, the guided synthetic funnel, and the
website all run offline with stub adapters. No owner action is needed before the next Fable session
continues implementation.
