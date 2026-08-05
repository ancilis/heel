# HEEL SaaS — Owner Actions (external necessities only)

These require a human legal identity, ownership, or credentials a model cannot possess. Everything
else is built and testable locally without them. Ordered by launch criticality.

## Blocking production launch
1. **Release identity and publisher approval.** Preserve the existing `v1.1.0` tag and mark its
   release notes as superseded; remove the false `pip install`, published-provenance, and SBOM claims
   without moving or deleting the tag. Protect the GitHub `pypi` environment with a required
   non-self reviewer, disable administrator bypass, and restrict deployments to protected release
   tags. Configure the PyPI Trusted Publisher for the exact owner/repository, `publish.yml`, and
   `pypi` environment. After the current source is pushed and CI passes, create the new immutable
   `v1.1.1` tag and stable (not draft or prerelease) GitHub Release. The workflow then verifies,
   attests, and publishes only the named 1.1.1 wheel and source archive.
2. **Legal counsel review** of Terms, Privacy, AUP, target-authorization policy, DPA, refund terms,
   and the open-core / commercial-license split (ADR-0001). Draft docs are in `docs/saas/legal/`
   (marked DRAFT — NOT LEGAL ADVICE).
3. **Stripe account** (live + test). Provide: `STRIPE_SECRET_KEY`, `STRIPE_TEST_KEY`,
   `STRIPE_WEBHOOK_SECRET`. Then run `python3 -m heel.saas.billing sync` to create Products/Prices
   from the code catalog. Verify with the included test-clock lifecycle suite.
4. **Managed Postgres** (Neon/Supabase/RDS). Provide `DATABASE_URL`. Run migrations:
   `python3 -m heel.saas.migrate up`.
5. **Auth vendor** (Clerk or WorkOS). Provide publishable/secret keys. Enterprise SSO/SCIM needs
   WorkOS org config.
6. **Domain + DNS** ownership (e.g. `heel.dev`/`.com`) for the marketing site, app, and TLS.
7. **Hosting accounts** for the browser app and Python control plane. Provide deploy credentials only
   through the selected hosts' secret managers.
8. **Secret manager** (cloud KMS/Secrets Manager) for the scope signing key and vendor secrets.
9. **Error tracking + status page** accounts (Sentry, statuspage/Better Stack) — provide DSN/keys.

## Non-blocking but recommended
10. Email/SMTP provider (Postmark/Resend) for lifecycle email — `RESEND_API_KEY`.
11. Analytics provider (privacy-aware, e.g. PostHog) — `POSTHOG_KEY`.

## What is NOT required to keep building
Local dev, all lifecycle/entitlement/ledger/tenancy tests, the guided synthetic funnel, and the
website all run offline with stub adapters. No owner action is needed before the next Fable session
continues implementation.
