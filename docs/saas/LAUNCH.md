# ARCEO Hosted — Launch Readiness

## Gate status (honest)
Launch is **NOT ready**. Two independent classes of blocker:
1. **Mandatory Sol review cannot run** — `gpt-5.6-sol` unavailable on installed Codex (OWNER_ACTIONS
   #12). No gate ratified; §17 forbids substituting a reviewer. Hard blocker.
2. **Owner-only external inputs** — Stripe, Postgres, auth vendor, domain, hosting, secret manager,
   legal counsel (OWNER_ACTIONS #1–8). Hard blockers for production.

## What IS done and verified
- Base reconciled to `origin/main`; feature worktree `saas/arceo-build`; baseline 200 tests green.
- Open-core boundary (Apache core + proprietary `arceo/saas/`) with SPDX headers + LICENSE-COMMERCIAL.
- Typed versioned catalog; tenancy (orgs/workspaces/roles/invites/hashed API keys) + `require()`;
  atomic usage ledger (reserve/consume/refund, idempotency, transactional quotas, verified-run
  ceiling); server-side entitlement authority; billing state machine with webhook signature/replay/
  order safety. **235 tests green.**
- Full documentation spine (ADRs, PRODUCT, PRICING, ARCHITECTURE, THREAT_MODEL, OPERATIONS,
  OWNER_ACTIONS, SELF_REVIEW, this file).

## Shortest path from here to the first real signup + payment
1. **Owner:** upgrade Codex so `gpt-5.6-sol` resolves → Fable runs Sol gates 1–4, fixes findings.
2. **Owner:** create Stripe (test+live), Postgres, auth-vendor, domain, hosting, secret-manager
   accounts; supply env per OWNER_ACTIONS; legal reviews the DRAFT policies.
3. **Fable (Phases 2–3):** hosted auth/session HTTP surface; migrations; job plane + workers + target
   verification + egress guard (T3/T4).
4. **Fable (Phase 4):** wire live Stripe (catalog→Stripe sync, webhooks) + test-clock lifecycle suite.
5. **Fable (Phases 5–6):** live app UX (replace static snapshot with authenticated backend), guided
   onboarding, public website + pricing + enterprise + docs + legal.
6. **Fable (Phases 8–9):** IaC, CI/CD, staging deploy, black-box acceptance (15-step script, §19).
7. **Sol gate 4 + owner go/no-go**, then production deploy → accept first signup and payment.

Nothing above is bypassable while blocker #1 stands.
