# ADR-0003 — Billing provider: Stripe

Status: Accepted · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

## Decision
Use **Stripe** (Billing + Checkout + Customer Portal + webhooks + Tax config points). Rejected:
Paddle/Lemon Squeezy (Merchant-of-Record simplifies tax but higher fees, weaker metered-usage and
test-clock tooling); homegrown billing (explicitly disallowed by spec §5).

## Integration contract (implemented as interfaces; live calls gated on owner keys)
- **Catalog is code, not Stripe-authored.** One typed product catalog (`arceo/saas/catalog.py`) is the
  source of truth for plan names, prices, quotas, entitlements. Stripe Product/Price IDs are injected
  per-environment via env, never hard-coded. A `stripe sync` step reconciles catalog → Stripe.
- **Entitlements derive from a server-side subscription state machine, never from raw Stripe metadata
  or client claims.** Webhooks update subscription state; the entitlement service reads that state.
- **Webhook safety:** signature verification (`Stripe-Signature`), idempotency keys, replay/duplicate/
  out-of-order tolerance via an event-id dedupe table and monotonic subscription versioning.
- **Usage ledger** (`arceo/saas/ledger.py`) is append-only with reserve/consume/refund and idempotency
  keys; metered usage is reported to Stripe from the ledger, not the reverse.
- **Lifecycle covered:** checkout, portal, monthly/annual, proration, upgrade, scheduled downgrade,
  cancel-now / cancel-at-period-end, grace/dunning, payment failure, refund/chargeback.
- **Verification:** Stripe **test mode + test clocks** exercised in CI once `STRIPE_TEST_KEY` exists
  (owner action). Until then, a deterministic `StubBilling` adapter drives the full state machine and
  all lifecycle tests offline.

## No production IDs/prices/secrets in the repo. Verified by a CI guard.
