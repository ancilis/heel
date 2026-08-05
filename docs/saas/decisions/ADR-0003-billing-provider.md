# ADR-0003 — Billing provider: Stripe

Status: Accepted · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

## Decision
Use **Stripe** (Billing + Checkout + Customer Portal + webhooks + Tax config points). Rejected:
Paddle/Lemon Squeezy (Merchant-of-Record simplifies tax but higher fees, weaker metered-usage and
test-clock tooling); homegrown billing (explicitly disallowed by spec §5).

## Implementation status (honest)
Implemented and tested today: the subscription state machine, webhook signature verification +
dedupe/ordering guards (fail-closed without a secret), the append-only usage ledger, env-injected
price-ID lookup (`live_price_id`), and `StubBilling` driving the full lifecycle offline. **The live
Stripe adapter, catalog→Stripe sync, Customer Portal wiring, and test-clock CI are NOT implemented**
— they are the contract below, gated on owner keys (OWNER_ACTIONS). Self-serve paid checkout is not
live until the owner lands them.

## Integration contract (target design; live pieces owner-gated)
- **Catalog is code, not Stripe-authored.** One typed product catalog (`heel/saas/catalog.py`) is the
  source of truth for plan names, prices, quotas, entitlements. Stripe Product/Price IDs are injected
  per-environment via env, never hard-coded. A `stripe sync` step reconciles catalog → Stripe.
- **Entitlements derive from a server-side subscription state machine, never from raw Stripe metadata
  or client claims.** Webhooks update subscription state; the entitlement service reads that state.
- **Webhook safety:** signature verification (`Stripe-Signature`), idempotency keys, replay/duplicate/
  out-of-order tolerance via an event-id dedupe table and monotonic subscription versioning.
- **Usage ledger** (`heel/saas/ledger.py`) is append-only with reserve/consume/refund and idempotency
  keys; metered usage is reported to Stripe from the ledger, not the reverse.
- **Lifecycle to cover:** checkout, portal, monthly/annual, proration, upgrade, scheduled downgrade,
  cancel-now / cancel-at-period-end, grace/dunning, payment failure, refund/chargeback. The state
  machine and stub exercise these transitions offline; the live Stripe flows remain owner-gated.
- **Verification:** Stripe **test mode + test clocks** exercised in CI once `STRIPE_TEST_KEY` exists
  (owner action). Until then, a deterministic `StubBilling` adapter drives the full state machine and
  all lifecycle tests offline.

## No production IDs/prices/secrets in the repo. Verified by a CI guard.
