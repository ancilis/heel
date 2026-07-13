# ARCEO Hosted — Architecture

Two separated planes over the open-source engine. Everything runs locally with zero external
accounts; prod adapters swap in behind interfaces.

## Control plane (`arceo/saas/`)
- **Identity & tenancy:** orgs/workspaces, memberships, invites. Roles: owner, admin,
  member/operator, billing, viewer. Sessions, scoped service accounts, hashed+scoped API keys.
- **Entitlement service** (`entitlement.py`) — the single server-side authority. Consumed by UI, API,
  MCP, workers, billing. Client claims and raw Stripe metadata are never authorization.
- **Product catalog** (`catalog.py`) — one typed, versioned source of truth for plans/quotas.
- **Usage ledger** (`ledger.py`) — append-only, idempotent, reserve/consume/refund. Quotas enforced
  transactionally at enqueue AND at execution.
- **Billing** (`billing.py`) — Stripe adapter + `StubBilling`; subscription state machine; webhook
  dedupe/replay/order safety.
- **Target verification** (`verification.py`) — human-only proof-of-control (DNS TXT / HTTP challenge)
  before a target becomes eligible for a signed scope. A checkbox is never sufficient.
- **Store** — tenant-scoped Postgres (prod) / SQLite (local) behind `store.py`-style abstraction, with
  a tenant boundary column on **every** durable record and RLS where supported.

## Execution plane
- Durable job queue (Postgres SKIP LOCKED local; managed in prod). Reservation → execute →
  refund/finalize semantics tied to the ledger.
- Isolated workers: a worker pinned to a tenant claims with a workspace filter (`JobPlane.claim`
  refuses foreign jobs at the SQL level); shared-pool workers rely on per-run isolation (sandbox +
  egress), never a shared mutable filesystem/cache namespace. Egress restricted to the run's single
  verified target, per-run CPU/wall-clock/network/token/storage budgets, cancellation, retries,
  timeouts, backpressure, dead-letter.
- Workers never trust user-controlled job fields; targets and scopes are re-verified server-side.

## Safety spine (inherited + strengthened)
- `scope.py` HMAC-signed, human-only authorization scopes — no mint/widen/relax path over any agent
  surface. Hosted scope creation is `POST /workspaces/{id}/scopes`: session principals with
  `create_scope` (owner/admin) only, step-up confirmation (retype the exact target), mandatory
  audited reason, target currently verified; the scope material comes from an engine-injected
  minter and the route answers 501 when none is configured (fail closed). Scopes are bound to the
  exact target they were minted for — the job plane passes the requested target to the validator,
  so a scope for target A never authorizes target B.
- SSRF/rebinding/redirect/private-address defenses at the worker egress layer (`verification.py` +
  worker guard); target-to-IP pinning; cross-tenant target substitution rejected.
- Findings contained, canary-only. Global + tenant kill switches.

## Boundaries
Every durable record, object key, cache key, queue message, log, trace, audit event carries a
tenant/workspace id. Adversarial cross-tenant + IDOR tests are mandatory (Phase 9).

## Interfaces (adapter pattern → local vs prod)
`Store`, `Queue`, `Billing`, `Auth`, `Secrets`, `Egress` are interfaces. Local impls are zero-infra;
prod impls need owner credentials (OWNER_ACTIONS).
