# HEEL Hosted — Architecture

Two separated planes over the open-source engine. Everything runs locally with zero external
accounts; prod adapters swap in behind interfaces.

**Implementation status (honest):** what exists today is the local layer — SQLite stores, the
SQLite-backed job plane, `StubBilling`, and the loopback HTTP control plane, all covered by the
test suite. Production adapters (live Stripe, Postgres, managed queue, deployed workers) are
*designs behind the same interfaces*, gated on owner credentials (OWNER_ACTIONS); they are not
implemented yet, and nothing below should be read as a claim that they are. Stripe price IDs are
injected via env (`live_price_id`) so no production ID lives in code.

## Control plane (`heel/saas/`)
- **Identity & tenancy:** orgs/workspaces, memberships, invites. Roles: owner, admin,
  member/operator, billing, viewer. Sessions, scoped service accounts, hashed+scoped API keys.
- **Entitlement service** (`entitlement.py`) — the single server-side authority. Consumed by UI, API,
  MCP, workers, billing. Client claims and raw Stripe metadata are never authorization.
- **Product catalog** (`catalog.py`) — one typed, versioned source of truth for plans/quotas.
- **Usage ledger** (`ledger.py`) — append-only, idempotent, reserve/consume/refund. Run quotas are
  reserved transactionally at enqueue; at execution the job plane enforces the concurrency
  entitlement in `JobPlane.claim` and the retention entitlement via `JobPlane.purge_retention`;
  active API keys are capped by the integrations quota at key creation.
- **Billing** (`billing.py`) — subscription state machine + webhook dedupe/replay/order safety,
  with `StubBilling` driving the full lifecycle locally. The live Stripe adapter is not yet
  implemented (owner-gated); its price IDs come from env via `live_price_id`. The webhook
  endpoint fails closed: without a configured signing secret it answers 503.
- **Target verification** (`verification.py`) — human-only proof-of-control (DNS TXT / HTTP challenge)
  before a target becomes eligible for a signed scope. A checkbox is never sufficient.
- **Store** — SQLite today, with a tenant boundary column on **every** durable record; the planned
  Postgres production store (RLS where supported) sits behind the same abstraction (owner-gated).

## Execution plane
- Durable job queue: SQLite-backed `JobPlane` today (reservation → claim/lease → settle/refund
  semantics tied to the ledger, idempotent enqueue keyed to the reservation's idempotency key);
  a managed queue is the owner-gated production swap.
- Isolated workers: a worker pinned to a tenant claims with a workspace filter (`JobPlane.claim`
  refuses foreign jobs at the SQL level) and claim refuses to exceed the workspace's concurrency
  entitlement; shared-pool workers rely on per-run isolation (sandbox + egress), never a shared
  mutable filesystem/cache namespace. Every job carries an immutable `RunBudget` (wall-clock,
  token, egress-host ceilings) that workers are contractually required to enforce; the deployed
  worker fleet that executes real runs is owner-gated and not yet built.
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
- Findings contained, canary-only. Global + tenant kill switches (manual), plus an automatic
  platform circuit breaker: platform-wide run / verified-run caps enforced inside the ledger's
  reserve transaction. Signup is throttled per-IP and platform-wide; one hostname can hold an
  active verification in only a bounded number of workspaces.

## Boundaries
Every durable record, object key, cache key, queue message, log, trace, audit event carries a
tenant/workspace id. Adversarial cross-tenant + IDOR tests are mandatory (Phase 9).

## Interfaces (adapter pattern → local vs prod)
`Store`, `Queue`, `Billing`, `Auth`, `Secrets`, `Egress` are interfaces. Local impls are zero-infra;
prod impls need owner credentials (OWNER_ACTIONS).
