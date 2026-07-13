# ARCEO Hosted — Product Definition

Status: Phase-1 baseline · Date: 2026-07-13 · Owner: Fable build (autonomous, delegated)

## What it is
ARCEO Hosted is the managed service on top of the open-source ARCEO engine. Teams rehearse
incident-response and control validation against synthetic targets and, after proof-of-control
verification, against their own verified targets — without operating the engine, workers, or storage
themselves. The open-source engine stays free and self-hostable; the hosted product sells operation,
not the engine (ADR-0001).

## Who it is for (ICP)
1. **Security / platform engineers at small-to-mid SaaS companies** who want scheduled, repeatable
   control rehearsals without running infrastructure.
2. **Consultancies and red/purple teams** running rehearsals for multiple clients (workspaces per
   client, exportable evidence).
3. **Enterprises** needing SSO/SCIM, audit export, data-region controls, and private runners.

## Value proposition
- **Rehearse before it is real:** verified, contained rehearsal runs with planted ground truth and
  honest scoring, not simulated confidence.
- **Zero-ops:** managed queue, workers, retention, and dashboards.
- **Evidence:** append-only containment log, exportable findings, scheduled regressions.
- **Safety by construction:** human-only signed authorization scopes, target proof-of-control,
  per-run egress restricted to the verified target. No agent surface can mint or widen a scope.

## What is sold (and what is not)
Sold: hosted rehearsal runs (metered), verified-target capacity, concurrency, retention, seats,
integrations, enterprise capabilities, support. See `PRICING_AND_ENTITLEMENTS.md` and
`arceo/saas/catalog.py` (source of truth).
Not sold: the engine itself (Apache-2.0), UI decoration, or access to anything that bypasses the
safety spine.

## Product surfaces
- **App (Next.js):** onboarding, guided first rehearsal against a synthetic target, live run
  dashboard, findings, billing portal, member/role management.
- **Hosted API + MCP access (paid tiers):** tenant-scoped API keys, run enqueue/status/results, CI
  integration. What is paid is access to the *hosted* control plane; the engine's own loopback
  MCP/REST surfaces stay Apache-2.0 and free for self-hosters (ADR-0001).
- **CLI:** the open-source CLI can point at the hosted API with an API key.
- **Public website:** product, pricing, docs, security page, enterprise contact.

## Onboarding funnel (free, no card)
1. Sign up → workspace created on Free (no card).
2. Guided first rehearsal against a **synthetic** target (deterministic, $0 marginal cost) —
   value visible in minutes.
3. Verify a real target via DNS TXT / HTTP challenge, then a signed-in owner/admin mints a
   target-bound authorization scope (step-up confirmation, audited) → up to 5 verified runs on Free.
4. Quota hit → in-context upgrade to Pro (self-serve checkout).

## Cost model (free-tier ceiling) {#cost-model}
Every free unit is atomically capped in the usage ledger (reserve-at-enqueue). Worst case per free
workspace per month: 20 synthetic runs at ~$0 marginal + 5 verified runs under per-run budget
ceilings (wall-clock ≤ 60 s, egress limited to the verified target, token budget capped). Signup
throttles, proof-of-control, and global/tenant circuit breakers bound aggregate liability.

## Non-goals (v1)
- No usage-based pay-as-you-go pricing and no metered overage: predictable tiers only, every
  self-serve quota is a hard stop with an in-context upgrade path.
- No unverified real-target execution at any tier, ever.
- No on-prem control plane in v1 (private runners cover the data-locality need; full on-prem is a
  later enterprise conversation).

## Success metrics
Activation: signup → first completed synthetic run < 15 minutes. Conversion: free → Pro after
quota contact. Retention proxy: scheduled regressions enabled per paying workspace.
