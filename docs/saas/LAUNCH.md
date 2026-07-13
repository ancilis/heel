# ARCEO Hosted — Launch Readiness

## Gate status (honest)
Launch is **NOT ready**. Remaining blocker classes:
1. **Mandatory Sol review gates 1–4 not yet ratified.** The reviewer model `gpt-5.6-sol` now
   RESOLVES on Codex CLI 0.144.3 (verified 2026-07-13); the remaining obstacle is the Codex MCP
   transport idle-timing-out from this session. Gate attempts continue; no gate is ratified yet
   and §17 forbids substituting a reviewer.
2. **Owner-only external inputs** — Stripe, Postgres, domain, hosting, secret manager, ESP,
   legal counsel (OWNER_ACTIONS #1–8). Hard blockers for production exposure.

Nothing below is bypassable while blocker #1 stands.

## What IS done and verified (2026-07-13, full suite 331 tests OK)
- Open-core boundary (Apache core + proprietary `arceo/saas/`), SPDX headers, LICENSE-COMMERCIAL.
- Typed versioned catalog; tenancy/roles/invites/hashed API keys behind one `require()` choke
  point; atomic usage ledger (reserve/consume/refund, idempotency, race-proof quotas);
  server-side entitlement authority; billing state machine with signed/replay-safe webhooks.
- **Phase 2:** PBKDF2 auth + hashed sessions + lockout; versioned SQLite↔Postgres migrations;
  loopback-default JSON control-plane API. API keys can never mint scopes (human-only preserved).
- **Phase 3:** DNS TXT / HTTP-file target verification; default-deny egress guard with
  private-IP (rebinding) refusal; budgeted job plane with leases, reaper, and exact
  ledger settlement; verified runs fail closed without target + human scope.
- **Phase 4:** reconciliation report + customer-favorable auto-repair.
- **Phase 5:** server-rendered onboarding/dashboard on the same auth + choke points.
- **Phase 6:** static site/docs generated FROM the catalog; legal pages as counsel-review
  templates.
- **Phase 7:** kill switches (global/tenant) denying spend at enqueue, append-only admin audit,
  metrics, healthz/readyz, seven runbooks.
- **Phase 8:** end-to-end smoke script (SMOKE PASS), backup/restore-verify tooling (VERIFY PASS),
  make targets + CI wiring.
- **Phase 9:** adversarial black-box pass — auth bypass, cross-tenant probing, replay,
  idempotency, quota races, malformed input; all fail closed.

## Shortest path from here to the first real signup + payment
1. **Sol gates 1–4** over MCP (transport permitting) → fix findings → ratify.
2. **Owner:** Stripe (test+live), managed Postgres, domain/TLS/hosting, secret manager, ESP;
   counsel replaces the template terms/privacy pages.
3. **Fable:** swap StubBilling for the live Stripe adapter behind the same interface; point the
   Migrator at Postgres (`dialect='postgres'` + `copy_table`); front the control plane with the
   TLS edge; wire the engine's scope verifier as the job plane's `scope_validator`.
4. Staging deploy → `make saas-smoke` against staging → restore drill on a staging backup.
5. **Sol gate 4 + owner go/no-go**, then production deploy → first signup and payment.

## Handoff summary
Everything local-first runs today with zero external accounts:
`make test` (331) · `make saas-smoke` · `make saas-site` · `make saas-backup DB=… OUT=…` ·
`make saas-restore-verify OUT=…`. State ledger: `docs/saas/BUILD_STATE.md`. Runbooks:
`docs/saas/RUNBOOKS.md`. Owner to-dos: `docs/saas/OWNER_ACTIONS.md`.
