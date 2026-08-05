# Builder self-review (NOT the mandated independent review)

The mandatory Codex **Sol** gates cannot run — `gpt-5.6-sol` is unavailable on the installed Codex
(see BUILD_STATE.md / OWNER_ACTIONS #12). Substituting another reviewer is prohibited (§17). This is
a Fable **self**-adversarial pass on its own code. It does NOT satisfy any gate; every item here must
still be re-reviewed by Sol once Codex is upgraded.

## Findings and dispositions
1. **[FIXED · cost] Free-tier verified-run ceiling was unenforced.** The catalog metered a single
   `RUNS` credit (free=25); a free user could spend all 25 on costly verified-target runs, breaking
   the documented "5 verified" liability ceiling. Fix: added `Meter.VERIFIED_RUNS` (free=5) and
   `EntitlementService.reserve_run(verified=…)`, which reserves both meters atomically and refunds the
   RUNS credit if the verified ceiling is exhausted. Test: `test_verified_run_ceiling_bounds_free_liability`.

2. **[ACCEPTED RISK · billing atomicity] `apply_event` upsert and `record_event` are not one DB
   transaction.** A crash between them leaves state advanced but the event unrecorded. Verified safe:
   on replay the same event has `version == cur.version` → disposition `stale`, a no-op. Idempotent by
   version guard even without atomicity. Tightening to a single transaction is a Phase-4 follow-up.

3. **[NO FINDING · authorization] Client claims / raw billing metadata as authorization.** Entitlements
   are computed only from the pinned catalog + server-stored subscription state
   (`entitlement.py:effective_plan`). No code path reads a client-supplied role/plan as truth;
   `tenancy.require()` reads role from the DB. Confirmed.

4. **[NO FINDING · dead checkboxes] Config-gated enterprise features.** SSO/SCIM/data-region/private-
   runners return `has_feature=False` and status `contact_sales` until `HEEL_FEATURE_*=1` is set
   (`entitlement.feature_status`). Test covers both states.

5. **[NO FINDING · secrets] No hard-coded production price/product IDs or secrets** in `heel/saas/`.
   `StubBilling` ids contain "stub"; live ids are read from env via `live_price_id` and raise if unset.
   Guard test: `test_no_hardcoded_price_ids`, `test_live_price_id_requires_env`.

6. **[NO FINDING · concurrency] Quota race.** 40 concurrent workers (separate connections) against a
   quota of 25 → exactly 25 succeed, never more (`test_concurrent_reservations_respect_quota`).
   `BEGIN IMMEDIATE` + `busy_timeout` serialize check-then-append.

7. **[OPEN · scope] Target verification & signed-scope hosted path (Phase 3) not yet implemented.**
   The open-source `scope.py` HMAC spine is inherited unchanged; the hosted human-only verification
   flow (DNS TXT / HTTP challenge → eligible target → signed scope) is designed in ARCHITECTURE.md but
   not built. Tracked as Phase 3. No unsafe interim path exists (no hosted scope-mint code was added).

## Known not-yet-built (honest gaps, not defects)
Phases 2 (hosted auth/session HTTP surface), 3 (job plane/workers/verification), 5 (live app UX),
6 (website/legal/email), 7 (observability/admin), 8 (IaC/CI/CD/staging), 9–10 (E2E/load/black-box/
deploy). Most require owner credentials (OWNER_ACTIONS) and all require Sol ratification before launch.
