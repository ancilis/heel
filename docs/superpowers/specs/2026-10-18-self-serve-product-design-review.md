# Heel self-serve launch — T1R adversarial specification review (documentation only)

Date: 2026-10-18. Reviewer: Claude Fable 5.1, fresh interactive session (T1R), medium effort.
Subject: `2026-10-18-self-serve-product-launch.md` as committed in
`f54c053ea480b030e22842284f2553a1d8b372c0`, reviewed against the original T1 assignment, the
T1/T1D closing reports, `RUN-LOG.md` and the T1 artifacts. Scope: validate or repair the
specification so that T2 is safe, concretely bounded and reviewable. No product code, test or
configuration was changed. Historical documents were read as evidence, not authority.

Artifacts for this review: `.git/self-serve-launch/sessions/T1R-artifacts/`
(`focused-skip-reasons-py313.log`, `t1r-spec-fact-checks.log`, `edit1..5.py` = the exact
spec replacements applied). Every claim below is CONFIRMED (evidence named) or INFERRED
(confirming action named).

## 1. Astra's concerns, one verdict each

| # | Concern | Verdict | Evidence | Repair in the spec |
|---|---|---|---|---|
| 1 | Truncated test names with ellipses cannot be run | CONFIRMED (2 names) plus one wrong name | §10 rows 4 and 5 ended in `…`; `grep "def test_"` gives the full ids `test_findings_upload_recursively_rejects_raw_credential_fixture_and_local_path_leakage` (`test_canary_privacy.py:29`) and `test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_assessment` (`:59`). Row 12 cited `test_restart_rehydrates_active_binding_but_requires_fresh_heartbeat`, which does not exist; the real id is `test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat` (`test_runner_coordinator.py:757`). All other 40 cited ids exist (fact-check log). Four whole-file counts were wrong: `test_verified_environments.py` 67 collected (spec said 30), `test_runner_redaction.py` 12 (6), `test_canary_quota.py` 7 (8), `test_canary_stop.py` 18 (21) | §10 rewritten: every id complete and file-qualified, counts from `--collect-only`, proposed tests labelled "not yet implemented" with the owning task |
| 2 | Evidence provenance: loopback HTTP and rendered HTML are not browser end-to-end proof; "works (API + UI)" and "verification works" overstate | CONFIRMED | The walk log is direct `http.client` traffic to `heel.saas.server`; the `vinext dev` run left no artifact (none in `T1-artifacts/`; the terminal transcript has no captured page responses), and ran in `local_review` mode where `/me` is 503, so the browser signup path never executed. The environment walk produced a challenge (201) and no successful `check`. T1D found no deployed backend through the access it had; absence elsewhere is unproven (Cloudflare untested) | §1.4 provenance note; §2 rows 1–4 and 6 reworded ("works (loopback API)", "challenge issuance works", "untested", "as far as this audit could see"); legend under the table; §13 rows 2–4; §15 note |
| 3 | Baseline arithmetic and skips | CONFIRMED | Both runs total 1755 tests; 145→1 means 144 removed, 1 persisting (demo-bench via system Python 3.9). The `/tmp` log holds only 39 `FAILED` rows (32 runtime, 7 stop) because the first wrapper piped pytest through tail, so "all 145 are inode-guard failures" is INFERRED (confirming action in §1.3). Skips: focused `pytest -q -rs` on the three modules with skip markers (same venv, 42 passed, 2 skipped) → `test_open_core_release.py:1604` (setuptools/wheel not installed) and `:1908` (`build.__main__` not importable). No full rerun was performed; the baseline of record stays 1752/1/2 + 653 subtests | §1.2 note, §1.3 items 1 and "Net" rewritten with the exact numbers and both skip reasons |
| 4 | `fixed_origin` cannot keep saying `private-vpc-only` | CONFIRMED | `server.py:183-186`: the value only acknowledges a non-loopback bind; it enforces nothing. The original §8.2 also had the edge-secret check "prove" a private network. A shared header secret proves possession, not caller identity | §8.2 rewritten: distinct `HEEL_INGRESS_ACK=edge-authenticated-tls-ingress` (T7, `server.py` added to allowed files), loopback app bind behind a host-local TLS terminator, four enforceable restrictions with recorded acceptance checks, explicit three-holder secret distribution consistent with §8.3, mode deferred and INFERRED until a host exists; no private-network claim |
| 5 | Exact APIs and order for "Prepare plan"; inventory 200 vs result 100; dynamic parameters and labels bound to the signed approval | CONFIRMED gap | No new route is needed: "Prepare plan" is the existing `POST …/runner-context-bindings` → runner `contexts/list` / `claim` / `approval-projections` → human approve (one-transaction quota + grant) → runner grant claim (`runner_contexts.py`, `canary_runs.py`, Worker `RUNNER_CONTEXT_CONTROL`). Bounds found: v1 `actions` ≤20 and 64 KiB (`canary_contracts.py:402-410`), Worker context-submit cap 69 632 B, runner executes `effective_max_ops // 2` ≤50 pairs (`plan_differential.py`, `MAX_MAX_OPS = 100`), compiler accepts 2000 routes. Parameter values enter the plan as `bindings_sha256` per pair | §7.1: reject-never-truncate rules (`inventory_too_large`, `inventory_invalid`), `unmapped` reason; §7.2: numbered seven-step ownership order, `pairs_planned` ≤50 with `bindings_sha256`, `not_executed_count` + `not_executed_digest`, v2 `actions` cap 100; §6 plan rows |
| 6 | 50-regression cap and 30-day result retention invent policy | CONFIRMED (both) | No existing decision sets a regression count; `catalog.py` marks `scheduled_regressions` unavailable on free; free `retention_days=7`; existing constants `FINDINGS_RETENTION_MS` 7 d, `OPERATIONAL_RETENTION_MS` 7 d, `AUDIT_RETENTION_MS` 30 d | §7.3 result rows follow the 7-day findings constant, audit 30 d; §7.4 regressions bounded at 100 as a stated technical storage bound (not pricing), manual replay only, `finding_expired` state; §7.6 "no new retention period" |
| 7 | T2 allowed files omit secure-storage schema; split if needed; no fabricated credentials | CONFIRMED | `plan_label` must live in the credential record (`store.py` `_credential_record` field set is closed, `:772`); pairing journal / identity records already exist in `RunnerStore`; `SystemSecureSigner` (`identity.py:317`) owns the seed. Larger defect: **no product code constructs `RunnerControlClient`, `RunnerCoordinator` or `RunnerService`** and the control client has **no HTTPS transport** (`transport` injected; only `urlsplit` imported). T2 as written could not reach a server | §12 T2 split into T2a (pair/status/unpair, HTTPS transport, store `plan_label`, identity) and T2b (`serve` loop); allowed files extended; gates require real exchange/approve/activate over the harness, no seeded rows |
| 8 | Real pairing gate must exercise the real flow with a correct test TLS/edge harness and keep production guards | CONFIRMED | `test_runner_control_http.py` `test_http_*` run `serve(ControlPlane(...))` over plain HTTP, no TLS, no edge secret (`:681-700`); the app refuses every non-operational route without `X-Heel-Edge-Auth` when a secret is configured (`http_api.py:787`) | T2a gate: test-only loopback TLS listener with ephemeral CA injecting the edge header, product unchanged except an explicit CA-bundle parameter unreachable from env/config; identity backend injected only through the existing constructor parameter from test code and labelled limited proof; separate real-Keychain restart acceptance required; no new env switch to insecure storage; the pre-existing `PYTEST_CURRENT_TEST` check in `identity.py:338` is recorded as a question for the T2a review, to be treated as a defect only with concrete runtime reachability evidence |
| 9 | Install command coherence (system Python, clean machine, dependencies, keychain, hash) | CONFIRMED | `requires-python >=3.11`, `runner` extra = `cryptography==45.0.7` (`pyproject.toml`); macOS `python3` is 3.9 (baseline items 2–3); `/tmp` venvs trip the inode guard (item 1); `mcp-quickstart.test.mjs:26` pins the exact `/agent` string; v1.3.0 release does not exist | §8.1: one fail-fast `&&` chain with version check, `$HOME` venv, `#sha256=` URL fragment bound to the wheel digest, explicit statement that the release does not exist yet, keychain fail-closed rule |

## 2. Other load-bearing gaps found and repaired

- §8.3 claimed "eight names" in `deploy/.env.production.example`; the file lists 12 keys, 6 of
  them secret-bearing. Corrected, and the Worker secret is stated to be the same value as
  `HEEL_EDGE_AUTH_SECRET_B64`.
- §2 row 7 contained raw `|` characters inside a table cell, breaking the row. Repaired
  (table width check: 0 mismatched rows).
- §12 T3 and T4 each list more than ten files; the T2b review must confirm or re-split them
  before T3 starts (candidate split recorded).
- §13 owners updated for the T2a/T2b split; row 11 adds T2b.

Not changed, deliberately: the data flow (§4), threat model (§5), the free-tier numbers (§9),
the clean-room script's structure (§11, one restart step added), the exclusions (§14). The
cloud/local trust boundary is unchanged: credentials, parameter values, raw OpenAPI and bodies
still never leave the runner machine, and the Worker still proxies to one build-time origin.

## 3. T2 prerequisite defects (must be true before an Opus session starts T2a)

1. CONFIRMED there is no runner-side control transport or CLI entry point; T2a builds both.
   Evidence: zero constructors of the three classes under `heel/` or `scripts/` (fact-check
   log), `heel runner --help` surface (`wheel-cli-surface.log`).
2. CONFIRMED `plan_label` has no home in the credential record; T2a adds it in `store.py`.
3. CONFIRMED the only HTTP pairing tests run without TLS or edge secret; T2a adds the
   test-only harness under `tests/support/`.
4. CONFIRMED `identity.py:338` admits an injected in-memory backend when `PYTEST_CURRENT_TEST`
   is set. Constructor injection is not itself a vulnerability; no CLI or daemon path selects
   that backend today (no product constructor exists, item 1). T2a must not extend it and must
   not add any env-selected backend; the review treats it as a defect only with reachability
   evidence.
5. INFERRED the Worker runner-route allowlist already covers everything T2a needs
   (`RUNNER_PAIRING_*`, `RUNNER_CONTROL`, `RUNNER_CONTEXT_CONTROL`, `RUNNER_REVOKE`,
   `worker/index.ts:146-158`); confirming action: `runner-edge-route.test.ts` run in T2a.

## 4. Next bounded assignment: T2a (fresh Opus)

Build `heel runner pair | status | unpair`, the HTTPS control transport, the optional
credential `--plan-label` (required only by the self-serve path, legacy records and CLI tests
unchanged), and the test TLS + edge harness, exactly as §12 T2a specifies. Allowed files:
`heel/cli.py`, new `heel/runner/daemon.py`, new `heel/runner/control_transport.py`,
`heel/runner/store.py` (credential record `plan_label` only), `heel/runner/identity.py` (label
namespace only), `heel/runner/__init__.py`, new `tests/test_runner_daemon.py`,
`tests/test_runner_cli.py`, `tests/test_runner_vault.py`, `tests/test_runner_identity.py`, new
`tests/support/edge_tls_harness.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Gate: §12 T2a (real
pairing integration test over the harness, reused-invitation / wrong-origin test, label-print
test, recorded real-Keychain restart acceptance), then focused → affected → full suites green
against the §1.2 baseline, signed small commits, then a fresh Fable review covering device-code
theft, invitation replay, rotation races, downgrade-to-http, CA-bundle reachability and the
`PYTEST_CURRENT_TEST` question. T2b follows only on PASS.

## 5. Verdict

**DESIGN PASS** for the specification as repaired in this revision: T2a is concretely bounded,
its gate is executable without fabricated state, and every remaining unknown is labelled. This
is not product or launch acceptance; nothing deployed, nothing merged, PR #41 untouched.
Residual external blockers are unchanged (§15 of the spec): hosting decision and legal
acceptance, each needed only when T7/T6 start.
