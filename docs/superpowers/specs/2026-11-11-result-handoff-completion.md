# Result handoff completion: a completed run that survives reload, and a redacted finding the customer can inspect and share without copying anything by hand

Date: 2026-11-11. Design base `7550b986` (candidate `1d069d16` = `7550b986` + the three-file follow-to-terminal patch). Released
comparison tree: `main` `17a1ea70` (public rc3 wheel `0b75aef7…`, tracked blob `7fcbeb66`). Author: Claude Fable 5.1, bounded
independent session CUSTOMER-RESULT-HANDOFF-FABLE. **Design only: no product code, test, configuration or build artifact
changed.** Decision owner: Astra (parent). Implementation owner: one bounded Opus 5.5 task (§7).

Every load-bearing claim is **CONFIRMED** (`file:line` at the named tree, a test id, or a sealed evidence artifact) or
**INFERRED** (with what confirms it). Proposed routes, schemas and functions are marked **(proposed)**; none exists.

## 0. What the live journey proved (evidence, not narrative)

| # | Fact | Status | Evidence |
|---|---|---|---|
| E1 | Run `crun_7d4865c0…` executed exactly two approved `GET /api/export` requests (free, then pro), both 200, 0 retries, 18 of 20 remaining; the runner finalized it `completed` and produced one medium finding, "Lower-plan read covered every key path of the higher-plan response" | CONFIRMED | `CUSTOMER-LIVE-RUNNER/private/39-runner-findings.json`, `40-run-local-summary.json`, STATUS Round 12 |
| E2 | The cloud accepted that terminal result: `GET …/canary-runs/crun_7d4865c0…` returns `status: terminal`, `execution_disposition: completed`, `scenarios_completed 1/1`, `requests 2/2`, `remaining_requests 18`, `local_result_ready: true` | CONFIRMED (parent capture, same-origin browser tab, no cookie export, no mutation) | `CUSTOMER-LIVE-BROWSER/candidate-terminal-cloud-readmodel.txt`; derivation `http_api.py:2634-2727` at `17a1ea70` |
| E3 | The deployed dashboard (old source `28c705`) showed "running 0/1, 0 requests" forever and lost the run on reload | CONFIRMED | `CUSTOMER-LIVE-BROWSER/candidate-completed-run-stale-browser.png`; cause in §1 |
| E4 | A regression was saved from that finding: `rreg_ecf6e767…`, and a replay `crun_05e7705b…` is at the approval boundary | CONFIRMED | `41-regress-add.out`, `45-status-after-submit.json` |
| E5 | `heel runner findings --run RUN` exists in the released tree and prints the store-verified `heel.local-result-view.v1` (`operational_projection`, `findings_projection`, `containment_summary`) plus one unsigned `evidence_states` list, as one JSON line; the trailing `rc=0` in artifact 39 is the capture harness, not CLI output | CONFIRMED | `heel/cli.py:1387-1390, 401-421` at `17a1ea70`; `regressions.py:133-145`; artifact 39 tail |

Everything the customer needs already exists on their machine and in the cloud's run row. What is missing is the last
two hops: the browser keeping hold of the run, and the redacted finding reaching the browser without a human carrying bytes.

## 1. Review of the candidate `1d069d16` (polling, counts, dead link)

Scope reviewed: the three files in the commit, read in full against the parent; the author's six logs re-hashed
against `SEAL.sha256` (all OK); the five focused tests re-run by this session in the candidate worktree (5/5, rc 0,
8.6 s). Full unit (482/3 skipped), typecheck, lint and node privacy-boundary (35/35) evidence is reused from the
author's sealed logs, not re-run.

Cause, CONFIRMED by code: `listPendingApprovalRequests` only returns runs `awaiting_execution_approval`; after
`approveRun` the page read `getRun` once and nothing re-read it (`page.tsx` before the patch). That single read is the
pre-receipt progress object (`http_api.py:2672-2684`: 0/1, 0 requests, full wall budget), which is exactly the
screenshot. The author's red run reproduces it (5/5 failed, `logs/01-red.log`).

Fix, CONFIRMED by diff: one effect follows the observed run's own `GET …/canary-runs/{run}` every 1 s while
`status ∉ {terminal, cancelled, expired}` and no approval is pending; generation ticket, abort on cleanup, visibility
gate, single in-flight request; 401 → session ended, 403 → reconnect, 404 → drop the run, `unavailable` → silent retry.
Counters rendered are only what `parseRunDashboard` returned (strict key check in `canary-api.ts:355`). The activation
card counts `terminal + completed` as step 4. The `http://127.0.0.1:7331/runs/{id}` link is removed; nothing in
`heel/runner` binds 7331 and `CompanionServer` binds `127.0.0.1:0` behind a bootstrap token and is wired to no command
(`companion.py:1-40`, CONFIRMED).

Checks requested by the assignment:
- Accepted counts are not fabricated: the only sources are `next.progress.*` from the read model; the test fixture
  mirrors `_canary_dashboard_progress` field for field. CONFIRMED.
- No auth, privacy or tenant weakening: no new fetch site (privacy analyzer pins fetch sites and route allowlist,
  35/35), no storage use, no new route, same `view`-role GET. CONFIRMED.
- Observations, non-blocking: (a) a persistent 403 re-runs `connect` once per tick; identical to the existing
  pending-approval poll's behaviour; (b) the server verifies two stored signatures on every status read
  (`http_api.py:2655-2704`), so 1 Hz per open tab is the cost ceiling and it stops at terminal; (c) `canaryAccess`
  is forced to `ready` while a run is past approval, display only.

**Verdict: scoped PASS for the polling/terminal-count/dead-link patch.** It is not launch acceptance of the result
handoff: on the candidate the completed run still disappears on reload (§2) and the finding is still reachable only
through a manual file transfer that the launch spec forbids (§3).

## 2. G1: the completed run survives reload

Constraint, CONFIRMED: browser storage is a forbidden capability (`privacy-boundary.test.mjs:1662`; onboarding tests
assert both storages stay empty). No read model lists a run once it leaves `awaiting_execution_approval`
(`http_api.py:1105-1124` routes; `canary_runs` has `claim`, `get_status`, events, no human list).

| Option | What changes | Verdict |
|---|---|---|
| (a) third opaque address ref `run=crun_<32 hex>` | client only: `account-context.ts` (today "never carries anything but the two opaque refs", `:73-80`), `dashboard/page.tsx`, two test files | **Recommended** |
| (b) server read model `GET …/projects/{p}/canary-runs/latest` (or `?latest=1`) reusing `get_status` + `_canary_dashboard_progress` | new human route in `http_api.py`, Worker allowlist regex, privacy-boundary route family test, `canary-api.ts` method and parser, page | Defer: correct, but it is a new API for a case (a) already covers, and it does not help the "share this run with a colleague" case, which (a) does |
| (c) browser storage | forbidden | Rejected |

Rules for (a) (proposed), each one a test:
1. `selectionFromParams` accepts `run` only when it matches `^crun_[0-9a-f]{32}$` **and** a well-formed workspace and
   project are present; `selectionQuery` serializes it third. The doc comment and the test "serializes nothing but
   the two refs" (`account-context.test.ts:122`) become "the three refs".
2. The ref is re-authorized by the existing `getRun` (view role, tenant-scoped, 404 for a run outside the project)
   after the context is server-confirmed; a 401/403/404 drops the ref from the URL and shows nothing.
3. A pending approval for a different run wins: the ref is ignored while `pendingApproval` is set.
4. The ref is replaced by the URL whenever `observedRun` changes (approve, follow, drop) and stripped on every
   workspace/project transition and on session end; it is never written to storage.
5. Reload of a URL carrying a terminal run renders "Rehearsal complete" with the read-model counts and the §3
   disclosure state; a foreign or purged run ref renders the setup steps, not a notice.

Limit stated: a customer who returns without the URL sees setup steps until the next run. The "latest run" read model
(b) is the follow-up if that is observed to matter; it is not needed for the first useful finding.

## 3. G2 + G3: inspect and share the redacted finding with no manual copy

### 3.1 Where the released system stops (CONFIRMED)

- The browser's only entry is a file input, "Load local summary", requiring a bare
  `heel.canary-findings-projection.v1` ≤ 256 KB with ≤ 4 `scenario_results` (`page.tsx:792-813`). The CLI prints the
  wrapper view (E5), so the customer would have to extract `findings_projection` by hand. After "Share" the page says
  "One-use disclosure permit created. Return to the local runner to upload this exact summary." (`page.tsx:826`).
- The released runner has nothing to return to: the only callers of `coordinator.upload_findings` are the replay of
  an already staged `upload-findings` call (`coordinator.py:156-176`) and `control_client.upload_findings`; no CLI
  subcommand (`cli.py:1596-1617`) and no `serve` loop path (`daemon.py:534-556` claims grants only) consumes a permit.
  The permit is therefore minted and never used.
- Even after a successful upload nothing renders it: `getFindings` (`canary-api.ts:852`, validated) is called from
  no page or component at `7550b986` or `17a1ea70`.
- The launch spec forbids this hop as acceptance evidence: "manual copying of evidence between machines"
  (`2026-10-18-self-serve-product-launch.md:685`, §11.1 item 3). The bridge spec already designed the cure, row 12
  "Permit without manual copying: runner polls `POST …/runners/{id}/runs/{run}/disclosure-permits/claim`"
  (`2026-10-18-self-serve-runner-bridge.md:421`, tasks T4b-c/T4b-r), and it never landed: no `permits/claim` or
  `disclosure-poll` route exists in `heel/` at `17a1ea70`.

What already exists and is reused unchanged:
- Server: `CanaryDisclosureService.preview` registers digest/count metadata, requires a terminal result and an active
  runner key, is idempotent for identical metadata and refuses different metadata with `canary_state_conflict`, and
  audits as `actor_class="runner"` (`canary_disclosure.py:276-390`). `permit` mints a 10-minute signed permit bound to
  workspace, project, run, grant, runner id + key id, projection digest, byte count and counts, owner/admin with recent
  auth (`:531-713`). `upload` consumes it once, re-verifies every binding against the stored approval, grant and
  receipt, and rolls back atomically (`:773-1040`; tests `test_canary_disclosure.py:318-614`). `get` returns the
  tenant-bound synchronized projection (`:1042-1071`). Human routes: `POST disclosure-permits`, `POST
  disclosure-local-only`, `GET findings` (`http_api.py:1119-1124`).
- Runner: `control_client.upload_findings` on the result chain under a runtime terminal-disclosure lease with staged,
  replay-safe calls (`control_client.py:1646-1838`); `coordinator.upload_findings` checks workspace, run, project,
  grant, anchor digest, permit TTL and the grant authority's signature before any byte leaves (`coordinator.py:885-937`).
  The runtime already keeps a `terminal_disclosures` row per run with states `local_terminal | available | consumed |
  prune_pending` and fields `permit_id`, `findings_projection_digest`, `receipt_digest`, `disclosed_at_ms`
  (`runtime.py:200-205, 628-648`). Evidence 40 shows the live run in state `available`.
- The local findings projection is the one the CLI prints: `store.load_final_projections(run)["local_view"]["findings_projection"]`.

### 3.2 Options

| Option | Handshake | Verdict |
|---|---|---|
| H1 bridge row 12 as written | runner polls a permit-claim route; the browser still registers metadata from a file | Incomplete: the file hop remains, still manual |
| **H2 one runner poll that registers and claims** | runner sends metadata (digest, bytes, counts) and receives the disclosure state or the permit in one PoP call; browser reads the disclosure state, decides, then renders `getFindings` | **Recommended**: one new runner op, one new human read, zero new tables, every check already written |
| H3 browser pulls the file from the runner | loopback companion or local HTTP | Rejected: `CompanionServer` is unwired, loopback from a Worker-served page is a new trust path, and the assignment forbids a companion rewrite without a proven blocker (none: H2 needs no local viewer) |

### 3.3 H2 handshake (proposed)

Runner → cloud, one new PoP operation on the run's result chain, capability `runner_result`, body ≤ 2 KiB:

```
POST /v1/workspaces/{ws}/runners/{runner}/runs/{run}/disclosure-poll
{ "schema_version": "heel.runner-disclosure-poll.v1", "run_id": "crun_…",
  "projection": { "schema_version": "heel.canary-findings-projection.v1", "projection_digest": "<64 hex>",
                  "byte_count": n, "scenario_count": k, "finding_count": f } }
```

Server (`CanaryDisclosureService.poll`, proposed): inside the caller's PoP transaction, `preview(...)` with the
runner's id and key (existing), then answer by the request row's status:

| request status | response (200 unless noted) |
|---|---|
| no row yet → created `local_result_ready`; or `awaiting_disclosure_approval` | `heel.canary-disclosure-state.v1 {run_id, status}` |
| `permitted`, permit unexpired | the stored `permit_json`, byte-identical `heel.disclosure-permit.v1` (already the runner's input schema) |
| `permitted`, permit expired | `_expire_unused_permits` (existing), then state `awaiting_disclosure_approval` |
| `local_only` | state `local_only` (runner stops polling) |
| `synchronized` | state `synchronized` (runner stops polling) |
| metadata differs from the registered row | 409 `canary_state_conflict` (existing code) |
| not terminal, revoked key, other runner, other workspace | existing errors: `canary_state_conflict`, `canary_authority_unavailable`, `canary_run_not_found` |

No findings bytes travel on this call; bytes travel only on the existing `result-projection` upload under the permit.

Runner (`serve`, proposed): each idle poll (2 s, `DEFAULT_POLL_INTERVAL_SECONDS`) after the grant claim, for every
runtime `terminal_disclosures` row in state `available` whose retention is unexpired and that has no pending
`upload-findings` call: build the metadata from the local findings projection, call `poll-disclosure` (staged on the
result chain like `upload-findings`, replay-safe because `preview` is idempotent and the permit answer is a read); on a
permit, call the existing `coordinator.upload_findings(run_id, permit, findings_projection)`; on receipt mark the row
`consumed` with `permit_id`, `receipt_digest`, `disclosed_at_ms` (existing fields); on `local_only` or `synchronized`
mark it so polling stops (the implementer uses the existing state transition; INFERRED that `consumed` without a
receipt is the intended spelling, confirmed by reading `runtime.py` state updates). Backoff: 2 s for the first 10
minutes after terminal, then every 60 s until retention expiry. `heel runner status --offline` is unchanged.

Cloud → browser, one new human read, view role:

```
GET /v1/workspaces/{ws}/projects/{p}/canary-runs/{run}/disclosure
→ 200 heel.canary-disclosure-preview.v1 (existing _preview_response: request_id, run_id, status, projection{…})
→ 404 canary_run_not_found while no request row exists
```

Browser (`dashboard/page.tsx`, proposed): once the followed run is terminal with `local_result_ready`, poll the
disclosure read every 2 s with the same generation/visibility/abort guards as the candidate's follow effect, until
status ∈ {`synchronized`, `local_only`}. Render by status:

| status | rail copy and control |
|---|---|
| 404 | "Waiting for the paired runner to report the local result." |
| `local_result_ready` / `awaiting_disclosure_approval` | existing `DisclosureDialog` opened from server metadata (scenario count, finding count, byte count); `outcomeCounts` becomes optional. "Share redacted summary" → existing `createDisclosurePermit` with the server's metadata; "Keep local" → existing `markDisclosureLocalOnly` |
| `permitted` | "Permit issued. The paired runner uploads the exact summary within seconds while `heel runner serve` is running." (no permit bytes shown) |
| `synchronized` | `getFindings` (existing) → new `FindingsCard`: per scenario the route, `assessment_outcome`, `finding.confidence`, `finding.title`, `recommended_control`, `reachability_rationale`, `regression_suggestion`, observations as `status_code` + `body_shape`, evidence refs as opaque ids. Nothing is derived client-side. |
| `local_only` | "Result kept local. No summary bytes were uploaded." (existing copy) |

The file input and `loadDisclosurePreview` are removed. "Share" is the explicit human approval already required by the
permit; it is not hidden and needs no admin. Inspect before sharing stays local through `heel runner findings`
(E5) and the dialog's counts; inspect after sharing is the dashboard card, visible to every workspace member with
`view`, which is the share.

### 3.4 Privacy and binding (what makes the cloud copy safe)

- The projection is the already redacted `heel.canary-findings-projection.v1` (forbidden-key check
  `canary_contracts.py:103`), signed by the runner key; raw responses and credentials never leave the machine
  (`local_evidence_refs` are opaque `ev1_` ids). CONFIRMED by E1 artifact content.
- Permit binding is digest, byte count, counts, run, grant, runner id + key, workspace, project, 10-minute TTL,
  owner/admin recent-auth actor, grant-authority signature. The runner refuses a permit for another workspace, run,
  project or grant and an expired one before sending (`coordinator.py:910-923`). CONFIRMED.
- The poll adds no authority: it is PoP-signed by the runner key on the result chain, identical to `upload-findings`.
  A forged or replayed poll can at most re-register identical metadata (idempotent) or receive a permit the forger
  cannot use without the runner's signing key and the lease.

### 3.5 Tests required (new ids; existing ones stay)

Server, `tests/test_canary_disclosure.py` and `tests/test_runner_control_http.py`:
- `test_disclosure_poll_registers_metadata_once_and_reports_state`
- `test_disclosure_poll_returns_the_byte_identical_permit_until_consumed_then_synchronized` (replay)
- `test_disclosure_poll_refuses_metadata_that_differs_from_the_registered_request` (forgery of counts/digest)
- `test_disclosure_poll_from_another_runner_key_or_workspace_is_not_found` (tenant/authority)
- `test_disclosure_poll_after_key_revocation_or_before_terminal_result_is_refused` (revocation)
- `test_expired_permit_is_not_returned_and_a_fresh_human_permit_is_polled_next` (expiry)
- `test_human_disclosure_read_is_view_scoped_and_404_before_registration`
- `tests/test_canary_http.py`: both routes in the control-path allowlist, body cap 2048, canonical-bytes check.

Runner, `tests/test_runner_coordinator.py` and `tests/test_runner_control_http.py`:
- `test_serve_poll_uploads_once_on_permit_and_marks_the_terminal_disclosure_consumed`
- `test_serve_poll_stops_after_local_only_or_synchronized`
- `test_staged_disclosure_poll_replays_without_a_second_registration_or_upload` (crash replay)
- `test_permit_for_another_run_workspace_or_expired_is_refused_locally_before_any_bytes_are_sent`

Browser, `apps/heel-cloud/tests`:
- `terminal-result-view.test.tsx`: reload with `run` ref restores the terminal view; foreign/404 ref dropped; disclosure
  state polled; dialog from server counts; share → permitted → synchronized → finding card from a fixture equal to the
  server schema; keep-local path; no `<input type=file>` remains.
- `canary-api.test.ts`: `getDisclosure` strict parse. `account-context.test.ts`: three refs. `account-onboarding.test.tsx:916`
  and `canary-activation.test.tsx`: label removed. `privacy-boundary.test.mjs`: new route families (human GET, runner POST).

### 3.6 Finite acceptance (the gate Astra reads)

1. Local gates exactly as the candidate: `vitest run` 0 failed, `typecheck` rc 0, `eslint` on changed files rc 0,
   `node --test tests/privacy-boundary.test.mjs` 0 failed; Python: `test_canary_disclosure.py`,
   `test_runner_control_http.py`, `test_runner_coordinator.py`, `test_canary_http.py`, `test_canary_privacy.py`
   0 failed; the three download artifacts regenerated and the release import/allowlist guards green.
2. One real paired journey on the existing runner root (`/private/tmp/heel-live-runner.EFLSzZ`, rc-next wheel,
   same pairing, no re-pair): approve the already submitted replay `crun_05e7705b…` or a fresh prepare; within 15
   minutes of approval the dashboard shows "Rehearsal complete", the disclosure dialog opens from server counts with
   no file chosen, "Share" is clicked once, and the finding card renders the finding whose title and digest equal
   `heel runner findings` output on the runner. Reload the tab: the run and the card are still there. Evidence: the
   `GET …/disclosure` and `GET …/findings` bodies, serve log lines, and the CLI output, all sealed.
3. Negative: a second "Share" after synchronization is refused with `permit_consumed`; "Keep local" on a second run
   leaves `GET …/findings` 404.

## 4. Non-goals, kept out on purpose

No pricing, no write operations against the target, no MCP, no browser capture, no local companion or loopback
viewer, no browser storage, no "latest run" list API (deferred, §2), no change to `heel runner findings` output, no
change to the permit or upload contracts, no admin or support path to findings.

## 5. Why a runner release is unavoidable (the proven blocker)

The assignment asked for no local rewrite unless a blocker is proved. The blocker is concrete: in the released tree
nothing on the runner ever consumes a permit (§3.1, CONFIRMED by exhaustive caller search). Any design that ends the
manual copy must give the runner a consumer, and that is a wheel change (rc4). H2 keeps it to three runner files and
reuses every verification already shipped. The dashboard-only parts (§2 and the §3.3 read/render) can ship first and
are useful alone only with the file hop, which stays forbidden for acceptance; so the order is server + runner, then
dashboard, under one owner.

## 6. Alternatives if the runner release is blocked

- A1 dashboard-only now: ship §2 (reload) and the §3.3 read/render; keep the file input but accept the wrapper
  `heel.local-result-view.v1` and extract `findings_projection` client-side, and add `heel runner disclose --run RUN
  --permit-file PATH` (one CLI subcommand calling the existing `coordinator.upload_findings`). Both hops are still
  manual copies; this is an engineering convenience, not launch acceptance, and the spec must say so.
- A2 bridge row 12 verbatim (permit claim only, file stays): same manual hop on the way in; rejected for the same reason.

## 7. Implementation owner, allowed files, order

One bounded task, Opus 5.5 medium, branch from `1d069d16` (so the follow-to-terminal patch is included), two commits
in this order, each with DCO sign-off and co-author trailer, no push:

Commit A, contract + server + runner (source 8): `heel/canary_contracts.py` (poll request validator, disclosure
read parser), `heel/saas/canary_disclosure.py` (`poll`), `heel/saas/http_api.py` (two routes, allowlist, cap,
validator map, capability), `apps/heel-cloud/worker/index.ts` (two allowlist regexes), `heel/runner/control_client.py`
(`poll-disclosure` op and response shapes), `heel/runner/coordinator.py` (`poll_disclosure`), `heel/runner/daemon.py`
(serve loop step). Tests: the five Python files in §3.5 plus `apps/heel-cloud/tests/privacy-boundary.test.mjs`.
Mechanical: the three download artifacts under `apps/heel-cloud/public/downloads` and the release manifest, with the
version decision (rc4) recorded by Astra before the artifacts are regenerated.

Commit B, dashboard (source 6): `apps/heel-cloud/lib/account-context.ts`, `apps/heel-cloud/lib/canary-api.ts`
(`getDisclosure`), `apps/heel-cloud/app/dashboard/page.tsx`, `apps/heel-cloud/components/canary/DisclosureDialog.tsx`,
new `apps/heel-cloud/components/canary/FindingsCard.tsx`, `apps/heel-cloud/components/canary/ActivationCard.tsx` (next
action copy). Tests: the five TSX/TS files in §3.5.

Anything outside these files is out of scope and returns to Astra. A fresh Fable review follows each commit; the
acceptance in §3.6 item 2 is run by the parent on the live runner after both reviews pass.
