# Managed Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Assignment-specific override: fresh bounded Opus implementation sessions only, fresh independent Astra acceptance before dependents, no self-review or same-session correction. This document grants no implementation, agent dispatch, publication or deployment permission.

**Goal:** Make every managed target request depend on its own durable CP admission and charge, remove reusable local authority, and demonstrate a useful customer journey without weakening retained safety or custody contracts.

**Architecture:** CP serializes terminal state and exact admissions in SQLite; root owns inert construction and exact process/namespace/handle association; the fixed executor validates private action/credential mapping and spends each receipt once before transport. Managed state is in-memory candidate data or historical evidence, never an active disk selector. Host composition waits for separately accepted H3 and a reviewed integration tree.

**Tech Stack:** Python >=3.11, sqlite3, existing Ed25519/cryptography runner extra, closed canonical JSON over peer-authenticated Unix channels, Linux namespaces/nftables, existing nginx/njs ingress, TypeScript/React Worker UI, pytest/Vitest/Node tests and pinned wheel/image builds.

---

## Status, source pins and precedence

Prepared 2026-11-02 by OpenAI Astra (gpt-6-astra); medium requested, no model/settings change. **Ready for fresh whole-plan review; implementation and launch NOT_ACCEPTED.** All packet designs below are **INFERRED obligations**, confirmed only by the stated future tests and independent acceptance. No test proposed below is represented as already implemented or passing.

| Alias | Exact pin / source | CONFIRMED meaning and limit |
|---|---|---|
| Q | `46cefba00192ea5fe3efb663fea89ee9561b6422`, tree `4b876d49445dfae06315a61c4127da7158f87e4e`; `docs/superpowers/specs/2026-10-30-managed-pairing-attempt-admission.md` | DesignPASS / FEASIBLE-TO-PLAN from `.worktrees/heel-task-evidence/C4-ATTEMPT-ADMISSION-REVIEW/REPORT.md` and `CLOSING.md`; F1/F2 closed at design level only. Q wins on per-attempt admission, wire versions/caps and raw fence. |
| EA | `c54f872a48f5ea85eab2b0279074b800e1519a61`; `docs/superpowers/specs/2026-10-29-managed-pairing-exact-admission.md` | Retain §§1–2, ceremony §4, consumer removal §6, restore §7, observations §8, real gates §10. Window-only authority in §§3–5/9 is superseded by Q. EA alone failed review. |
| S | `2a71221704f3b7b5d1f893df6ced5fb972b2cf57`; `docs/superpowers/specs/2026-10-27-managed-pairing-design.md` | Retain ceremony, nullability, predecessor, custody, cleanup and retry contracts, particularly §14.2; active file publication is superseded. This is historical failed correction 3, not an implementation base. |
| Observation | EA parent `ed901650ffd1042f6b36eaa7b5c0a270c4af9c00`; `docs/superpowers/specs/2026-10-29-managed-pairing-authority-domain.md` §7 | Exact observational object retained by EA §8; no current-authority assertion. |
| M | `86c612a7ada2f8cd563936c4b9ce0e15d5061c31` | Accepted H2 contract lineage; retain H1/H2 deadlines, STOP and namespace proofs. |
| B | `f736279a33bc1b8bd094e301ddd52045eb96a149`, tree `6274eb979880bec238fe7058d43597794c96880b` | Assignment's accepted-main implementation starting point. Actual files/package commands pinned in this task's `source-manifest.json`. |
| H | `d929888271ab2f14236ffc68a7d906c49fe48138` | UNACCEPTED H3 candidate; useful source inventory only. DNS review `01a185fe` remains waitingOnApproval; late-reply ownership concern is unconfirmed. No diagnostic restart, assumed PASS or silent cherry-pick. |
| Customer | B:`docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md` §§2,6; B:`docs/superpowers/specs/2026-10-18-self-serve-product-launch.md` | All 15 outcomes/12 properties retained with customer-ready amendments. C3 provider STOP is external, not a parser task or alternate-model route. |

Failed corrections `3793e4a5d38a5e384957eafeb4aec68ad4c766bc`, `933545930465fddf3937a14211aefac6153b3b13`, and S remain recorded. The 126 author schedules and 27 independent traces are planning aids, not SQLite/kernel/HTTP/browser proof. The model combined spend/dispatch and omitted lifetime uniqueness, first ordinal and actual retry failure witnesses.

**CONFIRMED discovery:** graph project `local repository graph` reports 10,666 nodes/33,882 edges; search returned AttemptPermit/execution_gate, not nested before_attempt. The short `heel` project was unavailable. Fixed-object reads supplied exact B/H files. Main has no `deploy/host/executor.py`, `executor_link.py` or `supervisor.py`; do not turn H witnesses into main claims. Evidence directory: `.worktrees/heel-task-evidence/C4-MANAGED-AUTHORITY-PLAN/` (source/command/hash manifests, DECISION and CLOSING).

## H6 R3 serialization status — PROPOSED plan amendment

2026-11-04, GPT-6 Astra (medium requested). The accepted plan baseline is `38e6bf1a3bc6ed2d923f878561140cda928b56d0`, tree `385b47e67c236aa0ce633d328dd6306ba8e1b405`, document SHA256 `405984bc838c04eb1f7f7338f0687cd0fd7db951a3dc5776b6489d7bc1812d2c` (C4-PRIVATE-PLAN-COUNT-R1-REVIEW). This amendment is **PROPOSED until fresh independent whole-plan acceptance**. It issues no implementation grant.

**CONFIRMED design authority:** H6 `3b03721a47d1e816d2ed082f62fdeeaa1429e1b1`, tree `626d6bd2306082b3b68ce257a2bd8a5920ac8c2f`, `docs/superpowers/specs/managed-host-handoff.md`, SHA256 `39b32f5a87ddaa343e70e812bd19499309d2d5dcec880bd4ea55846b69482456`, accepted by `.worktrees/heel-task-evidence/H6-HOST-INTERFACE-R3-REVIEW/ACCEPTANCE.json`, REPORT and CLOSING (70-file sealed review). Acceptance covers the whole exact design, A-LAUNCH/A-LOCK2/A-STORE2/A-FENCE2/A-RECON2/A-P02R2/A-ART3/A-ENR2/A-PREFIX/A-P15/A-RUN and the explicit Q §3/§6.7 / EA §4/§7 transport-authentication amendment. It accepts neither this plan mutation nor any inherited product ancestry or runtime backend.

The normative H6 transcript at the end reproduces H6 §§2–10 exactly; section numbers, `[B]`, `[H]`, `[R]`, `[P]`, `[U]`, P line references and witness filenames inside it refer to that immutable source and its own §0 alias table, not this amended plan's line numbers. Historical author wording such as “proposed” or “pending review” in the transcript records the source at authorship: the exact **design** subsequently passed the bound independent review, while this **plan amendment** and all implementation/runtime proofs remain unaccepted. H6 §§0–1 and §§11–14 remain normative by the same exact source pin, including all unknowns, amendment scope and ownership exclusions. The author ownership matrix is supporting evidence only. No excerpt, summary or static witness replaces any closed shape, cross-field constraint, callable, limit, error, measurement, real oracle or acceptance gate in that source.

The prior R3 candidate added only P05 `tests/test_host_enrollment.py` (107 entries) and failed whole-plan review F1. This F1 correction is PROPOSED: P02 adds `heel/saas/server.py` and `scripts/saas_backup.py` (4→6); P04 adds `heel/saas/canary_disclosure.py` (9→10); the separately counted CP-WRITERS packet below adds exactly ten entries. P01–P18 now total 110; with CP-WRITERS, 120. These are explicit scope proposals requiring fresh whole-plan review, not implementation grants. All other exhaustive lists, original B/M/Q/EA/S/H provenance, future I/J11 composition reviews, commercial/public boundary and download lane are retained. P01 PR70 still requires full source/CI/H2/runtime/composition acceptance before P02 can be granted; H6 design PASS alone does not unlock P02. H3/DNS and Worker reviews remain held; B0 image/private-runtime NO-GO and C3 STOP remain. Provider/billing/target authorization, backend F23 qualification, deployment, release and customer acceptance stay separate.

## Base matrix, ownership and dependency DAG

`B+n` means B plus only independently accepted predecessor packets. Record exact HEAD/tree before every grant. `I` is a **future unresolved hash**, not H: coordinator composes accepted CP work with actually accepted/remediated H3 and accepted H6-LAUNCH, then a fresh Astra reviews the merge/diff and inherited proofs. Record I commit/tree, H3 review/CI identities and conflict resolution before granting P09 onward. Any upstream change invalidates that manifest and requires focused revalidation of changed interfaces; never apply this documentation branch's inherited product code.

- Accepted-main chain: P01 → P02 → P03 → P04 → CP-WRITERS → P05 → P06 → P07. P08 follows P04 and can proceed on accepted main without H3; its artifact handoff must precede P10.
- Host chain: accepted P01–P07 + accepted H3 + accepted H6-LAUNCH + reviewed I → P09 → P10 → P11 → P12 → P13 → P14 → P15 → P16 → P17 → P18.
- P08 joins P10 (download writer handoff) and P16 (browser surface). The interface milestones and external implementation handoffs below join P11/P12/P14/P16/P17. C3 release of STOP, actual H3/DNS acceptance and deployment authorization join final P18 customer acceptance.
- Intermediate CP/host changes remain disabled for customer enablement; test fixtures alone exercise them until migration, runtime, artifact and final gates pass. No partially removed consumer composition is deployed.

All arrows mean **fresh independent acceptance**, not just authored commit or green unit tests. Shared file ownership is serialized by this DAG; P08 may overlap the CP-only P05–P07 branch, but never another download writer. P10 must include accepted P08 before writing downloads; external writers use the serialized handoffs below.

| Responsibility | Exclusive packet write owner (sequential handoff where repeated) |
|---|---|
| Closed codecs and shared inert contracts | P01 `heel/saas/managed_authority_contracts.py` |
| Runtime DDL/migrations and physical ledger | P02 `canary_store.py`, `migrate.py`, new ledger module; P05 consumes/extends ledger |
| CP ceremony and lifecycle | P03 new managed pairing module; P04 guards existing public/internal owners |
| Host listener and exact admission | P05 `host_authority.py`, `host_snapshot.py`, run claim/counters |
| Real storage/race harness | P06; full CP qualification P07 |
| Observation UI/API client | P08; real browser acceptance P16 |
| Exact root W/Q link/controller | P09 (I only) |
| Executor callback, permit spend and attribution | P10 (I only) |
| Historical backend and daemon selection removal | P11; root seed/ceremony P12 |
| H0 registry/nginx consumer removal | P13 |
| Migration/offline restore and listener fence | P14 |
| Real Linux integration proof | P15 |
| Download artifacts | P08 → P10 → C5-IMPL → C6-IMPL → P11 → P17; every intervening shipped-source writer regenerates at its own candidate |
| Final images/release/installed parity | P17; deployed clean-room journey P18 |

The exhaustive path list in each packet is the entire tracked write grant; paths marked new must not overwrite an upstream file. Read-only dependencies are not write grants. No recursive ownership wildcard. If another file becomes necessary, stop that packet and request a revised bounded grant with a fresh review. Excluded throughout: `.github/workflows/claude-review.yml`, `tests/test_review_workflow_security.py` (REVIEW-ACTION-PINS); CLOUD-FRAMEWORK-B-HARNESS and original/private framework evidence, build plugins, framework lock upgrades and model settings. Existing C5/C6/H6 product owner files beyond the explicit lists are external integration prerequisites, not hidden work in this plan.

## Composed behavioral contract (all INFERRED implementation obligations)

| Boundary | Required contract / oracle |
|---|---|
| T/G | T binds restore epoch, workspace, managed/pairing identities, runner/key, host boot and slot; G additionally binds generation/raw fence/process/namespace. Execution has no nullable identity. Root derives actual channel/process/handle; no caller-chosen namespace or DB path. |
| Signed vs private | CP verifies stored signed projection, manifest digest, ordinal, scenario/adapter, role/method/template, inventory/selection/plan limits and grant/binding. Template digest hashes canonical `{method,route_template}`. Executor rechecks full manifest action and exact fixture substitution; route digest hashes canonical `{method,route}`. Credential-binding digest hashes selected binding (anonymous canonical null), never secret bytes. CP cannot reconstruct private route/credential mapping from hashes. |
| Q | `(T,G,run_id,manifest_digest,W,action_ordinal,method,route_template_digest,route_digest,semantic_role,attempt,attempt_deadline_ns,operation_digest)`; W binds original operation and actual handle. Descriptor binds full action and credential selection. Request identity hashes all request fields except operation_digest; operation digest hashes descriptor, without a cycle. |
| Routes | Same peer-authenticated Unix owner; fixed POST `/host/v3/managed-operation`, `/host/v1/managed-attempt`, `/host/v3/managed-ceremony`. Browser/public runner cannot issue host receipts. Managed provenance rejects v1 snapshots, failed v2 routes and connector downgrade; connector-only semantics remain covered. Peer authentication is not run authorization. |
| Codec | Q §6 exact key sets and versions; ASCII sorted compact canonical JSON, duplicate/extra/noncanonical rejection, integer-not-bool, closed enum, nullable only inherited ceremony fields. Raw `secrets.token_hex(16)` hex32 is unchanged across producer, G row, W/Q/ceremony, response, descriptors and notifications. Existing H3 pin/revoke/fd-forward stays hex32; never hash/pad/truncate it into a replacement. |
| Sequence | Separate window and attempt high-water. Valid in-domain refusal consumes exchange sequence/disposition, no nonexistent charge/progress. Foreign/malformed request allocates nothing. Gap/reuse closes G. Duplicate tuple/nonce/receipt never replays executable authority. Terminal check precedes all replay and action. |
| Progress | Lifetime unique `(restore_epoch,run_id,action_ordinal,attempt)` independent of W/G. Initial ordinal=0; subsequent initial action increments exactly one; attempt 2 is latest charged attempt 1 before advancing, only after actual connect_error/timeout allowed by signed policy. Attempt 1 uses failure enum none. No failed-admission retry. |
| Admission | BEGIN IMMEDIATE on one connection, under-lock time, terminal joins then W/signed action then sequence/progress/quota/capacity then immutable insert+charge+high-water+revision, commit before response. R helpers never commit/nest transactions; no FS/network/key read in transaction. R changes bounded parents/auth state, never all historical attempt rows. |
| Charge | Claim reserves approved <=20 slots plus terminal obligations; request/retry charge occurs before local reservation, <=1 retry. Local lower counters cannot erase CP charges. Lost commit/reply is unknown: abandon run, no executable replay/reissue/refund. Unused reserved slots release only on terminalization; charged slots/replay fences persist. |
| Local machine | candidate→waiting→received→reserved→spent OR abandoned; one pending Q. Receipt matches exact pending T/G/Q/W/handle/process; cached gate vetoes only. Spend under request lock BEFORE actual `_one_attempt`, even if dial/write fails/unknown. Retry requires new CP charge. Late callback/worker completion cannot resurrect pending state. Restart discards maps and closes/fences prior G. |
| Race | R-first forbids A(Q), including fresh cached gate/open W. A(Q)-first permits only that Q once if original bounds and known STOP allow. R never waits for frozen host writer or cleanup. Pause after spend before physical transport explicitly; it cannot create Q2, renew W or bypass original deadline/STOP. |
| Deadlines | W E_lower=t_p0+3000ms−2tick, E_upper=t_p1+3000ms+tick; activation before E_lower and E_upper<=original D; exchange by min(original start+1000ms,E_lower). D_Q=min(W E_lower,W authority D,original transport request deadline,run start+wall timeout,callback entry+action timeout,nonrenewable proof/grant deadline). Retry retains original transport/run bounds. CP wall expiry and same-host elapsed-gap checks never compare remote monotonic clocks as wall time. Pending Q freezes W; expiry/change discards Q. |
| Storage | <=65536 installation-wide reserved-or-used lifetime attempt slots; 40-bit seen map/run, counters/progress/closed state survive G/restart. <=65536 generation rows; no fence TTL/eviction. Logical attempt 1092/2048 bytes; attempt logical allocation <=128MiB and generation addition <=256MiB share **512MiB physical ledger** incl indexes/metadata. Entire H6 footprint <=1GiB, admission <=896MiB, exclusive terminal reserve 128MiB. Include pages/freelist/all indexes/WAL/checkpoint temporaries and aggregate outstanding R obligations; blocked checkpoint stops admissions. No silent cap enlargement. |
| Restore | Trusted maintenance/enrollment fence outside restored volume; offline revoke all reservations (also null runner), keys/nonces/proofs/receipts/grants/runs/W/Q; rotate restore/enrollment domain, reconcile provenance, keep old hosts fenced. Neither HTTP nor Unix listener may publish before complete reconciliation. Interruption stays disabled; fresh pairing/binding/scan approval required. Ordinary restart is not epoch rotation; no universal antirollback witness is claimed. |

Exact byte witnesses retained from Q review: window request **1739/2048**, attempt/forward **2254/2560**, window/attempt response **1925/4096,2142/4096**, descriptors **736/2048,855/2048**, notifications **428/1024,520/1024**; ceremony offer/challenge **979/4096,1191/4096**, terminal/retired/identity **980/4096,835/4096,739/4096**, poll/none **412/4096,368/4096**. Header **8192**, one request/connection, backlog **64**, timeout **5s** (never a deadline extension). Payload sum 9728 per pending Q excludes copies/heap/socket workers; measure those, do not equate backlog with resident memory. Existing H3 claimed/pin/resolved caps and bodies stay unchanged (1723/2048,1126/4608,833/4352; small 663/1024, launch 719/1024).

### Retained ceremony/custody table

| Phase / condition | Identity and recovery rule |
|---|---|
| Unreserved key offer / fresh epoch | workspace/managed/pairing/runner/expiry null; slot/epoch/key/fingerprint nonnull. Preserve full predecessor completion separately; orphan counts against retained capacity. |
| Reserved pre-invite failure | workspace/managed nonnull, pairing/runner/original expiry null only if CP atomic no-invite fact is proven. |
| Post-invite pre-exchange failure | pairing and original expiry nonnull, runner null. Never infer no invitation from file absence. |
| Matched pending/identity observation | all adopted identities nonnull, original expiry immutable; identity observation authorizes nothing. Active spool/journal/config states are removed, not renamed. |
| Terminal/retired | Preserve adopted tuple/nullability/expiry, both retry/cleanup generations. CP reconciles exact pairing runner association before immutable terminal publication. No higher stale ack overrides terminal intent. |
| Predecessor/adoption | One current + one predecessor completion, predecessor only retired; persist chosen next epoch before seed generation; restart resumes it. Release predecessor only on durable successor adoption proving CP observed exact retired ack. No second unobserved predecessor. |
| Bounds | One live +16 retained/orphan epochs, 28KiB retained evidence union; retained record max4096 with maximal coexistence. 64 deliveries/10min, root ack at bounded cadence (10s), six cleanup attempts at 1/2/4/8/16/32s within persisted 10min. Authorized retry >=600000ms apart; delivery raises retry_generation only; failed-cleanup retry raises both generations. Completed tuple re-acks without repeated cleanup, unchanged completion time. No reboot reset. |
| Custody | Root seed backend is separate from target credential vault and encrypted historical evidence. No secrets/secret-derived receipt values in CP/logs/model. No CLI/env switch selects trusted managed signer. C5/C6 own deletion/legal hold/retention; H6 owns provisioning/quota. No deletion to make replay capacity. |

## Common packet procedure and economical verification

Every packet owner is **fresh Opus**. Each correction is another fresh bounded Opus session; every acceptance is **fresh independent Astra**, never the author. Each packet must complete these ordered steps (the packet-specific tests below instantiate steps 2–4):

- [ ] Record exact base/tree, predecessor review IDs, allowed diff and private evidence directory; check free space >=5GiB internal and >=2GiB external. No HOME/home/CODEX_HOME or global-profile changes. Private runtime/cache/TMPDIR only; reuse verified runtimes read-only.
- [ ] Write named negative and useful positive tests first/with code; run the packet's focused command. Establish a behavioral red result (not missing dependency/collection error), save it and the relevant existing baseline. No production implementation in Markdown.
- [ ] Implement only the stated behavioral delta in allowed files. For a shipped-source packet, run `python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads` before affected/full tests; preserve baseline behavioral-red evidence separately. Stage only the exhaustive paths and DCO-sign the candidate (packet commit command below, executed here). This candidate is unaccepted pending verification. No uncommitted source/artifact substitution.
- [ ] Record clean HEAD/tree. Run focused green, affected-package verification and the full required suite on that exact committed candidate under the shared lock. Python: `python -m pytest -q tests`; web: the ordered UI sequence below (never `npm run test` before build). Shipped-source packets also run deterministic `--check` and `tests/test_open_core_release.py` unchanged. A repair produces a new committed candidate and new affected/full evidence; no tests of an earlier tree certify it.
- [ ] Record collected/pass/fail/skip reasons, exact runtime and output hashes. CI Python matrix 3.11/3.12/3.13/3.14 remains required. Reuse identical-candidate evidence only with hashes; optional-tool skips never establish release coverage. Final DCO/Opus trailer, diff/check and clean status must match the tested commit. Fresh independent Astra accepts or blocks; no successor on author assertion alone. The repeated packet commit checkbox verifies this already-created candidate, not a second post-test commit.

Heavy command execution must hold `fcntl.flock(LOCK_EX)` on `/private/tmp/heel-launch-full-pytest.lock` for the subprocess lifetime, preserve exit status, and check both space reserves before/during work. Use a private harness wrapper (not a product edit); create mode0700 scratch on the external volume, keep runtime/cache inside it, release lock and reap only owned processes on exit. Lock acquisition is bounded/reportable; do useful independent work or return HOLD, never run concurrently to bypass it. Exact subprocess argv above and below are authoritative. No network/kernel/customer tests in this planning session. Future real fixtures/proofs require their authorized environment; unsupported platform is BLOCKED, not a skipped success.

Affected packages: CP=`python -m pytest -q tests/test_canary_*.py tests/test_runner_control_http.py tests/test_runner_context_bindings.py tests/test_host_authority.py tests/test_host_snapshot.py tests/test_saas_http_api.py tests/test_saas_server.py`; Runner=`python -m pytest -q tests/test_runner_*.py tests/test_canary_contracts.py`; Host=`python -m pytest -q tests/test_host_*.py`; UI=the complete ordered clean-build sequence below, including browser prerequisites and Node artifact consumers. These existing paths/scripts were read at B; new focused tests are explicitly proposed below. On I, append accepted H3 test paths without pretending they exist on B.

### Download ownership and retained packet bound (F1)

**CONFIRMED at B:** `release/open-core-v1.json` enumerates shipped inputs; `scripts/build_open_core_release.py` defines the three exact names listed in each shipped-source packet. Intersecting every packet list with all manifest input categories yields P08 (`heel/cli.py`), P10 (`heel/runner/{coordinator,execution,http_transport,adapters}.py`), P11 (`heel/runner/{store,daemon,coordinator,execution}.py`), and P17 (release build inputs). Private CP/root code, heel/saas/managed_authority_contracts.py and heel/saas/managed_backend.py are excluded from the public release. Preserve their existing commercial classification. Only private CP/host entry code and their own tests import these modules. Public runner code accepts injected callables/structural values; no literal, conditional or dynamic private import or codec copy. A public inclusion requires an explicit human license/publication decision as well as a revised reviewed grant; no implicit allowlist expansion at P17. P01 changes no public shipped input: verify deterministic byte parity of all three downloads before affected/full verification and leave them unchanged if equal. Any approved shipped-input change requires exact three-download regeneration in that owning packet before affected/full verification.

P08 → P10 → C5-IMPL → C6-IMPL → P11 → P17 is the download-writer lane. C5/C6 own their regeneration before their own tests; a later C3/DA shipped change must be inserted as an accepted writer after P15 and before P16, with downloads regenerated and all affected proofs revalidated. No parallel branch merge of binary artifacts: compose accepted source, regenerate, commit, check, independently review. External ownership manifests must account for every shipped input before dispatch. P17 performs final image/release composition and clean installs, not the first parity restoration.

Retained bound: ≤10 nonmechanical tracked files plus three mechanical downloads (Customer §7). Counts include tests/docs, not only `.py`. Exhaustive packet entries after correction: P01=7, P02=6, P03=3, P04=10, P05=6, P06=3, P07=1, P08=11 (8+3), P09=5, P10=9 (6+3), P11=10 (7+3), P12=5, P13=6, P14=6, P15=4, P16=4, P17=13 (10+3), P18=1; total **110 entries**. These 110 entries count P01–P18 only; the explicit CP-WRITERS ten-path scope makes **120 combined entries**, excluding unchanged H6 external producers and separately bounded inventory packets; no packet exceeds the bound. Every future tracked heel addition or removal also requires a serialized, explicitly granted H2 inventory/proof update before acceptance. Before granting such a packet, enumerate tuple/count/doc/test changes and either include them within its <=10+3 bound or insert a separately reviewed bounded inventory packet; do not silently expand P04/P17. Recount the exact plan/grant ledger then. External packets are separately counted before grant.

**CONFIRMED at B:** H2 `HEEL_TREE_FILES` equals the sorted tracked `heel/` tree (109 paths). Packets already listed here that add a tracked `heel/` path are P02 `heel/saas/managed_authority_ledger.py`, P03 `heel/saas/managed_pairing.py`, P11 `heel/saas/managed_backend.py` and P14 `heel/saas/managed_restore.py`. **INFERRED obligation:** before each of those grants the parent names the inventory owner and scope: either the packet's own fresh Opus author with exactly `scripts/host_h2_policy_proof.py`, `tests/test_host_h2_policy_proof.py` and `docs/saas/H2_POLICY_PROOF.md` added to its exhaustive list (P02 6→9, P03 3→6, P14 6→9, then recount this ledger), or a separately granted fresh Opus inventory packet limited to those three paths, composed serially onto that packet's exact candidate before its affected/full suites. P11 currently lists 10 entries (7 nonmechanical + 3 mechanical downloads); its H2 inventory update must nevertheless use the separately granted three-path packet as an explicit serialized ownership requirement, with both scopes frozen and recounted before grant. Proof gate either way: exact ordered tuple/count/doc with missing/extra/byte-change controls, affected/full suites on the composed exact tree, fresh independent Astra review, and a coordinator-authorized fixed-ref real H2 run (all 18 cases/eight p0–p7 records/zero skips) on the new exact closure before that packet's acceptance; record H0 whole-tree impact. `deploy/host` additions (P12, P14) do not change `HEEL_TREE_FILES` at B but are checked against the then-current H2 STAGE_FILES and H0 STAGE_PATHS before grant. These inventory entries are not part of the 110/120 counts.

### Runtime, build and release prerequisites (F2)

**CONFIRMED sources:** B `apps/heel-cloud/package.json`, lockfile, `.github/workflows/ci.yml` browser-alpha/package/test jobs, `build/deployment-config.ts`, `scripts/prepare-runtime.mjs`, Node production-artifact/browser-engine consumers, release tests and hash lock. Commands below are future execution instructions, not planning-session runs. Use exact accepted candidate source and a fresh private scratch/venv/cache. Resolve and record absolute `python`, `python3`, `node`, `npm` executables, versions and hashes before testing. Python and Node-spawned `python3` must both resolve to the private supported Python 3.13 venv (matrix separately covers 3.11–3.14). Put its bin first in process-local PATH, followed by the verified Node distribution bin; do not inherit macOS system Python. Node 26 is the CI browser reference and satisfies package `>=24.13.1`; pin its actual patch/distribution checksum and bundled npm version in the packet runtime manifest before install (CI currently pins only major 26, not a claimed exact accepted patch). A missing verified runtime is prerequisite HOLD, not behavioral red. No runtime/global profile mutation.

Install Python test prerequisites in the private venv as B CI: `python -m pip --isolated install --only-binary=:all: cryptography==50.0.1 pytest==9.0.2`, with `PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1`; download `dnspython==2.8.0` using `--only-binary=:all: --no-deps` to private scratch, verify wheel SHA256 `01d9bbc4a2d76bf0db7c1f729812ded6d912bd318d3b1cf81d30c0f845dbf3af`, then install with `--no-index --find-links` that directory. Record all resolved transitive versions. This describes existing CI coverage, not a new claim that its entire environment is hash-locked.

From repository root, under the common lock, with private npm cache/TMPDIR and no reused `dist` (move aside only this checkout’s prior generated output, or use a fresh candidate checkout), execute in order:

```sh
npm --prefix apps/heel-cloud ci --ignore-scripts --no-audit --no-fund
python scripts/build_browser_engine.py --output apps/heel-cloud/browser-engine --check
python scripts/build_browser_sample.py --check
python -m unittest tests.test_browser_engine_build tests.test_browser_review tests.test_browser_sample tests.test_browser_native_parity -v
npm --prefix apps/heel-cloud run test:unit
npm --prefix apps/heel-cloud run typecheck
npm --prefix apps/heel-cloud run lint
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=00000000-0000-4000-8000-000000000001 HEEL_PUBLIC_ORIGIN=https://heel.example npm --prefix apps/heel-cloud run build
npm --prefix apps/heel-cloud run test:node
```

The checked-in browser engine wheel and sample must pass checks before build; `prebuild` copies validated runtime/downloads. Do not silently regenerate unowned engine/sample assets. `test:node` covers actual Pyodide under Node and the just-built `dist/client`/`dist/server` artifact; hash those outputs with the source commit, package lock and nonsecret build fixture environment. Unit/typecheck/lint prove source contracts only; fixture build/Node tests prove artifact contracts, not a deployed browser/customer journey. P08/P13/P16/P17 and any external web writer use this sequence. Run this UI sequence before the first P16/P18 focused browser command, not only in the later affected-package checkbox. P16/P18 additionally require the separately reviewed browser-harness dependency/Chromium binary hashes, fixture HTTPS CA, real CP/root/Linux environment and private runtime endpoints before invoking their browser command; no browser install/build is performed in planning.

P17/P18 required release gates use a fresh Python 3.13 release venv with the candidate's `release/requirements-release.txt` and **both** enforcement flags, including when the full suite is run:

```sh
PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1 python -m pip --isolated install --require-hashes --only-binary=:all: -r release/requirements-release.txt
python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
HEEL_REQUIRE_STANDARD_BUILD=1 HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m unittest tests.test_open_core_release tests.test_public_runner_preview_release -v
HEEL_REQUIRE_STANDARD_BUILD=1 HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m pytest -q tests
```

The lock supplies build 1.5.0, setuptools 84.0.0, wheel 0.48.0, twine 7.0.0, cryptography 50.0.1 and hashed transitive tools. Also perform B CI package job's source-free wheel install/MCP lifecycle (`--no-index --no-deps --no-cache-dir`, isolated `-I`, no PYTHONPATH/PYTHONHOME) and enforced runner-extra install/two synthetic outcomes. Standard sdist rebuild and installed-runtime checks must actually execute; missing index/tooling/platform yields release HOLD/FAIL, never optional skip PASS. Earlier local full suites report each optional skip and coverage limit; CI package gates close those release obligations. CI checkout/merge identity must match the candidate evidence. Build/action pinning remains separately reviewed; this plan does not certify unaccepted pinning work.

### External interface milestones and acyclic handoffs (F3)

Except H6-IF R3 design acceptance pinned above, interface milestones remain **INFERRED proposed deliverables** with exact hashes unresolved until discharge. None is an accepted implementation. Each named `*-IF` is a separately reviewed interface-only document with one exhaustive tracked write path specified below; it grants no product edits. Fresh bounded Opus authors; fresh independent Astra accepts the entire interface. Record mandatory `ACCEPTANCE.json` in that milestone’s evidence directory with base/commit/tree/document SHA256, exact symbol/line map, closed input/output fields and limits, error/terminal/retry semantics, exhaustive future implementation write list, per-file ownership edges, named positive/negative test oracles, and independent review ID/verdict. An unspecified future contract, existence of a path, or author assertion does not discharge it. Changes to accepted Q require separate design review, not this handoff; the exact H6 R3 A-ENR2 transport amendment has that design acceptance, subject to this proposed plan serialization and subsequent bounded grants.

| Milestone / producer / earliest inputs | Exhaustive interface-only write path and required deliverable | Consumers and acceptance oracle |
|---|---|---|
| C4-IF / C4 interface author / accepted P01–P07, Q/EA/S; no H3 or full C4 prerequisite | `docs/superpowers/specs/managed-authority-custody-interface.md`: freeze inert callback/managed-entry, credential-handle and historical-evidence boundary. Map B `RunnerExecutionAdapter`, `PreparedAction`, `AttemptPermit`, coordinator/execution/store/vault entry points and P01/P05 schemas. Specify bindings `{restore_epoch, workspace_id, project_id, environment_id, runner_id, runner_key_id, run_id, action_ordinal, attempt, operation_digest, credential_binding_digest}`; opaque transient secret resolution only within executor; no receipt or history can authorize. Exact callable signatures, closed error union, lifecycle/nullability and size limits are the required reviewed deliverable, not invented code here. | C5-IF/C6-IF/DA-IF; independent source/signed-vs-private mapping and mutation-test design review. Interface acceptance is not useful-run or customer acceptance. P01 remains independent of external runtime milestones; P02 additionally requires the accepted H6 design and fresh whole-plan acceptance of this serialization before its grant. P05 consumes that same H6 contract; neither waits for H6-RUNTIME. |
| C5-IF / custody owner / C4-IF + recorded custody decision | `docs/superpowers/specs/managed-credential-handoff.md`: exact Customer §§2.4/3.6/5.3 intake→claim→vault→login→delete interfaces, mapped to B `vault.py`, `catalog.py`, `execution.py`, `compiler.py`, `control_client.py`, `http_api.py`, migrations. Metadata `{identity_id, role_slot, plan_label, profile, created_at_ms, intake_state}`; intake reply only `{identity_id,state}`; ≤4KiB secret, ≤10s transient intake; AEAD associated tuple `{workspace_id,project_id,environment_id,identity_id,intake_request_id,runner_key_generation}`. Define one-use claim, failure/replay, delete_pending versus executor `deleted_at_ms`, revoke/expiry deletion. Include Customer §3.6 exact confirmed login declaration and DA-IF dependency. | C5-IMPL then P11/P12/P16/P17/P18. Interface review must trace secret lifetime and every sink, wrong tenant/role, replay/timeout/delete cases; C5-IMPL must supply actual vault/intake/deletion evidence before P11. Login runtime waits for DA-IMPL, not a broadened Q. |
| C6-IF / evidence owner / C4-IF (+ C5-IF for pairs) | `docs/superpowers/specs/managed-evidence-handoff.md`: exact persistence→redacted projection→audited view→save/replay→delete/retention interface, mapping B `execution.py`, `store.py`, `findings_sync.py`, `regressions.py`, `canary_disclosure.py` and Customer §§2.4/6.1/7.1 C6, bridge T4b/T5. Bind raw record to C4 tuple/containment; freeze projection schema/version, evidence refs and viewer authorization, no raw body at CP; ≤256KiB scan response/≤20 per run, seven-day `FINDINGS_RETENTION_MS`, immediate evidence deletion/revoke, transient discovery discarded by round end. Preserve applicable legal hold and disclose any delete-pending state. | C6-IMPL then P11/P16/P17/P18. Interface oracle: trace real record to projection and authorized view, cross-tenant denial, tamper and restart, bounded retention/deletion, saved vulnerable fail→patched pass regression; no injected verdict. |
| H6-IF / host provisioning owner / Q/EA/S and accepted host facts; no full C4 dependency | `docs/superpowers/specs/managed-host-handoff.md`: exact numeric UID/GID ownership matrix for root/signer/executor/vault/evidence/epoch parents; modes/mounts/quota and aggregate 1GiB/896MiB/128MiB reserve; outside-restored-volume maintenance and enrollment domain API, fence/ack/failure semantics, old-host denial and provider capability/STOP/restore facts; map EA restore §7, S custody §14.2, `deploy/host` entry and `deploy/compose.yaml`. Required output is concrete provider/runtime fact manifest with evidence and unknowns, not assumed capable hosting. | Accepted H6 R3 serialization: P02 schema; P05 authentication/capacity; P06 physical qualification; H6-LAUNCH before I; P11 storage; P12 seed/epoch; P14/H6-RUNTIME fence, artifact/channel and restore; P15 integration; P17/H6-IMAGE. Missing provider/billing/secret access holds dependent runtime work only. Review separately verifies ownership and storage contracts; actual provider claims require H6-RUNTIME evidence. |
| DA-IF (discovery/login companion admission) / C3 discovery owner + C5 custody owner, one bounded Opus document author / C4-IF+C5-IF+C6-IF, accepted discovery contract; C3 STOP unchanged | `docs/superpowers/specs/managed-discovery-login-admission-interface.md`: separately reviewed complete closed admission/receipt/charge/spend schemas for discovery GET/HEAD and narrowly authorized login POST, exact CP/root/executor entry points and allowed files. Bind discovery authorization/round/issued action and login identity/confirmed declaration/authorization to T/G, exact pending operation, original deadlines, target and one-use spend; allocate distinct accounting and replay domains. Prove Q scan GET/HEAD and ≤20 limits unchanged, no cross-domain receipt use, no reusable permit. Carry Customer §§3.4–3.6 budgets: ≤5 rounds/100 issued actions, 120s total active execution/15min TTL, one round pending, transient ≤2MiB/body, ≤8MiB/round/32MiB/authorization; separately authorized ≤1 login POST/identity/discovery authorization or scan run, 3/hour/identity, no login raw-body evidence, prelogin GET charged. Define commit-before-reserve, spend-before-dial, terminal-before-replay, original deadlines/STOP and physical-storage/R-reserve composition for both domains. | DA-IMPL then default P16/P18. Interface must have maximal byte witnesses, independent mutation/race/replay/budget tests and real transport oracle plan; independent design acceptance mandatory before implementation. No parser, provider routing or alternate model work authorized; implementation remains blocked until C3 owner clears STOP. Failure to compose within retained bounds returns to interface review; no widening Q. |

**Implementation handoff procedure (mandatory before each external grant):** C4-IF is a smaller planning/contract milestone, explicitly NOT completion of P01–P18 or the historical C4 customer journey. Customer §7.1 C5/C6's C4 prerequisite is discharged for interface preparation by C4-IF and for runtime integration by the staged exact candidates below; final historical C4 detection/discovery gate still belongs to P18. This decomposition requires independent whole-plan/interface review, not a silent assertion that historical gates passed.

C5-IMPL runs after P10, C5-IF, DA-IF, H6-IF and custody authorization; C6-IMPL after C5-IMPL and C6-IF; coordinator composes those accepted commits into **J11**, independently reviews conflicts/changed Q proofs and pins commit/tree before P11. C5-IMPL owns the exact Customer §7.1 C5 ten-file list plus the three downloads; C6-IMPL must expand bridge T4b-c/r/u/T5 and `canary_disclosure.py` into exhaustive per-packet lists in C6-IF, split ≤10+3, and receive review before any write. No wildcard ownership grant. This deliberately leaves concrete new callable schemas to the named bounded interface review, not to an implementation improvisation. Their actual custody/persistence interfaces must be usable without waiting for P11; P11 injects them into the historical backend. Login/discovery-specific runtime activation remains disabled until DA-IMPL; this is not completion of all C5 customer acceptance.

Shared-file handoffs are compulsory: migrations P02 → C5-IMPL → C6-IMPL; `http_api.py` P04 → C5-IMPL → C6-IMPL; `execution.py` P10 → C5-IMPL → C6-IMPL → P11; `coordinator.py` P10 → C6-IMPL (if its reviewed list includes it) → P11; `store.py` C6-IMPL (if included) → P11; `http_transport.py` P10 → DA-IMPL; `compiler.py`/`canary_contracts.py` C5-IMPL as granted → C3/DA-IMPL as separately granted. UI `worker/index.ts`/`canary-api.ts`/dashboard P08 → C5/C6 UI subpackets as explicitly listed → P16. Executor host code P09 → P10 → P11 → P12 → P14: external authors provide reviewed interfaces/facts and do not write these paths without a revised serialized grant. H6-IMAGE supplies digest/hash-lock/mount/entrypoint facts without writing P17 image/config paths. P17 exclusively owns final `Dockerfile.executor`, control-plane Dockerfile, compose, release builder/allowlist and CI changes under this plan, writing the control-plane Dockerfile and CI only after B0's accepted frozen handoff (Private delivery contract below). Every other external path must appear exactly once per handoff stage in its accepted ownership manifest; unknown overlap blocks that external grant, never enlarges a C4 packet implicitly.

H6-RUNTIME supplies actual provider fencing, UID/storage, STOP/pause and pre-restore maintenance evidence before P14; H6-IMAGE supplies immutable base digests, dependency lock hashes, entrypoint and provisioning/rollback inputs before P17, not a prebuilt P17 output. DA-IMPL is a separate accepted bounded series after P15, DA-IF and C3 clearance, with any changed P10–P15 proofs rerun on its exact candidate before default P16. Its source/artifact owners are discharged by DA-IF's exhaustive manifest and reviewed composition. P16 Q-only synthetic integration may run while DA is held, but must report default acceptance HOLD; P18 requires actual DA/C3/C5/C6/H6 runtime and customer authorization, not just interface documents.

A topological witness is P01–P07 → C4-IF → C5-IF → C6-IF/DA-IF; independently accepted H6-IF R3 → fresh plan amendment acceptance → P02; accepted H3+H6-IF+plan acceptance → H6-LAUNCH; accepted P05+H6-LAUNCH+provider authorization → H6-RUNTIME; accepted merged B0/BIR handoff+H6-IF+plan acceptance → H6-IMAGE; P04 → P08; P07+accepted H3+H6-LAUNCH → I → P09; P09+P08 → P10 → C5-IMPL → C6-IMPL → J11 → P11 → P12 → P13; P13+H6-RUNTIME → P14 → P15; P15+DA-IF+C3 clearance → DA-IMPL → default P16; P16+H6-IMAGE → P17 → P18. No producer requires full P18 as an input. A later request for such an edge is a dependency defect requiring a reviewed correction. Provider/billing/secret holds do not block independently accepted-main codec work after whole-plan acceptance.

### Private delivery contract (P01 classification amendment)

This subsection resolves the original non-saas placement contradiction without public relicensing. It is an implementation obligation, not evidence of an existing managed image or accepted runtime. Accepted Q and Customer2026-10-19 authority, all15 outcomes/all12 properties remain unchanged.

P02–P07 private CP consumers import the single codec from heel.saas. P09 private deploy/host entry/link/controller and P12 ceremony do likewise; re-resolve launch ABI on accepted H3 at reviewed I. P10 deploy/host/executor.py owns the private managed admission adapter using the bound ExecutorLink. It injects the required service through P10's public coordinator/execution/adapters interfaces. P11 creates heel/saas/managed_backend.py (not heel/runner/managed_backend.py) and injects it only from that trusted private entry. No new adapter source file is granted; if one is needed, recount/review before grant.

C4-IF must freeze exact callable signatures, structural values, closed errors, size/lifecycle/nullability and original deadlines before P10. The current before_attempt(attempt, previous_failure_code) and deadline-only AttemptPermit are not sufficient managed authority. Preserve P10's required receipt-bound permit: private adapter owns canonical wire codec/receipt matching, full manifest/route/credential metadata association and live pending map; public transport consumes the returned structural single-use capability under its lock before _one_attempt, rechecks cancellation/original deadlines/exact association, and cannot mint authority from history. Charge precedes reservation/action_started. No managed fallback to connector permit or caller-selectable mode. No duplicate wire implementation in public runner. P11 retains C5/C6 custody interfaces and connector recovery without managed active selection.

P17 deploy/Dockerfile.executor must create a source-free immutable runtime prefix `/opt/heel`: exact public wheel content under that prefix, exact reviewed private closure under `/opt/heel/heel/saas`, exact host entry closure under `/opt/heel/deploy/host`, commercial notice, and H6-reviewed hash-locked dependency closure available to isolated Python. Its Docker build uses pinned reviewed sources automatically; no customer/admin copying or checkout mount. No private pip package or registry availability is assumed. H3 inventory's `python -I -S -B` and package-root relative lookup require this coherent prefix; a venv site-packages install alone is not proof. Revalidate actual accepted I ABI before implementation. H6-IF governs ownership/mount/CP DB and key exclusions; packaging source is not permission to expose privileged state. Provisioning must consume this hashed artifact, not a repository checkout.

P17 CP image packages the same codec bytes in its private application closure and verifies its public runner files match the delivered wheel; no duplicate public package shadow. B0's current COPY heel is a static packaging witness, not image acceptance. P17 tests/test_managed_artifact_parity.py must record source→installed hashes, wheel identity, dependencies, image digests, exact entry argv/cwd and module origins with no PYTHONPATH/PYTHONHOME/repository mounts. Positive private codec/backend import and actual useful Q-authorized GET pair/retry/HEAD execution must work from image only. Missing codec/backend/adapter, forged/stale/duplicate receipt, wrong private route/role/credential and known STOP refuse without connector fallback. Public wheel clean install without saas must separately perform authorized connector flows. P15/P16/P18 actual runtime/browser/target/evidence gates remain mandatory; source stubs and injected verdicts cannot substitute.

B0 exclusively owns deploy/Dockerfile.control-plane, deploy/requirements-control-plane.txt, tests/test_saas_deployment.py, scripts/verify_control_plane_image.py and .github/workflows/ci.yml until independent source and exact-tree CI image acceptance, then freezes those blobs. P01 edits none. Coordinator qualifies composed B0+P01 full/package/image results on actual merge identity. P17 later serially owns its Dockerfile/CI changes, consumes other three support inputs read-only unless separately granted. No concurrent CI edits or pending-review bypass.

Temporal ownership: one-file amendment author→fresh independent reviewer→parent exact correction grant→fresh Opus P01 correction→fresh source review→separately authorized CI/H2/H0/image gates as applicable. Future heel additions each receive bounded serialized inventory owner and fresh-closure gate before acceptance; no wildcard authority. Existing P08→P10→C5→C6→P11→P17 download lane stays because P01 A changes no public input. Any intervening public-byte change must receive explicit artifact ownership before affected/full verification. P17 is final composition, not deferred repair.

Managed execution remains default with customer signup/URL/credential/approval, discovery and actual findings; optional released local connector retains authorized mode and safety restrictions. No customer Python/source/OpenAPI prerequisite, manual seed copy, hidden admin step or invented package. Preserve C3 STOP, pending DNS/reviews, H3/H6/C5/C6/DA gates and both clean-room layers including second target. This amendment grants no implementation, license/public distribution, deployment or runtime acceptance.

## Packet P01: Closed private managed contracts and route codecs

**Owner:** fresh Opus; fresh Astra independently reviews. **Base:** correction of unaccepted candidate 5fa01be88013cded564ed5045e2033a26768f4e7, tree7f33dd15b5bd12389e3703e4b288110f3278edae, atop accepted B. This amendment and parent explicit correction grant are prerequisites; the previous author stays closed. Do not import this documentation branch's product ancestry.

**Exhaustive final tracked files against B (7 nonmechanical, no mechanical downloads):**

- `heel/saas/managed_authority_contracts.py` — create by byte-identical move from candidate `heel/managed_authority_contracts.py`; delete old path, no shim, preserve commercial SPDX.
- `tests/test_managed_authority_contracts.py` — carry original tests; change only two imports to private path.
- `tests/fixtures/canary/contracts/managed-authority-v1.json` — carry unchanged original fixture.
- `scripts/host_h2_policy_proof.py` — exact ordered new private path in HEEL_TREE_FILES.
- `tests/test_host_h2_policy_proof.py` — independent109→110 count, retain full ordered equality; missing/extra/byte-change refusal controls.
- `docs/saas/H2_POLICY_PROOF.md` —110 count and changed closure UNRUN qualification.
- `tests/test_managed_authority_artifact_parity.py` — create source/public-artifact boundary and byte-parity tests.

Correction touches seven nonmechanical paths counting deletion+addition separately; original fixture is not rewritten. Do not change public release policy/build/metadata/license, product consumers, B0 image/CI files or codec semantics. Unexpected path/input drift requires renewed exact scope. Separately count this plan amendment if composing documentation with P01.

**Behavior/interfaces:** The same inert validators/data contracts, no listener/admission enablement. Freeze Q§6 schemas verbatim, EA fields only where Q retains them, S ceremony/nullability and observations. Preserve maximal canonical examples, ordering, server-owned provenance, rawhex32 and old codecs. Private source location does not provide authority or sanitize secrets. Existing six semantic interpretation questions still require independent review.

**Verification:** Preserve the six exact5fa01be inventory failures and qualified B ConnectionResetError history. Check moved bytes equal original codec SHA256126b2186636579fd3206609526355abdbd32a2aba4582510317befcbd2cb3915. Keep exhaustive contract tests (maxima, duplicate/extra/bool/noncanonical/oversize, phase nullability, hash cycles, private route/credential substitutions). New artifact tests inspect actual wheel/sdist membership; neither old/new codec path, saas, private backend, deploy, tests nor secrets may ship. Positively exercise installed public runner/connector operations with private modules absent, outside checkout, verify __file__/hash and MCP lifecycle. Scratch unlisted-module, private-import and commercial-marker mutants must be refused for their intended reasons. A missing import alone is not positive runtime proof. P01 private codec source tests are not private image delivery proof.

- [ ] Focused: `python -m pytest -q tests/test_managed_authority_contracts.py tests/test_managed_authority_artifact_parity.py tests/test_host_h2_policy_proof.py tests/test_host_proof_import_identity.py`; separately unchanged `python -m pytest -q tests/linux/test_host_h2_policy.py -k static` with selected/deselected counts (not real H2 proof).
- [ ] Before affected/full, run deterministic release --check and independently reconstruct wheel/sdist/manifest in private scratch, compare all bytes to committed downloads. Enforced standard-build/runner-extra/source-free positive connector outcomes required. If equal, no tracked download edits. If unequal, HOLD: explain input change and obtain revised exact scope, regenerate all three before tests. Never defer parity to P17.
- [ ] Run affected CP, Runner, Host and release parity suites, then common full required suite with HEEL_REQUIRE_STANDARD_BUILD=1 and HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 on exact committed candidate. Supported private tooling, short TMPDIR, shared full-suite lock/reserves apply. Preserve argv/rc and original failures; unexplained failure/required skip is HOLD.
- [ ] Commit exact granted paths with DCO and fresh Opus attribution; record commit/tree/artifact hashes. Fresh Astra challenges source/interface and original interpretation questions before successors; author cannot accept.
- [ ] Coordinator separately authorizes fixed real H2 launcher on refs/heads/codex/self-serve-host-h2-policy-proof with zero selectors: all18 cases/eight p0–p7 records/zero skips, pinned kernel, exact110+14 ordered closure, isolated import identity, unchanged host fingerprints, zero leftovers; fresh independent runtime acceptance. Preserve static tuple/count/doc controls and all14 stage members. No ref spoofing, workflow widening, historical-run substitution or fabricated digest. Repin/review any proof-branch composition.
- [ ] H0 includes whole tracked heel/tests and changes: fresh authorized H0 for whole-candidate ingress qualification. H1 authority/feasibility/key-shape explicit staged files do not intersect correction: retain hashes/static checks and original historical identities; no claim of new exact-HEAD H1 runtime. CI/matrix/package and image gates separately owned; P01 local green alone is not acceptance of them.

## Packet P02: Schema and runtime migration parity

**Owner:** fresh Opus. **Base / prerequisites:** B+independently accepted P01 (including PR70 source/CI/H2/runtime/composition gates); accepted H6 R3 design and fresh whole-plan acceptance of this serialization. No P02 grant follows from design PASS alone. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/migrate.py` — modify
- `heel/saas/canary_store.py` — modify
- `heel/saas/managed_authority_ledger.py` — create
- `tests/test_managed_authority_migrations.py` — create
- `heel/saas/server.py` — modify (PROPOSED F1: early CP domain/connection lifecycle only; serialized P02→P14 handoff)
- `scripts/saas_backup.py` — modify (PROPOSED F1: managed maintenance/backup physical-writer guard only)

**F1 producer and early wiring:** P02 `managed_authority_ledger.py` owns the dependency-free `CPWriteDomain` API and process/domain registry specified below, alongside noncommitting ledger helpers. `canary_store.py` and `migrate.py` guard schema/savepoint/executescript/tracking/copy boundaries; `server.py` owns the process lock, early domain construction and guarded connection setup/close before workers. `scripts/saas_backup.py` owns the explicit maintenance-only managed backup boundary. No new product module is proposed. Existing migration tests own F1-M01–M04 below. This advances synchronization ownership, not H6 runtime/gate implementation; P14 receives server.py only after P02 and preserves it.

**H6 serialization — A-P02R2 (§8, exact DDL in transcript):** Implement the singleton domain table, immutable-delete and domain-restore-only update triggers identically in runtime DDL and the next actual migration. Persist operation kind/id, previous epoch, provenance, all stable reconciliation-result columns and digest in the same P14 reconciliation transaction. P14 alone writes it; the gate and CP epoch checks read exactly one row and recompute the digest. Add `test_managed_restore_domain_constraints_and_singleton` and `test_fresh_bootstrap_and_restore_schema_parity` to the existing migration test file, alongside schema parity. Cover bootstrap/migration/pre-domain INSERT, domain UPDATE, invalid previous epoch/provenance/singleton/deletion/stale digest; bool/float/string rejection is pre-binding validation, not SQLite affinity enforcement. No new path, no listener enablement; P14 still proves actual durable COMMIT/lost-output recovery.

**Behavior/interfaces:** Add managed reservation/ceremony fields from S §14.2, restore marker/domain, extended generation high-water/disposition, run reservation/progress/40-bit seen bitmap and immutable charged-attempt table Q §7. Use next available migration numbers determined from actual B+n; never force historical proposed migration35 over current schema. Both migration and runtime DDL yield identical constraints/indexes/FKs. Charge row columns are exactly Q §7; no executable receipt body. Ledger helpers accept an existing connection, never own commits.

**Tests written first/with code (proposed names and fixtures):** `test_fresh_runtime_and_upgraded_database_schema_parity`; `test_upgrade_is_idempotent_and_rollback_atomic`; `test_attempt_unique_across_window_generation_and_restart`; `test_scalar_length_type_and_foreign_key_constraints`; `test_no_receipt_blob_or_replay_fence_ttl`; `test_null_pre_runner_reservation_survives_upgrade`. Inspect sqlite_master, PRAGMA table_info/index_list/foreign_key_list and migrated old rows, not only column presence.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_authority_migrations.py tests/test_canary_migrations.py
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Fresh and upgraded DBs have identical normalized schemas and enforcement; no listener enabled, no historical identity silently classified connector. Migration collisions require rebase/renewed review before commit.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P02 schema and runtime migration parity" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P03: CP ceremony service and bounded lifecycle

**Owner:** fresh Opus. **Base / prerequisites:** B+P02. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/managed_pairing.py` — create
- `heel/saas/runner_auth.py` — modify
- `tests/test_managed_pairing_service.py` — create

**F1 consumer:** P03 uses the accepted P02 domain before any new outer ceremony transaction, and retains its token through commit/rollback; invite/revoke helpers join only a verified caller token. `runner_auth.py` handoff P03→P04 is explicit: P03 guards touched/new ceremony wrappers, P04 completes the entire historical auth inventory.

**Behavior/interfaces:** Implement service-side reserve/invite association, exact key offer and fingerprint checks, existing proof/approval/activation semantics, terminal reconciliation, predecessor adoption, delivery/retry/cleanup budgets and observations. Extract transaction-sharing invite and revoke helpers without BEGIN/COMMIT/ROLLBACK; existing connector wrappers retain ownership. Invocation produces CP state/observations only, no filesystem publication. Bind invitation+original expiry+managed association atomically; no persisted raw invitation token. Resolve post-exchange runner identity from exact pairing row before terminalizing.

**Tests written first/with code (proposed names and fixtures):** `test_invite_and_managed_association_commit_together`; `test_terminal_before_runner_and_exchange_before_projection`; `test_original_expiry_never_uses_receipt_horizon`; `test_predecessor_ack_required_before_successor`; `test_higher_delivery_reacks_completed_without_cleanup`; `test_delivery64_cleanup6_retry600000_and_restart_budgets`; `test_unknown_pairing_result_abort_retire_not_reexchange`; `test_connector_invite_revoke_semantics_preserved`.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_pairing_service.py tests/test_runner_control_http.py
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Fault cuts at invite/exchange/association/retry commits preserve full phase-nullability and fixed predecessor linkage. R can complete without root I/O. Service is not yet a host enablement grant.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P03 cp ceremony service and bounded lifecycle" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P04: Terminal guards before every replay and action

**Owner:** fresh Opus. **Base / prerequisites:** B+P03. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/http_api.py` — modify
- `heel/saas/runner_auth.py` — modify
- `heel/saas/runner_contexts.py` — modify
- `heel/saas/canary_runs.py` — modify
- `heel/saas/canary_reaper.py` — modify
- `heel/saas/ops.py` — modify
- `heel/saas/verification.py` — modify
- `heel/saas/managed_pairing.py` — modify
- `tests/test_managed_authority_routes.py` — create
- `heel/saas/canary_disclosure.py` — modify (PROPOSED F1: `_write` and constructor transaction participation only)

**F1 outer-writer ownership:** P04 applies the P02 domain at every boundary in its ten-path inventory below, including both reaper `_cycle` transactions, its independently called reconciliation/auth-retention transactions, independent connection setup/close, implicit ops/verification writes, disclosure `_write`, HTTP signup and constructors. Acquire before BEGIN/first implicit write, never in a terminal helper after BEGIN; retain through all commit/rollback/close failure paths. Existing routes test file owns F1-R01–R04.

**Behavior/interfaces:** Wire managed human create/status/cancel/retry routes and exact existing public pairing/binding/claim/activation controls with same-origin/recent owner/admin/workspace checks. Classify managed provenance from durable association before receipt lookup and before guarded mutation. Compose cancel/revoke/environment revoke/expiry/reaper/key rotation/kill switch terminal changes in caller transaction via noncommitting helpers. Preserve legacy/connector behavior only for positively nonmanaged records; ambiguous provenance refuses. Read-only observation is historical, never executable replay.

**Tests written first/with code (proposed names and fixtures):** `test_terminal_guard_precedes_nonce_and_receipt_replay_every_route`; `test_managed_cannot_downgrade_public_internal_legacy_connector`; `test_null_runner_cancel_closes_associated_invite`; `test_reaper_rotation_kill_and_binding_revoke_share_transaction`; `test_recent_owner_origin_and_cross_workspace_rejected`; `test_revocation_does_not_wait_for_host_writer`; `test_connector_receipt_compatibility`. Parameter table enumerates every actual public route and fixed internal callback in http_api/runner_auth plus old host versions; no assertion that one sampled route proves all.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_authority_routes.py tests/test_canary_stop.py tests/test_canary_reaper.py tests/test_runner_control_http.py
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Reviewer compares route inventory to pinned matcher/auth callbacks and tests each terminal owner. No nested commit; terminal/revision exhaustion remains absorbing. Replayed pre-R successes cannot pass after R.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P04 terminal guards before every replay and action" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P05: Claim reservation and exact CP attempt admission

**Owner:** fresh Opus. **Base / prerequisites:** B+P04+independently accepted CP-WRITERS (complete same-volume writer closure). **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/host_authority.py` — modify
- `heel/saas/host_snapshot.py` — modify
- `heel/saas/managed_authority_ledger.py` — modify
- `heel/saas/canary_runs.py` — modify
- `tests/test_managed_attempt_admission.py` — create
- `tests/test_host_enrollment.py` — create (H6 §12 exact A-ENR2 addition; private test, not a HEEL_TREE_FILES addition)

**H6 serialization — A-ENR2/A-STORE2 (§§5.4,7.1–7.3,12):** `host_authority.py` owns the opaque production loader, strict 32-byte K/config profile, three-route request-context/path/exact-body HMAC after SO_PEERCRED, fixed 401 status and `HostAuthorityService(enrollment=LoadedEnrollment)` required in managed mode. K is distinct from edge/tunnel/seed/target keys; no K/proof/secret-file digest in receipts, DB, logs, executor IPC or public wheel. The gate and service will consume the same loaded object at P14; no reload or caller tuple substitutes. Q body/digest/receipt/GET|HEAD/one-shot/terminal guards remain unchanged. E01–E04 live in `tests/test_host_enrollment.py` plus existing admission tests; E15 sink exclusions apply. P05 tests production loader/authenticator including valid all-three-route requests, wrong uid/pidns/key/id/path/body, old proof and replay, strict header/config grammar and cap+1, with zero decider/charge/sequence on authentication refusal.

`host_snapshot.py`/`canary_runs.py` consume the already accepted P02 `CPWriteDomain` with P03/P04/CP-WRITERS participation, sample statvfs under its capacity token before BEGIN, and use P06-measured worst costs or refuse admission. P05 owns admission/checkpoint policy and touched run wrappers only, not reaper/auth/ops boundary repairs. The exact earlier production owners below discharge the historical H6 §5.4 placement note; the transcript remains verbatim. Retain 640 MiB CP admission, 512 MiB ledger, 64 MiB WAL/outstanding-terminal caps, >=1024 free inodes and exclusive 128 MiB terminal reserve. Existing admission tests own F1-A01–A03 and F2-L01–L08, including actual socket publication/failure/cleanup against decisions/reaper under the F2 protocol; P06 owns real full-closure F1-S01–S06 and F2-S01–S03. H6-RUNTIME consumes accepted P05; P05 does not depend on that runtime.

**Behavior/interfaces:** Add route-specific bounded parsing at existing peer-authenticated listener; preserve v1 only outside managed provenance. Claim reserves approved slots and terminal capacity. Decider uses one BEGIN IMMEDIATE transaction and commit-before-return for W/Q and the retained ceremony exchange wired to P03, immutable signed projection joins and guards. Keep attempt and window sequences separate, strict ordinal progression and allowed actual prior failure. CP stores charge even if reply is lost. Public progress/result cannot lower charge counts. Enforce total reserved-or-used65536, per-run20/retry1 and conservative physical obligations before admission; capacity policy is fail-closed pending P06 measurement.

**Tests written first/with code (proposed names and fixtures):** `test_first_ordinal19_and_skipped_action_refused`; `test_retry_requires_latest_actual_connect_error_or_timeout`; `test_lifetime_reuse_across_new_window_generation_refused`; `test_wrong_tuple_role_method_template_route_fence_executor_refused`; `test_valid_refusal_consumes_sequence_without_charge`; `test_gap_reuse_closes_generation`; `test_claim_reserves_all_slots_and_terminal_capacity`; `test_lost_commit_reply_never_replays_or_refunds`; `test_client_counter_cannot_lower_cp_charge`; `test_no_fs_network_or_key_read_inside_transaction`. Private-route corruption must be tested at trusted executor in P10 too; CP equality alone is insufficient.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_host_enrollment.py tests/test_managed_attempt_admission.py tests/test_host_authority.py tests/test_host_snapshot.py tests/test_canary_quota.py
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Count charged rows/seen bits/high-water after each real transaction. R-first no charge/admission; A-first immutable charge. This packet cannot certify physical fit or real transport; P06/P15 remain gates.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P05 claim reservation and exact cp attempt admission" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P06: Two-connection races and physical capacity qualification

**Owner:** fresh Opus. **Base / prerequisites:** B+P05. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `tests/test_managed_authority_storage.py` — create
- `tests/support/managed_authority_race_harness.py` — create
- `scripts/managed_authority_storage_proof.py` — create

**H6 serialization — A-STORE2 (§5):** In existing storage tests/proof add T-N05 `test_cp_admission_refuses_at_ceiling_terminal_still_commits`, T-N06 `test_blocked_checkpoint_wal_cap_refuses_admission` and `test_aggregate_physical_budget_and_terminal_reserve` (row 19). Measure `device_bytes − f_bavail*f_frsize`, all indexes/metadata/freelist/WAL/checkpoint and outstanding terminal obligations; no logical-row-size proxy. Prove capacity-mutex → BEGIN order and admission refusal without refusing terminal/R/cleanup. H6-RUNTIME supplies actual device/inode host measurements; P06 cannot stand in for them.

**F1/F2 real closure proof:** Include F2-S01–S03 filesystem/lifecycle effects and P02 preownership lock exclusion as specified below. Parameterize F1-S01–S06 over every boundary in the F1 owner map, including CP-WRITERS and nonmanaged/implicit writes on the same database. Remove each boundary separately as a negative control. P06 changes only its three test/proof paths; a failed production boundary returns to its named owner through a fresh bounded correction, never a P06 production edit.

**Behavior/interfaces:** Build a bounded harness using production CP API/Unix handlers and independent SQLite connections (not one service lock). Barriers distinguish durable commit, reply delivery and client observation. Build physically representative maximal rows and all existing table/index/WAL obligations, including claim reservations and outstanding R obligations. Measure DB pages/freelist, index dbstat where available with explicit fallback measurement, WAL bytes/checkpoint temporary growth, actual filesystem peak and memory/buffer/backlog behavior. Script interface proposed: --output DIR --max-seconds 600; emit redacted JSON and nonzero on missing measurement or violation. Stop at reserve thresholds, never fill host disk.

**Tests written first/with code (proposed names and fixtures):** `test_R_vs_initial_next_retry_both_commit_orders_two_connections`; `test_concurrent_full_capacity_and_R`; `test_rollback_busy_checkpoint_pressure_preserves_terminal_reserve`; `test_unknown_commit_and_lost_reply_have_distinct_durable_outcomes`; `test_revision_exhaustion_still_terminalizes`; `test_reserved_slots_release_only_on_terminal_and_charged_never_reuse`. Block checkpoints with a real long reader; inject write/rollback faults separately. At full admission ceiling, terminal updates must still commit with fixed bounded work and retain all fences.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_authority_storage.py
python scripts/managed_authority_storage_proof.py --output "$HEEL_PACKET_SCRATCH/storage-proof" --max-seconds 600
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Independent reviewer reconciles actual files/PRAGMAs/row counts/commit logs to <=512MiB ledger, <=1GiB total, <=896MiB admission and exclusive128MiB terminal reserve. Failure means layout/obligation accounting needs a fresh bounded correction, not a larger cap or eviction. Record throughput separately; 1092 bytes logical is not capacity proof.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P06 two-connection races and physical capacity qualification" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P07: Accepted-main CP qualification checkpoint

**Owner:** fresh Opus. **Base / prerequisites:** B+P06. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `tests/test_managed_cp_composition.py` — create

**Behavior/interfaces:** Compose P01–P06 through actual service construction and public/private handlers. Keep host target admission disabled until reviewed I. Cover upgrade/current schema and connector compatibility, terminal precedence, successful valid CP charge alongside refusal paths. Inventory all route owners against P04 matrix; no helper-only acceptance. This is the accepted-main handoff and no source from H is imported.

**Tests written first/with code (proposed names and fixtures):** `test_managed_cp_end_to_end_ceremony_claim_window_attempt_terminal`; `test_all_terminal_owners_precede_replay_in_production_wiring`; `test_connector_remains_separate_and_managed_has_no_fallback`; `test_restart_preserves_capacity_and_closed_domain`. Positive test commits valid Q without pretending it dispatched.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_cp_composition.py
```

- [ ] Run affected package: **CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Fresh Astra records exact accepted CP tree and remaining H3/C3/C5/C6/H6 gates. CP acceptance is not C4 completion or customer launch. I must later revalidate merge conflicts and this suite.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P07 accepted-main cp qualification checkpoint" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P08: Historical observations in browser and CLI

**Owner:** fresh Opus. **Base / prerequisites:** B+P04 (may branch independently; join at P16). **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `apps/heel-cloud/lib/canary-api.ts` — modify
- `apps/heel-cloud/worker/index.ts` — modify
- `apps/heel-cloud/components/canary/RunnerStep.tsx` — modify
- `apps/heel-cloud/app/dashboard/page.tsx` — modify
- `heel/cli.py` — modify
- `tests/test_managed_observation_cli.py` — create
- `apps/heel-cloud/tests/managed-observation.test.tsx` — create
- `apps/heel-cloud/tests/managed-routes.test.ts` — create

- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2-py3-none-any.whl` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2.tar.gz` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` — modify (mechanical regeneration)

**Artifact handoff:** Regenerate all three downloads from this packet’s final source before affected/full verification; commit source and generated bytes together, then run deterministic `--check` and the unconditional current-source/wheel/sdist parity test on that exact clean commit. Follow the shared-writer DAG; P17 is not a deferred parity repair.

**Behavior/interfaces:** Expose fixed managed human routes through existing Worker origin/CSRF filters and bounded client schemas. Render first-load/frozen/offline state as Last checked, including accessible labels and CLI output. Terminal revision dominates delayed nonterminal; equal revision conflict is error, successor identity separate. Cancellation requested, durable access revoked, and cleanup completed remain distinct. Each button invokes independently guarded CP action; observations cannot mint binding/claim. No framework dependency upgrades or new pricing.

**Tests written first/with code (proposed names and fixtures):** `test_first_render_is_last_checked_in_visual_and_accessible_copy`; `test_offline_frozen_delayed_revision_and_terminal_precedence`; `test_lost_cancel_reply_never_claims_completed`; `test_successor_keeps_predecessor_terminal`; `test_post_R_action_refused_despite_stale_pixels`; `test_managed_cli_never_claims_current_active`; `test_worker_fixed_routes_preserve_origin_recent_auth`.

- [ ] Run focused red/green command(s):

```sh
npm --prefix apps/heel-cloud run test:unit -- tests/managed-observation.test.tsx tests/managed-routes.test.ts
python -m pytest -q tests/test_managed_observation_cli.py
```

- [ ] Run affected package: **UI + CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Component tests establish copy/state semantics only; real browser cuts wait for P16. Worker allowlist adds only exact routes, no host receipt exposure. Cross-branch merge into I needs review.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P08 historical observations in browser and cli" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P09: Root exact W/Q exchange and raw fence ownership

**Owner:** fresh Opus. **Base / prerequisites:** I; accepted P01–P07, actual H3 acceptance/remediation, accepted H6-LAUNCH and fresh integration review. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `deploy/host/executor_link.py` — modify
- `deploy/host/executor.py` — modify
- `deploy/host/supervisor.py` — modify
- `deploy/host/cycle.py` — modify
- `tests/test_managed_host_exchange.py` — create

**Behavior/interfaces:** Complete inert target bootstrap before timed W prepare; control-only pair generation is distinct and retired first. Replace run-only authorized trigger with fixed W completion and Q request/notification. Root captures actual handle/process/namespace/fence and forwards fixed metadata only. Bind reply to exact original pending exchange; ready/claimed/install context cannot grant traffic. Freeze W while Q pending, retire on uncertain installer; late workers cannot attach to a successor. Remove supervisor six registry writes (H1041/1171/1187/1238/1315/1344), including inactive writes, static config runner cache and managed active launch-input selection.

**Tests written first/with code (proposed names and fixtures):** `test_ready_claimed_and_cached_context_never_authorize`; `test_raw_fence_bootstrap_to_receipt_and_successor_rejection`; `test_wrong_handle_process_namespace_or_delayed_reply_abandoned`; `test_unknown_install_quarantines_without_new_prepare`; `test_pending_Q_freezes_W_and_original_deadline`; `test_six_registry_writes_absent_in_managed_flow`; `test_legacy_managed_launch_input_rejected`. Source lines are H witnesses; re-resolve symbols on I and save reviewed callsite map.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_host_exchange.py tests/test_host_cycle.py tests/test_host_h3.py
```

- [ ] Run affected package: **Host**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: No guessed H3 fix. Late-reply ownership must have its own accepted evidence before I. Preserve accepted H3 resolver budgets/codecs and original H1 prepare/activation timing; no target proxy in root.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P09 root exact w/q exchange and raw fence ownership" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P10: Executor per-attempt callback, spend and evidence

**Owner:** fresh Opus. **Base / prerequisites:** I+P09+accepted P08 artifact handoff. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/runner/coordinator.py` — modify
- `heel/runner/execution.py` — modify
- `heel/runner/http_transport.py` — modify
- `heel/runner/adapters.py` — modify
- `deploy/host/executor.py` — modify
- `tests/test_managed_attempt_transport.py` — create

- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2-py3-none-any.whl` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2.tar.gz` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` — modify (mechanical regeneration)

**Artifact handoff:** Regenerate all three downloads from this packet’s final source before affected/full verification; commit source and generated bytes together, then run deterministic `--check` and the unconditional current-source/wheel/sdist parity test on that exact clean commit. Follow the shared-writer DAG; P17 is not a deferred parity repair.

**Behavior/interfaces:** Wire required managed admission dependency, no optional deadline-only fallback. Extend callback contract to carry original transport/run/action deadlines and actual previous failure, without resetting on retry. Revalidate full manifest/PreparedAction/credential selection both before Q request and before spend. Charge precedes local budget reservation/action_started; spend before _one_attempt under lock. Preserve evidence attribution, target pinning, headers/redaction/containment. Connector callback compatibility remains explicit and unreachable for managed provenance.

**Tests written first/with code (proposed names and fixtures):** `test_open_W_fresh_cached_gate_after_R_cannot_mint_permit`; `test_initial_next_retry_each_need_distinct_cp_charge`; `test_pause_after_spend_before_physical_transport`; `test_original_transport_run_action_window_deadlines_never_extend`; `test_late_callback_after_timeout_never_resurrects`; `test_private_fixture_credential_role_route_substitution_refused`; `test_known_STOP_expiry_duplicate_permit_prevents_dial`; `test_lower_higher_GET_pair_and_HEAD_inconclusive`; `test_evidence_bound_to_consumed_Q_and_cp_charge_not_client_counter`. Barriers include before send, after commit/reply, root receipt, reservation, spend and actual dial; physical target count is separate from charged row count.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_attempt_transport.py tests/test_runner_http_transport.py tests/test_runner_adapters.py tests/test_runner_stop.py
```

- [ ] Run affected package: **Runner**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Actual request path, not extracted helper, demonstrates one receipt cannot dial twice. A(Q)-first may leave a charge with no dial; R prevents Q2. Paused transport resumes only within original limits/known STOP; no execute/refund from unknown result.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P10 executor per-attempt callback, spend and evidence" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P11: Historical store backend and managed daemon selection removal

**Owner:** fresh Opus. **Base / prerequisites:** I+P10+C5-IMPL+C6-IMPL at reviewed J11; accepted C5-IF/C6-IF/H6-IF and private storage facts (table below). **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/managed_backend.py` — create
- `heel/runner/store.py` — modify
- `heel/runner/daemon.py` — modify
- `heel/runner/coordinator.py` — modify
- `heel/runner/execution.py` — modify
- `deploy/host/executor.py` — modify
- `tests/test_managed_backend.py` — create

- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2-py3-none-any.whl` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2.tar.gz` — modify (mechanical regeneration)
- `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` — modify (mechanical regeneration)

**Artifact handoff:** Regenerate all three downloads from this packet’s final source before affected/full verification; commit source and generated bytes together, then run deterministic `--check` and the unconditional current-source/wheel/sdist parity test on that exact clean commit. Follow the shared-writer DAG; P17 is not a deferred parity repair.

**Behavior/interfaces:** Provide focused historical evidence backend without active identity/context selectors; inject only from trusted managed entry. Preserve signed context validation as inert data scoped to exact run/Q. Remove managed calls to store active selection, install journal/stage/finish/publish/bind/recovery/rollover and daemon startup active selection. Connector backend retains existing recovery. Read-only historical records cannot mint permits. Integrate existing credential vault and raw/redacted evidence custody through reviewed C5/C6 interfaces without rewriting those subsystems.

**Tests written first/with code (proposed names and fixtures):** `test_managed_backend_has_no_active_selection_or_rollover`; `test_old_active_context_files_never_rehydrate_authority`; `test_history_cannot_create_Q_after_restart`; `test_managed_entry_only_no_cli_or_env_switch`; `test_redacted_findings_persist_with_exact_containment_chain`; `test_connector_store_recovery_unchanged`; `test_retired_evidence_and_vault_retention_survive_repair`. Exercise every EA §6 store callsite (select_active, stage/finish journal, publish, bind/install, pending/finish rollover, load/verify context, assert contract, reserve/transition run), not just filename absence.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_backend.py tests/test_runner_coordinator.py tests/test_runner_daemon.py tests/test_runner_store_probe.py tests/test_runner_redaction.py
```

- [ ] Run affected package: **Runner**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: No managed live authority recovered from files/FDs. Useful paired run must persist valid evidence; blanket refusal fails. If C5/C6 interface is missing/unaccepted, this packet remains blocked on named external owner, no substitute vault.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P11 historical store backend and managed daemon selection removal" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P12: Root seed ceremony and retained cleanup evidence

**Owner:** fresh Opus. **Base / prerequisites:** I+P11; accepted H6-RUNTIME real layout/quota fixture capability before P12 real integration proof, H6-IF UID/epoch-parent/quota facts and C5-IF/C6-IF deletion contracts. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `deploy/host/managed_identity.py` — create
- `deploy/host/managed_pairing.py` — create
- `deploy/host/supervisor.py` — modify
- `deploy/host/executor.py` — modify
- `tests/test_managed_root_ceremony.py` — create

**H6 serialization — A-LOCK2/A-STORE2/A-ENR2 (§§3–7):** `supervisor.py` and root signer hold their own stable L(SH) for process lifetime before the per-slot S lock; no inherited lock FD or SH→EX upgrade. `managed_identity.py`/`managed_pairing.py` own the exact root-only slot marker and retirement/replacement flow (§7.7); identifiers, markers and completion receipts only deny or record provenance. Consume the H6-LAUNCH selected-home container and H6-RUNTIME layout/quota contracts; root signer uses the P05-compatible enrollment proof, never sends K/header to executor. Keep host/executor `/opt/heel/deploy/host/executor.py` and `/opt/heel/heel/{runner,saas}` layout and existing serialized executor ownership.

Existing `tests/test_managed_root_ceremony.py` owns E11/E15, T-N04/T-N07/T-N12 and `test_slot_inode_and_block_exhaustion_root_reserve` protocol integration: real quota mount, all six cleanup attempts, crashes/stale temps/restart, 27 root inodes/179 blocks within 64/512 reserves. Fresh home + runner-daemon directory + seed charge **three** executor inodes: `used − 1 + 3 <= LX`, otherwise honest `managed_capacity_unavailable` after retirement. No history deletion or cleanup_failed-as-guarantee; no extra storage grant.

**Behavior/interfaces:** Root owns protected seed, immutable allocation/recovery intent, historical completion/predecessor evidence and cleanup only. No active config/journal/registry publication. Fixed signer performs unchanged PoP in inert control-only generation; target credentials remain separate. Preserve phase nullability, original expiry, exact predecessor adoption, higher-delivery re-ack, orphan retention and all budgets. Abort-and-retire on uncertain/restarted incomplete activation; do not reconstruct executable maps.

**Tests written first/with code (proposed names and fixtures):** `test_root_seed_reload_delete_ownership_and_secret_sink_absence`; `test_pair_generation_has_no_target_rule_and_ends_before_target_generation`; `test_all_phase_nullability_original_expiry`; `test_predecessor_adoption_and_tmpfs_loss_reack`; `test_completed_higher_generation_never_repeats_cleanup`; `test_one_live16_retired28KiB_and4096_maximal_record`; `test_cleanup_reserved_before_effect_and_reboot_no_budget_reset`; `test_custody_failure_blocks_new_enrollment_not_R`.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_root_ceremony.py tests/test_managed_pairing_service.py tests/test_managed_host_exchange.py
```

- [ ] Run affected package: **Host + Runner**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Fault every fsync/adoption/ack boundary, compare exact tuple/both generations; cleanup completion cannot be inferred from absent files or process exit. Six attempts exhausted stays failed until separately authorized bounded retry.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P12 root seed ceremony and retained cleanup evidence" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P13: H0/nginx transport-only ingress and no registry seam

**Owner:** fresh Opus. **Base / prerequisites:** I+P12. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `deploy/host/ingress/policy.js` — modify
- `deploy/host/ingress/nginx.conf` — modify
- `tests/support/host_ingress_harness.py` — modify
- `tests/test_host_ingress.py` — modify
- `apps/heel-cloud/tests/host-ingress.test.ts` — modify
- `tests/test_managed_ingress.py` — create

**Behavior/interfaces:** Remove managed registry file load/check/watermark/cache/refresh and current runner routing. Keep static topology, kernel peer, fixed path/header/body/origin restrictions and private CP backend. Move exact invitation key/pairing/workspace checks to P03/P04 CP guarded routes, prove they remain enforced. Remove SEAM-REGISTRY DB-reading supplier from managed acceptance path; existing connector-only tests may retain explicitly nonmanaged seams. Renderer must ship no registry variables or generation shared cache.

**Tests written first/with code (proposed names and fixtures):** `test_managed_ingress_never_reads_registry_or_cached_runner`; `test_real_pairing_through_both_listeners_without_DB_supplier`; `test_wrong_expected_key_pairing_workspace_refused_at_CP`; `test_fixed_transport_routes_cannot_expose_host_receipt_or_target_proxy`; `test_old_nginx_worker_fd_cannot_be_migration_success`. Run actual nginx/njs on qualified fixture, with same runtime-lock identity; parser-only JS tests are insufficient.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_ingress.py tests/test_host_ingress.py
npm --prefix apps/heel-cloud run test:unit -- tests/host-ingress.test.ts
```

- [ ] Run affected package: **Host + UI**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Positive pairing reaches real CP and unchanged PoP; reused invitation/terminal activation refuse. Source removal and runtime file-open traces agree. No weakening into an unrestricted static control proxy.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P13 h0/nginx transport-only ingress and no registry seam" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P14: One-time migration and offline restore before both listeners

**Owner:** fresh Opus. **Base / prerequisites:** I+P13; H6-IF plus H6-RUNTIME maintenance fence/enrollment/provisioning evidence. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `heel/saas/managed_restore.py` — create
- `heel/saas/server.py` — modify
- `deploy/host/managed_migration.py` — create
- `scripts/managed_restore_proof.py` — create
- `tests/test_managed_restore.py` — create
- `docs/saas/RUNBOOKS.md` — modify

**H6 serialization — A-RECON2/A-ART3/A-LOCK2/A-ENR2/A-RUN (§§6–8):** H6-RUNTIME's accepted fixture capability, including F17/F20/F21/F22/F23, precedes this packet's integrated proof. `server.py` owns the root-created private-channel adapter, ordinary/offline entry wiring, opaque `ArtifactObservation`, one production enrollment load shared with gate/listener and the exact ordered gate (including rows 3a and 11a). `managed_restore.py` owns pre-binding validation, durable reconciliation and recovery; `managed_migration.py` orchestrates the host-facing migration consumer. Every ordinary/service/runtime restart/boot and offline entry uses the root launcher anew; no direct CP restart or cached permit. Freeze integrated snapshot/mount/normalization/resource facts before proof.

Implement the transcript's complete every-launch contract, not recipe equality: staged measurement and ordinary receipt equality before entry execution; live pinned-child/tree/profile and authenticated inherited-channel checks; nonce/process/mode/L inode/revision/receipt bytes/config binding/recipe/volume bound to use. L→lease→child DB process lock→connection/service gate→capacity token→SQLite; parent never takes child DB lock. P14 offline reconciliation, startup schema work, recovery reads capable of WAL recovery/checkpoint and connection teardown consume the P02 token; keep it through commit/rollback/physical teardown, then release before filesystem receipt emission. No SQLite transaction contains statvfs or network/key reads. The original L/lease lifetime and ordering remain unchanged. Reap, release lease and SH, acquire fresh EX then fresh lease and fully remeasure before enrollment ack. Parent loss retains the live child's lease until supervised reap; no caller-created lookalike pipe or claimed parent PID authenticates a frame. E17/F22/F23 must prove endpoint ownership/direction/exclusivity/inheritance, not only nonce echo. No listener, reaper or DB mutation on artifact refusal.

Offline bootstrap, same/new-host legacy migration, pre-domain/domain restore and verification construct no listeners. Reconcile with synchronous FULL and one BEGIN/COMMIT; persist result and targets atomically in the domain row, then emit receipt with freshly measured physical checks. Recover committed/lost stdout by exact operation/targets/digest/provenance, including migrator-created empty table; do not repeat the write. Root owns fence/J/intent publication, durable config and acknowledgment; no atomic SQLite+filesystem assumption. Verification precedes ack→complete→ordinary launch→both listeners→readiness→edge smoke. `RUNBOOKS.md` forbids D_CP expansion: equal-size restore replacement only; K replacement requires full domain replacement, never same-id regeneration or automatic reenrollment.

Existing restore test/proof paths own E07–E10, E12–E13, E15–E19 and E20's acyclic-offline sequence; T-P02/T-N01/T-N08/T-N10/T-N14 and rows 20–24 CP halves. Use the 25-oracle and E01–E20 tables in the transcript without dropping any case. Distinguish same-recipe A/A′ with different exact manifests, same-A positive and kind mismatch; missing/tampered/ambiguous/unsupported content, receipt or channel; fresh ordinary/restart/boot measurement; every replacement cut; parent death and orphan recovery; both-listener nonpublication. Models are not integrated proof.

**Behavior/interfaces:** Add startup maintenance reconciliation gate before constructing/publishing either HTTP or Unix listener. One-time migration terminalizes old managed authority, fences/stops all old supervisor/executor/daemon/resolver/nginx processes, descriptors and pending I/O before fresh enrollment. Restore offline onto isolated new volume; external maintenance marker/enrollment domain never loaded from restored completion marker. Terminalize null/pre-runner reservations too; revoke old proof/key/receipt/grant/W/Q eligibility, reconcile provenance, retain history. Old inaccessible hosts remain administratively fenced. Script proposed: --output DIR --max-seconds 600, isolated pre-R backup/interruption drill only.

**Tests written first/with code (proposed names and fixtures):** `test_old_process_FD_and_pending_IO_block_migration_enablement`; `test_pre_R_backup_invalidates_all_authority_before_both_listeners`; `test_interruption_each_step_stays_disabled`; `test_backup_completed_marker_cannot_open_listener`; `test_unclassified_restored_runner_is_not_connector`; `test_unreachable_old_host_cannot_reenroll`; `test_fresh_pair_binding_approval_after_restore_useful`; `test_R_does_not_wait_for_ordinary_cleanup`.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_restore.py tests/test_saas_server.py
python scripts/managed_restore_proof.py --output "$HEEL_PACKET_SCRATCH/restore-proof" --max-seconds 600
```

- [ ] Run affected package: **CP + Host**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Observe listener socket publication directly, not a readiness boolean. A stopped legacy writer/surviving FD or unresolved issued I/O means HOLD. No live restore/key rotation performed by this plan. No seamless identity recovery claim.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P14 one-time migration and offline restore before both listeners" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P15: Real Linux W/Q boundary and containment proof

**Owner:** fresh Opus. **Base / prerequisites:** I+P14; qualified Linux and separately authorized privileged proof environment. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `tests/linux/test_managed_authority_proof.py` — create
- `scripts/managed_authority_proof.py` — create
- `tests/test_managed_authority_proof_contract.py` — create
- `docs/saas/MANAGED_AUTHORITY_PROOF.md` — create

**H6 serialization — A-P15 (§§4.7,9):** Rerun accepted `python scripts/managed_container_proof.py --output "$HEEL_PACKET_SCRATCH/container-proof" --max-seconds 600` on the exact integration candidate; no added path. Existing Linux proof/tests own T-P01/T-N09, E12–E13/E15, real SO_PEERCRED E02 and retained integration oracles. Use `integrated_source` images, useful paired GETs/HEAD-inconclusive, physical packets and original deadlines/STOP. Revalidate container/FD/host-path boundaries and provider pause facts; fixture-only H6 success does not discharge this stage or release/customer proof.

**Behavior/interfaces:** Create bounded launcher in established proof style; proposed command has no arguments and writes fixed bounded evidence under private scratch. Drive real CP, root, executor, kernel and owned HTTPS target without scripted decider/cached-gate permit substitutes. Preserve original H1/H2/H3 proof cases and running-kernel limits. Correlate CP commits/rows, exact W/Q/handle descriptors, clocks, root/process/namespace identities, physical packets and evidence. Pause all actual cuts including after permit spend. Reap only owned resources and verify unchanged outer namespace.

**Tests written first/with code (proposed names and fixtures):** `test_real_R_initial_next_retry_and_paused_spent_transport`; `test_inert_empty_gate_same_prepared_handle_original_time`; `test_STOP_clock_gap_expiry_delayed_installer_quarantine`; `test_wrong_executor_successor_late_reply_no_effect`; `test_positive_GET_pair_HEAD_inconclusive_and_no_uncharged_request`; `test_cleanup_no_namespace_FD_child_or_socket_survivor`. Launcher must make skips/missing pinned kernel or required privileges non-PASS.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_authority_proof_contract.py
python scripts/managed_authority_proof.py
```

- [ ] Run affected package: **Host**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Rerun named existing `python scripts/host_lease_key_shape.py`, `python scripts/host_authority_proof.py`, `python scripts/host_h2_policy_proof.py`, `python scripts/host_ingress_proof.py` on exact integration candidate where their authorized launchers apply. Retain H1 T4/T4N/T4S/C2 and cycle S cases; H2 P0–P7. Accepted H3 launcher/command must be pinned in I manifest, not guessed from H. Original five-second product STOP and H6 provider pause/restore qualification remain separate required evidence.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P15 real linux w/q boundary and containment proof" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P16: Real browser observations and paired synthetic product journey

**Owner:** fresh Opus. **Base / prerequisites:** I+P15+P08; reviewed J11 C5-IMPL/C6-IMPL integration and H6-RUNTIME. Default discovery/login acceptance additionally requires DA-IF, DA-IMPL and C3 owner clearance; synthetic Q-only integration may be recorded separately while held. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `apps/heel-cloud/tests/managed-authority-browser.mjs` — create
- `apps/heel-cloud/package.json` — modify
- `apps/heel-cloud/package-lock.json` — modify
- `tests/test_managed_journey_contract.py` — create

**Behavior/interfaces:** Add proposed script `test:managed-authority-browser` running the bounded new browser harness. Use accepted exact browser/runtime dependency pair; if none exists, pin exact dependency and matching Chromium in a reviewed grant before install, no unrelated upgrades. Browser uses actual built Worker/CP/root/paired executor/HTTPS fixture; signup/project/verification/pairing/bind/approval through product only. Hold/reorder responses for first-render/offline/frozen/terminal cases and attempt actions after R. Capture visual/accessibility evidence and redacted network/result trace. No manual DB/seed/active store/source-checkout requirement.

**Tests written first/with code (proposed names and fixtures):** `browser_signup_project_verified_pair_approve_GET_pair_findings`; `browser_HEAD_is_inconclusive`; `browser_first_render_offline_frozen_terminal_revision`; `browser_lost_cancel_ack_and_cleanup_distinct`; `browser_stale_observation_post_R_action_refused`; `browser_save_regression_patch_replay_revoke`. Harness accepts `--output DIR --max-seconds 900`; nonzero for timeout, missing stage, unexpected gap or leaked fixture secret; all processes owned/bounded.

- [ ] Run focused red/green command(s):

```sh
python -m pytest -q tests/test_managed_journey_contract.py
npm --prefix apps/heel-cloud run test:managed-authority-browser -- --output "$HEEL_PACKET_SCRATCH/browser-proof" --max-seconds 900
```

- [ ] Run affected package: **UI + Runner + CP**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Useful two-identity GET pair persists correlated redacted findings; HEAD cannot invent content evidence. Synthetic route can be explicitly approved for C4 integration while C3 is STOP, but this does not satisfy default discovery or customer readiness. Report that distinction and keep P18 blocked.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P16 real browser observations and paired synthetic product journey" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P17: Delivered artifact parity and reviewed release integration

**Owner:** fresh Opus. **Base / prerequisites:** I+P16; C5-IMPL/C6-IMPL, H6-IMAGE manifest and upstream digest/hash-lock/security reviews. P17 creates the executor image from the H6 manifest; it does not wait for an image that only P17 can build. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `MANIFEST.in` — modify
- `scripts/build_open_core_release.py` — modify
- `release/open-core-v1.json` — modify
- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2-py3-none-any.whl` — modify
- `apps/heel-cloud/public/downloads/heel_sim-1.3.0rc2.tar.gz` — modify
- `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` — modify
- `deploy/Dockerfile.control-plane` — modify
- `deploy/Dockerfile.executor` — create
- `deploy/compose.yaml` — modify
- `deploy/.env.production.example` — modify
- `tests/test_managed_artifact_parity.py` — create
- `.github/workflows/ci.yml` — modify
- `docs/saas/MANAGED_AUTHORITY_PROOF.md` — modify

**H6 serialization — A-ART3/A-PREFIX/A-ENR2 (§§7.4a,9–10,12):** Consume H6-IMAGE's facts after the accepted merged B0/BIR frozen handoff; retain ten nonmechanical + three downloads. Existing compose/Dockerfile paths wire the host root launch verifier and disable direct CP autostart/restart; service invocation is specified in H6-RUNTIME's existing runtime document. Do not add root credentials/runtime sockets to CP. No new unit file, runtime daemon change, third-party implementation, requirements file or hidden path is granted: inability to express deployment here is a concrete ownership gap requiring separate reviewed scope.

`tests/test_managed_artifact_parity.py` owns E14/E15/E20: repeat every-launch measurement, exact receipt comparison and lifetime/channel checks on `release` images without checkout; reverify enrollment deliberately on release. Freeze exact OCI manifest/blob/snapshot/mount/normalization and measured image/memory/scratch maxima; same tree or recipe is not same artifact. Maintain source-free `/opt/heel` private overlay and CP `/app` closure; hash-locked executor requirements use the existing Dockerfile heredoc, with no ungranted lock file. B0's requirements/verification/test support paths remain read-only. All source/public-wheel/private-image positive and negative parity proofs and download regeneration stay required.

**Behavior/interfaces:** Package only accepted integration tree. Source/artifact parity was already restored at each shipped-source packet; P17 composes final release and image identities. Regenerate delivered runner copies, inventory generated wheel/sdist/image/config/renderers for old active selectors and registry caches. Keep CP/root private modules out of Apache public wheel; do not expand public module policy implicitly. New runner module inclusion must pass existing release allowlist/privacy contracts. H6 accepted image facts supply exact digest and hash-locked dependencies; no floating base or dependency install. CI adds narrowly named managed proof/browser jobs after source acceptance with correct privilege gates and pinned actions, leaving review-action workflow untouched. Proposed job ids: managed-authority-proof and managed-authority-browser.

**Tests written first/with code (proposed names and fixtures):** `test_wheel_source_and_image_installed_module_parity`; `test_delivered_managed_entry_has_no_legacy_selector`; `test_public_release_excludes_private_CP_root_and_secrets`; `test_image_digest_and_dependency_hash_lock_match_review`; `test_ci_checks_out_actual_candidate_and_proof_import_identity`. Inspect installed __file__/module hashes from clean artifact-only runtime, not source checkout imports.

- [ ] Run focused red/green command(s):

```sh
python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
HEEL_REQUIRE_STANDARD_BUILD=1 HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m pytest -q tests/test_managed_artifact_parity.py tests/test_open_core_release.py tests/test_public_runner_preview_release.py tests/test_saas_deployment.py tests/test_release_automation.py
```

- [ ] Run affected package: **UI + Runner + CP + Host**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Build without --check once only when regenerating allowed outputs, then --check must reproduce byte-for-byte. No version policy decision hidden here: if accepted upstream version changed, revise exhaustive paths/grant before writing. Pin image digests, wheel/sdist/source hashes, CI checkout HEAD/tree (including synthetic merge identity), import identities and all job conclusions. Green CI alone does not close upstream digest/hash-lock review or remaining scanning-alert dispositions. No push/publish/deploy by this packet.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P17 delivered artifact parity and reviewed release integration" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

## Packet P18: Final clean-room and customer acceptance record

**Owner:** fresh Opus. **Base / prerequisites:** Exact reviewed P17 release/integration tree, delivered image/wheel/Worker digests; C3 STOP explicitly cleared by its owner, actual H3/DNS/C5/C6/H6 acceptance, authorized deployment/target. **Independent acceptor:** fresh Astra.

**Exhaustive allowed tracked files:**

- `docs/saas/MANAGED_AUTHORITY_ACCEPTANCE.md` — create

**Behavior/interfaces:** Run existing accepted customer/release acceptance machinery on delivered artifacts in a clean environment. Revalidate fifteen outcomes and twelve safety properties below through public browser→Worker→CP→real paired executor. Synthetic known-positive/patch transition is layer1; separately real authorized SaaS not prepared for Heel is layer2. Record user authorization and target/data provenance separately from ownership proof; one identity proves signed-out/signed-in only. No new parser/discovery/model workaround while C3 STOP. No manually seeded DB/seed copy, fixture-only adapter, canned finding, local-source requirement or hidden admin setup.

**Tests written first/with code (proposed names and fixtures):** Acceptance cases `C4_clean_room_layer1_detection_patch_replay`, `C4_clean_room_layer2_unprepared_SaaS`, `C4_clean_room_delete_revoke_STOP`, and each O01–O15/S01–S12 mapping below. Use P16 browser command against exact approved deployed endpoints via private runtime config (no secrets in argv). Preserve target receipt and CP charge correlation for every actual initial/next/retry.

- [ ] Run focused red/green command(s):

```sh
npm --prefix apps/heel-cloud run test:managed-authority-browser -- --output "$HEEL_PACKET_SCRATCH/clean-room" --max-seconds 900
python scripts/customer_acceptance_preflight.py --help
```

- [ ] Run affected package: **Final release required suites at exact candidate**, then common full required suite on the final candidate. Expected: all required assertions pass, intentional skips individually justified; runtime/privileged stages blocked until authorized qualified environment, never counted as PASS from unit results.
- [ ] Review acceptance oracle: Preflight --help is capability inspection only, never acceptance; choose its actual supported deployment inputs in the separate runtime grant. Do not invent flags or claim preflight equals journey proof. Missing prerequisites produce BLOCKED with named owner, not PASS. Fresh independent Astra accepts source/CI/runtime evidence; only authorized coordinator/user can grant release/deployment. This packet authors only the acceptance record, not another implementation pass.
- [ ] Commit only the allowed changed paths with `git add -- <explicit paths above>` then `git commit -s -m "feat: managed authority P18 final clean-room and customer acceptance record" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`; for evidence-only P18 use docs subject. Record commit/tree, commands, failures, hashes and clean status.
- [ ] Fresh independent Astra challenges the whole packet and records ACCEPTED/BLOCKED before successors. Any correction is a fresh bounded Opus task; no reviewer repairs its own candidate.

### P18 mandatory Layer 1 and Layer 2 acceptance detail (F3)

Customer-ready §§6.3/6.4 are mandatory, separately verdicted stages. Layer 1 starts with URL, proof, two credentials and explicit authorization on a real synthetic HTTPS target: authenticate, discover an **undeclared** export route from authenticated HTML/JS (`html_link_auth` or `js_literal_auth`), approve the finite scan, observe `finding/body_superset/observed`, save the regression, patch the target, replay and observe `pass/blocked`. Correlate target access receipts, run/action/attempt, durable admission/charge and containment. A hand-built two-role route pair, manual seed, optional OpenAPI import or fixture credentials injected below the product is not default discovery acceptance.

Layer 2 uses the separately authorized actual SaaS not prepared for Heel, with no repository checkout/install/OpenAPI/manual endpoint or login-shape editing. Timestamp signup, URL/proof check, customer-labelled credentials, automatic proposed login declaration plus customer confirmation, Authorize discovery, partial/completed inventory with provenance, ≤10 selected candidates, hostname-confirmed scan approval, findings/no-findings and audited evidence view; then delete credentials with executor acknowledgement, delete evidence and revoke target. One identity proves signed-out/signed-in only, never plan-differential detection. DA/C5 must prove exactly the bounded authorized login count per identity/authorization/run and separate discovery (≤100), scan (≤20) and login traffic counters; prelogin GET counts in its proper budget. No unsupported SSO/MFA/CAPTCHA/private-address/proof/login-shape state can be hidden or called PASS, and no finding may be fabricated for an honest `findings.none` or held/inconclusive result.

Repeat the same product code on a second target with different hostname, inventory and credentials; review the diff for target-host/fixture/demo special cases. Record customer synthetic-data and “not prepared for Heel” provenance statements separately from ownership proof and the product authorization record. Byte-scan canary credentials and target data at every specified sink: CP DB dump/queues/caches, Worker and executor logs, traces, metrics, crash dumps, support exports, CI/output artifacts, model API payloads, inventory/projections; raw scan bodies may exist only in authorized bounded evidence custody, discovery bodies never persist. Scan seed/key material too where applicable. Record elapsed minutes signup→first understandable result (target ≤15 minutes), with customer-paced ownership-proof time separately identified. Layer 1 proves mechanism; Layer 2 proves onboarding; neither can substitute for the other. Actual provider, secret, billing, deployment or customer authorization gaps remain named dependent HOLDs.

## Customer outcomes and safety acceptance matrix

**CONFIRMED requirement sources:** B customer-ready spec §§2/6 and launch spec §2 journey rows 1–15/§10. Those audits describe their historical bases, not current product defects. **INFERRED confirmation action:** P18 reruns the following existing journeys on the exact delivered candidate; P16 supplies intermediate synthetic evidence only. Reuse accepted signup/project/verification/approval/findings/regression components and existing tests, do not speculatively rebuild them. Each outcome needs timestamped browser/CLI evidence, artifact identities, target receipts where applicable and an independent verdict.

| ID | Preserved customer outcome, including customer-ready amendments | Revalidation / external gate |
|---|---|---|
| O01 | Reach public HTTPS product | P17/P18 deployed Worker/CP identity, certificate and public entry |
| O02 | Sign up/login through production auth | P16/P18 real browser→Worker→CP, sessions and throttles |
| O03 | Create/select workspace/project | P16/P18 isolation and selection through UI |
| O04 | Register and successfully verify target | Actual ownership challenge/check; authorization proof is not target provenance |
| O05 | Obtain execution without engineer setup | Managed default, no customer Python/source/install requirement; optional private connector release install remains revalidated |
| O06 | Pair through product | Real root ceremony/PoP/CP, explicit fingerprint/key/managed association, no seed copying |
| O07 | Supply identities with explicit roles/plan labels | C5 browser intake to vault, two identities for plan pair; one identity honest comparison only |
| O08 | Obtain inventory | Default authorized discovery C3; optional OpenAPI still works. No requirement for customer OpenAPI; STOP blocks default-path acceptance |
| O09 | Review dry run / finite plan | Inventory/selection/scope digest visible, no target execution from preview |
| O10 | Approve and execute scan from product | Each actual GET/HEAD initial/next/retry has durable Q and correct signed action/credential mapping |
| O11 | Observe progress/recover | Last-checked status; lost replies/CP outage visible, no authority rehydration; fresh authorization where required |
| O12 | Receive honest observed/verified findings | Default authenticated HTML/JS discovers undeclared export route (`html_link_auth`/`js_literal_auth`); `finding/body_superset/observed`, then patch and saved replay `pass/blocked`; HEAD inconclusive |
| O13 | Inspect redacted evidence | C6 audited bounded view, raw evidence remains controlled, exact Q attribution |
| O14 | Save/replay regression | Vulnerable fail/still_reachable then patched pass/blocked through product and preserved CLI |
| O15 | Revoke runner/target and delete credentials/evidence | Independent R, prompt STOP, C5/C6 signed deletion/retention, cleanup separately observed |

| ID | Preserved safety property | Named evidence/gate |
|---|---|---|
| S01 | Verified-origin confinement incl redirect/rebinding/address/Host | Existing `tests/test_runner_plan_differential_safety.py` and `tests/test_runner_http_transport.py`, P15 physical target/packet oracle |
| S02 | Approved-inventory GET/HEAD; only separately authorized narrow login_exchange exception | Q admits only GET/HEAD here. C3/C5 separately own discovery/login_exchange; this plan does not add POST to Q or silently claim it covers those operations. DA-IF then DA-IMPL are named mandatory gates before default P16/P18; no POST in Q |
| S03 | Signed immutable scope and one-shot request | P05/P10 wrong signed projection/action fixtures, per-attempt charges and spend-before-dial |
| S04 | No credential outside vault/specified transient intake | C5 proof plus P11/P12/P16/P18 scans of CP DB/queues/caches, Worker/executor logs/traces/metrics/crash dumps/support exports/CI artifacts/model API payloads/inventory/projections; no secret-derived receipts |
| S05 | Bounded raw evidence on executor, projections only at CP | C6 and P11 real persistence/view deletion/legal-hold tests |
| S06 | Verifiable containment attribution | P10/P15 request-before-send entry and tamper verification bound workspace/project/runner/grant/route/ordinal/attempt/Q |
| S07 | Workspace/project isolation | P04 cross-tenant route tests and P16 second-account attempt; host per-workspace isolation under H6 |
| S08 | Pairing/verification non-replayable | P03/P04/P12 exact PoP, all public/internal/legacy replay routes, restore/old epoch P14 |
| S09 | Idempotent quotas without uncertain refunds | P05/P06 claim reservation/charge high-water, concurrency, retained lifetime tuple; existing account/discovery quotas preserved |
| S10 | Prompt revocation | R independent of host writer; P15 original H1/H2 bounds and product <=5s gate plus H6 provider proof; C5/C6 deletion acknowledgements distinct |
| S11 | Sessions/origin/CSRF/rate limits/audit | Existing `tests/test_saas_http_api.py`, `tests/test_runner_control_http.py`, P04 and real Worker P16/P18 |
| S12 | Offline/lost authorization/malformed input fails closed visibly | P01 malformed/oversize, P05 unknown commit, P10 late callback, P14 interrupted restore, P16 frozen/offline browser |

C3 STOP is an explicit external dependency, not a newly assigned parser/model prompt task. The real non-simulated SaaS path must be authorized and unprepared for Heel; record human provenance statement separately from file/DNS ownership proof. Layer1 synthetic pass never substitutes for layer2, and no unit/mock boundary is a clean-room success. C5/C6 login/intake/evidence integration cannot be waved through with fixture credentials. If the named C4-IF/C5-IF/C6-IF/H6-IF/DA-IF handoffs fail to compose, block their first consuming packet and return that precise interface gap to the owner; no broader architecture audit or weaker contract is authorized.

## Dispatch, evidence and stop conditions

This plan is reviewable documentation, not an implementation grant. Next step is fresh independent whole-plan review; no execution-choice question is needed. Only after acceptance does the coordinator issue bounded Opus grants using these packet lists, exact current bases and reviewed prerequisites. No agents/messages are sent by this planning task.

For each future packet, evidence must record: source base/HEAD/tree; allowed-file diff; red/green and package/full command argv/exit; runtime/OS/kernel/library identities; non-secret fixture origin; exact test cases and skips; review ID/verdict; artifact/import hashes; known gaps. Real tests add commit-vs-reply barrier logs, DB/page/index/WAL snapshots, immutable Q/W/deadline association, physical request/packet counts, containment/evidence refs and cleanup result. Hashes must exclude the hash manifest itself, mutable session state and private capability/secret-bearing captures. Do not erase old failed diagnostics. CI evidence records the **actual checked-out** commit/tree, head vs merge SHA and deployed digest, not merely a green badge on a branch name.

Stop a dependent packet on: missing independent predecessor acceptance; H3/DNS unresolved status; source/base or ownership drift; missing C5/C6/H6 contract; inability to preserve exact budgets/nullability/STOP/custody; physical storage overflow; unexplained test skip/failure; stale artifact/CI identity; absent clean-room stage. Ordinary source drift calls for a narrow updated grant/review, not design weakening. Remaining image upstream digest/hash-lock and scanning-alert dispositions, release packaging, deployment authorization and real customer readiness remain independent gates even after every local suite passes. No new price or billing policy is proposed.

## Interface transcription checklist for P01/P05

These sets supplement the behavioral tables; Q §6 and retained EA §4 remain the exact schema authority. P01 must compare every field, grammar and canonical byte example to those pinned sources, not infer fields from Python defaults.

- Window request v3 exact set: `schema_version, kind, restore_epoch, managed_executor_id, pairing_epoch, pairing_id, host_boot_epoch, slot_id, generation_id, bootstrap_fence, workspace_id, project_id, environment_id, verification_record_digest, runner_id, runner_key_id, binding_id, binding_digest, run_id, grant_id, grant_digest, kill_switch_generation, sequence, request_nonce, monotonic_ms, operation_digest`. Kind `execute_window`; raw fence hex32, restore/digests hex64; existing full 128-character runner/key/grant grammar, never S's narrower historical runner/key spelling on this wire.
- Attempt request v1 is that set with schema/kind changed to `heel.managed-attempt-request.v1` / `execute_attempt`, plus `window_operation_digest, manifest_digest, action_ordinal, method, route_template_digest, route_digest, semantic_role, attempt, previous_failure_code, attempt_deadline_ns`. Roles exactly anonymous/authenticated/object_owner/non_owner/lower_privilege/higher_privilege/lower_plan/higher_plan. Method GET|HEAD, ordinal0..19, attempt1|2, failure none|connect_error|timeout subject to progression/policy. No null failure on wire.
- Window descriptor v2 exact set: `schema_version, request_identity_digest, handle_nonce, handle_mark, namespace_dev, namespace_ino, process_instance, src, dst, prepared_ns, prepare_return_ns, request_start_ns, tick_ns, lease_ms, exchange_deadline_ns, scope_digest, bootstrap_fence`. Actual root object values; lease3000ms, no caller namespace/path. Attempt descriptor v1: `schema_version, request_identity_digest, window_operation_digest, bootstrap_fence, process_instance, manifest_digest, action_digest, route_digest, credential_binding_digest, action_ordinal, method, semantic_role, attempt, attempt_deadline_ns, request_start_ns`.
- Attempt notification v1: `schema_version, request_digest, attempt_digest, window_operation_digest, bootstrap_fence, generation_id, run_id, sequence, deadline_ns`. Resolve exact already-pending object; receipt/notification never creates one. Window notification/response use retained EA exact sets plus raw fence; attempt response adds `attempt_digest, window_operation_digest, attempt_deadline_ns`. Admitted/refused union must be checked separately: refusal carries no active fields. Terminal failure wins over duplicate success; quotas→resource_exhausted, identity/duplicate→operation_mismatch.
- Ceremony v3 retains EA envelope plus raw fence on request AND response, including poll/none. Exact payload alternatives remain key offer, challenge, terminal, retired ack, identity observation. **No activated.v1 payload or active local acknowledgement**; identity_observed is not an admission. Null managed identity resolves only via trusted installation/slot/exact epoch. S slot ids outside H's stricter host grammar refuse enrollment, never normalize silently.
- Observation exact set: `schema_version, managed_executor_id, observation_kind, authority_revision, observed_at_ms, observed_state, pairing_id, runner_id, runner_key_id, delivery_status, host_ack_state, recovery_code, retry_after_ms, original_pairing_expires_at_ms, cancellation_phase`; schema `heel.managed-executor-observation.v1`, kind `historical_not_authorization`, revision0..2147483647 never wraps; status POST body `{}`, no-store, <=4096. EA §8 plain Last checked copy supersedes predecessor protocol-heavy wording; tuple/revision is internal, not new UX metadata.
- Durable attempt exact columns: `restore_epoch, tuple_digest, run_id, generation_id, ordinal, method, semantic_role, attempt, manifest_digest, route_template_digest, route_digest, window_operation_digest, operation_digest, request_digest, bootstrap_fence, exchange_sequence, authority_revision, admitted_at_ms, attempt_deadline_ns, previous_failure_code`. Presence means charged. Run aggregate and claim reservations cannot be reconstructed from a new generation or client report.

## F1 correction: shared capacity ownership before admission (PROPOSED)

This corrects planning ownership, not the independently accepted H6 design. H6's exact transcript and section hashes remain unchanged. Its §5.4 INFERRED P05 placement note is resolved here by **earlier P02 production**, P03/P04 and CP-WRITERS participation, then P05 consumption. No accepted capacity, lifetime, terminal, oracle or customer contract is relaxed. `B:file:line` below means immutable `f736279a33bc1b8bd094e301ddd52045eb96a149`, not a claim about unimplemented successor code or this documentation branch's inherited product ancestry. Evidence: `.worktrees/heel-task-evidence/C4-MANAGED-PLAN-H6-R3-F1/SOURCE-MANIFEST.json`, `source-boundaries.json` and `BOUNDARY-OWNER-TEST-MAP.md`. Graph search/trace preceded immutable Git/AST fallback; the graph is discovery, not historical source authority.

### Producer API, identity and lifetime

P02's existing new `heel/saas/managed_authority_ledger.py` produces `CPWriteDomain` without importing service/server modules. It has two distinct mechanisms: the existing exclusive database-process lock (same exclusive `.lock` inode/path semantics extracted from `server.py`, with F2 removing managed pre-ownership creation/chmod rather than preserving that unsafe historical ordering), and **one CP-process capacity mutex**. The mutex is keyed by the trusted installation/volume identity and canonical sole CP database path, shared by HTTP, host admission, reaper, every independent connection and every store instance. Construct/register it before opening any CP connection; validate path/device/volume and reject alias/replacement/multiple-database ambiguity. Binding an existing connection verifies `PRAGMA database_list` against the already validated identity outside a transaction. A new instance, connection, thread, service or caller-supplied path cannot silently create another domain. An in-memory test domain must be explicitly isolated; it does not qualify production. No public wire field, persisted authority, new lock file or new filesystem budget is introduced.

Proposed exact private API:

- `CPWriteDomain.open_owned(identity, process_lock)` returns the process singleton only after verified exclusive DB ownership; it does not connect to SQLite or start a transaction. P02 moves the reusable process-lock primitive from `server.py` into this module while preserving its identity and lifetime. Offline callers acquire that same process lock, not a second lock naming scheme.
- `domain.unit(*, kind, deadline_ns, conn=None)` yields an opaque `CapacityToken`; `kind` is closed to `admission`, `ordinary`, `terminal`, `maintenance`. It acquires before connection open/recovery/DDL/first implicit write/BEGIN, never after SQLite ownership. An already-active transaction without the exact current token is rejected **before any mutation**, not repaired by late acquisition. `token.bind(conn)` registers a newly opened connection before SQL; `token.join(conn)` verifies the same thread/domain/connection and active outer token without acquiring/releasing/committing. Noncommitting helpers use join; nested wrappers cannot begin a second transaction. Cross-connection recursive acquisition fails before SQL. Token cannot cross threads or survive its context/process/fork.
- `token.sample(cost_profile)` performs physical sampling/checkpoint checks before BEGIN; `token.reserve_in_transaction(conn, cost_profile, terminal_delta)` rechecks durable aggregate obligations under BEGIN using that same token and fresh sample. P02 owns these noncommitting accounting primitives and strict measured-profile validation; P05 supplies Q/admission-specific policy, P06 supplies verified worst-cost profiles. Ordinary writers consume a profile for their own bounded mutation, including rollback/close overhead; no caller-supplied optimistic byte estimate. Reservations and terminal deltas commit/rollback with their owning mutation. Missing/invalid profiles deny new growth, not previously reserved terminal completion. These are private APIs, not new public wire/schema authority.
- Outer owner explicitly BEGINs and commits/rolls back. Unit exit in `finally`, including `BaseException`/cancellation, rolls back any uncompleted transaction before releasing; no return path silently commits. If rollback/close fails, quarantine connection/domain, stop new admissions/readiness and preserve original error; never release an ambiguous live writer for reuse. Closing the owned connection under the token must establish teardown before release; inability to establish it keeps the domain fenced until process termination. Successful commit followed by response failure remains charged/unknown, not replayable/refundable. Release is exactly once after transaction end and any close-triggered checkpoint. Connection creation, PRAGMA mode change, WAL recovery and teardown each have their own guarded unit when outside an ordinary transaction.
- Bounded lock acquisition uses a monotonic deadline no later than `min(caller original deadline, entry + 250ms)`; SQLite busy wait consumes the remaining same budget, never starts a fresh 250ms window. Preserve any stricter existing deadline. Waiters have bounded queue admission and cancellation removes the waiter. Waiting terminal work precedes new admission/ordinary work, FIFO among terminal waiters; active units are bounded and contain no network/host cleanup wait. Maintenance requiring long work runs only while drained, with bounded chunks/deadlines, never while target authority is serving. Internal errors are `capacity_busy`, `capacity_scope_error`, `capacity_io_error`; owning adapters map them into existing closed wire errors (no new Q error variant). Admission cannot be issued on timeout. A terminal timeout is retryable operational contention under its existing bounded reaper/STOP policy, never “resource_exhausted” from admission pressure or a false terminal-success acknowledgement. Exhausted operational retry budget drains/fails readiness; qualification must prove terminal commit within original STOP bounds, not justify missing progress with retries.

Ordering is **L → runtime artifact lease → child database-process lock → per-connection/service/request gate → capacity mutex → SQLite**. The first three are lifetime ownership as specified by H6, not reacquired per request. Never acquire a service/request gate, L, artifact lease, host writer lock or another connection while holding the capacity token. P04 resolves same-connection helper calls with `join` and pure nonlocking helpers; P05 `_db_gate` stays before capacity. Verification's DNS/TLS phase releases both SQLite and capacity, then reacquires the same order and rechecks state. There is no mutex across a whole HTTP request, external call, response write or reaper sleep. Do not use generic execute/cursor interception to acquire a lock: it misses implicit writes, executescript, recovery and close and can invert BEGIN ordering. Guard assertions may reject an unowned write but cannot manufacture ownership.

Supported production contexts remain one CP process, multiple threads/connections, uid 10001 alone writing D_CP. A second server/standalone repair/backup writer must fail the same process lock before opening a write-capable connection. Managed migration/restore runs only in the H6 fenced offline child after ordinary owner/workers are reaped; P14 preserves L/lease/process-lock/token ordering. No multi-process writer/backend support is added by this plan. A read-only maintenance verifier cannot upgrade to repair; read opens/close that might recover WAL or alter SHM are guarded or performed only under exclusive offline ownership. New writers and newly introduced triggers inherit the same-domain rule before their first physical effect, regardless of managed versus connector provenance; triggers run inside their caller's token. Each future grant must regenerate the exact callsite manifest for its accepted B+n and reject any uncovered path, not treat this historical list as proof of future code.

### Complete bounded owner map

Every row owns acquisition at the **outer** boundary and release after commit/rollback/teardown. Names ending `_in_transaction`, audit/insert helpers and savepoint subroutines inherit a verified caller token and never acquire late. Standalone use of a helper requires a separate guarded outer entry in that same owner file. The evidence map lists every scanned callsite, including read candidates, with source hashes so the following grouped entries can be challenged. Tests below are planned obligations, not executed product tests.

| Producer/consumer owner | Exact production paths and historical boundary inventory | Required handling / future tests |
|---|---|---|
| P02 producer/schema | `heel/saas/managed_authority_ledger.py` (new); `heel/saas/canary_store.py`: `CanaryStore.__init__`, all `ensure_*_schema`, `_apply_runner_context_schema_script`; `heel/saas/migrate.py`: `Migrator.__init__` tracking DDL, `apply_all`, `copy_table`, CLI `main` | Token before constructor DDL, SAVEPOINT and executescript, not only BEGIN. Guard whole script including implicit commit; script forbidden inside caller transaction unless replaced with transaction-preserving statement execution by this owner. `copy_table` destination physical domain participates; reject cross-domain write in a live managed unit. F1-M01/M02. |
| P02 early setup/maintenance (two explicit added paths) | `heel/saas/server.py`: `build_server`, migration connection at B:445, WAL/FULL PRAGMAs, construction and close/unwind; `scripts/saas_backup.py`: `backup` B:23–30 and `verify` | Establish singleton/process ownership before first connect, wire one domain through construction and close after worker join. Managed backup must use offline exclusive ownership and destination outside D_CP; reject aliases/same-volume destinations before create. Never use the current unchecked online writable source open on a serving managed DB. Read-only verification stays nonrepairing. No new backup/restore workflow or volume enlargement. F1-M03/M04; P14 later owns server lifecycle/gate handoff, not retroactive repair. |
| P03 then P04 | `heel/saas/managed_pairing.py` (new); `heel/saas/runner_auth.py`: `invite`, `exchange`, `approve`, `activate`, executable/rotation activate/abort/challenge, provision chains, revoke, start/approve rotation, resync, attest, authenticate/consume, receipt purge, `reap_expired_auth`; schema initialization/lifecycle tables | P03 guards new ceremony wrappers; P04 closes all remaining outer wrappers, including deferred BEGIN/read-then-write and auth constructor DDL. `_in_transaction` variants join. F1-R01/R02 and P03 ceremony tests. |
| P04 reaper | `heel/saas/canary_reaper.py`: `_connect`, `_service`, `_disclosure_service`, `_cycle`, `run_once`, `_run` | B:534 BEGIN→542 commit/545 rollback and B:551 BEGIN→554 commit/557 rollback are separate units. `expire_and_reconcile` and `reap_expired_auth` own their intervening/following units in their respective P04 modules, not one reaper-wide mutex. Guard open/schema construction and final close. `_request_authority_stops` inherits caller token. F1-R01–R04. |
| P04 run/context | `heel/saas/canary_runs.py`: constructor/`ensure_discovery_plan_schema`, submit, approve, claim, heartbeat, progress, request/ack stop, result, discovery create/get/revoke/close, `expire_and_reconcile`; `heel/saas/runner_contexts.py`: create, revoke, create_plan_request plus transaction-sharing expiry/cancellation/purge/claim/projection/list functions | Explicit wrappers acquire before BEGIN; even nominal get/list paths that expire state participate. Helper writes stay inside their caller unit. P04→P05 run-file handoff preserves every existing unit. F1-R01/R03. |
| P04 HTTP/implicit ops/verification/disclosure | `heel/saas/http_api.py`: `ControlPlane.__init__`, connection factory and `runner_request_store`, `_signup`, shared/independent close paths, route callers; `heel/saas/ops.py`: constructor, `record`, `trip`, `clear`; `heel/saas/verification.py`: both verifier constructors/start/check/revoke, `rotate_unrecoverable_challenge`, `_record_failure`, `_finalize_success`; **added** `heel/saas/canary_disclosure.py`: constructor and `_write` enclosing preview/permit/upload/local-only/purge | Guard before implicit DML and context-manager transactions as well as explicit BEGIN. Split verification network phase; never lock over DNS/TLS. `_write` detects validated nested token rather than acquiring after caller BEGIN. HTTP request lock alone is insufficient for reaper/host connections. F1-R02–R04. |
| CP-WRITERS identity/account | `heel/saas/tenancy.py`: `ControlPlaneStore.__init__`, create org/workspace/user/invite, set plan, add/accept member/invite, issue/authenticate/revoke API key; `heel/saas/auth.py`: constructor, password set/rehash, failure record/clear, throttle signup, create/resolve/revoke sessions; `heel/saas/device_auth.py`: constructor/start/poll/inspect/decide/exchange/refresh/revoke and mint/revoke-family helpers | Includes reads that touch last-used/expiry/throttle rows, autocommit and implicit transactions. Constructor connect occurs inside unit, not before binding. Reentrant same-connection calls join without premature commit; extract noncommitting helper only within owned files. F1-W01/W02. |
| CP-WRITERS billing/work/recovery | `heel/saas/billing.py`: constructor/upsert/record_event; `heel/saas/projects.py`: constructor/create; `heel/saas/ledger.py`: constructor/reserve/settle/refund/consume; `heel/saas/jobs.py`: constructor/enqueue/claim/heartbeat/settle/reap/purge; `heel/saas/findings_sync.py`: constructor/approve/accept/audit; `heel/saas/reconcile.py`: repair branch and `_repair_canary_refund` B:196 / `_repair_canary_compensation` B:222 | All same-volume ordinary writes participate even when unrelated to managed rows. `repair=False` remains read-only; repair helpers run guarded units, ledger `_in_transaction` joins. Existing context-manager commit/rollback must occur before token exit. F1-W01–W03. |
| P05 admission/physical sample | `heel/saas/host_snapshot.py`: `_transaction` B:255–279, `_ledger`, `_close`, `_require_capacity`; `heel/saas/host_authority.py`: service construction/teardown/admission dispatch; `heel/saas/canary_runs.py`, `heel/saas/managed_authority_ledger.py` sequential extensions | Sample under the already shared token before BEGIN; retain through decision/commit or rollback/close. Host listener publication/cleanup is on D_CP and participates in the same capacity domain under the F2 local-effect protocol below. F1-A01–A03 and F2-L01–L08, then F1-S01–S06/F2-S01–S03. |
| P14 offline/restore | `heel/saas/managed_restore.py`, `deploy/host/managed_migration.py`, `heel/saas/server.py`, `docs/saas/RUNBOOKS.md` (existing exact P14 scope) | Root-owned equal-size replacement only when old child/workers are gone under H6 EX/lease; child DB token before reconciliation BEGIN and schema/recovery/close. No serving-device copy, extra backup inside D_CP, automatic epoch rotation or lost-output replay. Existing restore tests/proof plus F1-S05 integration rerun. |

Scope closure: immutable AST inventory scans all Python under B `heel/`, `deploy/`, `scripts/`, not only these modules. `heel/saas/catalog.py`, `dashboard.py` have read SQL only; `network_guard.py` socket `connect` is not SQLite. `heel/store.py` is the local engine store, `heel/runner/runtime.py` the executor runtime DB, not the CP `ControlPlaneStore` in `tenancy.py`; H6 layout keeps executor/local stores and slot files outside D_CP. Those paths receive no grant; P07/P14 must reject configuration/alias that places them on D_CP. Other scripts are caller/proof consumers of these modules, not licensed independent physical writers. SQL schema constants/triggers in these files inherit constructor/migrator token. The bounded source manifest also lists non-SQL file mutations; P14/H6-RUNTIME qualify mount routing so root metadata, logs, temporary files, artifacts, export/backup destinations and slot storage cannot silently consume D_CP; the listener socket is explicitly included on D_CP. F2 supplies exact filesystem/lifecycle dispositions and supersedes generic outside-CP candidate labels in the F1 evidence map. Existing root provisioning/replacement is H6-RUNTIME/P14 offline work, not a concurrent CP writer. No new runtime, third-party or unit-file path is authorized.

### Capacity and progress rules

P05 owns policy under the P02 primitive: checkpoint (if needed) while holding capacity and outside SQLite transaction; if blocked, admit no new work. Then take the fresh statvfs sample under the same token before BEGIN, never sample first then acquire. In the transaction, recheck durable logical/ledger/outstanding-terminal obligations and conservative WAL growth against the pre-BEGIN measurement; do not call stat/statvfs or perform a physical checkpoint inside SQLite. Then reserve prospective insert + worst-case WAL + new terminal obligation atomically, commit then release. Keep the physical sample exclusive until that commit/rollback. Every ordinary growth unit, including connector/auth/billing/jobs, must preserve the reserved terminal headroom and its own measured worst-case cost; no “not a managed row” exemption. CP-WRITERS/P04 own these prewrite checks through the shared P02 reservation interface, P05 refines admission, P06 supplies measured costs. Until measured, new ordinary/admission growth is disabled in managed production; authorized fixture work remains labelled. Terminal/revocation and bounded cleanup spend previously reserved capacity and never run the admission-ceiling refusal branch. Do not make terminal progress depend on unmeasured optional admissions.

All H6 numbers remain exact: D_CP 768 MiB, slots 256 MiB, CP admission 640 MiB, ledger 512 MiB, WAL 64 MiB, aggregate outstanding terminal obligations ≤64 MiB, ≥1024 remaining inodes and exclusive 128 MiB terminal reserve. SQLite indexes, freelist, metadata, WAL/checkpoint side effects and retained history count physically. Commit, rollback and connection-close checkpoint costs must be included. Growth units that cannot establish a safe prospective allowance refuse before mutation; no deletion/VACUUM/pruning of authority history to manufacture space. Existing authorized bounded retention remains subject to Q/H6, not expanded by this synchronization work. WAL autocheckpoint at guarded commit/close remains under token; explicit checkpoint only in guarded nontransactional unit. Reserve accounting and terminal-priority scheduling need real proof of useful admission plus progress; serializing everything and refusing every useful operation fails acceptance.

### Supplemental packet CP-WRITERS (PROPOSED, 10+0)

**Owner:** fresh bounded Opus; **prerequisites:** accepted P04 (transitively P02 producer and P03); **consumer:** P05; **independent acceptor:** fresh Astra. These paths are absent from the old 107 list and cannot be assigned to P06 tests or smuggled into P05. This is the smallest explicit additional production set found by the source closure: nine existing ordinary/recovery writer modules plus one focused test. P02's two added setup/backup paths and P04's one disclosure path bring P01–P18 to 110, plus this 10 = 120. H6-LAUNCH/RUNTIME/IMAGE remain 6/6/2 separately; inventory grants remain separately counted. No transfer of unrelated feature ownership; only transaction/capacity participation and necessary same-connection helper composition in these files.

**Exhaustive proposed tracked paths:**

- `heel/saas/tenancy.py` — modify
- `heel/saas/auth.py` — modify
- `heel/saas/device_auth.py` — modify
- `heel/saas/billing.py` — modify
- `heel/saas/projects.py` — modify
- `heel/saas/ledger.py` — modify
- `heel/saas/jobs.py` — modify
- `heel/saas/findings_sync.py` — modify
- `heel/saas/reconcile.py` — modify
- `tests/test_managed_cp_writer_boundaries.py` — create (private CP test)

- [ ] Write F1-W01–W03 first and show failure without each relevant outer guard, including implicit session/API-key touches and repair helpers.
- [ ] Add only the named domain/outer-boundary participation, keeping existing semantics and noncommitting inner helpers; no connection proxy/monkeypatch shortcut.
- [ ] Run red/green `python -m pytest -q tests/test_managed_cp_writer_boundaries.py`; then affected CP package and common full required suites at the exact committed candidate, preserving their authorization/runtime requirements. P02/P04 use their existing focused commands plus the F1 names below.
- [ ] Commit only these ten paths with DCO and Opus attribution; record exact source/connection/mutator inventory and per-boundary tests, diff/tree/command results. Fresh Astra acceptance precedes P05. No product implementation grant is issued by this plan.

### Named future real tests and offline countermodels

| IDs / exact proposed test names | Existing/new test owner and required counterexample/positive |
|---|---|
| F1-M01 `test_capacity_domain_identity_and_foreign_transaction_rejection`; M02 `test_schema_scripts_implicit_commit_and_rollback_guard`; M03 `test_setup_recovery_close_share_capacity_domain`; M04 `test_managed_backup_excludes_live_owner_and_cp_destination` | P02 `tests/test_managed_authority_migrations.py`: independent connections/instances share token, alias/fork/foreign active transaction refused; schema savepoint/script behavior, migration tracking/copy, open/close/rollback faults, backup destination and process-lock exclusion; positive fresh/upgraded initialization. |
| F1-R01 `test_reaper_each_outer_begin_precedes_terminal_helper_lock`; R02 `test_auth_ops_verification_disclosure_implicit_writes_guarded`; R03 `test_terminal_commit_rollback_cancel_releases_capacity`; R04 `test_terminal_progress_does_not_wait_on_network_or_host_cleanup` | P04 `tests/test_managed_authority_routes.py`: exercise actual public/internal services, both reaper BEGINs and following reconciliation/auth phase; all named outer owners parameterized, real two connections; foreign caller transaction rejected rather than late acquire, failure/cancel/commit cuts. |
| F1-W01 `test_every_cp_ordinary_writer_excludes_admission_sample`; W02 `test_session_device_and_api_key_implicit_write_boundaries`; W03 `test_repair_job_findings_commit_rollback_and_positive_work` | CP-WRITERS `tests/test_managed_cp_writer_boundaries.py`: all nine modules and constructors, SQLite context manager/autocommit/read-that-writes; preserve useful login/signup/account/billing/job/findings/recovery behavior, no all-refusal substitute. |
| F1-A01 `test_two_connection_sample_stays_exclusive_until_commit`; A02 `test_no_capacity_acquire_after_sqlite_begin`; A03 `test_positive_admission_after_competing_writer_commit_or_rollback` | P05 `tests/test_managed_attempt_admission.py`: hold at sample-before-BEGIN, race actual terminal and ordinary writer connections, assert contender cannot mutate until A exits; reverse schedule resamples after writer commit/rollback; positive legal admission commits a durable charge. |
| F1-S01 `test_all_outer_boundaries_stale_sample_negative_controls`; S02 `test_all_outer_boundaries_lock_order_negative_controls`; S03 `test_competing_writer_commit_rollback_cancellation_physical_cost`; S04 `test_terminal_progress_at_ceiling_with_queued_admissions`; S05 `test_open_recovery_checkpoint_close_and_offline_writer_exclusion`; S06 `test_useful_admission_and_terminal_reserve_real_two_connections` | P06 `tests/test_managed_authority_storage.py`, `tests/support/managed_authority_race_harness.py`, `scripts/managed_authority_storage_proof.py`: production constructors/routes/independent connections, every row/callsite parameterized; barriers at sample, BEGIN, commit/rollback, physical teardown; remove each owner guard as separate negative control. Real maximal records, blocked reader/checkpoint, physical peak and terminal latency; existing T-N05/T-N06/row19 and all 25 H6 oracles remain mandatory. P07 checks complete production closure; P14 repeats offline cuts. |

All owners must show focused red/green, affected-package and common full obligations at the exact final candidate, with intentional skips individually explained and no missing runtime stage labelled PASS. P06 cannot implement a failing production boundary; it returns it to the exact earlier owner under a fresh bounded correction. H6-RUNTIME host physical facts and P12 real quota integration are separate proofs.

Offline author models are illustrative finite schedules, not SQLite/storage/latency qualification: admission-only locking permits sample=(640 MiB−8192), admission cost=8192, unguarded writer growth=4096, ending 4096 above ceiling; acquiring inside helper after BEGIN permits `A owns capacity → waits SQLite`, `R owns SQLite → waits capacity`. Corrected pre-BEGIN outer units exclude the first interleaving and eliminate the order cycle. Negative controls remove each enumerated owner boundary, move acquisition after BEGIN, release before commit/rollback, or split mutex identity; each restores a bad schedule. Positive cases include competitor-first commit/resample/refusal, rollback/resample/useful admission, admission-first then reserved terminal progress, cancellation releasing ownership, and bounded timeout without granting authority. These demonstrations establish only model properties. Actual fair progress, cost bounds, crash recovery and every API edge require the named future tests.

## F2 correction: D_CP filesystem lifecycle ownership (PROPOSED)

This SECOND bounded correction follows two failed whole-plan reviews; the next fresh whole-plan review is THIRD and another failure escalates to the project owner, with no automatic fourth cycle. It is not plan acceptance, a source grant or a P02 unlock. H2/preflight fifth-cycle requests remain pending separately. H6 `3b03721a` §§3.1/5.2 explicitly puts `host/authority.sock`, its directory/inode and filesystem metadata/journal on D_CP. The earlier exclusion was false. Preserve the accepted layout and all H6 bytes/caps. The 110 primary + 10 CP-WRITERS = 120 proposed entries, P11 7+3/P17 10+3 and every DAG edge are unchanged. These are behavioral corrections in existing P02/P05/P14 paths, not extra source permissions.

Historical evidence is B=`f736279a33bc1b8bd094e301ddd52045eb96a149`: `host_authority.py:281,286,304,443` bind/chmod/rename/unlink really mutate filesystem state; `host_snapshot.py:648,656` unlinks before joining; `server.py:500` starts the reaper before host publication. An active decision can already have sampled when stop sets flags; flags do not drain it. `server.py:106,113,115` additionally opens with O_CREAT and fchmods **before** flock: even a losing second process can mutate metadata before ownership. These are source-order witnesses, not measured overflow or deployed failures. Full source, all-call AST, filesystem census and per-candidate dispositions are retained under `.worktrees/heel-task-evidence/C4-MANAGED-PLAN-H6-R3-F2/`; prior SQL-owner map remains binding. Neither a module name nor an incomplete method filter establishes storage placement.

### Same-domain local-effect protocol

P02's existing `CPWriteDomain` covers **all D_CP physical effects**, including listener lifecycle without a SQLite connection. No new token kind: publication uses a measured `maintenance` unit; mandatory cleanup uses a pre-reserved `terminal` unit. Each takes the existing bounded original deadline (≤250 ms acquisition, stricter limits retained), before the first local effect and outside SQLite, and retains ownership through the last synchronous mutation/descriptor teardown and accounting reconciliation. A unit without `conn` may not secretly open SQLite or reuse a caller transaction. Any durable SQL reservation update is a separate guarded transaction before filesystem work, committed before releasing its token; filesystem operations never occur inside that transaction. Reserve remains charged across this separation. No SQLite/filesystem atomicity is assumed.

P05 `host_authority.py` owns temporary bind, chmod, local listen, rename, ownership verification, descriptor close and exact-owner unlink; `host_snapshot.py` owns service state, start/stop coordination and unexpected-death dispatch. P02 `server.py` wires the same domain before constructing either worker; P14's later server handoff preserves it. A reaper already running during publication is supported: its open/BEGIN/commit/rollback/close units and the listener's local-effect unit exclude each other on **the identical domain**. P05 does not repair reaper code. Existing F1 SQL units and connection/service-gate → capacity → SQLite order remain mandatory.

Use a bounded listener lifecycle gate **before** capacity for start/publication/cleanup ownership; decision `_db_gate` likewise precedes capacity. No callback under capacity may acquire either gate. The lifecycle gate never spans a join, wait for serving, decision drain, external failure callback, response I/O, network accept/recv/send, host cleanup or reaper stop. Local AF_UNIX bind/listen are bounded local syscalls, not waits for a client; actual socket shutdown/wakeup is separated from cleanup and must not conceal a network wait or unguarded inode-releasing close. Any final close that may release a filesystem inode is inside the local-effect unit. Accepted connection resources are inventoried separately; anonymous connected sockets cannot be used as justification to exclude the pathname listener. Profile possible deferred kernel metadata/reclamation at the domain level as described below.

Publication state is `unstarted → publishing → serving`, with absorbing `draining/cleanup_pending → stopped` or `quarantined`; states are internal, not new wire authority. Before bind, register an in-memory cleanup record holding exact directory identity, expected tmp/final names, descriptor and observed dev/ino as each becomes known. One listener generation, one bounded temporary name, no overlapping replacement generation. Validate fixed trusted mount/path, directory owner/mode and no symlink/alias before effects; serialize all CP publishers through the gate and domain. Do not rename over a live, foreign or unexplained endpoint. Persisted/crash remnants are inventoried before readiness; cleanup/recovery may never guess ownership from PID or name alone.

After taking capacity, verify identities again and reserve/validate the bounded peak allowance, bind tmp, capture identity, chmod/verify, local listen, rename, verify final identity. Retain capacity across failure cleanup; only publish serving readiness after successful verification, token release, thread start and observed service-alive checks under the existing readiness/death coordination. Thread creation/start and serving wait happen outside capacity. If stop wins during publication, publication may complete its bounded local unit but cannot announce readiness or start an untracked worker; start hands its recorded object to the single cleanup owner. Thread-start failure, startup timeout/cancellation and unexpected `_run` death route through that same cleanup ownership, after any decision SQL unit has fully unwound. No self-join; failure callbacks run outside capacity and lifecycle gate.

Stop first marks draining under state coordination and prevents new decisions; an already active decision still owns its SQL unit. A single stop caller claims the cleanup record; concurrent/repeated stop callers observe or boundedly wait outside capacity, never duplicate close/unlink or reset deadlines. Cleanup acquires lifecycle gate then capacity and can therefore run **before join**, but only after any active decision/reaper unit releases capacity. An active decision may continue after cleanup if it had not yet entered its unit; it must recheck draining under its own gate before mutation/admission and fail closed, retaining previously committed charge. A decision already committed before draining keeps its charge; existing terminal-before-action and STOP contracts still govern authority. Stop does not hold the decision gate while waiting for the listener to exit.

Within cleanup ownership, detach/close the recorded descriptor exactly once, lstat and unlink only matching socket dev/ino under the validated parent, track both temporary and final paths through the rename cut, and complete the local-effect unit. The historical `suppress(OSError)` is not evidence of success: missing path is successful only when descriptor/path inventory proves no remaining owned object; replacement, inaccessible metadata or ambiguous rename/bind/close/unlink outcome quarantines the domain and fails readiness. Never delete a replacement inode or retry a stale descriptor number. Losing ownership is not a capacity refund. Gate serialization plus a single CP uid/process and trusted directory prevents cooperating replacement races; privileged/uncontrolled mutation invalidates the profile and fences the domain, rather than claiming lstat+unlink is intrinsically atomic against an attacker.

Release capacity and the lifecycle gate **before** bounded joining, reaper shutdown or waiting for another stop owner. On acquisition timeout/cancellation, do not perform unguarded cleanup: retain ownership record and reservation, mark cleanup pending/draining, report existing bounded failure/lingering result and permit the existing bounded retry path. On uncertain physical completion, fence further use of the domain (including ordinary workers), retain process ownership until workers are reaped, and require offline reconciliation before restart; never forcibly unlock a live mutation. Preserve the original exception. Proven synchronous failure with intact ownership may retry within the original bounded policy. A stop result cannot say fully stopped/reusable merely because a flag is set, a thread joined, or one pathname vanished: require joined workers, completed owned cleanup and unambiguous connection teardown. The service instance is never restarted. Replacement process/service starts only after prior workers, descriptors and ownership have been discharged or fenced/reconciled under H6 offline rules. No unbounded retry/temp accumulation.

### Physical accounting and remaining non-SQL boundary dispositions

P02/P05 reserve a fixed measured listener lifecycle envelope before allowing publication/readiness: peak existing final + one tmp if recovery permits it, directory blocks, inode allocation, rename/chmod, failure paths, close/unlink, filesystem journal/metadata and delayed completion. At least 1024 available inodes remain after prospective allocations; the envelope is inside the unchanged D_CP 768 MiB, 640 MiB admission ceiling and exclusive 128 MiB terminal reserve. Mandatory cleanup's outstanding cost is included in the existing ≤64 MiB aggregate terminal obligations, not added on top as a new budget. Do not double-spend or refund the envelope on optimistic unlink. No further generation is enabled until cleanup and fresh measurement establish its allowance. Startup crashes reconstitute a conservative envelope from the fixed bounded object inventory before any new admissions, never assume an in-memory reservation survived a crash. Startup may refuse publication for missing profile; previously reserved cleanup does not take an admission-pressure refusal branch. P06 must demonstrate both useful serving/admission and terminal/revocation progress, not permanent all-refusal.

An unlink may free storage; this plan asserts neither positive unlink cost nor filesystem monotonicity. Serializing syscalls does not prove completion of delayed journal, dirty-page or orphan-reclamation effects. P06/H6-RUNTIME must qualify the exact ext4/mount profile and bound those effects across token release, or require a bounded measured synchronization barrier inside the local unit before release. The conservative domain-wide allowance stays charged until fresh measurement **and** the qualified completion condition show it is safe to reduce; sampling alone cannot erase pending work. If the profile cannot bound/demonstrate this within existing deadlines and reserve, that implementation fails qualification; no lock over an unbounded fsync, no capacity enlargement and no model-based kernel claim. File/dir fsync semantics and unsupported socket fsync are explicitly measured, not assumed. SQL open/recovery/commit/rollback/close deferred effects inherit the same qualification requirement. Sampling for admission occurs after acquiring capacity and before BEGIN; no local filesystem inspection/effect inside SQLite. Listener cleanup after an admission's commit/rollback/close and token release uses its own reserved allowance and cannot invalidate that earlier protected sample.

| Physical class / exact boundary | Disposition, owner and enforcing proof |
|---|---|
| D_CP `host/authority.sock` + tmp, `host/` directory | P05 publication/cleanup protocol above. No online mkdir/rmdir/replacement of `host/`; P02 validates the provisioned directory. Missing/wrong directory refuses before worker startup. H6-RUNTIME/P14 provision/repair only while no serving child/workers under EX/lease. Allocation/metadata is counted, not excluded because offline. F2-L01–L08. |
| D_CP DB `.lock`: B `server.py:106–134` open/fchmod/flock/close | P02 must remove pre-flock mutation in managed mode: fixed `.lock` is provisioned while offline under H6 EX/lease with no CP workers; online contenders open existing validated no-follow inode **without O_CREAT/O_TRUNC or pre-lock chmod/chown/write**, acquire nonblocking existing flock and validate identity/mode. Bad/missing inode fails closed; no unlink/replace fallback. Retain same lock inode/exclusivity semantics and unmanaged compatibility. Successful owner does not need online chmod. Nonowner open/fstat/close on this regular inode has no data/metadata-write intent; prove on qualified mount. Final unlock/close only after all workers/SQLite/socket cleanup have ended, with conservative deferred effects accounted before new owner sampling. P02 owns extraction/API/test; P14/H6-RUNTIME own offline creation and restart handoff. F2-M01/M02. |
| D_CP `.heel-volume-id`, directory ownership/modes, preallocation/mkfs/metadata tables, replacement volume | Count on D_CP per H6 §§3.1/5.2/5.3. H6-RUNTIME/P14 exclusively offline creation/restore (uid/profile as pinned); EX excludes live SH child, runtime lease retained, old processes reaped before mutate. `.heel-volume-id` root-owned/read-only online. No root online metadata repair, chown, mkdir/rmdir, fsync or volume expansion. Fresh measurement before readiness, no serving-device restore/copy. F2-M02 and P14 restore/H6 runtime oracles. |
| CP SQLite DB/WAL/SHM/journal, implicit recovery/checkpoint, connection close | F1 owners remain in full. SQL reads do not establish read-only filesystem behavior. File reads/read_text/read_bytes/mmap may also update atime or other metadata on the qualified mount: H6 root online backup/identity readers must prove a nonmutating no-atime open/read path, or run only before child startup/after full drain under EX. Read-only bind/URI alone does not establish this; stat/lstat do not read file data. P14/H6-RUNTIME own this reader qualification; no online root write exception. Every write-capable open/close and metadata side effect participates or is exclusive offline. No read-only-URI shortcut for SHM/recovery. F1-M/R/W/A/S plus F2-S01/S02. |
| SQLite temp, CP `/tmp`, log/output destinations | H6 §§3.2/5.2 fixes bounded tmpfs (CP `/tmp` 16 MiB); configure/verify SQLite temp routing there, refuse alias to D_CP. HTTP `wfile.write` is response I/O, outside token; logs go to bounded configured non-D_CP sink, never arbitrary D_CP file handler. P02 validates configuration, P07 closes import/caller reachability, P14/H6-RUNTIME/P17 prove mounts/runtime env. No file-output capability on D_CP beyond listed objects. F2-M03/S03. |
| Root fence/J/intent/enrollment/receipts/layout/artifact files, P12 slot records/seed/vault/runtime DB | Exact H6 §§3.1–3.3/5.2 assigns root FS/D_SLOT and their own budgets; bind/chmod/chown/rename/unlink/mkdir/rmdir/fsync/write/close there remain real effects, **conditionally outside D_CP only with device/mount/alias proof**. Anonymous pipe/socketpair, AF_INET bind and read-only `/proc` namespace descriptors have no D_CP pathname allocation; a socket connect is not a pathname bind. H6-RUNTIME/P12/P14 prove routing and lifecycle; no new grant for historical helpers. |
| `scripts/saas_backup.py:22–30,43–63`, migration copy, export/site/build/local engine/executor CLI/proof writers | P02 offline exclusive source ownership and destination validation; all mkdir/create/write/close on backup destination occur only after outside-D_CP validation, not merely after checking DB connect. Source open/backup/close effects included. H6 root's separately qualified read-only online backup must demonstrate no D_CP metadata/recovery mutation or is offline; this script is not that job. `heel/saas/site.py:142–143` static build output and arbitrary path writers are not serving CP capabilities. Local engine/executor homes, exports and build/proof outputs are denied D_CP mount access in the accepted deployment; never infer exclusion from module name. P07 manifest/caller closure and P14/H6-RUNTIME/P17 isolation must prove this, otherwise hold and issue minimal fresh scope proposal, not silently add writers. F2-M03/S03. |

The expanded evidence retains every AST call (not just these method names), exact source hashes and per-candidate disposition including false positives such as string/dataclass `replace`, read-only file opens, network writes and resource closes. Dynamic/helper/subprocess effects need accepted B+n import/call and mount review: unknown routing is a **refusal/hold**, never a confirmed exclusion. These obligations cover non-Python compose/image/config inputs and future generated runtime helpers too. No additional runtime daemon or catch-all execute interception.

### Named actual tests, integration and negative controls

All names below are future implementation tests in already listed paths, not executed tests in this planning task. Tests use actual listener/service/reaper/decision boundaries and real filesystem/SQLite calls with deterministic barriers; a fake stop flag or mock-only unlink does not discharge them.

| IDs and exact names | Owner / required useful and adversarial cases |
|---|---|
| F2-M01 `test_managed_lock_contender_has_no_preownership_filesystem_mutation`; M02 `test_cp_offline_creation_and_final_release_exclude_live_workers`; M03 `test_cp_all_output_paths_reject_same_device_alias_before_create` | P02 `tests/test_managed_authority_migrations.py`: real two-process lock contender before/after flock, missing/replaced/symlink/wrong-mode lock, mkdir/chmod/open flags, failed construction/unwind, deferred close accounting, backup pre-mkdir routing. Positive initialization and normal restart. P14 repeats final production gate wiring; later H6 mount proof is required. |
| F2-L01 `test_socket_publication_excludes_active_reaper_and_decision_sample`; L02 `test_socket_failed_start_cleans_tmp_and_final_under_capacity`; L03 `test_stop_unlink_waits_for_active_decision_without_join_under_token`; L04 `test_unexpected_listener_death_unwinds_decision_before_cleanup` | P05 `tests/test_managed_attempt_admission.py`: actual bind/chmod/listen/rename, both reaper transactions plus connection open/close, hold decision at sample/BEGIN/commit/rollback/close; fail each publication cut including bind-success-before-stat, rename-success-before-stat, thread-start/serving timeout and BaseException. Both schedule orders, useful ready service and charged admission, terminal commit at ceiling. |
| F2-L05 `test_duplicate_stop_and_start_stop_have_one_cleanup_owner`; L06 `test_socket_inode_replacement_and_ambiguous_cleanup_quarantine`; L07 `test_cleanup_timeout_cancel_retains_reservation_and_original_deadline`; L08 `test_restart_reconciles_socket_remnants_before_readiness` | Same P05 test path: concurrent stop/start/_run death, stop during partial construction, descriptor reuse, replacement inode untouched, all close/unlink errors, failed state callbacks, cancellation at every handoff, no new generation before old cleanup; positive repeated stop and fresh process after proven drain. Remove gate, shared domain, reservation retention and quarantine separately to reproduce bad cases. No self-join or network/host/serving wait while token held. |
| F2-S01 `test_all_filesystem_effects_exclude_sample_until_physical_completion`; S02 `test_lifecycle_reserve_preserves_useful_admission_and_terminal_progress`; S03 `test_non_sql_mount_and_lifecycle_exclusions_are_enforced` | P06 existing storage test/harness/proof paths: map actual bind/chmod/rename/unlink/close plus SQL/reaper and startup-lock candidates, qualify max temp/inode/metadata/journal/deferred costs; real ext4 proof at H6-RUNTIME, exact mount aliases and negative controls. P07 audits complete integrated callsite closure; P14 repeats startup/failure/drain/restart with real gate/channel/reconciliation, P17 exact released artifact and P18 both customer layers remain mandatory. |

Offline finite models must retain the historical stop-before-join counterexample (physical effect during protected sample, **no positive unlink cost assumed**), publication/reaper overlap, corrected useful admission/terminal schedules and negative controls removing the FS token, using split identity, releasing before final close, sampling before acquisition, skipping drain/reconciliation, forgetting pending reservation, and joining while holding capacity. They also model duplicate cleanup ownership and start/stop cuts. Their units are abstract; finite results are not actual implementation, fairness, kernel/storage-cost, crash or five-second STOP proof. All 25 H6 real oracles/E01–E20/F17/F20/F21/F22/F23 and O01–O15/S01–S12 remain unchanged. Independent THIRD review judges the entire plan and 120-entry proposal; no self-acceptance.

## Serialized H6 external producers and interface ownership

These are future separately bounded grants after fresh whole-plan acceptance, not additions to the 110 P01–P18 entries or the separate ten CP-WRITERS entries. Each requires fresh independent acceptance before consumers. No named backend is qualified by H6 DESIGN-PASS.

| Producer | Prerequisites → consumers | Exhaustive future paths and responsibilities |
|---|---|---|
| H6-LAUNCH (6+0) | accepted H3 + H6 design + plan acceptance → reviewed I → P09; P12 consumes; P15 reruns | `deploy/host/supervisor.py`, `deploy/host/managed_container.py`, `tests/test_managed_container_plan.py`, `tests/test_host_h3.py`, `tests/linux/test_managed_container_boundary.py`, `scripts/managed_container_proof.py`. Exact §4 container/helper, launch-plan/rootfs validation and selected-home/FD/host-path oracles. H1/H2/accepted H3 proofs rerun on this candidate and I. |
| H6-RUNTIME (6+0) | accepted P05 + H6-LAUNCH + provider authorization → P12 real quota/integration proof and P14 fixture-capability gate | `deploy/host/managed_fence.py` owns root launch/measurement/lease orchestration, fence/J/intent/ack callables; `deploy/host/managed_host_layout.py` owns layout, provisioning, quota and runtime adapter; `scripts/managed_host_qualification.py`, `tests/test_managed_fence.py`, `tests/test_managed_host_layout.py` own real fixture qualification/fault cuts; `docs/saas/MANAGED_HOST_RUNTIME.md` owns root service invocation and qualified profile/resources. No P14 import at normal import time: consume P05 loader/authenticator and a labelled fixture verifier until integrated P14 exists. |
| H6-IMAGE (2+0) | accepted H6 + plan acceptance + accepted merged B0/BIR frozen handoff → P17 | `docs/saas/MANAGED_HOST_IMAGE_FACTS.md`, `tests/test_managed_host_image_facts.py`. Facts only: immutable base/frontend/dependency identities, prefix/entry, OCI and mount/normalization profiles, code/dependency manifest layout, image/measurement resource maxima, provisioning and rollback inputs. No P17 artifact/build/config/CI writes. |

H6-RUNTIME owns E05–E06/E15–E19 and F23 fixture proof in its existing script and two tests, plus T-P03/T-N02/T-N03/T-N05/T-N07/T-N09/T-N10/T-N13 and rows 19–25 host halves. H6-LAUNCH owns T-N04/T-N11/row 18. H6-IMAGE checks fact completeness; P17 owns E14/E20 release proof. P02/P05/P06/P12/P14/P15 mappings are inside those packets; P16/P18 retain real browser/customer obligations. These mappings supplement the exact 25 rows and E01–E20 below, never replace them.

F23 must demonstrate the actual chosen runtime adapter and storage/API enforcement: immutable snapshots, exclusion honored by GC/replacement/mount mutation, no writable alias, process/channel identity, retained live-child lease on parent death and restart recovery of orphaned leases. A Boolean, content-retention lease or read-only bind is insufficient. Concrete size/time/memory/scratch bounds must fit the host budget; no extra D_CP/slot allocation. Failure blocks launch as unsupported/unavailable. F17 cross-container flock, F20 durability, F21 actual quota and F22 live inspection/private pipes remain required separate facts. No third-party runtime patch is implicitly authorized.

Same-file ownership is serialized: supervisor H3→H6-LAUNCH→P09→P12; executor P09→P10→P11→P12; ledger P02→P05; host_authority P05; server P02→P14 and restore P14; disclosure P04; CP-WRITERS follows P04 before P05; B0 Dockerfile/CI freeze→P17. The original migrations/C5/C6/J11 and download writer handoffs remain. Each tracked heel addition still has the separately frozen three-path inventory scope and exact-closure H2/H0 gates. H6 deploy additions require stage-input review before grant. An unlisted terminal/R writer, unit file, adapter or dependency path is an ownership gap, never an implicit grant.

The following machine-readable predecessor table is the executable DAG witness for this amendment. It supplements every original authorization/source/CI/runtime gate; an edge means independent acceptance, not merely a commit. `PLAN` means fresh acceptance of this entire proposed plan, `H6` the exact design acceptance, `B0-HANDOFF` the independently accepted merged frozen B0/BIR handoff, and authorization nodes require their actual owners. `I` and `J11` remain future reviewed composition identities. No P14/P17 output feeds H6-RUNTIME.

<!-- H6-DAG-BEGIN -->
```json
{
  "PLAN": [
    "H6"
  ],
  "P01": [
    "P01-GRANT"
  ],
  "P02": [
    "P01",
    "PLAN",
    "H6"
  ],
  "P03": [
    "P02"
  ],
  "P04": [
    "P03"
  ],
  "P05": [
    "P04",
    "H6",
    "CP-WRITERS"
  ],
  "P06": [
    "P05"
  ],
  "P07": [
    "P06"
  ],
  "P08": [
    "P04"
  ],
  "H6-LAUNCH": [
    "H3",
    "H6",
    "PLAN"
  ],
  "I": [
    "P07",
    "H3",
    "H6-LAUNCH"
  ],
  "P09": [
    "I"
  ],
  "C4-IF": [
    "P07"
  ],
  "C5-IF": [
    "C4-IF",
    "CUSTODY-AUTH"
  ],
  "C6-IF": [
    "C4-IF",
    "C5-IF"
  ],
  "DA-IF": [
    "C4-IF",
    "C5-IF",
    "C6-IF"
  ],
  "P10": [
    "P09",
    "P08",
    "C4-IF"
  ],
  "C5-IMPL": [
    "P10",
    "C5-IF",
    "DA-IF",
    "H6",
    "CUSTODY-AUTH"
  ],
  "C6-IMPL": [
    "C5-IMPL",
    "C6-IF"
  ],
  "J11": [
    "C5-IMPL",
    "C6-IMPL"
  ],
  "P11": [
    "J11",
    "P10",
    "H6"
  ],
  "P12": [
    "P11",
    "H6",
    "C5-IF",
    "C6-IF",
    "H6-RUNTIME"
  ],
  "P13": [
    "P12"
  ],
  "H6-RUNTIME": [
    "P05",
    "H6-LAUNCH",
    "PROVIDER-AUTH"
  ],
  "P14": [
    "P13",
    "H6-RUNTIME"
  ],
  "P15": [
    "P14",
    "PRIVILEGED-PROOF-AUTH"
  ],
  "DA-IMPL": [
    "P15",
    "DA-IF",
    "C3-CLEAR"
  ],
  "P16": [
    "P15",
    "P08",
    "J11",
    "H6-RUNTIME",
    "DA-IMPL"
  ],
  "H6-IMAGE": [
    "H6",
    "PLAN",
    "B0-HANDOFF"
  ],
  "P17": [
    "P16",
    "H6-IMAGE",
    "B0-HANDOFF",
    "SECURITY-REVIEWS"
  ],
  "P18": [
    "P17",
    "C3-CLEAR",
    "H3",
    "H6-RUNTIME",
    "DA-IMPL",
    "DEPLOY-TARGET-AUTH"
  ],
  "CP-WRITERS": [
    "P04"
  ]
}
```
<!-- H6-DAG-END -->

## Normative H6 transcript — exact immutable source §§2–10

<!-- H6-TRANSCRIPT-BEGIN -->
## 2. Principals and numeric UID/GID matrix

| Principal | Where | UID:GID | Groups | Basis |
|---|---|---|---|---|
| Host root: supervisor, worker, root ceremony/signer, H6 tools | host initial namespaces | 0:0 | n/a | [H] `supervisor.py:9`; [B] CP requires peer uid 0 (`server.py:306,354`) |
| Control plane (CP), P14 offline entries incl. verifier | CP container, identity uid map, own PID ns (`external-pidns`) | 10001:10001 | none | [B] `Dockerfile.control-plane:8–9`, `host_authority.py:47,165–172`, `server.py:306–313,354–357` |
| Lifecycle/fence/enrollment reader group | — | gid 10001 | — | [P] reuse of CP primary group |
| Ingress (nginx/njs H0) | host, P13-rendered | 10002:10002 [P] | none | gets no §3 path; never sees K or the enrollment header |
| Executor of slot ordinal n | per-workspace container (§4) | (71000+n):(71000+n), n ∈ 0..999 [P] | none | [H] `supervisor.py:124–131,244–245` |
| Signer / vault / raw-evidence writer | executor UID of that slot | same | — | [R:S §5 708–728; Customer 186; S 579–587] |

Invariants [P]: pairwise distinct; executor UID == GID; no executor in group 0, 10001, 10002, `docker`;
ordinal/UID/`slot_id`/`workspace_id` bound for the host lifetime (§3.4), never reused; ordinal 1000
exhaustion refuses. S 726–728 trust statement retained. K (§7) is readable only by uid 0 and gid 10001.

## 3. Host paths, modes and root records

### 3.1 Host namespace

Executor-related ancestors are root 0700 [R:S 569, 590–592]; the executor never resolves a host path (§4).

| Path | Type / bound | Owner:group | Mode | FS | Writer → readers |
|---|---|---|---|---|---|
| `/etc/heel/` | dir | 0:0 | 0755 | root FS | H6 provisioning |
| `/etc/heel/host-layout.json` | §3.4, ≤ 524 288 B | 0:0 | 0600 | root FS | H6 layout tool → H6 tools, P12 |
| `/etc/heel/.layout.lock` | empty, never replaced | 0:0 | 0600 | root FS | H6 layout tool only |
| `/etc/heel/executor-rootfs.json` | §4.3, ≤ 1024 B | 0:0 | 0600 | root FS | H6 layout tool → supervisor |
| `/etc/heel/slots/`, `<slot>.json` | ≤ 16 384 B | 0:0 | 0700 / 0600 | root FS | H6 static fields → supervisor [H] `supervisor.py:285–300` |
| `/etc/heel/maintenance/` | dir | 0:10001 | 0750 | root FS | H6 → CP (read-only bind) |
| `…/maintenance/lifecycle.lock` (L) | empty, never unlinked/renamed/replaced | 0:10001 | 0640, nlink 1 | root FS | §6.1 holders |
| `…/maintenance/fence.json` | §6.2, ≤ 2048 B | 0:10001 | 0640, nlink 1 | root FS | fence mutators → gate, offline entries, supervisors |
| `…/maintenance/fence.publication.json` (J) | §6.3, ≤ 4096 B, present only while a publication is uncertain | 0:0 | 0600 | root FS | fence mutators; every reader refuses while it exists (presence via `lstat`; dir search permission suffices) |
| `…/maintenance/enrollment-verified.json` | §7.4 receipt, ≤ 1024 B | 0:10001 | 0640, nlink 1 | root FS | `verify_and_record_enrollment` → gate |
| `…/maintenance/.*.tmp` | ≤ 1 per record kind | 0:0 or 0:10001 | 0600/0640 | root FS | removed under L(EX) before the next write of that kind |
| `/etc/heel/enrollment/` | dir, the **only** secret directory bound into a container (CP, read-only) | 0:10001 | 0750 | root FS | H6 → CP |
| `/etc/heel/enrollment/current.json` | §7.1 config incl. K, ≤ 1024 B, exactly one | 0:10001 | 0640, nlink 1, regular | root FS | H6 under L(EX) → CP loader, root signer/verifier |
| `/etc/heel/private/` | dir, never bound | 0:0 | 0700 | root FS | H6 tools |
| `/etc/heel/private/operation-intent.json` | §6.4, ≤ 1024 B, at most one; carries K only until ack | 0:0 | 0600 | root FS | H6 creators → H6 |
| `/etc/heel/private/receipts/<operation_id>.json` | ≤ 1024 B, ≤ 2 retained | 0:0 | 0600 | root FS | fence tool (provenance only) |
| `/srv/heel/deploy/.env.production` | edge/tunnel secrets only, never K | 0:0 | 0600 | root FS | operator [B] `compose.yaml:11–12` |
| `/srv/heel/volumes/` | preallocated backing images | 0:0 | 0700 | root FS | H6 layout tool |
| `/srv/heel/cp/<vol_id>/` | mount point = D_CP root | 10001:10001 | 0700 | D_CP `nodev,nosuid,noexec` | CP; root reads only for online backup |
| `…/<vol_id>/.heel-volume-id` | exactly 37 B (§7.8) | 0:10001 | 0440 | D_CP | H6 at volume creation → gate |
| `…/<vol_id>/control-plane.sqlite3` (+ sidecars, `.lock`) | SQLite | 10001:10001 | 0600 lock | D_CP | CP [B] `server.py:94–125,445–475` |
| `…/<vol_id>/host/`, `authority.sock` | dir / socket | 10001:10001 | 0700 / 0600 | D_CP | CP [B] `host_authority.py:271–305` |
| `/srv/heel/backups/` | ≤ 1 staged encrypted backup | 0:0 | 0700 | root FS | trusted backup job (§5.2) |
| `/opt/heel/` | immutable private runtime prefix for **host root** processes (§10) | 0:0 | dirs 0755, files 0644 | root FS, read-only after install | release provisioning |
| `/var/lib/heel/executor-rootfs/<hex64>/` | immutable executor rootfs store (§4.3), contains its own `/opt/heel` prefix | 0:0 | 0700 store dir; tree dirs 0755, files 0644/0755 | read-only mount `nodev,nosuid` | H6 `install-rootfs` |
| `/var/lib/heel/launch/<slot_id>/` | empty mountpoint | 0:0 | 0700 | root FS | provisioning; mounted only in the helper's private mount ns |
| `/var/lib/heel/slots/`, `<slot>/` | dir / D_SLOT root | 0:0 | 0700 | root FS / D_SLOT `nodev,nosuid,noexec,usrquota` | H6 provisioning [R:S 569] |
| `…/<slot>/.lifecycle.lock` | S per-slot lock | 0:0 | 0600 | D_SLOT | root ceremony [R:S 599] |
| `…/<slot>/ceremony.json` | ≤ 4096 B | 0:0 | 0600 | D_SLOT | P12 [R:S §14.2] |
| `…/<slot>/domain.json` | §7.7, ≤ 1024 B | 0:0 | 0600 | D_SLOT | P12 |
| `…/<slot>/executor-input.json` | ≤ 1024 B | 0:(71000+n) | 0640 | D_SLOT | supervisor → bound read-only |
| `…/<slot>/epochs/`, `epoch_<hex32>/` | dirs, ≤ 17 epochs | 0:0 | 0700 | D_SLOT | root ceremony [R:S 590–591, 612–615] |
| `…/epoch_<hex32>/home/` and `runner-daemon/identity.seed` | `HEEL_HOME`; 32 B seed | executor | 0700 / 0600 | D_SLOT | executor; root writer [R:S 312, 718–720] |
| `…/<slot>/vault/` | C5 vault | executor | 0700 | D_SLOT | executor [R:S 613] |

### 3.2 CP container

[B] `compose.yaml:21–29`: `/var/lib/heel` = read-write bind of `/srv/heel/cp/<vol_id>`; read-only root FS;
`/tmp` tmpfs 16 MiB; `cap_drop: ALL`; `no-new-privileges`. Added facts for P17 [P]: `/etc/heel/maintenance`
read-only bind at the same path; `/etc/heel/enrollment` read-only **directory** bind at
`/run/heel-enrollment` (a single-file bind would pin an obsolete inode across atomic replacement);
the named volume (`compose.yaml:54–56`) is replaced by the D_CP bind. Never bound: `/etc/heel/private`,
slots, host-layout. No secret env, argv, image layer or Docker secret-env copy of K; public configuration
names only the fixed mount path. The executor and ingress receive neither directory.

### 3.3 Root records outside the aggregate

Caps 2048 (fence) + 4096 (J) + 1024 (verification receipt) + 1024 (config) + 1024 (intent) + 524 288
(layout) + 1024 (rootfs record) + 1000 × 16 384 (slot configs) + 2 × 1024 (receipts) + 2 × 4 × 4096
(stale temps) + 0 (locks) ≤ 16.95 MiB, no growth path beyond caps. Outside the restored volume because EA
180–186 requires it; outside the 1 GiB aggregate by explicit bound. Provisioning reserves this plus the
host prefix, rootfs store and image layers (sized by H6-IMAGE facts) in the H6-RUNTIME root-FS budget.

### 3.4 Host layout record `heel.managed-host-layout.v2` [P]

Canonical ASCII JSON (sorted keys, compact, exact key sets, duplicates/extras rejected, byte-identical
re-encoding, integers never booleans, no floats). Cap **524 288 B**; legal maximum with 1000 lifetime
entries **266 500 B** (`witness-records.json`, every entry at the grammar maximum). Top-level keys exactly
`{schema_version, installation_id, host_id, layout_revision, next_ordinal, principals, storage, slots,
updated_at_ms}`.

| Field | Grammar / rule |
|---|---|
| `installation_id` / `host_id` | `inst_[0-9a-f]{32}` / `hst_[0-9a-f]{32}`; equal the fence values |
| `layout_revision` | int 1..2147483647, +1 per write; exhaustion refuses writes |
| `next_ordinal` | int 0..1000; equals `len(slots)`; never decreases |
| `principals` | exactly `{cp_uid:10001, cp_gid:10001, ingress_uid:10002, ingress_gid:10002}` |
| `storage` | exactly `{aggregate_bytes:1073741824, cp_device_bytes:805306368, slot_pool_bytes:268435456, cp_terminal_reserve_bytes:134217728, slot_root_reserve_bytes:2097152, min_slot_device_bytes:33554432, slot_inode_count:4096, slot_root_inode_reserve:64, cp_inode_count:16384}`; immutable after creation |
| `slots[]` | ≤ 1000 entries ordered by `ordinal`, exact keys `{ordinal, slot_id, workspace_id, uid, gid, device_bytes, state, created_at_ms, retired_at_ms, released_at_ms}` |
| `slots[].ordinal` / `uid` / `gid` | ordinal = array index; uid = gid = 71000 + ordinal |
| `slots[].slot_id` / `workspace_id` | B codec grammars (`host_authority.py:60,63`); each unique over all entries ever |
| `slots[].device_bytes` | **every** entry, including `released`: int multiple of 4096 in [33 554 432, 268 435 456]; **immutable once written** (a released entry keeps the size the device had); Σ over `active`+`retired` ≤ `slot_pool_bytes` |
| `slots[].state` | `active → retired → released` only; `released` = device destroyed after a C5/C6 root-verified release decision [R:S 628–630]; never removed |
| timestamps | ms 1..9007199254740991; `retired_at_ms` null iff `active`; `released_at_ms` null iff not `released` |

Writers hold `/etc/heel/.layout.lock` `LOCK_EX` (bounded 30 s, else `layout_busy`) across read–validate–
write (temp, fsync, rename, dir fsync, readback; on any fsync failure rewrite a fresh temp, §6.3 rule);
the layout tool never takes L, so no lock-order cycle. Provisioning/release keep their root-verified
release precondition and never mutate a live epoch. Verifier (H6-RUNTIME) cross-checks `/etc/passwd`
/`/etc/group`, `findmnt`, `blockdev --getsize64` equal to `device_bytes`, quota limits (§5.5) and slot
root owners. Oracles: add/retire/release positive; duplicate ordinal/uid/slot_id/workspace_id, rebinding,
`retired→active`, deletion, pool overflow, released-size change, size outside range, cap+1,
noncanonical bytes, bool-as-int.

## 4. Mandatory per-workspace executor container

### 4.1 Boundary (retained from R1)

[R:Customer 188, 512–514] container per workspace, read-only root FS, no shell; [R:S 591–592] root binds
only the selected home; [R:S 599–616] quiescence and sealing. Own mount, PID, IPC and UTS namespaces plus
the root-owned generation network namespace (H1/H2 lineage unchanged); no user namespace; no capabilities;
`no_new_privs`; exactly the FDs of §4.5; old root detached after `pivot_root`. Not claimed: seccomp,
cgroup memory/pids limits. A Docker/OCI container per workspace is rejected (moves netns ownership to
dockerd).

### 4.2 Exact host → container mapping

| Container path | Source (host) | Mount flags |
|---|---|---|
| `/` | `/var/lib/heel/executor-rootfs/<rootfs_tree_digest>/` | bind, remount `ro,nodev,nosuid` |
| `/heel/home` | `/var/lib/heel/slots/<slot_id>/epochs/<epoch_id>/home` | bind `rw,nodev,nosuid,noexec` |
| `/heel/vault` | `/var/lib/heel/slots/<slot_id>/vault` | bind `rw,nodev,nosuid,noexec` |
| `/heel/input.json` | `/var/lib/heel/slots/<slot_id>/executor-input.json` | bind file `ro,nodev,nosuid,noexec` |
| `/tmp` | new tmpfs 16 MiB, owner executor, 0700 | `nodev,nosuid,noexec` |
| `/dev` | tmpfs 64 KiB; binds of `/dev/null`, `/dev/zero`, `/dev/urandom` only | `ro,nosuid,noexec` after population |
| `/proc` | own-PID-ns procfs | `ro,nosuid,nodev,noexec,hidepid=invisible,subset=pid` |

Nothing else: no `/sys`, host `/tmp`, `/run`, other slot, `epochs/` parent, sealed epoch, `/etc/heel`
(hence never K). Source paths derive from plan identifiers by fixed grammar; each component opened
`O_PATH|O_NOFOLLOW|O_DIRECTORY` from the pinned parent with owner/mode/`st_dev` checks.

**Private prefix reconciliation (closes REV2 delta).** Executor argv is exactly
`/usr/bin/python3 -I -S -B /opt/heel/deploy/host/executor.py /heel/home /heel/input.json <link_fd>`
inside the rootfs. [H] `executor.py:40–44` computes its package root as `_HERE.parents[1]`; for this entry
that is `/opt/heel`, where the rootfs contains exactly `/opt/heel/heel/runner` (public wheel content),
`/opt/heel/heel/saas` (reviewed private closure) and `/opt/heel/deploy/host` (host entry closure), matching
P 183. Under `-I -S` there is no site-packages, user-site, `PYTHONPATH`, script-directory or checkout
fallback. Third-party dependencies (if any) are installed hash-locked inside the rootfs at one fixed
directory under `/opt/heel` frozen by H6-IMAGE; if the entry must add that directory to `sys.path`, that
is an `executor.py` change owned by the existing executor writers (P09→P10→P11→P12, P 169), not by H6.
R1's `/opt/heel/executor/executor.py` entry (package root `/opt`) is withdrawn. Host root processes run
`/usr/bin/python3 -I -S -B /opt/heel/deploy/host/<entry>.py` from the host prefix with the same layout.
CP keeps its separately pinned `/app` closure (B0/BIR).

### 4.3 Serialized handoff records [P]

**Launch plan `heel.managed-launch-plan.v2`** (supervisor → helper over an inherited pipe FD, read to EOF,
closed; canonical; cap 1024, legal max 316): exact keys `{schema_version, slot_id, uid, gid, epoch_id,
rootfs_tree_digest, rootfs_kind, tmp_bytes}`; `rootfs_kind` ∈ {`qualification_fixture`,
`integrated_source`, `release`}; other grammars as R1.

**Rootfs record `heel.managed-executor-rootfs.v2`** (cap 1024, legal max 405): exact keys
`{schema_version, kind, tree_digest, image_digest, entry_path, entry_sha256, installed_at_ms}`;
`entry_path` = `/opt/heel/deploy/host/executor.py` literal; `image_digest` = `sha256:`+hex64 iff
`kind=release`, else null. Install verifier refusals as R1 (root-owned only, no group/world-write,
setuid/setgid, device, socket, FIFO, escaping symlink, no shell names `sh, bash, dash, ash, zsh, ksh, csh,
busybox, toybox, su, sudo, env`).

**Kinds.** `qualification_fixture`: source-built by H6-LAUNCH/H6-RUNTIME harnesses for capability only.
`integrated_source`: built from the exact P14/P15 integration tree for integrated proofs. `release`: only
from the P17-built executor image digest. Evidence carries the kind; no fixture or integrated-source
evidence is ever cited as delivered-image proof; P17 must re-prove on `release` and P18 requires
`release`. The same three kinds label the CP consumer recipe (§7.4).

### 4.4–4.6 Helper sequence, FD/process boundary, oracles

Retained from R1 unchanged except the entry path above: argv `ns_fd link_fd plan_fd`; unshare
NEWNS|NEWPID|NEWIPC|NEWUTS; fork; PID-1 child with `PDEATHSIG`; build §4.2; `pivot_root`; detach old;
`setns(ns_fd, CLONE_NEWNET)`; drop to executor ids; verify caps zero; `execve`; exit codes 122–127 only.
Executor holds exactly fds 0–2 (`/dev/null`) and `link_fd`; "no surviving process" = PID namespace has no
member. `test_workspace_container_selected_home_and_host_path_denial` with mutants (missing pivot_root,
writable root, extra bind, extra FD, shell present, plan path injection, wrong UID) plus: K and the
enrollment header absent from every executor FD, mount, env and `/heel/input.json`.

### 4.7 Producer: proposed precursor H6-LAUNCH (A-LAUNCH, retained)

Owner fresh Opus, acceptor fresh Astra. Base: the accepted H3 commit, after H3 acceptance; never pending H.
Position: accepted H3 → H6-LAUNCH → I (composes accepted P07 + accepted H3 + accepted H6-LAUNCH) → P09.
Six nonmechanical paths, 0 mechanical: `deploy/host/supervisor.py` (modify: helper/launch-plan/rootfs
checks only), `deploy/host/managed_container.py` (create), `tests/test_managed_container_plan.py`
(create), `tests/test_host_h3.py` (modify: launch-helper expectations only),
`tests/linux/test_managed_container_boundary.py` (create), `scripts/managed_container_proof.py` (create,
`--output DIR --max-seconds 600`, fixture rootfs only). supervisor.py chain: accepted H3 → H6-LAUNCH →
P09 → P12. H1 `host_authority_proof.py`, H2 `host_h2_policy_proof.py` and the accepted H3 proof rerun
(not rebuilt) on H6-LAUNCH and again on I. P15 reruns `managed_container_proof.py` (A-P15, no path).

## 5. Aggregate storage

### 5.1 Partition (retained)

[R:P 78] footprint ≤ 1 GiB, admission ≤ 896 MiB, exclusive terminal reserve 128 MiB; [R:Q 150; EA 143,
190; S 626–627].

| Term | Bytes |
|---|---:|
| Aggregate = D_CP + Σ D_SLOT | 1 073 741 824 |
| D_CP device [P] | 805 306 368 (768 MiB) |
| — exclusive CP terminal/R/cleanup/checkpoint reserve | 134 217 728 |
| — CP admission ceiling | 671 088 640 |
| — ledger physical sublimit | 536 870 912 |
| Slot pool, Σ `active`+`retired` device bytes [P] | ≤ 268 435 456; each slot ∈ [32 MiB, pool] |
| Admission-eligible = ceiling + pool | 939 524 096 (= 896 MiB) |

Lifetime caps, epochs (1 live + 16), 28 KiB evidence, cleanup budgets unchanged [R:Q 146–154, P 93].

### 5.2 Inclusion and exclusion (retained)

D_CP counts every CP byte (pages, freelist, indexes, WAL incl. blocked-checkpoint growth, shm, journal,
lock, socket inode, `.heel-volume-id`, FS metadata/journal/inode tables). Each D_SLOT counts its epochs,
runtime DB, evidence, vault, input, ceremony/domain records, metadata and root reserves. SQLite temp
files and executor `/tmp`: bounded tmpfs. Root records: §3.3. **One** retained old D_CP (fence
`retained_volume_id`; `begin_restore` refuses while non-null) and **one** staged backup are bounded
operator-recovery allocations in the provider-disk budget, not serving storage. "Expand the volume"
([B] `RUNBOOKS.md:112`) is unavailable for managed D_CP; replacement is equal-size via restore (A-RUN,
P14 RUNBOOKS text).

### 5.3 Device-to-allocatable accounting [P]

`used(X) = device_bytes(X) − f_bavail × f_frsize`, `free_inodes(X) = f_favail` from `statvfs`;
`(f_blocks − f_bavail) × f_frsize` is not used. Provisioning: ext4 `mkfs.ext4 -F -b 4096 -I 256
-E lazy_itable_init=0,lazy_journal_init=0`; D_CP `-m 0 -N 16384`; D_SLOT `-N 4096 -O quota
-E quotatype=usrquota` then `tune2fs -r 512 -u 0 -g 0` (512 × 4096 B = 2 MiB uid-0 reserved blocks;
corrects R1's misuse of mkfs `-r`, which sets the revision). Image files `fallocate`d. Measurement error or
unsupported device → `capacity_unmeasurable`, refuse. Physical qualification is P06 (CP) and H6-RUNTIME.

### 5.4 CP admission and serialization (retained; consumers P05/P06)

One CP-process capacity mutex, order *capacity mutex → BEGIN IMMEDIATE*; `statvfs` sampled under the mutex
before BEGIN. The CP uid 10001 is the only D_CP writer, so a sample under the mutex is a valid reservation
for D_CP (unlike slots, §5.5). Admission requires `used + insert_cost + wal_allowance ≤ 671 088 640` and
`free_inodes − insert_inodes ≥ 1024`; Σ outstanding terminal cost + new ≤ 64 MiB (durable aggregate);
`-wal` ≤ 64 MiB; ledger ≤ 512 MiB. Costs are P06-measured worst cases or admission refuses.
Terminal/R/cleanup never refused for admission pressure; no deletion/VACUUM/pruning [R:Q 148, EA 190].
Owner note (INFERRED, must be confirmed at the P05 grant): the mutex is introduced in P05's
`host_snapshot.py`/`canary_runs.py`; any terminal/R writer located in a file outside P05's five-plus-one
list (§12) needs a revised serialized grant before P05, not hidden work.

### 5.5 Slot devices: block **and inode** reservation (R1-F4)

**Mechanism (kernel-enforced, inside the existing 32 MiB/2 MiB/1 GiB, no extra bytes):**

| Resource | Executor uid (71000+n) | Root (uid 0) |
|---|---|---|
| Blocks | ext4 reserved blocks: 512 blocks (2 MiB) usable only by `resuid 0` (`tune2fs -r 512 -u 0 -g 0`) | the 2 MiB reserve |
| Inodes | ext4 **usrquota inode hard limit** `LX = I0 − 64`, where `I0` = `f_ffree` measured on the freshly made, empty slot FS (expected 4085 for `-N 4096`; measured, never assumed); soft limit = hard limit; grace irrelevant | the remaining ≥ 64 inodes (`slot_root_inode_reserve`), never chargeable to the executor |

Root never relies on a quota exemption: executor-owned inodes are capped at LX by the kernel, root-owned
inodes are bounded by design below, and `LX + 64 = I0`. An inode-count sample is not used as a
reservation anywhere.

**Worst-case root obligations per slot (witness `witness-inodes.json`):** persistent root-owned inodes
`.lifecycle.lock`, `ceremony.json`, `domain.json`, `executor-input.json`, `epochs/`, ≤ 17 epoch dirs
(1 live + 16 retained/orphan, quarantined orphans included) = 22; ≤ 1 live atomic-replacement temp (S
lock serializes replacements); ≤ 4 stale temps (one per replaced kind: ceremony/journal, domain marker,
input, receipt-bearing ceremony rewrite) surviving any crash, each removed by the next attempt **before**
it creates its own; six retry attempts and restarts reuse, never accumulate. Total **27 ≤ 64** inodes and
**179 ≤ 512** blocks (one block per ≤ 4096 B record plus 8 blocks of directory growth per touched
directory). Seed destroy (overwrite + unlink) and sealing (chmod) need no new inode.

**Executor-charged root writes:** a fresh epoch needs a new executor-owned `home/`, `home/runner-daemon/` and `identity.seed`
(all three charged to LX; REV3 precision correction). If `executor_inodes_used − 1 (destroyed seed) + 3 > LX` or blocks are short, fresh
allocation returns `managed_capacity_unavailable` [R:S 631–637] **after** retirement/receipts completed;
no deletion, no replay/history deletion, no `cleanup_failed` used as a guarantee. Usefulness then waits
for the accepted C5/C6 release policy (S §4.9 dependency), exactly as for blocks.

**Capability test and refusal.** At slot provisioning H6-RUNTIME (`managed_host_layout.py`) must: verify
`tune2fs -l` features include `quota` and reserved-block uid 0 = 512 blocks; mount with `usrquota`; set
limits via `quotactl(Q_SETQUOTA)`; read back with `Q_GETQUOTA`; and run a functional probe as the slot's
executor uid before first use — create empty files until `EDQUOT` occurs at exactly LX, then confirm root
can still create and atomically replace a 4096 B file, then remove all probe files and re-measure `I0`.
Any deviation → `slot_inode_reserve_unavailable`, the slot is not provisioned, and the layout entry is not
written. Eight slots repeat this independently (one quota per device).

**Real oracles (later, not here):** H6-RUNTIME `test_slot_inode_and_block_exhaustion_root_reserve` on a real
Linux ext4 slot device: executor fills inodes to `EDQUOT` and, separately, blocks to `ENOSPC`, then root
performs every S cleanup stage including crash-and-restart with stale temps; P12
`tests/test_managed_root_ceremony.py` proves the protocol through all six attempts and restart with the
real quota mount. Witness `witness_inodes.py` is an abstract counterexample check (R1 design consumes all
inodes and root temp creation fails; R2 keeps 42 free with 27 needed), not ext4 evidence.

### 5.6 Capacity consequence (reported, unchanged)

At most 8 concurrent 32 MiB slots; larger capacity needs a separately reviewed amendment of P 78/Q 150/EA
143/S 626. Per-slot executor inodes ≈ 4021 is a further usefulness limit to be measured by H6-RUNTIME/P15.

## 6. Trusted maintenance fence and lifecycle (R1-F2, R1-F3)

Authority: host operator as root through H6-RUNTIME `deploy/host/managed_fence.py`. The fence is never on
D_CP or in any backup; a restored completion marker is never permission [R:EA 181, 186]. Security rests on
operator fencing and configuration replacement [R:EA 182]; simultaneous malicious rollback of fence,
configuration and DB is outside the model [R:EA 188].

### 6.1 Host lifecycle lock L: creation, repair, holders

**Creation is idempotent and never replaces.** `ensure_lifecycle_lock()` (inside every creator, under no
other lock): `open(L, O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0640)` — **no `O_EXCL`**; `flock(LOCK_EX)`
bounded 30 s; `fstat` must be regular, nlink 1, size 0, owner uid 0, not a symlink, same `(st_dev,st_ino)`
as `lstat(L)`; then `fchown(0,10001)`, `fchmod(0640)`, `fsync(fd)`, `fsync(dir)`. An existing L that is
pristine (empty regular uid-0 single-link file) is adopted as-is: an empty lock file carries no state, so
an orphan L from a crashed initializer is indistinguishable from a fresh one and needs no reconciliation.
A non-pristine L (size > 0, nlink ≠ 1, wrong type, owner ≠ 0, symlink) → `lock_invalid`; operator
escalation, never unlink. L is never unlinked, renamed or replaced for the installation lifetime.

Every holder opens `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, takes `flock`, verifies `fstat == lstat` identity and
the exact profile (0:10001, 0640, nlink 1, size 0); otherwise releases and returns `lock_invalid`. Lock
FDs are `O_CLOEXEC` and every spawn uses `close_fds=True`, so no child inherits a parent's lock (a shared
open file description would share the flock).

| Holder | Mode | Held | Bound |
|---|---|---|---|
| CP `main()` | `LOCK_SH` | before DB lock until exit | 5 s, else `lifecycle_busy` |
| P14 offline entries (bootstrap/migration/restore/verify) | `LOCK_SH` | whole process | 5 s |
| Root supervisors (P12) and root signer | `LOCK_SH` | whole process | 5 s |
| Verification orchestrator parent (§7.4) | initial `LOCK_SH` released before dispatch; §7.4a launch phase reacquires SH | launch through child exit; releases before ack EX | 5 s |
| Root actual-artifact launcher (§7.4a) | `LOCK_SH`, then artifact lease | before spawn through child reaping; every restart anew | 5 s each, else `lifecycle_busy` |
| Every fence/config/receipt/intent mutator | `LOCK_EX` | whole mutation incl. J removal | 30 s, else `lifecycle_busy` |

Order everywhere: L → artifact lease (launch/ack only) → CP DB `.lock` → SQLite; mutators never take the DB lock; layout tool never takes L;
per-slot S lock only after L(SH). No holder upgrades SH→EX: a process that held SH releases it, then
acquires EX as a new bounded acquisition and re-validates `fence_revision`. No parent holds EX while
waiting for a child that needs SH (`witness-cuts.json` D: 19 683 schedule prefixes, 0 stuck, negative
control stuck 16 432). Cross-container flock on one inode is [U] F17.

### 6.2 Fence record `heel.managed-fence.v2` — closed variants

File checks: `O_RDONLY|O_NOFOLLOW`, regular, 0:10001, 0640, nlink 1, size ≤ **2048**, parent 0:10001 0750,
`st_dev` ≠ D_CP (`fence_on_restored_volume`). Canonical rules §3.4. **26** structural variant classes
(state × stage × origin/adoption × reason × nullable verification digest); legal maximum **1397 B**
(adopted `restore_pending/enrollment_installed`, `witness-records.json`).

Common keys C (non-null): `schema_version`, `installation_id` inst, `state`, `fence_revision` int
1..2147483647, `restore_epoch` hex64, `enrollment_secret_id` `enr_[0-9a-f]{32}` (random, never derived
from K), `cp_volume_id` vol, `host_id` hst, `updated_at_ms` ms.

| `state` | Exact key set = C ∪ | Rules |
|---|---|---|
| `serving` | `domain_operation_id` rop; `domain_receipt_digest` hex64; `enrollment_verification_digest` hex64; `retained_volume_id` vol\|null | retained ≠ `cp_volume_id` |
| `maintenance` | serving keys + `reason_code` ∈ {`enrollment_reverification`,`disk_pressure`,`operator_hold`}; `entered_at_ms` | `enrollment_verification_digest` null **only** if reason = `enrollment_reverification` |
| `bootstrap_pending` | `operation_id`; `operation_stage` ∈ {entered, reconciled, enrollment_installed}; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `entered_at_ms` | reconciliation null iff entered; verification non-null iff enrollment_installed; tunnel null if entered |
| `migration_pending` | `operation_id`; stage ∈ {entered, backup_verified, reconciled, enrollment_installed}; `origin` ∈ {`same_host`,`new_host`}; `backup_digest`\|null; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `fencing`\|null; `entered_at_ms` | backup null iff entered; reconciliation null iff stage < reconciled; verification as bootstrap; tunnel null if stage < reconciled; fencing: same_host ⇒ `{host_id: C.host_id, method: same_host_reaped}`; new_host ⇒ `{host_id: null, method: destroyed\|powered_off_detached}` |
| `restore_pending` | `operation_id`; stage ∈ {entered, backup_verified, domain_rotated, reconciled, enrollment_installed}; `previous_host_id` hst\|null; `pending_cp_volume_id` vol; `backup_digest`\|null; `backup_provenance` ∈ {`pre_domain`,`domain`}\|null; `pending_restore_epoch`\|null; `pending_enrollment_secret_id`\|null; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `fencing`\|null; `entered_at_ms` | pending volume ≠ C volume; backup digest/provenance null iff entered; `pre_domain` only if `previous_host_id` null (§6.10); pending epoch/enrollment null iff stage < domain_rotated, then ≠ C; reconciliation/verification/tunnel as above; fencing same-host ⇒ this host/`same_host_reaped`, adopted ⇒ `previous_host_id`/`destroyed`\|`powered_off_detached` |

`fencing` keys `{host_id, method, evidence_digest, fenced_at_ms}`; evidence = SHA-256 of the redacted
operator attestation. In pending variants C holds the values being **replaced**; targets are C
(bootstrap/migration) or the pending values (restore). No other states, keys or nulls.

### 6.3 Publication protocol with journal J (closes the serving-durability gap)

Every fence mutation (and the first fence creation) under L(EX):

1. Remove stale `.fence.*.tmp`/`.fencepub.*.tmp` (unlink, `fsync(dir)`).
2. Write J = `heel.managed-fence-publication.v1` `{schema_version, operation_id|null, prior_digest
   hex64|null, intended, intended_digest, created_at_ms}` (`intended` = the full new fence object; cap 4096,
   max 1717 B) to a fresh temp (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600), `fsync`, rename to J, `fsync(dir)`.
3. Write the new fence to a fresh temp (0640, `fchown(0,10001)` before write), `fsync`, rename onto
   `fence.json`, `fsync(dir)`, reopen with §6.2 checks and compare bytes to `intended`.
4. Unlink J, `fsync(dir)`. Only now return the record (the durable acknowledgement).

**Reader rule (gate, offline entries, supervisors):** after taking L(SH), `lstat(J)`; if J exists (any
content) → `FenceError fence_publication_uncertain` → refuse. Because J is unlinked only after step 3's
directory fsync returned success, a reader that sees no J and a `serving` fence sees a record whose rename
was made durable; a later power loss can at most make J reappear (refuse until recovery), never revert the
fence under a running server (`witness-cuts.json` A: 68 cuts incl. kill, fsync failure and power loss;
0 non-durable serves; R1 negative control 4 non-durable serves).

**Failed sync.** After any `fsync`/dir-`fsync` error, the possibly poisoned inode is never re-fsynced and
trusted: recovery rewrites a **fresh** temp of `intended` and repeats steps 3–4. A readback alone is never
an acknowledgement. **Permissions/FD ownership:** temps are created by root with exact mode, `fchown` before
content, `O_CLOEXEC`; all FDs closed before L(EX) is released; a holder or reader never inherits them.

`recover_publication(*, now_ms)` (root, L(EX)): J absent → no-op; J valid and `fence.json` bytes ==
`intended` or == the record with `prior_digest` → rewrite `intended` fresh (steps 3–4); J unparsable or
fence matches neither → `fence_invalid` (operator escalation; no guessing). Every mutator begins with this
recovery. For first creation, `prior_digest=null` means expected fence **absence**, not a hash of a
missing file; absent fence + valid first-creation J rewrites intended fresh. Non-null prior with absent
fence, or null prior with an unrelated existing fence, refuses. Thus a retry of the same call completes the earlier publication before evaluating its own
precondition. **Startup durability qualification** is therefore part of the gate: no listener and no
offline write runs while J exists, and the only way out is root recovery under EX.

### 6.4 Operation intent (closes the creation gap and binds K before use)

`/etc/heel/private/operation-intent.json`, `heel.managed-operation-intent.v1`, root 0600, cap 1024 (max
576): exact keys `{schema_version, operation_kind (bootstrap|migration|restore), origin
(same_host|new_host|null; migration only, else null), operation_id, installation_id, host_id,
target_cp_volume_id, target_restore_epoch|null, target_enrollment_secret_id|null, secret_b64|null,
created_at_ms}`. Restore targets/secret are null until `rotate_domain`; `secret_b64` (44-char strict
base64 of 32 bytes) is non-null from target generation until the enrollment ack (§7.4), then rewritten
null. Written with the §6.3 temp/fsync/rename/dir-fsync/readback/fresh-rewrite rule (no J needed: no
reader acts on it). **Randomness rule:** operation id, installation/host id (fresh only), restore epoch,
enrollment id and K are drawn exactly once, inside the mutation that first makes the intent **visible**.
An unpublished temp is discarded unread; filenames never carry or select randomness. A visible intent is
always reused, never redrawn (`witness-cuts.json` C: every cut, one visible draw, one L inode, fence ==
intent == config; R1 negative control 9 stuck cuts).

### 6.5 Callables (H6-RUNTIME `deploy/host/managed_fence.py`, uid 0)

Keyword-only; mutators take `expected_revision` (except creators) and `now_ms`; return the re-read
validated record; raise `FenceError(code)` (§6.8). Every mutator: ensure/verify L, L(EX), recover J,
validate, write per §6.3/§6.4.

| Callable | Inputs | Precondition | Result |
|---|---|---|---|
| `read_fence(*, db_dir)` | — | caller holds L(SH) | record or error incl. `fence_publication_uncertain` |
| `recover_publication` | — | L(EX) | §6.3 |
| `initialize_installation(*, kind, origin, cp_volume_id)` | kind ∈ {`fresh`,`legacy_migration`}; origin ∈ {`same_host`,`new_host`} for legacy only | no fence (or a fence equal to this intent's record → idempotent return); intent absent **or** intent of this kind/origin/volume; `.heel-volume-id` = `cp_volume_id`; fresh: DB absent or (intent present and DB written only by offline bootstrap); legacy: DB present | ensure L; intent (draw once: op, inst, host, epoch, enr id, K); config `current.json` = intent targets (§7.1); fence revision 1 `bootstrap_pending/entered` or `migration_pending/entered` |
| `adopt_for_restore(*, previous_installation_id, previous_host_id, previous_cp_volume_id, previous_restore_epoch, previous_enrollment_secret_id, new_cp_volume_id)` | previous values **read from the verified backup's domain row** by P14's read-only observer | no fence on this host (or a fence equal to this intent's record → idempotent return); intent absent or same | ensure L; intent (op, host drawn once; targets null); fence `restore_pending/entered`, C = previous values, `host_id` = this host |
| `enter_maintenance(*, reason_code)` | — | `serving` | `maintenance`, digests carried |
| `invalidate_enrollment_verification()` | — | `maintenance/enrollment_reverification` | removes receipt file, digest ← null |
| `reinstall_enrollment_config()` | — | `maintenance/enrollment_reverification`, digest null | rewrites `current.json` from the **current** loaded bytes to a fresh inode (same K/ids/op); never generates K |
| `leave_maintenance()` | — | `maintenance`; verification digest non-null and equal to `SHA256(J(receipt))`; current config binding/profile/context equal the receipt | `serving`, same domain |
| `begin_restore(*, new_cp_volume_id)` | — | `maintenance`, retained null | intent (op drawn once) ; `restore_pending/entered`, previous null |
| `record_backup_verified(*, operation_id, backup_digest, backup_provenance)` | provenance from P14 observer: `pre_domain`\|`domain` (restore), `pre_domain` (migration) | stage entered; restore+adopted requires `domain` | `backup_verified` |
| `rotate_domain(*, operation_id)` | — | restore `backup_verified` | intent targets + K drawn once; config installed for pending targets; `domain_rotated` |
| `record_reconciled(*, operation_id, receipt: bytes)` | ≤ 1024 B | reconcile stage (bootstrap entered / migration backup_verified / restore domain_rotated) **or** stage ≥ reconciled with equal digest (idempotent); receipt valid (§6.6) | `reconciled`; `reconciliation_digest` ← `SHA256(J(result))`; receipt copy to `private/receipts/` |
| `record_fencing(*, operation_id, host_id, method, evidence_digest, fenced_at_ms)` | per §6.2 | migration/restore, any stage; null or byte-identical | `fencing` set |
| `record_tunnel_rotated(*, operation_id, tunnel_rotated_at_ms)` | operator rotation evidence time; **not** proof of K | stage ≥ reconciled; null or equal | set |
| `verify_and_record_enrollment(*, operation_id\|None, expected_revision)` | none from caller beyond ids; consumes its own observation (§7.4) | pending stage `reconciled` (or `enrollment_installed` for re-ack) **or** `maintenance/enrollment_reverification` with digest null | receipt written, then fence: pending → `enrollment_installed`; maintenance → digest set, stays maintenance; intent `secret_b64` → null after fence durable |
| `complete_operation(*, operation_id)` | — | stage `enrollment_installed`; tunnel non-null; migration/restore fencing non-null; config binding/profile/context re-checked equal to the receipt | `serving`: `domain_operation_id` ← `operation_id`; restore ⇒ C ← pending, `retained_volume_id` ← previous volume; `domain_receipt_digest` ← `reconciliation_digest`; verification digest carried; then intent unlinked + dir fsync |
| `release_retained_volume(*, volume_id, evidence_digest)` | — | serving\|maintenance; retained = volume_id | retained null |

No pending state is left except by `complete_operation`; no abort. Interruption keeps ingress disabled and
resumes under the same `operation_id` [R:EA 186, Q 172]. Restore is the only domain replacement; ordinary
restart never rotates. A stale intent whose `operation_id` equals a serving fence's `domain_operation_id`
is removed by the next mutator; any other intent/fence mismatch → `operation_mismatch`.

### 6.6 Reconciliation result and receipt (P14 producer, fence consumer)

**Result** `heel.managed-reconciliation-result.v1` (stable, stored durably in the domain row by the same
SQLite transaction that reconciles): exact keys `{schema_version, operation_kind, operation_id,
installation_id, restore_epoch, enrollment_secret_id, cp_volume_id, backup_provenance, db_schema_version,
terminalized_reservations, revoked_runner_keys, closed_generations, revoked_grants, stopped_runs,
reconciled_at_ms}` plus `previous_restore_epoch` hex64 **only** for restore. `backup_provenance`:
bootstrap `none`, migration `pre_domain`, restore `pre_domain|domain`; `db_schema_version` = `user_version`
at commit, int 1..2147483647; counts int 0..2147483647 (all 0 for bootstrap). `reconciliation_digest` =
`SHA256(J(result))`, stored in the row.

**Receipt** `heel.managed-reconciliation-receipt.v2` = `{schema_version, result, check}`; `check` exact
`{integrity_check:"ok", open_managed_authority_rows:0, measured_used_bytes, measured_free_inodes,
measured_at_ms}` re-measured at **every** emission (after commit, read-only connection). The digest covers
`result` only, so re-emission after a lost stdout yields the same digest. Field grammar: measured values
0..9007199254740991 (int, never bool). **Accepted physical range** (checked by `record_reconciled`, else
`capacity_reserve_unavailable`): `measured_used_bytes ≤ 671 088 640`; `1024 ≤ measured_free_inodes ≤
16 384` (`cp_inode_count`). Maxima (`witness-records.json`): field-grammar 852/903/993 B, accepted
physical 834/875/965 B for bootstrap/migration/restore; cap 1024. Neither maximum is a measured
device value. `record_reconciled` requires result ids equal the fence targets (restore: pending values,
`previous_restore_epoch` = C.`restore_epoch`), provenance equal the fence's, and digest idempotency.

**Offline transaction (P14):** one `BEGIN IMMEDIATE` with `PRAGMA synchronous=FULL`: terminalize all
managed rows incl. null-runner reservations, revoke keys/nonces/proofs/receipts/grants, close generations,
stop runs, then INSERT (bootstrap, migration, pre-domain restore) or UPDATE (domain-bearing restore) the
domain row with targets **and** result columns, COMMIT. Neither listener, reaper, tunnel nor host-authority
service is constructed; emit the receipt on stdout; exit 0. The migrator's own commits precede it; a crash
between leaves `pre_domain` with an empty domain table, which §6.7 accepts as initial.

### 6.7 CP startup gate (consumer P14: `server.py`, `managed_restore.py`)

Placement in B `build_server`: L(SH) first (new, before `server.py:436`), DB lock (436), enrollment load
(once, §7.3), gate — all before the migrator (449), HTTP `serve()` (477) and `HostAuthorityService`
(519–527). Every managed entry is launched through §7.4a; absence of its live channel refuses before either
listener constructor. There is no raw container restart/autostart bypass. Only when `HEEL_MANAGED_HOST=1` ([B] `server.py:291–313`); connector-only unchanged.

`evaluate_startup_gate(*, mode, fence: FenceRecord | FenceError, db: DbObservation, volume:
VolumeObservation, enrollment: EnrollmentObservation, verification: VerificationObservation,
artifact: ArtifactObservation) ->
GateDecision` — pure, total.

- `mode` ∈ {`ordinary`, `offline_bootstrap`, `offline_migration`, `offline_restore`,
  `offline_verify_enrollment`}; only P14's explicit offline CLI passes non-ordinary; no bool fallback.
- `VolumeObservation` = vol id | `volume_id_missing` | `volume_id_invalid`.
- `DbObservation` (read `mode=ro` before any migration) = `empty` (no file or zero tables) |
  `pre_domain(schema_version, table_present: bool)` (no domain table, or table with zero rows) |
  `domain(row, schema_version)` (exactly one row and stored digest == `SHA256(J(result-from-columns))`) |
  `invalid`.
- `EnrollmentObservation`, `VerificationObservation`: §7.3. `ArtifactObservation`: §7.4a;
  production cannot manufacture it from JSON, env, CLI digest, receipt or an old decision.

Decision records `heel.managed-startup-gate.v2`, canonical, cap 1024 (max 489): `refuse_unidentified`
`{schema_version, mode, decision:"refuse", reason_code}`; `refuse` + `{installation_id, fence_revision,
fence_state}`; `serve` `{schema_version, mode:"ordinary", decision:"serve", installation_id,
fence_revision, restore_epoch, enrollment_secret_id, cp_volume_id, domain_operation_id}`;
`offline_proceed` `{schema_version, mode, decision:"offline_proceed", installation_id, fence_revision,
operation_id, recovery: bool, target_restore_epoch, target_enrollment_secret_id, target_cp_volume_id}`.
35 closed reason codes retained (`witness-records.json`) plus the eight artifact codes in §7.4a.
The 489-byte gate bound is unchanged; artifact facts are not added to persistent decisions. No nullable field; no secret, binding or path dump.

Evaluation order (first match):

| # | Condition | Decision |
|---|---|---|
| 1 | fence error (`fence_missing`, `fence_invalid`, `fence_profile`, `fence_on_restored_volume`, `lock_invalid`, `lifecycle_busy`, `fence_publication_uncertain`) | `refuse_unidentified` |
| 2 | volume error | `refuse volume_id_missing\|volume_id_invalid` |
| 3 | enrollment error (`config_missing`, `config_unavailable`, `config_invalid`, `config_profile`, `config_changed`) in any mode | `refuse <code>` |
| 3a | any mode: artifact error, or observation does not bind this live process/mode/fence revision/config/recipe/volume and receipt bytes (including absence for offline) | `refuse <artifact code>` (§7.4a); binding disagreement → `artifact_binding_changed` |
| 4 | **ordinary**: state ≠ serving | `maintenance_active` / `bootstrap_pending` / `operation_pending` |
| 5 | ordinary: verification error | `verification_missing\|verification_invalid\|verification_unavailable` |
| 6 | ordinary: volume ≠ C volume | `volume_mismatch` |
| 7 | ordinary: db `empty`\|`pre_domain` / `invalid` | `domain_absent` / `domain_invalid` |
| 8 | ordinary: row installation/epoch/enrollment/volume/operation_id/digest ≠ fence C / `domain_operation_id` / `domain_receipt_digest` | `installation_mismatch\|epoch_mismatch\|enrollment_mismatch\|volume_mismatch\|operation_mismatch\|receipt_mismatch` |
| 9 | ordinary: loaded config C ≠ fence C (installation, host, epoch, enrollment id, volume) or config `operation_id` ≠ `domain_operation_id` | `enrollment_mismatch` |
| 10 | ordinary: `SHA256(J(receipt))` ≠ fence verification digest, or receipt C/operation ≠ loaded, or receipt recipe digest ≠ measured | `enrollment_verification_mismatch` |
| 11 | ordinary: receipt `file_binding` ≠ loaded binding | `enrollment_config_changed` |
| 11a | ordinary: measured artifact kind/digest ≠ receipt kind/digest | `artifact_mismatch` |
| 12 | ordinary: all equal | **`serve`** |
| 13 | offline: state not matching mode | `mode_mismatch` |
| 14 | offline: volume ≠ target volume, or loaded config C/operation ≠ targets/`operation_id` | `volume_mismatch` / `enrollment_mismatch` |
| 15 | offline_bootstrap, stage entered: **recovery** if db `domain` with `operation_id` = fence op, kind bootstrap, ids = targets; **initial** if db `empty` or `pre_domain` (bootstrap DB written only by this entry); `pre_domain` containing any managed row → `bootstrap_db_not_fresh` | `offline_proceed` (recovery flag) |
| 16 | offline_migration, stage backup_verified: recovery as 15 (kind migration); initial if `pre_domain` | `offline_proceed` |
| 17 | offline_restore, stage domain_rotated: recovery if db `domain` with op = fence op, kind restore, ids = pending, `previous_restore_epoch` = C epoch; initial if (`pre_domain` and fence provenance `pre_domain`) or (`domain` with installation = C, epoch = C epoch, op ≠ fence op, and provenance `domain`); `domain` with other installation/epoch → `restored_domain_mismatch`; provenance disagreeing with db → `backup_provenance_mismatch` | `offline_proceed` |
| 18 | offline_* at stage ≥ reconciled: recovery predicate only (read-only re-emission of the stored result) | `offline_proceed` (recovery) or `operation_mismatch` |
| 19 | offline_verify_enrollment: pending stage ∈ {reconciled, enrollment_installed} with db recovery predicate true, **or** `maintenance/enrollment_reverification` with digest null and ordinary rows 6–9 true | `offline_proceed` (recovery = true) |
| 20 | otherwise | `stage_invalid` |

Recovery mode never opens a write transaction; it re-runs `integrity_check`, re-measures and re-emits the
stored result. This is the exact same-operation predicate: a row is accepted only if its `operation_id`
equals the fence's fresh random `operation_id` **and** every target and the recomputed digest match; an
arbitrary new-domain row is not accepted (`witness-cuts.json` B: four journeys × every cut, 0 unrecovered,
≤ 1 commit; R1 rule reproduces REV2's restore counterexample and a migrator-partial cut). Only `serve`
reaches line 449 in `main()`; direct oracle: no TCP listen and no socket inode for every non-serve
decision (P 570).

### 6.8 Closed errors and retry

`FenceError(code)`, code ∈ {`fence_missing`, `fence_invalid`, `fence_profile`, `fence_on_restored_volume`,
`lock_invalid`, `lifecycle_busy`, `fence_publication_uncertain`, `fence_exists`, `revision_conflict`,
`transition_invalid`, `operation_mismatch`, `backup_unverified`, `backup_provenance_mismatch`,
`receipt_invalid`, `reconciliation_incomplete`, `capacity_reserve_unavailable`, `fencing_missing`,
`tunnel_unrecorded`, `enrollment_unverified`, `enrollment_binding_changed`, `config_io`,
`retained_volume_present`, `revision_exhausted`, `io_failed`}.

- `lifecycle_busy`: stop holders, retry; no state change.
- `revision_conflict`: after J recovery, if the record already equals this exact transition with the same
  ids, return it (idempotent); else stop.
- `io_failed`: J remains (if written) and every reader refuses; retry the same call → J recovery rewrites
  fresh; never a second epoch, enrollment id, K or operation.
- `config_io`: config/receipt write failed; fence unchanged or J-protected; retry rewrites fresh from the
  intent (pending) or from current bytes (reinstall).
- `revision_exhausted`: operator escalation.

### 6.9 Crash-cut tables (separately modelled cuts, not an atomic write)

Abbreviations: V = visible, D = durable after power loss; "retry" = same callable, same ids.

**Initialize / adopt**

| Cut | State left | Recovery |
|---|---|---|
| I1 L created, before fchown/fsync | L pristine-but-wrong-profile or absent after power loss | retry repairs profile under EX or recreates; holders refuse `lock_invalid` meanwhile |
| I2 intent temp written, not renamed | no visible intent | retry discards temp unread and draws once |
| I3 intent V not D | power loss may remove it | retry: if visible reuse; else draw (no value was ever used) |
| I4 config written (bootstrap/migration) | config ≠ fence (no fence) | gate `fence_missing`; retry rewrites identical config from intent |
| I5 J written, fence not | readers `fence_publication_uncertain` | J recovery completes fence |
| I6 fence V before dir fsync | J present | J recovery rewrites fresh |
| I7 J unlink V not D | power loss → J reappears | refuse until recovery; never reverts fence |

**Offline reconciliation (all four journeys)**: crash before COMMIT → initial predicate reruns; migrator
commit only → `pre_domain(table_present)` initial; COMMIT D, stdout lost → recovery predicate re-emits the
same result; receipt delivered, `record_reconciled` J present → recovery; fence D, reply lost → idempotent
`record_reconciled`. SQLite reporting COMMIT success that the device later loses is outside the model
([U] F20).

**Enrollment / complete / leave-maintenance**

| Cut | Recovery |
|---|---|
| E1 rotate: intent with K D, config not installed | retry installs once from intent |
| E2 config rename V, dir fsync fails | `config_io`; retry rewrites fresh; startup binding check refuses meanwhile |
| E3 verifier passed, parent/child dies before EX | observation lost; retry runs the actual verifier again |
| E4 receipt file D, fence not | gate digest mismatch refuses; retry re-verifies and replaces the receipt |
| E5 fence `enrollment_installed` D, intent `secret_b64` still set | next mutator nulls it; config remains the only K copy |
| C1 complete: J written, fence not | readers refuse; J recovery |
| C2 complete: fence `serving` V, dir fsync fails or process dies | J present → **no reader serves** (the R1 defect) until recovery rewrites |
| C3 complete: J unlink not D | refuse after power loss until recovery; fence stays serving |
| C4 complete: intent unlink lost | stale intent with op = `domain_operation_id` removed by next mutator |
| L1–L3 leave-maintenance | identical to C1–C3 |

### 6.10 Procedures and pre-domain provenance

**Fresh bootstrap:** create D_CP + `.heel-volume-id`; `initialize_installation(fresh)` (intent, config,
fence); operator rotates tunnel; P14 `offline_bootstrap` → `record_reconciled` → `record_tunnel_rotated` →
`verify_and_record_enrollment` → `complete_operation` → start CP → gate `serve` → listeners → readiness →
edge smoke → ingress opens.
**Legacy migration, same host:** stop/reap every legacy process/FD [R:EA 172]; `initialize_installation
(legacy_migration, same_host)`; fresh backup → `record_backup_verified(pre_domain)`; `record_fencing
(same_host_reaped)`; `offline_migration`; then as bootstrap.
**Legacy migration, new host** (journey preserved for a pre-domain backup whose original host is lost):
restore the legacy DB into a fresh D_CP; `initialize_installation(legacy_migration, new_host)`;
`record_backup_verified(pre_domain)`; `record_fencing({host_id: null, destroyed|powered_off_detached})`
— the old host is identified only by the operator's evidence digest, no invented `hst_` id; continue as
migration. A new K means any old managed installation's credential never authenticates here.
**Restore, same host:** stop tunnel/CP/supervisors; old volume read-only; `enter_maintenance
(operator_hold)` + `begin_restore`; verify backup into the new D_CP → `record_backup_verified(pre_domain|
domain)` → `rotate_domain` → `offline_restore` → `record_reconciled` → `record_fencing(same_host_reaped)` →
`record_tunnel_rotated` → `verify_and_record_enrollment` → `complete_operation` → start exactly one CP →
fresh S seed/pair/bind/approval [R:EA 185]. Pre-domain backup: previous epoch is the **current fence**
`restore_epoch`, not a value invented for the backup.
**Restore, adopted (new host):** `adopt_for_restore` with values read from a **domain-bearing** backup
row; a pre-domain backup is refused (`backup_provenance_mismatch`) and must use the new-host legacy
migration journey above.
**Positive/refused provenance variants:** positive = {same-host pre_domain, same-host domain, adopted
domain, new-host legacy migration}; refused = {adopted pre_domain, domain row of another installation or
epoch, bootstrap with managed rows, provenance disagreeing with the DB}.
**K replacement (compromise or loss):** only by a full domain replacement — same-host restore of a fresh
verified backup onto a new equal-size volume (one retained old volume). No same-id regeneration, no
dual-key grace, no leave-maintenance shortcut.
**Ordinary restart/reboot:** invoke the root launch verifier (§7.4a) afresh; measure and bind the
actual child artifact; fence serving; load current config; compare exact artifact to receipt; gate `serve`; epoch, counters and terminal
history unchanged; executors burn their old generation [R:Q 83]. Device renumbering that changes the config
`file_binding` refuses (`enrollment_config_changed`) until maintenance re-verification.

## 7. Installation enrollment (R1-F1; A-ENR2, pending Q/EA amendment review)

Source: ENR (unaccepted, selected as basis). Deviations from ENR are listed in §7.6. Everything here is
INFERRED design; the enrollment amendment to Q §3/§6.7 and EA §4/§7 is **explicit and pending fresh
independent review**; this author does not accept it.

### 7.1 Key and configuration

K: exactly 32 bytes from the OS CSPRNG, drawn once per durable operation intent (§6.4) at fresh bootstrap,
legacy migration or `rotate_domain`. `enrollment_secret_id` is an independent random 16 bytes (`enr_`+32
hex), never K, a hash, MAC or fingerprint. K is never the Worker/edge key, tunnel token, runner seed or a
target credential, and no such key ever serves as K.

`/etc/heel/enrollment/current.json`, `heel.host-enrollment-config.v1`, exact keys `{schema_version,
operation_id, installation_id, host_id, restore_epoch, enrollment_secret_id, cp_volume_id, secret_b64}`;
all strings; grammars inst/hst/hex64/enr/vol/rop; `secret_b64` RFC 4648 standard base64 with padding, 44
chars, strict decode/re-encode equality incl. zero pad bits; canonical compact sorted ASCII JSON, no
newline; cap 1024 (471 B). Profile: regular, 0:10001, 0640, nlink 1; dir 0:10001 0750; no symlink at any
component; descriptor-relative no-follow opens; bounded read; `fstat` before/after read equal and equal to
`lstat`. Errors never echo rejected bytes. LoadedEnrollment is opaque; K excluded from repr/debug/
exceptions; no public export or public-wheel inclusion.

`FileBinding` = `{device, inode, size, mtime_ns, ctime_ns}`, ints 0..2^63−1 (inode > 0, size 1..1024),
never bool; from `fstat` of the opened inode. Root source and CP destination must resolve the same
`(st_dev, st_ino)` in one kernel (verified by §7.4). No secret-file hash substitutes for the binding.

### 7.2 Header and authenticator (three Q managed routes only)

Routes exactly `POST /host/v3/managed-ceremony`, `POST /host/v3/managed-operation`, `POST
/host/v1/managed-attempt` [R:Q 56], HTTP/1.1, AF_UNIX. SO_PEERCRED admission ([B]
`host_authority.py:165–172`, uid 0 + external pidns) still runs first and denies before any read. Legacy
`/host/v1/authority-snapshot` and any v2 managed route never accept managed provenance even with a proof.

Exactly one header `X-Heel-Host-Enrollment: v1 <enrollment_secret_id> <mac_hex>`: value = `v1 ` + 36-char
`enr_` id + SP + 64 lowercase hex = **104 B**; complete line 130 B incl. CRLF. Managed-route header set is
closed: `Host` (exactly `localhost`, new managed-only rule — B drops Host unread), `Content-Length`,
`Content-Type` (exactly `application/json`), optional `Connection: close`, `X-Heel-Host-Enrollment`;
case-insensitive duplicate detection; no tabs, folding, extra whitespace, `Transfer-Encoding`, `Expect`,
`Upgrade`, cookies, `Authorization` or edge header. The B parser is not widened for other routes.

`D` = `{schema_version:"heel.host-enrollment-auth.v1", installation_id, host_id, restore_epoch,
enrollment_secret_id, cp_volume_id, method:"POST", path, body_sha256: SHA256-hex(exact received body)}`;
`mac_hex = HMAC-SHA256(K, b"heel-host-enrollment-request-v1\x00" + J(D))`; constant-time compare after
strict grammar; header id = loaded C id; body hashed before any parse. Authentication yields C only — never
a runner, workspace, slot, job or request authority; slot/epoch in the body must still match the
authenticated installation and the trusted slot join, and every Q/EA guard (runner PoP, binding, scope,
grant, W/Q, sequence, one-shot, terminal-before-replay) runs unchanged. A replayed valid MAC is not a
fresh operation; no replay table or receipt stores the header or a hash of it; Q `request_digest` still
hashes the body only.

Errors (each closes the connection, calls no decider, allocates/charges nothing, increments one fixed
nonsecret counter, logs no bytes): framing/unknown/duplicate/grammar → 400 `{"error":"managed_protocol_
error"}`; over cap → 413 same body; missing or mismatched proof on a well-formed request → **401**
`{"error":"host_enrollment_required"}` (P05 adds 401 to B's `_STATUS`); unknown path → existing 404.
Caps unchanged: W 2048, Q 2560, ceremony 4096, responses 4096, head 8192 (B `MAX_HEAD_BYTES`, excludes the
terminating CRLFCRLF; maximal managed head 261 B), one request/connection, backlog 64, 5 s.

### 7.3 Trusted observations into the gate

`EnrollmentObservation` = `loaded(C, operation_id, file_binding, consumer_recipe_digest)` from the **same**
production LoadedEnrollment object later passed to `HostAuthorityService` (P05 constructor parameter,
P14 wiring), or one of `{config_missing, config_unavailable, config_invalid, config_profile,
config_changed}`. `consumer_recipe_digest` is recomputed at startup from self-measured facts (§7.4); never
read from env. No bool, env id or caller tuple can produce `loaded` in production composition; secret
bytes never enter gate inputs/results.

`VerificationObservation` = parsed `/etc/heel/maintenance/enrollment-verified.json` (same file rules as the
fence) or `{verification_missing, verification_invalid, verification_unavailable}`.

### 7.4 Listener-free actual-consumer verification and ack

`verify_and_record_enrollment` (H6-RUNTIME orchestrator, uid 0), acyclic and never holding EX while a
child needs SH:

1. Parent: L(SH); read fence (no J), capture `fence_revision`, operation/targets, config inode/bytes
   binding; release SH.
2. Through the host launch verifier (§7.4a, explicit offline mode; no old receipt equality required),
   spawn the pinned P14 `offline_verify_enrollment` entry in the configured CP launch recipe (uid/gid
   10001, identity uid map, own PID ns, read-only enrollment and maintenance binds, D_CP bind) with exactly
   two private pipes (no Docker exec/stdio logging, tee, terminal, network socket or listener). Child: L(SH)
   for its whole life; loads the real `ProductionConfiguration`, the production P05 loader and
   authenticator; runs the gate in `offline_verify_enrollment` (row 19); constructs no HTTP server, reaper
   or Unix listener; writes no DB.
3. At the rendezvous, root inspects the live child: `/proc/<pid>/ns/*`, `uid_map`, `status` uids/caps,
   `/proc/<pid>/root/run/heel-enrollment/current.json` `(st_dev, st_ino)` = the host source inode and
   profile, fixed volume/fence binds, executable/argv and code/dependency manifests against the pinned
   recipe. Any uninspectable fact → `config_unavailable`; never assumed.
4. Challenge `heel.host-enrollment-check.v1` `{schema_version, operation_id, installation_id, host_id,
   restore_epoch, enrollment_secret_id, cp_volume_id, nonce}` (fresh 32-byte hex nonce, cap 1024, 485 B);
   child checks fields against its loaded object and answers `{schema_version:"heel.host-enrollment-check-
   response.v1", mac}` (cap 256, 132 B), `mac = HMAC-SHA256(K, b"heel-host-enrollment-check-v1\x00" +
   J(challenge))`, plus in-process production-authenticator self-tests on synthetic requests for all three
   paths (valid accepts authentication; one-bit wrong key/proof and changed C/path/body deny; no decider).
   Parent computes with its separately loaded K. One exchange, ≤ 5 s; timeout/EOF/excess → fail. Challenge
   and response are never persisted, hashed into a record or logged.
5. Child exits; parent confirms no survivor/FD, releases launch SH and the artifact lease, then takes
   L(EX) as a new acquisition and performs J recovery. Require the same revision, operation, targets,
   config bytes/inode/binding and recipe as inspected. Acquire a new artifact lease after EX and fully
   remeasure the retained stopped snapshot/store against the recorded identity before publication;
   missing/changed snapshot or profile → re-verify. Hold EX and this new lease through ack; any change →
   re-verify, never replay.
6. Write receipt `heel.host-enrollment-verified.v2` `{schema_version, operation_id, installation_id,
   host_id, restore_epoch, enrollment_secret_id, cp_volume_id, file_binding, consumer_recipe_digest,
   artifact_kind, artifact_digest, verified_at_ms}` (cap 1024, max 819 B; no nonce, MAC, key, key hash or
   transcript); artifact kind/digest come only from §7.4a host measurement of that verifier child,
   never its request or self-report. Publish with temp/fsync/rename/dir-fsync/readback; then fence (via §6.3) with
   `enrollment_verification_digest = SHA256(J(receipt))`; then null intent `secret_b64`.

**Consumer recipe** `heel.host-enrollment-consumer-recipe.v2` (cap 2048, 483 B), self-measurable by the CP
at every startup: `{schema_version, artifact_kind (qualification_fixture|integrated_source|release),
code_manifest_digest, dependency_manifest_digest, entrypoint:"heel.saas.server", uid:10001, gid:10001,
peer_profile:"external-pidns", credential_target:"/run/heel-enrollment", receipt_target:"/etc/heel/
maintenance/enrollment-verified.json"}`; manifests are nonsecret files whose exact layout H6-IMAGE/P17
freeze (inspected to contain no rendered secret or secret-file digest). `artifact_digest` has the exact §7.4a identity for every kind. The CP does not self-measure an image
digest: the trusted host verifier measures and binds it on **every** launch, including ordinary, restart
and boot, and the CP gate compares that observation with the receipt. Recipe equality never substitutes
for artifact equality. P17 parity and re-verification are additional obligations.

The receipt is durable provenance of root's own observation, not attestation against malicious root. No
caller-supplied JSON, bare id or saved success replaces the actual verifier; no arbitrary root signing API.

### 7.4a Actual artifact launch contract (R2-F1; A-ART3, proposed)

**Identity and measurement.** All three CP kinds (`qualification_fixture`, `integrated_source`,
`release`) must be materialized as a single-platform OCI image before execution. No live source bind,
editable installation, bare checkout or arbitrary tar/tree is an admitted CP artifact. Fixture and
integrated images are local test products, not release proof. For each kind, `artifact_digest` is
`sha256:` followed by exactly 64 lowercase hex characters: SHA-256 of the **exact single-platform OCI
manifest bytes**, not an index, tag, config ID, source commit, code manifest, label or requested digest.
Kind is separately bound by the root-selected launch mode and compared exactly; a caller label cannot
upgrade fixture provenance to release. The platform descriptor is selected before launch; ambiguous
selection, unsupported media type/compression/features or multiple candidate manifests refuse.

The host verifier is trusted uid 0 code installed with H6-RUNTIME, invoking the qualified local runtime
through its root-only API. It reads the manifest, config and every referenced compressed layer blob
from the runtime's actual content store, hashes bytes against their descriptors (size and sha256),
accepts only an OCI image manifest (schemaVersion 2) and image config, sha256 descriptors and uncompressed or gzip
OCI tar layers (no foreign layers, nested indexes or runtime conversion); other formats are unsupported.
It checks config rootfs diff_ids against the decompressed streams and verifies the platform. It derives
the complete expected merged root tree by ordered OCI layer/whiteout application, including every file
byte, path/type, symlink target, hardlink relation, mode, uid/gid, mtime and supported xattr. Tree identity excludes host inode/device numbers and atime/ctime,
which are not image metadata; hardlink groups must match and have no external links. Unsupported archive
entries or metadata refuse; no skipping unknown fields with filesystem effects. Hash/descriptor/parse
failure is `artifact_measurement_invalid`. The manifest bytes are the identity even where two manifests
extract to the same root tree. No claimed digest is evidence until these checks and live binding succeed.

Before starting any image entrypoint, root creates a stopped container/snapshot under the lease,
validates the content and complete staged root tree as above, and in ordinary mode compares its measured
kind/digest to the enrolled receipt. A mismatch/tampered object never executes CP code. Root supplies the
fixed trusted P14 entry, explicit mode and managed configuration (`HEEL_MANAGED_HOST=1`); no image
entrypoint, env override, user command or restart policy can select an ungated path. The runtime must
support this stopped-snapshot inspection; otherwise unsupported. The subsequent live rendezvous checks
that precisely that staged immutable snapshot and launch profile were used, not a new resolution of a tag.

At the child rendezvous, root obtains the runtime's immutable container ID and init process identity,
pins the process (pidfd plus start time; no PID-only lookup), and inspects its mount namespace and actual
root through that pinned process. Root enumerates and compares the **entire** live immutable image tree
against the derived tree, including files outside the recipe closure; missing/extra/changed bytes or
metadata refuse. Runtime snapshot ancestry must resolve uniquely to the measured manifest and layers;
an image tag or inspect-reported image string alone is insufficient. An opaque snapshot backend whose
association/contents cannot be checked is unsupported. Runtime-generated files and mounts are not
silently exempt: the closed CP mount profile is exactly §3.2 plus the two private launch pipes. Each
allowed mounted subtree (D_CP, enrollment, maintenance, tmpfs and runtime proc/dev/etc entries) is checked
against that profile and its existing context/inode rules; the obscured image paths are still checked
in the underlying snapshot. No mount may shadow the interpreter, entrypoint, modules or dependencies.
H6-IMAGE records the concrete proc/dev/etc mount list and metadata normalization rules for the chosen
runtime before P17; H6-RUNTIME freezes the fixture profile before qualification, P14 the integrated
profile before its proof. Unspecified mounts/normalization are refusals, not implementation discretion.

**Use-time binding.** Before snapshot creation/inspection the verifier obtains L(SH), then an exclusive
runtime artifact lease (root-only runtime lock/lease object, no new filesystem record). Lock order is
L → artifact lease → child DB lock → SQLite. GC, snapshot/image replacement and mount-profile mutation
must honor the same lease; mutators needing L take EX before any artifact lease. The lease pins the
manifest/blob descriptors, immutable snapshot and launch profile through child exit. Store bytes and
snapshot contents have no writable alias accessible to CP/executor/ingress; runtime rootfs is read-only,
with no writable upper tree, code bind or post-measurement mount mutation. Root store maintenance must
quiesce/reap the child and release its lease before changing those objects. A read-only bind alone is
not evidence of immutability. The qualified backend must supply immutable snapshots plus enforced lease
exclusion, or launch refuses `artifact_measurement_unsupported`. This is a trusted root/runtime contract,
not tamper resistance against compromised root/runtime/kernel. Recipe checks still measure actual loaded
code/dependencies; trusted Python startup must not import from D_CP/tmp/env/PYTHONPATH or mutable paths.

The child starts the trusted P14 entry with neither listener nor reaper constructed, acquires its own
L(SH) and DB lock in the existing order, loads enrollment once, and sends a fresh 32-byte nonce on its
inherited private child→root pipe as exactly
`{schema_version:"heel.cp-artifact-ready.v1", nonce}` (cap 256, canonical, no extra keys).
Frames use a four-byte unsigned big-endian length followed by exactly that many bytes; reject length
above the phase cap before reading its body. No EOF-delimited frame on these lifetime pipes.
Root independently reads fence/J/config/receipt/volume and the live
child facts; it compares child facts rather than trusting a claimed image or tuple. Both sides read the
same receipt inode/bytes under L(SH); for offline modes receipt may be absent and is bound as null.
Root sends exactly one launch frame on the root→child pipe:
`{schema_version:"heel.cp-artifact-launch.v1", nonce, mode, fence_revision, receipt_digest,
artifact_kind, artifact_digest, consumer_recipe_digest, file_binding, cp_volume_id}`.
`nonce`/recipe/receipt digests are hex64, receipt_digest nullable only for offline modes; other types
are the already closed types in §6–§7; cap 2048 bytes, no extra keys, EOF/duplicate/oversize reject.
Frame schema_version is the fixed literal above; mode is the §6.7 enum, fence_revision int
1..2147483647 (never bool), artifact kind/digest as above, and nonce exactly 32 fresh random bytes
encoded as hex64. No secret, proof, credential hash or arbitrary path enters this frame. It is ephemeral, never stored,
logged, exported to cloud or accepted through a socket, CLI or environment variable. Root compares
receipt kind/digest before sending in ordinary mode; CP independently compares them in row 11a.
The ready/launch pair is one-shot. Only `offline_verify_enrollment` subsequently uses the same two
pipes for §7.4's one challenge/response pair, after its offline gate; phase-specific schema and caps
are enforced. Other modes accept no further payload; liveness uses open/closed state only. This does
not create four pipes or recursively invoke enrollment verification during ordinary startup.

`ArtifactObservation` is an opaque in-process value produced by the P14 private-channel adapter:
`measured(kind, digest, binding)` or one of the eight errors below. Binding comprises the fresh nonce,
exact child/mode, L generation (stable inode), fence revision, receipt digest/absence, loaded FileBinding,
recipe and volume; local kernel channel ownership and root's pinned child handle bind the frame to this
process (process IDs need not be serialized). The adapter checks the full frame against its local
observations and consumes it once. The same LoadedEnrollment and immutable observation reach the gate
and listener composition; no reload/spawn/exec may occur between measurement and constructing either
listener. A child exec, exit, namespace/root/config change or re-created pipe invalidates the rendezvous.
The host and child recheck pinned process/mount/lease and context at the permit boundary; changes after
that boundary are excluded by lifetime leases/SH and read-only snapshots, not by a timestamp comparison.
A direct invocation with no inherited root-created channel always fails closed. Test constructors are
never reachable in production composition.

Parent holds L(SH) and the artifact lease for the entire child lifetime. Enrollment ack follows
§7.4 step 5: after reaping release both, acquire fresh EX then a new lease and remeasure; never acquire
L while retaining an artifact lease. Child retains its own
SH and DB lock as before. Parent never takes the child's DB lock or waits under EX. Stop waits for child
exit and reaping before lease release; EX mutation times out `lifecycle_busy` while holders survive.
The private pipes remain open as liveness channels; parent loss/EOF before gate means refuse, after
startup means supervised shutdown/reap. Runtime restart policies and boot units start the **root
verifier**, never an old CP container directly. Each replacement child (including runtime auto-restart,
service restart and reboot) gets a fresh nonce, new measurement and receipt comparison. No disk cache
of a permit is valid. Parent death must not let a surviving child outlive its lease: the backend retains
the lease until that child is reaped, and supervision terminates it. F23 must test this, including
restart recovery of orphaned leases; if unavailable there is no managed launch. No instantaneous
post-start shutdown latency or perfect antirollback claim is made.

**Closed failures and recovery.** Artifact errors are exactly:
`artifact_measurement_missing` (no channel/actual object); `artifact_measurement_unavailable` (I/O,
inspection failure or deadline); `artifact_measurement_invalid` (malformed/tampered manifest/blob/tree);
`artifact_measurement_unsupported` (kind/backend/platform/immutability capability not admitted);
`artifact_measurement_ambiguous` (nonunique manifest/snapshot/process association);
`artifact_mismatch` (measured kind/digest differs from enrolled receipt);
`artifact_binding_changed` (process/context/lease changes);
`artifact_channel_invalid` (nonce/frame/peer/liveness failure).
All refuse before **both** TCP server and Unix listener construction, with no socket inode, DB mutation,
reaper, domain rotation or automatic enrollment. Host emits only the fixed code and exits on errors
before a child exists; after spawn it closes pipes, kills/reaps the unserved child and releases leases.
CP emits only the corresponding fixed gate refusal. Lock acquisition keeps §6.1 bounds; measurement
and rendezvous have a 60-second total deadline after lock acquisition (channel reply after child's
ready frame ≤ 5 s). Timeout refuses and reaps, never falls back to claimed metadata. Large artifacts
that cannot be measured within the bound are unavailable until separately reviewed; no unbounded wait.
Missing/corrupt receipt retains §6.7 row 5 errors. Exact artifact mismatch needs deliberate maintenance
re-verification (§7.5), while transient inspection failures may retry a fresh complete launch. Receipt
replacement requires L(EX), so cannot race a live child or measurement. A same-recipe A′ never borrows
A's receipt; a valid A launch changes no epoch/counter/history. Pending/offline paths measure identically
but do not compare to an old receipt; they never construct listeners and cannot mint ordinary permits.

**Qualification boundary.** F23 [U] is this complete runtime-store/live-snapshot/lease/process/channel
capability, not presumed from an inspect API. H6-RUNTIME proves it with fixture images; P14 proves real
entry/adapter/gate composition; P17 repeats on release artifacts. All scans stream within the declared H6-RUNTIME root-FS/image and memory budgets, including any
comparison index/snapshot scratch; no extra D_CP/slot allocation or unbounded verifier cache is allowed.
Concrete image sizes and measurement resource maxima must be recorded in H6-IMAGE facts and qualified
by the stage owner before launch admission; unavailable capacity refuses. A source recipe, offline model or
one-time image smoke proves none of F23. Missing capability blocks launch; no weaker equivalence policy.
R3 `base-countermodel.json` reproduces the R2 A/A′ serve/serve defect before amendment.
`witness-artifact.json` checks 56 synthetic cases and a 695-byte maximal launch frame; its JSON trees
are not an OCI extractor. `witness-interleavings.json` enumerates 27 schedules (zero stale constructions
under modeled locks; six without enforcement). They check design consistency only; F23 is still unknown.

### 7.5 Operation identities and repair

| Situation | config `operation_id` | fence | DB row `operation_id` | receipt `operation_id` |
|---|---|---|---|---|
| bootstrap/migration pending | intent op | `operation_id` | same op after reconcile | same op |
| restore pending (after `rotate_domain`) | restore op | `operation_id` | same op after reconcile | same op |
| serving / ordinary boot | completed op | `domain_operation_id` | same | same |
| maintenance re-verification (recipe or binding changed, same K) | unchanged domain op | `domain_operation_id` | same | same; new receipt replaces old |

Re-verification creates **no** operation id and no new cycle: `enter_maintenance(enrollment_reverification)`
→ `invalidate_enrollment_verification` → optional `reinstall_enrollment_config` (same bytes, fresh inode)
→ `verify_and_record_enrollment` → `leave_maintenance`. Missing/corrupt/mismatched K is not repairable
this way; it requires domain replacement (§6.10). An artifact or kind change requires this maintenance re-verification even when the recipe is equal.
The ordinary host launch comparison (§7.4a), not recipe inequality, prevents using A's receipt for A';
P17 re-verifies on release. A failed launch never auto-enrolls the newly requested artifact.

Sequence: pending intent → config → offline reconcile/recovery → `record_reconciled` → tunnel record →
offline actual-consumer verify and exit → EX ack → `complete_operation` (J-protected) → ordinary startup
host artifact measurement + bound load/gate → both listeners → readiness → edge smoke → ingress. Authenticated HTTP smoke is after
completion and is never an ack prerequisite; a failed smoke keeps ingress closed and the operator returns to
maintenance only after quiescing holders. Edge/tunnel rotation remains separately owned
([B] `RUNBOOKS.md:117–128`) and never acknowledges enrollment.

### 7.6 Deviations from ENR (explicit) and preserved properties

D-E1 recipe split into a startup-self-measurable digest plus root-observed `artifact_digest` (ENR put the
image digest inside the startup-checked recipe, which the CP cannot measure from inside). R3 adds
mandatory host-side actual-artifact measurement and comparison at every startup (§7.4a); this corrects
R2's unenforced ordinary-start promise without weakening exact identity to recipe equivalence. D-E2 maintenance
reason `enrollment_reverification` replaces `secret_rotation` (K rotation is domain replacement). D-E3 fence
gains `domain_operation_id` so config/DB/receipt operation ids can be compared in serving. D-E4 K staging
lives in the operation intent rather than a separate staging file. D-E5 tunnel evidence is a separate
callable. D-E6 receipt schema v2 adds `artifact_kind`/`artifact_digest` (819 ≤ 1024). Preserved: Customer
§6.1's twelve properties, all 15 outcomes, Q GET/HEAD/one-shot/terminal semantics, no target POST, S
§14.2 nullability/predecessor/expiry, 1 live + 16 retained, 28 KiB, 64 deliveries/10 min, six cleanup
attempts. Threat boundary: protects against an old installation, stale mount/image, executor, ingress or a
holder of ids/receipts/DB snapshots; not against compromised current root, CP or operator, or simultaneous
rollback of fence + config + DB. Old hosts remain powered off/detached/destroyed under operator fencing.

### 7.7 Slot marker `heel.managed-slot-domain.v1` (P12 writer, retained)

`/var/lib/heel/slots/<slot>/domain.json`, root 0600, cap 1024 (max 381), keys `{schema_version, slot_id,
installation_id, restore_epoch, enrollment_secret_id, epoch_id, adopted_at_ms}`. Match → ordinary S
ceremony (authority still from CP); missing with no epoch → write then allocate; missing with epoch,
mismatched or corrupt → close admission, S §4.9 retirement (`local_state_invalid`), then marker, fresh epoch,
seed, pairing/binding/approval; retirement that cannot validate → `cleanup_failed`, no new epoch; fence not
serving → supervisor cannot run.

### 7.8 Volume identity `.heel-volume-id`: exactly 37 bytes (`vol_` + 32 hex + LF), written once, 0:10001 0440.

### 7.9 Denial/provenance-only rule (retained)

`domain.json`, `.heel-volume-id`, the verification receipt and every id may only deny or record provenance;
none selects a runner, reloads a permit, recreates W/Q, resurrects a receipt or authorizes a target request
[R:EA 151, 158–168; P 501; Q 68, 83, 148].

## 8. Early H6-IF → P02 schema amendment (A-P02R2, before the P02 grant)

P02's four paths unchanged (`heel/saas/migrate.py`, `heel/saas/canary_store.py`,
`heel/saas/managed_authority_ledger.py`, `tests/test_managed_authority_migrations.py`). R2 extends R1's
DDL with the durable result columns, provenance and an update rule (explains R1-F2: the result must survive
a lost receipt inside the same transaction). P02 implements it identically in migration and runtime DDL at
its next migration number; P14 is the only writer; readers are the gate and CP runtime epoch checks.

```sql
CREATE TABLE managed_restore_domain (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  installation_id TEXT NOT NULL CHECK (typeof(installation_id)='text' AND length(installation_id)=37
    AND substr(installation_id,1,5)='inst_' AND substr(installation_id,6) NOT GLOB '*[^0-9a-f]*'),
  restore_epoch TEXT NOT NULL CHECK (typeof(restore_epoch)='text' AND length(restore_epoch)=64
    AND restore_epoch NOT GLOB '*[^0-9a-f]*'),
  enrollment_secret_id TEXT NOT NULL CHECK (typeof(enrollment_secret_id)='text' AND length(enrollment_secret_id)=36
    AND substr(enrollment_secret_id,1,4)='enr_' AND substr(enrollment_secret_id,5) NOT GLOB '*[^0-9a-f]*'),
  cp_volume_id TEXT NOT NULL CHECK (typeof(cp_volume_id)='text' AND length(cp_volume_id)=36
    AND substr(cp_volume_id,1,4)='vol_' AND substr(cp_volume_id,5) NOT GLOB '*[^0-9a-f]*'),
  operation_kind TEXT NOT NULL CHECK (typeof(operation_kind)='text'
    AND operation_kind IN ('bootstrap','migration','restore')),
  operation_id TEXT NOT NULL CHECK (typeof(operation_id)='text' AND length(operation_id)=36
    AND substr(operation_id,1,4)='rop_' AND substr(operation_id,5) NOT GLOB '*[^0-9a-f]*'),
  previous_restore_epoch TEXT CHECK ((operation_kind='restore') = (previous_restore_epoch IS NOT NULL)
    AND (previous_restore_epoch IS NULL OR (typeof(previous_restore_epoch)='text'
      AND length(previous_restore_epoch)=64 AND previous_restore_epoch NOT GLOB '*[^0-9a-f]*'
      AND previous_restore_epoch <> restore_epoch))),
  backup_provenance TEXT NOT NULL CHECK (typeof(backup_provenance)='text' AND (
    (operation_kind='bootstrap' AND backup_provenance='none')
    OR (operation_kind='migration' AND backup_provenance='pre_domain')
    OR (operation_kind='restore' AND backup_provenance IN ('pre_domain','domain')))),
  db_schema_version INTEGER NOT NULL CHECK (typeof(db_schema_version)='integer'
    AND db_schema_version BETWEEN 1 AND 2147483647),
  terminalized_reservations INTEGER NOT NULL CHECK (typeof(terminalized_reservations)='integer'
    AND terminalized_reservations BETWEEN 0 AND 2147483647),
  revoked_runner_keys INTEGER NOT NULL CHECK (typeof(revoked_runner_keys)='integer'
    AND revoked_runner_keys BETWEEN 0 AND 2147483647),
  closed_generations INTEGER NOT NULL CHECK (typeof(closed_generations)='integer'
    AND closed_generations BETWEEN 0 AND 2147483647),
  revoked_grants INTEGER NOT NULL CHECK (typeof(revoked_grants)='integer'
    AND revoked_grants BETWEEN 0 AND 2147483647),
  stopped_runs INTEGER NOT NULL CHECK (typeof(stopped_runs)='integer'
    AND stopped_runs BETWEEN 0 AND 2147483647),
  reconciliation_digest TEXT NOT NULL CHECK (typeof(reconciliation_digest)='text'
    AND length(reconciliation_digest)=64 AND reconciliation_digest NOT GLOB '*[^0-9a-f]*'),
  reconciled_at_ms INTEGER NOT NULL CHECK (typeof(reconciled_at_ms)='integer'
    AND reconciled_at_ms BETWEEN 1 AND 9007199254740991),
  CHECK (operation_kind <> 'bootstrap' OR (terminalized_reservations = 0 AND revoked_runner_keys = 0
    AND closed_generations = 0 AND revoked_grants = 0 AND stopped_runs = 0))
);
CREATE TRIGGER managed_restore_domain_no_delete BEFORE DELETE ON managed_restore_domain
BEGIN SELECT RAISE(ABORT, 'managed_restore_domain_immutable'); END;
CREATE TRIGGER managed_restore_domain_update_rule BEFORE UPDATE ON managed_restore_domain
WHEN NEW.operation_kind <> 'restore' OR NEW.backup_provenance <> 'domain'
  OR NEW.operation_id = OLD.operation_id OR NEW.installation_id <> OLD.installation_id
  OR NEW.previous_restore_epoch IS NOT OLD.restore_epoch OR NEW.singleton <> OLD.singleton
BEGIN SELECT RAISE(ABORT, 'managed_restore_domain_update_invalid'); END;
```

Writes: only the P14 offline entry, inside its single reconciliation transaction: `INSERT` (bootstrap,
migration, pre-domain restore) or `UPDATE … WHERE singleton=1` (domain-bearing restore: kind restore,
provenance domain, new operation id, same installation, `previous_restore_epoch` = old epoch). Reader
contract: exactly one row and stored `reconciliation_digest` = `SHA256(J(result-from-columns))`, else
`domain_invalid`; the fence decides completion. SQLite INTEGER affinity converts `True`, `1.0` and `"1"` to integer 1 before
any CHECK runs (`witness-sql.json`), so rejecting bool/float/str is the P14 pre-binding validator's job,
tested by P02/P14, not a DDL guarantee. P02 tests: schema parity
(`test_fresh_runtime_and_upgraded_database_schema_parity`) and
`test_managed_restore_domain_constraints_and_singleton` (all `witness-sql.json` cases) within the existing
test file. Witness `witness_sql.py` extracts this exact block and runs it in-memory (SQLite 3.x):
5 accepted shapes, 26 rejections, 3 recorded affinity coercions, stale-digest reader rejection;
not P02 parity.

## 9. Staged acceptance, DAG and named oracles

```
accepted H3 ─▶ H6-LAUNCH ─▶ I ─▶ P09 ─▶ P10 ─▶ … ─▶ P12 ─▶ P13 ─┐
H6-IF R3 + Q/EA amendment ─▶ plan amendment ─▶ P02 … P05 ─▶ P06/P07  │
                     P05 + H6-LAUNCH ─▶ H6-RUNTIME (provider authz) ─┴─▶ P14 ─▶ P15 ─▶ P16 ─┐
                     H6-IMAGE (H6-IF + accepted, merged B0/BIR handoff) ────────────────────┴─▶ P17 ─▶ P18
```

No stage consumes a later stage's evidence. **H6-RUNTIME** is a prerequisite capability qualification on a
real host with a labelled source-pinned `qualification_fixture`: provisioning/layout/UIDs, devices, §5.3
measurements, slot quota capability and inode/block exhaustion, fence/J/intent callables with fault
injection, cross-container flock with a minimal holder container, mount/pipe/process-inspection capability
for §7.4/§7.4a with a fixture verifier (including actual OCI measurement and lease binding), kernel/nft/HZ/setns profile, container capability, pause behaviour,
provider power-off/destroy, backup exclusion. It neither requires nor claims P14 integrated restore, P15
transport, P16 browser, P17 artifact or P18 customer proof. **P14** proves the actual integrated
loader/verifier/gate/offline entries on `integrated_source`; **P17** proves packaged identity and
re-verifies enrollment on `release`; **P18** customer use. Mocked consumers never discharge a real gate.

**25 named oracles** (17 original + 8 review; all PENDING until their owners execute them in authorized
environments):

| # | Test | Owner (file) | Oracle |
|---|---|---|---|
| 1 | T-P01 `test_accepted_host_useful_path` | P15 (`tests/linux/test_managed_authority_proof.py`) + P16 | real CP/root/container; inert pairing → W → Q lower GET → Q higher GET → redacted findings |
| 2 | T-P02 `test_restore_complete_then_fresh_pairing_useful` | P14 → P15 | full restore incl. enrollment verify; fresh seed/pair/bind/approval; useful GET pair; old grants refused |
| 3 | T-P03 `test_reboot_keeps_epoch_and_counters` | H6-RUNTIME fence half; P14 CP half | same fence/epoch/counters; uncertain-completion cut C2 refuses until recovery |
| 4 | T-N01 `test_maintenance_or_pending_publishes_neither_listener` | P14 | every non-serve decision incl. J present and verifier mode: no TCP listen, no socket inode |
| 5 | T-N02 `test_fence_missing_invalid_profile_symlink_hardlink_same_device_refused` | H6-RUNTIME (`tests/test_managed_fence.py`) + P14 | each fence error incl. `fence_publication_uncertain`; orphan/wrong-profile L repair |
| 6 | T-N03 `test_executor_uid_collision_or_group_membership_refused` | H6-RUNTIME (`tests/test_managed_host_layout.py`) | uid ∈ {0,10001,10002,65534, reused} or any group → refuse |
| 7 | T-N04 `test_epoch_parent_symlink_mount_or_mode_drift_refused` | H6-LAUNCH + P12 | drift at any component → refuse |
| 8 | T-N05 `test_cp_admission_refuses_at_ceiling_terminal_still_commits` | P06 + H6-RUNTIME | §5.4; R commits in reserve |
| 9 | T-N06 `test_blocked_checkpoint_wal_cap_refuses_admission` | P06 | long reader, WAL > 64 MiB → refuse |
| 10 | T-N07 `test_slot_quota_exhaustion_capacity_unavailable_no_deletion` | H6-RUNTIME + P12 | block **and inode** exhaustion by executor writes; root cleanup completes; fresh allocation honest |
| 11 | T-N08 `test_restored_db_with_old_live_host_rejected` | P14 | old holder → `lifecycle_busy`; old epoch → `restore_mismatch`; old K → 401 |
| 12 | T-N09 `test_provider_pause_longer_than_window_never_extends_authority` | H6-RUNTIME facts + P15 | pause > 3 s; no packet without fresh Q; STOP ≤ 5 s |
| 13 | T-N10 `test_interrupted_operation_each_stage_stays_disabled` | H6-RUNTIME + P14 | every §6.9 cut; same op id; one epoch/K |
| 14 | T-N11 `test_executor_host_tmp_and_host_root_unreachable` | H6-LAUNCH | during-run denial |
| 15 | T-N12 `test_rotation_old_host_and_old_slot_identity_rejected` | P12 + P14 | old marker/epoch refused; old K/id/receipt cannot authenticate |
| 16 | T-N13 `test_backup_excludes_slot_fs_fence_and_secrets` | H6-RUNTIME | backup contains only CP DB; no K/intent/config/receipt |
| 17 | T-N14 `test_restored_completion_marker_is_not_permission` | P14 | restored row + pending fence → refuse |
| 18 | `test_workspace_container_selected_home_and_host_path_denial` | H6-LAUNCH; P15 rerun; P18 `release` | §4.6; no K in executor |
| 19 | `test_aggregate_physical_budget_and_terminal_reserve` | H6-RUNTIME + P06 | partition; data + inode fill; WAL reader; reserve intact |
| 20 | `test_fence_cas_two_writers_and_startup_interleavings` | H6-RUNTIME + P14 | lock schedules incl. verifier SH/parent EX, old/new volumes |
| 21 | `test_fresh_bootstrap_and_restore_schema_parity` | P02 + P14 | bootstrap, both migrations, pre-domain and domain restore incl. lost-receipt recovery |
| 22 | `test_fence_closed_records_crossfield_mutations` | H6-RUNTIME + P14 | every variant/record of §6–§7 constructible; mutants and cap+1 reject |
| 23 | `test_enrollment_rotation_and_domain_markers_never_authorize` | P05 + H6-RUNTIME + P12 + P14 | E01–E15 below; markers/ids never authorize |
| 24 | `test_restore_interruption_and_old_host_exclusion` | P14 on qualified host | crash/reboot each stage; fenced old host/image cannot rejoin |
| 25 | `test_layout_lifetime_binding_and_hostile_mutations` | H6-RUNTIME | §3.4 incl. released device size |

Final artifact journey (P17 parity + P18 clean room, `release`) is an additional obligation, not a row.

**Enrollment oracles (from ENR, owners per §12):** E01 P05 `tests/test_host_enrollment.py` correct
key/C/path/body accepts on all three routes; old/wrong key, copied ids/receipt/DB → 401 before
decider/charge/sequence. E02 same: wrong uid, overflowuid, wrong pidns deny before read (P15 proves real
SO_PEERCRED). E03 same: header/config grammar mutants, cap+1, framing ambiguity reject; no bytes logged.
E04 same + `tests/test_managed_attempt_admission.py`: altered path/body/epoch/host/volume under captured
MAC reject; valid replay cannot execute Q twice. E05 H6-RUNTIME `tests/test_managed_fence.py`: §6.9 cuts
for key/config/receipt/fence. E06 H6-RUNTIME layout test + qualification script: root/CP inode equality,
wrong bind/profile/uid map/symlink/hardlink refuse; executor/ingress cannot read K; pipes never logged.
E07 P14 `tests/test_managed_restore.py`: same fence/DB/volume with different loaded binding → serve vs
refuse; listener gets the gate's object. E08 P14 + `scripts/managed_restore_proof.py`: actual entry/mount/key
positive; same-id wrong K, old bind/image, stale/forged receipt, wrong recipe, EOF/timeout/killed child
cannot ack; no listener before completion. E09 P14: revision/config change between verify and EX forces
re-verify; receipt-before-fence and lost ack recover. E10 P14: four journeys positive, all
volume×config×state mismatches deny, lost receipt recovers. E11 P12 `tests/test_managed_root_ceremony.py`:
key/header absent from executor IPC; marker retirement; cleanup under inode exhaustion. E12 P14→P15 old
credential rejected with authorized old-host fencing evidence. E13 P14/P15 complete → useful GET pair.
E14 P17 `tests/test_managed_artifact_parity.py` release loader/verifier/prefix, no secret in
layers/wheel/logs. E15 existing owner tests: K/proof absent from DB, diagnostics, traces, CI, cloud.
E16 H6-RUNTIME + P14: A/A′ same recipe but different manifest, same A positive and kind mismatch;
compare actual content/snapshot, not requested tag; every refusal opens neither listener.
E17 same: missing/ambiguous/unsupported backend, tampered blob/tree, wrong receipt, forged/replayed
frame/nonce, direct CLI, EOF and timeout fail closed. E18 same: ordinary/restart/runtime restart/boot all
measure anew; no permit cache, no receipt means no serve. E19 same: concurrent tag replacement, snapshot
mutation/GC and receipt/config mutation at every rendezvous cut; lifetime lease/SH block replacement or
binding drift refuses; parent kill and orphan restart never release a live child's artifact.
E20 P17 E14 parity extension: same checks for release with no source checkout; P14 verifies offline
bootstrap/reconcile/verifier → ack → complete → ordinary host launch → listeners remains acyclic.
These extend rows 3, 4, 11, 20, 23, 24, not the count of 25 real oracles.

All customer O01–O15 and safety S01–S12 (P 718–755) remain required; this interface waives none.
P18 needs synthetic layer 1 and an authorized real SaaS unprepared for Heel at layer 2, plus actual
C3/DA/C5/C6/H3/H6 gates. C3 STOP and pending H3/B0 reviews are unchanged.

## 10. Image and build-input handoff

BIR (accepted) grants B0 exactly five paths; B0 `5eefa25` is not accepted. After B0 independent
source/provenance review, exact-tree CI image acceptance and merge, `deploy/Dockerfile.control-plane` and
`.github/workflows/ci.yml` pass to P17; `deploy/requirements-control-plane.txt`,
`scripts/verify_control_plane_image.py`, `tests/test_saas_deployment.py` stay read-only for P17. P17 keeps
exactly **10 + 3** paths (P 650); nothing appended. A current-CP image is never final managed evidence.

H6-IMAGE (fresh Opus/Astra; after H6-IF and the accepted, merged B0 handoff; 2 paths:
`docs/saas/MANAGED_HOST_IMAGE_FACTS.md`, `tests/test_managed_host_image_facts.py`) writes **facts only**:
executor base and BuildKit frontend digests; hash-locked runtime closure with no test packages and no shell;
the `/opt/heel` prefix layout (§4.2: `/opt/heel/deploy/host/executor.py`, `/opt/heel/heel/{runner,saas}`,
fixed dependency directory, interpreter path); rootfs contract §4.3; CP enrollment directory bind and
receipt path; consumer-recipe manifest layout (§7.4); mount table; rollback inputs. Executor lock: hash-
locked requirement lines embedded in `deploy/Dockerfile.executor` as a BuildKit heredoc consumed by `pip
install --require-hashes --only-binary=:all: --no-index` (inside P17's existing path); fallback
`deploy/requirements-executor.txt` only via a separately reviewed handoff before P17. H6-IMAGE writes no
Dockerfile/compose/env/lock/builder/CI path and no artifact; `install-rootfs` later consumes the P17 image.
Public wheel exclusion and commercial classification preserved; no public shim or relicensing.

<!-- H6-TRANSCRIPT-END -->
