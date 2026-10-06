# Plan-differential runner — Phase 1 design spec

Date: 2026-10-02. Branch: `feat/plan-differential-runner` (base `main` @ `844fc1f`).
Blast radius: **medium — adds network egress under a signed scope.**
Role: design only (T1 apps-exception revision; fourth revision; post-escalation D4
correction of 2026-10-05, §0.1; post-escalation D5 correction of 2026-10-06, §0.2). It replaces the revision committed at `1c6b324` in full. This document is the contract for T2 (implementation), T3 (red team),
T4 (remediation) and T5 (acceptance). It makes no acceptance claim and contains no product
code.

Normative words: **MUST**, **MUST NOT**, **MAY**. Where this spec and the controlling brief
(`.heel/plan-differential-run/brief.md`) disagree, the brief wins and the implementer stops
and reports.

---

## 0. Correction record (why this revision exists)

Three revisions precede this one.

- `cdf0411` extended four existing runner modules. T2 then found that a release test
  byte-compares 17 `heel/runner/*.py` files with the wheel and sdist checked in under
  `apps/`, and the brief forbade `apps/` (F22).
- `1c6b324` therefore changed no existing runner module. The price was that every `HEAD`
  route sent four requests, two of them with no credential. The orchestrator rejected
  that: the brief requires one request per supplied plan identity and nothing else.
- On 2026-10-02 Kevin authorized one narrow exception, now recorded in the brief: Opus may
  regenerate and commit **exactly** the three tracked release artifacts
  `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`,
  `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` and
  `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`, with the existing release
  builder. Every other `apps/` path stays forbidden.

With that exception the blocker of F22 is gone (F35), so this revision restores the
extension architecture of `cdf0411` and removes the anonymous-control workaround.

| # | Change in this revision | Where |
|---|---|---|
| A1 | **Exactly one `GET` or `HEAD` request per supplied plan credential for every planned route: two wire requests per route before retries, and no request without a plan credential.** `plan_entitlement_read` is widened to `HEAD` in the catalog; a `HEAD` pair is one run of that scenario | §6.1, R17 |
| A2 | The route and method allowlist is back in `heel/runner/compiler.py`. The private in-module compiler and its tickets are withdrawn | §6.2, I2 |
| A3 | Inventory reads are back in `heel/runner/store.py` as two read-only methods | §6.3 |
| A4 | Trust loading is back in `TLSTransport.__init__` | §6.4 |
| A5 | The three release artifacts are regenerated last, checked, and confined by path gates | §14.5, §17, R27 |

Corrections from `1c6b324` that remain valid and are kept unchanged:

| # | Correction | Where |
|---|---|---|
| C3 | Common numeric JSON (float, negative and large integer) completes through a redactor seam in the **new module**; evidence redaction is unchanged and the whole-`HEEL_HOME` credential scan stays clean | §7.4, R25, I5 |
| C4 | The real `SSL_CERT_FILE`/`SSL_CERT_DIR` trust boundary is stated and tested; Heel adds no CA or transport option | §7.2, R23, R14 |
| C5 | The existing fixed runner rejection text is reused; no new constant | §3.6, R16 |
| C6 | A 2xx denial envelope is inconclusive in a fresh run and in replay, never a regression pass | §8, §10, R24 |
| C7 | The row-1 reason list is closed and complete | §8.5 |
| — | Findings are stored only for completed pairs; `--as` takes handles; `--routes` takes a complete imported inventory; all eight invariants keep named tests; no scope creation or mutation path; no MCP or REST entry | §11, §3.2, §3.3, §12 |

C1 and C2 of `1c6b324` (no runner module may change; `HEAD` under
`anonymous_authenticated_read`) are **withdrawn**.

### 0.1 Post-escalation correction record (2026-10-05): D4

Written by a fresh Fable design session after the run stopped at `85d14cd`. Design only:
no product code, test or artifact was changed by this record.

Why. T3 found D1 (a 2xx denial body counted as parity, R11) at `0c456f1`. T4 loop 1
(`93521ed`) and loop 2 (`a1c2acd`) widened the denial-envelope recognizer to the closure
of report §9.3; the final T3 rerun (report §10, commit `85d14cd`) showed four concrete
denial bodies outside that closure still stored as `observed`, and named the structural
cause: a body that repeats the higher plan's key paths with `null` data is a key-path
superset, so every denial the recognizer misses becomes `observed`. That was the third
R11 break; the run stopped and escalated. On 2026-10-05 Kevin said "Continue", which the
orchestrator reads as authorization for one structural D4 cycle, a fresh red team and the
remaining gates, and not for another vocabulary extension or any scope change.

Decision (D4). `body_superset` now requires a **material** superset as well as a key-path
superset: the lower body must carry a JSON-truthy value at every path where the higher body
carries one. A lower 2xx body that echoes the higher key shape but is hollow at any such
path withholds parity exactly as a recognized denial envelope does (`inconclusive`,
`lower_hollow_shape`, row 9, not a candidate). No denial word, key, wrapper, heuristic,
classifier, annotation or network behavior is added. No value is compared with another:
a same-shape lower body with different URLs, IDs, names, counts or tenant values is still
`observed`. The exact rule, truth tables and test map are §8.6.

| # | Change in this correction | Where |
|---|---|---|
| D4.1 | `material_paths` beside `key_paths`; `body_superset` true only when shape and material supersets both hold; hollow shape withholds `status_parity` and `body_superset` | §7, §8.2, §8.4, §8.5, §8.6 |
| D4.2 | Row-9 reason list gains `lower_hollow_shape` | §8.5 |
| D4.3 | §8.3 synced to the accepted T4 loop-2 recognizer (report §9.3 closure), which it had understated since loop 1 | §8.3 |
| D4.4 | §7 and §7.4 redaction wording synced to the accepted T4 loop-1 D2 remediation (every JSON spelling of each secret character), with its known limits | §7, §7.4, §7.5, §16 |
| D4.5 | The fail-closed bullet "never yields `verified`" corrected: a 2xx envelope that discloses the supplied marker is row 3, `verified`, as `test_error_envelope_never_counts_as_parity` already pins | §8.5 |
| D4.6 | Replay: a hollow lower shape is `fail` / `inconclusive`, never a pass | §10 |
| D4.7 | Named tests Opus MUST add and MUST preserve; R28 | §8.6, §12 |
| D4.8 | Exhaustive post-escalation file allowlist for Opus | §14.6 |

Unchanged by this correction, explicitly: Phase 1 scope (§1), the CLI surface (§3), route
and identity rules (§3.2–§3.4), authorization and egress (§7.1–§7.2, §9), the verdict rows
and their order (§8.5), finding schema (§11), the eight invariants (§12), the T2 file list
(§14.1–§14.4) and the artifact procedure (§14.5).

### 0.2 Post-escalation correction record (2026-10-06): D5 — structural path identity

Written by a fresh Fable design session at `d479ff9`. Design only: no product code, test or
artifact was changed by this record. Normative content is §8.7, §14.7 and §17.6.

Why. The fresh red team after D4 (report §11) found D9, a fourth R11 break. `key_paths`
and `material_paths` render a path as `f"{path}.{key}"` and `path + "[]"`
(`heel/runner/plan_differential.py:131-179`), so the rendering is not injective: a literal
top-level key spelled `a.b` renders as `$.a.b`, the same string as the nested member `b` of
`a`. Lower `{"a": {"b": null}, "a.b": 1}` against higher `{"a": {"b": 1}}` is therefore a
string superset in both the shape and the material set, and the pair is stored `finding` /
`observed` and replays `fail` / `still_reachable` (report §11.3 item 5, §11.4). The same
collision exists for `[]`, `$`, the empty key, deeper nesting and lists. The committed
failing test is `test_redteam_break_d9_path_alias_turns_hollow_lower_body_into_observed`
(`tests/test_runner_plan_differential_redteam.py`). A literal key is not the nested path.
Kevin authorized continued execution; the orchestrator opened one D5 structural-path cycle.

Decision (D5). **Path identity is structural**: two paths are equal if and only if their
segment sequences are equal, where a segment is either an object key (any string, the empty
string included) or the array-element token. The representation stays `frozenset[str]`: the
string is now an **injective rendering** of the segment sequence, obtained by escaping the
renderer's own four metacharacters (`\`, `.`, `[`, `]`) inside every key with a leading `\`
(§8.7.1). Injectivity is proven for arbitrary JSON keys in §8.7.2 and machine-checked by a
fixed-seed corpus test (§8.7.7). The rejected alternative, tuple paths with a non-string
array sentinel, is recorded in §8.7.3 with the reason. No denial word, key, wrapper,
heuristic, classifier, annotation, network behavior or value comparison is added. The escape
set is fixed by the grammar of the renderer, not by observed attack spellings: it is the set
of characters the renderer itself uses, and the proof covers every other character.

| # | Change in this correction | Where |
|---|---|---|
| D5.1 | Path type, segment grammar, injective rendering, equality, bounds and secret-key stop | §8.2, §8.7.1, §8.7.2 |
| D5.2 | `key_paths` and `material_paths` render each key through `_path_segment`; `_evaluate`, `_observation_view` and `__all__` byte-unchanged | §7, §8.7.4 |
| D5.3 | Compatibility statement: internal helpers with a stable signature; no stored run, finding or regression format changes | §8.7.5 |
| D5.4 | Truth tables T4 (alias rows, before and after) and T5 (rendering) | §8.7.6 |
| D5.5 | Named tests Opus MUST add and MUST preserve; R29 | §8.7.7, §12 |
| D5.6 | Red-team acceptance attacks and stop conditions | §8.7.8 |
| D5.7 | Exhaustive post-escalation D5 file allowlist for Opus | §14.7 |
| D5.8 | Baseline → final counts and gate | §17.6 |

Unchanged by this correction, explicitly: Phase 1 scope (§1), the CLI surface (§3), route
and identity rules (§3.2–§3.4), authorization and egress (§7.1–§7.2, §9), the predicate
rules of §8.4, every verdict row and its order (§8.5), every D4 rule, row and case id
(§8.6), the denial-envelope recognizer (§8.3), redaction (§7.4–§7.5), the finding schema
(§11), replay (§10), the eight invariants (§12), the T2 file list (§14.1–§14.4) and the
artifact procedure (§14.5). Signed scope, host/redirect/DNS confinement, GET/HEAD only,
attempt reservations, budgets, credential secrecy, containment attribution and chain
verification are byte-for-byte unchanged in behavior: D5 touches two pure functions that
read a parsed body and nothing else.

## 1. What ships

One new public command, CLI only:

```
heel runner run --scope <scope-id> --base-url https://<host> \
    --as <lower-label>=<credential-handle> --as <higher-label>=<credential-handle> \
    [--routes <imported-inventory>] [--max-ops 50] [--dry-run]
```

For every route in the imported GET/HEAD inventory it sends the request **once per canary
identity** (lower plan, then higher plan) through `heel/runner/http_transport.py` and
compares the two responses. That is exactly two wire requests per planned route before
retries, for `GET` and `HEAD` alike. No request is ever sent without one of the two
supplied plan credentials. Where the lower plan receives what the higher plan receives it
records a finding with `evidence_state: observed` that no input declared.

One existing command changes its output: `heel runner credential add` now prints the
opaque handle it created (§3.2). No other command is added. Nothing else ships: no HAR
import, tenant differential, limit probing, writes, lifecycle sequences, MCP or REST
exposure, cloud, static-reviewer, pricing or site changes, and no scope creation or
mutation path.

## 2. Verified facts that shape the design

F1–F20 were read or run on 2026-10-02 at `844fc1f`. F22–F32 were read or run at `cdf0411`
(product code identical to `844fc1f`). F33–F39 were read or run for this revision on
2026-10-02 at `1c6b324` with the uncommitted T2 tree in place (the "dirty tree", §14.3),
or on a scratch copy of it. Line numbers cite files as committed at `HEAD` unless a row
says "dirty tree". F21 stays withdrawn; F34 replaces it with a measurement.

| # | Fact | Evidence |
|---|------|----------|
| F1 | `heel runner import-openapi` and `heel runner credential add` exit 2 in a fresh `HEEL_HOME`. Every `RunnerStore` read or write needs a bound context and no public command binds one. | Ran both in an empty `HEEL_HOME`; `heel/runner/store.py:5203-5206`, `:5276-5288` |
| F2 | A credential handle is `secrets.token_hex(16)`: random, 32 hex, not derived from the secret. One handle per semantic role per context; a second registration for a role raises. | `heel/runner/store.py:6998`, `:7025`, `:6961-6979` |
| F3 | `credential add` prints only `{"registered_count": 1}`. An ephemeral credential is read from `HEEL_RUNNER_CREDENTIAL_<HANDLE>`, so an operator who is never shown the handle cannot supply it. | `heel/cli.py:199`; `heel/runner/vault.py:186-192`, `:252-270`; `tests/test_runner_cli.py:75` |
| F4 | The existing privacy boundary is: handle and label never enter the cloud-disclosed approval projection (they are in the local manifest), and `runner prepare` stdout is counts only. The label is treated as possibly sensitive operator text. | `tests/test_runner_compiler.py:291-292`; `tests/test_runner_cli.py:76`, `:96-98` |
| F5 | The imported inventory is persisted as `routes.json` in the bound context directory, in the envelope `heel.runner-route-inventory.v1` (`schema_version`, `namespace`, `origin`, `verification_record_digest`, `inventory: {source_digest, routes}`). Each route is `{method, route_template, operation_id, placeholders}` with method `GET` or `HEAD` only, in canonical order. | `heel/runner/store.py:6839-6904`, `:808-826`; `heel/cli.py:142-154` |
| F6 | At `844fc1f`, `plan_entitlement_read` permits `GET` only (§6.1 widens it), roles `lower_plan`, `higher_plan`. `anonymous_authenticated_read` permits `GET` and `HEAD`, roles `anonymous`, `authenticated`. No other entry permits `HEAD`. | `heel/runner/catalog.py:60-93` |
| F7 | The transport and the manifest contract carry `HEAD`: HEAD framing is parsed, a HEAD body is refused, and a HEAD pair always evaluates `inconclusive`. | `heel/runner/http_transport.py:594-595`, `:612-613`, `:801`; `heel/canary_contracts.py:270-271`; `heel/runner/adapters.py:189-195` |
| F8 | The transport is HTTPS only, port 443, public addresses only, exact IANA-TLD hostname; no IP literal, port, userinfo, path, punycode or reserved suffix. | `heel/runner/http_transport.py:98-142`, `:46-53`, `:157-175` |
| F9 | Any 3xx raises `response_rejected`; no redirect is followed. `Host` is always the normalized hostname; no caller input reaches a header. | `heel/runner/http_transport.py:571-572`, `:906-912` |
| F10 | DNS is pinned. Each attempt re-resolves, requires set equality with the preflight set, connects to the pinned numeric address and re-checks the peer address. | `heel/runner/http_transport.py:695-716`, `:734-737`, `:760-761` |
| F11 | `TLSTransport` builds `ssl.SSLContext(PROTOCOL_TLSv1_2)` with `CERT_REQUIRED` and `check_hostname` but loads no trust store (zero CA certificates). `TargetHTTPSClient` accepts a `tls` object and exposes the context as `tls.context`. | `heel/runner/http_transport.py:233-243`, `:681`; ran `cert_store_stats()` |
| F12 | A test pins `TLSTransport().context.protocol == PROTOCOL_TLSv1_2` and forbids `ssl.create_default_context`, for the runner class and the `heel/saas` twin. | `tests/test_runner_http_transport.py:30-38` |
| F13 | The transport refuses `Transfer-Encoding` and `Content-Encoding`, bodies over 256 KiB, and any non-empty body that is not one JSON object. Evidence is stored before the body-shape refusal. | `heel/runner/http_transport.py:591-592`, `:604-605`, `:609-633`, `:845-863` |
| F14 | The executor reserves the grant before any transport call, calls `before_attempt` before every socket, and writes **raw** response headers and body to the private store. | `heel/runner/execution.py:579`, `:651-710`, `:716-736` |
| F15 | One manifest holds at most 20 actions and `maximum_requests` ≤ 20; evidence ordinals are < 20; the store keeps one mapping per scenario and at most four. | `heel/canary_contracts.py:309`, `:377`; `heel/runner/store.py:9270`, `:6932`, `:6953` |
| F16 | The marker contract: exactly one fixture binding beginning `heel-canary-` opts the route into `protected_canary`. | `heel/runner/execution.py:712-714`; `heel/runner/content_assertion.py:7-37`; `docs/EXPORT_DEMO.md:32` |
| F17 | `heel findings --run`, `heel log --run` and `heel regress add` read the SQLite `Store` and the HMAC containment chain, which carries `caller`. The runner's Ed25519 chain has no caller field. | `heel/cli.py:1423-1428`; `heel/containment.py:24-65`; `heel/runner/containment.py:25-29` |
| F18 | `heel regress run` re-executes through `HeelServer.heel_run`, which only knows registered synthetic targets. | `heel/regressions.py:142-203` |
| F19 | The wheel's module list is pinned twice. `tests/` is pruned from the wheel. | `release/open-core-v1.json`; `tests/test_open_core_release.py:107-206`, `:223` |
| F20 | `reference_rehearsal.run_reference` is the proven safe sequence: verify scope → exclusive attempt directory → ephemeral signer and identity → private `RunnerStore` → compile → locally signed grant → `LocalCanaryExecutor` → read private evidence → report. | `heel/reference_rehearsal.py:107-184` |
| F22 | `test_checked_in_runner_artifacts_match_the_current_public_pairing_and_recovery_api` requires 17 `heel/runner/*.py` files (`__init__`, `adapters`, `catalog`, `companion`, `compiler`, `containment`, `control_client`, `coordinator`, `execution`, `http_transport`, `identity`, `openapi_routes`, `redaction`, `runtime`, `service`, `store`, `vault`) to be byte-identical to the wheel and sdist under `apps/heel-cloud/public/downloads`. `content_assertion.py` is not in the list but is not changed either. | `tests/test_open_core_release.py:955-984` |
| F23 | On the dirty tree the full suite has exactly one failure, the artifact byte-compare of F22, on `catalog.py`. | Ran `TMPDIR=<resolved> .venv/bin/python -m pytest -q tests`: 1 failed, 1485 passed, 5 skipped. Baseline is 1486 passed, 5 skipped (F38) |
| F24 | The CI `package` job runs `scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`. It rebuilds the wheel from source and fails with `generated artifact is stale` if any shipped file differs. | `.github/workflows/ci.yml:85-87`; `scripts/build_open_core_release.py:1086-1092`. Ran on a pristine export of `HEAD`: `artifacts are current`, exit 0. Appended one comment line to `heel/cli.py`: `generated artifact is stale: heel_sim-1.2.0-py3-none-any.whl`, exit 1 |
| F25 | A `HEAD` action under `plan_entitlement_read` is refused today in three places, and all three read the permitted methods from the catalog or from the adapter registry derived from it. Widening the one catalog entry is the only change they need. | `heel/runner/compiler.py:147-149`; `heel/runner/adapters.py:46`, `:92`, `:186`; `heel/runner/http_transport.py:473-486` |
| F26 | The executor keeps one credential per semantic role per manifest and evaluates observations `[0]` and `[1]` of each scenario, so one `plan_entitlement_read` manifest is exactly one lower-plan and one higher-plan action. | `heel/runner/execution.py:421`, `:948-960` |
| F27 | The inherited failure: the transport calls `redactor.count_bytes(raw_headers, raw_body)` and maps any exception to `evidence_rejected`. `count_bytes` parses a JSON body and `_safe_json` raises on a float, a negative integer, an integer above 2^53−1, more than 1024 nodes, more than 256 members, or depth above 16. The executor classifies `evidence_rejected` as `failed` / `runner_fault`. The count is used only as a number; stored evidence is the raw bytes. | `heel/runner/http_transport.py:833`, `:851-856`; `heel/runner/redaction.py:141-155`, `:158-193`; `heel/runner/execution.py:548`. Ran `Redactor(()).count_bytes(b'{"price": 1.5}')` → `TypeError`; `b'{"n": -3}'` → `ValueError` |
| F28 | The transport accepts any `Redactor` instance (`isinstance`), and receives it as a `request()` argument from the executor. | `heel/runner/http_transport.py:899`; `heel/runner/execution.py:631`, `:754` |
| F29 | `ssl.SSLContext.load_default_certs()` honours `SSL_CERT_FILE`. On this build (OpenSSL 3.5.5) an unset environment loaded 128 CAs; `SSL_CERT_FILE=<test CA>` loaded exactly 1 and the test CA was trusted. | Ran on `TLSTransport().context` in two subprocesses; `ssl.get_default_verify_paths().openssl_cafile_env == "SSL_CERT_FILE"` |
| F30 | A scratch prototype through the real `CanaryCompiler`, `LocalCanaryExecutor` and `TargetHTTPSClient` over a loopback seam showed: (b) a GET body `{"price": 1.5, "n": -3, "big": 2**60, "echo": <Authorization>}` gave `failed`/`runner_fault` with the inherited redactor and `completed` with a tolerant `Redactor` subclass substituted at the transport seam; (c) with a `RunnerStore` subclass redacting before `store_response_evidence`, no file under `HEEL_HOME` contained either credential. Part (a) of this row in `1c6b324` measured the rejected four-request path and is withdrawn. Repeated on the dirty tree in F34. | Ran; script not committed |
| F31 | The runner parser already prints the fixed line `Heel runner command was rejected.` for every argparse error under `runner`. | `heel/cli.py:42`, `:1199-1207` |
| F33 | Outside `heel/saas`, `TLSTransport()` is constructed in exactly one place, the default of `TargetHTTPSClient`, and no product code constructs `TargetHTTPSClient` except the new module. So loading default trust in `TLSTransport.__init__` changes behavior only for this feature. | `grep -rn "TLSTransport(\|TargetHTTPSClient(" heel` excluding `heel/saas`: `heel/runner/http_transport.py:681` and the new module only |
| F34 | **Two requests per route, measured.** On the dirty tree (catalog widened), through the public CLI and the loopback seam, a full run planned 10 pairs. For `HEAD /api/export` the target log held exactly one `HEAD` with the lower credential, one with the higher, and none without a credential. Across the run no request arrived without a plan credential. 18 requests in total (two pairs stopped after a refused first response), chain valid, second listener untouched, no credential bytes under `HEEL_HOME`. With a route returning a float, a negative integer, `2**60`, 300 keys and the echoed credential listed first: the inherited redactor ended the run after 1 request (`transport:evidence_rejected`); with a tolerant redactor substituted in `_ScopedTransport` the pair was `completed`/`body_superset`, later pairs ran, and the `HEEL_HOME` scan stayed clean. | Ran two scratch scripts on a scratch copy; not committed |
| F35 | **The exception removes the blocker, measured.** On a scratch copy of the dirty tree: `--check` printed `generated artifact is stale: heel_sim-1.2.0-py3-none-any.whl`, exit 1; the builder without `--check` rewrote the artifacts; `git status --short -- apps` then listed exactly the three authorized files; `--check` printed `open-core release artifacts are current`, exit 0; the full suite gave 1486 passed, 5 skipped, 0 failed. | Ran `scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads` with and without `--check`, then the full suite, in the copy |
| F36 | The builder reads the working tree, not a commit, and is deterministic. The manifest holds only `name`, `sha256`, `size`, `schema_version`, `version`. The artifact hashes appear in no other tracked file; the `apps/` tests and `prepare-runtime.mjs` read them from the manifest. | `scripts/build_open_core_release.py:925-950`; `git grep` of both current hashes matches only the manifest; `apps/heel-cloud/scripts/prepare-runtime.mjs:212-220`; `apps/heel-cloud/tests/production-artifact.test.mjs:1078-1083` |
| F37 | The separate browser-engine wheel under `apps/heel-cloud/browser-engine` packages ten modules, none of which this feature changes, so its CI `--check` is unaffected. | `scripts/build_browser_engine.py:27-36`; `.github/workflows/ci.yml:183` |
| F38 | **Baseline record** (T2 session, at `cdf0411`, product code identical to `844fc1f`; Python 3.12.13, pytest 9.0.2, dnspython 2.8.0, repo-local `.venv`). Raw macOS `python -m pytest -q tests`: 35 failed, 1451 passed, 5 skipped; the 35 are 16 in `tests/test_runner_control_http.py` and 19 in `tests/test_runner_public_client.py`, all `RunnerRuntimeCorrupt: runtime state parent is unsafe`, because the default `TMPDIR` passes through the `/var` symlink. CI-equivalent, with `TMPDIR` resolved to its real path: **1486 passed, 5 skipped, 0 failed**. | `.heel/plan-differential-run/T2-baseline.txt`; `heel/runner/runtime.py:810-811` |
| F39 | The CI `package` job also runs `HEEL_REQUIRE_STANDARD_BUILD=1 python -m unittest tests.test_open_core_release -v` and installs the committed wheel. The strict mode needs the PyPA build frontend from `release/requirements-release.txt`, which is not in the local `.venv`; locally two of its tests fail for that reason alone. It has not been run for this feature. | `.github/workflows/ci.yml:79-93`; ran the strict command on the scratch copy |
| F32 | `RunnerStore` exposes `root`, `namespace`, `load_context()`, `list_routes()`, `replace_routes()`, `save_mapping()`, `list_mappings()`, `list_credentials()`. `list_routes()` validates the stored envelope and canonical order but does not return `source_digest`. | `heel/runner/store.py:878`, `:5203`, `:6831-6959` |

Consequence: Phase 1 is `run_reference` with the fixture transport replaced by the real
`TargetHTTPSClient`. Where an existing runner interface is too narrow, that interface is
**extended in place** (§6) and the file is listed in §14; nothing is worked around.
Restrictions that are properties of the inherited transport are kept and stated in §15.

## 3. CLI surface (exact)

### 3.1 Arguments

| Argument | Required | Rule |
|---|---|---|
| `--scope ID` | always | Existing signed scope. Loaded with `scope.get_scope`, checked with `scope.verify`. |
| `--base-url URL` | always | MUST pass `http_transport.normalize_target_origin`. `http://`, ports, paths, queries, userinfo, IPv4 and IPv6 literals, trailing dot, punycode and reserved suffixes are rejected. |
| `--as LABEL=HANDLE` | exactly twice to execute or to plan; zero only for the bootstrap dry-run (§4) | §3.2 |
| `--routes PATH` | no | §3.3 |
| `--max-ops N` | no, default `50` | Integer, `2 ≤ N ≤ 100`. §9 |
| `--dry-run` | no | Compile and print the plan. No DNS, socket, credential load or attempt reservation. |

The subparser uses `_RunnerArgumentParser` (no abbreviations) and inherits the `runner`
argv guard (`heel/cli.py:960-964`). No other option exists. There is **no** Heel option,
`HEEL_*` environment variable, config key or scope field that selects a transport, scheme,
port, resolver, CA bundle, header, method, attempt ID or caller identity. The one
environment influence that does exist, OpenSSL's default trust locations, is stated in
§7.2.

### 3.2 `--as`: credential handles and plan ordering

`HANDLE` is the opaque 32-hex credential handle ID created by `heel runner credential add`.
It is not the label and no label is accepted in its place.

- `LABEL` matches `[a-z0-9][a-z0-9_-]{0,31}`. `HANDLE` matches `[0-9a-f]{32}`. The two
  labels MUST differ and the two handles MUST differ.
- Each handle MUST resolve to exactly one `active` record in the setup store. Otherwise
  reject.
- **Tier comes from the role the human chose at `credential add`.** One handle MUST have
  role `lower_plan` and the other `higher_plan` (F6). The first `--as` MUST be the
  `lower_plan` handle and the second the `higher_plan` handle. Any other combination is
  rejected. Heel never reorders, never infers tier from a label's spelling and never
  infers it from a response.
- Both records MUST share one auth profile (`heel/runner/compiler.py:160-162`).
- The label is the human's plan name. It is carried into the plan, the containment
  entries, the report and the findings. It has no effect on execution.

**Obtaining a handle.** `heel runner credential add` MUST print:

```json
{"credential_handle": "<32 hex>", "credential_source": {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_<HANDLE>"}, "registered_count": 1}
```

`credential_source.kind` is `environment`, `inherited_fd` (with `variable`) or `os_vault`
(no `variable`). The label, the role's secret and the secret's length MUST NOT be printed.

Why this is safe, and what stays private:

- A handle is random and not derived from the secret (F2). It is an index into the vault,
  not a credential. Knowing it grants nothing without the vault or the environment.
- Without it, an ephemeral credential cannot be supplied at all (F3).
- The existing boundary (F4) is unchanged: handles and labels still never enter the
  cloud-disclosed approval projection, `runner prepare` stdout stays counts only, and the
  label is still never printed by any command.
- Handles appear only in local output of `credential add` and `runner run`, in the local
  report and in local findings. They are never sent to the target.

### 3.3 `--routes`: the imported inventory

`--routes` names an **imported inventory**: a file in exactly the persisted format that
`heel runner import-openapi` writes (F5). It is not a selector and no other format is
accepted.

- Omitted (default): the setup store's current inventory, the file returned by
  `RunnerStore.route_inventory_path()` (§6.3). The dry-run prints that path, its
  `source_digest` and its route count so the operator can copy or archive it.
- Given: `PATH` is read with the existing bounded loader `_load_bounded_openapi` (regular
  file, no symlink, size-limited, duplicate keys rejected). It MUST be a complete
  `heel.runner-route-inventory.v1` envelope for the bound setup context, validated by
  `RunnerStore.route_inventory(artifact)` (§6.3). Typical
  use is a saved copy of an earlier import for the same origin.
- The file is the whole allowlist for that invocation. **Every** route in it is handed to
  the compiler (§6.2) and every route the compiler plans is executed. The CLI never
  removes, selects or rewrites a route. Execution order is the inventory's canonical order
  `(route_template, method, operation_id)`.
- An inventory file carries no signature. It is operator input at the same trust level as
  the OpenAPI document it was derived from. It can never name another origin (envelope
  check), a non-GET/HEAD method or an unsafe template (§6.2).

`--routes` never writes to the setup store and never changes the default inventory.

### 3.4 Per-route planning

Decided in the compiler (§6.2), for every route of the chosen inventory:

| Route | Decision |
|---|---|
| `GET` or `HEAD`, no placeholders | planned: 2 requests |
| `GET` or `HEAD`, placeholders, and the setup store holds a `plan_entitlement_read` mapping for exactly this `(method, route_template)` | planned with those fixture bindings: 2 requests |
| placeholders, no such mapping | `not_executed`, reason `unbound_placeholder`; never sent |
| any other method, or a route failing template rules | compile error for the whole command |

`HEAD` routes are executed exactly like `GET` routes: once with the lower-plan credential,
then once with the higher-plan credential, and never skipped. Heel never invents a path
parameter value; a human supplies one through the existing
`heel runner map --scenario plan_entitlement_read --method M --route T --fixture-fd N`.

### 3.5 Human-supplied marker

There is no marker flag. The marker is supplied through the existing channel (F16): one
fixture value beginning `heel-canary-` in the `plan_entitlement_read` mapping opts that
route into the `protected_canary` contract. Heel never generates, guesses or
extracts a marker from a response. The fixture value is never written to a finding, report
or log; only `marker_supplied: true` and the SHA-256 of the canonical binding list are. A
`HEAD` pair never has a marker (`marker_supplied: false`), whatever its fixture value.

### 3.6 Modes, output, exit codes

Mode selection, in order:

1. Scope unknown, signature invalid, unbound or expired → **reject**.
2. `--base-url` invalid, or argument rules of §3.1–3.2 violated → **reject**.
3. Normalized host is not exactly equal to an entry of `scope.target_allowlist` → **forced
   dry-run**: print the plan with `"authorized": false`, send nothing, bind nothing, append
   a `reject_run` security entry, exit `3`. This holds with or without `--dry-run`.
4. `--dry-run` → **dry-run**, exit `0`.
5. Otherwise → **execute**.

Allowlist matching is string equality between the normalized lowercase hostname and an
allowlist entry. No wildcard, suffix, scheme or port form matches.

Stdout is one JSON object. On rejection, stdout is empty and stderr is the **existing**
fixed line `Heel runner command was rejected.` (`_SAFE_RUNNER_COMMAND_FAILURE`, F31), the
same line argparse errors already produce. No new rejection constant is added. No path,
URL, label, handle, route or exception text is reflected. All exceptions are caught at the
command boundary.

| Exit | Meaning |
|---|---|
| 0 | Dry-run printed, or executed with no `observed`/`verified` finding |
| 1 | Executed; at least one `observed` or `verified` finding |
| 2 | Rejected before any request |
| 3 | Forced dry-run: host not in the scope allowlist |

Dry-run object:

```json
{"mode": "dry_run", "authorized": true, "scope_id": "...", "origin": "https://...",
 "context": "bound|already_bound|mismatch|unbound",
 "inventory": {"path": "...", "source_digest": "<64 hex>", "route_count": 9, "source": "default|file"},
 "plans": [{"label": "free", "role": "lower_plan", "credential_handle": "<32 hex>",
            "credential_source": {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_<HANDLE>"}},
           {"label": "pro", "role": "higher_plan", "...": "..."}],
 "max_ops": 50, "effective_max_ops": 50,
 "pairs": [{"ordinal": 0, "method": "GET", "route_template": "/api/export",
            "requests": 2, "marker_supplied": false},
           {"ordinal": 1, "method": "HEAD", "route_template": "/api/export",
            "requests": 2, "marker_supplied": false}],
 "not_executed": [{"method": "GET", "route_template": "/items/{id}", "reason": "unbound_placeholder"}],
 "requests_planned": 4, "requests_sent": 0, "plan_sha256": "<64 hex>"}
```

`requests` is every request the pair sends before retries and is always `2`: one per plan
credential. `plan_sha256` is the canonical digest of origin, scope ID, both plan
entries, inventory `source_digest`, the ordered pairs with their binding digests, and
`effective_max_ops`. The executed result repeats it so an operator can compare a run with
its dry-run.

Executed object: `mode: "executed"`, `run_id`, `attempt_id`, `scope_id`, `origin`,
`plan_sha256`, `requests_sent`, `effective_max_ops`, `pairs` (one entry per planned pair:
`method`, `route_template`, `verdict`, `predicate`, `reason`, `execution_disposition`,
`candidate`, `finding_id` or `null`, `runner_run_ids`), `not_executed`, `findings` (`id`, `predicate`, `evidence_state`,
`method`, `route_template`), `chain_valid`, `report_path`. `pairs` is the truthful record
of every planned pair, including pairs that did not complete; `findings` lists only stored
findings (§11).

## 4. Operator journey and state

Two `RunnerStore` roots under `HEEL_HOME`, both private (0700/0600, no symlinks):

- **Setup store**: the default `RunnerStore()`. Holds the inventory, credential metadata
  and the optional mappings. It never executes.
- **Attempt store**: `HEEL_HOME/plan-runs/<attempt_id>/`, created per execution exactly as
  `reference/<attempt>` is today (F20). Holds manifests, grants, reservations, the
  runner's signed containment chains, redacted evidence and `report.json`.

**Bootstrap dry-run.** Because of F1 the setup store must be bound before
`import-openapi` or `credential add` can work, and `run` is the only new command. So a
dry-run that is authorized (mode 4) and finds no bound setup context binds one and
reports `"context": "bound"`. This dry-run MAY be given with zero `--as` (handles cannot
exist yet); it then prints `plans: []`, `pairs: []` and the inventory block. Binding uses
the existing `RunnerStore.bind_context` with:

- `RunnerContext("workspace_local", "project_plan_differential", "env_" +
  sha256(host)[:16], <normalized origin>, sha256(canonical{"kind":
  "heel.local-plan-differential-context.v1", "host": host}), "staging")`
- an ephemeral in-process Ed25519 identity whose private key is discarded.

This is an implementation necessity. It reads the existing signed scope, writes only
runner state, and creates, edits or re-signs no scope. The context digest is a local
label, not a cloud verification record; authorization is always the live scope check.

If the setup store is already bound to a different origin or to any cloud context, the
command MUST NOT rebind, roll over or overwrite: dry-run reports `"context": "mismatch"`
with an empty plan and execute rejects. One `HEEL_HOME` serves one staging origin.
A forced dry-run (mode 3) never binds.

Documented order (the T5 path):

```
scope create → runner run --dry-run (binds) → runner credential add ×2 (prints handles) →
runner import-openapi → [runner map] → runner run --dry-run --as … --as … (plan) →
runner run → findings --run → regress add → regress run
```

## 5. Reused modules

`heel.scope` (`get_scope`, `verify`, `heel_home`, `ensure_home`), `heel.contracts`
(`AbuseVector`, `Severity`, `Category`), `heel.store.Store`, `heel.containment`
(`ContainmentLog`, `verify_chain`), `heel.crypto.SigningAuthority`, `heel.canary_contracts`,
`heel.runner.catalog` (`CATALOG_BY_ID`), `heel.runner.compiler` (`CanaryCompiler`,
`plan_differential_pairs`), `heel.runner.http_transport` (`TargetHTTPSClient`,
`BoundedResolver`, `TLSTransport`, `normalize_target_origin`, `CancellationToken`,
`TransportFailure`), `heel.runner.execution` (`LocalCanaryExecutor`, `ExecutionBundle`,
`ExecutionGate`), `heel.runner.store` (`RunnerStore`, `RunnerContext`), `heel.runner.vault`
(`EphemeralVault`, `select_vault`, `ephemeral_environment_name`), `heel.runner.redaction`
(`Redactor`, `_secret_key`), `heel.runner.content_assertion.protected_content`,
`heel.runner.openapi_routes` (`normalize_route_template`), `heel.runner.identity`,
`heel.runner.containment` (`verify_containment_chain`).

Four existing runner modules are extended, each by the smallest change that §6 names:
`catalog.py`, `compiler.py`, `store.py`, `http_transport.py`. **Every other existing file
under `heel/runner/` MUST be byte-identical to `844fc1f` at the end of T2** — in
particular `adapters.py`, `execution.py`, `redaction.py` and `vault.py` (path gate P2,
§17).

## 6. Extensions to existing modules

Each subsection is the complete permitted change to that file. The uncommitted T2 tree
already contains hunks for all six files; §14.3 says which are reused and which reworked.

### 6.1 `heel/runner/catalog.py` — `HEAD` for the plan pair

`plan_entitlement_read`: `allowed_methods` becomes `("GET", "HEAD")`. Nothing else
changes: roles stay `("lower_plan", "higher_plan")`, statuses stay `(200, 402, 403, 404)`,
`adapter_version` stays `"1"`.

This is what makes the two-request rule possible. One `plan_entitlement_read` manifest is
exactly two actions, `lower_plan` then `higher_plan` (F26), and after the widening the
compiler, `prepare_action` and the transport's `_valid_route` accept `HEAD` for it because
all three read the catalog (F25). So a planned `HEAD` route is **one run with two
actions: one `HEAD` carrying the lower-plan credential, then one `HEAD` carrying the
higher-plan credential.** There is no `anonymous` action, no third credential record and
no second run. `anonymous_authenticated_read` is not used by this feature at all.
Measured in F34.

The change is additive inside the already closed read-only `GET`/`HEAD` set. A `HEAD` pair
still always assesses `inconclusive` in the executor (F7). Consequence the docs MUST
state: `heel runner map` and `heel runner prepare` now accept a `HEAD` mapping for
`plan_entitlement_read`.

### 6.2 `heel/runner/compiler.py` — the route and method allowlist

Add one module-level pure function and one `CanaryCompiler` method. Change nothing else
in the file except the import they need.

```python
def plan_differential_pairs(
    inventory_routes: Sequence[Mapping[str, Any]],
    *, mapping: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:      # (planned, not_executed)

class CanaryCompiler:
    def compile_plan_differential_pair(
        self, *, method: str, route_template: str,
        fixture_bindings: Mapping[str, str],
    ) -> CompileResult:
```

`plan_differential_pairs` is the per-route allowlist of brief §1.2. It takes the **raw**
route list of the chosen inventory. For a `--routes` file that is the list as parsed from
the file, **before** the store or any other code has validated or filtered it. `mapping`
is the setup store's `plan_entitlement_read` mapping or `None`. It MUST:

- raise `ValueError` if any entry's method is not in
  `CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"]`, so a `POST` (or any other)
  inventory entry is a compile error for the whole command;
- raise `ValueError` if the argument is not a list of closed `{method, route_template,
  operation_id, placeholders}` records, if `normalize_route_template` rejects or changes a
  template, if placeholders disagree, if a `(method, route_template)` repeats, or if there
  are more than 2000 entries;
- return planned and not-executed routes per §3.4 in canonical order
  `(route_template, method, operation_id)`. It never adds, rewrites or derives a route.

`compile_plan_differential_pair` compiles one pair in the attempt store. It MUST:

- raise unless `method` is in the catalog's allowed methods for `plan_entitlement_read`;
- raise unless `(method, NFC route_template)` is exactly in `self.store.list_routes()`.
  This is an independent membership check against the persisted inventory of the store
  the compiler is bound to, not against the caller's list;
- call `self.store.save_mapping("plan_entitlement_read", …)` (which re-checks membership,
  `heel/runner/store.py:6924-6930`), then `self.compile(["plan_entitlement_read"])`;
- raise unless the result has **exactly two actions**, both with that method and
  template, roles `lower_plan` then `higher_plan`.

### 6.3 `heel/runner/store.py` — read-only inventory access

Add two read-only public methods to `RunnerStore`. No existing method changes behavior.

- `route_inventory(artifact: Mapping[str, Any] | None = None) -> dict` returns
  `{"source_digest", "routes"}`. With `None` it reads `routes.json` and raises if there is
  none. With a parsed artifact it applies the same `_validate_envelope` (schema,
  namespace, origin, verification-record digest of the bound context) and the same route
  and canonical-order checks used for the stored file. The body of the existing
  `_routes_locked` is factored into one private validator so both paths share it;
  `list_routes()` returns what it returned before (F32).
- `route_inventory_path() -> Path` returns the `routes.json` path of the bound context.

Neither method writes. A supplied artifact never replaces the stored inventory.

### 6.4 `heel/runner/http_transport.py` — trust loading

`TLSTransport.__init__` additionally calls `self.context.load_default_certs()`. Protocol,
`CERT_REQUIRED` and `check_hostname` are unchanged, so the pinned test (F12) still holds.
Without this the production client cannot complete any handshake (F11). Nothing else in
the file changes, and no constructor gains a parameter. Only this feature constructs the
class in product code (F33). The trust boundary this creates is stated in §7.2.

### 6.5 `heel/cli.py`

- `runner run` subparser, handler `_runner_run(args)`, one dispatch line. Rejections print
  `_SAFE_RUNNER_COMMAND_FAILURE`. No new constant.
- `_runner_credential_add` prints the object of §3.2 using the record returned by the
  store. No other command's behavior or output changes.
- `_runner_run` passes the parsed `--routes` object through untouched; it contains no
  route or method logic.

### 6.6 `heel/regressions.py`

The replay branch of §10 in `run_regressions`.

### 6.7 Why every wire request is a compiled, allowlisted action

1. Planning calls `plan_differential_pairs` on the raw route list (§7.1 step 2). A
   non-`GET`/`HEAD` entry stops the command there.
2. Each planned pair is compiled by `compile_plan_differential_pair`, which re-checks the
   method and the attempt store's own inventory and returns exactly two actions.
3. `_ScopedTransport` (§7) is constructed for that one compiled pair and refuses any
   action whose scenario is not `plan_entitlement_read`, whose method is not `GET` or
   `HEAD`, whose role is not `lower_plan` or `higher_plan`, or whose `(method,
   route_template)` is not that pair, with `TransportFailure("gate_rejected")` before any
   budget, log or socket activity.
4. `_ScopedTransport.request` is the only call site of `TargetHTTPSClient.request` in the
   new module, and `LocalCanaryExecutor.execute` is only ever given a `_ScopedTransport`.
5. Behind these, the unmodified `prepare_action` and the transport's `_valid_route`
   remain as independent checks (F25), and the transport refuses a non-anonymous role
   without a credential.

Tests prove each numbered sentence (I2).

## 7. New module `heel/runner/plan_differential.py`

Public functions (everything else underscore-private):

| Function | Purpose |
|---|---|
| `plan_differential(scope_id, base_url, plans, *, caller, routes_artifact=None, max_ops=50) -> dict` | Verify scope, normalize origin, decide mode, bind the setup store when allowed, build the plan. No network. |
| `run_plan_differential(scope_id, base_url, plans, *, caller, routes_artifact=None, max_ops=50, attempt=None) -> dict` | Execute. Returns the executed object of §3.6. |
| `replay_plan_differential(store, regression, *, scope_id, target, caller) -> dict` | One-pair replay for `heel regress run` (§10). |
| `evaluate_plan_pair(lower, higher, *, method, marker, executor_outcome) -> PairVerdict` | Pure function implementing §8. No I/O. |
| `key_paths(value) -> frozenset[str]` | Pure, bounded (§8.2). Each element is the injective rendering of one structural path (§8.7.1, post-escalation D5). |
| `material_paths(value) -> frozenset[str]` | Pure, bounded, same walk, bounds and rendering as `key_paths` (§8.2, §8.6, §8.7). Post-escalation D4; rendering corrected by D5. |
| `is_denial_envelope(value) -> bool` | Pure (§8.3). |

`plans` is `[(label, handle), (label, handle)]`, lower first. `routes_artifact` is the
parsed JSON of `--routes` or `None`. `caller` MUST be a non-empty string beginning `cli:`;
anything else raises before any state is touched. `attempt` is **not reachable from the
CLI**: the CLI always passes `None`, meaning `secrets.token_hex(16)`.

Private pieces:

| Name | Purpose |
|---|---|
| `_authorize(scope_id, host)` | `get_scope` + `verify` + exact allowlist equality. Re-reads the scope file from disk on every call. Used at entry and inside the gate. |
| `_prepare(...)` | Builds the plan for both public entry points: steps 1–3 of §7.1. Calls `plan_differential_pairs` and `RunnerStore.route_inventory` (§6.2, §6.3). No network. |
| `_Budget` | The invocation-wide op counter of §9. |
| `_build_client(origin) -> TargetHTTPSClient` | The only client constructor. One bounded `BoundedResolver()` preflight, then `TargetHTTPSClient(origin=origin, preflight_addresses=answers)` with **no** `resolver`, `sockets` or `tls` argument, so the defaults `BoundedResolver`, `SocketTransport` and `TLSTransport` (with §6.4 trust loading) are used. It takes no other parameter and reads no Heel environment variable, file or config. |
| `_AttemptReservation` | Result of the exclusive `os.mkdir`. Holds attempt ID and root. Constructed only by `_reserve_attempt`. |
| `_PlanVault` | `supported=True`, `backend_id="ephemeral_env"`. Maps each of the two attempt-store handles to its setup-store record. Loads each real secret **once per invocation** from its real vault (`EphemeralVault` or `select_vault(backend)`), keeps it in memory only, registers it with the redacting store and the tolerant redactor, and clears it at exit. Refuses (`VaultUnavailable`) a bearer or API-key value, or any cookie value, shorter than 8 bytes, because it cannot be redacted reliably. |
| `_RedactingRunnerStore(RunnerStore)` | Overrides only `store_response_evidence`: before delegating, replaces every registered secret, in every spelling of §7.5, in `raw_headers` and `raw_body` with `b"[REDACTED:secret]"`. Needed because the executor stores raw bytes (F14). |
| `_TolerantRedactor(Redactor)` | §7.4. |
| `_ScopedTransport` | Wraps the client for **one compiled pair**. Requires an `_AttemptReservation` whose directory exists, else raises `TransportFailure("gate_rejected")`. Refuses any action that is not that pair (§6.7 item 3). Replaces the `redactor` argument with the `_TolerantRedactor` (§7.4). Wraps the executor's `before_attempt` as in §9. |
| `_gate(scope_id, host)` | `gate_source` for the executor. Calls `_authorize` each time; inactive if the scope no longer verifies or no longer lists the host. |
| `_grant(...)` | As `reference_rehearsal._grant`, with `approval_actor {"user_id": "local_operator", "role": "owner"}` and a reason naming the scope ID. Ephemeral `SigningAuthority`, trusted only in this process. |
| `_finding(...)` | Builds one `AbuseVector` (§11). |

### 7.1 Execute sequence

1. `caller` check. `_authorize`. Normalize origin. Host not in allowlist → forced dry-run
   result, stop. Setup context MUST be bound to this origin, else reject.
2. Resolve both handles (§3.2). Take the raw route list: for a `--routes` artifact,
   `artifact["inventory"]["routes"]` exactly as parsed; otherwise
   `setup.route_inventory()["routes"]`. Call `plan_differential_pairs(raw, mapping=…)`
   **first**, then `setup.route_inventory(artifact)` for the envelope and
   `source_digest`. Either failing → reject. Zero planned pairs → reject.
3. Budget (§9). Planned pairs beyond `effective_max_ops // 2` become `not_executed`
   (`over_budget`).
4. **Reserve the attempt**: `os.mkdir(HEEL_HOME/plan-runs/<attempt>, 0o700)`, exclusive. An
   existing directory is a replay and is rejected. Nothing above this line touches the
   network; nothing below runs without it.
5. Open `Store(HEEL_HOME/heel.db)`; `add_run("pdrun-<attempt>", scope_id, origin, caller,
   "running", …)`; containment `run_start`.
6. Build the attempt store (`_RedactingRunnerStore`), ephemeral signer and identity, bind
   the same context values as the setup store, `replace_routes(<whole inventory>,
   source_digest=…)`. Register exactly two ephemeral credential records, `lower_plan` and
   `higher_plan`, served by `_PlanVault`. No other credential record exists in an attempt
   store.
7. `_build_client(origin)` once: one DNS preflight pins the address set for the invocation.
8. For each planned pair in order: skip as `not_executed` (`budget_exhausted`) if fewer
   than 2 ops remain; else `compile_plan_differential_pair` → `_grant`
   (`run_id="crun_<attempt>_<nn>"`, 30 s expiry) → `LocalCanaryExecutor.execute(bundle,
   transport=_ScopedTransport, gate_source=_gate, cancellation=token)`. The executor
   reserves the grant and sends lower then higher: two requests, the same for `GET` and
   `HEAD`.
9. After each pair: read both evidence records from the attempt store, matched by
   `action_ordinal` as `reference_rehearsal.py:160-167` does; run `evaluate_plan_pair`;
   append a `plan_differential_pair` containment entry carrying the verdict, reason and
   the executor's true `execution_disposition`. Then, **only when the executor disposition
   is `completed` and the verdict is not `held`** (§8.5 rows 2, 3,
   5, 6, 8, 9), `add_finding` plus a `finding` containment entry. A pair that did not
   complete (row 1) stays in the result and `report.json` as `inconclusive` with its true
   disposition and reason, and creates **no** `AbuseVector`.
10. Continue to the next pair only when the pair completed or failed with executor
    `error_category == "containment_rejected"` (a response-level refusal). On any other
    failure or a stop, mark the pair `inconclusive` and all later pairs `not_executed`
    (`run_stopped`).
11. `set_run_status("complete")`, containment `run_complete`, `verify_chain`, write
    `report.json` (`O_EXCL|O_NOFOLLOW`, 0600), return.

Any exception after step 4 MUST leave the run row with a terminal status (`complete` or
`rejected`) and a `run_complete` or `run_failed` containment entry, and MUST NOT leave
credential bytes anywhere under `HEEL_HOME`.

### 7.2 Network decisions and the real trust boundary

| Topic | Decision |
|---|---|
| Scheme | HTTPS only. No HTTP, loopback, private-address or custom-port capability exists in product code and no switch enables one. |
| TLS | Certificate required, hostname checked, SNI = normalized host. TLS 1.2 only (inherited, F12). A TLS failure ends the invocation (`transport:tls_error`). |
| Trust anchors | `load_default_certs()` in `TLSTransport.__init__` (§6.4): the default trust locations of the Python build's TLS library. **`SSL_CERT_FILE` and `SSL_CERT_DIR` in the process environment change those locations (F29).** Heel adds no option, `HEEL_*` variable, config key or scope field for trust. |
| DNS | One bounded preflight per invocation; every answer must be public; the set is pinned. Each attempt re-resolves and requires set equality, connects to the pinned numeric address and re-checks the peer (F10). A change ends the invocation (`dns_changed`). A replay re-preflights and never reuses stored addresses. |
| Host header | Always the normalized hostname, built by the transport (F9). |
| Redirects | Never followed, on or off the allowlist (F9). The pair is `inconclusive` (`transport:response_rejected`). |
| Encodings | `Accept-Encoding: identity`. Chunked or content-encoded responses are refused (F13). |

**Trust boundary, stated plainly.** The operator's process environment and `HEEL_HOME`
are inside the trust boundary: the environment already supplies the credentials
(`HEEL_RUNNER_CREDENTIAL_<HANDLE>`), the data directory and the user name. Someone who
controls that environment can also choose the CA set through `SSL_CERT_FILE` or
`SSL_CERT_DIR`. Heel does not defend against that and the docs MUST say so. What Heel
guarantees is narrower and is tested: no Heel argument, Heel variable, inventory file or
scope field changes the transport, resolver, port or trust store, and certificate and
hostname verification are always on.

### 7.3 Test seams versus the unmodified public CLI

There is exactly one seam: tests replace the module attribute
`heel.runner.plan_differential._build_client`. It is not a parameter of any public
function and no argv, environment variable, file or scope field can set it.

| What | How it is tested | What it proves and does not prove |
|---|---|---|
| Argument rules, rejection, forced dry-run, bootstrap, plan, `credential add` output | `heel.cli.main(argv)` with **no** seam, with `socket.socket` and `socket.getaddrinfo` patched to fail | The unmodified public CLI, and that these paths open no socket. |
| Execution, findings, containment, regression replay | `heel.cli.main(argv)` with `_build_client` replaced by a factory returning a real `TargetHTTPSClient` whose injected `resolver` returns a fixed public address, whose `sockets` connects to the loopback synthetic target and reports the pinned address from `getpeername`, and whose `tls` is a pass-through | Request construction, `Host`, framing, 3xx refusal, body rules, compiler checks, gate, budget, reservation, evidence, redaction, predicates and logging are product code. **It proves nothing about TLS, DNS answers or address selection.** |
| Production client construction | `_build_client` unreplaced, with only `socket.getaddrinfo` patched to return a public address | The production path builds `BoundedResolver`, `SocketTransport` and the default `TLSTransport` with certificate verification, hostname checking and default trust loading, and passes no seam object. No handshake is performed. |
| Trust environment | `_build_client` unreplaced, `SSL_CERT_FILE` set to a CA generated in the test | That the stated boundary of §7.2 is accurate (R23). |
| Real TLS verification | A real `TLSTransport` wraps a real socket to a loopback `ssl` server whose certificate is issued by a test CA generated in the test. The test adds that CA to `transport.context` | The real class performs a real handshake, accepts a matching chain and hostname, and rejects a wrong hostname and an untrusted issuer. It does not prove the contents of the system trust store or a public PKI handshake. |

No CI test performs a real public HTTPS request through the full client. No test in this
feature may be described as proving real TLS behavior unless it is the real-handshake test
above.

### 7.4 Numeric and large JSON bodies: the redaction-count seam

The failure (F27) is in a **count**, not in redaction of stored data. The inherited
`Redactor.count_bytes` parses a JSON body with rules meant for outbound projections and
raises on ordinary values; the transport turns that into `evidence_rejected`, which the
executor classifies as a runner fault, which §7.1 step 10 treats as the end of the run.

Seam (F28, proven in F30): the executor hands its `Redactor` to `transport.request()`.
`_ScopedTransport` replaces that argument with a `_TolerantRedactor`, a subclass of
`Redactor` constructed with the invocation's registered secret strings.

`_TolerantRedactor.count_bytes(*chunks)`:

1. Return `super().count_bytes(*chunks)` when it succeeds. Behavior is unchanged for every
   body the inherited redactor accepts.
2. If it raises `TypeError` or `ValueError`, re-check the inherited argument rules itself
   (at least one chunk, every chunk `bytes`, every chunk ≤ 256 KiB) and re-raise if they
   fail. Otherwise return `min(1024, n)` where `n` is the number of occurrences of the
   registered secrets (every spelling of §7.5) in the chunks.
3. It overrides nothing else and reads no private attribute of the base class.

Why this is safe:

- What is stored is decided by `_RedactingRunnerStore`, which removes every registered
  credential from headers and body before the bytes reach disk, for every body shape. The
  count plays no part in that (F27, F30c).
- The count only feeds `redaction_count` in local results and the signed `redacted` event.
  In the fallback it counts exactly what was replaced on disk.
- No bound is lifted: the 256 KiB body limit, the one-JSON-object rule and the header
  limits are the transport's and are unchanged.

Bodies containing floats, negative integers, large integers, more than 256 members, more
than 1024 nodes or depth above 16 therefore complete normally and are judged by §8. The
predicate parser of §8.1 is the module's own and accepts all finite JSON numbers.

If the store itself refuses evidence, the pair is still `transport:evidence_rejected` and
the run stops (step 10): that is a local storage fault, not a response property.

### 7.5 Secret spellings that are redacted (synced 2026-10-05 to the accepted D2 remediation)

As implemented in T4 loop 1 (`93521ed`, `_secret_pattern`) and confirmed by report §9.4 and
§10.4. For each registered secret, one bytes pattern is built in which every character
matches, independently of its neighbours, any of: its raw UTF-8 bytes; its `\uXXXX` escape
with hex digits in either case (two escapes, a surrogate pair, for a code point above
U+FFFF); its JSON short escape when one exists (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`,
`\t`). Mixed escapings of one secret therefore match. Secrets are applied longest first so
a secret that contains another is replaced whole. No body is parsed and the pattern has no
repetition, so matching is bounded. The same patterns serve `_RedactingRunnerStore` (what
reaches disk, headers and body) and `_TolerantRedactor` (the count).

Known limits, unchanged and stated in report §9.4: a secret that reaches the body double
encoded, split across strings, or in base64, hex or percent form is not matched. I5
covers raw and single-decoded views.

## 8. Predicates

### 8.1 Inputs

For lower (`L`) and higher (`H`): `status`, `body` (the stored, redacted bytes), `json`
(parsed with duplicate-key rejection and `NaN`/`Infinity` rejection; `None` if empty or
unparseable). Plus `method`, `marker` (the supplied `heel-canary-` value or `None`) and
the executor's `execution_disposition` and `assessment_outcome`.

`2xx` = 200–299. `denial status` = 401, 402, 403, 404.
`P(x) = protected_content(x.body, marker=marker, status=x.status, method=method)`.

### 8.2 `key_paths`

Computed on the parsed, redacted body. For an object, each key `k` at path `p` adds
`p.k`; recursion continues into the value unless `redaction._secret_key(k)` is true. For
an array at path `p`, add `p[]` and recurse into every element, unioning results. Scalars
add nothing. Bounds: depth ≤ 16, visited nodes ≤ 4096; exceeding either makes
`body_superset` undetermined.

`material_paths` (post-escalation D4, §8.6) is the subset of those paths at which the value
is JSON-truthy: for an object member `k` with value `v` at path `p`, `p.k` is material iff
`truthy(v)` and `k` is not a secret-named key; for an array at `p`, `p[]` is material iff at
least one element is truthy. `truthy(v)` is exactly Python `bool(v)` on the parsed value:
`null`, `false`, `0`, `0.0`, `-0.0`, `""`, `[]` and `{}` are not truthy; every other string
(including `"0"`, `"false"`, `"null"` and `" "`), number, `true`, nonempty array and
nonempty object is. String content is never read and no value is compared with another.
Same walk, same secret-key stop, same bounds and same `BodyTooComplex` as `key_paths`.
`_evaluate` MUST still obtain the shape sets through `key_paths` (the fault-injection case
of `test_r11_predicates_fail_closed` patches that name).

Rendering (post-escalation D5, §8.7). `p.k` above means `p + "." + esc(k)`, where `esc`
prefixes each of the four characters `\`, `.`, `[`, `]` inside the key with `\` and leaves
every other code point unchanged; `p[]` is unchanged. Before D5 the key was inserted
verbatim, so distinct structural paths could render as one string (D9). For a key that
contains none of the four characters, `esc` is the identity and every string in this
section, in §8.6 and in the existing tests is unchanged.

### 8.3 Denial envelope

Synced 2026-10-05 to the accepted T4 loop-2 recognizer (`a1c2acd`, `is_denial_envelope`;
the closure of report §9.3). A parsed top-level object is a denial envelope when any member
satisfies one of the following, its key compared after case-folding and removing `_` and
`-`:

1. key in {`error`, `errors`, `errorcode`} and the value is JSON-truthy;
2. key in {`ok`, `success`, `allowed`} and the value is JSON-falsy, or a string that after
   strip and casefold is empty or one of `false`, `0`, `no`;
3. key in {`upgraderequired`, `paymentrequired`, `denied`, `forbidden`} and the value is
   JSON-truthy and not a string that after strip and casefold is one of `false`, `0`, `no`;
4. key in {`status`, `statuscode`, `code`} and the value is an `int` or `float` with an
   integral value in 400–599, or a string in which a denial word (`error`, `fail`,
   `failed`, `failure`, `denied`, `forbidden`, `unauthorized`, `required`) or a three-digit
   group beginning `4` or `5` is found after splitting on non-alphanumerics or on
   camel-case and letter/digit boundaries;
5. key in {`data`, `result`, `response`} and the value is an object that satisfies 1–5,
   followed through at most two wrapper levels.

Arrays are never inspected. The vocabulary is closed and is not extended again: it is not
by itself the rule of brief §1.5, and report §10.3 lists what it does not read. The
structural rule that closes the remainder is D4 (§8.6). An envelope only ever
**withholds** parity, for either plan; it never creates a finding, never creates a `held`
verdict and never creates a regression pass.

### 8.4 Three-valued predicates

Each is `True`, `False` or `None` (undetermined).

`completed` := the pair's run has executor disposition `completed` and both evidence
records load and verify.

`positive_control` := `completed` ∧ `H.status` is 2xx ∧ `H.json` is not a denial envelope
∧ (`marker` supplied ⇒ `H.status == 200` ∧ `P(H)` is `True`).

| Predicate | `None` when | `True` when | `False` when |
|---|---|---|---|
| `status_parity` | no `positive_control`; or `L.status` is neither 2xx nor a denial status; or `L.status` is 2xx and `L.json` is a denial envelope; or `L.status` is 2xx and `L` is a hollow shape of `H` (§8.6) | `L.status` is 2xx, `L.json` is not a denial envelope and `L` is not a hollow shape of `H` | `L.status` is a denial status |
| `body_superset` | no `positive_control`; or `method` is `HEAD`; or `H.json` is not an object; or `key_paths(H)` is empty; or a bound is exceeded; or `L.json` is a denial envelope; or `L` is a hollow shape of `H` (§8.6) | `L.status` is 2xx, `L.json` is an object, not a denial envelope, `key_paths(L) ⊇ key_paths(H)` and `material_paths(L) ⊇ material_paths(H)` | otherwise (lower denied by status, lower empty or not an object, or lower lacks a higher key path) |
| `marker_leak` | no marker; or `method` is `HEAD`; or no `positive_control`; or `P(L)` is `None`; or the executor's `assessment_outcome` disagrees | `P(L)` is `True` and executor outcome is `observed` | `P(L)` is `False` and executor outcome is `blocked` |

A 2xx denial envelope, and likewise a 2xx hollow shape (§8.6), therefore makes
`status_parity` and `body_superset` undetermined, never true and never false. The two are
decided in that order: an envelope is reported as `lower_denial_envelope` whether or not it
is also hollow.

### 8.5 Verdict table — first matching row wins

| # | Condition | Verdict | `evidence_state` | Predicate / reason |
|---|---|---|---|---|
| 1 | not `completed` | inconclusive, **no finding stored** | — (report only) | `inconclusive` / one of the closed list below |
| 2 | no `positive_control` | inconclusive | `inconclusive` | `inconclusive` / `no_positive_control` or `positive_control_missing_marker` |
| 3 | `marker_leak` is `True` | finding | `verified` | `marker_leak` |
| 4 | `marker_leak` is `False` | held | — | `marker_absent` |
| 5 | marker supplied (and `marker_leak` is `None`) | inconclusive | `inconclusive` | `inconclusive` / `marker_undetermined` |
| 6 | `body_superset` is `True` | finding | `observed` | `body_superset` |
| 7 | `status_parity` is `False` | held | — | `lower_denied` |
| 8 | `status_parity` is `True` | inconclusive, `candidate: true` | `inconclusive` | `status_parity` / `head_status_only`, `status_only` (no comparable bodies) or `lower_subset` |
| 9 | otherwise | inconclusive | `inconclusive` | `inconclusive` / `lower_denial_envelope`, `lower_hollow_shape`, `unexpected_status` or `body_too_complex` |

Row-1 reasons (closed): `transport:<code>` where `<code>` is the transport failure code
recorded by the runner's signed log; `stopped`; `budget_exhausted`;
`credential_unavailable`; `executor:<error_category>` for any other executor error
category; `executor_rejected` when `execute` raised before producing a result;
`evidence_unavailable` when a completed run's evidence cannot be loaded or verified.
`not_executed` reasons (closed): `unbound_placeholder`, `over_budget`,
`budget_exhausted`, `run_stopped`.

Fail-closed requirements (tested, R11):

- Status parity alone never yields `observed`, `verified` or `held`.
- A 2xx denial envelope never yields `observed` or, without a marker, `held`, and is never
  a candidate. With a marker, rows 3–5 precede: an envelope body that still discloses the
  supplied marker is row 3, `verified` (corrected 2026-10-05; pinned by
  `test_error_envelope_never_counts_as_parity`).
- A 2xx hollow shape (§8.6) never yields `observed`, is never a candidate and, without a
  marker, is never `held` (post-escalation D4).
- A key-path bound exceeded leaves `body_superset` `None`; with a 2xx lower body that is
  neither an envelope nor hollow the pair lands on row 8 `status_only` (as implemented and
  tested; the row-9 reason `body_too_complex` is kept for completeness and is not reached
  from a 2xx lower body). Unchanged by D4.
- A HEAD pair can only be `held` (row 7) or `inconclusive`.
- `verified` is reachable only through row 3; `observed` only through row 6.
- An exception inside evaluation yields `inconclusive` (`predicate_error`), never a pass.
- `candidate` is `true` on row 8 (`status_parity`) and `false` on every other row.
- Row 1 never stores a finding; rows 4 and 7 (`held`) never store a finding.
- Heel never derives the tier, the marker or the expected result from a response.

Empty and non-JSON bodies: an empty 2xx body has `json = None`, so `body_superset` is
`None` (higher) or `False` (lower) and the pair lands on row 7, 8 or 9. A non-empty body
that is not one JSON object is refused by the transport (F13) and is row 1
(`transport:response_rejected`), as is a body over 256 KiB (`transport:response_too_large`).

Honest scope of `observed`: row 6 says the lower plan received every field the higher plan
received on that one read. Heel holds no declaration that the route is plan-gated, so a
route that is ungated by design will also be reported. The finding text MUST say this.
`held` (row 7) says only that the lower plan was refused by status on this one read while
the higher plan succeeded.

### 8.6 D4: material superset (post-escalation correction, 2026-10-05)

**Invariant (encode this).** With a positive control, a `GET` pair and comparable object
bodies, `observed` requires both

    key_paths(L) ⊇ key_paths(H)          (shape, unchanged)
    material_paths(L) ⊇ material_paths(H)   (material, new)

and a lower 2xx object body for which the shape test passes and the material test fails is
a **hollow shape**: it withholds `status_parity` and `body_superset` (both `None`), lands
on row 9 with reason `lower_hollow_shape`, stores an `inconclusive` finding, and is not a
candidate. Everything else in §8.4–§8.5 is unchanged.

Definitions, on the parsed and redacted bodies of §8.1 (`L` lower, `H` higher):

- `truthy(v)` and `material_paths(B)`: §8.2.
- `shape(L, H)` := `key_paths(L) ⊇ key_paths(H)`.
- `material(L, H)` := `material_paths(L) ⊇ material_paths(H)`.
- `hollow(L, H)` := `L.status` is 2xx ∧ `L.json` is an object ∧ `L.json` is not a denial
  envelope ∧ `shape(L, H)` ∧ ¬`material(L, H)`.
- Computed only when `positive_control` ∧ `method ≠ HEAD` ∧ `H.json` is an object ∧
  `key_paths(H)` is nonempty ∧ no bound is exceeded by either body. Otherwise `hollow` is
  false and the pre-D4 rules apply unchanged.

Deterministic evaluation order inside `_evaluate`: parse; `lower_denial`; positive control;
shape and material sets (`key_paths` then `material_paths`, each body; `BodyTooComplex`
from any of the four walks ⇒ `body_superset = None`, `hollow = False`); then
`body_superset` := `None` if hollow, else `2xx(L) ∧ object(L) ∧ shape(L, H)`; then
`status_parity` := `None` if `lower_denial` or `hollow`, else as §8.4; then `marker_leak`;
then rows 1–9 in order. Row-9 reason precedence: `lower_denial_envelope`, then
`lower_hollow_shape`, then `unexpected_status`, then `body_too_complex`.

Properties the tests pin:

- Reflexive: `L.json == H.json` is `observed` exactly as before, so the 53 affirmative
  controls of report §10.3 and the 11 committed guards are unchanged.
- Value-blind: replacing any truthy value in `L` by any other truthy value of any JSON
  type changes nothing. Heel never compares a URL, ID, name, count or tenant value for
  equality. Only the truthy/non-truthy class of a value at a path is read.
- Monotone: adding a truthy value or a key to `L` never turns `observed` into anything
  else; removing one never turns a non-finding into `observed`.
- Not required: a path that is `null`, `false`, `0`, `""`, `[]` or `{}` in `H` is not in
  `material_paths(H)`, so `L` may hold anything there. A higher body with no truthy value at
  all has an empty material set and behaves as before.
- Missing versus hollow: a higher key path absent from `L` is the pre-D4 `lower_subset`
  (row 8, candidate); present with a non-truthy value it is hollow (row 9, not a
  candidate). The distinction is the point of D4: an omitted field is a narrower response,
  an echoed-but-empty field is the signature of a schema-shaped denial.

**Truth table T1: leaf materiality** (`material_paths` of `{"k": v}` contains `$.k`?)

| `v` | material | `v` | material |
|---|---|---|---|
| absent | no (no path at all) | `"x"`, `"0"`, `"false"`, `"null"`, `" "` | yes |
| `null` | no | `1`, `-1`, `0.5`, `2**60`, `1e-9` | yes |
| `false` | no | `true` | yes |
| `0`, `0.0`, `-0.0`, `0e0` | no | `[0]`, `[null]`, `[""]`, `{"a": null}` (the container path) | yes |
| `""` | no | `["a"]`, `{"a": 1}` | yes |
| `[]`, `{}` | no | value under a secret-named key, any `v` | no (path kept, never material, not descended) |

For `{"k": [e1, e2, …]}`: `$.k[]` is material iff some `ei` is truthy; `$.k[].m` is material
iff some element object has a truthy `m`. `NaN`, `Infinity` and duplicate keys never reach
this table (§8.1 parse rejects them: `json = None`).

**Truth table T2: pair rows.** All with `status 200` both sides, `GET`, no marker, positive
control present. `H` = `{"ok": true, "success": true, "status": "ok", "export_url":
"https://files/x.csv", "rows": 3}` unless stated. Columns: verdict row, reason,
`status_parity`, `body_superset`, candidate.

| Case id | `L` (relative to `H`) | Row | Reason | `sp` | `bs` | cand. |
|---|---|---|---|---|---|---|
| `missing_key` | `rows` absent | 8 | `lower_subset` | T | F | yes |
| `null_key` | `rows: null` | 9 | `lower_hollow_shape` | — | — | no |
| `empty_string` | `export_url: ""` | 9 | `lower_hollow_shape` | — | — | no |
| `empty_list_for_scalar` | `rows: []` | 9 | `lower_hollow_shape` | — | — | no |
| `empty_object_for_scalar` | `rows: {}` | 9 | `lower_hollow_shape` | — | — | no |
| `false_for_true` | `H` has `verified: true`; `L` same but `verified: false` | 9 | `lower_hollow_shape` | — | — | no |
| `zero_for_three` | `rows: 0` | 9 | `lower_hollow_shape` | — | — | no |
| `zero_float` | `rows: 0.0` | 9 | `lower_hollow_shape` | — | — | no |
| `different_string` | `export_url: "https://files/other.csv"` | 6 | `lower_superset` | T | T | no |
| `different_number` | `rows: 7` | 6 | `lower_superset` | T | T | no |
| `negative_number` | `rows: -1` | 6 | `lower_superset` | T | T | no |
| `string_for_number` | `rows: "seven"` | 6 | `lower_superset` | T | T | no |
| `number_for_string` | `export_url: 42` | 6 | `lower_superset` | T | T | no |
| `true_for_string` | `export_url: true` | 6 | `lower_superset` | T | T | no |
| `whitespace_string` | `export_url: " "` | 6 | `lower_superset` | T | T | no |
| `string_zero` | `rows: "0"` | 6 | `lower_superset` | T | T | no |
| `list_for_scalar` | `rows: [1]` | 6 | `lower_superset` | T | T | no |
| `object_for_scalar` | `rows: {"n": 1}` | 6 | `lower_superset` | T | T | no |
| `nested_same_shape_other_values` | `H` `{"a": {"b": "x", "c": 1}}`, `L` `{"a": {"b": "y", "c": 2}}` | 6 | `lower_superset` | T | T | no |
| `nested_null_leaf` | same `H`, `L` `{"a": {"b": null, "c": 2}}` | 9 | `lower_hollow_shape` | — | — | no |
| `nested_empty_object` | `H` `{"a": {"b": "x"}}`, `L` `{"a": {}}` | 8 | `lower_subset` | T | F | yes |
| `list_rows_other_values` | `H` `{"rows": [{"id": "r1", "amount": 1}]}`, `L` `{"rows": [{"id": "z", "amount": 9}]}` | 6 | `lower_superset` | T | T | no |
| `list_rows_null_stuffed` | same `H`, `L` `{"rows": [{"id": null, "amount": null}]}` | 9 | `lower_hollow_shape` | — | — | no |
| `list_rows_one_material_element` | same `H`, `L` `{"rows": [{"id": null, "amount": null}, {"id": "z", "amount": 2}]}` | 6 | `lower_superset` | T | T | no |
| `list_empty_for_populated` | `H` `{"rows": [{"id": "r1"}]}`, `L` `{"rows": []}` | 8 | `lower_subset` | T | F | yes |
| `list_of_nulls_for_scalars` | `H` `{"tags": ["a", "b"]}`, `L` `{"tags": [null]}` | 9 | `lower_hollow_shape` | — | — | no |
| `list_fewer_elements` | same `H`, `L` `{"tags": ["z"]}` | 6 | `lower_superset` | T | T | no |
| `higher_null_lower_null` | `H` = `L` = `{"a": 1, "b": null}` | 6 | `lower_superset` | T | T | no |
| `higher_null_lower_material` | `H` `{"a": 1, "b": null}`, `L` `{"a": 2, "b": "x"}` | 6 | `lower_superset` | T | T | no |
| `higher_empty_list_lower_empty_list` | `H` = `L` = `{"a": 1, "b": []}` | 6 | `lower_superset` | T | T | no |
| `higher_empty_list_lower_null` | `H` `{"a": 1, "b": []}`, `L` `{"a": 1, "b": null}` | 8 | `lower_subset` | T | F | yes |
| `higher_false_lower_false` | `H` = `L` = `{"a": 1, "f": false}` | 6 | `lower_superset` | T | T | no |
| `higher_false_lower_true` | `H` `{"a": 1, "f": false}`, `L` `{"a": 1, "f": true}` | 6 | `lower_superset` | T | T | no |
| `higher_all_hollow` | `H` = `L` = `{"a": null, "b": ""}` | 6 | `lower_superset` | T | T | no |
| `mixed_one_hollow` | `export_url: "https://files/y.csv"`, `rows: null` | 9 | `lower_hollow_shape` | — | — | no |
| `mixed_extra_keys_hollow` | `rows: null`, plus `extra: "more"` | 9 | `lower_hollow_shape` | — | — | no |
| `extra_hollow_keys_only` | `H` plus `extra: null` | 6 | `lower_superset` | T | T | no |
| `final_status_false` | `export_url: null`, `rows: null`, `status: false`, `message: "Upgrade required"` | 9 | `lower_hollow_shape` | — | — | no |
| `final_message_only` | `export_url: null`, `rows: null`, `message: "Upgrade required"` | 9 | `lower_hollow_shape` | — | — | no |
| `final_PAYMENTREQUIRED` | `export_url: null`, `rows: null`, `code: "PAYMENTREQUIRED"` | 9 | `lower_hollow_shape` | — | — | no |
| `final_accessdenied` | `export_url: null`, `rows: null`, `status: "accessdenied"` | 9 | `lower_hollow_shape` | — | — | no |
| `denial_and_hollow` | `export_url: null`, `rows: null`, `ok: false` | 9 | `lower_denial_envelope` | — | — | no |

The four `final_*` rows are the bodies of
`test_redteam_break_d1_final_unrecognized_denial_body_yields_observed`; the three `ok`,
`success`, `status: "ok"` members are truthy in both bodies and are not what decides them.

**Truth table T3: ordering, bounds, HEAD, marker, replay.** `Hn` = `H` with `rows: null`
(a hollow echo of `H`).

| Case id | Pair | Result |
|---|---|---|
| `hollow_higher_denial_is_row_2` | `L` = `Hn`, `H` = `H` with `ok: false` | row 2 `no_positive_control`; hollow is not computed |
| `hollow_lower_denial_status_is_held` | `L` = 403 `Hn`, `H` | row 7 `held` `lower_denied` (status decides; hollow needs a 2xx lower) |
| `hollow_lower_500_is_unexpected` | `L` = 500 `Hn`, `H` | row 9 `unexpected_status` |
| `hollow_lower_201_204_299` | `L` = 201/204/299 `Hn`, `H` | row 9 `lower_hollow_shape` at each 2xx status |
| `head_unaffected` | `L` = `Hn`, `H`, `method = HEAD` | row 8 `head_status_only`, `sp` T, `bs` None, candidate; a HEAD pair never reads bodies |
| `marker_present_in_hollow_body` | marker `M`; `H` `{"protected_canary": M, "rows": [{"id": "r1"}], "n": 1}`; `L` same with `rows: [{"id": null}]`, `n: null`; executor `observed` | row 3 `verified`: marker verification precedes D4 |
| `marker_undetermined_in_hollow_body` | same, executor `inconclusive` | row 5 `marker_undetermined`; never row 6 or 9 |
| `marker_absent_hollow_body` | same `H`; `L` `{"protected_canary": "", "rows": [{"id": null}], "n": null}`, executor `blocked` | row 4 `held` when `P(L)` is `False`, else row 5; never row 6 |
| `bounds_wide_or_deep_body` | 4097 keys, or depth 18, either side | `BodyTooComplex` from both `key_paths` and `material_paths`; `bs` None, hollow false, pair on row 8 `status_only` as before D4 |
| `secret_key_never_material` | `H` `{"a": 1, "token": "abc"}`, `L` `{"a": 1, "token": null}` | row 6: a secret-named key's value is never required |
| `hollow_lower_replay` | saved `body_superset` regression; replay lower = 2xx `Hn` | §10 row 3: `fail` / `inconclusive` (verdict row 9 is neither `p` true nor `held`) |
| `hollow_lower_in_fresh_run` | CLI run, lower answers 2xx `Hn` | stored `inconclusive` finding, `candidate: false`, exit code as for any inconclusive-only run; two requests on the route, lower then higher |
| `reflexive_guards` | the 11 bodies of `test_redteam_holds_affirmative_bodies_keep_the_positive_control`, same body both sides | row 6 `observed`, unchanged |

**Test map.** Opus adds the following to `tests/test_runner_plan_differential_predicates.py`
(additive only; see §14.6). Each T2 and T3 case id above MUST be the parametrize id of a
case in the named test, so a reviewer can find every row by name.

| Named test | Rows it proves |
|---|---|
| `test_d4_truthy_leaf_table` | every T1 row, through `material_paths` directly |
| `test_d4_material_paths_are_structural_and_bounded` | T1 array and secret-key rows; same output notation as `key_paths`; `BodyTooComplex` on the §8.2 bounds; `material_paths(x) ⊆ key_paths(x)` for every body of this file |
| `test_d4_verdict_truth_table` | every T2 row and the T3 rows `hollow_higher_denial_is_row_2`, `hollow_lower_denial_status_is_held`, `hollow_lower_500_is_unexpected`, `hollow_lower_201_204_299`, `head_unaffected`, `secret_key_never_material`; asserts row, reason, `status_parity`, `body_superset`, `candidate`, `evidence_state`, `stores_finding` |
| `test_d4_same_shape_different_values_stay_observed` | the mission guard: the T2 rows with row 6 whose `L` differs from `H` in value or type (`different_*`, `string_for_number`, `number_for_string`, `true_for_string`, `whitespace_string`, `string_zero`, `list_for_scalar`, `object_for_scalar`, `nested_same_shape_other_values`, `list_rows_other_values`, `list_fewer_elements`, `higher_null_lower_material`, `higher_false_lower_true`), plus a body whose every leaf is replaced by a different account-specific URL, ID, name and tenant value; every one `finding` / `observed` / row 6 |
| `test_d4_hollow_shape_is_never_observed_candidate_or_held` | a grid over lower status {200, 201, 204, 299}, marker {none, `M`}, executor outcome {`observed`, `blocked`, `inconclusive`}, method {GET, HEAD} and the five hollow bodies `null_key`, `empty_string`, `zero_for_three`, `list_rows_null_stuffed`, `final_message_only`: `evidence_state` is never `observed`, `candidate` is true only for HEAD (row 8), `held` only on row 4; the marker rows `marker_present_in_hollow_body`, `marker_undetermined_in_hollow_body`, `marker_absent_hollow_body` |
| `test_d4_bounds_leave_body_superset_undetermined` | `bounds_wide_or_deep_body` |
| `test_d4_reflexive_bodies_unchanged` | `reflexive_guards`, plus `FULL`, `SUBSET`, `protected()` and `{"rows": []}` of this file, same body both sides, each row 6 |

`hollow_lower_replay` and `hollow_lower_in_fresh_run` are proven at unit level by
`test_d4_verdict_truth_table` (row 9, `body_superset` `None`, verdict not `held`) together
with the unchanged §10 mapping that `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay`
already exercises end to end for row 9. The end-to-end hollow replay and fresh-run probes
are reserved for the fresh Fable red team after Opus (§14.6), which may add them to
`tests/test_runner_plan_differential_redteam.py`.

Tests Opus MUST preserve unedited, all green on the final commit: the four
`test_redteam_break_d1_final_unrecognized_denial_body_yields_observed` cases and the other
57 cases of `tests/test_runner_plan_differential_redteam.py` (the D1 and rerun breaks,
the 11 affirmative guards, D2, redirects, scope tamper, DNS rebinding, header injection);
`test_r11_verdict_table_rows`, `test_r11_predicates_fail_closed`,
`test_error_envelope_never_counts_as_parity`,
`test_key_paths_are_structural_and_skip_secret_named_subtrees`; the I1–I8, R9–R27 tests of
§12 including `test_r17_*` (exactly two requests per route) and `test_r24_*`.

Accepted losses, stated so T5 and operators are not surprised: a genuine lower response
that echoes the higher shape but is `false`, `0`, `null` or empty at any path where the
higher body is truthy (a pagination flag that differs, a count of zero, an optional field
left null for that account) is `inconclusive` / `lower_hollow_shape`, not `observed`. It
fails closed. The residual false-positive surface is a denial body that puts a truthy
value at every path the higher body populates (for example an upgrade URL in `export_url`
and `1` in `rows`); Phase 1 cannot separate that from entitled data without comparing
values, which the brief forbids, and it is recorded in §16.

### 8.7 D5: structural path identity (post-escalation correction, 2026-10-06)

**Invariant (encode this).** For every parsed body `B`, `key_paths(B)` and
`material_paths(B)` are in one-to-one correspondence with the *structural* paths of `B`
(sequences of object keys and array-element tokens). Consequently, for comparable bodies,

    key_paths(L) ⊇ key_paths(H)        ⟺  every structural path of H is a structural path of L
    material_paths(L) ⊇ material_paths(H) ⟺  every structurally material path of H is structurally material in L

and a lower body that is hollow at a structural path the higher body populates is a hollow
shape (§8.6) whatever other keys it carries. Nothing in §8.4–§8.6 changes; only the identity
of a path does.

#### 8.7.1 Path type, segment grammar, equality, rendering, bounds, secret-key stop

- **Structural path.** A finite sequence of segments. A segment is `Key(k)` for an object
  member whose key is the string `k` (any JSON string, the empty string included) or `Index`
  for an array element. The root is the empty sequence and is never itself a path in either
  set; the walk adds the child paths of the root.
- **Type.** `str`, returned inside `frozenset[str]`. The annotation and the public signature
  of both functions are unchanged. A path string is an **identity token**: product code
  MUST NOT parse, split, join, prefix-match or hand-build one. The only producers are the
  two walks; the only consumers are set algebra in `_evaluate` and `len` in
  `_observation_view`.
- **Rendering `R`.** `R(ε) = "$"`; `R(s · Key(k)) = R(s) + "." + esc(k)`;
  `R(s · Index) = R(s) + "[]"`. `esc(k)` maps each code point `c` of `k` to `"\\" + c` when
  `c ∈ {"\\", ".", "[", "]"}` and to `c` otherwise. Implementation: one module constant
  `_PATH_ESCAPES = str.maketrans({"\\": "\\\\", ".": "\\.", "[": "\\[", "]": "\\]"})` and
  one helper `_path_segment(key: str) -> str` returning `key.translate(_PATH_ESCAPES)`. No
  other character is escaped: `$`, `/`, `~`, quotes, whitespace, control characters, `NUL`,
  non-ASCII and lone surrogates pass through unchanged.
- **Equality.** Python `str` equality on `R`. By §8.7.2 this is exactly structural equality
  of segment sequences.
- **Determinism.** `R` is a pure function of the segment sequence. It reads no locale,
  environment, hash seed or normalization table. Two keys are the same key iff they are the
  same sequence of code points, as in JSON (RFC 8259 §4) and in a Python `dict`; NFC and NFD
  spellings of one glyph are distinct keys, and `"é"` and `"é"` in JSON text are the
  same key because the parser already unified them.
- **Bounds.** Unchanged: `MAX_KEY_PATH_DEPTH = 16`, `MAX_KEY_PATH_NODES = 4096`, counted on
  visited nodes, raising `BodyTooComplex` from either walk. Alias-spelled keys are ordinary
  members and count as nodes. The rendered length is at most `1 + Σ (1 + 2·len(k))` over the
  segments and is not bounded separately; the transport's 256 KiB body cap (F13) bounds it.
- **Secret-key stop.** Unchanged: `redaction._secret_key(k)` is evaluated on the **raw** key
  `k`, before escaping. A secret-named key's path is added by `key_paths`, never by
  `material_paths`, and is not descended. Note that `_secret_key` splits on non-alphanumerics,
  so a literal key `a.token` or `token.a` is itself secret-named (never material, not
  descended); that is pre-existing behaviour, unchanged by D5 and harmless to the rule (a
  path that is never material cannot satisfy a material requirement). The hash-seed defect of
  report §11.5 is unchanged and outside this correction.

#### 8.7.2 Injectivity of `R` (proof)

Claim: `R(s₁) = R(s₂)` implies `s₁ = s₂` for all segment sequences `s₁`, `s₂`.

Proof: exhibit a decoder `D` with `D(R(s)) = s`. `D` reads the string left to right by code
point after the leading `$`:

1. If the next code point is `[`, the following one is `]` (see below) and the segment is
   `Index`; advance two.
2. Otherwise the next code point is `.` (see below); advance one and read a key: repeat
   while there is a code point and it is neither `.` nor `[`: if it is `\`, take the
   following code point literally and advance two; otherwise take it and advance one. The
   collected code points are `k`; the segment is `Key(k)`.
3. Stop at the end of the string.

`D` is well defined and inverts `R` because of three properties of `esc`:

- (E1) `esc(k)` contains no unescaped `.`, `[` or `]`: every occurrence of those three
  characters in `k` is emitted with a `\` in front, and `esc` never emits a bare one.
- (E2) every `\` in `esc(k)` is the first of an escaped pair `\c` with
  `c ∈ {\, ., [, ]}`: a `\` in `k` is emitted as `\\`, and no other `\` is emitted. So the
  decoder's "take the following code point literally" step always consumes exactly the
  escaped pair and never runs past the key.
- (E3) `esc` is injective and its inverse is "drop the `\` of each escaped pair", which is
  what step 2 computes.

Hence after `$`, the string is a concatenation of blocks that each begin with `[` (exactly
`[]`, the only source of a bare `[`, by E1) or with `.` followed by `esc(k)` for one key,
and the first code point of each block decides which case applies. Step 2 stops exactly at
the first bare `.` or `[` after the key, which by E1 is the start of the next block, or at
the end. So `D` recovers the segment sequence, `D ∘ R = id`, and `R` is injective. ∎

Coverage of the cases the brief names:

| Key content | Treatment | Why it cannot collide |
|---|---|---|
| separator `.` | escaped `\.` | E1: the only bare `.` starts a key block |
| brackets `[`, `]` | escaped `\[`, `\]` | E1: the only bare `[` is the `[]` token |
| backslash `\` | escaped `\\` | E2: pairs are consumed as pairs; `\\.` is `\` then separator, `\\\.` is `\` then `.` |
| `$` | literal | only position 0 is the root; inside a key it is always preceded by `.` or by other key text |
| `/`, `~` | literal | not metacharacters of this grammar; `a/b` and nested `a`→`b` differ in the presence of a bare `.` |
| empty string | `.` followed by `.`, `[` or end | step 2 reads zero code points; `{"": {"": 1}}` is `$..`, `{".": 1}` is `$.\.` |
| Unicode, control, `NUL`, surrogates | literal | the decoder is per code point and only four ASCII code points are special |
| key equal to a whole path spelling (`$.a.b`, `a[]`, `[]`) | escaped per character | E1 |

**Lemma (D4 preservation).** If no key of a body contains `\`, `.`, `[` or `]`, then `esc`
is the identity on every key and `R` equals the pre-D5 rendering, so `key_paths`,
`material_paths`, their cardinalities and every §8.4–§8.6 result for that body are
unchanged byte for byte. Every body in §8.6 T1–T3, the 11 affirmative guards, `FULL`,
`SUBSET`, `ENVELOPE`, `protected()` and the synthetic target of §13 is such a body.
CONFIRMED by the design session with the renderer patched in memory (no file changed):
`tests/test_runner_plan_differential_predicates.py` + `_redteam.py` **183 passed, 0 failed**
(the D9 test green); `_cli.py` + `_safety.py` + `_release.py` **35 passed**.

#### 8.7.3 Rejected alternative: typed tuple paths

Representation: `tuple[str | _ArraySegment, ...]` with a frozen, field-less dataclass
singleton as the array token, so `("a", "b") != ("a.b",)` by construction and no rendering
exists. The design session implemented it in memory as well (not committed) and confirmed
that it also turns the D9 test green and gives the identical T4 table. It is rejected for
this cycle because, for the same fail-closed outcome, it

- changes the return type of two exported functions shipped in the open-core wheel and adds
  a public sentinel type to the module;
- breaks **28** preserved test cases in three D4-pinned tests, purely on notation
  (`test_d4_truthy_leaf_table` ×26, `test_d4_material_paths_are_structural_and_bounded`,
  `test_key_paths_are_structural_and_skip_secret_named_subtrees`; CONFIRMED), so the fresh
  red team would have to re-verify 28 rewritten expectations instead of reading an unchanged
  file;
- buys injectivity "by construction" where §8.7.2 already gives it by a one-paragraph proof
  that the fixed-seed corpus test checks mechanically against an independent tuple walk.

A hybrid (tuples inside, rendered strings outside) carries the same proof obligation as the
chosen option with strictly more code, and no caller needs a string. Should a later phase
need to print or persist a path, the tuple form MAY be introduced then, with a renderer
equal to `R`; that is out of Phase 1.

#### 8.7.4 Exact changes (Opus)

`heel/runner/plan_differential.py`, and nothing else in product code:

1. Immediately above `def key_paths`, add the constant `_PATH_ESCAPES` and the helper
   `_path_segment` of §8.7.1 (a two-line function with a one-line docstring is enough).
2. In `key_paths`, replace `child_path = f"{path}.{key}"` with
   `child_path = f"{path}.{_path_segment(key)}"`.
3. In `material_paths`, make the same one-token replacement.
4. The docstrings of the two functions MAY gain one sentence naming the rendering.

Everything else in the file is byte-unchanged: `_evaluate` (its set algebra is over opaque
strings and needs no edit; the fault-injection seams of `test_r11_predicates_fail_closed`
and `test_d4_bounds_leave_body_superset_undetermined` still patch the module names),
`_observation_view`, `__all__` (no new export; `_path_segment` is private), every
constant, class, reason string, row and import. No new import: `str.maketrans` and
`str.translate` are builtins. `_secret_key(key)` keeps receiving the raw key.

Callers, reports and persisted data:

- `_evaluate`: unchanged code; behaviour changes only for bodies whose keys contain one of
  the four metacharacters (T4), always in the fail-closed direction or toward the correct
  `lower_subset`.
- `_observation_view` → `reproduction.observations[].key_path_count`: unchanged code, still
  an integer count of distinct paths. It now counts structural paths, so for an alias body
  it may be larger than before (`{"a": {"b": 1}, "a.b": 1}`: 3, previously 2); for any body
  without metacharacters it is identical. It is informational; nothing reads it back.
- No path string is persisted or printed anywhere: not in findings (§11: "No key-path
  names … appear in a finding"), `report.json`, regressions, containment entries, stdout or
  stderr (CONFIRMED: the only derived field is `key_path_count`; grep over `heel/`, `docs/`
  and `tests/` finds no other consumer of either function outside the predicates test).
- Replay (§10): unchanged code. A regression saved from an alias body (report §11.4) now
  replays `fail` / `inconclusive` (`lower_hollow_shape`) instead of `fail` /
  `still_reachable`; never `pass` on a 2xx lower.
- Every D4 predicate row, case id and precedence is preserved; path identity required no
  correction to any rule.

#### 8.7.5 Compatibility

- `key_paths` and `material_paths` are in `__all__` and shipped in the open-core wheel
  (R26), so they are importable by third parties. No importer exists in this repository
  outside the module itself and `tests/test_runner_plan_differential_predicates.py`, and no
  operator document describes them (CONFIRMED by grep). They are **internal helpers with a
  stable signature**: name, parameters, return type `frozenset[str]`, bounds and exception
  are unchanged.
- What changes for an external importer: only the rendered string of a key containing `\`,
  `.`, `[` or `]`, and the set cardinality for a body with such keys. Any code that parsed
  the old strings as JSONPath was already wrong (D9) and is not supported.
- Stored run, finding and regression formats: **no change**. Existing `HEEL_HOME` stores,
  findings and `regress` entries load and replay unchanged; only re-evaluated verdicts on
  alias bodies move, in the fail-closed direction.
- The three release artifacts regenerate because `plan_differential.py` changes (R26, R27,
  §14.5). No other package content changes.

#### 8.7.6 Truth tables

**T4: alias rows.** `GET`, no marker, status 200 both sides unless stated, positive control
present. Columns: verdict row, reason, `status_parity`, `body_superset`, candidate, and the
result at `d479ff9` before D5 where it differs. `OBS` = row 6 `lower_superset` T T no
(`observed`); `SUB` = row 8 `lower_subset` T F yes; `HOL` = row 9 `lower_hollow_shape`
— — no. Every row CONFIRMED by the design session against the in-memory renderer and at
`d479ff9`.

| Case id | `L` | `H` | D5 | Before D5 |
|---|---|---|---|---|
| `dot_alias_hollow_nested` (D9) | `{"a": {"b": null}, "a.b": 1}` | `{"a": {"b": 1}}` | HOL | OBS |
| `dot_alias_wrapped_hollow` | `{"data": {"url": null, "n": null}, "data.url": "https://files/x.csv", "data.n": 2, "ok": true}` | `{"data": {"url": "https://files/x.csv", "n": 2}, "ok": true}` | HOL | OBS |
| `dot_literal_lower_vs_nested_higher` | `{"a.b": 1}` | `{"a": {"b": 1}}` | SUB | SUB |
| `nested_lower_vs_dot_literal_higher` | `{"a": {"b": 1}}` | `{"a.b": 1}` | SUB | OBS |
| `dot_alias_in_higher_only` (reverse) | `{"a": {"b": 1}}` | `{"a": {"b": null}, "a.b": 1}` | SUB | OBS |
| `dot_literal_both_sides_truthy` | `{"a.b": 2}` | `{"a.b": 1}` | OBS | OBS |
| `dot_literal_both_sides_hollow` | `{"a.b": null}` | `{"a.b": 1}` | HOL | HOL |
| `nested_both_sides_truthy` | `{"a": {"b": "x"}}` | `{"a": {"b": 1}}` | OBS | OBS |
| `nested_both_sides_hollow` | `{"a": {"b": 0}}` | `{"a": {"b": 1}}` | HOL | HOL |
| `nested_and_literal_both_truthy_both_sides` | `{"a": {"b": "p"}, "a.b": "q"}` | `{"a": {"b": "x"}, "a.b": "y"}` | OBS | OBS |
| `nested_and_literal_literal_hollow` | `{"a": {"b": 1}, "a.b": null}` | `{"a": {"b": 1}, "a.b": 2}` | HOL | OBS |
| `lower_carries_literal_and_nested` | `{"a": {"b": 1}, "a.b": 1}` | `{"a.b": 1}` | OBS | OBS |
| `array_token_alias_hollow_list` | `{"x": [0], "x[]": 1}` | `{"x": [1]}` | HOL | OBS |
| `array_token_literal_vs_list` | `{"x[]": 1}` | `{"x": [1]}` | SUB | SUB |
| `array_element_object_alias` | `{"a": [{"b": null}], "a[]": {"b": 1}}` | `{"a": [{"b": 1}]}` | HOL | OBS |
| `array_vs_literal_both_truthy` | `{"x": [2], "x[]": 2}` | `{"x": [1], "x[]": 1}` | OBS | OBS |
| `dollar_literal_key_hollow` | `{"$": 1, "a": null}` | `{"$": 1, "a": 1}` | HOL | HOL |
| `dollar_key_nested_alias` | `{"a": {"$": null}, "a.$": 1}` | `{"a": {"$": 1}}` | HOL | OBS |
| `dollar_dot_a_literal_vs_a` | `{"$.a": 1}` | `{"a": 1}` | SUB | SUB |
| `dollar_literal_both_sides` | `{"$": "y"}` | `{"$": "x"}` | OBS | OBS |
| `empty_key_nested_alias` | `{"": {"a": null}, ".a": 1}` | `{"": {"a": 1}}` | HOL | OBS |
| `empty_key_double_alias` | `{"": {"": null}, ".": 1}` | `{"": {"": 1}}` | HOL | OBS |
| `empty_key_both_sides` | `{"": 2}` | `{"": 1}` | OBS | OBS |
| `empty_key_hollow` | `{"": ""}` | `{"": 1}` | HOL | HOL |
| `dot_key_vs_empty_nested` | `{".": 1}` | `{"": {"": 1}}` | SUB | SUB |
| `slash_tilde_keys_truthy` | `{"a/b": 2, "a~b": "y", "~1": 1}` | `{"a/b": 1, "a~b": "x", "~1": 1}` | OBS | OBS |
| `slash_tilde_keys_hollow` | `{"a/b": null, "a~b": "y"}` | `{"a/b": 1, "a~b": "x"}` | HOL | HOL |
| `slash_literal_vs_nested` | `{"a/b": 1}` | `{"a": {"b": 1}}` | SUB | SUB |
| `pointer_escape_vs_slash` | `{"a~1b": 1}` | `{"a/b": 1}` | SUB | SUB |
| `backslash_key_vs_nested` | `{"a\\": {"b": 1}}` | `{"a\\.b": 1}` | SUB | OBS |
| `backslash_dot_alias` | `{"a\\": {"b": null}, "a\\.b": 1}` | `{"a\\": {"b": 1}}` | HOL | OBS |
| `unicode_nested_alias` | `{"ключ": {"数": null}, "ключ.数": 1}` | `{"ключ": {"数": 1}}` | HOL | OBS |
| `unicode_same_key_both_sides` | `{"ключ": {"数": "y"}}` | `{"ключ": {"数": "x"}}` | OBS | OBS |
| `unicode_nfc_vs_nfd_distinct` | `{"é": 1}` (decomposed) | `{"é": 1}` | SUB | SUB |
| `unicode_escaped_spelling_same_key` | JSON text `{"é": 2}` | `{"é": 1}` | OBS | OBS |
| `secret_subtree_alias_never_material` | `{"token": {"a": null}, "token.a": 1}` | `{"token": {"a": 1}}` | OBS | OBS |
| `secret_sibling_hollow` | `{"token": {"a": 1}, "rows": null}` | `{"token": {"a": 1}, "rows": 3}` | HOL | HOL |
| `secret_literal_vs_secret_nested` | `{"token.a": 1, "rows": 3}` | `{"token": {"a": 1}, "rows": 3}` | SUB | SUB |
| `same_shape_different_truthy_values_with_literal_keys` | `{"a": {"b": "p"}, "a.b": "q", "x[]": [0, 1]}` | `{"a": {"b": 1}, "a.b": 2, "x[]": [3]}` | OBS | OBS |
| `reflexive_alias_body` | `{"a": {"b": null}, "a.b": 1}` | same | OBS | OBS |

Bounds rows (CONFIRMED): `bounds_wide_alias` — `H` with 4097 plain keys, `L` the same keys
all `null` plus one alias key → `BodyTooComplex` from both walks, row 8 `status_only`, `bs`
None, candidate, as §8.6 `bounds_wide_or_deep_body`; `bounds_deep` unchanged. Thirteen T4
rows change from `d479ff9`; every change is OBS → HOL (a structurally hollow lower body) or
OBS → SUB (a structurally non-superset lower body). No row moves toward `observed`.

**T5: rendering** (`key_paths` of the body; CONFIRMED).

| Body | `key_paths` |
|---|---|
| `{"a": {"b": 1}}` | `$.a`, `$.a.b` |
| `{"a.b": 1}` | `$.a\.b` |
| `{"a": {"b": 1}, "a.b": 1}` | `$.a`, `$.a.b`, `$.a\.b` (3 paths) |
| `{"x": [1]}` | `$.x`, `$.x[]` |
| `{"x[]": 1}` | `$.x\[\]` |
| `{"[]": 1}` | `$.\[\]` |
| `{"$": 1}` | `$.$` |
| `{"": 1}` | `$.` |
| `{"": {"": 1}}` | `$.`, `$..` |
| `{".": 1}` | `$.\.` |
| `{"\\": 1}` | `$.\\` |
| `{"q\\": {"r": 1}}` | `$.q\\`, `$.q\\.r` |
| `{"q\\.r": 1}` | `$.q\\\.r` |
| `{"a/b": 1, "a~1b": 1, "é": 1}` | `$.a/b`, `$.a~1b`, `$.é` |

#### 8.7.7 Named tests

Opus adds the following. Each T4 case id MUST be the parametrize id of a case so a reviewer
can find every row by name. Only existing dependencies: `json`, `random`, `pytest`, the
module under test and the existing support helpers.

In `tests/test_runner_plan_differential_predicates.py` (additive only):

| Named test | Proves |
|---|---|
| `test_d5_path_segments_render_injectively` | every T5 row by exact set equality; `_path_segment` on each T5 key; `len(key_paths({"a": {"b": 1}, "a.b": 1})) == 3`; both functions still return `frozenset` of `str`; `__all__` unchanged (no `_path_segment`) |
| `test_d5_alias_truth_table` | every T4 row (40 ids) through `evaluate_plan_pair`: `(row, reason, status_parity, body_superset, candidate, evidence_state, stores_finding)`; the HOL rows additionally at lower status 201, 204 and 299 |
| `test_d5_bounds_count_alias_keys_as_nodes` | `bounds_wide_alias`: `BodyTooComplex` from both walks and row 8 `status_only` |
| `test_d5_structural_identity_fixed_seed_corpus` | parametrized over seeds `20261006`, `1`, `2`; `random.Random(seed)`; 1 500 random bodies per seed, depth ≤ 4, width ≤ 4, lists, scalars from `{null, 0, 1, "", "x", true, false, 2.5, "0"}`, keys drawn from the alphabet `a`, `b`, `a.b`, `.`, `..`, `[]`, `a[]`, `$`, `$.a`, `""`, `\`, `a\.b`, `\.`, `/`, `~`, `~1`, `é`, `e+U+0301`, `数`, `token`, `ok`, `x]`, `[`, `]`. The test defines an **independent** recursive reference walk returning tuples (with a private object as the array token, honouring `_secret_key`) and the decoder `D` of §8.7.2, and asserts for every body: (a) `{D(p) for p in key_paths(B)}` equals the reference structural path set; (b) `len(key_paths(B))` equals its size (injective on `B`); (c) the same two for `material_paths` against the reference material walk; (d) **two-direction check**: for `L` built by setting one random material leaf of `H` to `null` and adding truthy alias-spelled keys, `evaluate_plan_pair(L, H).body_superset` is `None` exactly when the reference says `L` is a hollow shape of `H`, `True` exactly when the reference shape superset holds and it is not hollow, and `False` otherwise (pairs on row 2 or `lower_denial_envelope` are skipped); and (e) the count of structurally hollow pairs judged `observed` is 0. CONFIRMED by the design prototype: passes under the D5 renderer on all three seeds and **fails at `d479ff9` on all three seeds**, so it detects D9. |

In `tests/test_runner_plan_differential_cli.py` (additive only; no edit to
`tests/plan_differential_support.py` or the harness):

| Named test | Proves |
|---|---|
| `test_d5_alias_lower_body_is_hollow_in_fresh_run_and_regression_replay` | with `World`: vulnerable run → `GET /api/export` `observed`, `add_regression`; then `monkeypatch.setattr(world.target, "respond", …)` with a wrapper that answers the **free** session on `/api/export` with `{**EXPORT, "rows": [{"id": null, "amount_cents": null}], "rows[].id": "row_1", "rows[].amount_cents": 1200}` and delegates everything else to the original `respond` (the listener looks `respond` up on the instance per request); fresh run → pair `inconclusive` / `inconclusive` / `lower_hollow_shape`, `candidate` false, `execution_disposition` `completed`, stored finding `evidence_state: inconclusive`; `regress run` → `fail` / `inconclusive`, the replay's stored reproduction reason `lower_hollow_shape`; wrapper disabled → `fail` / `still_reachable`. CONFIRMED by the design prototype under the D5 renderer; at `d479ff9` the same test fails with the pair `finding` / `lower_superset` (the D9 end-to-end reproduction of report §11.4). |

The committed D9 regression `test_redteam_break_d9_path_alias_turns_hollow_lower_body_into_observed`
MUST turn green from change 1 of §8.7.4 alone and MUST NOT be edited, weakened, skipped,
xfailed or deleted.

Tests Opus MUST preserve unedited, all green on the final commit: every existing test of
the five plan-differential files, in particular the three notation-pinned tests
`test_key_paths_are_structural_and_skip_secret_named_subtrees`, `test_d4_truthy_leaf_table`
and `test_d4_material_paths_are_structural_and_bounded` (their `$.k` expectations are
unchanged by the lemma of §8.7.2), the seven `test_d4_*` tests, `test_r11_*`,
`test_error_envelope_never_counts_as_parity`, the 62 cases of the red-team file, and the
I1–I8, R9–R27 tests of §12.

#### 8.7.8 Red-team acceptance attacks and stop conditions

The fresh Fable red team after Opus MUST at least:

1. Run every T4 row end to end through the unmodified CLI, transport, executor, store,
   `heel findings --run`, `regress add` and `regress run`, by the `respond` wrapper of
   §8.7.7 or a scratch `World`; record pair verdict, stored `evidence_state`, replay result.
2. Fuzz with a seed other than the three committed ones and a wider alphabet: control
   characters, `NUL`, lone surrogates (`"\ud800"` in JSON text), keys of 1 000+ code
   points, runs of metacharacters (`\\\\`, `..`, `[[]]`, `.[`, `\.`, `\[]`), keys equal to
   whole rendered paths (`$`, `$.a.b`, `$.x[]`), keys that are secret-named only because of
   a separator (`a.token`, `token.a`), aliases on both sides, aliases in the higher body
   only, aliases at depth 15 and 16, and 4 096-node bodies composed of alias keys. Classify
   each pair with an independent tuple walk and compare both directions, as the corpus test
   does.
3. Re-run the §11.4 journey of the report (the D9 pair, the wrapped alias, hollow at
   201/204/299, hardened 403) and the I1–I8 and original adversarial sets.
4. Check `key_paths` output for every body of the five test files is byte-identical to
   `d479ff9` (the lemma of §8.7.2), and that `git diff d479ff9..HEAD -- heel/` adds no
   import, regex, word list, key set, classifier, annotation or network call.

Stop conditions, each a **FAIL** for D5:

- any alias, spelling or encoding under which a lower body that is structurally hollow at a
  path the higher body populates, or structurally not a shape superset, is `observed`, a
  candidate, or `held` without a marker;
- any regression replay returning `pass` on a 2xx lower body;
- any preserved test edited, skipped, xfailed or deleted, or the D9 test not green from the
  product change alone;
- any change outside the §14.7 allowlist; any new import or vocabulary in product code;
- any rendered path for a metacharacter-free body that differs from `d479ff9`;
- any change to egress, scope verification, method set, reservation, budget, redaction,
  containment or chain behaviour (the I1–I8 tests and R9, R12, R13, R17 must be unchanged
  and green).

Recorded limits that are **not** D5 failures: the value-blind boundary of §16 (a truthy
denial-shaped value at every higher-material path is still `observed`); the hash-seed
`_secret_key` defect of report §11.5; `key_path_count` growing for alias bodies.

## 9. Requests, budget, reservation, logging

- **Unit**: one op is one request attempt on the wire, including a retry. Every op carries
  one of the two plan credentials.
- `effective_max_ops = min(--max-ops, scope.rate_and_resource_limits["max_requests"])` when
  the scope defines an integer `max_requests`, else `--max-ops`. If the result is < 2, or
  `Store.scope_run_count(scope_id) >= max_requests` (the rule `heel_run` already applies),
  reject.
- Every pair, `GET` or `HEAD`, needs exactly 2 ops before retries.
- **Per-attempt order**, inside the wrapped `before_attempt`, before any socket:
  1. `_authorize` again; failure raises `gate_rejected`.
  2. take one unit from the invocation-wide counter, or raise `gate_rejected` with
     `gate_error="budget_exhausted"`;
  3. call the executor's own `before_attempt` (grant authority, per-manifest budget,
     retry rules, signed `action_started` event);
  4. append one HMAC containment entry `plan_differential_request` with `method`,
     `route_template`, plan `label`, `role` (`lower_plan` or `higher_plan`), `attempt`,
     `runner_run_id`, `op_index`. If the append fails the attempt is refused.
  Only then does the transport resolve and connect. So total wire requests never exceed
  `effective_max_ops`, and no request exists without an earlier entry. An entry MAY exist
  for an attempt that then failed in DNS or connect.
- The per-manifest `BUDGETS` and `RETRY_POLICY` (one retry, `connect_error`/`timeout`)
  apply unchanged inside each run. Concurrency is one.
- `--max-ops ≤ 100` keeps one attempt at ≤ 50 reserved runs (one run per pair), below the
  store's 64-run tracking bound
  (`heel/runner/store.py:190`).
- **Attempt ID**: generated by Heel, reserved by exclusive `mkdir`, never reusable. Each
  run additionally consumes its own one-shot grant through `RunnerStore.reserve_run`
  (F14). A crashed or cancelled attempt stays consumed.
- **Scope reuse**: one scope serves many invocations until it expires or its run count is
  exhausted. Heel never extends, re-signs or rewrites it.

## 10. Regression replay

`heel regress add --run <pdrun-…> --vector <pdv-…> --name N` works unchanged: the vector
has a `scenario_id`, and `add_regression_from_finding` falls back to
`_affordance_pattern_from_vector` and `{"observed": reproduction["observed"]}`
(`heel/regressions.py:64-78`).

`heel regress run --target <origin> --scope <scope-id>`: one branch at the top of the loop
in `run_regressions`.

- A regression whose `scenario_id` starts with `plan_differential.` is handled by
  `replay_plan_differential` and never reaches `server.heel_run`.
- When `--target` starts with `https://`, regressions of other kinds are skipped. When it
  does not, plan-differential regressions are skipped.

`replay_plan_differential` loads the original vector with `store.find_vector(
original_vector_id, run_id=source_run_id)` and reuses, exactly as saved:

| Saved value | Replay rule |
|---|---|
| `base_origin` | `target` MUST equal it |
| `scope_id` | `--scope` MUST equal it, and the scope MUST still verify and list the host |
| `plans` (labels, roles, handles, in order) | the same two handles MUST still be `active` with the same roles; same order |
| `predicate` | the same predicate is re-evaluated |
| `method`, `route_template` | MUST still be in the current default inventory; planned and compiled through §6.2 |
| `fixture_bindings_sha256`, `marker_supplied` | the current mapping's binding digest MUST equal it |

Any mismatch produces result `fail` with `current_status: "inconclusive"` and **no
request**. Otherwise the full execute sequence of §7.1 runs for that one pair with a new
attempt ID and `max_ops=4` (two requests and at most one retry of each). The saved predicate `p` is re-evaluated on the new responses
and the result is decided by the first matching row:

| # | Fresh evaluation | `result` | `current_status` |
|---|---|---|---|
| 1 | `p` is `True` | `fail` | `still_reachable` |
| 2 | verdict is `held` (§8.5 row 4 or 7): the positive control succeeded and the lower plan was denied by status, or the marker was absent | `pass` | `blocked` |
| 3 | anything else | `fail` | `inconclusive` |

So a pass needs an affirmative denial. In particular:

- **A 2xx denial envelope is `fail` / `inconclusive`.** With an envelope, `body_superset`
  and `status_parity` are undetermined (§8.4), the verdict is `inconclusive`
  (`lower_denial_envelope`), and row 3 applies. `body_superset` becoming not-true is never
  a pass by itself.
- **A 2xx hollow shape (§8.6) is `fail` / `inconclusive`** for the same reason
  (`lower_hollow_shape`, verdict row 9, not `held`). Post-escalation D4; the replay code is
  unchanged.
- A lower response that is 2xx with fewer fields (`lower_subset`) is `fail` /
  `inconclusive`: the lower plan still received content.
- A replay pair that does not complete is `fail` / `inconclusive` and stores no finding.
- For a saved predicate of `inconclusive` there is no `p`; rows 2 and 3 decide.

`result` is only ever `pass` or `fail`. The result record keeps the existing fields
(`matches_expected = current_status == expected_status`) plus `result`, and is stored with
`add_regression_result` and a `regression_result` containment entry.

## 11. Finding schema

**Eligibility.** One `AbuseVector` is stored with `Store.add_finding` for a pair if and
only if the pair's run has executor `execution_disposition` exactly `completed` and the
verdict is not `held`. Pairs that did not complete (`incomplete`, `failed`,
`stopped`, or never started) and `held` pairs create no `AbuseVector`; they are recorded
in the result `pairs`, in `report.json` and in the containment log only. Every stored
finding therefore has `reproduction.execution_disposition == "completed"` (brief §1.6).

| Field | Value |
|---|---|
| `id` | `"pdv-" + sha256(f"{run_id}:{method}:{route_template}")[:12]` |
| `scenario_id` | `"plan_differential." + predicate` (`body_superset`, `marker_leak`, `status_parity`, `inconclusive`) |
| `category` | `Category.LICENSE_ENTITLEMENT` |
| `target_id` | normalized origin |
| `affordance_id` | `method + " " + route_template` |
| `severity` | `verified`: 0.9 × 0.7, uncertainty 0.1. `observed`: 0.6 × 0.6, uncertainty 0.3. `inconclusive`: 0.2 × 0.4, uncertainty 0.5. Fixed priors, not measured. |
| `reachability_score` / `plausible` | 1.0 / `True` for `verified` and `observed`; 0.3 / `False` for `inconclusive` |
| `recommended_control` | "Enforce the plan entitlement check server-side on this read before the response is serialized." |
| `verification_status` | `PREDICTED` |
| `notes` | For `observed`: the honest-scope sentence of §8.5 |

`reproduction` (closed; no other keys):

```json
{"contained": true, "sample": "canary_only",
 "evidence_state": "observed|verified|inconclusive",
 "execution_disposition": "completed",
 "predicate": "body_superset|marker_leak|status_parity|inconclusive",
 "reason": "<reason code>", "candidate": false,
 "hypothesis": "endpoint_without_plan_gate|export_without_entitlement",
 "operator_declared": false,
 "observations": [
   {"label": "free", "role": "lower_plan", "status_code": 200, "body_shape": "json_object",
    "key_path_count": 7, "response_bytes": 412,
    "request_ref": {"method": "GET", "route_template": "/api/export",
                    "host": "staging.example.com", "credential": "[REDACTED:secret]"},
    "response_ref": "ev1_<64 hex>"},
   {"label": "pro", "role": "higher_plan", "...": "..."}],
 "observed": {"predicate": "...", "method": "GET", "route_template": "...",
              "base_origin": "https://staging.example.com", "scope_id": "...",
              "plans": [{"label": "free", "role": "lower_plan", "credential_handle": "<32 hex>"},
                        {"label": "pro", "role": "higher_plan", "credential_handle": "<32 hex>"}],
              "marker_supplied": false, "fixture_bindings_sha256": "<64 hex>",
              "inventory_source_digest": "<64 hex>",
              "lower_status": 200, "higher_status": 200},
 "attempt_id": "...", "runner_run_ids": ["crun_<attempt>_<nn>"], "plan_sha256": "<64 hex>",
 "provenance": {"kind": "plan_differential_execution", "network_calls": true,
                "target_verification": "signed_local_scope_only"}}
```

- `execution_disposition` is always the literal `completed`, and it is always true: it is
  copied from the executor result, and a pair with any other disposition is never stored
  as a finding. The implementation MUST NOT write `completed` for a pair that did not
  complete; it writes no finding instead.
- `candidate` is a JSON boolean: `true` if and only if `predicate == "status_parity"`
  (§8.5 row 8); `false` for `body_superset`, `marker_leak` and `inconclusive`.
- `inconclusive` findings exist only for completed pairs (rows 2, 5, 9 and
  `predicate_error`).
- `observations[].role` is the plan role (`lower_plan`, `higher_plan`) for `GET` and
  `HEAD` alike. `runner_run_ids` has exactly one entry.
- `hypothesis` is `export_without_entitlement` when a marker was supplied for the route,
  else `endpoint_without_plan_gate`. It is not inferred from route names.
- `observed` is the block `regress add` copies; it is everything replay needs (§10).
- Raw headers and bodies stay in the attempt store. No key-path names, body text, fixture
  value or credential appear in a finding. Handles appear (§3.2); labels of credentials do
  not.

## 12. Safety invariants → named tests

All in `tests/test_runner_plan_differential_safety.py` unless a file is named. Every test
that sends a request sends it only to the loopback synthetic target, bound to port 0 per
test. Each brief §1.8 bullet is mapped in the last column.

| # | Invariant | Named tests | Must prove | §1.8 bullet |
|---|---|---|---|---|
| I1 | **Host confinement.** No connection to any host outside the scope allowlist, including through a redirect. | `test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`; `test_i1_host_header_is_always_the_normalized_host` | (a) host not in allowlist → forced dry-run, exit 3, zero connections on the target and on a second listener; (b) a route answering `302 Location:` the second listener yields zero connections there and an `inconclusive` pair; (c) IPv4 literal, IPv6 literal, `http://`, port, userinfo, trailing dot and punycode base URLs are rejected before any socket; (d) a resolver whose answer changes after preflight ends the run with `dns_changed` and no further request; (e) every request seen by the target has `Host` equal to the normalized host. | No request to a host outside the scope allowlist, ever, including redirects |
| I2 | **GET/HEAD and inventoried-route confinement, enforced in the compiler.** | `test_i2_only_inventoried_get_and_head_reach_the_wire`; `test_i2_post_inventory_is_rejected_at_compile`; `test_i2_every_transport_action_is_the_compiled_pair` | (a) an inventory artifact with a `POST` entry reaches `heel.runner.compiler.plan_differential_pairs` unfiltered (the test wraps the function and records its argument) and is rejected there before `RunnerStore.route_inventory` is called; the command exits 2 with zero requests; (b) `CanaryCompiler.compile_plan_differential_pair` refuses a route absent from the bound store's inventory and a non-GET/HEAD method, and returns exactly two actions `lower_plan`, `higher_plan` for a `GET` and for a `HEAD` route; (c) across a full run the target's log contains only `GET` and `HEAD` and only planned paths; (d) `_ScopedTransport.request` with a well-formed action of another scenario, another route, another method, or a role other than `lower_plan`/`higher_plan` raises `gate_rejected` with zero connections, zero budget use and zero log entries; (e) by AST of the new module: `TargetHTTPSClient.request` is called only inside `_ScopedTransport`, `execute(` is called only with a `_ScopedTransport`, every `_ScopedTransport` is constructed from a `compile_plan_differential_pair` result, and `_build_client` is referenced only at its definition and one call site; (f) by AST of `heel/cli.py`: `_runner_run` passes the loaded artifact to the module unmodified and contains no reference to `method`, `route_template` or `routes` keys. | No method other than GET/HEAD |
| I3 | **Verified signed scope.** | `test_i3_no_request_without_verified_signed_scope` | Unknown scope, hand-edited scope file (allowlist widened), expired scope and unbound scope each give exit 2 and zero requests; a scope file edited after the first pair stops the run before the next request. | No request without a signed scope … |
| I4 | **One-shot reserved attempt.** | `test_i4_no_request_without_one_shot_reserved_attempt` | (a) reusing an attempt ID is refused with zero requests; (b) `_ScopedTransport` built without a reservation, or whose directory is gone, refuses with zero connections; (c) with `reserve_run` forced to fail, zero requests are sent; (d) a consumed grant cannot be executed twice. | … and a reserved attempt ID |
| I5 | **Secret exclusion.** | `test_i5_credential_plaintext_absent_from_heel_home_and_output` | After a successful run, a run against a route echoing the credential in a header and in the body, a run whose echoing body also contains floats and negative integers, a run failing in transport, a run stopped by scope tamper, and a run with a missing credential: a byte scan of every file under `HEEL_HOME` (`heel.db`, evidence `.bin`, reports, both containment logs) finds neither credential, and stdout, stderr, findings and containment rows contain neither. | Credentials never appear in reports, logs, findings, or containment entries |
| I6 | **Every request logged.** | `test_i6_every_request_is_logged_before_it_is_sent` | In a run with no append failure, count of `plan_differential_request` entries == sum of runner `requests_started` ≥ requests counted by the target, including a forced retry; each target request maps to a distinct entry appended before it arrived; a failing append sends nothing. | Containment log records every request … |
| I7 | **Caller attribution.** | `test_i7_every_containment_entry_carries_cli_caller` | Every containment row for the run has `caller == "cli:<user>"`; `run_plan_differential` raises for an empty or non-`cli:` caller before any state change. | … with caller attribution |
| I8 | **Chain integrity.** | `test_i8_containment_chains_verify_and_detect_tamper` | `containment.verify_chain` is true after success and after failure; mutating one stored row makes it false; the runner's signed chain verifies for each `crun_` run with `verify_containment_chain`. | chain verifies |

Independent requirements:

| # | Requirement | Named test | File and proof |
|---|---|---|---|
| R9 | Total request budget | `test_r9_max_ops_hard_caps_total_requests` | safety — with `max_ops=5` and retries forced the target sees ≤ 5 requests; `--max-ops` 1, 101 and non-integer are rejected; a lower scope `max_requests` wins. |
| R10 | CLI-only entry | `test_r10_no_mcp_or_rest_entry` | safety — `mcp_server.TOOL_NAMES` equals an explicit expected set; nothing in `mcp_server.py` or `rest.py` references `plan_differential`. |
| R11 | Fail-closed predicates | `test_r11_verdict_table_rows` (one case per §8.5 row), `test_r11_predicates_fail_closed`, `test_error_envelope_never_counts_as_parity`; and, from the red-team file, `test_redteam_break_d1_*` (all three generations, 29 cases, green after D4) and `test_redteam_holds_affirmative_bodies_keep_the_positive_control` | `tests/test_runner_plan_differential_predicates.py` — status-only, 2xx denial envelope, empty, HEAD, missing positive control, executor disagreement, exception in evaluation; `candidate` is `true` on row 8 only; an envelope makes `body_superset` `None`, not `False`. |
| R28 | Material superset (D4, §8.6) | `test_d4_truthy_leaf_table`, `test_d4_material_paths_are_structural_and_bounded`, `test_d4_verdict_truth_table`, `test_d4_same_shape_different_values_stay_observed`, `test_d4_hollow_shape_is_never_observed_candidate_or_held`, `test_d4_bounds_leave_body_superset_undetermined`, `test_d4_reflexive_bodies_unchanged` | `tests/test_runner_plan_differential_predicates.py` — every row of §8.6 T1–T3 by case id; a hollow shape is never `observed`, never a candidate, never `held` without a marker; a same-shape materially populated lower body with different values is still `observed`. |
| R29 | Structural path identity (D5, §8.7) | `test_d5_path_segments_render_injectively`, `test_d5_alias_truth_table`, `test_d5_bounds_count_alias_keys_as_nodes`, `test_d5_structural_identity_fixed_seed_corpus` (predicates); `test_d5_alias_lower_body_is_hollow_in_fresh_run_and_regression_replay` (cli); `test_redteam_break_d9_path_alias_turns_hollow_lower_body_into_observed` (red team, unedited) | every T4 and T5 row by case id; a fixed-seed corpus checked against an independent tuple walk in both directions; the D9 pair end to end through CLI, findings and replay. |
| R12 | No scope creation or mutation | `test_r12_scope_files_are_never_written` | safety — the scopes directory's file list, bytes and mtimes are identical before and after bootstrap, dry-run, run, failed run and replay; the new module does not import `create_scope`. |
| R13 | Dry-run sends nothing | `test_r13_dry_run_sends_nothing` | safety, no seam — zero sockets, no resolver call, no attempt directory, no credential variable consumed. |
| R14 | No transport selection from the CLI | `test_r14_cli_cannot_select_transport` | `tests/test_runner_plan_differential_cli.py` — the `run` option set equals the six of §3.1; `_build_client` takes only `origin`; setting `HEEL_CA_BUNDLE`, `HEEL_RUNNER_CA_FILE`, `HEEL_RUNNER_TRANSPORT`, `HEEL_RUNNER_RESOLVER`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` leaves the constructed client's resolver, socket and TLS classes and its CA count unchanged. It makes no claim about `SSL_CERT_FILE` (see R23). |
| R15 | Observed finding without declaration | `test_r15_observed_finding_from_undeclared_route` | cli — with an OpenAPI carrying no plan metadata the run yields a `body_superset` finding with `evidence_state == "observed"` and `operator_declared is False`; `heel findings --run` and `heel regress add` work on it unchanged. |
| R16 | Safe failure output, existing text | `test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` | cli — an unknown option, a missing required option, and each handler rejection (bad scope, bad URL, bad `--as`, bad `--routes`, POST inventory) all print exactly `Heel runner command was rejected.` on stderr with empty stdout and exit 2; `heel/cli.py` defines no `_SAFE_RUNNER_RUN_FAILURE`. |
| R17 | **Exactly two requests per route, `GET` and `HEAD`** | `test_r17_every_route_sends_exactly_one_request_per_plan_credential`, `test_r17_head_pair_is_two_head_requests_and_no_anonymous_request` | safety — in a full run with no forced retry, for **every** completed pair the target log holds exactly two requests on that path with that method: the first carries the lower credential, the second the higher. For every planned `HEAD` route specifically: exactly one `HEAD` with the lower credential, exactly one with the higher, **zero** with no credential or an unknown one, one `runner_run_id`, exactly two `plan_differential_request` containment entries with roles `lower_plan` and `higher_plan`, and `requests_sent` grows by exactly 2. Across the whole run the count of requests that carry no plan credential is 0, and no attempt store holds a credential record with role `anonymous` or `authenticated`. The `HEAD` pair is `held` or `inconclusive`, never skipped. `CATALOG_BY_ID["plan_entitlement_read"]["allowed_methods"] == ("GET", "HEAD")`; the new module contains no reference to `anonymous_authenticated_read`. |
| R18 | Handles on `--as` | `test_r18_as_accepts_only_registered_credential_handles`, `test_r18_credential_add_prints_handle_never_label_or_secret` | cli — a label, an unknown handle, swapped order, same handle twice and mismatched profiles are rejected; `credential add` prints the §3.2 object and nothing sensitive. |
| R19 | Imported inventory on `--routes` | `test_r19_routes_consumes_persisted_inventory_artifact`, `test_r19_routes_default_is_existing_imported_inventory` | cli — a copy of `routes.json` is accepted and every route in it is planned or listed `not_executed`; a selector-style array, another origin's envelope, a non-canonical or symlinked file are rejected; omitted means the stored inventory; the setup store is never rewritten. |
| R20 | Replay fidelity | `test_r20_regression_replay_reuses_saved_predicate_order_scope_origin` | cli — replay is `fail` on the vulnerable target and `pass` on the hardened (403) one; a different origin, scope, handle, role order or binding digest gives `fail`/`inconclusive` with zero requests. |
| R21 | Production client | `test_r21_production_client_construction_is_unseamed`, `test_r21_tls_transport_real_handshake_verifies_chain_and_hostname` | safety — as described in §7.3, with the stated limits. |
| R22 | Finding eligibility | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` | safety — in a run mixing completed pairs, a `transport:response_rejected` pair, a redirect pair, a scope-tamper stop and budget exhaustion: every row in `heel findings --run` has `reproduction.execution_disposition == "completed"`; each non-completed pair has no `AbuseVector` but appears in the result `pairs` and `report.json` as `inconclusive` with its true disposition and reason; `held` pairs have no finding; `candidate` is `true` exactly for `status_parity` findings. |
| R23 | CA trust boundary is as stated | `test_r23_ca_trust_follows_openssl_default_locations` | safety — with `_build_client` unreplaced and `getaddrinfo` patched: with `SSL_CERT_FILE` pointing at a CA generated in the test, `client.tls.context.get_ca_certs()` contains that CA; with it unset, it does not; in both cases `verify_mode == CERT_REQUIRED`, `check_hostname is True` and the protocol is TLS 1.2. The test asserts that the variable **is** honoured; it MAY skip only when `ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE"`. `docs/PLAN_DIFFERENTIAL_RUNNER.md` contains the trust-boundary statement of §7.2 (asserted by text). |
| R24 | Denial envelope never passes | `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay` | cli — a `body_superset` finding is recorded on the vulnerable target and added as a regression. The target is switched so the lower plan gets `200 {"error": "upgrade required"}`: a fresh run gives `inconclusive` / `lower_denial_envelope` with no `observed` finding, and `regress run` gives `result == "fail"`, `current_status == "inconclusive"`. Switched to a subset 200 body: `fail` / `inconclusive`. Switched to 403: `pass` / `blocked`. |
| R25 | Common numeric JSON completes | `test_r25_numeric_json_bodies_complete_and_do_not_end_the_run`, `test_r25_tolerant_redactor_matches_base_when_base_succeeds` | safety — a route whose body has a float, a negative integer, an integer above 2^53, an object of 300 keys and the echoed credential is planned with other routes after it in canonical order; its pair has disposition `completed` and a §8 verdict (`observed` on the vulnerable target), no pair has reason `transport:evidence_rejected`, later pairs execute, and the `HEEL_HOME` scan of I5 is clean. Unit: for bodies the base accepts, `_TolerantRedactor.count_bytes` equals `Redactor.count_bytes`; for a non-`bytes` or oversized chunk it raises as the base does. |
| R26 | Runner-module packaging | `test_r26_shipped_runner_modules_match_the_checked_in_wheel` | `tests/test_runner_plan_differential_release.py` — every `heel/runner/*.py` named in `release/open-core-v1.json`, including `plan_differential.py` and the four extended modules, is byte-identical to the member of the same name in `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` and in the sdist (read only); the new module imports nothing outside the contract's `python_modules` and the standard library except lazily imported `cryptography`. |

| R27 | Release artifacts are current and are the only files there | `test_r27_release_artifacts_are_current_and_exactly_three` | `tests/test_runner_plan_differential_release.py` — `build_release()` of `scripts/build_open_core_release.py`, run in-process on the working tree, returns bytes equal to the three checked-in files (the same comparison as the CI `--check`); the manifest's `sha256` and `size` equal the checked-in wheel and sdist; the wheel contains `heel/runner/plan_differential.py` and an entry point `heel = heel.cli:main`; `git ls-files apps/heel-cloud/public/downloads` is exactly the three authorized names. The test never writes under `apps/`. It reads the tree only, so it stays valid after merge. |

Path gates P1–P3 and the release commands that complete R27 are in §17. They are command
gates, not pytest tests, because they compare against the base commit `844fc1f`, which a
permanent test must not pin.

## 13. Synthetic target and harness (tests only)

`tests/plan_differential_support.py`: a stdlib `http.server` on `127.0.0.1`, port 0,
started and stopped per test, with two bearer sessions carrying a plan flag (`free`,
`pro`). Every response sends `Content-Length`, closes the connection and uses no transfer
or content encoding. It records every request: method, path, `Host`, arrival order and
which session it carried (`free`, `pro`, `none` or `unknown`), never the token. A
constructor argument selects the lower-plan behavior: `vulnerable`, `hardened` (403),
`envelope` (200 denial body) or `subset` (200 with fewer keys). The module also holds the
loopback seam objects and the test CA helper of §7.3.

| Route | Free | Pro | Expected verdict |
|---|---|---|---|
| `GET /api/export` | 200 same object (vulnerable) / 403 (hardened) / 200 envelope / 200 subset | 200 object | `observed` `body_superset` / `held` / `inconclusive` `lower_denial_envelope` / `inconclusive` `status_parity` |
| `HEAD /api/export` | 200 / 403 | 200 | `inconclusive` `status_parity` (`head_status_only`) / `held`. A request with no credential would get 401; the run never sends one (R17) |
| `GET /api/pricing` | 200, floats, negative and large integers, 300 keys, echoes the credential | same | `observed` `body_superset` (vulnerable); used by R25 and I5 |
| `GET /api/reports` | 403 | 200 object | `held` `lower_denied` |
| `GET /api/billing` | 200 `{"error": "upgrade required"}` | 200 object | `inconclusive` `lower_denial_envelope` |
| `GET /api/summary` | 200, subset of pro's keys | 200 object | `inconclusive` `status_parity` |
| `GET /api/empty` | 204 | 204 | `inconclusive` `status_parity` |
| `GET /api/text` | 200 `text/plain` | same | `inconclusive` `transport:response_rejected` |
| `GET /api/redirect` | 302 to a second listener | same | `inconclusive`; second listener untouched |
| `GET /api/echo` | 200, echoes the credential in a header and the body | same | used by I5 |
| `GET /exports/{id}` | marker present (vulnerable) or absent | marker present | `verified` / `held` |
| `GET /items/{id}` | | | `not_executed` `unbound_placeholder` |
| `POST /api/export` | in the OpenAPI document only | | never imported, never sent |

`tests/fixtures/plan_differential/openapi.json` describes these routes with **no**
`x-heel-*` plan or control metadata.

`tests/plan_differential_harness.py` is the synthetic journey for T5. `serve` starts the
target and writes its port to a file. `heel <args…>` installs the loopback factory of
§7.3 as `_build_client` and calls `heel.cli.main(args)` in-process. The synthetic origin
is `https://plan-differential-synthetic.heel.dev`; the harness never resolves it. The
harness adds no option to the product CLI and is not in the wheel (F19).

## 14. Files the implementer may touch — exhaustive

### 14.1 Final diff (the only paths that may differ from `844fc1f` when T2 ends)

Besides this spec, which only Fable edits.

New:

1. `heel/runner/plan_differential.py`
2. `tests/test_runner_plan_differential_safety.py`
3. `tests/test_runner_plan_differential_predicates.py`
4. `tests/test_runner_plan_differential_cli.py`
5. `tests/test_runner_plan_differential_release.py` — R26 and R27 only.
6. `tests/plan_differential_support.py`
7. `tests/plan_differential_harness.py`
8. `tests/fixtures/plan_differential/openapi.json`
9. `docs/PLAN_DIFFERENTIAL_RUNNER.md` — **the runnable documentation T5 follows.** It MUST
   contain, as copy-pasteable commands in the order of §4, the real-staging journey and
   the synthetic journey through the harness, the seam disclosure of §7.3, the trust
   boundary of §7.2, the two-requests-per-route rule and the `HEAD` mapping consequence of
   §6.1, and the limits of §15.

Modified, with the only permitted change:

10. `heel/cli.py` — §6.5.
11. `heel/regressions.py` — §6.6.
12. `heel/runner/catalog.py` — §6.1: the one tuple.
13. `heel/runner/compiler.py` — §6.2: one function, one method, one import.
14. `heel/runner/store.py` — §6.3: two read-only methods and the shared validator.
15. `heel/runner/http_transport.py` — §6.4: one line.
16. `tests/test_runner_cli.py` — the `credential add` output assertion at line 75 only;
    the label assertion at line 76 stays.
17. `tests/test_runner_compiler.py` — the catalog pin at line 132 only: entries 1 and 2
    stay `("GET",)`, entry 3 becomes `("GET", "HEAD")`.
18. `release/open-core-v1.json` — add `heel/runner/plan_differential.py`.
19. `tests/test_open_core_release.py` — add the same path to `EXPECTED_CONTRACT`; nothing
    else.

Regenerated, never hand-edited, and only by the procedure of §14.5:

20. `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`
21. `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl`
22. `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`

These three are the whole of the user-authorized `apps/` exception. No other path under
`apps/` may be created, modified, deleted, renamed or have its mode changed.

### 14.2 General rules for the dirty tree

The uncommitted files in the working tree were written by the first T2 session (Opus).
They are evidence and a starting point, not accepted work. The next T2 session:

- MUST NOT run `git reset --hard`, `git checkout .`, `git restore .`, `git stash`,
  `git clean`, or any restoring command that names more than one path.
- First records `git status --short` and, for each path of §14.3, `git hash-object <path>`.
  The expected values are in the table. A different value means someone changed the file
  after this spec: do not discard it; diff it against the table's description and report
  the difference in the closing status before continuing.
- Reuses a hunk only after re-reading it against the section named in the table.
- Removes an obsolete hunk by editing that hunk. `git restore --source=HEAD --worktree --
  <one file>` is permitted only for a file whose **entire** diff is obsolete, one file per
  command, after saving it with
  `git diff -- <file> > .heel/plan-differential-run/T2-discarded-<basename>.patch`. With
  this design no file is expected to need it.
- Fable does not stage or commit any of these files; they are committed by Opus in small
  signed commits.

### 14.3 Disposition of every dirty path

`+/−` is `git diff --numstat` against `HEAD` at the time of this spec.

| Path | State now (`+/−`, worktree blob) | Disposition |
|---|---|---|
| `heel/runner/catalog.py` | modified, 1/1, `5e11c054…` | **Reuse as is.** It is exactly §6.1. |
| `heel/runner/compiler.py` | modified, 124/1, `0362fd14…` | **Reuse after re-check against §6.2.** `plan_differential_pairs`, `compile_plan_differential_pair` and one import; no other hunk. |
| `heel/runner/store.py` | modified, 21/2, `527836f5…` | **Reuse after re-check against §6.3.** `_inventory_locked`, `route_inventory`, `route_inventory_path`. |
| `heel/runner/http_transport.py` | modified, 1/0, `2d21503d…` | **Reuse as is.** It is exactly §6.4. |
| `tests/test_runner_compiler.py` | modified, 2/1, `8196c103…` | **Reuse as is** (§14.1 item 17). |
| `heel/cli.py` | modified, 65/4, `3d4b6c25…` | **Rework one hunk.** Keep the `_runner_credential_add` hunks, the `runner run` subparser, `_runner_run` and the dispatch line. Delete the added constant `_SAFE_RUNNER_RUN_FAILURE` and make `_runner_run` print `_SAFE_RUNNER_COMMAND_FAILURE` (C5, R16). |
| `heel/regressions.py` | modified, 27/0, `b3c01313…` | **Reuse as is** (the branch only delegates), subject to §10 being implemented in the module. |
| `release/open-core-v1.json` | modified, 1/1, `024db5aa…` | **Reuse as is.** |
| `tests/test_open_core_release.py` | modified, 1/0, `802323d4…` | **Reuse as is.** |
| `tests/test_runner_cli.py` | modified, 9/1, `21d8201d…` | **Reuse as is.** |
| `heel/runner/plan_differential.py` | untracked, 1652 lines, `db1e0807…` | **Rework, do not rewrite.** Its architecture is this design: it already calls `plan_differential_pairs`, `compile_plan_differential_pair`, `route_inventory` and `route_inventory_path`, runs one `plan_entitlement_read` run per pair, and sent exactly two requests per route in F34. Later evidence found these defects, each of which MUST be fixed and tested: (1) no redaction-count seam — add `_TolerantRedactor` and substitute it in `_ScopedTransport` (§7.4, R25); (2) regression replay must pass only on a `held` verdict (§10, R24) — re-check `replay_plan_differential` line by line; (3) row-1 and `not_executed` reasons must be exactly the closed lists of §8.5; (4) replay uses `max_ops=4`; (5) every other function re-checked against §7–§11 before it is committed. |
| `tests/plan_differential_support.py` | untracked, 486 lines, `fda2dc10…` | **Rework**: replace the `hardened` flag with the four lower-plan behaviors and add `/api/pricing` (§13). The loopback seam objects and the test CA helper are reusable. |
| `tests/fixtures/plan_differential/openapi.json` | untracked, `fb2b84db…` | **Rework**: add `/api/pricing`. |
| `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`, `launch/` | untracked, unrelated | **Do not touch, stage or commit.** |

The `1c6b324` revision listed five of these files as "cleanup-only, restore to `HEAD`".
That instruction is **withdrawn**: restoring them would remove the design. Nothing in the
current tree implements the withdrawn four-request path, so there is no obsolete hunk
from it to remove.

### 14.4 Out of bounds

Reserved for later tasks, not T2: `docs/REDTEAM_PLAN_DIFFERENTIAL.md` and
`tests/test_runner_plan_differential_redteam.py` (T3); `docs/CAPABILITIES.md` (T5, three
rows only).

Everything else is out of bounds, explicitly: every existing file under `heel/runner/`
other than the four of §6 (`__init__.py`, `adapters.py`, `companion.py`,
`containment.py`, `content_assertion.py`, `control_client.py`, `coordinator.py`,
`execution.py`, `identity.py`, `openapi_routes.py`, `redaction.py`, `runtime.py`,
`service.py`, `vault.py`), `heel/scope.py`, `heel/contracts.py`, `heel/containment.py`,
`heel/store.py`, `heel/canary_contracts.py`, `heel/mcp_server.py`, `heel/rest.py`,
`heel/static_review.py`, `heel/reference_rehearsal.py`, `heel/saas/`, **every path under
`apps/` except the three of §14.1 items 20–22**, `web/`, `scripts/`, `.github/`, `README`,
pricing docs, `pyproject.toml`, `MANIFEST.in`, `release/` other than item 18,
`tests/test_runner_http_transport.py`, Claude settings, hooks, and the untracked
`docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md` and `launch/`. If the implementation cannot be
completed without one of these, stop and report; do not edit it.

No new dependency. `cryptography` stays under the `runner` extra and is imported lazily.
The new module MUST NOT assign to, patch or mutate any object of another `heel.runner`
module at import or run time (for example `CATALOG`, `ADAPTER_REGISTRY`); it only
subclasses `RunnerStore` and `Redactor`.

### 14.5 Regenerating the three release artifacts

The artifacts are a function of the shipped files only: the paths named in
`release/open-core-v1.json` (F36). Tests and docs are not inputs. The builder reads the
working tree, so it must run on the final tree.

Until this procedure has run, exactly three tests are expected to fail and no other:
the existing `test_checked_in_runner_artifacts_match_the_current_public_pairing_and_recovery_api`
(F22), R26 and R27. Commits before the artifact commit therefore carry those known
failures; the T2 gate is evaluated on the final commit.

Procedure, in this order, **only after** all source, test and doc changes of §14.1 items
1–19 are committed and no further edit to a shipped file is planned:

1. `git status --porcelain` MUST list only `?? docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`
   and `?? launch/`. Run the final test command of §17; the failures MUST be exactly the
   three named above.
2. Build with the existing builder, unmodified:
   `.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads`
   It MUST print `built heel_sim-1.2.0-py3-none-any.whl, heel_sim-1.2.0.tar.gz, and heel-open-core-manifest.json`.
3. Check with the existing command the CI `package` job runs:
   `.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`
   It MUST print `open-core release artifacts are current` and exit 0.
4. `git status --porcelain -- apps/` MUST print exactly three lines, each ` M` followed by
   one of the three authorized paths. Anything else: stop, do not commit, report.
5. Stage the three paths by explicit path (never `git add -A`, `git add .` or
   `git add apps`) and commit them alone, `git commit -s` with the Opus trailer last.
   `git show --stat --format= HEAD` MUST list exactly those three paths.
6. Run the final test command of §17 again: zero failures. Run path gates P1–P3 (§17).

The builder, `MANIFEST.in`, `pyproject.toml`, the CI workflow and the `--check` step MUST
NOT be changed, weakened or skipped. Version stays `1.2.0`; the file names do not change.

If any shipped file changes after step 5 — in T2, or in a T4 remediation — steps 1–6 are
repeated in that same task before its closing status, and the artifact commit again
contains only the three paths.

### 14.6 Post-escalation D4 implementation allowlist (2026-10-05) — exhaustive

The Opus D4 session starts at the commit that carries this record and may make the
following changes and no other. `git diff --name-only <that commit> HEAD` on its final
commit MUST list exactly paths 1–5 below.

1. `heel/runner/plan_differential.py` — only: add `material_paths` (and export it in
   `__all__`); change `_evaluate` to §8.6 (shape and material sets, `hollow`, the
   `status_parity` and `body_superset` rules of §8.4, the row-9 reason
   `lower_hollow_shape`); nothing else. `is_denial_envelope` and its helpers, `key_paths`,
   the row order and row numbers, `PairVerdict`, the redaction classes, `_ScopedTransport`,
   `_build_client`, `_prepare`, `_execute`, `replay_plan_differential`, every constant and
   every reason string other than the one added MUST be byte-unchanged. No new import.
2. `tests/test_runner_plan_differential_predicates.py` — additive only: the seven named
   tests of §8.6. No existing line of the file may be edited or deleted (checked by
   `git diff` of the file showing only `+` lines outside hunk headers). Shared helpers of
   the file (`observation`, `evaluate`, `protected`, `FULL`, `SUBSET`, `ENVELOPE`) may be
   reused.
3. `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` }
4. `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` } regenerated only by
5. `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz` } the procedure of §14.5

Explicitly not touched by Opus in this cycle: `tests/test_runner_plan_differential_redteam.py`
(the Fable regression; its four failing cases MUST turn green by change 1 alone, and no
case may be edited, weakened, skipped, xfailed or deleted), `docs/REDTEAM_PLAN_DIFFERENTIAL.md`,
this spec, `docs/PLAN_DIFFERENTIAL_RUNNER.md` and `docs/CAPABILITIES.md` (their one-line lag
on the hollow-shape reason is recorded in §16 for a later Fable doc commit), every file of
§14.1 items 2, 4–19, and everything in §14.4.

Commits: small, `git commit -s`, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
as the last trailer; the artifact commit alone holds paths 3–5. No push, no PR, no branch
change.

Gate the orchestrator reads: the final test command of §17.2 gives **0 failed**, passed =
1598 + the number of cases Opus added (1594 + the 4 D1 final cases now green), 5 skipped;
`tests/test_runner_plan_differential_redteam.py` alone gives **61 passed, 0 failed**;
§17.3 `--check` prints `open-core release artifacts are current`; §17.4 P1–P3 unchanged
(P2 still the same five runner modules); `git diff --check` clean; the diff of change 1
contains no new denial word, key, wrapper, regex, classifier, annotation, network call or
import.

### 14.7 Post-escalation D5 implementation allowlist (2026-10-06) — exhaustive

The Opus D5 session starts at the commit that carries this record and may make the
following changes and no other. `git diff --name-only <that commit> HEAD` on its final
commit MUST list exactly paths 1–6 below.

1. `heel/runner/plan_differential.py` — only the four edits of §8.7.4: add `_PATH_ESCAPES`
   and `_path_segment` above `key_paths`; the one-token replacement in `key_paths`; the same
   in `material_paths`; optional one-sentence docstring additions. `_evaluate`,
   `_observation_view`, `__all__`, every other function, class, constant, reason string and
   import MUST be byte-unchanged. No new import.
2. `tests/test_runner_plan_differential_predicates.py` — additive only: the four named tests
   of §8.7.7. No existing line edited or deleted (checked by `git diff` of the file showing
   only `+` lines outside hunk headers). Existing helpers (`observation`, `evaluate`,
   `FULL`, `SUBSET`, `ENVELOPE`, `protected`, `_d4_columns`, `_d4_complex_bodies`) may be
   reused.
3. `tests/test_runner_plan_differential_cli.py` — additive only: the one named test of
   §8.7.7, reusing `World`, `finding_for`, `add_regression`, `regress`, `pairs_by_route`
   and `EXPORT` of that file and of `plan_differential_support`.
4. `apps/heel-cloud/public/downloads/heel-open-core-manifest.json` }
5. `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl` } regenerated only by
6. `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz` } the procedure of §14.5

Explicitly not touched by Opus in this cycle: `tests/test_runner_plan_differential_redteam.py`
(the D9 regression MUST turn green by change 1 alone), `tests/plan_differential_support.py`,
`tests/plan_differential_harness.py`, `tests/test_runner_plan_differential_safety.py`,
`tests/test_runner_plan_differential_release.py`, `heel/runner/redaction.py` (the §11.5
hash-seed defect is a separate decision), `docs/REDTEAM_PLAN_DIFFERENTIAL.md`, this spec,
`docs/PLAN_DIFFERENTIAL_RUNNER.md`, `docs/CAPABILITIES.md`, every file of §14.1 items 2,
4–19, and everything in §14.4. No new dependency of any kind.

Commits: small, `git commit -s`, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
as the last trailer; the artifact commit alone holds paths 4–6. No push, no PR, no branch
change. Gate: §17.6.

## 15. Limits the docs must state

Inherited from the existing transport and contracts, unchanged by this work:

- Public HTTPS staging hosts only: port 443, public addresses, an IANA-TLD hostname.
  Private-network, loopback and custom-port staging are not reachable.
- TLS 1.2 only. No redirect is followed.
- Responses must carry `Content-Length`, no transfer or content encoding, and be empty or
  one JSON object of at most 256 KiB. Chunked, compressed, array and non-JSON responses
  make the pair `inconclusive`.
- One mapping per scenario, so at most one parameterized route (`GET` or `HEAD`) can be
  given fixture values; other parameterized routes are listed as `not_executed`.

Chosen for Phase 1:

- One staging origin per `HEEL_HOME`. Two plans. One credential per plan role.
- Every route, `GET` or `HEAD`, costs exactly two requests before retries: one per plan
  credential. Heel sends no unauthenticated request. A `HEAD` pair compares statuses only.
- `heel runner map` and `heel runner prepare` accept a `HEAD` mapping for
  `plan_entitlement_read` (§6.1).
- Trust anchors are the TLS library's default locations and follow `SSL_CERT_FILE` /
  `SSL_CERT_DIR`; the operator's environment is trusted (§7.2).
- `observed` means the lower plan received every field the higher plan received on one
  read. It is a hypothesis about a missing plan gate; ungated-by-design routes will appear.
- A 2xx denial body is never counted as parity, never as `held` without a marker, and
  never as a regression pass. Nor is a 2xx body that repeats the higher plan's key shape
  but is `null`, `false`, `0` or empty at a path where the higher plan's body carries a
  value (§8.6); it is reported `inconclusive` / `lower_hollow_shape`.
- A regression passes only when the lower plan is denied by status (or the marker is
  absent) while the higher plan still succeeds.
- Target ownership is asserted only by the operator's signed local scope.
- A regression replays only under the same, still-valid scope.
- Nothing is uploaded.

## 16. Open risks for T2 and T3 to confirm

| Risk | What would confirm or refute it |
|---|---|
| The default trust locations may hold zero CAs on some Python builds; the run then fails closed with `tls_error`. | A real run against a public staging host. Not covered by CI. |
| TLS 1.2 only and no chunked decoding may make many real targets `inconclusive`. | First real-staging run. Lifting either is a transport change outside Phase 1. |
| Widening `plan_entitlement_read` to `HEAD` under adapter version `"1"` also changes what `runner map`, `runner prepare` and any cloud-approved manifest of that scenario may carry. Grep found no reader of `allowed_methods` outside `heel/runner/` and no mirror of it in `heel/saas`, `apps/` or `web/`, and the full suite passes with it (F35). | T3 to check the cloud projection and approval path for a `HEAD` plan pair. |
| `load_default_certs()` now runs for every `TLSTransport`. Only this feature constructs one in product code today (F33). | T3 to re-run the grep of F33 on the final tree. |
| The sdist is gzip-compressed, so its bytes depend on the zlib of the Python that builds it. The artifacts are built locally (Python 3.12, macOS) and checked in CI (Python 3.13, Linux). The artifacts at `HEAD` pass `--check` locally, which is evidence, not proof, that the two agree. | The CI `package` job on the T6 pull request. If it reports `generated artifact is stale` for the sdist only, stop and report to Kevin; do not edit the builder. |
| CI strict mode (`HEEL_REQUIRE_STANDARD_BUILD=1`), the wheel install step and the `apps/` Node tests have not been run for this feature (F39). They read the manifest and the wheel; nothing they read is pinned elsewhere (F36). | T2 SHOULD install `release/requirements-release.txt` into a throwaway venv outside the repo and run the strict command; otherwise the T6 CI run. |
| The frozen-pair check in `_ScopedTransport` is enforcement inside one module, not a separate trust domain. The compiler and the transport's own route check stand behind it. | I2 (b), (d), (e); T3 to attack `_ScopedTransport` directly. |
| The HMAC append inside `before_attempt` runs under the transport's attempt deadline; a slow disk becomes `gate_rejected`. Fails closed, may be flaky. | I6 under repeated runs. |
| Up to 50 reserved runs in one attempt store against the 64-run bound. | R9 at `--max-ops 100`. |
| Redaction matches every single-level JSON spelling of each secret character (§7.5); a double-encoded, split, base64, hex or percent-encoded echo is not matched (report §9.4, §10.4, D2 accepted). | I5 echo cases held through three T3 sessions. Remaining forms are out of Phase 1 scope. |
| D4 (§8.6) loses genuine observations where the lower body is `false`, `0`, `null` or empty at a path the higher body populates (a differing pagination flag, a zero count, an optional field). Fails closed to `inconclusive`. | T5 to note how many pairs land on `lower_hollow_shape` against the synthetic target (expected: none of the documented journey's routes). |
| D4 does not read values, so a 2xx denial body that places a truthy value at every path the higher body populates (an upgrade URL where a file URL was, `1` where a count was) is still `observed`. This is the stated boundary of a value-blind rule; closing it needs value comparison, which the brief forbids. | Fresh Fable red team after Opus to probe and record it as a documented limit or a break; a break here is a Phase 2 question, not a vocabulary patch. |
| Doc lag: `docs/PLAN_DIFFERENTIAL_RUNNER.md` and the finding text do not yet name `lower_hollow_shape`. | A later Fable-authorized doc commit; not Opus, not T5 (brief T5 limits doc edits to three `CAPABILITIES.md` rows). |
| Credentials registered before this change have handles that were never displayed. | Operator uses a fresh `HEEL_HOME`. |
| `SYNTHETIC_ONLY` is the only data mode `heel scope create` issues; this design relies on canary accounts holding synthetic data. | Operator decision; not testable in code. |
| Whether the `apps/` exception lets a T4 remediation regenerate the artifacts again. The brief says "after the product implementation is final"; §14.5 reads that as "whenever a shipped file last changed". | Orchestrator to confirm before any T4. |
| D5 (§8.7): `reproduction.observations[].key_path_count` counts structural paths, so it may exceed the pre-D5 value for a body with alias-spelled keys. Informational; nothing reads it back. | T5 to note the count on the documented journey (expected unchanged: the synthetic target has no such keys). |
| D5 does not change `_secret_key`, so a literal key with a separator and a secret word (`a.token`) is secret-named: path kept, never material, not descended. Pre-existing; cannot create a false `observed` because a never-material path cannot satisfy a material requirement. | Fresh red team item 2 of §8.7.8. |
| Doc lag: `docs/PLAN_DIFFERENTIAL_RUNNER.md` does not describe the path rendering; it never named `key_paths`, so no operator-visible statement is wrong. | A later Fable-authorized doc commit, with the `lower_hollow_shape` lag above. |

## 17. Baseline, final commands and T2 gates

### 17.1 Baseline record

Recorded by the first T2 session before any edit (F38), saved in
`.heel/plan-differential-run/T2-baseline.txt`:

| Run | Command | Result |
|---|---|---|
| Raw macOS | `.venv/bin/python -m pytest -q tests` | **35 failed**, 1451 passed, 5 skipped. All 35 are `RunnerRuntimeCorrupt: runtime state parent is unsafe` in `tests/test_runner_control_http.py` (16) and `tests/test_runner_public_client.py` (19): the default `TMPDIR` is under `/var`, a symlink to `/private/var`. Environment, not product. |
| CI-equivalent | the same command with `TMPDIR` set to its resolved real path | **1486 passed, 5 skipped, 0 failed** |

All deltas are reported against the CI-equivalent line. The raw macOS failures are not a
regression and MUST NOT be "fixed" in product code.

### 17.2 Final test command

```
TMPDIR="$(cd "$(.venv/bin/python -c 'import tempfile; print(tempfile.gettempdir())')" && pwd -P)" \
    .venv/bin/python -m pytest -q tests
```

On this machine the resolved value is
`/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`. The closing status MUST print
the resolved value used. Required result on the final commit: **0 failed**; passed =
1486 + the number of new tests; skipped = 5, plus R23 only under its stated skip
condition; no baseline test missing. Report the exact counts and the delta.

### 17.3 Package build and check commands

```
.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads
.venv/bin/python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
```

Run only as steps 2 and 3 of §14.5. The second is the command of the CI `package` job
(F24) and MUST end with `open-core release artifacts are current`, exit 0.

### 17.4 Path gates (commands, run on the final commit)

| Gate | Command | Required output |
|---|---|---|
| P1 **three artifacts only** | `git diff --name-only 844fc1f HEAD -- apps/` | exactly the three lines `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`, `apps/heel-cloud/public/downloads/heel_sim-1.2.0-py3-none-any.whl`, `apps/heel-cloud/public/downloads/heel_sim-1.2.0.tar.gz`, and nothing else |
| P1 (working tree) | `git status --porcelain -- apps/` | empty: no modified, staged or untracked path under `apps/` |
| P2 runner modules | `git diff --name-only 844fc1f HEAD -- heel/runner/` | exactly `catalog.py`, `compiler.py`, `http_transport.py`, `plan_differential.py`, `store.py` under `heel/runner/` |
| P3 whole diff | `git diff --name-only 844fc1f HEAD` | a subset of §14.1 items 1–22 plus this spec |

### 17.5 Named tests the T2 gate reads first

| Requirement | Test |
|---|---|
| Exactly two requests per route, `HEAD` included, none anonymous | `test_r17_every_route_sends_exactly_one_request_per_plan_credential`, `test_r17_head_pair_is_two_head_requests_and_no_anonymous_request` |
| Numeric JSON completes and the whole-`HEEL_HOME` secret scan is clean | `test_r25_numeric_json_bodies_complete_and_do_not_end_the_run`, `test_r25_tolerant_redactor_matches_base_when_base_succeeds`, `test_i5_credential_plaintext_absent_from_heel_home_and_output` |
| Denial envelope in fresh run and in replay | `test_r24_denial_envelope_is_inconclusive_in_fresh_run_and_regression_replay`, `test_error_envelope_never_counts_as_parity` |
| Release artifacts current, three files only | `test_r27_release_artifacts_are_current_and_exactly_three`, `test_r26_shipped_runner_modules_match_the_checked_in_wheel`, the `--check` command of §17.3 and gate P1 |
| Trust boundary | `test_r23_ca_trust_follows_openssl_default_locations`, `test_r14_cli_cannot_select_transport` |
| Existing rejection text | `test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` |
| Completed-only findings | `test_r22_findings_only_for_completed_pairs_and_disposition_is_completed` |
| Eight invariants | the I1–I8 tests of §12 |

The T2 closing status MUST list: baseline → final delta, every changed file, the
invariant → test map, the output of §17.3 and of each gate of §17.4, the dry-run plan
against the synthetic target, and its least-certain claim.

### 17.6 Post-escalation D5 gate (2026-10-06)

Baseline, CONFIRMED by the design session at `d479ff9` with the §17.2 command and
`TMPDIR=/private/var/folders/yc/l85h50j14_96655zkm2z_mdw0000gn/T`: **1 failed, 1703 passed,
5 skipped** (640 subtests, 259 s); the one failure is
`test_redteam_break_d9_path_alias_turns_hollow_lower_body_into_observed`.

Required on the Opus final commit:

| Gate | Required |
|---|---|
| §17.2 full suite | **0 failed**; passed = **1704 + N**, where N is the number of D5 cases added by §8.7.7 (with exactly the named cases: 1 + 40 + 1 + 3 + 1 = 46, so **1750 passed**); **5 skipped**; no baseline test missing |
| `tests/test_runner_plan_differential_redteam.py` alone | **62 passed, 0 failed**, file unchanged from `d479ff9` |
| the three notation-pinned tests of §8.7.7 | present, unedited, green |
| §17.3 `--check` | `open-core release artifacts are current`, exit 0 |
| §17.4 P1–P3 | unchanged (P2 still the same five runner modules) |
| `git diff --name-only <spec commit> HEAD` | exactly the six paths of §14.7 |
| `git diff <spec commit> HEAD -- heel/` | adds one constant, one two-line helper and changes two f-string tokens; no new import, regex, word, key set, classifier, annotation or network call |
| `git diff --check` | clean |

Delta to report: from the D5 baseline (1 / 1703 / 5) and from the T2 baseline
(0 / 1486 / 5).
