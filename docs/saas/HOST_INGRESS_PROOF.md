# Host ingress proof (H0B, `ingress-v1`)

Status: source/configuration candidate. The first Linux proof run (commit `3d9bc2b`) failed; this
remediation has not yet run on Linux.
Nothing here is a production deployment, public TLS, hosted VPC or launch claim.

## What is proved, and where

The real closed ingress sits between the Worker/runners and the private control plane (CP):
nginx 1.30.6 with the njs 1.0.2 HTTP module on the QuickJS engine (`js_engine qjs`), configured by
[`deploy/host/ingress/nginx.conf`](../../deploy/host/ingress/nginx.conf). The only request authority
is [`deploy/host/ingress/policy.js`](../../deploy/host/ingress/policy.js). Every runtime input and its
SHA-256 is in [`deploy/host/ingress/runtime-lock.json`](../../deploy/host/ingress/runtime-lock.json).

- Management TLS listener (8443): only the registered management peer with the one Worker edge
  secret, and only the Worker `controlPlaneRoute` inventory and header classes. CP bytes return unchanged.
- One runner TLS listener per slot (443): listener identity comes from the local socket, never from a
  request field. Strict raw target/header/framing/body checks, closed JSON and identity comparison
  with the root-owned registry, one internal subrequest to the one literal backend, then bounded
  response verification. At most 8 concurrent requests per runner listener and 32 on management,
  one request per connection.
- CP (private HTTP 8080) and the original runner verifier keep every cryptographic, approval,
  receipt and grant decision.

## Commands

The required proof is exactly:

```
python scripts/host_ingress_proof.py
```

from the repository root, with no arguments (one fixed `ingress-v1` profile; any argument exits 2).
It verifies a clean candidate checkout, fetches every archive in the runtime lock and checks its
hash, runs the pinned actionlint 1.7.8 against `.github/workflows/codeql.yml`, builds QuickJS and
nginx+njs privately, installs the hash-pinned wheels into a private venv, runs
`apps/heel-cloud/tests/host-ingress.test.ts` and builds the Worker artifact. A fixed privileged child
(`sudo -n`, schema-checked JSON on stdin, no shell or caller-supplied command) then creates an outer
network+mount+PID namespace with no external interface and runs, inside it:

```
HEEL_REQUIRE_HOST_INGRESS=1 python -m pytest -q tests/test_host_ingress.py
```

The namespace receives only tracked files under the launcher's fixed `STAGE_PATHS` allowlist
(`heel`, `tests`, `deploy/host/ingress`, `pyproject.toml` and the four other proof files: the
launcher, the workflow, the app ingress test and this document). A static test requires that
allowlist to cover every path the test module and harness read and every proof file, and, from a
checkout, stages an exact copy with the launcher's own `stage_tree` and runs the `-k static`
selection there. Run the same check locally before any dispatch:

```
python -m pytest -q -p no:cacheprovider tests/test_host_ingress.py -k test_static_launcher_stages_every_path_the_proof_module_reads
```

With `HEEL_REQUIRE_HOST_INGRESS=1` every G0–G9 case must run: a missing platform, runtime, namespace
capability, case function, skip, xfail or xpass makes the launcher exit nonzero. The launcher
compares the collected case functions with its `REQUIRED_CASES` list (a static test keeps that
list equal to every test function in the module). Outside that switch, on a developer machine, the
dynamic cases skip; that is never proof.

Budgets are fixed: tests 12 minutes inside a 20-minute launcher (the last 60 seconds are reserved
for evidence and cleanup), the launcher step 20 minutes, the job 30 minutes. A timeout is a
failure, not permission to extend or skip.

The GitHub job `host-ingress-proof` in the existing CodeQL workflow runs this launcher on
`ubuntu-24.04` only for a manual dispatch of the literal ref
`refs/heads/codex/self-serve-host-ingress-proof`, with `contents: read`, an exact-SHA checkout
without persisted credentials, SHA-pinned actions, no inputs, secrets, environment or cache, and a
3-day upload of six fixed files. The analyzer job keeps its Python `security-extended` analysis.

## Total deadlines and the njs 1.0.2 timer lifecycle

nginx's `client_body_timeout` and `proxy_*_timeout` are idle timers; a 1 byte/s dribble never trips
them. The policy therefore enforces totals itself (and `client_body_timeout` is only an 11 s idle
backstop behind it, see "Native body-idle backstop" below):

- body read: 10 s from the access handler's entry (runner listener and management POST);
- validation plus upstream response: 25 s from the access handler's entry (runner listener).

Both use one primitive (H0BTD section 5.1, absolute due time from H0BR3). `deadline(r, origin,
budget, status, reason)` calls `deadlineWith()` with the runtime clock and timers
(`DEADLINE_RUNTIME`: `Date.now()`, `setTimeout`, `clearTimeout`, the counters and the fixed refusal);
the policy selftest passes a scripted clock and scheduler to the same function. Abridged:

```js
function deadlineWith(env, r, origin, budget, status, reason) {
    const start = deadlineStart(env.now(), origin, budget);       // ['arm', delay] | ['due', 0] | ['invalid', 0]
    if (start[0] !== 'arm') {                                       // synchronous, before any read or subrequest
        if (start[0] === 'invalid') env.count('deadline_invalid:' + reason);
        refuse(status, reason);
    }
    const due = origin + budget;
    const d = { fired: false, id: null, extended: 0, rearms: 0, env: env };
    const fire = () => {
        let plan = deadlinePlan(env.now(), due, d.extended, d.rearms);   // due | rearm | bound | invalid
        if (plan[0] === 'rearm') {
            d.id = env.arm(fire, plan[1]);    // d.id names the pending timer before this callback returns
            d.rearms += 1; d.extended += plan[1];
            env.count('early:' + reason); env.count('rearm_ms:' + reason, plan[1]);
            return;
        }
        d.fired = true;
        if (plan[0] !== 'due') env.count((plan[0] === 'bound' ? 'early_final:' : 'deadline_invalid:') + reason);
        env.count('expired:' + reason);
        env.refuse(r, status, reason);       // the fixed refusal
        env.arm(() => {}, 0);                // flush the posted terminate now
        throw new Error('deadline');         // -> NGX_ERROR -> ngx_http_terminate_request
    };
    d.id = env.arm(fire, start[1]);
    return d;
}
function settle(d) { if (!d.fired) d.env.cancel(d.id); return d.fired; }
```

(The source wraps each count, the refusal and the re-arm in `try`; a re-arm that cannot be armed
refuses at once as `deadline_invalid`.) The origin is `Date.now()` at the access handler's entry,
taken after nginx finished reading the header block; the content handler reuses that origin through
`$heel_t0` (parsed strictly as a positive decimal) for the 25 s budget, so every due time is
`origin + budget` on one clock and nothing is derived from a shorter remaining interval.

and each awaited operation is wrapped as
`try { x = await op; } finally { if (settle(d)) return; }`.

At expiry the client receives the fixed refusal (`408` body read, `504` upstream), the exception
makes njs return `NGX_ERROR`, nginx terminates the request (HTTP cleanups run and the upstream
connection is closed at once) and posts its terminate handler; the zero-delay timer's own
completion runs posted requests, so the connection, its `limit_conn` slot and the request's JS
context are released at the deadline. A body or reply that arrives later cannot dispatch or be
delivered: the context that awaited it no longer exists.

**Never clear a timer that has fired.** In njs 1.0.2 the timer handler deletes the timer's event
after its callback returns; `clearTimeout()` on that timer from the callback, or from a microtask
the callback runs (for example a `Promise.race` continuation), deletes it a second time and the
worker dies with SIGSEGV. A dead worker never releases the `limit_conn` counts it held, so the
listener then refuses every request. The previous candidate's `race()` helper did exactly this; it
is deleted. A static test allows exactly one `clearTimeout()` (in `DEADLINE_RUNTIME.cancel`, called
only from `settle()`) and one `setTimeout()` (its `arm`), forbids `Promise.race`, and pins the
re-arm's `d.id` replacement before its `return` and the final order (fired flag, fixed refusal,
zero-delay kick, throw). The G0 deadline cases exercise that lifecycle as behaviour (below).

### Absolute due time and bounded re-arm (H0BR3)

nginx keys a timer to `ngx_current_msec`, its cached, millisecond-truncated `CLOCK_MONOTONIC`
reading, updated once per event-loop iteration (`timer_resolution` is unset). A `setTimeout(f, ms)`
called late in a busy iteration is therefore keyed from a stale instant and can fire up to that
staleness plus 1 ms before `ms` have passed since the policy's own `Date.now()` origin. The Linux
cap gate measured four of eight holds 1–3 ms early (run 39547871512); how those milliseconds split
between this server-side staleness and the then post-`sendall` client mark was not measured.

The timer is now only a wake-up. Its callback reads `Date.now()` (the origin's clock, a
`gettimeofday` reading floored to an integer millisecond): before `due` it re-arms for exactly
`due − now` and returns normally; at or after `due` it refuses. Bounds: at most
`DEADLINE_REARMS_MAX = 8` re-arms and `DEADLINE_SLACK_MS = 500` ms re-armed in total (the proof's
only tolerance, `SLACK_S`), after which an early wake refuses at once and counts `early_final:<reason>`.
The initial delay is `due − now` in `(0, budget]`; a re-arm is in `(0, 500]`; the kick is 0. Every
value is checked to be a safe integer before any arithmetic or `setTimeout` (which would otherwise
coerce `NaN` to 0 and wrap negatives modulo 2^32): a clock reading, origin, budget or counter that is
not a safe non-negative integer in range, numeric strings, booleans, `null`, objects, fractions,
`NaN`/`Infinity`, inconsistent counters, or a clock that reads before the origin all yield
`invalid`. An invalid start refuses synchronously, before the body read or subrequest (arming a
0 ms timer instead would let an already-complete body settle it first and proceed, which the G0
native case checks); an invalid wake refuses at once. Both count `deadline_invalid:<reason>`,
distinct from the ordinary `expired:<reason>`. There is no `$msec` or other cross-clock compensation
and no padding: a deadline is extended only by the measured shortfall against its own due time.

Clock assumptions, stated rather than assumed away: the host's `CLOCK_REALTIME` must not step
during one request window (the origin, `$heel_t0` and the post-read belts already rely on this). A
backward step before arming refuses as `invalid`; one after arming makes wakes early, which re-arm
within the 500 ms bound and then refuse as `early_final`; a forward step makes the refusal early
(fail-closed). Re-arming can delay a refusal past `due` by at most 500 ms of scheduled time; it is
not a hard wall-clock guarantee under arbitrary process suspension, which only the real Linux gate's
unchanged upper bounds measure. `early:<reason>` and `rearm_ms:<reason>` are diagnostics of the
staleness (expected non-zero under load); `early_final:` and `deadline_invalid:` must never appear,
and the G8 deadline gates and the G9 worker sentinel assert that.

### Native body-idle backstop (H0BR3 amendment)

`client_body_timeout` also guards a quiet body read, keyed from the same cached `ngx_current_msec` as
the policy's timer (`ngx_http_request_body.c:346,438`). When it expires nginx finalizes the request
with `NGX_HTTP_REQUEST_TIME_OUT`, terminates it without any response (`ngx_http_request_body.c:279-283`,
`ngx_http_request.c:2688-2697`) and, with `reset_timedout_connection on`, resets the connection
(`ngx_http_request.c:3955-3957`). At the former 10 s it expired together with the policy's first,
possibly early wake; once that wake re-arms, nginx's timer ran first and the client got a reset with
no fixed refusal (local run d00: four re-armed holds of the cap gate, four resets; reproduced
deterministically in the pinned runtime). The template therefore sets `client_body_timeout 11s`, the
smallest whole second above the policy's 10 s deadline plus its 0.5 s re-arm bound. Nothing else
changes: the policy's 10 s total deadline is still the only bound the gates accept, every 10.5 s and
25.5 s maximum is unchanged, and a request ended by the 11 s backstop (a reset with no fixed body)
fails every deadline gate. The G0 case `test_g0_native_body_idle_backstop_outlives_the_js_deadline_and_its_rearm_bound`
derives a scaled backstop from the template's margin and checks, in the pinned runtime, that the
largest re-arm still refuses first, that a backstop equal to the deadline loses even a 1 ms re-arm
(reset, no byte), and that the backstop never stands in for the deadline.

### How the gates measure a deadline (H0BR3)

The probe takes `time.time_ns()` immediately **before** `sendall` (CPython's `time.time_ns()` is
`clock_gettime(CLOCK_REALTIME)`, the clock behind QuickJS's `Date.now()`; the Linux probes and
nginx share it, no time namespace), keeps the existing float `time.time()` mark **after** `sendall`,
and records integer ns and float marks for the first response byte (ns read first) and the close.
`_assert_fixed_refusal_at` then checks:

- lower bound, on `Date.now()`'s integer-millisecond grid:
  `floor(first_ns / 1 ms) − floor(sent_ns / 1 ms) ≥ budget` (10000 or 25000). Because
  `floor(sent_ns) ≤ origin` and the refusal is issued only at `Date.now() ≥ origin + budget`, this
  holds by construction with no slack. It is a statement on the millisecond grid: a true interval
  up to 1 ms shorter (for example 9999.000001 ms that straddles two grid lines) passes, exactly as
  `Date.now()` itself cannot see sub-millisecond time;
- upper bounds, unrounded: the existing post-`sendall` float checks, unchanged
  (`first − t0 ≤ budget + 0.5 s`, `closed − t0 ≤ budget + 0.5 s`), **and**
  `first_ns − sent_ns ≤ budget + 500 ms` and `closed_ns − sent_ns ≤ budget + 500 ms` in integer ns
  from the pre-`sendall` mark (stricter by the `sendall` duration). No maximum is compared after
  rounding: a reply 10.50005 s after the send whose floored-ms delta is 10500 fails.


This primitive relies on pinned njs internals (timer handler order, exception to `NGX_ERROR`,
zero-delay timer running posted requests). The runtime lock records that dependency. **Any change
to the nginx, njs or QuickJS pin must re-run the G8 deadline gates and the G9 worker sentinel on
the Linux proof job before review.** Results from macOS (kqueue) do not carry over to Linux
(epoll).

## Gates

| Gate | Content |
|---|---|
| G0 | Runtime/API compatibility in the real njs/qjs: pinned NFC tables (QuickJS lacks `normalize`), strict UTF-8 and the canonical JSON scanner; the deadline planner's numeric validation, the deadline lifecycle under a scripted clock and scheduler (cancel before a wake, early wake then cancel of the re-armed timer, expiry after re-arms, the 8/500 ms bounds, invalid clock or state) and with the real njs timers and body read (pending cancel, re-arm then cancel, expiry after re-arm, synchronous refusal of an invalid start with the body already complete, one surviving worker); the native body-idle backstop outlives the deadline plus its re-arm bound and never replaces the fixed refusal |
| G1 | The compiled Worker reaches CP only through the fixed binding destination with TLS name and Host H; no redirect following |
| G2 | Management boundary: real session/Origin checks through nginx; wrong edge secret, peer, route or header class refused before CP |
| G3 | Real pairing, exchange, approval, activation, context claim, projection submission, human run approval, claim with the unchanged grant verifier, heartbeat/progress/resync/restart, stop-ack, terminal result, registered rotation (slot b's claimed run is first ended by the same stop/stop-ack/terminal ceremony and the owner revokes slot b's context binding, since CP refuses rotation start during an active run and rotation activation while the old key holds an active binding); repeated on SQLite |
| G4 | TLS trust/name/SNI/Host/alias negatives; wrong runner key; forged grant from another key fails the unchanged verifier |
| G5 | Cross-slot identity swaps, registry faults, phase gates; well-formed forgeries reach CP and fail without state change |
| G6 | Invitation reuse, exact retained retries, mutated retries (sequence/signature reach CP and fail; a mutated claim body is refused 403 at ingress with no CP contact), stale and superseded requests |
| G7 | Raw HTTP: duplicates, folding, framing, encodings, targets and methods refused on the real wire without CP contact |
| G8 | Caps and boundaries (including the carried 65,536 CP framing limit), truncated and extra bytes, slow headers, scripted response negatives; total deadlines: runner and management dribble refused at 10.0–10.5 s, body complete at 9 s forwarded and at 11 s refused, late body gives one response and no CP contact, eight held slots released by 10.5 s, slow upstream cut at 25.0–25.5 s with the backend seeing EOF before 26 s, a paced in-budget reply delivered unchanged, mixed expiring and valid load |
| G9 | No sibling/CP/management reach from a slot, no default route, runner processes without capabilities, ingress worker PID unchanged across the whole module, owned processes and namespaces removed; with both module environments closed the only live processes in the launcher's PID namespace are pytest and its PPID-chain ancestors |

Every deadline gate also asserts the ingress worker PID is unchanged.

## Seams (named, not proved)

`SEAM-TEST-CA` (ephemeral test CA, constructor-only trust), `SEAM-FAKE-VPC` (a Node TLS adapter in
place of the Cloudflare VPC binding; its source block is hash-pinned by both test suites),
`SEAM-REGISTRY` (a fixture controller in place of the H1/H3/C4 slot-state supplier),
`SEAM-RUNNER-SECRET` (RAM signing backend), `SEAM-ENV-DNS` (environment proof TXT records) and
`SEAM-SCRIPTED-BACKEND` (response-parser and upstream-timing negatives only; never the G3 chain).

## Evidence

Uploaded files: `summary.json`, `cases.jsonl` (fixed case names, status, policy reasons, CP contact,
changed table names), `versions.txt`, `cleanup.json`, `report.txt` and `build-manifest.json`. Raw
pytest output stays in private memory. No SQLite/WAL, keys, certificates, generated configuration,
raw HTTP, tokens, proofs, nonces, signatures, bodies or environment dumps are written. Every
artifact is scanned for the run's synthetic secrets (edge secret, session cookies, invitation
tokens, CP peppers and seed) before upload; a match replaces the file and fails the run. Host
network, firewall, resolver, hosts, trust-store, sysctl and mount fingerprints must be unchanged
after cleanup.

- **Fingerprint normalisation.** Firewall state is read as `iptables-save` and
  `nft -s list ruleset` (stateless: no counter values). Before hashing, only the dated
  `# Generated by` and `# Completed on` lines are removed from the iptables-save output and its
  chain packet/byte counters `[n:m]` are written as `[-:-]`; any nft `counter packets n bytes m`
  becomes `counter`. Tables, chain names, policies and rules are hashed byte for byte. The
  privileged child takes two snapshots two seconds apart before it creates the namespace; if any
  key differs it runs nothing and the run fails with `failure fingerprint_unstable` and one
  `unstable_fingerprint <key>` report line per key. The same contract is in the runtime lock notes.
- **Leftover processes.** After pytest exits, PID 1 of the outer namespace first reaps every
  exited child it inherited (`waitpid(-1, WNOHANG)`), then records each remaining process as
  namespace-local PID, state letter, PPID and one fixed role (`ingress_nginx`, `worker_node`,
  `suite_python`, `exited`, `unreadable`, `other`, chosen by comparing `/proc/<pid>/exe` with the
  staged binaries), kills and reaps them. `cleanup.json` carries `leftover_processes`, up to 32
  `leftover_records`, `leftover_after_kill` and `reaped_before_count`; `report.txt` has one
  `leftover <pid> <state> <ppid> <role>` line each. No argv, environment, path or command line is
  read into evidence. PASS still requires `leftover_processes 0`.
- **Failure locators.** For every failing, erroring or skipped case, `summary.json`
  (`tests.failure_locators`) and `report.txt` (`locator <case> tests/test_host_ingress.py:<line> <reason>`)
  carry the case function, the deepest traceback line in the test module (0 when none) and one
  token from a closed set (`assertion_failed`, `explicit_fail`, `timeout`, `json_decode_error`,
  `file_not_found`, `permission_error`, `connection_error`, `tls_error`, `os_error`, `lookup_error`,
  `type_error`, `value_error`, `attribute_error`, `subprocess_error`, `other_exception`,
  `setup_error`, `teardown_error`, `skipped`). The exception type is read privately only to pick
  the token; messages, assertion operands, tracebacks, paths and payloads are never published, and
  locators are grammar-checked before they are written. Raw pytest output and `junit.xml` stay private.
- **Confirmation seams.** `versions.txt` and `build-manifest.json` (`nginx_event_method`) carry
  `NGX_HAVE_EPOLL 1` or `NGX_HAVE_EPOLL 0` from the built `objs/ngx_auto_config.h`.
  `summary.json` timings carry `inner_pytest` (pytest wall time inside the namespace) separately
  from `privileged_child` (the whole privileged child, including fingerprints and cleanup).
- **Connection-cap timing telemetry (H0BR2, extended in H0BR3; diagnostic).** Before any
  assertion of the eight-slot cap gate, the separate case `g8.listener_connection_cap_timing`
  carries one optional `telemetry` object; `g8.listener_connection_cap` itself is still written only
  on success. The object has exactly these keys, each a plain integer in a fixed range: `holds`
  (0–8), `holds_unmeasured` (0–8: missing or non-finite float marks, non-integer ns marks, or a
  delta outside ±120 s), `holds_early` (0–8: the grid lower bound above fails), `holds_late` (0–8:
  either unrounded first-byte upper bound above fails), `first_byte_ms_min` (the smallest grid delta,
  exact in the lower-bound domain) and `first_byte_ms_max` (the largest pre-send ns delta rounded
  **up** to a millisecond, so any overrun reads above 10500) (−120000–120000, or `null` only when no
  hold was measured), `probes` and `probes_503` (0–64), `probes_admitted` (0–1), and four deltas of
  the policy's counters across the holds: `early_fires` (0–64, sum of `early:*`), `rearm_ms`
  (0–4000, sum of `rearm_ms:*`), `early_final` (0–8) and `deadline_invalid` (0–8). Consistency:
  early plus late at most the measured holds, `probes_503 + probes_admitted ≤ probes`, and
  `early_fires ≤ rearm_ms ≤ 500 × early_fires`. Each hold is classified with exactly the comparisons
  `_assert_fixed_refusal_at` makes on its first byte (a static test checks agreement on the precision
  edges); the close bound is asserted but not part of the telemetry. The cap gate asserts
  `early_final == deadline_invalid == 0` right after writing the record. The launcher re-checks the
  grammar (no bool, float, string, nesting, missing or unknown key, including an H0BR2-era nine-key
  object; consistent counts) and publishes `"telemetry": null` for anything else; case lines over
  4,096 characters, non-JSON or `NaN`/`Infinity` lines are dropped. Records without telemetry keep
  their seven fields; deadline cases may now list `early:<reason>`/`rearm_ms:<reason>` among their
  fixed counter `reasons`. No per-request timing, payload or identifier is published.
  `versions.txt` adds `cpu_count <n>` or `cpu_count unavailable` as runner context, and the fixed
  line `time_clock CLOCK_REALTIME` (the launcher interpreter, which the staged venv copies, reports
  `clock_gettime(CLOCK_REALTIME)` for `time.time`) or `time_clock unavailable`; never runtime text.
- **The cap gate's 408 timing on Linux (cycle 3).** Runs 39534930239, 39540910899 and 39547871512
  failed `test_g8_listener_connection_cap_holds_at_eight_and_releases_at_the_deadline` at the
  first-byte window; the last run's telemetry showed the refusals early (four of eight, 9997–10001 ms
  after the post-`sendall` mark, none late). H0BR3 changes the deadline to the absolute due time
  above and the probe's lower-bound mark to the pre-`sendall` ns mark, with every threshold, the cap
  of eight and the refusal bytes unchanged. This is not established on Linux until a new exact-SHA
  run passes; macOS developer runs are scratch evidence only.

## Limits

- Linux namespace/UID/capability/TLS behavior is proved only by the GitHub job above; developer
  (macOS loopback) runs are scratch evidence only.
- The 65,536-byte CP framing limit versus the 69,632-byte handler limit is a carried compatibility
  limit; no contract-valid projection submission exceeds 44,098 bytes.
- A worker crash from any cause would still leak `limit_conn` slots (an nginx property); the G9
  worker sentinel makes that visible rather than hiding it.
- Not covered: production bootstrap, workerd/Cloudflare, public DNS and certificates, durable runner
  key custody, the H1–H6 host work and the full customer journey.
