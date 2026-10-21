# Host ingress proof (H0B, `ingress-v1`)

Status: source/configuration candidate. The dynamic Linux proof has not yet run on this candidate.
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
them. The policy therefore enforces totals itself:

- body read: 10 s from the access handler's entry (runner listener and management POST);
- validation plus upstream response: 25 s from the access handler's entry (runner listener).

Both use one primitive (H0BTD section 5.1):

```js
function deadline(r, ms, status, reason) {
    const d = { fired: false, id: null };
    d.id = setTimeout(() => {
        d.fired = true;
        try { count('expired:' + reason); } catch (e) {}
        try { sendRefusal(r, status, reason); } catch (e) {}
        setTimeout(() => {}, 0);        // flush the posted terminate now
        throw new Error('deadline');    // -> NGX_ERROR -> ngx_http_terminate_request
    }, ms);
    return d;
}
function settle(d) { if (!d.fired) clearTimeout(d.id); return d.fired; }
```

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
is deleted, and a static test allows `clearTimeout()` only inside `settle()` and forbids
`Promise.race`.

This primitive relies on pinned njs internals (timer handler order, exception to `NGX_ERROR`,
zero-delay timer running posted requests). The runtime lock records that dependency. **Any change
to the nginx, njs or QuickJS pin must re-run the G8 deadline gates and the G9 worker sentinel on
the Linux proof job before review.** Results from macOS (kqueue) do not carry over to Linux
(epoll).

## Gates

| Gate | Content |
|---|---|
| G0 | Runtime/API compatibility in the real njs/qjs: pinned NFC tables (QuickJS lacks `normalize`), strict UTF-8 and the canonical JSON scanner |
| G1 | The compiled Worker reaches CP only through the fixed binding destination with TLS name and Host H; no redirect following |
| G2 | Management boundary: real session/Origin checks through nginx; wrong edge secret, peer, route or header class refused before CP |
| G3 | Real pairing, exchange, approval, activation, context claim, projection submission, human run approval, claim with the unchanged grant verifier, heartbeat/progress/resync/restart, stop-ack, terminal result, registered rotation; repeated on SQLite |
| G4 | TLS trust/name/SNI/Host/alias negatives; wrong runner key; forged grant from another key fails the unchanged verifier |
| G5 | Cross-slot identity swaps, registry faults, phase gates; well-formed forgeries reach CP and fail without state change |
| G6 | Invitation reuse, exact retained retries, mutated retries, stale and superseded requests |
| G7 | Raw HTTP: duplicates, folding, framing, encodings, targets and methods refused on the real wire without CP contact |
| G8 | Caps and boundaries (including the carried 65,536 CP framing limit), truncated and extra bytes, slow headers, scripted response negatives; total deadlines: runner and management dribble refused at 10.0–10.5 s, body complete at 9 s forwarded and at 11 s refused, late body gives one response and no CP contact, eight held slots released by 10.5 s, slow upstream cut at 25.0–25.5 s with the backend seeing EOF before 26 s, a paced in-budget reply delivered unchanged, mixed expiring and valid load |
| G9 | No sibling/CP/management reach from a slot, no default route, runner processes without capabilities, ingress worker PID unchanged across the whole module, owned processes and namespaces removed |

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

## Limits

- Linux namespace/UID/capability/TLS behavior is proved only by the GitHub job above; developer
  (macOS loopback) runs are scratch evidence only.
- The 65,536-byte CP framing limit versus the 69,632-byte handler limit is a carried compatibility
  limit; no contract-valid projection submission exceeds 44,098 bytes.
- A worker crash from any cause would still leak `limit_conn` slots (an nginx property); the G9
  worker sentinel makes that visible rather than hiding it.
- Not covered: production bootstrap, workerd/Cloudflare, public DNS and certificates, durable runner
  key custody, the H1–H6 host work and the full customer journey.
