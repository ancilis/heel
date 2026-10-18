# Plan-differential runner

`heel runner run` replays the read routes of your own staging product as two canary
accounts on different plans and compares what each one receives. Where the lower plan
receives every field the higher plan receives, Heel records a finding with
`evidence_state: observed`. No annotation or declaration is needed.

```
heel runner run --scope <scope-id> --base-url https://<host> \
    --as <lower-label>=<credential-handle> --as <higher-label>=<credential-handle> \
    [--routes <imported-inventory>] [--max-ops 50] [--dry-run]
```

The command is CLI only. It is not available through MCP or REST. It cannot create,
widen or re-sign a scope.

## What is sent

- Only `GET` and `HEAD` routes from the inventory that `heel runner import-openapi` wrote.
  An inventory that names any other method is rejected for the whole command.
- **Every planned route costs exactly two requests before retries: one with the lower-plan
  credential, then one with the higher-plan credential.** This holds for `GET` and `HEAD`
  alike. Heel sends no request without one of the two credentials.
- Only to the exact host in `--base-url`, and only when the signed scope lists that host.
  No redirect is followed.
- At most `--max-ops` request attempts in total, retries included (default 50, range 2 to
  100). A lower `max_requests` in the scope wins.
- Every request is written to the containment log, with your CLI user as caller, before it
  is sent.

## Real staging journey

Run these in order. Replace the values in capitals.

```sh
python3 -m venv --copies .venv
. .venv/bin/activate
python -m pip install './heel_sim-1.2.0-py3-none-any.whl[runner]'
export HEEL_HOME="$PWD/.heel"
```

1. Create the signed scope. The allowlist entry is the bare host.

   ```sh
   heel scope create --target staging.example.com --operator "YOUR NAME" --confirm
   ```

2. Bind this `HEEL_HOME` to the staging origin. The first authorized dry-run does this and
   reports `"context": "bound"`. It sends nothing.

   ```sh
   heel runner run --scope SCOPE_ID --base-url https://staging.example.com --dry-run
   ```

3. Register one canary credential per plan. The role is the tier: `lower_plan` or
   `higher_plan`. Each command prints an opaque `credential_handle` and, for the ephemeral
   backends, the environment variable that will carry the secret. The label and the secret
   are never printed.

   ```sh
   heel runner credential add --role lower_plan --profile bearer \
       --label "free canary" --backend ephemeral-env
   heel runner credential add --role higher_plan --profile bearer \
       --label "pro canary" --backend ephemeral-env
   ```

   Profiles are `bearer`, `x_api_key` and `cookie_jar`; both credentials must use the same
   one. Backends are `ephemeral-env`, `ephemeral-fd`, `keychain` and `secret-service`.

   macOS `keychain` stores a credential (up to 16 KiB) as format v2 under the Keychain service
   `heel.runner.canary.v2`: base64 chunk items `<handle>.0`…`<handle>.7` (at most 3072
   characters each) committed by a header item `<handle>` written last and read back before
   the credential is used. Each item is written with one `security -i` command on standard
   input, never in process arguments, because `/usr/bin/security` keeps at most 128 bytes of a
   prompted password and cuts `security -i` lines longer than 4095 bytes. Earlier releases wrote
   `heel.runner.canary.v1` items through the prompted form, which stored them **empty**: Heel
   reads such an item as `secure credential is empty; remove it and add it again` and never
   rewrites it; a non-empty v1 item is still read unchanged. A store interrupted before its
   header leaves chunk items that are not a credential; the next credential recovery deletes
   them (and retries later if the Keychain refuses), and removing a credential deletes the
   header, all eight chunk slots and any v1 item.

   Optional for this standalone CLI, required for the self-serve (Heel Cloud) path:
   `--plan-label <your name for the plan>`, for example `--plan-label free` on `lower_plan`
   and `--plan-label pro` on `higher_plan`. The plan label is your own word, 1–32 printable
   ASCII characters, no leading or trailing space, and different between the two roles; it
   is not a closed list and Heel never infers it from responses. Unlike `--label`, the plan
   label is public and is printed back with its role; the secret never is. Credentials
   registered without it keep working here; `heel runner status` then reports
   `access.incomplete` with reason `plan_label_missing` (or `credential_missing`) and the
   exact command to run.

4. Import the route inventory from your OpenAPI document. Only `GET` and `HEAD` operations
   are kept.

   ```sh
   heel runner import-openapi ./openapi.json
   ```

5. Optional: give one parameterized route its path values. Heel never invents an ID. A
   value beginning `heel-canary-` also opts that route into the protected-marker check
   described in `docs/EXPORT_DEMO.md`.

   ```sh
   printf '{"id":"heel-canary-export-0001"}' > fixtures.json
   heel runner map --scenario plan_entitlement_read --method GET \
       --route '/exports/{id}' --fixture-fd 3 3<fixtures.json
   ```

6. Print the plan. `--as` takes the handles from step 3, lower plan first. The label before
   `=` is your own plan name and has no effect on execution.

   ```sh
   heel runner run --scope SCOPE_ID --base-url https://staging.example.com \
       --as free=LOWER_HANDLE --as pro=HIGHER_HANDLE --dry-run
   ```

   The plan lists every pair, every route that will not run and why, the inventory path
   and digest, and a `plan_sha256`. `requests_sent` is `0`.

7. Run. Supply each secret in the variable printed in step 3.

   ```sh
   HEEL_RUNNER_CREDENTIAL_LOWERHANDLE='free-plan-token' \
   HEEL_RUNNER_CREDENTIAL_HIGHERHANDLE='pro-plan-token' \
   heel runner run --scope SCOPE_ID --base-url https://staging.example.com \
       --as free=LOWER_HANDLE --as pro=HIGHER_HANDLE
   ```

   The result repeats `plan_sha256`, so you can compare it with the dry-run.

8. Read the findings, save one as a regression, and replay it.

   ```sh
   heel findings --run RUN_ID
   heel regress add --run RUN_ID --vector VECTOR_ID --name export-plan-gate
   HEEL_RUNNER_CREDENTIAL_LOWERHANDLE='free-plan-token' \
   HEEL_RUNNER_CREDENTIAL_HIGHERHANDLE='pro-plan-token' \
   heel regress run --target https://staging.example.com --scope SCOPE_ID
   heel log --run RUN_ID
   ```

Exit codes of `heel runner run`: `0` dry-run printed, or executed with no `observed` or
`verified` finding; `1` executed with at least one; `2` rejected before any request; `3`
the host is not in the scope allowlist, so only the plan was printed. Every rejection
prints the one line `Heel runner command was rejected.` and nothing else.

`--routes PATH` takes a saved copy of the inventory file that `import-openapi` wrote (the
dry-run prints its path). The file is the whole allowlist for that invocation. It is not a
selector, and it never replaces the stored inventory.

## Synthetic journey

This runs the same commands against a loopback target shipped with the tests, from a
checkout of this repository. Use two terminals.

```sh
python3 -m venv --copies .venv-synthetic
.venv-synthetic/bin/python -m pip install -e '.[runner]'
export HEEL_HOME="$PWD/.heel-synthetic"
export PLAN_DIFFERENTIAL_HARNESS_PORT_FILE="$PWD/.heel-synthetic.port"
```

Terminal 1 starts the target. It prints one line per request it receives.

```sh
.venv-synthetic/bin/python tests/plan_differential_harness.py serve
```

Terminal 2, with the same two exports. `HARNESS` runs the unmodified `heel` CLI in-process
with the one seam described below.

```sh
HARNESS=".venv-synthetic/bin/python tests/plan_differential_harness.py heel"
ORIGIN=https://plan-differential-synthetic.heel.dev

.venv-synthetic/bin/heel scope create --target plan-differential-synthetic.heel.dev \
    --operator "synthetic operator" --confirm
$HARNESS runner run --scope SCOPE_ID --base-url $ORIGIN --dry-run
$HARNESS runner credential add --role lower_plan --profile bearer \
    --label "free canary" --backend ephemeral-env
$HARNESS runner credential add --role higher_plan --profile bearer \
    --label "pro canary" --backend ephemeral-env
$HARNESS runner import-openapi tests/fixtures/plan_differential/openapi.json
$HARNESS runner run --scope SCOPE_ID --base-url $ORIGIN \
    --as free=LOWER_HANDLE --as pro=HIGHER_HANDLE --dry-run
```

In `zsh`, run `setopt shwordsplit` first or type the harness command in full. Terminal 1
has printed no request line so far. Now run, using the two variables printed by
`credential add`:

```sh
HEEL_RUNNER_CREDENTIAL_LOWERHANDLE=synthetic-free-session-0001 \
HEEL_RUNNER_CREDENTIAL_HIGHERHANDLE=synthetic-pro-session-0001 \
$HARNESS runner run --scope SCOPE_ID --base-url $ORIGIN \
    --as free=LOWER_HANDLE --as pro=HIGHER_HANDLE
```

Expected: exit code `1`; `GET /api/export` has verdict `finding`, predicate
`body_superset`; `GET /api/reports` is `held`; `GET /api/billing` is `inconclusive`
(`lower_denial_envelope`); `HEAD /api/export` is `inconclusive` (`head_status_only`);
`GET /api/redirect` and `GET /api/text` are `inconclusive`
(`transport:response_rejected`). The OpenAPI fixture carries no plan metadata.

```sh
.venv-synthetic/bin/heel findings --run RUN_ID
.venv-synthetic/bin/heel regress add --run RUN_ID --vector VECTOR_ID --name export-plan-gate
HEEL_RUNNER_CREDENTIAL_LOWERHANDLE=synthetic-free-session-0001 \
HEEL_RUNNER_CREDENTIAL_HIGHERHANDLE=synthetic-pro-session-0001 \
$HARNESS regress run --target $ORIGIN --scope SCOPE_ID
```

Use the `id` of the `GET /api/export` finding as `VECTOR_ID`. The replay reports
`"result": "fail"`, `"current_status": "still_reachable"`. Stop the target in terminal 1
with Ctrl-C, start it again with the plan gate in place, and repeat the `regress run`
command:

```sh
.venv-synthetic/bin/python tests/plan_differential_harness.py serve --behavior hardened
```

The replay now reports `"result": "pass"`, `"current_status": "blocked"`. The other
behaviors are `envelope` (the lower plan gets `200 {"error": ...}`) and `subset` (a `200`
with fewer fields); both replay as `fail` / `inconclusive`.

### The one test seam

The harness and the tests replace exactly one module attribute,
`heel.runner.plan_differential._build_client`, with a factory that returns the real
`TargetHTTPSClient` over three test objects: a resolver that returns a fixed public
address, a socket connector that dials the loopback target, and a pass-through in place of
TLS. No argument, environment variable, file or scope field can set this seam.

With the seam in place, request construction, the `Host` header, framing, redirect
refusal, body rules, the compiler checks, the gate, the budget, the attempt reservation,
evidence storage, redaction, the predicates and the logging are all product code. **The
seam proves nothing about TLS, DNS answers or address selection.** Those are covered
separately: one test builds the production client with no seam and checks that
certificate verification, hostname checking and default trust loading are on, and one
test performs a real TLS handshake between the real `TLSTransport` and a loopback server
with a certificate from a CA generated in the test. No test makes a real public HTTPS
request.

## Reading the result

| Verdict | `evidence_state` | Meaning |
|---|---|---|
| `finding`, predicate `marker_leak` | `verified` | The lower plan's response contained the protected marker you supplied. |
| `finding`, predicate `body_superset` | `observed` | The lower plan received every field the higher plan received on this one read. |
| `held` | none stored | The higher plan succeeded and the lower plan was refused by status (401, 402, 403 or 404), or the marker was absent. |
| `inconclusive`, predicate `status_parity`, `candidate: true` | `inconclusive` | Both plans got a 2xx but the bodies do not show the lower plan received the same content. |
| `inconclusive` | `inconclusive`, or none stored | Anything else. The `reason` says why. |

- `observed` is a hypothesis about a missing plan gate. Heel holds no declaration that a
  route is plan-gated, so a route that is ungated by design is reported too.
- A 2xx response whose body says no (`error`, `errors`, `ok: false`, `success: false`,
  `upgrade_required`, `payment_required`, `denied`, `forbidden`) is never counted as
  parity, never as `held` without a marker, and never as a regression pass.
- A `HEAD` pair compares statuses only. It can be `held` or `inconclusive`, nothing else.
- A finding is stored only for a pair that completed. A pair that did not complete is in
  the result's `pairs` and in `report.json` as `inconclusive` with its true disposition.
- A regression passes only when the lower plan is denied by status (or the marker is
  absent) while the higher plan still succeeds. It replays only under the same,
  still-valid scope, against the same origin, with the same two handles in the same order.
- Raw responses stay in the private attempt store under
  `$HEEL_HOME/plan-runs/<attempt>/`, with both credentials replaced by
  `[REDACTED:secret]`. The report at `report_path` holds references only. Nothing is
  uploaded.

## Pairing with Heel Cloud (`pair`, `status`, `serve`, `unpair`)

```sh
heel runner pair --origin https://<heel origin> --invite <one-time invitation>
heel runner status            # live check over the claim chain; --offline skips it
heel runner serve             # stay online until stopped or revoked; --once polls once
heel runner unpair
```

`pair` uses the existing ceremony: the dashboard's one-time invitation (10 minutes) →
exchange → the runner prints six words and a key fingerprint → the owner compares both in
the browser and approves → the runner activates and prints `"state": "active"`. Output is
JSON lines; failures print one fixed line `Heel runner pairing failed: <reason>.` and never
echo the invitation, responses or keys. A reused, expired or unknown invitation reports
`invitation_rejected`; an unapproved pairing reports `approval_timeout` (run `unpair`, then
pair with a new invitation).

- The Ed25519 key seed is generated into and kept only in macOS Keychain or the Linux
  secret service (`secret-tool`). Without either, `pair` fails with
  `no supported runner OS secret service`; there is no file fallback and no flag or
  variable that selects another store.
- On macOS the seed is written with one `security -i` command on standard input (never in
  process arguments) and is kept only after it reads back as exactly the generated seed;
  otherwise the new item is deleted and `pair` fails closed. Earlier releases stored an
  **empty** Keychain item (the prompted `security … -w` form reads its value twice); such an
  item is reported as `local_identity_unavailable` or `no supported runner OS secret service`
  and is never rewritten. Recover with `heel runner unpair` (it deletes the item) and pair
  again with a new invitation.
- `$HEEL_HOME/runner-daemon/pairing.json` holds public coordinates only: the pinned origin,
  the random installation ID naming the secret-store account, the cloud-assigned IDs and the
  cloud's grant-signing public key (`grant_authority_key_id`, `grant_authority_public_key_b64`).
  The signed pairing journal, paired identity and claim cursor are the existing runner
  store and runtime records.
- **Cloud grant authority.** The activation the owner approved
  (`heel.runner-pairing-activated.v4`; `control_protocol` stays `heel.runner-control.v2`)
  carries `grant_authority: {key_id, public_key_b64}`: the raw 32-byte Ed25519 public key of
  the control plane's own configured grant-signing authority, whose key ID must be derived
  from the key. It is public material; it is the key the runner will use to verify context
  bindings and grants the cloud signs. The runner never fetches it separately and there is
  no flag or variable that supplies another key. A control plane without a configured
  authority refuses new activations. The control plane replays a stored activation receipt
  exactly as stored, including a receipt stored before this change (`v3`, no key), and never
  rewrites it.
- **Key rotation requires re-pairing.** The control plane signs with one grant key
  (`HEEL_GRANT_SIGNING_KEY_ID`). After it changes, every paired runner holds the old public
  key: `unpair`, then pair with a new invitation. This is a launch limitation, not a promise
  of automatic re-trust.
- **Version mismatch fails closed.** This runner accepts only a `v4` activation. Against a
  control plane that answers `v3`, and for the runner in the pre-grant-authority download
  artifact (which accepts only `v3`) against a control plane that answers `v4`, `pair` fails with `response_rejected` and nothing is
  downgraded. This is a closed failure, **not** backward compatibility: the control plane has
  already activated the pairing, so Heel Cloud lists an **active** runner that no local
  runner can use, and it stays active after the local `unpair`. It counts against the
  workspace's runner quota, so an owner must revoke it in Heel Cloud before a retry can
  activate; then `unpair` and pair once both sides match. Both that artifact and the current
  one report version `1.2.0`, so the version string does not tell them apart: the `v3`-only
  wheel is the one committed before this change (commit `b426fc2`, sha256
  `4dd9eec27ee57df187ccb5664a816cc3fdc17f6f132c166ab8d27bb1b6c428bf`). Whether anyone
  installed it is unknown; this path is tested, not assumed unused.
- Control traffic goes only to the `--origin` given at pairing: `https://` only, exact
  pathless lowercase origin, system trust with TLS 1.2 or newer and hostname checks, no
  redirects, no proxies, at most 256 KiB of JSON per response, one 30-second deadline per
  call covering connect (all resolved addresses together), TLS handshake, request, status
  line, headers and body, however slowly the peer sends. Host name resolution by the system
  resolver cannot be interrupted: a resolver slower than the deadline extends the call by its
  own duration, after which the call fails with `timeout` without connecting or sending. There
  is no CA-bundle flag or variable (the same `SSL_CERT_FILE` caveat below applies).
- `status` reports `active`, `offline` (control plane unreachable), `runner_revoked` (the
  control plane rejects the runner key), `pairing_incomplete`, `local_identity_unavailable`,
  `cloud_authority_missing` or `unpaired`, plus the self-serve access state.
  `cloud_authority_missing` means the record was written by a runner paired before the grant
  authority was delivered (or its key does not match its key ID); it is reported without any
  network call or secret-store access, with the next steps `heel runner unpair` and
  `heel runner pair --origin <origin> --invite <new token>`. Such a record still loads, `pair`
  still refuses it as `already_paired`, and `unpair` removes it and its seed. A record with
  only one of the two key fields is `local_state_invalid`. `unpair` refuses while a context binding
  is installed; it removes the local identity and the OS-stored seed but cannot revoke the
  runner in Heel Cloud. An owner or admin revokes it there from a recent same-origin browser
  session with `POST /v1/workspaces/{ws}/runners/{id}/revoke` and the body
  `{"schema_version":"heel.runner-revoke.v1","reason_code":"<reason>"}`; the reason and actor
  are audited, a repeat is refused, and the runner's next `status` reports `runner_revoked`.
  The dashboard has no runner-revoke control yet.
- Pairing alone authorizes no target traffic, and neither does `serve` (below).

### `heel runner serve`

`serve` keeps the paired runner online with the control plane. It polls over the existing
signed claim chain every 2 seconds (`contexts/list`, then `claim` once a binding is
installed); every call is a PoP-signed `POST` to the pairing origin and none is target
traffic. The trust anchor is only the grant-authority key in `pairing.json`; a record
without a consistent key exits `cloud_authority_missing` before any secret-store access or
network call, and there is no flag or variable that supplies another key.

Order of onboarding: `pair` → `serve` → the owner authorizes the runner for one verified
environment in Heel Cloud → `serve` claims that cloud-signed context binding and installs it
→ `heel runner credential add --role lower_plan --plan-label <name> …` and the same for
`higher_plan` (refused before the binding exists) → `status` reports `access.ready`. Plan
labels, never credential handles or values, appear in `status` and in `serve` output.

Output is JSON lines (`serve_state` events, then `serve_stopped`); failures print one fixed
line `Heel runner serve stopped: <reason>.` and never a traceback, response body or key.
Exit codes: `0` stopped (SIGINT, SIGTERM or `--once` done), `1` offline (`--once` only),
`2` failed closed, `3` revoked.

- **One serve per `HEEL_HOME`.** `serve` holds a non-blocking kernel `flock` on
  `$HEEL_HOME/runner-daemon/.serve.lock` (no symlink, single link, mode 0600, never
  unlinked). A second `serve` exits `already_serving` at once; `unpair` refuses
  `serve_running` until the serve has stopped. The kernel releases the lock when the process
  ends, including `SIGKILL`; no PID is ever trusted. `status` and `credential add` work while
  serving; `status` does not make its own control call then (the serve owns the claim chain)
  and reports `control_plane: not_checked, reason: serve_running`.
- **Visible state.** `$HEEL_HOME/runner-daemon/serve-state.json`
  (`heel.runner-serve-state.v1`: `state` ∈ starting, online, offline, revoked, stopped,
  failed; `runner_id`, `since_ms`, `updated_at_ms`, `last_error_code`, `binding_id`,
  `access` (labels only), informational `pid`). `status` shows it under `serve`, and only
  while the lock is held does it describe a running serve; otherwise it is reported as
  `not_running` with the last state, so a file left by a crash never implies a live process.
  It is never authority for anything. `unpair` removes it.
- **Offline and resume.** A connection failure, a timeout or an edge answer that its control
  plane is unreachable (`502`/`503`/`504`) marks the serve `offline` and retries with
  exponential backoff from 2 s to 60 s (±25 % jitter), interruptible by a signal. Each retry
  rebuilds the coordinator, which first replays any staged signed call exactly; the serve is
  `online` again only after a new authenticated answer. Each failure is classified from the
  exception the failing call raised, never from transport state another call may have set.
- **Closed failures, no retry.** `401 invalid_runner_auth` → `revoked` (exit 3, no further
  call). `403 runner_protocol_upgrade_required` → `protocol_upgrade_required`. Any other
  status, a malformed answer, a non-advancing server time or a regressed control generation →
  `response_rejected`; local store/runtime problems → `local_state_invalid`. Before each cycle
  the pairing record is re-read and must still name the same pairing.
- **Stop.** SIGINT/SIGTERM end the idle wait or backoff at once and request the existing
  local stop of any in-flight work. A control call already in progress finishes first (its
  30-second deadline applies, and system name resolution can extend it, see above); the serve
  keeps the lock until its own workers can make no further call.
- **No execution yet.** `serve` executes nothing. If a run is ever claimed (only reachable
  through a legacy catalog projection a human submitted and approved), `serve` exits
  `execution_unavailable` without acknowledging, heartbeating or sending any target request;
  the server's reaper ends that run. The local runtime may keep that run's sealed record, in
  which case a later `serve` is expected to fail closed `local_state_invalid` until the runner
  is re-provisioned (separate `HEEL_HOME`, re-pair); this restart path is not yet tested.
  Revocation therefore cannot yet be shown to
  stop target traffic; that is proven when execution exists.
- **Unpair after a binding: open gap, no recovery path yet.** Once a context binding is
  installed, `unpair` refuses `context_bound` (unchanged) and `pair` refuses the same
  `HEEL_HOME`. There is no product command that retires the bound context, its credential
  items in the OS secret store or the pairing seed; a new `HEEL_HOME` leaves all of them
  behind. Retirement is being designed separately and is not part of this release.

## Trust boundary

The operator's process environment and `HEEL_HOME` are inside the trust boundary. The
environment already supplies the credentials (`HEEL_RUNNER_CREDENTIAL_<HANDLE>`), the data
directory and the user name recorded as caller.

Trust anchors for TLS are the default locations of the Python build's TLS library, loaded
with `load_default_certs()`. **`SSL_CERT_FILE` and `SSL_CERT_DIR` in the process
environment change those locations.** Someone who controls that environment can choose
the CA set. Heel does not defend against that.

What Heel guarantees is narrower: no Heel argument, Heel variable, inventory file or scope
field changes the transport, resolver, port or trust store, and certificate and hostname
verification are always on.

Target ownership is asserted only by the operator's signed local scope.

## Limits

Inherited from the existing runner transport:

- Public HTTPS staging hosts only: port 443, public addresses, a hostname under an IANA
  top-level domain. Private-network, loopback and custom-port staging are not reachable.
- TLS 1.2 only. No redirect is followed.
- Responses must carry `Content-Length`, use no transfer or content encoding, and be empty
  or one JSON object of at most 256 KiB. Chunked, compressed, array and non-JSON responses
  make the pair `inconclusive`.
- One mapping per scenario, so at most one parameterized route (`GET` or `HEAD`) can be
  given fixture values. Other parameterized routes are listed as `not_executed`.

Chosen for this phase:

- One staging origin per `HEEL_HOME`. Two plans. One credential per plan role.
- Every route, `GET` or `HEAD`, costs exactly two requests before retries. Heel sends no
  unauthenticated request.
- `heel runner map` and `heel runner prepare` now accept a `HEAD` mapping for
  `plan_entitlement_read`.
- Bearer and API-key values, and cookie values, shorter than 8 bytes are refused because
  they cannot be redacted reliably. Redaction matches a credential in its raw form and in
  its JSON-string form; other encodings of an echoed credential are not matched.
- An `ephemeral-env` or `ephemeral-fd` credential is consumed when it is read, once per
  process. `heel regress run` therefore replays one plan-differential regression per
  invocation with such credentials; a second one in the same invocation is `fail` /
  `inconclusive` and sends nothing.
- Credentials registered before this command existed have handles that were never
  displayed. Use a fresh `HEEL_HOME`.
