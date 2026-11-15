# Controlled staging target (synthetic acceptance fixture)

A tiny standalone Cloudflare Worker that stands in for a customer's staging SaaS during the
real customer-local Heel journey. It is a test fixture: not Heel product code and not Heel's
control plane. It is not inside the Heel runner package: the wheel and source archive exclude
`tests/` (`scripts/build_open_core_release.py`). Its four files are distributed separately, as
the `heel-staging-fixture-*` assets of the Heel 1.3.0rc6 runner preview prerelease, next to a
manifest of their sizes and SHA-256 digests. It has no bindings, storage, outbound fetch,
redirect, dependency or paid feature, and serves only static fake data.

## Standalone files

Deploying the target needs only these four files, extracted together into one directory. No
repository checkout, git metadata, Heel source or `node_modules` is needed:

| File | Bytes | sha256 |
|---|---|---|
| `worker.mjs` | 13120 | `b0d8c1f426986ab613c1f4ca46302607c249cf4a7bcb47c415ac747b552d3bf3` |
| `wrangler.jsonc` | 765 | `9c33fbf3092722dbfde0f09d6ff68557a07e6cb7379c9e2d72509faaf46b988a` |
| `openapi.json` | 2282 | `520288872cee2480168063427ce616e7ee15aa9931c8d0ec40029899f7c13f19` |
| `README.md` | this file | |

Check them before deploying (`shasum -a 256 worker.mjs wrangler.jsonc openapi.json README.md`).
The publisher of these files states one explicit source version with them: the 40-character
lowercase hex commit they were taken from. The steps below call it `SOURCE_REVISION`; the
target reports it at `/healthz`. Do not guess it, and do not use `git rev-parse` in an
extracted copy. `target.test.mjs` and the repository paths named below (`heel/runner/...`,
`tests/...`) are repository-only background; deployment does not need them.

### Download without a checkout

The files are published as assets of the GitHub prerelease
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc6>, each under the prefix
`heel-staging-fixture-`, with `heel-staging-fixture-manifest.json` listing every file's asset name,
original name, byte count and SHA-256. The release notes state `SOURCE_REVISION` and repeat the
same table, including this README's digest. Download them anonymously into one new directory under
their original names:

```sh
mkdir heel-staging-target && cd heel-staging-target
B=https://github.com/ancilis/heel/releases/download/v1.3.0rc6
for F in README.md openapi.json worker.mjs wrangler.jsonc; do
  curl -fsSL --proto '=https' --proto-redir '=https' -o "$F" "$B/heel-staging-fixture-$F"
done
curl -fsSL --proto '=https' --proto-redir '=https' -o heel-staging-fixture-manifest.json "$B/heel-staging-fixture-manifest.json"
shasum -a 256 README.md openapi.json worker.mjs wrangler.jsonc   # compare with the manifest and release notes
```

Stop if any digest differs. No git, repository checkout, Heel source, private configuration or
helper is needed, and nothing here grants access to a target: the prerequisites below remain the
operator's.

It closes three target prerequisites of the older loopback harness
(`tests/plan_differential_support.py`): it is reachable over ordinary public HTTPS once
deployed (T-1), serves an ownership-proof file (T-2), and has a `patched` mode whose refusal the
existing matcher can decide (T-3). The export payload, the `{"error": "upgrade required"}`
envelope and the marker id are reused from that harness.

The target serves the same export through two export routes. They share the same digest-only auth and
operator-controlled mode, and differ only in the payload and in which Heel path can decide them.

**Ordinary route: `GET`/`HEAD /api/export`** (no path parameter, no marker). This is the
route for *ordinary plan-differential exposure*: the unchanged markerless comparator
(`heel/runner/plan_differential.py` `evaluate_plan_pair`, `marker=None`) compares the
free and pro responses' JSON key paths. Its mapping has **empty fixture bindings**. The paired
canary evaluator (`adapters.evaluate_pair`) has no marker here and stays `inconclusive` in
every mode. Body (pro, and free in `vulnerable`): the original 47ab432 payload, 97 bytes, sha256
`a0dacf6ab6bf8e510e7d114137046acd91d209ef04fd448a0a4cbf596ca2c0aa`:
`{"account_id":"acct_canary","format":"csv","rows":[{"id":"row_1","amount_cents":1200}],"total":1}`.

**Canary route: `GET`/`HEAD /api/exports/{id}`** (*canary-dependent paired read validation*).
The paired runner (`heel/runner/execution.py`) learns the protected marker solely from a route
fixture binding whose id starts with `heel-canary-`, and decides a read only when that exact
marker appears in the top-level `protected_canary` field of the response. It does not infer
anything from arbitrary response bodies. So this route is served only for the one approved
synthetic id `heel-canary-export-0001`, and its export carries that id as `protected_canary`.
The marker is public, fake and not a secret; it appears in this route's response body and
path, never in the ordinary body or the OpenAPI document. Body: 142 bytes, sha256
`32dcd0f899e627cf3d7c41cedf3a1ad67aba36523af5e404a71312304b3c28aa`:
`{"account_id":"acct_canary","format":"csv","rows":[{"id":"row_1","amount_cents":1200}],"total":1,"protected_canary":"heel-canary-export-0001"}`.

**Authentication read route: `GET`/`HEAD /api/auth-records/{id}`** (*anonymous vs
authenticated read*, catalog scenario `anonymous_authenticated_read`). The export routes refuse
every missing, malformed or unknown credential with the `401 {"error":"unauthenticated"}`
envelope in every mode. The content predicate correctly treats that envelope as inconclusive,
so those routes cannot show a decisive anonymous `blocked` or `observed` result. This route
fills that gap. It is served only for the one approved synthetic id `heel-canary-auth-0001`
and uses the same operator mode and the same two configured digests (no new secret). Body:
130 bytes, sha256 `e05f9db1b4cde34ee1a00b4077f2e541ade727d9208c8ba58427ec809a9489d2`:
`{"record_id":"rec_canary","account_id":"acct_canary","display_name":"Synthetic Record","protected_canary":"heel-canary-auth-0001"}`.

**Read-boundary routes: `GET`/`HEAD /api/private-record` and `GET`/`HEAD /api/profile`**
(ordinary markerless reads; **added after the deployment recorded before these files were
published**). See [Ordinary read-boundary routes](#ordinary-read-boundary-routes) below.

None of the routes is a coverage claim. Each one exercises a single synthetic read on this fixture.

`openapi.json`: 2282 bytes, sha256 `520288872cee2480168063427ce616e7ee15aa9931c8d0ec40029899f7c13f19`.
(Historical: the deployed three-path inventory was 1575 bytes, sha256
`38eeb21edaf16cefeff573c97aca50e1be56cafeb11c78736a2b04848e8ec132`.)

## Contract

| Route | Methods | Behavior |
|---|---|---|
| `/.well-known/heel-verify.txt` | GET, HEAD | `200 text/plain`, body = `HEEL_VERIFY_TOKEN` + `\n`; `503` if unset or not 16-512 printable ASCII. No setter. |
| `/api/export` | GET, HEAD | Ordinary export (97 bytes, no marker). `Authorization: Bearer <token>`; the SHA-256 of the token must equal exactly one configured digest. Missing/malformed/unknown → `401 {"error":"unauthenticated"}`. |
| `/api/exports/heel-canary-export-0001` | GET, HEAD | Canary export (142 bytes, `protected_canary`). Same auth and modes as `/api/export`. |
| `/api/auth-records/heel-canary-auth-0001` | GET, HEAD | Auth record (130 bytes, `protected_canary`). Either configured identity → `200` record in every mode. Malformed/unknown credential → `401 {"error":"unauthenticated"}` in every mode. **No** `Authorization` header → depends on mode (table below). |
| `/api/private-record` | GET, HEAD | Ordinary record (94 bytes, no marker). Either configured identity → `200` in every mode. Malformed/unknown credential → `401 {"error":"unauthenticated"}` in every mode. **No** `Authorization` header → depends on mode (read-boundary table). |
| `/api/profile` | GET, HEAD | Ordinary profile with one pro-only leaf (no marker). Pro → `200` full (114 bytes) in every mode. Free → depends on mode (read-boundary table). Missing/malformed/unknown → `401 {"error":"unauthenticated"}` in every mode. |
| `/healthz` | GET, HEAD | `{"status","mode","revision","ownership_configured","export_configured"}` only. |
| `/openapi.json` | GET, HEAD | `200 application/json`, byte-identical to `openapi.json` here, so a clean-room user can download the inventory without repository access. |
| any other path (including any other export or record id) | any | `404 {"error":"not found"}`; the path is never reflected. |
| known path | other methods | `405`, `Allow: GET, HEAD` |

The served inventory (`info.version` `1.3.0`) lists only `GET`/`HEAD /api/export`,
`GET`/`HEAD /api/private-record` and `GET`/`HEAD /api/profile` (no parameter),
`GET`/`HEAD /api/exports/{id}` and `GET`/`HEAD /api/auth-records/{id}` (each an
ordinary required `string` path parameter): no ownership, health or spec endpoint, no marker
value, no example value, and no plan, privilege, criterion, finding, security or `x-` annotation.

All five gated read routes fail closed with `503` unless `HEEL_TARGET_MODE` is a known mode and
`HEEL_FREE_TOKEN_SHA256` / `HEEL_PRO_TOKEN_SHA256` are two different 64-character lowercase hex
digests. The mode is set only by the operator at deploy time; no header, query or cookie
changes it. On the two export routes the pro identity always receives that route's export
(positive control). All routes use the same mode on every request.

| `HEEL_TARGET_MODE` | free identity receives (either export route) | Comparator (`evaluate_plan_pair`, `marker=None`), both routes | Paired canary evaluator (`adapters.evaluate_pair`), `/api/exports/{id}` only |
|---|---|---|---|
| `vulnerable` | `200` + that route's full pro export | finding, `body_superset` (row 6) | `observed` |
| `patched` | `403`, empty body | held, `lower_denied` (row 7) | `blocked` |
| `error_envelope` | `403 {"error":"upgrade required"}` | inconclusive, `lower_denial_envelope` (row 9) | `inconclusive` |

On `/api/export` the paired canary evaluator is `inconclusive` in every mode (no marker).

On `/api/auth-records/heel-canary-auth-0001`, only a request with no `Authorization` header
depends on the mode. The authentication-read evaluator (`adapters.evaluate_pair`,
`anonymous_authenticated_read`, anonymous action first and authenticated action second) gives:

| `HEEL_TARGET_MODE` | anonymous (no `Authorization`) receives | authenticated (free or pro) receives | Evaluator |
|---|---|---|---|
| `vulnerable` | `200` + the full record | `200` + the record | `observed` |
| `patched` | `401`, empty body, `WWW-Authenticate: Bearer` | `200` + the record | `blocked` |
| `error_envelope` | `401 {"error":"unauthenticated"}` | `200` + the record | `inconclusive` |

On this route `HEAD` is `inconclusive` in every mode. An unknown or malformed credential on the
authenticated side (failed positive control), or any other record id (`404`), is also
`inconclusive`. Malformed or unknown credentials never receive the record in any mode.

`HEAD` is never a finding on either route. The comparator gives status parity only (row 8,
`inconclusive`) in `vulnerable`, and a status-only hold (row 7, `held`, `body_superset` null) in
`patched` and `error_envelope`, where free gets `403` and pro `200`. The paired canary evaluator is
`inconclusive` for `HEAD` in every mode. It is also `inconclusive` when the positive control
fails (pro identity denied or unauthenticated) or when no `heel-canary-` id is bound.

### Ordinary read-boundary routes

These two routes, with the unchanged `/api/export`, give three distinct ordinary, markerless
expected rules on allowed reads:

| Route | Expected rule |
|---|---|
| `/api/private-record` | authentication: the record requires a configured identity |
| `/api/export` | whole-feature entitlement: the whole export requires pro (unchanged) |
| `/api/profile` | field-level redaction: both plans read the profile, `profile.billing_contact` requires pro |

They do **not** demonstrate tenant escape, object lifecycle, quotas, writes or broad business-abuse
coverage. Neither body has a `protected_canary` field, a `heel-canary-` id or any Heel label. Root
`account_id` `"acct_canary"` is an ordinary property that a customer may configure as its own
success witness; it is not a built-in detector marker. The fixture never emits a finding, verdict
or score, and no header, query or cookie (including one claiming a finding, marker, plan or mode)
changes a response. Same digests, same operator mode, same no-store/nosniff framing, same
`HEAD` semantics (status and `Content-Length` of the `GET`, empty body) and same bounded receipts
(`route` is `/api/private-record` or `/api/profile`) as the other routes. No new mode, secret or
public mutation endpoint: any other method is `405`, any near-miss path `404`.

Bodies:

- record, 94 bytes, sha256 `bef7297c0db3a782d68e477482da4a858809d18563558fed1cd5e834cff39a27`:
  `{"account_id":"acct_canary","record_id":"rec_0001","title":"Example record","status":"active"}`
- full profile, 114 bytes, sha256 `f42fd1ddbcacce2d71ba55956a6cd33b7cd9fcb7ed692db5be467befb8685326`:
  `{"account_id":"acct_canary","profile":{"display_name":"Example account","billing_contact":"billing@example.test"}}`
- redacted profile, 73 bytes, sha256 `d29afc7c736617342b0a9a5c6cb58879d00a32873065e36c230eb7213c6a9a71`:
  `{"account_id":"acct_canary","profile":{"display_name":"Example account"}}` (parent `profile`
  object kept, so the leaf's absence is decidable)

All values are fake; `billing@example.test` is a reserved-domain placeholder.

`/api/private-record`:

| `HEEL_TARGET_MODE` | no `Authorization` header | free or pro identity | malformed or unknown credential |
|---|---|---|---|
| `vulnerable` | `200` + record | `200` + record | `401 {"error":"unauthenticated"}` |
| `patched` | `401`, empty body, `WWW-Authenticate: Bearer` | `200` + record | `401 {"error":"unauthenticated"}` |
| `error_envelope` | `401 {"error":"unauthenticated"}` | `200` + record | `401 {"error":"unauthenticated"}` |

`/api/profile`:

| `HEEL_TARGET_MODE` | free identity | pro identity | missing, malformed or unknown credential |
|---|---|---|---|
| `vulnerable` | `200` + full profile (leaf leaked) | `200` + full profile | `401 {"error":"unauthenticated"}` |
| `patched` | `200` + redacted profile (leaf withheld) | `200` + full profile | `401 {"error":"unauthenticated"}` |
| `error_envelope` | `403 {"error":"upgrade required"}` (no profile data) | `200` + full profile | `401 {"error":"unauthenticated"}` |

`target.test.mjs` covers these matrices in-process only (component proof). It does not run any
Heel evaluator on these two routes; which Heel path decides them, and how, belongs to the
upcoming configurable-read acceptance, not to this fixture.

The prerequisites a public-only reviewer needs are listed under
[Prerequisites](#prerequisites-declared-not-provided-by-these-files).

### Configured tests on this fixture

These are the guide's examples: two comparisons applied to three ordinary access rules, not
three detectors and not complete coverage of any rule. Every test uses `GET` (a field condition
on `HEAD` is always inconclusive) and the success check: field `account_id` equals the local
value `expected_account`, entered on the runner as text `acct_canary`.

| Test | Comparison (restricted → control) | Route | Condition |
|---|---|---|---|
| authentication | anonymous → signed-in (free or pro credential) | `/api/private-record` | `record_id` is present |
| field-level redaction | lower plan (free) → higher plan (pro) | `/api/profile` | `profile` › `billing_contact` is present |
| whole-feature entitlement | lower plan (free) → higher plan (pro) | `/api/export` | `rows` is present |

Expected outcome per mode, derived from the response tables above and the configured evaluator,
**not recorded**:

| `HEEL_TARGET_MODE` | `/api/private-record` | `/api/profile` | `/api/export` |
|---|---|---|---|
| `vulnerable` | `observed` (anonymous `200` record) | `observed` (free gets the leaf) | `observed` (free gets the export) |
| `patched` | `blocked` (empty `401`) | `blocked` (free `200` profile, leaf withheld) | `blocked` (empty `403`) |
| `error_envelope` | `inconclusive` (JSON `401`) | `inconclusive` (JSON `403`) | `inconclusive` (JSON `403`) |

Runner side, with the released runner's installed path `./heel-rc6/bin/heel`, which the
guide's one hash-pinned install command creates in an empty private directory (Python 3.11 or
newer; Apple silicon macOS or Linux x86_64/aarch64):

```sh
python3 -m venv heel-rc6 && ./heel-rc6/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc6/heel_sim-1.3.0rc6-py3-none-any.whl#sha256=bf1bf975fd970bc79c2fdf711d5113f852fa72549fbc0117f47e12e205e5403e' && ./heel-rc6/bin/heel --version
```

Use `--backend secret-service` instead of `keychain` on Linux. Credentials come from the operator's Keychain items (step 1 below) over a
file descriptor, never argv; the value `acct_canary` is typed at the hidden prompt. `HOST` and
`SVC` are set in [Operator setup](#operator-setup-after-independent-review-only):

```sh
H=./heel-rc6/bin/heel                       # used as "$H" below; quoted, so zsh and bash agree
curl -sS -o openapi.json "https://HOST/openapi.json"     # or this directory's openapi.json
"$H" runner import-openapi openapi.json
"$H" runner credential add --role lower_plan  --profile bearer --label "staging free" --backend keychain --secret-fd 3 \
  3< <(/usr/bin/security find-generic-password -s "$SVC" -a free -w | tr -d '\n')
"$H" runner credential add --role higher_plan --profile bearer --label "staging pro"  --backend keychain --secret-fd 3 \
  3< <(/usr/bin/security find-generic-password -s "$SVC" -a pro -w | tr -d '\n')
"$H" runner credential add --role authenticated --profile bearer --label "staging signed-in" --backend keychain --secret-fd 3 \
  3< <(/usr/bin/security find-generic-password -s "$SVC" -a pro -w | tr -d '\n')
"$H" runner input add --name expected_account --type text --backend keychain   # type acct_canary
```

The three tests themselves are created, reviewed and approved in the browser, as the guide
describes. This choreography (credentials taken from the operator's Keychain items) is specific
to this controlled fixture, whose tokens the operator generated; it is not a general Heel
requirement.

### Legacy fixed-marker mapping

The routes `/api/exports/{id}` and `/api/auth-records/{id}` serve the earlier fixed-marker
checks (`runner map`, `runner prepare`, `runner regress`). Configured tests do not use them:
a configured test needs a literal route.

```sh
"$H" runner import-openapi openapi.json
# Ordinary route: no placeholder, so no fixture (empty fixture bindings).
"$H" runner map --scenario plan_entitlement_read --method GET --route /api/export
# Canary route (paired canary validation only):
"$H" runner map --scenario plan_entitlement_read --method GET --route '/api/exports/{id}' \
  --fixture-fd 3 3< <(printf '%s' '{"id":"heel-canary-export-0001"}')
# Authentication read route (anonymous vs authenticated; the anonymous role sends no credential):
"$H" runner map --scenario anonymous_authenticated_read --method GET --route '/api/auth-records/{id}' \
  --fixture-fd 3 3< <(printf '%s' '{"id":"heel-canary-auth-0001"}')
```

For the authentication read, the `anonymous` role needs no credential. The `authenticated` role
needs one runner credential whose bearer token is either canary token (free or pro); the
`authenticated` credential add in the configured section above is the same one. On the canary
route the fixture id must be exactly `heel-canary-export-0001`; any other id reaches only `404`s
and stays `inconclusive`. Which Heel path turns an ordinary `/api/export` run into an observed
result is a runner property, not this fixture's. This fixture only supplies the markerless
payload.

Each request writes one console receipt: a generated `receipt` id, `method` (GET/HEAD/OTHER),
`route` (a known route or `unknown`), `role` (free/pro/none/malformed/unknown/`-`), `status`,
`mode` and `body_sha256` of the bytes sent. No header, query, token or body value is logged.

## Proof status

`target.test.mjs` (repository only) is **component proof only**: constructed `Request` objects
passed to the Worker in-process, plus the worker's own responses evaluated by the unchanged
Python product code: the standalone comparator, and the paired composition (served inventory →
`RouteInventory` → store mapping validator → catalog action → `prepare_action` → body shape →
`protected_content` with the bound marker → `evaluate_pair`), without mocks.
CI runs it in the `browser-alpha` job. It proves nothing about DNS, TLS, workers.dev response
framing, the released runner or the browser journey; those need the deployed run below.
For `/api/auth-records/{id}` it runs the same unchanged composition for
`anonymous_authenticated_read` (anonymous profile for the anonymous role, bearer for the
authenticated role).
For `/api/private-record` and `/api/profile` it proves the credential/mode matrices, the `200`
redaction control, markerless bodies, `HEAD` framing, method and unknown-path rejection, fail-closed
configuration, receipt privacy and served/static inventory parity (including `RouteInventory`
reading all five routes); it runs no Heel evaluator on them, so the configured outcomes above
are expectations only.
For `/api/export` it also proves the inventory → empty-binding mapping → `prepare_action` steps
and the comparator rows; it does not run the runner's ordinary plan-differential executor bridge,
which is implemented and reviewed separately.

```sh
node --test tests/fixtures/customer_staging/target.test.mjs     # repository checkout only, from its root
```

## Prerequisites (declared, not provided by these files)

These files do not grant any access. Before a deployment or a public-only review, the operator
must hold, and must state that they hold:

1. **Authorized Cloudflare access**: Wrangler logged in (`wrangler login`) to a Cloudflare
   account the operator is authorized to deploy to, with a `workers.dev` subdomain. The Workers
   Free plan is sufficient.
2. **Node.js, Wrangler and jq**: Node.js with `npx`; the steps below run Wrangler 4.154.0 (the
   version the Heel repository pins) through `npx`, which downloads it from npm. Step 5 also
   needs `jq` on `PATH` (for example `brew install jq`).
3. **Local synthetic credentials**: the two fake free and pro canary tokens generated in step 1,
   kept in the operator's macOS Keychain. They never appear in these files, argv, chat or logs.
   A reviewer receives them out of band through the Keychain and secret-fd flow only.
4. **Ownership-proof publication**: the ability to run `wrangler secret put HEEL_VERIFY_TOKEN`
   for this Worker with the token Heel issues for the target's exact origin.
5. **Target control**: the operator alone changes `HEEL_TARGET_MODE`, by redeploying. The target
   has no public control endpoint; a reviewer who needs a mode change asks the operator who
   declared control of the target.
6. **The source version**: the `SOURCE_REVISION` stated by the publisher of these files (the
   release notes of the prerelease that carries them).

The deployment recorded before these files were published does not include `/api/private-record`
or `/api/profile`; a deployment from these files does.

## Operator setup (after independent review only)

All commands run in the directory that holds the four extracted files, on the operator's macOS
machine, with the prerequisites above. **If any step asks to add a payment method or upgrade the
plan, stop and report that one decision; do not upgrade.** Placeholders: `HOST` is the
`heel-customer-staging-target.<SUBDOMAIN>.workers.dev` hostname printed by the first deploy.

```sh
wr() { npx --yes wrangler@4.154.0 "$@"; }  # a function, so zsh and bash run it the same way
CFG=./wrangler.jsonc                         # this directory's config; main is ./worker.mjs
SVC=heel-customer-staging-target             # Keychain service name for the two canary tokens
SOURCE_REVISION=PUBLISHED_40_HEX_COMMIT      # exactly as stated with these files
wr deploy --dry-run --outdir "$(mktemp -d)" --config "$CFG"   # local bundle check; deploys nothing
```

### 1. Canary tokens stay in the macOS Keychain; the Worker gets only digests

Tokens are generated inside one process and handed to `security -i` on stdin, never in argv,
source, environment or logs. (`security add-generic-password -w` prompted from a pipe stores an
empty item; `security -i` with one command line avoids that.)

```sh
for ROLE in free pro; do
  python3 -I -c 'import secrets, sys; print(f"add-generic-password -U -s {sys.argv[1]} -a {sys.argv[2]} -w hst_" + secrets.token_urlsafe(32))' "$SVC" "$ROLE" \
    | /usr/bin/security -i
  # Expect 47; anything else means the item is wrong. Approve Keychain access here once.
  /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w | tr -d '\n' | wc -c
done
```

### 2. First deploy (fails closed until secrets exist), then digests and ownership token

```sh
wr deploy --config "$CFG" --var HEEL_TARGET_MODE:vulnerable --var "HEEL_TARGET_REVISION:$SOURCE_REVISION"
for ROLE in free pro; do
  NAME=$( [ "$ROLE" = free ] && echo HEEL_FREE_TOKEN_SHA256 || echo HEEL_PRO_TOKEN_SHA256 )
  /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w | tr -d '\n' \
    | shasum -a 256 | cut -c1-64 | tr -d '\n' | wr secret put "$NAME" --config "$CFG"
done
# Heel issues the ownership token when you create the HTTPS-file proof for https://HOST.
# Copy it to the clipboard, then:
pbpaste | tr -d '\r\n' | wr secret put HEEL_VERIFY_TOKEN --config "$CFG"
curl -sS "https://HOST/healthz"     # expect mode vulnerable, revision $SOURCE_REVISION, both *_configured true
curl -sS "https://HOST/.well-known/heel-verify.txt"
```

A `revision` of `unknown` means `SOURCE_REVISION` was not 7-40 lowercase hex characters.

### 3. Runner credentials from the same Keychain items (secret fd, no argv)

Use the credential commands in [Configured tests on this fixture](#configured-tests-on-this-fixture).

### 4. Clean-machine curl check (header from stdin, never argv)

```sh
for ROLE in free pro; do
  for ROUTE in /api/export /api/private-record /api/profile; do
    /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w \
      | { IFS= read -r t; printf 'Authorization: Bearer %s\n' "$t"; } \
      | curl -sS -o /dev/null -w "$ROLE $ROUTE %{http_code} %{size_download}\n" -H @- "https://HOST$ROUTE"
  done
done
curl -sS -o /dev/null -w "anonymous /api/private-record %{http_code} %{size_download}\n" "https://HOST/api/private-record"
```

In `vulnerable` mode every authenticated line reads `200`: `/api/export` 97 bytes,
`/api/private-record` 94 and `/api/profile` 114, and the anonymous line reads `200 94`. In
`patched` mode free `/api/export` reads `403 0`, free `/api/profile` `200 73` and the anonymous
line `401 0`. In `error_envelope` mode free `/api/export` and free `/api/profile` read `403 28`
(`{"error":"upgrade required"}`), and the anonymous line reads `401 27`.

### 5. Receipts during the journey (bounded fields only)

`wrangler tail` events also carry request metadata, so keep only the logged receipt lines. Run
this in the same shell as the setup block (it uses `wr`), and stop it with Ctrl-C after the
journey. `EVIDENCE_DIR` is a local directory of your choice; it is created here, and nothing in
it is uploaded:

```sh
EVIDENCE_DIR="$PWD/evidence"                 # local only; any operator-owned path works
(umask 077 && mkdir -p "$EVIDENCE_DIR")
if command -v jq >/dev/null; then
  wr tail heel-customer-staging-target --format json \
    | jq -c --unbuffered '.logs[]?.message[]? | fromjson? | select(type == "object" and has("receipt"))' \
    > "$EVIDENCE_DIR/target-receipts.jsonl"
else
  echo "jq is required for receipts; install it first (see Prerequisites)" >&2
fi
```

### 6. Patch, error-envelope check, rollback, removal

Record each version id (non-secret) in the operator's evidence before changing mode:

```sh
wr deployments list --config "$CFG"                                   # note current VERSION_ID
wr deploy --config "$CFG" --var HEEL_TARGET_MODE:patched        --var "HEEL_TARGET_REVISION:$SOURCE_REVISION"
wr deploy --config "$CFG" --var HEEL_TARGET_MODE:error_envelope --var "HEEL_TARGET_REVISION:$SOURCE_REVISION"
wr rollback VERSION_ID --config "$CFG" --message "restore recorded target mode"
wr delete --config "$CFG"                                             # only on an explicit teardown decision
```

Secrets persist across deploys. Rotate a canary by repeating step 1 for that role, its digest
in step 2, and its runner credentials.

## Expected deployed acceptance (not yet run)

From a clean machine with the released runner, ownership verifies over HTTPS and each runner
request appears as one receipt. When these files were published, none of the following had been
run against a deployment of them; a later run is evidence only where its own record says so.

- **Configured tests**, the three tests in
  [Configured tests on this fixture](#configured-tests-on-this-fixture): `observed` in
  `vulnerable`, `blocked` in `patched` and `inconclusive` in `error_envelope`, as in that table.
- **Ordinary plan-differential exposure** (legacy), `GET /api/export`: a runner whose ordinary
  plan-differential bridge is deployed is expected to report the markerless comparator result:
  `observed` (row 6 key-path superset) in `vulnerable`, `blocked` (row 7) in `patched` and
  `inconclusive` (row 9) in `error_envelope`. Without that bridge the run is `inconclusive`.
- **Canary-dependent paired read validation** (legacy), `GET /api/exports/{id}`: `observed` in
  `vulnerable`, `blocked` in `patched` and `inconclusive` in `error_envelope`.
- **Authentication read** (legacy), `GET /api/auth-records/{id}`
  (`anonymous_authenticated_read`): `observed` in `vulnerable`, `blocked` in `patched` and
  `inconclusive` in `error_envelope`.

All are checks of this one synthetic target, not a product coverage claim.
