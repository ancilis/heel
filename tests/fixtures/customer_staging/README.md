# Controlled staging target (synthetic acceptance fixture)

A tiny standalone Cloudflare Worker that stands in for a customer's staging SaaS during the
real customer-local Heel journey. It is a test fixture: not Heel product code, not Heel's
control plane, and not shipped in any release artifact (`tests/` is excluded by
`scripts/build_open_core_release.py`). It has no bindings, storage, outbound fetch, redirect,
dependency or paid feature, and serves only static fake data.

It closes three target prerequisites of the older loopback harness
(`tests/plan_differential_support.py`): it is reachable over ordinary public HTTPS once
deployed (T-1), serves an ownership-proof file (T-2), and has a `patched` mode whose refusal the
existing matcher can decide (T-3). The export payload, the `{"error": "upgrade required"}`
envelope and the marker id are reused from that harness.

The target serves the same export through two routes. They share the same digest-only auth and
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

Neither route is a coverage claim. Each one exercises a single synthetic read on this fixture.

`openapi.json`: 1025 bytes, sha256 `dd562a1345fac05aec6cb3152ebf47c85caf354541b25d967238ed7ff48e0359`.

## Contract

| Route | Methods | Behavior |
|---|---|---|
| `/.well-known/heel-verify.txt` | GET, HEAD | `200 text/plain`, body = `HEEL_VERIFY_TOKEN` + `\n`; `503` if unset or not 16-512 printable ASCII. No setter. |
| `/api/export` | GET, HEAD | Ordinary export (97 bytes, no marker). `Authorization: Bearer <token>`; the SHA-256 of the token must equal exactly one configured digest. Missing/malformed/unknown → `401 {"error":"unauthenticated"}`. |
| `/api/exports/heel-canary-export-0001` | GET, HEAD | Canary export (142 bytes, `protected_canary`). Same auth and modes as `/api/export`. |
| `/healthz` | GET, HEAD | `{"status","mode","revision","ownership_configured","export_configured"}` only. |
| `/openapi.json` | GET, HEAD | `200 application/json`, byte-identical to `openapi.json` here, so a clean-room user can download the inventory without repository access. |
| any other path (including any other export id) | any | `404 {"error":"not found"}`; the path is never reflected. |
| known path | other methods | `405`, `Allow: GET, HEAD` |

The served inventory lists only `GET`/`HEAD /api/export` (no parameter) and `GET`/`HEAD
/api/exports/{id}` (an ordinary required `string` path parameter): no ownership, health or
spec endpoint, no marker value, no example value, and no plan, finding or `x-` annotation.

Both export routes fail closed with `503` unless `HEEL_TARGET_MODE` is a known mode and
`HEEL_FREE_TOKEN_SHA256` / `HEEL_PRO_TOKEN_SHA256` are two different 64-character lowercase hex
digests. The mode is set only by the operator at deploy time; no header, query or cookie
changes it. The pro identity always receives that route's export (positive control). Both
routes use the same mode on every request.

| `HEEL_TARGET_MODE` | free identity receives (either route) | Comparator (`evaluate_plan_pair`, `marker=None`), both routes | Paired canary evaluator (`adapters.evaluate_pair`), `/api/exports/{id}` only |
|---|---|---|---|
| `vulnerable` | `200` + that route's full pro export | finding, `body_superset` (row 6) | `observed` |
| `patched` | `403`, empty body | held, `lower_denied` (row 7) | `blocked` |
| `error_envelope` | `403 {"error":"upgrade required"}` | inconclusive, `lower_denial_envelope` (row 9) | `inconclusive` |

On `/api/export` the paired canary evaluator is `inconclusive` in every mode (no marker).

`HEAD` is never a finding on either route. The comparator gives status parity only (row 8,
`inconclusive`) in `vulnerable`, and a status-only hold (row 7, `held`, `body_superset` null) in
`patched` and `error_envelope`, where free gets `403` and pro `200`. The paired canary evaluator is
`inconclusive` for `HEAD` in every mode. It is also `inconclusive` when the positive control
fails (pro identity denied or unauthenticated) or when no `heel-canary-` id is bound.

### Runner mapping

```sh
curl -sS -o openapi.json "https://HOST/openapi.json"     # or use this folder's openapi.json
heel runner import-openapi openapi.json
# Ordinary route: no placeholder, so no fixture (empty fixture bindings).
heel runner map --scenario plan_entitlement_read --method GET --route /api/export
# Canary route (paired canary validation only):
heel runner map --scenario plan_entitlement_read --method GET --route '/api/exports/{id}' \
  --fixture-fd 3 3< <(printf '%s' '{"id":"heel-canary-export-0001"}')
```

On the canary route the fixture id must be exactly `heel-canary-export-0001`; any other id
reaches only `404`s and stays `inconclusive`. Which Heel path turns an ordinary `/api/export`
run into an observed result is a runner property, not this fixture's. This fixture only
supplies the markerless payload.

Each request writes one console receipt: a generated `receipt` id, `method` (GET/HEAD/OTHER),
`route` (a known route or `unknown`), `role` (free/pro/none/malformed/unknown/`-`), `status`,
`mode` and `body_sha256` of the bytes sent. No header, query, token or body value is logged.

## Proof status

`target.test.mjs` is **component proof only**: constructed `Request` objects passed to the
Worker in-process, plus the worker's own responses evaluated by the unchanged Python product
code: the standalone comparator, and the paired composition (served inventory →
`RouteInventory` → store mapping validator → catalog action → `prepare_action` → body shape →
`protected_content` with the bound marker → `evaluate_pair`), without mocks.
CI runs it in the `browser-alpha` job. It proves nothing about DNS, TLS, workers.dev response
framing, the released runner or the browser journey; those need the deployed run below.
For `/api/export` it also proves the inventory → empty-binding mapping → `prepare_action` steps
and the comparator rows; it does not run the runner's ordinary plan-differential executor bridge,
which is implemented and reviewed separately.

```sh
node --test tests/fixtures/customer_staging/target.test.mjs     # from the repository root
wrangler deploy --dry-run --outdir "$SCRATCH/out" --config tests/fixtures/customer_staging/wrangler.jsonc
```

## Operator setup (after independent review only)

All commands run from the repository root on the operator's macOS machine, already logged in
with `wrangler login` to the existing account. The Workers Free plan and the account's
`workers.dev` subdomain are sufficient. **If any step asks to add a payment method or upgrade
the plan, stop and report that one decision; do not upgrade.** Placeholders: `HOST` is the
`heel-customer-staging-target.<SUBDOMAIN>.workers.dev` hostname printed by the first deploy.

```sh
CFG=tests/fixtures/customer_staging/wrangler.jsonc
SVC=heel-customer-staging-target            # Keychain service name for the two canary tokens
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
wrangler deploy --config "$CFG" --var HEEL_TARGET_MODE:vulnerable --var "HEEL_TARGET_REVISION:$(git rev-parse HEAD)"
for ROLE in free pro; do
  NAME=$( [ "$ROLE" = free ] && echo HEEL_FREE_TOKEN_SHA256 || echo HEEL_PRO_TOKEN_SHA256 )
  /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w | tr -d '\n' \
    | shasum -a 256 | cut -c1-64 | tr -d '\n' | wrangler secret put "$NAME" --config "$CFG"
done
# Heel issues the ownership token in onboarding step 2. Copy it to the clipboard, then:
pbpaste | tr -d '\r\n' | wrangler secret put HEEL_VERIFY_TOKEN --config "$CFG"
curl -sS "https://HOST/healthz"     # expect mode vulnerable, both *_configured true
curl -sS "https://HOST/.well-known/heel-verify.txt"
```

### 3. Runner credentials from the same Keychain items (secret fd, no argv)

```sh
heel runner credential add --role lower_plan  --profile bearer --label "staging free" --plan-label free --backend keychain --secret-fd 3 \
  3< <(/usr/bin/security find-generic-password -s "$SVC" -a free -w | tr -d '\n')
heel runner credential add --role higher_plan --profile bearer --label "staging pro"  --plan-label pro  --backend keychain --secret-fd 3 \
  3< <(/usr/bin/security find-generic-password -s "$SVC" -a pro -w | tr -d '\n')
```

### 4. Clean-machine curl check (header from stdin, never argv)

```sh
for ROLE in free pro; do
  /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w \
    | { IFS= read -r t; printf 'Authorization: Bearer %s\n' "$t"; } \
    | curl -sS -o /dev/null -w "$ROLE %{http_code} %{size_download}\n" -H @- "https://HOST/api/export"
  /usr/bin/security find-generic-password -s "$SVC" -a "$ROLE" -w \
    | { IFS= read -r t; printf 'Authorization: Bearer %s\n' "$t"; } \
    | curl -sS -o /dev/null -w "$ROLE %{http_code} %{size_download}\n" -H @- "https://HOST/api/exports/heel-canary-export-0001"
done
```

In `vulnerable` mode the `/api/export` lines should read `200 97` and the canary lines `200 142`.

### 5. Receipts during the journey (bounded fields only)

`wrangler tail` events also carry request metadata, so keep only the logged receipt lines:

```sh
wrangler tail heel-customer-staging-target --format json \
  | jq -c --unbuffered '.logs[]?.message[]? | fromjson? | select(type == "object" and has("receipt"))' \
  > "$EVIDENCE_DIR/target-receipts.jsonl"
```

### 6. Patch, error-envelope check, rollback, removal

Record each version id (non-secret) in the operator's evidence before changing mode:

```sh
wrangler deployments list --config "$CFG"                                   # note current VERSION_ID
wrangler deploy --config "$CFG" --var HEEL_TARGET_MODE:patched        --var "HEEL_TARGET_REVISION:$(git rev-parse HEAD)"
wrangler deploy --config "$CFG" --var HEEL_TARGET_MODE:error_envelope --var "HEEL_TARGET_REVISION:$(git rev-parse HEAD)"
wrangler rollback VERSION_ID --config "$CFG" --message "restore recorded target mode"
wrangler delete --config "$CFG"                                             # only on an explicit teardown decision
```

Secrets persist across deploys. Rotate a canary by repeating step 1 for that role, its digest
in step 2, and its runner credential in step 3.

## Expected deployed acceptance (not yet run)

From a clean machine with the released runner and the mappings above, ownership verifies over
HTTPS and each runner request appears as one receipt.

- **Ordinary plan-differential exposure**, `GET /api/export`: a runner whose ordinary
  plan-differential bridge is deployed is expected to report the markerless comparator result:
  `observed` (row 6 key-path superset) in `vulnerable`, `blocked` (row 7) in `patched` and
  `inconclusive` (row 9) in `error_envelope`. Without that bridge the run is `inconclusive`.
- **Canary-dependent paired read validation**, `GET /api/exports/{id}`: `observed` in
  `vulnerable`, `blocked` in `patched` and `inconclusive` in `error_envelope`.

Both are checks of this one synthetic target, not a product coverage claim.
