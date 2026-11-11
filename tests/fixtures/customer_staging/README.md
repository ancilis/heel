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
envelope and the OpenAPI shape are reused from that harness.

## Contract

| Route | Methods | Behavior |
|---|---|---|
| `/.well-known/heel-verify.txt` | GET, HEAD | `200 text/plain`, body = `HEEL_VERIFY_TOKEN` + `\n`; `503` if unset or not 16-512 printable ASCII. No setter. |
| `/api/export` | GET, HEAD | `Authorization: Bearer <token>`; the SHA-256 of the token must equal exactly one configured digest. Missing/malformed/unknown → `401 {"error":"unauthenticated"}`. |
| `/healthz` | GET, HEAD | `{"status","mode","revision","ownership_configured","export_configured"}` only. |
| any other path | any | `404 {"error":"not found"}` |
| known path | other methods | `405`, `Allow: GET, HEAD` |

`/api/export` fails closed with `503` unless `HEEL_TARGET_MODE` is a known mode and
`HEEL_FREE_TOKEN_SHA256` / `HEEL_PRO_TOKEN_SHA256` are two different 64-character lowercase hex
digests. The mode is set only by the operator at deploy time; no header, query or cookie
changes it. The pro identity always receives the export (positive control).

| `HEEL_TARGET_MODE` | free identity receives | Existing matcher (`evaluate_plan_pair`) | Saved-regression replay |
|---|---|---|---|
| `vulnerable` | `200` + the full pro export | finding, `body_superset` (row 6) | `fail` / `still_reachable` |
| `patched` | `403`, empty body | held, `lower_denied` (row 7) | `pass` / `blocked` |
| `error_envelope` | `403 {"error":"upgrade required"}` | inconclusive, `lower_denial_envelope` (row 9) | `fail` / `inconclusive` — never `pass` |

`HEAD /api/export` is status parity only (row 8, inconclusive) in every mode. The ops proposal of
`403 {}` is also held (row 7) by the current matcher; the worker serves the empty body.

Each request writes one console receipt: a generated `receipt` id, `method` (GET/HEAD/OTHER),
`route` (a known route or `unknown`), `role` (free/pro/none/malformed/unknown/`-`), `status`,
`mode` and `body_sha256` of the bytes sent. No header, query, token or body value is logged.

## Proof status

`target.test.mjs` is **component proof only**: constructed `Request` objects passed to the
Worker in-process, plus the worker's own responses evaluated by the unchanged Python predicate.
CI runs it in the `browser-alpha` job. It proves nothing about DNS, TLS, workers.dev response
framing, the released runner or the browser journey; those need the deployed run below.

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
done
```

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

From a clean machine with the released runner: ownership verifies over HTTPS; the
`vulnerable` run records a `GET /api/export` `body_superset` finding; a saved regression replays
`fail`/`still_reachable`; after `patched` it replays `pass`/`blocked`; under `error_envelope` it
replays `fail`/`inconclusive`. Each runner request appears as one receipt.
