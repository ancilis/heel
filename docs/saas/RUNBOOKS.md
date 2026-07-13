# ARCEO Hosted — Runbooks (v1)

Each runbook is executable today against the local control plane; the owner-credential steps are
marked. Every intervention that changes state must go through `OpsStore` so it lands in the
append-only `admin_audit` table with actor + reason.

## Kill switch (global or per-workspace)
Use when: runaway spend, abuse in progress, upstream provider incident.
1. Trip: `OpsStore.trip('global'|<workspace_id>, actor=<you>, reason=<ticket>)`. Effect is
   immediate: new run enqueues return 503; running jobs finish under their existing budgets.
2. Verify: `POST /v1/workspaces/<id>/runs` returns 503; `arceo_quota_exceeded_total` stops moving.
3. Communicate (owner): status page + affected-tenant email.
4. Clear with `OpsStore.clear(scope, actor=, reason=)` once the cause is closed. Audit both ends.

## Target abuse (runs against a target the caller shouldn't touch)
1. `TargetVerifier.revoke(workspace_id, hostname)` — verified status drops instantly; further
   verified runs 403 at enqueue.
2. Trip the workspace kill switch if runs are in flight (they remain egress-limited to the
   revoked target and die at the 60 s wall-clock ceiling).
3. Preserve `jobs` + `usage_ledger` rows for the case record; note actions in admin_audit.

## Billing support (customer disputes a charge / state looks wrong)
1. `reconcile(conn, ledger)` — read the report; do not hand-edit rows.
2. Plan mismatch → replay the provider's latest webhook event (idempotent; version-ordered).
3. Dangling reservations → `reconcile(..., repair=True)` refunds (customer-favorable only).
4. Refund money at the provider (owner) — the ledger never charges; it only meters.

## Key rotation
- API key: customer mints a replacement via `POST /v1/workspaces/{id}/api-keys`, cuts over, then
  `DELETE /v1/workspaces/{id}/api-keys/{old}`. Zero downtime; old key dies at revoke.
- Server pepper (`ARCEO_API_KEY_PEPPER`): rotating it invalidates ALL stored key/invite/session
  hashes at once — treat as an incident action, force re-login, and have customers re-mint keys.
- Webhook secret: set the new secret at the provider and in the deployment env together (owner).

## Suspected credential breach (tenant)
1. `AuthStore.revoke_all(user_id)` — kills every session for the user.
2. Revoke the workspace's API keys; owner re-mints after re-securing.
3. Reset password via `set_password` on a verified recovery channel (owner process).
4. Review `admin_audit`, `jobs`, and the containment log for the exposure window.

## Restore drill (monthly) / actual restore
1. Take the latest backup snapshot of the control-plane DB (owner: managed Postgres PITR; local:
   copy the SQLite file while the server is stopped).
2. Restore into a scratch instance; run `Migrator.apply_all()` (must report `[]` pending) and
   `python3 -m unittest tests.test_saas_reconcile` shape checks.
3. `reconcile(conn, ledger)` on the restored copy must be clean before promotion.
4. Promote by pointing the deployment at the restored DB; keep the old primary read-only 24 h.

## Incident (generic)
1. Declare: note UTC start, suspected blast radius, and owner in the ticket.
2. Stabilize: kill switch (global/tenant) beats debugging in production.
3. Diagnose from `/v1/metrics`, `/v1/readyz`, admin_audit, and job/ledger tables.
4. Postmortem within 5 working days; new invariants become reconcile checks or tests.
