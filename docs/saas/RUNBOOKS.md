# Heel Free-Launch Runbooks

These runbooks apply to the implemented single-node SQLite deployment in
`deploy/compose.yaml`. They do not describe a future Stripe/PostgreSQL system.

## Two secret files and one Compose entry point

The deployment uses two separate files. Never merge them.

| File | Read by | Contains |
|---|---|---|
| `deploy/.env.production` (in the checkout, git-ignored, mode 0600) | Compose `env_file:`, as the **control-plane** container environment | Only the control-plane variables. It must **not** contain `HEEL_CLOUDFLARE_TUNNEL_TOKEN` or `HEEL_CLOUDFLARED_IMAGE`. |
| Interpolation file **outside** the checkout, for example `$HOME/heel-secrets/cloudflared-interp.env` (directory 0700, file 0600, owned by the operator account) | The Compose CLI `--env-file`, only to fill `${HEEL_CLOUDFLARED_IMAGE}` and `${HEEL_CLOUDFLARE_TUNNEL_TOKEN}` in `deploy/compose.yaml` | Exactly two lines: `HEEL_CLOUDFLARED_IMAGE=` and `HEEL_CLOUDFLARE_TUNNEL_TOKEN=`. |

With this split, the Tunnel token reaches only the `cloudflared` container
(`TUNNEL_TOKEN`), not the control plane. `OPERATIONS.md` ("Deploy the private
services") shows how to create both files from `deploy/.env.production.example`,
which still lists both Tunnel variables and must not be copied unchanged. Do not use
`deploy/.env`, and do not export either Tunnel variable in the shell.

Run every Compose command from the repository checkout root through one shell
function, so every invocation uses `--env-file`:

```bash
HEEL_INTERP_ENV="$HOME/heel-secrets/cloudflared-interp.env"
hc() { docker compose -f deploy/compose.yaml --env-file "$HEEL_INTERP_ENV" "$@"; }
```

If the host needs `sudo`, put it inside the function (`sudo docker compose …`);
`$HEEL_INTERP_ENV` is expanded before `sudo` runs. If the interpolation file is missing,
Compose refuses to run because of the `:?` guards in `deploy/compose.yaml`. Fix the file
path. Do not move the token into `deploy/.env.production`.

Never run commands that print resolved configuration or environment: bare
`hc config`, `hc config --format …`, `docker inspect`, `hc exec … env`, `set -x`, or
`cat`/`grep` output from either secret file. Validate with `hc config --quiet`, which
prints nothing and exits 0 when the configuration is valid.

## Start or verify the private deployment

```bash
hc config --quiet
hc up -d --build
hc ps
hc logs --tail=200 control-plane cloudflared
```

The control plane must be healthy before `cloudflared` starts. There must be no
public `ports:` mapping. Confirm private readiness from inside the service:

```bash
hc exec control-plane python -c \
  "import http.client; c=http.client.HTTPConnection('127.0.0.1',8080,timeout=3); c.request('GET','/v1/readyz'); r=c.getresponse(); print(r.status, r.read().decode())"
```

Expected status is `200`. Do not expose this private port to perform monitoring;
run the probe from the host/private network.

## Public edge or Tunnel incident

Use when the Worker proxy, Tunnel, VPC binding, or shared edge secret may be unsafe.

1. Preserve the public browser-local product while cutting cloud continuity:

   ```bash
   hc stop cloudflared
   ```

2. Confirm the public website still loads and anonymous browser review still works.
   Cloud account/sync operations should fail unavailable.
3. Inspect Worker deployment/version, VPC service ID, Tunnel route, and
   `CONTROL_PLANE_EDGE_SECRET`/`HEEL_EDGE_AUTH_SECRET_B64` configuration. Never print
   either secret.
4. Redeploy the corrected Worker or private service, then restore the Tunnel:

   ```bash
   hc up -d cloudflared
   hc ps
   ```

## Database lock or unexpected second owner

`heel.saas.server` permits one live process for one database. A second process exits
with `HEEL_DATABASE_PATH already has a live process owner`.

1. Do not delete `<database>.lock` while any control-plane process may be alive.
2. Inspect Compose state and host processes; stop duplicate or orphaned service
   definitions.
3. If no owner is live, restart the single configured service:

   ```bash
   hc up -d --no-deps control-plane
   ```

4. Confirm one healthy container and one persistent database volume. A stale lock
   file is safe; the kernel lock, not file existence, determines ownership.

## Backup and restore verification

`scripts/saas_backup.py` uses SQLite's online backup API, so it can create a consistent
backup while the server is live. Run it only from a trusted host/job that has
filesystem access to the database on the persistent volume:

```bash
python3 scripts/saas_backup.py backup \
  /absolute/path/to/control-plane.sqlite3 \
  /absolute/path/to/backups/control-plane-YYYYMMDDTHHMMSSZ.sqlite3
python3 scripts/saas_backup.py verify \
  /absolute/path/to/backups/control-plane-YYYYMMDDTHHMMSSZ.sqlite3
```

The Compose bundle does not schedule or export backups. The owner must provide that
trusted access, encrypted destination, retention, and failure monitoring.

For a restore drill:

1. Keep the live service running; verify the candidate backup with the command above.
2. Restore the backup into a separate scratch path/host, never over the live file.
3. Start one scratch `heel.saas.server` with a scratch origin/private listener and run
   the private readiness probe.
4. Record integrity, schema, and application checks. Destroy the scratch instance
   after the drill.

For an actual restore, stop `cloudflared` (`hc stop cloudflared`), stop the control
plane (`hc stop control-plane`), preserve the old volume read-only, install the
verified database on a new persistent volume, then start exactly one control-plane
process (`hc up -d --no-deps control-plane`) and re-run readiness before restoring the
Tunnel (`hc up -d cloudflared`). Never copy only the main SQLite file from a running
WAL database.

## Disk pressure or SQLite health failure

1. Stop `cloudflared` (`hc stop cloudflared`) to prevent new cloud writes.
2. Preserve logs (`hc logs --tail=200 control-plane cloudflared`) and inspect
   persistent-volume free space. Do not run `VACUUM`, delete WAL files, or edit tables
   during the incident.
3. Take and verify an online backup if the database remains readable.
4. Expand or replace the volume, then restart one control-plane process and verify
   `/v1/readyz` before restarting the Tunnel.
5. If readiness remains unhealthy, restore the latest verified backup to a new
   volume; preserve the failed volume for investigation.

### Bounded automatic recovery after reaper lock exhaustion

A transient disk sync stall can hold the SQLite writer lock long enough for the canary
reaper to fail three consecutive cycles (`canary_reaper_cycle_skipped`, then
`canary_reaper_died`). The node first fails closed. It sets draining, so `/v1/readyz`
returns 503 and new requests return 503. WAL `synchronous=FULL` and the reaper thresholds are
unchanged.

- **Automatic recovery.** This applies only when the death is a genuine SQLite BUSY/LOCKED
  result code. The process records one entry in `<database>.recovery.json`, which is written
  atomically and fsynced beside the database. It logs `control_plane_recovery_exit` and then
  takes the ordinary SIGTERM shutdown path, which drains accepted requests, joins workers,
  checkpoints, closes, and releases the lock. It exits with code 75. The existing Compose
  `restart: unless-stopped` policy then restarts the same image on the same volume. No backup is
  restored and no rows change. `cloudflared` is not touched, so a fence stays fenced.
- **Budget.** At most 3 automatic exits per hour. When the budget is exhausted, or the budget
  file is malformed, symlinked, oversized or unwritable, the process logs
  `control_plane_recovery_budget_exhausted` with a `reason` and **stays draining**. It needs an
  operator.
- **Not covered.** Any other reaper failure, a host-authority death, or a worker that does not
  join keeps the existing permanent draining or retained ownership. Note the pre-existing
  Compose behavior: `unless-stopped` restarts *any* non-zero process exit, including startup
  configuration, migration or secret failures. Diagnose those from the startup log; this
  recovery adds no exit on those paths.
- **Diagnose.** Run `hc logs --tail=200 control-plane`. Look for
  `canary_reaper_cycle_skipped`, `canary_reaper_died`, and `control_plane_recovery_*`. Then
  check `docker inspect -f '{{.RestartCount}}'` on the control-plane container.
- **Hold for investigation.** Run `hc stop control-plane`. Docker never restarts a manually
  stopped container, and a SIGTERM shutdown never writes a budget entry.
- **Rollback.** Use the same schema on the same volume only, and redeploy the recorded previous
  image. **Retain `<database>.recovery.json` and all evidence.** Older images ignore the file.
  Never delete it, and never reset the counter to force another automatic cycle. Never restore an
  older backup after customer writes.

## Secret rotation

- **Edge-auth secret:** stop `cloudflared` (`hc stop cloudflared`); generate a new
  canonical base64url value; update both `HEEL_EDGE_AUTH_SECRET_B64` and the Worker
  `CONTROL_PLANE_EDGE_SECRET`; recreate the control plane
  (`hc up -d --no-deps control-plane`) and deploy the Worker; then restore the Tunnel
  (`hc up -d cloudflared`) after an authenticated smoke test.
- **Device-token pepper:** schedule a maintenance window. Rotation invalidates the
  existing device-token verification material; require machine reauthorization.
- **API-key pepper:** schedule a maintenance window and require affected keys to be
  reissued. Do not retain the old secret in application configuration.
- **Tunnel token:** rotate it in Cloudflare and the deployment secret manager, rewrite
  the interpolation file outside the checkout by re-running step 2 of `OPERATIONS.md`
  "Deploy the private services" (token from stdin, never on a command line), recreate
  only `cloudflared` (`hc up -d --no-deps cloudflared`), and confirm the VPC route before
  declaring recovery. The token never goes into `deploy/.env.production`.

## Rollback

1. Stop the private services with `hc stop`, or remove the containers with `hc down`.
   Never add `-v`: that deletes the named database volume.
2. Revert to the recorded rollback point (previous checkout, image, and Worker version)
   and start it again with the same two-file form and `hc`.
3. Never recombine the two secret files, and never put the Tunnel token into
   `deploy/.env.production` or the control-plane environment, not even temporarily.
   If the separated configuration cannot be made to work on the host, stop and report.
   Do not fall back to a single env file.

## Public-origin change

The public origin is bound into device verification and the Worker build.

1. Configure DNS/TLS and the Tunnel/VPC path for the new canonical HTTPS origin.
2. Set the same new `HEEL_PUBLIC_ORIGIN` for the control plane and Worker build.
3. Rebuild/redeploy the Worker and recreate the control plane
   (`hc up -d --no-deps control-plane`).
4. Verify signup cookies use `__Host-heel_session`, device verification resolves to
   the new origin, local review stays local, and findings-only sync succeeds.

## Payment or upgrade report

Production uses `DisabledBilling`. Free is available; Pro and Team are coming soon.
Checkout must return unavailable and no payment can be accepted. Treat any checkout
URL, charge, active paid plan, or request for card details as a launch incident: cut
the cloud path, preserve evidence, and verify `HEEL_BILLING_MODE=free_launch` before
returning service.

## Suspected privacy-boundary breach

1. Stop `cloudflared` (`hc stop cloudflared`); preserve the public local-only browser
   experience if safe.
2. Preserve Worker version, request metadata, receipts, and affected project/workspace
   references. Do not copy raw customer OpenAPI into tickets or logs.
3. Determine whether any payload exceeded the closed findings projection. Raw
   OpenAPI, guided answers, and full review context are never expected server data.
4. Notify the assigned security/privacy owner and follow the approved legal response
   process.
5. Restore cloud continuity only after route, payload, queue, and receipt gates pass
   on the corrected deploy candidate.
