# Heel Free-Launch Runbooks

These runbooks apply to the implemented single-node SQLite deployment in
`deploy/compose.yaml`. They do not describe a future Stripe/PostgreSQL system.

Set a shell variable once to keep commands consistent:

```bash
COMPOSE_FILE=deploy/compose.yaml
ENV_FILE=deploy/.env.production
```

## Start or verify the private deployment

```bash
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs \
  --tail=200 control-plane cloudflared
```

The control plane must be healthy before `cloudflared` starts. There must be no
public `ports:` mapping. Confirm private readiness from inside the service:

```bash
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec \
  control-plane python -c \
  "import http.client; c=http.client.HTTPConnection('127.0.0.1',8080,timeout=3); c.request('GET','/v1/readyz'); r=c.getresponse(); print(r.status, r.read().decode())"
```

Expected status is `200`. Do not expose this private port to perform monitoring;
run the probe from the host/private network.

## Public edge or Tunnel incident

Use when the Worker proxy, Tunnel, VPC binding, or shared edge secret may be unsafe.

1. Preserve the public browser-local product while cutting cloud continuity:

   ```bash
   docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop cloudflared
   ```

2. Confirm the public website still loads and anonymous browser review still works.
   Cloud account/sync operations should fail unavailable.
3. Inspect Worker deployment/version, VPC service ID, Tunnel route, and
   `CONTROL_PLANE_EDGE_SECRET`/`HEEL_EDGE_AUTH_SECRET_B64` configuration. Never print
   either secret.
4. Redeploy the corrected Worker or private service, then restore the Tunnel:

   ```bash
   docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d cloudflared
   docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps
   ```

## Database lock or unexpected second owner

`heel.saas.server` permits one live process for one database. A second process exits
with `HEEL_DATABASE_PATH already has a live process owner`.

1. Do not delete `<database>.lock` while any control-plane process may be alive.
2. Inspect Compose state and host processes; stop duplicate or orphaned service
   definitions.
3. If no owner is live, restart the single configured service:

   ```bash
   docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d \
     --no-deps control-plane
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

For an actual restore, stop `cloudflared`, stop the control plane, preserve the old
volume read-only, install the verified database on a new persistent volume, then
start exactly one control-plane process and re-run readiness before restoring the
Tunnel. Never copy only the main SQLite file from a running WAL database.

## Disk pressure or SQLite health failure

1. Stop `cloudflared` to prevent new cloud writes.
2. Preserve logs and inspect persistent-volume free space. Do not run `VACUUM`, delete
   WAL files, or edit tables during the incident.
3. Take and verify an online backup if the database remains readable.
4. Expand or replace the volume, then restart one control-plane process and verify
   `/v1/readyz` before restarting the Tunnel.
5. If readiness remains unhealthy, restore the latest verified backup to a new
   volume; preserve the failed volume for investigation.

## Secret rotation

- **Edge-auth secret:** stop `cloudflared`; generate a new canonical base64url value;
  update both `HEEL_EDGE_AUTH_SECRET_B64` and the Worker
  `CONTROL_PLANE_EDGE_SECRET`; recreate the control plane and deploy the Worker; then
  restore the Tunnel after an authenticated smoke test.
- **Device-token pepper:** schedule a maintenance window. Rotation invalidates the
  existing device-token verification material; require machine reauthorization.
- **API-key pepper:** schedule a maintenance window and require affected keys to be
  reissued. Do not retain the old secret in application configuration.
- **Tunnel token:** rotate it in Cloudflare and the deployment secret manager, recreate
  only `cloudflared`, and confirm the VPC route before declaring recovery.

## Public-origin change

The public origin is bound into device verification and the Worker build.

1. Configure DNS/TLS and the Tunnel/VPC path for the new canonical HTTPS origin.
2. Set the same new `HEEL_PUBLIC_ORIGIN` for the control plane and Worker build.
3. Rebuild/redeploy the Worker and recreate the control plane.
4. Verify signup cookies use `__Host-heel_session`, device verification resolves to
   the new origin, local review stays local, and findings-only sync succeeds.

## Payment or upgrade report

Production uses `DisabledBilling`. Free is available; Pro and Team are coming soon.
Checkout must return unavailable and no payment can be accepted. Treat any checkout
URL, charge, active paid plan, or request for card details as a launch incident: cut
the cloud path, preserve evidence, and verify `HEEL_BILLING_MODE=free_launch` before
returning service.

## Suspected privacy-boundary breach

1. Stop `cloudflared`; preserve the public local-only browser experience if safe.
2. Preserve Worker version, request metadata, receipts, and affected project/workspace
   references. Do not copy raw customer OpenAPI into tickets or logs.
3. Determine whether any payload exceeded the closed findings projection. Raw
   OpenAPI, guided answers, and full review context are never expected server data.
4. Notify the assigned security/privacy owner and follow the approved legal response
   process.
5. Restore cloud continuity only after route, payload, queue, and receipt gates pass
   on the corrected deploy candidate.
