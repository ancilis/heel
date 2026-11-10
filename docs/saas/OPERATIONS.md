# Heel Free-Launch Operations

## Production contract

The supported launch deployment is one private POSIX/Linux control-plane process,
one SQLite database on a persistent volume, one `cloudflared`, and one public
Cloudflare Worker. It is not a multi-replica topology.

| Boundary | Operational invariant |
|---|---|
| Public website | Anonymous browser review remains usable without the control plane. |
| Public proxy | Exact method/path/header allowlist; no arbitrary upstream URL. |
| Private origin | No Compose `ports:` entry; reachable through Tunnel/VPC service only. |
| Edge authentication | Worker `CONTROL_PLANE_EDGE_SECRET` equals server `HEEL_EDGE_AUTH_SECRET_B64`. |
| Sessions | Public `__Host-heel_session`; private `heel_session` only after edge translation. |
| Database | One absolute file on durable storage, WAL, `synchronous=FULL`. |
| Ownership | One process holds `<database>.lock`; additional owners fail closed. |
| Billing | `free_launch` with `DisabledBilling`; no payment accepted. |
| Privacy | Raw OpenAPI and full review context never sync. |

## Required environment

`heel.saas.server` requires:

```text
HEEL_DATABASE_PATH=/absolute/path/on/durable/volume.sqlite3
HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN
HEEL_DEVICE_TOKEN_PEPPER_B64=<canonical base64url for 32-64 random bytes>
HEEL_API_KEY_PEPPER=<32-256 character secret>
HEEL_EDGE_AUTH_SECRET_B64=<canonical base64url for 32-64 random bytes>
HEEL_BILLING_MODE=free_launch
```

The Compose deployment also sets for the control plane:

```text
HEEL_CONTROL_PLANE_HOST=0.0.0.0
HEEL_CONTROL_PLANE_PORT=8080
HEEL_PRIVATE_NETWORK_ACK=private-vpc-only
```

`cloudflared` needs two values that Compose interpolates from a separate file outside
the checkout (see "Deploy the private services"). They never belong in
`deploy/.env.production`:

```text
HEEL_CLOUDFLARE_TUNNEL_TOKEN=<provider secret>
HEEL_CLOUDFLARED_IMAGE=<reviewed immutable image digest>
```

The Worker build requires `HEEL_PUBLIC_ORIGIN` and
`HEEL_CONTROL_PLANE_VPC_SERVICE_ID`. The Worker runtime requires the secret
`CONTROL_PLANE_EDGE_SECRET`.

## Verify

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/saas_smoke.py
python3 -m unittest tests.test_saas_server tests.test_saas_deployment -v
```

```bash
cd apps/heel-cloud
npm ci --ignore-scripts --no-audit --no-fund
npm run test:unit
npm run typecheck
npm run lint
HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
  npm run build
npm run test:node
```

## Deploy the private services

Run these commands on the Linux host, from the repository checkout root. Two
separate files keep the Tunnel token out of the control-plane environment.
`RUNBOOKS.md` ("Two secret files and one Compose entry point") explains which file is
read by what.

1. Create the ignored control-plane file **without** the two Tunnel lines. The example
   still lists them, so do not copy it unchanged:

   ```bash
   umask 077
   grep -v -E '^HEEL_(CLOUDFLARE_TUNNEL_TOKEN|CLOUDFLARED_IMAGE)=' \
     deploy/.env.production.example > deploy/.env.production
   chmod 600 deploy/.env.production
   ```

   Fill the remaining control-plane values from the deployment secret manager in an
   editor. Do not type secrets as command arguments. Before every deployment, confirm
   that the Tunnel lines are absent:

   ```bash
   grep -c -E '^HEEL_(CLOUDFLARE_TUNNEL_TOKEN|CLOUDFLARED_IMAGE)=' deploy/.env.production
   ```

   This must print `0`.

2. Create the interpolation file outside the checkout. Write the image line first, then
   append the token from stdin. The token must never appear on a command line, in
   terminal output, or in shell history:

   ```bash
   HEEL_INTERP_ENV="$HOME/heel-secrets/cloudflared-interp.env"
   umask 077
   mkdir -p "$HOME/heel-secrets" && chmod 700 "$HOME/heel-secrets"
   printf 'HEEL_CLOUDFLARED_IMAGE=%s\n' \
     'cloudflare/cloudflared@sha256:<reviewed 64-hex digest>' > "$HEEL_INTERP_ENV"
   <command that prints only the Tunnel token from the secret manager> \
     | awk '{print "HEEL_CLOUDFLARE_TUNNEL_TOKEN=" $0}' >> "$HEEL_INTERP_ENV"
   chmod 600 "$HEEL_INTERP_ENV"
   ```

   Check the file shape without printing values. The expected outputs are `2`, `1`,
   `1`, then `700` and `600`:

   ```bash
   wc -l < "$HEEL_INTERP_ENV"
   grep -c '^HEEL_CLOUDFLARED_IMAGE=cloudflare/cloudflared@sha256:[0-9a-f]\{64\}$' "$HEEL_INTERP_ENV"
   grep -c '^HEEL_CLOUDFLARE_TUNNEL_TOKEN=.\{40,\}$' "$HEEL_INTERP_ENV"
   stat -c '%a' "$HOME/heel-secrets" "$HEEL_INTERP_ENV"
   ```

3. Define the single Compose entry point and deploy. Every Compose command, including
   `build`, `config`, `up`, `down`, `stop`, `ps`, `logs`, and `exec`, goes through `hc`:

   ```bash
   hc() { docker compose -f deploy/compose.yaml --env-file "$HEEL_INTERP_ENV" "$@"; }
   hc config --quiet
   hc up -d --build
   hc ps
   ```

`hc config --quiet` must exit 0 with no output. Never run bare `hc config`,
`config --format`, `docker inspect`, `exec … env`, or `set -x`, because they print
secrets. If the interpolation file is missing, Compose fails closed. Never fix that
by adding the Tunnel variables to `deploy/.env.production`, and never use
`deploy/.env`. To roll back, follow `RUNBOOKS.md` "Rollback": stop or revert the
deployment and never recombine the files.

The token stays readable in the `cloudflared` container environment and by host
root, and both files are plaintext 0600 on the host disk. This layout does not
provide encryption at rest.

`control-plane` must report healthy and `cloudflared` must start only after that
health gate. Do not add a public host port.

## Deploy the public Worker

After the Cloudflare account, domain, Tunnel, VPC service, and Worker secret exist:

```bash
cd apps/heel-cloud
HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
  npm run deploy:dry-run
HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
  npm run deploy
```

Provider authentication and account ownership are owner actions. Record the deployed
Worker version and generated configuration. No public deployment has been performed
from this workspace.

## Health and monitoring

- Compose probes private `/v1/readyz` every 30 seconds.
- On SIGTERM, readiness fails immediately and new accepted sockets receive 503. The
  server waits up to 30 seconds for active requests before checkpoint/close; Compose
  grants a 35-second stop grace period. Configure a provider termination grace of at
  least 35 seconds as well.
- Monitor container restarts, health state, Tunnel connectivity, persistent-volume
  capacity, backup freshness/verification, signup throttling, sync quota errors, and
  unexpected checkout attempts.
- Keep application logs free of credentials, raw OpenAPI, guided answers, and full
  review documents.
- Alert if more than one control-plane deployment is configured for the volume.
- Test the public anonymous sample independently from cloud operations. A private
  outage must not remove the local browser value.

The repository does not configure an external monitoring vendor or status page; the
owner must choose and operate them.

## Backup

From a trusted host/job with filesystem access to the persistent database:

```bash
python3 scripts/saas_backup.py backup \
  /absolute/path/to/control-plane.sqlite3 \
  /absolute/path/to/backups/control-plane-YYYYMMDDTHHMMSSZ.sqlite3
python3 scripts/saas_backup.py verify \
  /absolute/path/to/backups/control-plane-YYYYMMDDTHHMMSSZ.sqlite3
```

Schedule online backups, copy them to an encrypted failure-independent destination,
alert on missed/failed verification, and run restore drills. The Compose file does
not schedule backups.

## Capacity and upgrade boundary

SQLite single-node capacity, disk growth, and backup duration are the operational
limits. Scale vertically within the tested single-process model. Do not add replicas
or place the database on storage without correct POSIX locking.

PostgreSQL, managed queues, Stripe, paid checkout, horizontal scaling, and paid-plan
support are later migrations. They require a new deployment design and verification
before `HEEL_BILLING_MODE` can change from `free_launch`.

See `RUNBOOKS.md` for incident, restore, rotation, origin-change, and privacy response
procedures.

## Owner-private local review deployment

The existing Sites project is an owner-only preview at
`https://heel-agent-first-private.hellostella.chatgpt.site`. Its local review,
Agent downloads, and reference-result viewer can run without a private control plane.
For that deployment only, build with:

```bash
HEEL_DEPLOYMENT_MODE=local_review \
HEEL_PUBLIC_ORIGIN=https://heel-agent-first-private.hellostella.chatgpt.site \
  npm run build
```

This mode emits **no `CONTROL_PLANE` service binding** and rejects a supplied VPC
service ID. Account/sync APIs retain their existing fail-closed behavior. It does
not configure or deploy the Python control plane or make cloud runner pairing work.
The default `full` mode still requires a real VPC service UUID and canonical origin.
Use Sites version saving and private deployment for the configured project; preserve
its current audience. Never deploy the example UUID used by artifact tests.
