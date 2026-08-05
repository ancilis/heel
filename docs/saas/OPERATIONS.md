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

The Compose deployment also sets:

```text
HEEL_CONTROL_PLANE_HOST=0.0.0.0
HEEL_CONTROL_PLANE_PORT=8080
HEEL_PRIVATE_NETWORK_ACK=private-vpc-only
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

Create ignored `deploy/.env.production` from the example and source its values from
the deployment secret manager.

```bash
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml config
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml ps
```

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
