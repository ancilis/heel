# Heel Free Early-Access Launch

## Status

The repository contains the free early-access product surface listed below and a
production deployment bundle. It has not been publicly deployed. The full self-serve
product is not yet launch-ready: paired runner execution, the cloud route inventory bridge,
and approval wiring are incomplete, and final launch acceptance has not been given.

Customers can receive immediate anonymous value in the browser, use local CLI/MCP,
and optionally create an account for exact findings-only continuity. Production
billing is deliberately disabled: Free is available, Pro and Team are coming soon,
and Heel accepts no payment in this launch mode.

The remaining launch work includes that incomplete product work as well as
owner-controlled external systems and decisions (see `OWNER_ACTIONS.md`). It does not
include a Stripe or PostgreSQL integration.

## Implemented launch surface

- Anonymous browser-local OpenAPI review with a committed sample on first visit.
- Same-origin, pinned Pyodide runtime and Heel wheel; no analyzer network calls.
- Explicit local browser save/export without retaining the source document.
- Checked-in Heel 1.3.0rc3 runner preview candidate wheel, source archive, and manifest under
  `apps/heel-cloud/public/downloads/`, and the local stdio MCP quickstart. The 1.3.0rc3 candidate
  is not yet published; its runner code equals the 1.3.0rc2 component, which is published as the
  public GitHub prerelease
  <https://github.com/ancilis/heel/releases/tag/v1.3.0rc2>, with a one-command hash-pinned install
  whose independent anonymous run passed on Apple silicon macOS with Python 3.13.5. It is not a
  stable release, its release record is not immutable, it is not published to PyPI, and the website
  that bundles these files is not publicly deployed. It corrects the public 1.3.0rc1 prerelease's `error_envelope` and `hardened`
  errata (an error envelope is inconclusive at every HTTP status), stores no inconclusive
  plan-differential pair as a finding, and never passes a regression whose denial status still
  carries the paid payload. Publishing the component is not a completed customer journey:
  runner pairing, `heel runner serve`, HTTPS target traffic, hosted findings and the full customer
  acceptance remain unproven.
- Local CLI/MCP review without an account.
- Free account signup/login and private `__Host-heel_session` handling at the edge.
- Browser-mediated device authorization for CLI/MCP machines.
- Project creation/listing and server-generated project namespace keys.
- Immutable findings-only projections, exact digest approval, retry fencing,
  idempotent sync, validated receipts, and project review history.
- Free-launch plan availability and quotas with paid checkout disabled.
- Fail-closed production server configuration, migrations, SQLite WAL/FULL,
  adjacent process locking, durable-volume Compose deployment, health checks,
  backup verification, and private edge authentication.
- Cloudflare Worker route/header allowlisting and private VPC service binding.

Raw OpenAPI and full review context are not cloud payloads. Optional sync is limited
to the closed findings projection.

## Required pre-deployment verification

From the repository root:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest \
  tests.test_saas_server \
  tests.test_saas_deployment \
  tests.test_saas_device_auth \
  tests.test_saas_findings_http_api \
  tests.test_cloud_auth \
  tests.test_cloud_client \
  tests.test_sync_queue \
  tests.test_cli_sync \
  tests.test_mcp_sync -v
python3 scripts/saas_smoke.py
```

Browser/Worker verification:

```bash
python3 scripts/build_browser_engine.py \
  --output apps/heel-cloud/browser-engine --check
python3 scripts/build_browser_sample.py --check
python3 -m unittest \
  tests.test_browser_engine_build \
  tests.test_browser_review \
  tests.test_browser_sample \
  tests.test_browser_native_parity -v
cd apps/heel-cloud
npm ci --ignore-scripts --no-audit --no-fund
node --test tests/browser-engine.test.mjs
npm run test:unit
npm run typecheck
npm run lint
HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
  npm run build
npm run test:node
```

Use the real canonical origin and VPC service UUID for the deploy candidate. Do not
substitute a fake binding in a release build.

## Launch sequence

1. Complete the owner actions for domain/DNS, Cloudflare Worker/Tunnel/VPC service,
   private Linux container host, persistent volume, secrets, legal/support copy, and
   backup/uptime monitoring.
2. Create the two separate secret files as described in `OPERATIONS.md` ("Deploy the
   private services"). The ignored `deploy/.env.production` holds only control-plane
   values: remove the `HEEL_CLOUDFLARE_TUNNEL_TOKEN` and `HEEL_CLOUDFLARED_IMAGE` lines
   that `deploy/.env.production.example` still lists. Those two values go only into a
   0600 interpolation file outside the checkout, in a 0700 directory. Fill values
   through the deployment secret manager, never on a command line.
3. Run the verification commands above.
4. From the checkout root, validate and start the private control plane. Every Compose
   command passes the interpolation file with `--env-file`:

   ```bash
   HEEL_INTERP_ENV="$HOME/heel-secrets/cloudflared-interp.env"
   hc() { docker compose -f deploy/compose.yaml --env-file "$HEEL_INTERP_ENV" "$@"; }
   hc config --quiet
   hc up -d --build
   hc ps
   ```

   `hc config --quiet` must exit 0 with no output. Never run bare `config`,
   `config --format`, `docker inspect`, `exec … env`, or `set -x`. If the separated
   configuration does not work, stop and roll back (`RUNBOOKS.md` "Rollback"). Never
   put the Tunnel token into `deploy/.env.production`.

5. Configure the Worker secret `CONTROL_PLANE_EDGE_SECRET` with the exact same value
   as `HEEL_EDGE_AUTH_SECRET_B64`, then deploy the Worker:

   ```bash
   cd apps/heel-cloud
   HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
   HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
     npm run deploy:dry-run
   HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
   HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
     npm run deploy
   ```

6. Verify the public anonymous sample and private signup/device/project/sync flows;
   verify `/v1/readyz` privately; take and verify the first database backup.
7. Record the deployed image digest, Worker version, schema version, public origin,
   VPC service ID, Tunnel identity, backup location, and rollback point.

## Go/no-go gates

Go only if:

- the full Python and browser/Worker gates pass on the deploy candidate;
- the control plane has no public host port and only one process owns the database;
- the persistent volume and restore-verified backup exist;
- public and private edge secrets match without appearing in source or logs;
- anonymous review still works when the control plane is unavailable;
- a network inspection confirms raw OpenAPI and review context never leave the
  browser during local review or findings sync;
- Free is the only available plan and checkout returns unavailable;
- legal, privacy, support, incident, and data-retention contacts are published;
- the owner has approved the production domain and deployment.

The Docker image has not been executed in this workspace because no Docker daemon was
available. No public deploy has occurred.
