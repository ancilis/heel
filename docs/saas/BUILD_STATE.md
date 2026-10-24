# Latest private deployment

The owner-private Sites update is recorded in [DEPLOYMENT_2026-09-05.md](DEPLOYMENT_2026-09-05.md). No public launch or Python control-plane deployment is claimed.

# Heel SaaS Build State

Updated 2026-09-04; the download-artifact and launch-readiness entries were corrected 2026-10-23. The current validation wedge is the [synthetic export entitlement workflow](../EXPORT_DEMO.md); see [capabilities](../CAPABILITIES.md). Cloud pairing is not a supported end-to-end customer journey. Passing static gates does not establish launch safety. This file records the product that exists in the current
repository state. It does not record a public deployment.

## Launch decision

The implemented launch is **Heel free early access**:

- Free is available without a card.
- Pro and Team are coming soon.
- `heel.saas.server` accepts only `HEEL_BILLING_MODE=free_launch` and installs
  `DisabledBilling`.
- Checkout is unavailable and no payment is accepted.
- Stripe and PostgreSQL are later work, not blockers for this bounded free launch.

## Customer product implemented

- Anonymous browser-local OpenAPI 3.0/3.1 review with a committed sample and visible
  result on first use.
- Pinned same-origin browser runtime and dedicated Python Web Worker.
- Optional local browser save, delete, clear, JSON export, and Markdown export.
- Checked-in Heel 1.3.0rc2 runner preview candidate wheel/source/manifest under
  `apps/heel-cloud/public/downloads/`, and local MCP setup. The candidate is unreleased: it is
  not published as a GitHub release or to PyPI, and it is not publicly deployed. It reports the
  synthetic reference `error_envelope` case as inconclusive, and status-only or undecided
  plan-differential pairs store no finding. The earlier 1.3.0rc1 preview is a public GitHub
  prerelease whose `error_envelope` result is a documented erratum; its files are no longer in
  the tree. Earlier versions of this file listed the 1.2.0 files, which are no longer in the
  tree either.
- Local CLI and MCP review without an account.
- Free signup/login/logout at the website.
- Browser-mediated device authorization for a local machine.
- Cloud project creation/listing and server-generated namespace keys.
- Exact privacy-minimized findings projection in browser and Python clients.
- Interactive exact-digest approval, durable retry queues, fenced leases/transmission,
  idempotent sync, strict receipts, and project history.
- Free catalog limit of three new synced review projections per catalog period.

Raw OpenAPI, guided answers, arbitrary metadata, and full review context are not part
of the cloud sync contract.

## Production deployment implemented

- `heel.saas.server` validates all production environment invariants before binding.
- Required production values:
  `HEEL_DATABASE_PATH`, `HEEL_PUBLIC_ORIGIN`,
  `HEEL_DEVICE_TOKEN_PEPPER_B64`, `HEEL_API_KEY_PEPPER`, and
  `HEEL_EDGE_AUTH_SECRET_B64`.
- Non-loopback service binds require
  `HEEL_PRIVATE_NETWORK_ACK=private-vpc-only`.
- One SQLite database uses WAL and `synchronous=FULL` on a persistent volume.
- One adjacent owner-only POSIX process lock prevents multiple database owners.
- Startup applies migrations; graceful shutdown stops admission, drains accepted
  requests for up to 30 seconds, and checkpoints before close. Compose grants 35
  seconds before container termination.
- The non-root control-plane image runs `python -m heel.saas.server`.
- `deploy/compose.yaml` has one control plane and one `cloudflared`, a named persistent
  volume, no public host port, and health-gated Tunnel startup.
- The public Cloudflare Worker uses exact route/header allowlists, a VPC service
  binding, and a shared private edge-auth secret.
- Public sessions use `__Host-heel_session`; the private control plane receives only
  the translated `heel_session` credential.
- Online SQLite backup and restore verification are implemented in
  `scripts/saas_backup.py`.

## Supported launch boundary

- Browser review supports modern Windows browsers.
- The production server, machine credential fallback, and machine sync queue require
  POSIX/Linux security primitives.
- Windows machine cloud continuity is not launch-supported.
- The deployment is single-node. Multiple control-plane replicas against the same
  database are prohibited.

## Verification commands

Core and continuity:

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

Browser/Worker:

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

Deployment bundle:

```bash
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml config
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env.production \
  -f deploy/compose.yaml ps
```

## Not yet done

- No public domain/provider deployment has occurred.
- The Docker image was not executed in this workspace because a Docker daemon was
  unavailable.
- Production domain, Worker account, Tunnel, VPC service UUID, provider deployment
  credentials, durable host volume, and monitored backup destination remain owner
  actions.
- Production secrets have not been supplied.
- Legal/privacy/support materials still require owner approval for public use.
- Staging and public acceptance against the selected provider/domain remain to be run.
- The full self-serve product is not launch-ready. Paired runner execution, the cloud route
  inventory bridge, and approval wiring are incomplete, and final launch acceptance has not
  been given. Owner actions alone do not close these gaps.
- The 1.3.0rc2 candidate files are not yet published, and a one-command public install of a
  corrected release is later work.

## Exact next action

Finish the incomplete product work listed above, complete `OWNER_ACTIONS.md`, run the
verification commands against the real deploy
candidate, deploy first to staging, complete the go/no-go gates in `LAUNCH.md`, and
only then authorize the first public free early-access deployment.
