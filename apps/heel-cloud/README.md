# Heel Cloud

Heel Cloud is the deployable website and optional findings-continuity service for Heel.
The current launch is an evidence-first browser workspace for free early access. Free
is the only available plan, Pro and Team are shown as coming soon, checkout is
disabled, and no payment is accepted.

No public deployment has occurred from this repository.

## What customers can use

- The browser review works immediately without an account. It loads the pinned,
  same-origin Python runtime and reviews a sample or an OpenAPI 3.0/3.1 JSON document
  in a Web Worker.
- Raw OpenAPI, guided answers, and full review context stay in browser memory and are
  never uploaded. A customer can optionally save a validated result locally in that
  browser and export it locally.
- The downloadable CLI and stdio MCP server also run locally. They do not require a
  Heel account for local review.
- A customer may opt into cloud continuity. Account and project setup are explicit;
  CLI/MCP machines use browser-mediated device authorization. Every sync requires an
  exact findings-only projection and a short-lived approval. Raw OpenAPI and full
  review context are never part of the sync request.
- Free workspaces may store up to three new synced review projections per catalog
  period. Paid Pro and Team capabilities are not available during free launch.

The browser experience works on supported Windows browsers. The machine credential
fallback and durable machine sync queue require POSIX descriptor and file-locking
semantics; Windows CLI/MCP cloud continuity is not launch-supported.

The exact builder-verified Agent files advertised on `/agent` are the 1.3.0rc1 runner preview.
The same files are published as a public GitHub prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc1>. That prerelease is not a stable release,
its release record is not immutable, it is not a deployed Heel Cloud URL, and it does not indicate
customer acceptance. `heel-sim` is not yet published to PyPI. `/agent` and `/runner` also show a
no-download install of the hash-pinned public wheel and require a physical, symlink-free `HEEL_HOME`
(for example `"$(pwd -P)/.heel"`). The same-origin files are:

- `/downloads/heel_sim-1.3.0rc1-py3-none-any.whl`
- `/downloads/heel_sim-1.3.0rc1.tar.gz`
- `/downloads/heel-open-core-manifest.json`

## Dashboard account onboarding

`/dashboard` lets a visitor create an account or sign in, then choose a workspace and a
project, using only the existing `/v1/signup`, `/v1/login`, `/v1/logout`, `/v1/me` and
`/v1/workspaces/{ws}/projects` routes and the HttpOnly session cookie.

- Signup creates the account and one default workspace (server behavior). There is no route
  to create another workspace, and free workspaces have one seat, so invites return 402.
- The selected workspace and project are kept in the address as `?workspace=ws_…&project=prj_…`
  so a reload restores them. They are opaque refs and are honored only when `/v1/me` and the
  project list for the current session still include them. No password, session token or
  selection is written to browser storage.
- Project creation is offered to owner, admin and member roles. The server still decides; a
  403 is shown as a role message. Billing-only workspaces cannot list projects.
- Sign-out, an expired session, a workspace/project switch, or same-document Back/Forward to
  another address starts a new load generation; the address is re-resolved like a reload.
  Responses (successes and failures, including 401) that arrive for an earlier generation are
  discarded, so they cannot fill or end a newer view. This includes a local summary file read
  that finishes after the switch. Busy state belongs to the action that started it: a new
  generation releases it, so an older pending action cannot disable the new view's controls or
  Sign out, and its late completion cannot release a newer action's busy state. A follow-up
  refresh after a binding create/revoke or proof check runs under the generation of the action
  that started it: if that generation is gone when the action settles, no refresh is sent, and a
  refresh that settles later cannot restore the old project, runner selection or address. The
  server-side change itself is not rolled back.
- If the canary reads (environments, runner context) fail after the account and project
  resolved, the workspace/project controls and Sign out stay available, the project stays in
  the address, and verification, runner access and rehearsals stay locked until Try again
  succeeds. A 401 there is still treated as session loss. When Try again succeeds, the
  "Project created … blocked" notice is replaced by the ready next step (or removed if staging
  is already verified); if the outage continues, the notice stays.
- Error states show fixed messages for invalid input, duplicate email, wrong password, rate
  limiting, forbidden, signed-out and unavailable. Submitted values are never echoed.

Evidence: `tests/account-onboarding.test.tsx` (stubbed `fetch` and router) and
`tests/account-loopback.test.ts`, which runs the real Python `ControlPlane` over loopback HTTP
when `HEEL_LOOPBACK_PYTHON` is set; otherwise it is skipped. Neither test goes through the
Worker, TLS or a public origin.

## Production topology

The public artifact targets a Cloudflare Worker. Its proxy has an exact method/path
allowlist and reaches the Python control plane only through a Cloudflare VPC service
binding. It does not provide a general-purpose reverse proxy.

The control plane runs `python -m heel.saas.server` as one non-root process. The
production contract is deliberately single-node:

- SQLite on a persistent volume, with WAL and `synchronous=FULL`;
- one adjacent nonblocking process lock at `<database>.lock`;
- a canonical HTTPS `HEEL_PUBLIC_ORIGIN`;
- required device-token, API-key, and edge-auth secrets;
- `HEEL_BILLING_MODE=free_launch`, backed by disabled checkout;
- no public control-plane host port.

`deploy/compose.yaml` starts the private control plane and `cloudflared`. It uses
`expose`, not `ports`. The public Worker converts the public
`__Host-heel_session` cookie to the private `heel_session` cookie, strips ambient
credentials and forwarding headers, adds the shared edge-auth secret, and forwards
only allowlisted control-plane operations.

## Build and verification

## Node versions

- Production and hosting: Node.js `>=24.13.1`
- Security verification: Node.js 25+; Node.js 26 is recommended

The Python package supports Python 3.11+; release reproducibility uses Python 3.13.

From the repository root:

```bash
env PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1 \
  python3.13 -m pip --isolated install \
  --require-hashes --only-binary=:all: \
  -r release/requirements-release.txt
python3.13 scripts/build_open_core_release.py \
  --output apps/heel-cloud/public/downloads --check
HEEL_REQUIRE_STANDARD_BUILD=1 \
  python3.13 -m unittest tests.test_open_core_release -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest \
  tests.test_saas_server \
  tests.test_saas_deployment \
  tests.test_saas_device_auth \
  tests.test_saas_findings_http_api -v
python3 scripts/build_browser_engine.py \
  --output apps/heel-cloud/browser-engine --check
python3 scripts/build_browser_sample.py --check
python3 -m unittest \
  tests.test_browser_engine_build \
  tests.test_browser_review \
  tests.test_browser_sample \
  tests.test_browser_native_parity -v
```

Then build the Worker artifact with the real public origin and Cloudflare VPC
service UUID:

```bash
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

The build verifies the committed Agent downloads without regenerating them.

CI also runs `npm audit --omit=dev --audit-level=high --package-lock-only
--ignore-scripts --no-fund` after `npm ci`. It covers only lockfile packages npm does not mark
as dev, so it is not complete Worker-runtime coverage: vinext and other dev-declared
packages are bundled into the Worker but are outside this check.

## Deployment

1. Copy `deploy/.env.production.example` to the ignored
   `deploy/.env.production` and fill it through the deployment secret manager.
2. Provision the domain, Cloudflare Tunnel, and VPC service. The VPC service UUID
   supplied to the Worker build must identify the private control-plane service.
3. Set the Worker's `CONTROL_PLANE_EDGE_SECRET` to the same canonical base64url
   value used as `HEEL_EDGE_AUTH_SECRET_B64` by the control plane.
4. Validate and start the private services:

   ```bash
   docker compose --env-file deploy/.env.production \
     -f deploy/compose.yaml config
   docker compose --env-file deploy/.env.production \
     -f deploy/compose.yaml up -d --build
   docker compose --env-file deploy/.env.production \
     -f deploy/compose.yaml ps
   ```

5. After the Worker account, domain, VPC binding, public origin, and Worker secret
   exist, deploy from `apps/heel-cloud`:

   ```bash
   HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
   HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
     npm run deploy:dry-run
   HEEL_PUBLIC_ORIGIN=https://YOUR_HEEL_DOMAIN \
   HEEL_CONTROL_PLANE_VPC_SERVICE_ID=YOUR_VPC_SERVICE_UUID \
     npm run deploy
   ```

These are the repository's deployment commands, not evidence of a completed public
deployment. The Docker image was not executed in this workspace because a Docker
daemon was unavailable.
