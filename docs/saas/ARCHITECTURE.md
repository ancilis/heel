# Current business-abuse validation architecture — September 4, 2026

OpenAPI and ProductModel feed the pure static review. Optional ProductModel business_rules declare intended invariants and their source; lifecycle_sequences retain ordered actors/actions without asserting execution. Unknown controls produce questions. Static result evidence_state, execution_disposition and severity are distinct; the strict Python/TypeScript contract accepts historical records while rejecting verified behavior in new static records.

`heel reference prepare` connects the export rule to a bounded hypothesis. A human-created signed scope authorizes `reference:export`. CLI or MCP execution consumes an exclusive attempt ID, constructs a reference-only signed compiler manifest/grant and runs the existing LocalCanaryExecutor. A closed in-process transport calls ExportProduct's account and export-license handler twice. It accepts no external origin or replacement product/transport. Reference authority keys never enter cloud trust.

The executor assesses exact protected content from the local bounded evidence sink. Both role actions share an approved fixture. Status alone is insufficient; a positive entitled baseline is mandatory. It retains raw evidence in RunnerStore and emits existing closed projections without response bodies. A reference report explains the rule, result, provenance, fix, regression and gaps. The app imports only a local synthetic report summary; it does not execute targets or authenticate imported report signatures.

Production TargetHTTPSClient, target proof, cryptographic grant binding, replay, stop handling and separate disclosure remain their existing independent safety boundaries. Cloud pairing and arbitrary customer-target CLI/MCP execution are incomplete. See [capabilities](../CAPABILITIES.md) and [demo](../EXPORT_DEMO.md).

---

The following describes the broader existing control-plane implementation, not completion of a public validation journey.

# Heel SaaS Architecture

Heel's free early-access launch has two intentionally different data boundaries:
local review and optional findings-only continuity. Local value does not depend on
the hosted service.

## Customer flow

1. A visitor opens the Heel website and can run the committed sample or review an
   OpenAPI JSON document without an account.
2. The same-origin Pyodide runtime and Heel wheel run inside a dedicated browser
   Web Worker. The analyzer makes no network request after those runtime assets are
   loaded.
3. Raw OpenAPI, guided answers, and complete review context remain local. A customer
   may save a validated result envelope to that browser's IndexedDB or export it
   locally.
4. If continuity is useful, the customer creates or signs into a free account,
   chooses a project, previews the exact minimized findings projection, and approves
   that exact digest. Only the closed `heel.findings-sync.v1` projection is sent.
5. CLI and MCP use the same local-first model. Device authorization happens in the
   browser; MCP may prepare a projection, but final machine approval remains an
   interactive CLI/browser action.

## Public edge

The public application is a Cloudflare Worker built from `apps/heel-cloud`.

- Browser review assets are same-origin and integrity-pinned.
- The control-plane proxy uses an exact method/path allowlist for account, device,
  project, findings-sync, and review-history operations.
- Requests are reconstructed from an allowlist. Ambient cookies, authorization,
  forwarding headers, caller-supplied internal headers, and arbitrary routes are not
  forwarded.
- Browser sessions use `__Host-heel_session; Secure; HttpOnly; SameSite=Lax; Path=/`.
  Only that cookie is translated to the private `heel_session` cookie.
- Every private request carries `X-Heel-Edge-Auth`, sourced from the Worker's
  `CONTROL_PLANE_EDGE_SECRET` secret.
- The private origin is reached through the `CONTROL_PLANE` Cloudflare VPC service
  binding. The Worker has no configured public origin URL for the control plane.

## Private control plane

`heel.saas.server` is the only production entrypoint. It fails before binding unless
all required production invariants are present:

- `HEEL_DATABASE_PATH` is an absolute file below an existing durable directory;
- `HEEL_PUBLIC_ORIGIN` is one canonical HTTPS origin;
- `HEEL_DEVICE_TOKEN_PEPPER_B64` encodes 32–64 random bytes as canonical base64url;
- `HEEL_API_KEY_PEPPER` is a 32–256 character secret;
- `HEEL_EDGE_AUTH_SECRET_B64` encodes 32–64 random bytes as canonical base64url;
- a non-loopback listener includes `HEEL_PRIVATE_NETWORK_ACK=private-vpc-only`;
- `HEEL_BILLING_MODE` is exactly `free_launch`.

The server enables device authorization, project namespace keys, exact findings-only
sync, receipts/history, tenancy, quotas, operational health, and the existing local
SaaS controls. It installs `DisabledBilling`; checkout returns service unavailable,
Free is available, and Pro/Team are coming soon.

## Persistence and process model

The production launch is one process with one SQLite database on a persistent volume.

- Startup applies the versioned control-plane migrations.
- SQLite uses WAL and `synchronous=FULL`.
- An adjacent owner-only `<database>.lock` is acquired with a nonblocking POSIX
  `flock`. A second process refuses to start.
- Graceful shutdown stops admission, allows accepted requests up to 30 seconds to
  drain, and checkpoints the WAL before SQLite closes. Compose gives the process a
  35-second stop grace period before the container runtime may terminate it.
- `scripts/saas_backup.py` uses SQLite's online backup API and verifies integrity,
  migration currency, and reconciliation before a restored copy is eligible for use.

This is not a horizontally scalable database topology. Do not run multiple replicas
against the volume. PostgreSQL and managed multi-node execution are later adapters,
not blockers for the bounded free launch.

## Privacy and authorization boundaries

- Cloud sync contains pseudonymous project/finding/surface references, closed risk
  and control codes, severity/reachability, counts, and projection provenance. It
  never contains raw OpenAPI, questions, answers, arbitrary metadata, or the full
  local review.
- Browser and machine queues store the exact immutable projection plus bounded
  approval/retry state. A fresh short-lived approval is required before transport.
- Device access and refresh credentials are scoped to the authorized workspace and
  capabilities. The production edge and private server independently validate the
  route, credentials, payload, and receipt binding.
- Server-side entitlement and quota checks remain authoritative. The free catalog
  allows three new synced review projections per catalog period.

## Supported launch environments

- Browser review: supported modern browsers, including Windows.
- Production control plane: POSIX/Linux with durable local storage and file locking.
- CLI/MCP local review: Python 3.11+.
- Machine credential fallback and durable findings queue: supported POSIX systems;
  Windows machine cloud continuity is not launch-supported.
