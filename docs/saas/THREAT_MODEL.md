# Heel free-launch threat model

Scope: the anonymous local review, browser-mediated device authorization, private
single-node control plane, and optional findings-only continuity shipped for free early
access. Paid billing and public verified-target execution are outside this launch.

## Assets

- Raw OpenAPI, guided answers, and full review context. These remain on the customer's
  device and are not accepted by a cloud endpoint.
- Findings projections, project namespace keys, sync receipts, and review history.
- Account sessions, device grants, refresh/access tokens, API keys, tenant roles, and
  project membership.
- The private-origin edge secret, credential peppers, SQLite volume, backups, and Tunnel
  token.

## Trust boundaries

- Browser review and local MCP/CLI review are untrusted-input, no-network computations.
- MCP can prepare a findings projection and read status/history; it cannot sign in, grant
  consent, approve a device, send, retry, refresh, or revoke credentials.
- A human browser session must approve the exact device request and each exact findings
  projection. A persisted, short-lived, fenced transmission permit is the only send
  authority.
- The public Worker exposes an exact method/path allowlist. It strips ambient credentials
  and forwarding/internal headers, derives a keyed opaque signup/device client key, adds
  edge authorization, and streams only allowlisted requests to the private VPC service.
- The Python origin rejects stateful requests without the shared edge secret. It is not
  published directly and has no host port in `deploy/compose.yaml`.

## Threats and implemented controls

| # | Threat | Control |
|---|---|---|
| T1 | Raw source or review-context upload | Cloud request schemas accept only the canonical minimized findings projection; browser/runtime privacy tests reject network capability in anonymous review. |
| T2 | Agent silently authorizes disclosure | MCP registry is prepare/read-only; browser/device consent and CLI transmission are deliberately separate human actions. |
| T3 | Stale, replayed, or cross-record consent | Exact digest binding, short expiry, server transport approval, persisted transmission fencing, one live lease, and permit-bound completion. |
| T4 | Cross-tenant access / IDOR | Server-resolved principals, workspace/project capability checks, immutable tenant-scoped namespace keys, and adversarial cross-tenant tests. |
| T5 | Device-code phishing or token replay | Browser inspection before decision, recent-auth requirement, verifier binding, poll throttling, one-time exchange, refresh rotation, and family revocation on reuse. |
| T6 | Direct-origin or header spoofing | Private Tunnel/VPC topology plus mandatory shared edge authorization; caller forwarding and internal headers are removed and overwritten at the Worker. |
| T7 | Signup/trial farming | HMAC-derived opaque edge client keys, per-client and global signup limits, atomic quota reservation, and platform/workspace kill switches. |
| T8 | Paid-path exposure | `HEEL_BILLING_MODE=free_launch`, production `DisabledBilling`, checkout unavailable, and billing/metrics absent from the public Worker allowlist. |
| T9 | SQLite corruption, split ownership, or close during a live request | One process lock, one instance, local durable volume, migrations before bind, WAL, `synchronous=FULL`, readiness schema checks, a 30-second active-request drain within a 35-second container grace, checkpointed shutdown, backups, and restore verification. |
| T10 | Secret or diagnostic leakage | Required secret validation, hashed stored credentials, no committed production values, generic client errors, and redacted structured internal-error events containing only request ID, method, and exception type. |
| T11 | Supply-chain substitution | Pinned browser runtime, digest-pinned release artifacts, exact open-core allowlist, commercial-source boundary checks, and non-root read-only container contract. |

## Residual risks and launch constraints

- Cloudflare accounts, domain/Tunnel/VPC configuration, immutable image selection,
  off-instance backups, monitors, support contact, and approved legal text remain owner
  actions. They cannot be fabricated in source control.
- The Docker artifact has static contract coverage but was not executed in this workspace
  because no Docker daemon was available. It must pass the documented host dry run before
  public traffic.
- SQLite free launch is intentionally one node and one process. No autoscaling, shared
  filesystem, NFS, or overlapping deploy is supported.
- Windows browser review is supported; Windows machine credential storage and the durable
  MCP/CLI cloud queue are not launch-supported.
- Paid plans require a new billing security review, live-provider adapter, transactional
  event handling, tax/refund/support decisions, and dedicated lifecycle tests.
