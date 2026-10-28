# Heel SaaS Owner Actions

These actions require a human legal identity, provider account, production credential,
or risk decision. They are the remaining blockers to the free early-access public
deployment.

## Required for the first public launch

1. **Approve the Heel domain and canonical origin.** Register or select the domain,
   configure DNS/TLS, and provide one exact value such as `https://heel.example` for
   `HEEL_PUBLIC_ORIGIN`. The Worker build and private control plane must use the same
   origin.

2. **Choose the production providers.** The implemented topology expects:
   - a Cloudflare account for the public Worker, remotely managed Tunnel, and VPC
     service binding;
   - one POSIX/Linux container host for the private control plane;
   - one persistent volume mounted at `/var/lib/heel`.

3. **Create the private Cloudflare path.** Create the Tunnel and route it to the
   Compose `control-plane:8080` service. Create the VPC service that the Worker binds
   as `CONTROL_PLANE`, and provide its UUID as
   `HEEL_CONTROL_PLANE_VPC_SERVICE_ID`. Provide the remotely managed Tunnel token and
   a reviewed immutable `cloudflared` image digest.

4. **Generate and store production secrets.** Generate independent random values in
   the provider secret managers; never commit them or place them in build logs:
   - `HEEL_DEVICE_TOKEN_PEPPER_B64`: canonical base64url, 32–64 random bytes;
   - `HEEL_API_KEY_PEPPER`: 32–256 non-whitespace printable characters;
   - `HEEL_EDGE_AUTH_SECRET_B64`: canonical base64url, 32–64 random bytes;
   - `HEEL_CLOUDFLARE_TUNNEL_TOKEN`;
   - deployment credentials for the Worker and private host.

   Configure the Worker secret `CONTROL_PLANE_EDGE_SECRET` to the exact
   `HEEL_EDGE_AUTH_SECRET_B64` value. The server rejects a missing or malformed
   secret; the edge returns unavailable when its secret is absent.

5. **Configure the production environment.** Copy
   `deploy/.env.production.example` to the ignored `deploy/.env.production` or map
   those names directly from the host secret manager. Preserve
   `HEEL_BILLING_MODE=free_launch`; do not enable a stub or live checkout.

6. **Approve legal and privacy materials.** A qualified human must approve Terms,
   Privacy, acceptable-use/authorized-target language, retention/deletion behavior,
   open-core/commercial licensing, and any required data-processing terms. Replace
   every template or draft marker before public exposure.

7. **Publish real support and incident contacts.** Choose the support email/channel,
   security reporting address, privacy contact, and operational incident owner.
   Decide the free early-access response expectations; do not advertise paid support
   or an SLA.

8. **Provision backup and monitoring ownership.** Choose the encrypted backup
   destination and retention, schedule `scripts/saas_backup.py`, alert on failed or
   missing backups, monitor Compose health and private `/v1/readyz`, and assign the
   person responsible for restore drills and disk-capacity alerts.

9. **Run and sign off on staging acceptance.** Use the real domain-equivalent origin,
   Tunnel, and VPC binding. Verify anonymous local review, signup/login/logout,
   device authorization, project creation, findings-only sync/history, quota errors,
   disabled checkout, backup/restore verification, and control-plane unavailability.
   Inspect browser requests to confirm raw OpenAPI and full review context never sync.

10. **Approve production go-live.** Record the selected image digest, Worker version,
    origin, VPC service UUID, Tunnel identity, database/backup locations, secret
    rotation owners, and rollback point. Then authorize the first public deploy.

## Explicitly not required for free launch

- Stripe accounts, price IDs, webhooks, tax configuration, or payment terms. Heel
  accepts no payments in `free_launch`; Pro and Team are coming soon.
- PostgreSQL or a managed queue. The implemented launch is bounded to one process and
  one durable SQLite volume.
- SSO, SCIM, private runners, multi-region operation, or paid support integrations.
- A Windows machine credential/queue implementation. Windows browser review works;
  Windows CLI/MCP cloud continuity is not launch-supported.

These become separate product and architecture decisions before paid plans or
horizontal scaling are enabled.
