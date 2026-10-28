# Customer acceptance readiness

Current status: **BLOCKED**. No public deployment exists (`apps/heel-cloud/README.md`), and
discovery, managed scanning, credentials, findings and regression on the default path are not
implemented. Nothing in this document, the preflight or the local tests is customer acceptance.

The deployed journey this prepares for is:

`public HTTPS → browser account/session → URL ownership → discovery authorization/plan →
managed scan → findings/evidence → regression → credential/evidence delete + target revoke`

The final acceptance sequence (Layer 1 detection proof, Layer 2 onboarding proof) is fixed by
`docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md` §6.2–§6.5. This page
adds the operator gates that must hold before such a run and the evidence format.

## Evidence classes

| Class | Produced by | Counts as acceptance |
|---|---|---|
| `local-synthetic-test` | `tests/test_customer_acceptance_preflight.py` (fake resolver, sockets and TLS) | Never |
| Local HTTP integration | `tests/test_customer_onboarding_acceptance.py` (real `heel.saas.server` process, loopback HTTP) | Never |
| `deployed-preflight` | `scripts/customer_acceptance_preflight.py` against the canonical public origin | Never by itself; it only records what is still blocked |
| Deployed acceptance | A browser on the released public origin through Worker, private control plane, managed executor, real HTTPS target, persistence and dashboard | Only this, per stage |

A source checkout, database edit, seeded row, hidden admin call, manual findings copy, local fake
transport, prepared reference demo, owner-private local-review deployment or customer-installed
runner never produces deployed acceptance evidence.

## Preflight

```bash
# From the root of a Heel source checkout, with an interpreter that has dnspython==2.8.0
python scripts/customer_acceptance_preflight.py \
  --public-origin https://YOUR_CANONICAL_HOST \
  --output /absolute/path/to/redacted-evidence
```

Supported environment: this is an operator command. It runs from the root of a Heel source
checkout, because it imports the reviewed guards in `heel/saas/network_guard.py` from that checkout,
using Python 3.11+ (`pyproject.toml` `requires-python`) with the pinned control-plane DNS
dependency `dnspython==2.8.0`. `pyproject.toml` declares no extra for that dependency
(`dependencies = []`; the only extra is `runner`). Install the same wheel, verified by the same
sha256, as the "Install pinned runner/control-plane wheels" step in `.github/workflows/ci.yml` or
the `deploy/Dockerfile.control-plane` image. Without it the report is `FAIL` with
`dns_resolution_failed`. It is not part of the public runner install: the `heel_sim` wheel and its
`runner` extra ship only the `heel` and `heel.runner` packages (`pyproject.toml`
`[tool.setuptools]`), not `heel.saas`. It is not a no-checkout customer command.

This is an unauthenticated operator check of the Heel public origin. It is not a customer-target
scanner and does not change customer-evidence custody.

Run it only after the release owner has established the public origin; do not run it against a
placeholder to manufacture a negative result. It takes no other input and reads no environment
variable: never pass a password, token, credential, target URL, target body, provider or account
value.

The origin must be exactly `https://host` as accepted by the ownership verifier
(`heel.saas.network_guard.normalize_verified_origin`): lowercase public DNS name under an IANA
root-zone TLD, no port, path, query, fragment, userinfo, IP literal, IDNA, special-use or
reserved name (`.example`, `.test`, `.localhost`, `.local`, `.internal`, `example.com` and the
like), and not the owner-private local-review origin in `docs/saas/OPERATIONS.md`. A rejected
origin makes no network request.

The single network action is one unauthenticated, bounded, header-oriented `GET /` using the
verifier's guards: a bounded DNS answer in which every address must be public, a connection to
the selected address, TLS 1.2+ with certificate and hostname verification, a 5-second deadline
for the whole probe, and no redirect following.

Receives stop once the header block ends. In total they never exceed 16,388 bytes
(`MAX_CHALLENGE_HEADER_BYTES` + 4), and a longer header block fails as `malformed_response`.
TLS/TCP has no boundary between headers and body, so a receive can also deliver a bounded body
prefix coalesced with the headers. That prefix lands in a transient in-memory receive buffer, and
the TLS library and kernel may buffer more until the connection closes. The probe does not claim
that no response-body bytes are received or held briefly in memory. Only the status line is
parsed. Header values and any body prefix are not parsed, and they are never persisted, reported
or logged. No body bytes, header values, cookies or redirect locations appear in the report,
stdout, stderr or error text.

A 2xx answer proves reachability only. `GET /` cannot bind Heel identity, release revision or
readiness (the Worker exposes no public health route and the readiness probe is private), so
`public_https` stays `blocked` with `heel_identity_unproven`. It can become `proven` only from
deployed evidence that binds the origin to a recorded release.

### Report `heel.customer-acceptance-preflight.v1`

Written to `<output>/customer-acceptance-preflight.json`:

```json
{
  "schema_version": "heel.customer-acceptance-preflight.v1",
  "classification": "READY_FOR_LIVE_ACCEPTANCE|BLOCKED|FAIL",
  "public_origin": "https://HOST or null when the input was rejected",
  "observed_at": "UTC RFC3339",
  "evidence_class": "deployed-preflight|local-synthetic-test",
  "stages": [{"id": "public_https", "state": "proven|blocked|failed", "reason_code": "...", "evidence": "..."}],
  "external_blockers": [{"owner": "...", "next_test": "..."}]
}
```

`FAIL` when any stage failed; otherwise `BLOCKED` when any stage is blocked or the evidence class
is `local-synthetic-test`; `READY_FOR_LIVE_ACCEPTANCE` only when every stage is `proven` from a
deployed preflight. No supplied attestation can raise the classification. Exit codes: `0` ready,
`1` fail, `2` rejected origin (a `FAIL` report is still written), `3` blocked, `4` unusable
output directory.

`public_https` failure reason codes: `origin_rejected`, `dns_resolution_failed`,
`non_public_address`, `transport_failed`, `transport_timeout`, `tls_verification_failed`,
`tls_failed`, `peer_mismatch`, `malformed_response`, `redirect_refused`, `non_2xx_status`.

### Stages

| Stage | Current state | Reason code | Unblocked by |
|---|---|---|---|
| `public_https` | blocked or failed | `heel_identity_unproven` | Public release plus deployed identity/readiness evidence bound to its revision |
| `browser_auth` | blocked | `deployed_browser_session_unproven` | Released browser signup/login through the Worker on the public origin |
| `onboarding_target` | blocked | `ownership_proof_and_authorization_unrecorded` | Product-recorded ownership proof and the customer statement |
| `discovery_plan` | blocked | `blocked_on_c2_c3` | C2 + C3 landed and deployed |
| `managed_scan` | blocked | `blocked_on_c4` | C4 landed and deployed |
| `findings_evidence` | blocked | `blocked_on_c6` | C6 landed and deployed |
| `regression` | blocked | `blocked_on_c6` | C6 landed and deployed |
| `delete_and_revoke` | blocked | `blocked_on_c5_decision_and_c6` | Credential-custody decision, C5 and C6 |

## Local onboarding evidence

`tests/test_customer_onboarding_acceptance.py` starts the unmodified production entrypoint
`python -m heel.saas.server` with a synthetic configuration on a temporary SQLite volume and
drives only public routes with a plain HTTP client: signup, session, project creation, target
registration (challenge issued, status unverified, not executable), logout, a process restart on
the same volume, login, and re-reading the project and target, plus tenant isolation. It checks
that the server log contains no password, session, challenge token or edge secret.

Its controlled seams are explicit: the test supplies the edge-authentication, client-key and
same-origin headers that the Worker would add; transport is loopback HTTP, not TLS through the
Tunnel/VPC; the public origin is the synthetic `https://heel.example`; the registered target is
the reserved `https://staging.example.com`, which is never contacted, and ownership `check` is
never called. It proves the local API contract only.

## Gates before any live run

Every item is recorded (with a redacted evidence location) before the first deployed acceptance
step. A missing item keeps the run blocked.

1. **Release identity.** The canonical public URL, the released Worker version, the control-plane
   and executor image digests, and the source commit as an immutable revision. Deployment follows
   `docs/saas/OPERATIONS.md` ("Deploy the private services", "Deploy the public Worker"); the
   preflight is rerun against that exact origin and its report kept.
2. **Released product only.** Authenticated browser evidence comes from the released product on
   that origin, not from a source checkout, database edit, seed, hidden admin call, manual findings
   copy or reference demo.
3. **Release and migration.** The read-only schema state of the deployed database is recorded
   with `python3 -m heel.saas.migrate status /absolute/path/to/control-plane.sqlite3`
   (`current` must equal `target`), and the release's verification commands in
   `docs/saas/OPERATIONS.md` ("Verify") passed at the recorded revision.
4. **Verified pre-run backup.** A backup taken and verified with `scripts/saas_backup.py`
   (`docs/saas/OPERATIONS.md` "Backup", `docs/saas/RUNBOOKS.md` "Backup and restore
   verification") immediately before the run, stored at an encrypted failure-independent location.
5. **Rollback point and restore drill.** The previous Worker version and image digests are named
   as the rollback point, and a restore drill of the pre-run backup into a scratch instance has
   passed per `docs/saas/RUNBOOKS.md`.
6. **Kill-switch owner.** A named operator owns the global and workspace kill switches
   (`heel/saas/ops.py`) for the run and records the exact live check they will use. The repository
   ships no deployed operator command for this; until the operations owner defines and records
   one, this gate is unmet. The preflight task performs no production mutation, including no
   kill-switch trip.
7. **Customer authorization.** Product-recorded ownership proof for the target, plus the customer
   authorization and the customer-provided provenance statement (synthetic data, not prepared for
   Heel), quoted from the customer's own record. Ownership proof alone establishes neither
   authorization scope nor provenance.
8. **Credential custody.** No credentialed step runs until the credential-custody decision is
   recorded and C5 is implemented. Never store, transmit or prompt for real target credentials
   outside that path.

## Step dispositions

Each acceptance step gets exactly one recorded disposition with a timestamp and redacted evidence
location:

- `proven` — deployed evidence exists for the step.
- `findings.none` — the scan completed and found nothing; reported honestly with per-route
  reasons, never replaced by a fabricated finding.
- `partial` — some of the step completed; the missing part and its reason are named.
- `blocked` — a named dependency is absent (as in the stage table above).
- `gap` — the product cannot support the target at this step (for example MFA, SSO, CAPTCHA,
  private address or no possible proof); shown as a gap, not hidden.
- `failed` — the step ran and did not meet its contract.

## Evidence handling

Record **redacted** evidence locations only: report paths, release identifiers, timestamps,
status codes, request counts and digests. Never record secret values, passwords, cookies,
tokens, provider credentials, edge secrets or raw target bodies. Before publishing evidence, scan
it for those values as in launch spec §6.4 step 9.

## External blockers

| Blocker | Owner | Next test |
|---|---|---|
| Public URL, Worker, VPC service, Tunnel, provider account | Release/deployment owner | Rerun the preflight against the canonical origin; keep release revision and response metadata only |
| Heel identity/readiness on the public origin | Release/deployment owner | Deployed evidence binding the origin to the recorded release |
| Backup, restore drill, rollback point, kill-switch operator | Operations owner | Gates 4–6 above, without production mutation |
| Managed discovery and executor | C2/C3/C4 integration | Deployed Layer 1 synthetic known-positive path with real target logs and no test seam |
| Credential custody | Decision owner, then C5 | Recorded decision, then C5 privacy and managed-login gates |
| Results, evidence and regression | C6 owner | Deployed Layer 1 patch/replay and Layer 2 evidence-view test |
| Target ownership, authorization and provenance | Customer/target owner | Product-recorded proof plus the recorded customer statement |
