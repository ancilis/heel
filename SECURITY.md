# Security

HEEL is a security tool, so its own security model matters. This document is the threat model, the
production-hardening checklist, and the responsible-disclosure policy.

## Reporting a vulnerability in HEEL

Please report security issues privately via a GitHub security advisory on `ancilis/heel`, or by
email to the maintainers, **not** a public issue. We aim to acknowledge within 3 business days. Do
not include real exploit payloads against third-party systems; HEEL is synthetic-first by design.

## What HEEL is (and is not)

HEEL **rehearses how a customer, integration, bot, or agent could abuse a SaaS product you own**,
before launch and continuously after. Pre-launch launch review remains the default wedge, but
existing products can be rehearsed through authorized staging, sandbox, imported-model, sanitized
telemetry, or production-like adapter paths. It is **not** a replacement for application-security
review, penetration testing, or a bug-bounty program. Findings are **predicted, contained,
canary-only** proofs that an abuse path is *reachable*, they are leads to harden, not exploit code.

## The authorization model (§10, the non-negotiable safety spine)

HEEL is agent-native: its canonical surface is an MCP server that **other agents** call, and a
calling agent is an **untrusted, possibly prompt-injected channel**. HEEL therefore treats the
caller as a **confused deputy**:

- **Scopes are human-only and out-of-band.** A scope (target allowlist + limits + approver + expiry)
  is created **only** via `heel scope create --confirm` and written as an **HMAC-signed** file. No
  MCP / REST / agent code path can create, widen, add a target to, relax the limits of, or escape a
  scope: those tools **do not exist in the registry, by construction**.
- **All non-synthetic flows require signed scopes.** Real-target adapters, imported product models,
  sanitized telemetry, staging rehearsals, and production-like targets must be covered by an explicit
  human-created `AuthorizationScope` before an agent can run. The scope binds the allowlist, data
  handling mode, expiry, and operator-approved limits.
- **Immutable from the caller side.** The server only loads + verifies scopes; it never writes them.
  Hand-editing a signed scope file breaks the signature and the scope fails closed.
- **Every escalation is rejected and logged.** Out-of-allowlist targets, forged scope ids,
  prompt-injected target strings, injected `allowlist`/limit-override arguments, and forged
  scope-mutation tool calls are all rejected at the boundary and written to the containment log.
- **Tamper-evident self-audit.** Every run is recorded in an append-only, **HMAC-hash-chained**
  containment log attributed to the caller; `verify_chain` detects mutation, truncation, or deletion.

## Conduct guarantees (§10.2)

Synthetic-first · detection-not-weaponization (contained, canary-only PoCs, no real exfiltration or
resource exhaustion) · **never generates prohibited or illegal content under any framing** (guardrail
presence is verified with benign canaries only) · no real-PII harvesting · containment/back-off ·
plausibility-weighting · severity honesty · immutable self-audit · **lane discipline** (a genuine
software vulnerability is handed off to AppSec; a pure model-jailbreak surface is handed off to model
red-team: neither is weaponized or counted as a product-abuse finding).

## Existing product mode safety constraints

Existing-product rehearsal is allowed only when the operator keeps the run contained:

- Prefer staging, sandbox, or imported product models over production-like targets.
- Use synthetic users, canary tenants, canary records, and sanitized telemetry.
- Prefer read-only discovery where possible.
- Do not perform real exfiltration, credential abuse, payment abuse, spam, or resource exhaustion.
- Do not run automated high-volume probing.
- Keep limits operator-approved and encoded in the signed scope before any MCP, REST, or agent run.
- Treat true software vulnerabilities as AppSec handoffs and pure jailbreaks as model red-team
  handoffs, not HEEL findings to weaponize.

## Production hardening checklist

- [ ] **Separate key from data.** Set `HEEL_SIGNING_KEY` to a path (or secret mount) **outside**
      `HEEL_HOME`. Co-locating the key with the data dir only deters actors without filesystem
      access. `heel doctor` warns when the key is co-located.
- [ ] **Restrict the data dir.** `HEEL_HOME` (default `./.heel`) holds signed scopes, the SQLite
      store, and the containment log. Lock it down (`chmod 700`); it is git-ignored by default.
- [ ] **The REST API has no transport auth of its own.** `heel-rest` binds to `127.0.0.1` and relies
      on the scope-authorization model for *capability* control, not network access control. Do not
      expose it publicly; front it with your own authenticated gateway / mTLS / network policy if it
      must be reachable beyond localhost. It cannot mint or widen a scope regardless.
      Read routes (`/runs/{id}/...`) are **not confidential between local callers**: all callers on
      the loopback interface share one trust domain in v1; the `X-Heel-Caller` header is self-asserted
      attribution, not authentication. The server also rejects non-loopback `Host` headers (anti
      DNS-rebinding) and any request carrying an `Origin` (anti-CSRF).
- [ ] **Run against synthetic or explicitly-authorized targets only.** v1 ships two synthetic
      targets. Real-target adapters are beta and must run through signed scopes, canary-only data,
      and operator-approved limits. A human must authorize any target out-of-band before it can be
      run.
- [ ] **LLM control loop.** The optional `HEEL_MODEL=anthropic` path sends only *observable
      affordance properties* (never secrets/PII) to the Messages API and only receives declarative
      scenario proposals; it stays in HEEL's lane and falls back to the offline deterministic model
      on any error. Review your data-egress policy before enabling it.

## Supported versions

v1.x receives security fixes. The pure-stdlib core has **zero runtime dependencies**, minimizing
supply-chain surface.
