# Trust & assurance

Arceo is a security tool, so "trust me" isn't good enough. Here is the evidence, and how to verify it
yourself.

## Supply chain

| signal | status | verify |
|---|---|---|
| **Zero runtime dependencies** | pure Python stdlib | `pip show arceo` → no `Requires`; `pip install arceo` pulls nothing else |
| **Reproducible build** | static version, no VCS-derived metadata | `python -m build` twice → identical wheel contents |
| **Signed build provenance** | Sigstore attestation on every release (PEP 740) | `gh attestation verify <wheel> --repo ancilis/arceo` |
| **SBOM** | CycloneDX SBOM published with each release | `dist/sbom.cdx.json` on the GitHub Release |
| **Trusted publishing** | PyPI OIDC, **no API token stored anywhere** | `.github/workflows/publish.yml` |
| **Pinned, auto-updated CI** | Dependabot watches Actions + UI deps | `.github/dependabot.yml` |

## Automated security posture

- **OpenSSF Scorecard**: `.github/workflows/scorecard.yml` scores branch protection, CI, SAST,
  dangerous workflows, and dependency pinning, and publishes the public badge.
- **CodeQL** static analysis (`security-extended` queries) on every push/PR and weekly.
- **CI matrix**: tests on Python 3.11/3.12/3.13 + a clean warceo-install smoke test + the UI build,
  green on every commit to `main`.

## Production-ready vs beta

The production-ready claim applies to Arceo's safety, authorization, containment, audit, and
evaluation spine: signed scopes, no MCP/REST/agent scope mutation path, canary-only findings, lane
discipline, and the honest evaluation ladder are implemented and tested.

Real-target adapter coverage is beta. Existing-product rehearsals must stay inside explicit human
authorization, canary-only data, sanitized imports or telemetry, and operator-approved limits until
adapters mature.
The same pre-launch and existing-product safety contract is enforced across every surface: no scope
creation, widening, relaxation, or mutation path exists over MCP, REST, or agent callers.

## Adversarial review (the real assurance)

Arceo was hardened by **four independent multi-agent red-team passes**, each attacking a different
claim; every finding was fixed with a regression test. The full reports are in the repo:

- [`docs/REDTEAM_FINDINGS.md`](docs/REDTEAM_FINDINGS.md): the §10 safety/authorization spine.
- [`docs/REDTEAM_BLIND_FINDINGS.md`](docs/REDTEAM_BLIND_FINDINGS.md): blind-eval honesty (caught a circular metric).
- [`docs/REDTEAM_HELDOUT_METHOD.md`](docs/REDTEAM_HELDOUT_METHOD.md): held-out methodology (caught attribution-vs-localization conflation).
- [`docs/REDTEAM_LAUNCH.md`](docs/REDTEAM_LAUNCH.md): production launch review (verdict **SHIP**; REST DNS-rebinding/CSRF fixed pre-tag).

The #1 claim held under attack: **a prompt-injected MCP/REST caller cannot create, widen, or escape a
signed authorization scope.** It is enforced in code (`tests/test_arceo.py::TestAuthGate`,
`TestScopeImmutability`, `TestRestSharesAuthGate`) and is the property the entire design protects.

## Honest metrics (no vanity numbers)

Arceo refuses to quote a number it can't defend. It reports a *ladder* from weakest to strongest
evidence, ending in **held-out detection against abuse authored by an independent LLM swarm, blind to
Arceo's probes, on a frozen content-hashed test set**, and discloses its overfitting and
mis-categorization gaps rather than hiding them. Method + provenance:
[`EVAL.md`](EVAL.md) · [`docs/HELDOUT_PROVENANCE.md`](docs/HELDOUT_PROVENANCE.md).

## The safety spine (§10)

Synthetic-first · contained, canary-only PoCs (never working exploits / real exfiltration) · never
generates prohibited content under any framing · no real-PII · plausibility-weighted · severity-honest
· immutable hash-chained self-audit · lane discipline (true vulns → AppSec, jailbreaks → model
red-team). Existing-product runs use staging, imported models, sanitized telemetry, or explicitly
authorized production-like targets with canaries and limits. Threat model + production-hardening
checklist + responsible disclosure:
[`SECURITY.md`](SECURITY.md).

## Verify it yourself in one minute

```bash
pip install arceo
arceo doctor                       # environment + capability self-check
gh attestation verify $(python -c "import arceo,os;print()") --repo ancilis/arceo   # provenance (after release)
python -m unittest discover -s tests   # run the safety + acceptance suite from a clone
```
