# Arceo Roadmap

Arceo's near-term roadmap stays inside the existing safety spine: canary-only rehearsal, human-created
signed scopes, no scope mutation over MCP/REST/agent surfaces, no production-probing implication, and
zero runtime dependencies in the Python core.

## Standards Crosswalk

Add machine-readable standards references to scenarios and reports so operators can view Arceo's abuse
coverage through familiar external taxonomies without turning Arceo into a compliance scanner.

Planned scope:

- Add optional scenario metadata for standards such as OWASP API Security Top 10, OWASP WSTG Business
  Logic Testing, OWASP Automated Threats/OAT, OWASP LLM Top 10, and specific CWE/CAPEC entries where
  the mapping is root-cause accurate.
- Generate a coverage matrix that shows which Arceo categories, scenario packs, and findings map to
  those references.
- Keep category-level mappings honest: broad buckets such as CWE-840 are useful for browsing, but
  findings should prefer specific root-cause references when possible.
- Surface the crosswalk in CLI/report output as attribution metadata only. It must not imply standard
  certification, exploitability against live targets, or permission to probe production systems.
- Add tests that keep bundled research scenarios mapped, prevent invalid standards IDs, and verify the
  report layer stays metadata-only.
