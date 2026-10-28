# Heel security boundaries

Heel performs local, deterministic launch review. It predicts abuse paths from a
sanitized product description; it does not prove vulnerabilities against a live
service and should not replace application-security review or penetration testing.

## Data handling

- Supply sanitized OpenAPI documents without credentials, secrets, tokens, customer
  records, or personal data.
- Heel does not require network access for local review. Optional model integrations
  can introduce data egress and should remain disabled unless your policy permits it.
- `HEEL_HOME` contains saved reviews and other local state. Put it in a private
  operator-controlled directory and restrict filesystem access.

## Service boundaries

- `heel-mcp` is a stdio server. Treat the calling client identity as self-asserted and
  keep transport access within the operator's trust boundary.
- `heel-rest` is intended for loopback use and does not provide transport
  authentication. Do not expose it directly to a public or untrusted network.
- Review only products you own or are explicitly authorized to assess. Use synthetic
  inputs for demonstrations and avoid active probing of live systems.

## Reporting a security issue

Report suspected vulnerabilities privately to the distributor or maintainer who
provided your release artifact. Do not include secrets, customer data, or live
third-party exploit payloads in a report.

Return to the [release overview](README.md) or follow the
[MCP and CLI quickstart](MCP_QUICKSTART.md).
