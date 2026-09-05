# Export entitlement reference demo

Use the supplied wheel in a private POSIX workspace; no PyPI publication is implied.

```sh
python3 -m venv --copies .venv
. .venv/bin/activate
python -m pip install './heel_sim-1.2.0-py3-none-any.whl[runner]'
export HEEL_HOME="$PWD/.heel"
heel reference prepare
heel scope create --target reference:export --operator "demo owner" --confirm
```

Replace SCOPE_ID below with the returned ID. Each attempt ID is consumed once, including cancelled or interrupted attempts; choose fresh 32-character lowercase hexadecimal IDs on repetition.

```sh
heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
heel reference run --scope SCOPE_ID --case hardened --attempt 22222222222222222222222222222222
heel reference run --scope SCOPE_ID --case error_envelope --attempt 33333333333333333333333333333333
heel reference run --scope SCOPE_ID --case inconclusive --attempt 44444444444444444444444444444444
heel reference run --scope SCOPE_ID --case vulnerable --attempt 55555555555555555555555555555555 --stop
```

Expected results: verified_violation; invariant_held with regression_passed=true; invariant_held for the HTTP-200 denial envelope; inconclusive; inconclusive with cancellation. `public` and `redacted` are additional supported cases. A missing positive control never passes.

The fix is the account export-license check before serialization in `heel/reference_product.py`. Both variants use the same account table, fixture and invariant. The check verifies only read entitlement, not quotas or cumulative extraction. There is one synthetic row and two sequential reads, not bulk extraction.

Reports are saved to `$HEEL_HOME/reference/ATTEMPT/report.json`; raw synthetic evidence remains in that private attempt's runner store. Open `/runner` in the app and select the report to inspect a browser-local summary. The browser does not authenticate imported reports and uploads nothing.

For MCP, initialize `heel-mcp`, send notifications/initialized, call `heel_prepare_reference` with `{}`, then call `heel_execute_reference` with `{"scope_id":"SCOPE_ID","case":"vulnerable","attempt":"66666666666666666666666666666666"}`. The human-created signed scope must already exist. The MCP server cannot create scopes. It accepts no URL, credentials, or transport override.

For internal canary integrations, a GET route fixture binding beginning `heel-canary-` opts into the closed `protected_canary` output-field contract. The approved marker must be unique and synthetic, emitted only inside protected output. Public/error metadata must not echo it in that protected field. Without one matching fixture and a successful entitled read, the assessor returns inconclusive. This internal contract is not a claim that arbitrary customer-target onboarding is complete.
