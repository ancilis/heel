# Export entitlement reference demo

This optional local preview runs a synthetic reference product on your machine. It is not a step in
the default Heel journey (signup, product URL and credentials, explicit authorization, then discovery
and scanning), which needs no OpenAPI document or manual runner setup.

Heel 1.3.0rc1 is a public preview prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc1>. It is not a stable release, its GitHub
release record is not immutable, and it is not published to PyPI. The release is not a deployed Heel
Cloud URL and does not indicate customer acceptance.

You need a POSIX shell and Python 3.11 or newer (`python3 --version`). No source checkout or Heel
Cloud deployment is needed. Work in an empty private directory you own. pip installs the public wheel
only if it matches the pinned SHA-256. `--isolated` makes pip ignore environment variables and user
configuration. The `runner` extra then downloads the pinned `cryptography` dependency and its
dependencies from the Python package index (PyPI by default).

```sh
python3 -m venv .venv
.venv/bin/python -m pip --isolated install \
  'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc1/heel_sim-1.3.0rc1-py3-none-any.whl#sha256=176a17b0d4d7f4ea44420d8099239f32dbb17eeead981e5aa360f0a5bbccb94a'
export HEEL_HOME="$(pwd -P)/.heel"
.venv/bin/heel reference prepare
.venv/bin/heel scope create --target reference:export --operator "demo owner" --confirm
```

Use the same absolute physical `HEEL_HOME`, in which no component is a symbolic link, from the first
command onward. `pwd -P` prints that physical path; plain `$PWD` may not. On macOS, `/tmp` and `/var`
are symbolic links to `/private/tmp` and `/private/var`, as `$TMPDIR` often is below them. Scope
creation does not check the storage path, so `heel scope create` can succeed with a `HEEL_HOME` built
from a `$PWD` under them; that success does not show the path is safe. `heel reference run` then
opens the private runner and reference storage without following symbolic links, on purpose, and
refuses that `HEEL_HOME`. Do not disable or work around that check. Run the commands below in the
same shell so that `HEEL_HOME` stays set.

A Heel Cloud deployment built from the current repository serves the unpublished 1.3.0rc2 candidate
on its `/agent` page instead of the public 1.3.0rc1 wheel. If you downloaded
`heel_sim-1.3.0rc2-py3-none-any.whl` there, you can install that file instead with
`.venv/bin/python -m pip --isolated install './heel_sim-1.3.0rc2-py3-none-any.whl[runner]'`.

Replace SCOPE_ID below with the returned ID. Each attempt ID is consumed once, including cancelled or interrupted attempts; choose fresh 32-character lowercase hexadecimal IDs on repetition.

```sh
.venv/bin/heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
.venv/bin/heel reference run --scope SCOPE_ID --case public --attempt 22222222222222222222222222222222
.venv/bin/heel reference run --scope SCOPE_ID --case error_envelope --attempt 33333333333333333333333333333333
.venv/bin/heel reference run --scope SCOPE_ID --case hardened --attempt 44444444444444444444444444444444
.venv/bin/heel reference run --scope SCOPE_ID --case inconclusive --attempt 55555555555555555555555555555555
.venv/bin/heel reference run --scope SCOPE_ID --case vulnerable --attempt 66666666666666666666666666666666 --stop
```

Results, in order: verified_violation; invariant_held with regression_passed=true for `public`, a
successful read that withholds the protected field; for `error_envelope` and for `hardened`,
1.3.0rc1 prints invariant_held with regression_passed=true, which is a known erratum (see below) and
must be read as inconclusive; inconclusive; inconclusive with cancellation. `redacted` is the other
supported passing case. A missing positive control never passes.

**Erratum for 1.3.0rc1: `error_envelope`.** The published 1.3.0rc1 wheel reports the
`error_envelope` case as `invariant_held` with `regression_passed=true`. That output is a known
defect. In this case the reference product answers the lower-plan export with HTTP 200 and a
`{"error":"license required"}` body. A denial inside a successful response does not establish that
protected content was withheld, so the correct result is inconclusive. Treat the rc1
`error_envelope` report as inconclusive: it does not validate the invariant and is not a passing
regression. The commands and output above are the actual rc1 behavior; the published rc1 artifacts
are unchanged. The corrected 1.3.0rc2 candidate, whose evaluator, tests and artifacts changed
together, prints `inconclusive` for `error_envelope`, with `evidence_state` `unknown` and
`regression_passed=false`. 1.3.0rc2 is not yet published as a GitHub release or to PyPI, and no
public 1.3.0rc2 download exists.

**Erratum for 1.3.0rc1: `hardened`.** The same rule applies to an error response at any HTTP status.
In the `hardened` case the reference product answers the lower-plan export with HTTP 403 and the
same `{"error":"license required"}` body. The published 1.3.0rc1 wheel reports that case as
`invariant_held` with `regression_passed=true`. An error envelope neither proves a disclosure nor a
denial, and the status alone never decides it, so that report is also inconclusive and is not a
passing regression or a verified repair. The unpublished 1.3.0rc2 candidate prints `inconclusive`
for `hardened`, with `evidence_state` `unknown` and `regression_passed=false`. The `vulnerable`,
`public` and `redacted` results are not affected.

Every report has `execution_support` set to `reference_only`. Its provenance records
`network_calls: false`, and `uploaded` is `false`. The runs contact no product target and accept no
URL, credentials, or transport override. A passing synthetic reference shows only that this local
preview works. It does not show that Heel supports live targets or is ready for launch.

## If the reference run is rejected

The CLI prints the same message for every refusal:
`Reference rehearsal rejected. Check the signed synthetic scope, unique attempt and private local storage.`
It exits with status 2. The message does not say which check failed, so check each of these. Not
every rejection is a storage-path problem.

1. **Private storage path.** From your workspace, run `export HEEL_HOME="$(pwd -P)/.heel"` again.
   Every component of `HEEL_HOME` must be a real directory, not a symbolic link. Check this
   especially under macOS `/tmp`, `/var` or `$TMPDIR`. Do not replace directories with links,
   relax permissions, or edit the store database or scope files.
2. **Signed synthetic scope.** `SCOPE_ID` must come from
   `heel scope create --target reference:export ... --confirm`, run with the same `HEEL_HOME`. The
   scope must not have expired (the default lifetime is seven days). If you are unsure, create a
   fresh scope and use its ID.
3. **Unused attempt.** The attempt must be 32 lowercase hexadecimal characters that this
   `HEEL_HOME` has never used before. Cancelled or interrupted runs count as used. Retrying with a
   new attempt ID is always safe.

If you ask for help, share only the command (with `SCOPE_ID`), the exit status, the one-line
message, your OS, and your Python version. Never paste raw exceptions or tracebacks, signing keys,
scope files, `.heel` contents, or credentials.

The fix is the account export-license check before serialization in `heel/reference_product.py`. The `public` and `redacted` cases show a fixed read that a regression can confirm: a successful lower-plan response without the protected field. The `hardened` case applies the same check but refuses with an error response, which Heel reports as inconclusive. All cases use the same account table, fixture and invariant. The check verifies only read entitlement, not quotas or cumulative extraction. There is one synthetic row and two sequential reads, not bulk extraction.

Reports are saved to `$HEEL_HOME/reference/ATTEMPT/report.json`; raw synthetic evidence remains in that private attempt's runner store. Open `/runner` in the app and select the report to inspect a browser-local summary. The browser does not authenticate imported reports and uploads nothing. It says a regression passed only for the shape a completed held case writes: `public` or `redacted`, `invariant_held`, `regression_passed=true`, `evidence_state` `verified`, `execution_disposition` `completed` and reference-only provenance with no network calls. Any other held report, including an rc1 `hardened` or `error_envelope` report, is shown as not a pass.

For MCP, initialize `heel-mcp`, send notifications/initialized, call `heel_prepare_reference` with `{}`, then call `heel_execute_reference` with `{"scope_id":"SCOPE_ID","case":"vulnerable","attempt":"77777777777777777777777777777777"}`. The human-created signed scope must already exist. The MCP server cannot create scopes. It accepts no URL, credentials, or transport override.

For internal canary integrations, a GET route fixture binding beginning `heel-canary-` opts into the closed `protected_canary` output-field contract. The approved marker must be unique and synthetic, emitted only inside protected output. Public/error metadata must not echo it in that protected field. Without one matching fixture and a successful entitled read, the assessor returns inconclusive. This internal contract is not a claim that arbitrary customer-target onboarding is complete.
