# Self-serve preview: paired runner against your own staging target

This is the repository copy of the public guide that Heel Cloud serves at `/guide`. The two cover
the same steps, and neither needs a source checkout or access to internal reports.

## What it covers

The paired runner runs two fixed, marker-backed read checks over `GET` routes from your own
OpenAPI document:

- `anonymous_authenticated_read`: does an anonymous request get a record that only a signed-in
  canary should see?
- `plan_entitlement_read`: does a lower-plan canary get a record that only a higher-plan canary
  should see?

Limits on target traffic:

- The target is one verified public HTTPS origin on port 443.
- Methods are `GET` and `HEAD` only, and redirects are not followed.
- The runner sends nothing until a human approves an exact signed plan in the browser.

Nothing else about your product is tested. The scenario library (120 entries) shows breadth,
not executed coverage.

Preview constraints:

- Sign-up is public but rate-limited; if it is refused with "try again later", wait and retry.
- Version 1.3.0rc5 is a public preview prerelease: not stable, and not on PyPI.
- Only the `bearer` credential profile has been exercised end to end. `x_api_key` and
  `cookie_jar` are implemented, with no recorded acceptance.

This differs from the standalone `heel runner run` command ([runner doc](PLAN_DIFFERENTIAL_RUNNER.md)):

- `heel runner run` is CLI only and uses a signed local scope, with no pairing or browser
  approval.
- It is a body-differential comparison: it records `observed` when the lower plan's body
  contains every key path of the higher plan's.
- It is not a prerequisite for the paired workflow. Do not create a standalone scope for it.

## Steps

`CLI` below is `./heel-rc5/bin/heel`. Owners and admins pair runners, approve plans, share
results and revoke access. Each of these actions requires a sign-in from the last 15 minutes.
If your sign-in is older, the action is refused and nothing changes; sign in again and repeat
it.

1. **Account and project.** Create an account or sign in on the Heel Cloud dashboard, then create a project in your
   default workspace.
2. **Ownership proof.** Under Add target, enter one publicly reachable staging or sandbox
   HTTPS origin. Choose HTTPS file or DNS TXT, then Create ownership proof.
   - For HTTPS file, serve exactly the value shown at `/.well-known/heel-verify.txt`.
   - For DNS TXT, publish the record shown.

   Then choose Check ownership proof. A pending proof stays on the server, so you can resume it
   after signing in again. The recorded journey used HTTPS-file proof. DNS proof is implemented
   but was not part of that journey.
3. **Install.** You need Python 3.11 or newer as `python3` with `venv`, on Apple silicon macOS or
   Linux x86_64/aarch64. Intel macOS is unsupported. The command below installs the hash-pinned
   wheel from <https://github.com/ancilis/heel/releases/tag/v1.3.0rc5>:

   ```sh
   python3 -m venv heel-rc5 && ./heel-rc5/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc5/heel_sim-1.3.0rc5-py3-none-any.whl#sha256=a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226' && ./heel-rc5/bin/heel --version
   ```

   The signing key and credentials live only in macOS Keychain or the Linux Secret Service. There
   is no file fallback. A desktop Linux session normally has an unlocked keyring already. On a
   headless Linux host, install and unlock one first, in the private directory where you ran the
   install:

   ```sh
   sudo apt-get install dbus gnome-keyring libsecret-tools    # Debian/Ubuntu package names
   dbus-run-session -- bash                                   # headless only: private session bus
   IFS= read -rs pw && printf '%s' "$pw" \
       | gnome-keyring-daemon --unlock --components=secrets >/dev/null; unset pw
   (umask 077 && rm -f .heel-bus && printf '%s\n' "$DBUS_SESSION_BUS_ADDRESS" > .heel-bus)   # headless only
   ```

   - Type the keyring password at the hidden prompt. It reaches the daemon on standard input only.
   - The last line saves only the session bus address to `.heel-bus` with mode 0600. The address is
     local connection metadata, not a secret, and lets a second terminal reach the same unlocked
     keyring.
   - Keep this shell open and run steps 4 and 5 in it. Exiting it ends the bus and the keyring
     session.

   See also the `secret-service` prerequisites in the [runner doc](PLAN_DIFFERENTIAL_RUNNER.md).
4. **Pair.**
   1. Choose Create pairing invitation. The invitation is shown once and expires after 10
      minutes.
   2. Set `export HEEL_HOME="$(pwd -P)/.heel"`, a physical path with no symbolic link.
   3. Run the `CLI runner pair --origin … --invite …` command that the dashboard shows. The
      invitation appears in that process's arguments, so pair on a machine you control.
   4. Enter the printed pairing ID on the dashboard.
   5. Check that the six words and the fingerprint match the terminal exactly, then approve.

   Pairing alone authorizes no target traffic.
5. **Serve.** Keep `CLI runner serve` running in the first terminal. Run every later runner
   command in a second terminal, as the same user, in the same private directory and with the same
   `HEEL_HOME`:

   ```sh
   cd SAME_PRIVATE_DIRECTORY
   export HEEL_HOME="$(pwd -P)/.heel"
   IFS= read -r DBUS_SESSION_BUS_ADDRESS < .heel-bus && export DBUS_SESSION_BUS_ADDRESS   # headless Linux only
   CLI runner status
   ```

   On a headless Linux host, a new terminal does not inherit the private session bus, so the vault
   is unavailable there until you load the address saved in step 3. On macOS or a desktop Linux
   session, skip that line.
   - If `serve` stops with `response_rejected`, start it once more on the same `HEEL_HOME`.
   - If it stops again, report it instead of looping.
6. **Authorize the target.** Under Add canary access, select the verified environment and the
   runner, then choose Authorize paired runner. The runner is fixed to the first environment it
   claims.
7. **Credentials.** Use isolated staging accounts only. Each command prompts
   `Canary credential:` with hidden input. Use `--backend secret-service` on Linux.

   ```sh
   CLI runner credential add --role lower_plan --plan-label free --profile bearer --label "free canary" --backend keychain
   CLI runner credential add --role higher_plan --plan-label pro --profile bearer --label "pro canary" --backend keychain
   CLI runner credential add --role authenticated --profile bearer --label "signed-in canary" --backend keychain
   ```

   `free` and `pro` are your own plan labels, and Heel never infers them. Wait until
   `CLI runner status` reports `access.ready`.
8. **Routes and canary data.** Import your OpenAPI, then map each check to one imported route.
   Supply the path values with `--fixture-fd`. A parameterized route mapped without it is refused
   with `Heel runner mapping could not be saved safely.`

   ```sh
   CLI runner import-openapi ./openapi.json
   printf '{"id":"heel-canary-export-0001"}' > export-fixture.json
   CLI runner map --scenario plan_entitlement_read --method GET --route '/exports/{id}' --fixture-fd 3 3<export-fixture.json
   printf '{"id":"heel-canary-record-0001"}' > record-fixture.json
   CLI runner map --scenario anonymous_authenticated_read --method GET --route '/records/{id}' --fixture-fd 3 3<record-fixture.json
   ```

   The marker is a staging-data requirement, not something Heel reads from OpenAPI:
   - Create each canary record with an ID that starts with `heel-canary-`.
   - Return it as a JSON object whose `protected_canary` field equals that ID, and only to
     entitled identities. A minimal example (your record may carry other fields too):

     ```json
     {"id": "heel-canary-export-0001", "protected_canary": "heel-canary-export-0001"}
     ```

   The higher-plan or signed-in read is the positive control and must succeed with the marker.
   The possible outcomes:
   - The lower or anonymous read also receives the marker: `observed`.
   - That read is refused with 401, 402, 403 or 404 and an empty body: `blocked`.
   - A JSON error or denial envelope at any status: `inconclusive`.
9. **Plan.** `CLI runner prepare` checks readiness locally and sends nothing. `CLI runner prepare
   --live` compiles one signed plan, and `serve` submits its metadata for review. No target
   request is sent before browser approval.
10. **Approve.** The approval dialog shows the exact origin, the request and time ceilings, the
    only egress (`host:443`), each route once per role, and the scenarios.
    - Optionally, under What this run stands for, freeze library or custom bindings to the
      exact checks. Bindings never follow later edits, and approval does not require them.
    - To approve, retype the hostname, give a reason, and choose Approve and run.
11. **Result.** The dashboard shows signed progress. On the runner machine, read the result
    with `CLI runner findings --run RUN_ID`; `CLI runner status --offline` shows the `run_id`.
    The local submission view can still read "awaiting approval" after its run completed.

    Then choose Share this summary or Keep result local. Only an explicit share uploads the
    runner-signed redacted summary. Bodies, credentials and raw evidence stay on the runner
    machine.
12. **Regression.**

    ```sh
    CLI runner regress add --run RUN_ID --scenario plan_entitlement_read --name "export plan entitlement read"
    CLI runner prepare --live --regression REGRESSION_ID   # after the fix; approve in the browser
    CLI runner regress record --regression REGRESSION_ID --run NEW_RUN_ID
    ```

    The recorded outcome:
    - A blocked, completed replay records `pass`.
    - An `observed` result records `fail`.
    - Anything else records `inconclusive`.

    See [regression replay](RUNNER_REGRESSION_REPLAY.md).
13. **Stop and revoke.**
    - **Stop** asks the runner to stop the current run. Stopping a run while it is in flight
      has not been demonstrated.
    - **Revoke** on a context stops future authorization only. Grants already issued and work
      already active are unchanged.
    - **Revoke runner** makes Heel Cloud reject the runner's keys and request a stop of its
      active rehearsals. `serve` then exits `runner_authentication_rejected`. Run
      `CLI runner unpair` locally afterwards.

### Optional: custom scenarios

Save a workspace-private custom scenario in the public authoring schema from
[SCENARIO_AUTHORING.md](SCENARIO_AUTHORING.md), for example its `sc.internal.exports.entitlement_gate`
example.

- **Never executed.** The criterion is a declaration for analysis.
- **Immutable revisions.** Each save creates a new revision, and a run whose binding was frozen
  to revision 1 keeps naming revision 1.
- **Browser-only static assessment.** It runs in the browser and uploads nothing. A property
  absent from your OpenAPI stays `unknown`.

## Recorded evidence and limits

On 2026-11-13, one fresh preview account ran the steps above. It used a clean Linux container,
the public [1.3.0rc5 release](https://github.com/ancilis/heel/releases/tag/v1.3.0rc5) and the
browser, with the hosted build that includes
[PR #94](https://github.com/ancilis/heel/pull/94). The target was a controlled synthetic staging
app that Heel operates on the public network. This was not a customer target or customer
acceptance.

| Area | Recorded result |
| --- | --- |
| Findings | Two observed findings (authorization and entitlement), with a redacted shared summary |
| Regressions | Two saved regressions, each recorded `pass` on a patched replay |
| Custom revision | A private custom revision validated as r1 and r2; the run kept r1 after the edit and reload |
| Static assessment | `unknown` without uploading the input |
| Error envelopes | `inconclusive` |
| Tenant isolation | Another workspace answered 403 and another project 404 |
| Keep local | A run kept local uploaded no summary bytes |
| Revocation | The target context and the runner were revoked |

Limits:

- **Timing.** Time to the first finding was 1761.8 s (about 29.4 minutes), including the
  17.4 s install. The 15-minute goal was **not** met.
- **Control-plane outage.** The timing includes a control-plane outage that recovered with its
  data intact. An automatic-restart recovery
  ([PR #95](https://github.com/ancilis/heel/pull/95)) has since been merged and deployed. In a
  controlled fault test it restarted with data preserved and was ready in about 12 seconds.
- **`response_rejected` stop.** `serve` once stopped with `response_rejected` before a run
  started. Nothing was sent, and that run's quota was refunded. One `serve` restart recovered,
  and a fresh plan ran. The cause is unknown, and the stopped run's local record is retained.
- **Stop.** A Stop attempt hit a state-change conflict, and that short run completed first.
  Stopping a run while it is in flight is not demonstrated.
- **Scope of the evidence.** The two checks were exercised only as marker-backed checks over
  `GET` routes with the `bearer` profile.
- **Preview.** No launch-readiness claim is made.

## Feedback

Open an issue at <https://github.com/ancilis/heel/issues/new> with these details:

- the setup step
- `heel --version`
- your OS and Python version
- the command (without secrets) or button
- the exit status and fixed message or error code
- the approximate UTC time
- what you expected and what you observed

Issues are public. Never include credentials, invitations, raw response bodies, private OpenAPI
documents or unredacted logs.
