# Replaying a saved runner regression

Status: first shipped in the `1.3.0rc3` runner preview, published as a GitHub prerelease on
2026-11-11, still included in the `1.3.0rc4` runner preview, and included in the current `1.3.0rc5`
runner preview (<https://github.com/ancilis/heel/releases/tag/v1.3.0rc5>; install it with the one
hash-pinned command in the [README](../README.md)). These commands are **not** in the earlier
`1.3.0rc2` or `1.3.0rc1` previews. Beyond local test fixtures, one pre-release staging run (a
paired 1.3.0rc3 candidate runner) recorded a regression and replayed it through a real browser
approval against a controlled synthetic HTTPS target. On 2026-11-13, a fresh preview account
using the public 1.3.0rc5 release and the deployed Heel Cloud saved two regressions and recorded
each `pass` on a replay after the controlled synthetic staging target was patched (see the
[self-serve preview guide](SELF_SERVE_PREVIEW.md)). No replay against a customer target is
recorded.

Replay depends on the Cloud canary approval flow: it runs only the existing read-only
(`GET`/`HEAD`) canary scenarios, and only in a Cloud-bound context.

A saved regression records an observed finding from one of your approved paired-runner
runs. Replaying it builds a **fresh** plan for that one scenario. It never reuses the old
approval, grant or run: you approve every replay again in the browser, and the runner
executes it once.

## Before you start

- The runner is paired, bound to the verified environment, and `heel runner serve` is
  running. Replay needs the browser approval queue, so it works only in a Cloud-bound
  context.
- The source run is terminal, and `heel runner findings --run RUN_ID` shows the scenario
  as `observed`.
- The scenario mapping (method, route, fixture value), the context and the runner identity
  are the same as when you saved the definition. The definition's method and route are
  still in the imported route inventory; the rest of the inventory may have changed. The
  credentials for the scenario's roles are available from their secure backend.

## Commands

1. Save the finding as a definition (local data, not authority):

   ```
   heel runner regress add --run RUN_ID --scenario SCENARIO_ID --name "Ownership read"
   ```

   The output includes `regression_id` (`rreg_…`).

2. Prepare a fresh replay:

   ```
   heel runner prepare --live --regression REGRESSION_ID
   ```

   The runner checks the definition against the current context, identity, mapping and
   fixture digest, and checks that its route is still in the inventory. Then it compiles
   exactly that one scenario. It checks the
   compiled plan again and records which definition the new plan replays. Then it queues
   the plan for `serve`. The output shows `scenario_ids`, the new `projection_digest`, and
   `submission` and `regression` blocks with the new `projection_id`. Nothing contacts
   your target at this step.

3. Approve it in the browser. `heel runner status --offline` shows
   `projection_submission` with the `approval_id` and `run_id` once `serve` has submitted
   the plan. Review the hostname and the one selected route (listed once per role) in the
   approval request, then approve. `serve` claims the one-shot grant and runs the two reads.

4. Record the result:

   ```
   heel runner regress record --regression REGRESSION_ID --run RUN_ID
   ```

   | Signed local result for the scenario | Recorded `outcome` |
   | --- | --- |
   | `blocked`, run completed | `pass` |
   | `observed` | `fail` |
   | anything else, including error envelopes or an incomplete run | `inconclusive` |

   Recording the same run again returns the stored result with `"created": false` and
   writes nothing.

5. List definitions and results:

   ```
   heel runner regress list
   ```

After you fix the target, repeat steps 2–4. Each repeat is a new plan, a new approval and a
new run.

## What is refused

Each refusal exits `2` with a fixed message.

- `prepare` fails with `Heel runner regression replay could not be prepared safely.` in
  these cases:
  - `--regression` without `--live`
  - an unknown or malformed ID
  - a changed mapping, fixture, context or runner identity
  - the definition's route is no longer in the imported inventory
  - unavailable credentials
  - a local-only context
  - a compiled plan that differs from the definition

  When `prepare` refuses for one of the reasons above, it registers no replay association,
  leaves the queued submission as it was, writes no result, and sends no request to the
  control plane or your target. A plan that differs from the definition is refused after
  compilation, so the new compiled plan can remain stored locally. That plan is never
  queued, submitted or approved, and no result can be recorded for it.

  A local storage failure is different. The same message can appear after the replay
  association, and possibly the queued submission, was already written. Before you retry,
  run `heel runner status --offline` and `heel runner regress list` to see what was
  queued. An association that was written but never submitted cannot match a signed run.
  A plan that was queued is submitted by `serve` as usual and still needs your browser
  approval.
- `regress record` fails with `Heel runner regression result could not be recorded
  safely.` in these cases:
  - the source run
  - a run of an ordinary plan on the same route
  - a run whose stored grant does not name a replay prepared for this definition
  - foreign-signed or malformed finals
  - a non-terminal or unknown run

  When `regress record` refuses for one of the reasons above, it writes nothing, because the
  result is derived and verified before the only write. After a local storage failure, the
  result may already have been written. Run `heel runner regress list` before you retry.
  Recording the same run again is safe either way: it returns the stored result and writes
  nothing.

Recover by fixing the named input, then run `prepare --live --regression` again.

## What is stored

The runner keeps state in the bound context's directory:

- `regression-replays.json` holds one entry per prepared replay. Each entry links a
  definition digest to the fresh `projection_id`, projection and manifest digests and the
  context binding digest.
- `regression-results.json` holds one entry per recorded run: the identifiers, the grant
  and findings digests, the assessment and the outcome.

Each file is capped at 200 entries. Neither file holds a credential, a fixture value, a
response byte, a grant signature or a file path.
