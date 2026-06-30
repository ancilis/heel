# Local Codex prompt queue runbook for `ancilis/heel`

This repo stores the Heel uplift prompts as a merge-gated queue. The queue is
run by the local Codex CLI, authenticated with your ChatGPT/Codex subscription,
not by a GitHub Action and not by an OpenAI API key.

## Operating model

Use one PR per prompt.

1. The local runner starts at prompt 1 on the default branch.
2. It opens a fresh branch for the current prompt.
3. It builds a combined prompt from `00_MASTER.md` plus the current task prompt.
4. It starts a new Codex CLI session for that prompt.
5. When Codex finishes, the runner runs tests, advances the queue state inside
   the branch, commits, pushes, and opens a PR labeled `codex-queue`.
6. A human reviews and merges the PR.
7. The local watcher sees that there is no open queue PR, pulls the merged queue
   state from `main`, and starts the next prompt.

If a queued PR is closed without merge, the progress file on `main` does not
advance. The watcher can re-run that same prompt.

## Prerequisites

Install and authenticate the local tools:

```bash
gh auth status
codex login status
```

`codex login status` should report:

```text
Logged in using ChatGPT
```

If it does not, run:

```bash
codex login
```

No `OPENAI_API_KEY`, `CODEX_API_KEY`, or GitHub Actions secret is required for
the queue runner.

## Start one queued PR

From a clean checkout on the default branch:

```bash
python3 scripts/codex/local_queue_runner.py run-next
```

By default this uses:

```bash
codex exec --sandbox workspace-write --ask-for-approval never
```

`codex exec` reuses the saved local Codex login, so usage goes through the
ChatGPT/Codex account that `codex login status` reports.

## Run continuously

Keep this process running locally:

```bash
python3 scripts/codex/local_queue_runner.py watch --poll-seconds 60
```

The watcher never auto-merges. It waits while any open PR labeled
`codex-queue` exists. After a human merges that PR, the watcher pulls `main` and
starts the next queued prompt in a new Codex CLI session.

## Interactive Codex sessions

If you want each prompt to open in the Codex terminal UI instead of `codex exec`,
run:

```bash
python3 scripts/codex/local_queue_runner.py watch --mode tui
```

The runner passes the combined prompt into `codex`, then waits while you work in
the TUI. Exit the TUI after the prompt is finished; the runner then runs tests,
commits, pushes, and opens the PR.

## Useful commands

Show the queue state and any open queue PR:

```bash
python3 scripts/codex/local_queue_runner.py status
```

Run one watcher iteration, useful for smoke testing:

```bash
python3 scripts/codex/local_queue_runner.py watch --once
```

Open draft queued PRs instead of ready PRs:

```bash
python3 scripts/codex/local_queue_runner.py run-next --draft-pr
```

Act on trusted Claude review feedback for an open queue PR:

```bash
python3 scripts/codex/local_queue_runner.py repair-pr 15
```

`repair-pr` only consumes formal Claude reviewer Action reviews and local
comments headed `### Local Claude Max review` from trusted authors. It checks
out the PR branch, gives Codex the original queued prompt, trusted review text,
and current PR diff, then asks Codex to verify each item, implement only valid
actionable feedback, run tests, push any repair commit to the same PR, and post
a summary comment. It refuses to run on PRs that are not labeled `codex-queue`.

## Files

- `.github/codex/prompts/` - one prompt per PR-sized task.
- `.github/codex/prompt_queue/manifest.json` - ordered queue manifest.
- `.github/codex/prompt_queue/progress.json` - merge-gated queue state.
- `scripts/codex/queue_next.py` - stdlib-only helper that builds the current
  combined prompt and advances queue state.
- `scripts/codex/local_queue_runner.py` - local runner that starts Codex CLI,
  waits on PR merges, and opens the next queued PR.

## Review policy

For each queued PR:

- Confirm the diff only addresses the current prompt.
- Confirm safety constraints remain explicit.
- Confirm tests pass.
- Confirm no new Python runtime dependency was added unless the prompt
  explicitly allows it.
- Confirm docs do not overclaim production probing or exploitation.
- Confirm the MCP/REST/agent surfaces still cannot create, widen, or mutate
  scopes.
