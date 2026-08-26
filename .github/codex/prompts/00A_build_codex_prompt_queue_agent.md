# Prompt 0A — Build the merge-gated Codex prompt queue

Task: Add a merge-gated Codex prompt queue to the repository so prompts can be executed one at a time, each producing a PR, and the next prompt starts only after the previous queued PR is merged.

Implement:

- `.github/codex/prompts/`
- `.github/codex/prompt_queue/manifest.json`
- `.github/codex/prompt_queue/progress.json`
- `.github/workflows/codex-prompt-queue.yml`
- `scripts/codex/queue_next.py`
- `docs/CODEX_PROMPT_QUEUE_RUNBOOK.md`

Workflow behavior:

- Trigger manually via `workflow_dispatch`.
- Trigger on `pull_request.closed` only when:
  - PR was merged
  - PR has label `codex-queue`
- Read queue state.
- Build a combined prompt from `00_MASTER.md` + current prompt file.
- Run `openai/codex-action@v1` with:
  - `prompt-file`
  - `sandbox: workspace-write`
  - `safety-strategy: drop-sudo`
  - no auto-merge
- Run tests.
- Advance `progress.json` inside the PR branch.
- Open a PR labeled:
  - `codex-queue`
  - `heel-uplift`
  - `needs-human-review`

Do not create an endlessly running agent. Use merge-gated PR acceptance as the control point.

Security requirements:

- Use `OPENAI_API_KEY` from GitHub secrets.
- Do not expose secrets in logs.
- Do not run unsafe full access.
- Restrict execution to manual trigger or merged queue PRs.
- Do not accept untrusted prompt input from issue bodies, PR comments, branch names, commit messages, or forked PRs.

Tests:

- Add a small unit test for the queue helper if the repo has a scripts test pattern.
- Validate the manifest and progress files.
- Ensure the workflow references prompt files rather than issue text.

Acceptance criteria:

- A maintainer can trigger the first prompt manually.
- Each merged queued PR triggers the next prompt.
- Closing a queued PR without merge does not advance.
- Human review remains mandatory.
