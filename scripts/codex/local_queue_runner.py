#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


QUEUE_LABEL = "codex-queue"


class QueueError(RuntimeError):
    pass


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path,
    input_text: str | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, object] = {
        "cwd": str(cwd),
        "text": True,
        "check": False,
    }
    if input_text is not None:
        kwargs["input"] = input_text
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    result = subprocess.run(cmd, **kwargs)
    if check and result.returncode != 0:
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        raise QueueError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{stdout}{stderr}"
        )
    return result


def completed_text(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout or "") + (result.stderr or "")


def load_json(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def repo_root() -> pathlib.Path:
    result = run(["git", "rev-parse", "--show-toplevel"], cwd=pathlib.Path.cwd())
    return pathlib.Path(result.stdout.strip())


def require_tool(name: str) -> None:
    if not shutil.which(name):
        raise QueueError(f"required command not found on PATH: {name}")


def require_clean_worktree(root: pathlib.Path) -> None:
    result = run(["git", "status", "--porcelain"], cwd=root)
    if result.stdout.strip():
        raise QueueError(
            "working tree must be clean before running the queue.\n"
            + result.stdout
        )


def require_chatgpt_codex_login(root: pathlib.Path) -> None:
    result = run(["codex", "login", "status"], cwd=root)
    status = completed_text(result).strip()
    if "Logged in using ChatGPT" not in status:
        raise QueueError(
            "Codex must be logged in with ChatGPT subscription auth. "
            "Run `codex logout` if needed, then `codex login`."
        )


def gh_json(root: pathlib.Path, args: list[str]) -> object:
    result = run(["gh", *args], cwd=root)
    return json.loads(result.stdout)


def repo_full_name(root: pathlib.Path) -> str:
    data = gh_json(root, ["repo", "view", "--json", "nameWithOwner"])
    return str(data["nameWithOwner"])


def default_branch(root: pathlib.Path) -> str:
    data = gh_json(root, ["repo", "view", "--json", "defaultBranchRef"])
    return str(data["defaultBranchRef"]["name"])


def git_current_branch(root: pathlib.Path) -> str:
    result = run(["git", "branch", "--show-current"], cwd=root)
    return result.stdout.strip()


def sync_default_branch(root: pathlib.Path, branch: str) -> None:
    run(["git", "fetch", "origin", branch], cwd=root, capture=False)
    if git_current_branch(root) != branch:
        run(["git", "switch", branch], cwd=root, capture=False)
    run(["git", "pull", "--ff-only", "origin", branch], cwd=root, capture=False)


def queue_next(root: pathlib.Path) -> dict:
    result = run(["python3", "scripts/codex/queue_next.py", "next"], cwd=root)
    return json.loads(result.stdout)


def build_prompt(root: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
    run(
        ["python3", "scripts/codex/queue_next.py", "build", "--out", str(out)],
        cwd=root,
        capture=False,
    )
    return out


def advance_queue(root: pathlib.Path) -> None:
    run(["python3", "scripts/codex/queue_next.py", "advance"], cwd=root, capture=False)


def filter_queue_prs(prs: list[dict]) -> list[dict]:
    filtered = []
    for pr in prs:
        labels = pr.get("labels", [])
        if any(label.get("name") == QUEUE_LABEL for label in labels):
            filtered.append(pr)
    return filtered


def open_queue_prs(root: pathlib.Path, repo: str) -> list[dict]:
    data = gh_json(
        root,
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--json",
            "number,title,url,headRefName,labels",
        ],
    )
    return filter_queue_prs(data)


def build_codex_command(
    *,
    repo_root: pathlib.Path,
    mode: str,
    sandbox: str,
    approval_policy: str,
    output_path: pathlib.Path,
) -> list[str]:
    if mode == "exec":
        return [
            "codex",
            "exec",
            "--cd",
            str(repo_root),
            "--sandbox",
            sandbox,
            "--output-last-message",
            str(output_path),
            "-",
        ]
    if mode == "tui":
        return [
            "codex",
            "--cd",
            str(repo_root),
            "--sandbox",
            sandbox,
            "--ask-for-approval",
            approval_policy,
        ]
    raise QueueError(f"unsupported Codex mode: {mode}")


def run_codex(
    *,
    root: pathlib.Path,
    prompt_path: pathlib.Path,
    mode: str,
    sandbox: str,
    approval_policy: str,
    output_path: pathlib.Path,
) -> None:
    prompt_text = prompt_path.read_text(encoding="utf-8")
    cmd = build_codex_command(
        repo_root=root,
        mode=mode,
        sandbox=sandbox,
        approval_policy=approval_policy,
        output_path=output_path,
    )
    if mode == "exec":
        print(f"Starting Codex exec session: {' '.join(cmd)}", flush=True)
        run(cmd, cwd=root, input_text=prompt_text, capture=False)
    else:
        print(f"Starting Codex TUI session: {' '.join(cmd)} <prompt>", flush=True)
        print("Codex TUI will open. Exit the TUI when the queued task is finished.", flush=True)
        run([*cmd, prompt_text], cwd=root, capture=False)


def run_tests(root: pathlib.Path) -> None:
    if (root / "Makefile").exists():
        run(["make", "test"], cwd=root, capture=False)
    else:
        run(
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
            cwd=root,
            capture=False,
        )


def unique_branch(root: pathlib.Path, branch: str) -> str:
    local = run(["git", "branch", "--list", branch], cwd=root).stdout.strip()
    remote = run(["git", "ls-remote", "--heads", "origin", branch], cwd=root).stdout.strip()
    if not local and not remote:
        return branch
    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{branch}-{suffix}"


def ensure_labels(root: pathlib.Path, labels: list[str]) -> None:
    colors = {
        "codex-queue": "5319e7",
        "heel-uplift": "0e8a16",
        "needs-human-review": "fbca04",
    }
    descriptions = {
        "codex-queue": "Generated by the merge-gated local Codex prompt queue",
        "heel-uplift": "Heel uplift queue work",
        "needs-human-review": "Requires human review before merge",
    }
    for label in labels:
        run(
            [
                "gh",
                "label",
                "create",
                label,
                "--color",
                colors.get(label, "ededed"),
                "--description",
                descriptions.get(label, "Codex prompt queue label"),
                "--force",
            ],
            cwd=root,
            capture=False,
        )


def pr_body(item: dict, codex_output: str) -> str:
    return f"""## Codex queued task

This PR was generated by the merge-gated local Codex CLI prompt queue.

- Prompt id: `{item["id"]}`
- Slug: `{item["slug"]}`
- Title: `{item["title"]}`

## Human review required

Do not merge unless:
- The diff is scoped to this queued task.
- Safety constraints remain intact.
- Tests pass.
- Docs and public claims are accurate.
- No later prompt has been started in this PR.

Merging this PR advances `.github/codex/prompt_queue/progress.json` and lets the local watcher start the next queued prompt.

## Codex final message

{codex_output.strip() or "_No final message captured._"}
"""


def create_pr(
    *,
    root: pathlib.Path,
    repo: str,
    base: str,
    branch: str,
    item: dict,
    labels: list[str],
    draft: bool,
    codex_output: str,
) -> str:
    ensure_labels(root, labels)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as f:
        f.write(pr_body(item, codex_output))
        body_path = f.name
    try:
        cmd = [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            base,
            "--head",
            branch,
            "--title",
            f"Codex queue {item['id']}: {item['title']}",
            "--body-file",
            body_path,
        ]
        for label in labels:
            cmd.extend(["--label", label])
        if draft:
            cmd.append("--draft")
        result = run(cmd, cwd=root)
        return result.stdout.strip()
    finally:
        pathlib.Path(body_path).unlink(missing_ok=True)


def commit_and_open_pr(
    *,
    root: pathlib.Path,
    repo: str,
    base: str,
    branch: str,
    item: dict,
    labels: list[str],
    draft: bool,
    output_path: pathlib.Path,
) -> str:
    prompt_path = root / ".github/codex/current_prompt.md"
    prompt_path.unlink(missing_ok=True)
    codex_output = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    output_path.unlink(missing_ok=True)

    run(["git", "add", "-A"], cwd=root, capture=False)
    diff = run(["git", "diff", "--cached", "--quiet"], cwd=root, check=False)
    if diff.returncode == 0:
        raise QueueError("Codex produced no commit-worthy changes.")

    run(
        ["git", "commit", "-m", f"Codex queue {item['id']}: {item['slug']}"],
        cwd=root,
        capture=False,
    )
    run(["git", "push", "-u", "origin", branch], cwd=root, capture=False)
    return create_pr(
        root=root,
        repo=repo,
        base=base,
        branch=branch,
        item=item,
        labels=labels,
        draft=draft,
        codex_output=codex_output,
    )


def load_manifest(root: pathlib.Path) -> dict:
    return load_json(root / ".github/codex/prompt_queue/manifest.json")


def prepare(args: argparse.Namespace) -> tuple[pathlib.Path, str, str, str, dict]:
    root = repo_root()
    for tool in ("git", "gh", "codex", "python3"):
        require_tool(tool)
    if args.require_chatgpt_auth:
        require_chatgpt_codex_login(root)
    repo = repo_full_name(root)
    base = default_branch(root)
    manifest = load_manifest(root)
    return root, repo, base, manifest.get("branch_prefix", "codex/heel-uplift"), manifest


def cmd_status(args: argparse.Namespace) -> int:
    root, repo, _base, _prefix, _manifest = prepare(args)
    open_prs = open_queue_prs(root, repo)
    next_item = queue_next(root)
    print(json.dumps({"open_queue_prs": open_prs, "next": next_item}, indent=2))
    return 0


def cmd_run_next(args: argparse.Namespace) -> int:
    root, repo, base, _prefix, manifest = prepare(args)
    require_clean_worktree(root)
    sync_default_branch(root, base)
    require_clean_worktree(root)

    open_prs = open_queue_prs(root, repo)
    if open_prs:
        print(f"Queue is waiting on open PR: {open_prs[0]['url']}")
        return 0

    item = queue_next(root)
    if item.get("done"):
        print(item.get("message", "No prompts remaining."))
        return 0

    branch = unique_branch(root, item["branch"])
    run(["git", "switch", "-c", branch], cwd=root, capture=False)
    prompt_path = build_prompt(root, root / ".github/codex/current_prompt.md")
    output_path = root / "codex-output.md"

    try:
        run_codex(
            root=root,
            prompt_path=prompt_path,
            mode=args.mode,
            sandbox=args.sandbox,
            approval_policy=args.approval_policy,
            output_path=output_path,
        )
        if not args.skip_tests:
            run_tests(root)
        advance_queue(root)
        pr_url = commit_and_open_pr(
            root=root,
            repo=repo,
            base=base,
            branch=branch,
            item=item,
            labels=manifest.get("labels", [QUEUE_LABEL]),
            draft=args.draft_pr,
            output_path=output_path,
        )
        print(f"Opened queued PR: {pr_url}")
        return 0
    except Exception:
        print(
            f"Queued branch left for inspection: {branch}. "
            "Fix or reset it before re-running the queue.",
            file=sys.stderr,
        )
        raise


def cmd_watch(args: argparse.Namespace) -> int:
    root, repo, base, _prefix, _manifest = prepare(args)
    print(f"Watching {repo} for merge-gated Codex queue progress.")
    while True:
        require_clean_worktree(root)
        sync_default_branch(root, base)
        open_prs = open_queue_prs(root, repo)
        if open_prs:
            print(f"Waiting on {open_prs[0]['url']}")
        else:
            item = queue_next(root)
            if item.get("done"):
                print(item.get("message", "No prompts remaining."))
                return 0
            cmd_run_next(args)
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


def add_shared_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--require-chatgpt-auth",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require `codex login status` to report ChatGPT auth.",
    )


def add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=["exec", "tui"], default="exec")
    parser.add_argument("--sandbox", default="workspace-write")
    parser.add_argument(
        "--approval-policy",
        default=None,
        help="Defaults to `never` for exec mode and `on-request` for TUI mode.",
    )
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--draft-pr", action="store_true")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)

    p_status = sub.add_parser("status")
    add_shared_args(p_status)
    p_status.set_defaults(func=cmd_status)

    p_run = sub.add_parser("run-next")
    add_shared_args(p_run)
    add_run_args(p_run)
    p_run.set_defaults(func=cmd_run_next)

    p_watch = sub.add_parser("watch")
    add_shared_args(p_watch)
    add_run_args(p_watch)
    p_watch.add_argument("--poll-seconds", type=int, default=60)
    p_watch.add_argument("--once", action="store_true")
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args()
    if getattr(args, "approval_policy", None) is None:
        args.approval_policy = "never" if getattr(args, "mode", "exec") == "exec" else "on-request"
    try:
        return args.func(args)
    except QueueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
