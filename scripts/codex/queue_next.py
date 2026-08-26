#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone


def load_json(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def find_prompt(manifest: dict, prompt_id: int) -> dict:
    for item in manifest["prompts"]:
        if int(item["id"]) == int(prompt_id):
            return item
    raise SystemExit(f"Prompt id not found in manifest: {prompt_id}")


def cmd_next(args: argparse.Namespace) -> int:
    manifest = load_json(pathlib.Path(args.manifest))
    progress = load_json(pathlib.Path(args.progress))

    next_id = int(progress.get("next_prompt_id", 1))
    if next_id > len(manifest["prompts"]):
        print(json.dumps({"done": True, "message": "No prompts remaining."}))
        return 0

    item = find_prompt(manifest, next_id)
    print(json.dumps({
        "done": False,
        "id": item["id"],
        "slug": item["slug"],
        "file": item["file"],
        "title": item["title"],
        "branch": f"{manifest.get('branch_prefix', 'codex/heel-uplift')}-{item['id']:02d}-{item['slug']}",
    }))
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root)
    manifest = load_json(pathlib.Path(args.manifest))
    progress = load_json(pathlib.Path(args.progress))
    next_id = int(progress.get("next_prompt_id", 1))
    item = find_prompt(manifest, next_id)

    master_path = repo_root / manifest["master_prompt"]
    if not master_path.exists():
        master_path = repo_root / ".github/codex/prompts/00_MASTER.md"

    item_path = repo_root / item["file"]
    if not item_path.exists():
        item_path = repo_root / ".github/codex/prompts" / pathlib.Path(item["file"]).name

    master = master_path.read_text(encoding="utf-8")
    task = item_path.read_text(encoding="utf-8")

    combined = f"""{master}

---

# Current queued task

Queue id: {item['id']}
Slug: {item['slug']}
Title: {item['title']}

{task}

---

# PR requirements for this queued task

- Keep the PR focused on this single task.
- Run relevant tests.
- Include a PR body with:
  - Summary
  - Safety notes
  - Tests run
  - Docs updated
  - Known limitations
- Do not auto-merge.
- Do not begin any later prompt in this PR.
"""
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(combined, encoding="utf-8")
    print(str(out))
    return 0


def cmd_advance(args: argparse.Namespace) -> int:
    manifest = load_json(pathlib.Path(args.manifest))
    progress_path = pathlib.Path(args.progress)
    progress = load_json(progress_path)
    current_id = int(progress.get("next_prompt_id", 1))
    item = find_prompt(manifest, current_id)

    completed = list(progress.get("completed_prompt_ids", []))
    if current_id not in completed:
        completed.append(current_id)

    progress.update({
        "completed_prompt_ids": completed,
        "next_prompt_id": current_id + 1,
        "in_flight": None,
        "last_pr": {
            "prompt_id": current_id,
            "slug": item["slug"],
            "pr_url": args.pr_url or "",
            "advanced_at": datetime.now(timezone.utc).isoformat(),
        },
    })
    save_json(progress_path, progress)
    print(json.dumps(progress, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)

    p_next = sub.add_parser("next")
    p_next.add_argument("--manifest", default=".github/codex/prompt_queue/manifest.json")
    p_next.add_argument("--progress", default=".github/codex/prompt_queue/progress.json")
    p_next.set_defaults(func=cmd_next)

    p_build = sub.add_parser("build")
    p_build.add_argument("--manifest", default=".github/codex/prompt_queue/manifest.json")
    p_build.add_argument("--progress", default=".github/codex/prompt_queue/progress.json")
    p_build.add_argument("--repo-root", default=".")
    p_build.add_argument("--out", default=".github/codex/current_prompt.md")
    p_build.set_defaults(func=cmd_build)

    p_advance = sub.add_parser("advance")
    p_advance.add_argument("--manifest", default=".github/codex/prompt_queue/manifest.json")
    p_advance.add_argument("--progress", default=".github/codex/prompt_queue/progress.json")
    p_advance.add_argument("--pr-url", default="")
    p_advance.set_defaults(func=cmd_advance)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
