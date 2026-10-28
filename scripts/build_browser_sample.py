#!/usr/bin/env python3
"""Build the deterministic review rendered by Heel's anonymous browser app."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from heel.browser_review import review_openapi_json  # noqa: E402


SAMPLE_SOURCE = ROOT / "apps/heel-cloud/data/sample-openapi.json"
SAMPLE_REVIEW = ROOT / "apps/heel-cloud/data/sample-review.v1.json"


def build() -> str:
    """Return the canonical browser-local review with one trailing newline."""
    source = SAMPLE_SOURCE.read_text(encoding="utf-8")
    return review_openapi_json(source) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed sample review differs from the native adapter",
    )
    args = parser.parse_args(argv)
    generated = build()
    if args.check:
        if not SAMPLE_REVIEW.is_file():
            print(f"missing generated sample: {SAMPLE_REVIEW.relative_to(ROOT)}", file=sys.stderr)
            return 1
        if SAMPLE_REVIEW.read_text(encoding="utf-8") != generated:
            print("browser sample review is stale; run scripts/build_browser_sample.py", file=sys.stderr)
            return 1
        return 0
    SAMPLE_REVIEW.write_text(generated, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
