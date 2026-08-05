"""Secure local persistence for deterministic Heel review envelopes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Mapping

from .review_contract import stable_json, validate_review_envelope, validate_review_id
from .scope import ensure_home


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"stored review contains duplicate JSON key: {key}")
        result[key] = value
    return result


class LocalProjectStore:
    """Save and retrieve reviews below one selected Heel home directory."""

    def __init__(self, root: Path | None = None):
        self.root = Path(ensure_home()) if root is None else Path(root)
        self.reviews = self.root / "reviews"

    def _review_path(self, review_id: str) -> Path:
        return self.reviews / f"{validate_review_id(review_id)}.json"

    def _reviews_directory(self, *, create: bool) -> bool:
        if self.reviews.is_symlink():
            raise ValueError("reviews directory must not be a symbolic link")
        if not self.reviews.exists():
            if not create:
                return False
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            _chmod_best_effort(self.root, 0o700)
            if self.reviews.is_symlink():
                raise ValueError("reviews directory must not be a symbolic link")
            self.reviews.mkdir(mode=0o700, exist_ok=True)
        if self.reviews.is_symlink():
            raise ValueError("reviews directory must not be a symbolic link")
        if not self.reviews.is_dir():
            raise ValueError("reviews path must be a directory")
        _chmod_best_effort(self.root, 0o700)
        _chmod_best_effort(self.reviews, 0o700)
        return True

    @staticmethod
    def _reject_symlink_or_nonfile(path: Path) -> None:
        try:
            status = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode):
            raise ValueError("review target must not be a symbolic link")
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("review target must be a regular file")

    @staticmethod
    def _read_json(path: Path) -> Any:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("review target must be a regular file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                return json.load(stream, object_pairs_hook=_reject_duplicate_keys)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _load_review(self, path: Path, expected_review_id: str) -> dict[str, Any]:
        self._reject_symlink_or_nonfile(path)
        review = validate_review_envelope(self._read_json(path))
        if review["review_id"] != expected_review_id:
            raise ValueError("stored review_id does not match its filename")
        return review

    def save_review(self, envelope: Mapping[str, Any]) -> Path:
        review_id = validate_review_id(envelope.get("review_id"))
        review = validate_review_envelope(dict(envelope))
        self._reviews_directory(create=True)
        path = self._review_path(review_id)
        self._reject_symlink_or_nonfile(path)
        payload = stable_json(review) + "\n"

        descriptor = -1
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{review_id}.", suffix=".tmp", dir=self.reviews
            )
            temporary_path = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            self._reject_symlink_or_nonfile(path)
            os.replace(temporary_path, path)
            temporary_path = None
            self._fsync_reviews_directory()
            return path
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def _fsync_reviews_directory(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(self.reviews, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        path = self._review_path(review_id)
        if not self._reviews_directory(create=False):
            return None
        if not path.exists() and not path.is_symlink():
            return None
        return self._load_review(path, review_id)

    def list_reviews(self) -> list[dict[str, str]]:
        if not self._reviews_directory(create=False):
            return []
        summaries = []
        for path in sorted(self.reviews.iterdir(), key=lambda item: item.name):
            if path.suffix != ".json":
                continue
            review_id = validate_review_id(path.stem)
            review = self._load_review(path, review_id)
            summaries.append({
                "review_id": review["review_id"],
                "product_id": review["product_id"],
                "gate_status": review["gate_status"],
            })
        return summaries
