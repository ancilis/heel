"""Secure local persistence for deterministic Heel review envelopes.

The result hash detects accidental corruption. It is not an authenticity mechanism: a
malicious local writer can change an envelope and recompute its content hash. This milestone
does not add signatures or HMAC authentication to review files.
"""
from __future__ import annotations

from contextlib import contextmanager
import inspect
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Iterator, Mapping

from .review_contract import stable_json, validate_review_envelope, validate_review_id
from .scope import heel_home


class SecureStorageUnavailable(RuntimeError):
    """The platform cannot provide the no-follow, descriptor-anchored storage contract."""


class StoredReviewError(ValueError):
    """A named stored review is corrupt, unsafe, or violates the review contract."""


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _require_secure_storage_capabilities() -> None:
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rename)
    try:
        replace_parameters = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):
        replace_parameters = {}
    supported = (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and all(function in os.supports_dir_fd for function in required_dir_fd)
        and os.stat in os.supports_follow_symlinks
        and os.listdir in os.supports_fd
        and {"src_dir_fd", "dst_dir_fd"} <= set(replace_parameters)
    )
    if not supported:
        raise SecureStorageUnavailable(
            "secure local review storage requires POSIX dir_fd and O_NOFOLLOW support"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"stored review contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _absolute_without_resolving(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _raise_unsafe_component(parent_fd: int, name: str, error: OSError) -> None:
    try:
        status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise error
    if stat.S_ISLNK(status.st_mode):
        raise ValueError("Heel home path must not contain a symbolic link") from error
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("Heel home path components must be directories") from error
    raise error


def _open_child_directory(parent_fd: int, name: str, *, create: bool) -> int | None:
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            return None
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as error:
            _raise_unsafe_component(parent_fd, name, error)
    except OSError as error:
        _raise_unsafe_component(parent_fd, name, error)
    raise AssertionError("unreachable")


def _enforce_mode(descriptor: int, expected: int, label: str) -> None:
    os.fchmod(descriptor, expected)
    actual = stat.S_IMODE(os.fstat(descriptor).st_mode)
    if actual != expected:
        raise PermissionError(
            f"{label} must have mode {expected:#06o}; observed {actual:#06o}"
        )


def _stored_review_error(filename: str) -> StoredReviewError:
    return StoredReviewError(f"stored review {filename!r} is corrupt or invalid")


class LocalProjectStore:
    """Save and retrieve reviews below one POSIX descriptor-anchored Heel home."""

    def __init__(self, root: Path | None = None):
        _require_secure_storage_capabilities()
        selected = Path(heel_home()) if root is None else Path(root)
        self.root = _absolute_without_resolving(selected)
        if self.root == Path(self.root.anchor):
            raise ValueError("Heel home must not be a filesystem root")
        self.reviews = self.root / "reviews"
        with self._open_reviews(create=False, enforce_modes=False):
            pass

    def _open_root(self, *, create: bool) -> int | None:
        current = os.open(self.root.anchor, _DIRECTORY_FLAGS)
        anchor_status = os.fstat(current)
        try:
            for part in self.root.parts[1:]:
                child = _open_child_directory(current, part, create=create)
                if child is None:
                    os.close(current)
                    current = -1
                    return None
                os.close(current)
                current = child
            root_status = os.fstat(current)
            if (root_status.st_dev, root_status.st_ino) == (
                anchor_status.st_dev,
                anchor_status.st_ino,
            ):
                raise ValueError("Heel home must not be a filesystem root")
            return current
        except BaseException:
            if current >= 0:
                os.close(current)
            raise

    @contextmanager
    def _open_reviews(
        self, *, create: bool, enforce_modes: bool = True
    ) -> Iterator[int | None]:
        root_fd = self._open_root(create=create)
        if root_fd is None:
            yield None
            return
        reviews_fd = -1
        try:
            opened_reviews = _open_child_directory(root_fd, "reviews", create=create)
            if opened_reviews is None:
                yield None
                return
            reviews_fd = opened_reviews
            if enforce_modes:
                _enforce_mode(root_fd, 0o700, "Heel home")
                _enforce_mode(reviews_fd, 0o700, "Heel reviews directory")
            yield reviews_fd
        finally:
            if reviews_fd >= 0:
                os.close(reviews_fd)
            os.close(root_fd)

    @staticmethod
    def _target_status(reviews_fd: int, filename: str) -> os.stat_result | None:
        try:
            return os.stat(filename, dir_fd=reviews_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _reject_unsafe_target(reviews_fd: int, filename: str) -> None:
        status = LocalProjectStore._target_status(reviews_fd, filename)
        if status is None:
            return
        if stat.S_ISLNK(status.st_mode):
            raise ValueError("review target must not be a symbolic link")
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("review target must be a regular file")

    @staticmethod
    def _read_review_file(reviews_fd: int, filename: str) -> Any:
        descriptor = os.open(filename, _READ_FLAGS, dir_fd=reviews_fd)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("review target must be a regular file")
            _enforce_mode(descriptor, 0o600, "stored review file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                return json.load(stream, object_pairs_hook=_reject_duplicate_keys)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _load_review(
        reviews_fd: int, filename: str, expected_review_id: str
    ) -> dict[str, Any]:
        try:
            LocalProjectStore._reject_unsafe_target(reviews_fd, filename)
            review = validate_review_envelope(
                LocalProjectStore._read_review_file(reviews_fd, filename)
            )
            if review["review_id"] != expected_review_id:
                raise ValueError("stored review_id does not match its filename")
            return review
        except (OSError, UnicodeError, ValueError) as error:
            raise _stored_review_error(filename) from error

    @staticmethod
    def _create_temporary(reviews_fd: int, review_id: str) -> tuple[int, str]:
        for _ in range(100):
            filename = f".{review_id}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    filename, _WRITE_FLAGS, 0o600, dir_fd=reviews_fd
                )
            except FileExistsError:
                continue
            try:
                _enforce_mode(descriptor, 0o600, "temporary review file")
            except BaseException:
                os.close(descriptor)
                try:
                    os.unlink(filename, dir_fd=reviews_fd)
                except FileNotFoundError:
                    pass
                raise
            return descriptor, filename
        raise FileExistsError("could not allocate an exclusive review temp file")

    def save_review(self, envelope: Mapping[str, Any]) -> Path:
        snapshot = dict(envelope)
        review = validate_review_envelope(snapshot)
        review_id = review["review_id"]
        filename = f"{validate_review_id(review_id)}.json"
        payload = stable_json(review) + "\n"

        with self._open_reviews(create=True) as reviews_fd:
            if reviews_fd is None:
                raise SecureStorageUnavailable("could not create the secure reviews directory")
            self._reject_unsafe_target(reviews_fd, filename)
            descriptor, temporary = self._create_temporary(reviews_fd, review_id)
            try:
                with os.fdopen(
                    descriptor,
                    "w",
                    encoding="utf-8",
                    newline="\n",
                    closefd=False,
                ) as stream:
                    stream.write(payload)
                    stream.flush()
                os.fsync(descriptor)
                try:
                    os.replace(
                        temporary,
                        filename,
                        src_dir_fd=reviews_fd,
                        dst_dir_fd=reviews_fd,
                    )
                except (TypeError, NotImplementedError) as error:
                    raise SecureStorageUnavailable(
                        "secure local review storage requires anchored replace support"
                    ) from error
                temporary = ""
                _enforce_mode(descriptor, 0o600, "final review file")
                os.fsync(reviews_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if temporary:
                    os.unlink(temporary, dir_fd=reviews_fd)
        return self.reviews / filename

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        review_id = validate_review_id(review_id)
        filename = f"{review_id}.json"
        with self._open_reviews(create=False) as reviews_fd:
            if reviews_fd is None:
                return None
            if self._target_status(reviews_fd, filename) is None:
                return None
            return self._load_review(reviews_fd, filename, review_id)

    def list_reviews(self) -> list[dict[str, str]]:
        with self._open_reviews(create=False) as reviews_fd:
            if reviews_fd is None:
                return []
            summaries = []
            for filename in sorted(os.listdir(reviews_fd)):
                if not filename.endswith(".json"):
                    continue
                try:
                    review_id = validate_review_id(filename[:-5])
                except ValueError as error:
                    raise _stored_review_error(filename) from error
                review = self._load_review(reviews_fd, filename, review_id)
                summaries.append({
                    "review_id": review["review_id"],
                    "product_id": review["product_id"],
                    "gate_status": review["gate_status"],
                })
            return summaries
