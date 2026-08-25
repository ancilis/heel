"""Bounded deterministic redaction for runner-local serialization boundaries."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any


MAX_INPUT_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 4096
MAX_CONFIGURED_SECRETS = 64
MAX_SECRET_BYTES = 16 * 1024
MAX_CONFIGURED_BYTES = 256 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_SAFE_JSON_BYTES = 64 * 1024
_MARKER = "[REDACTED:secret]"
_TRUNCATED = "[TRUNCATED]"
_HEADER = re.compile(
    r"(?im)^(?P<name>[ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)[ \t]*:[ \t]*)"
    r"(?P<value>[^\r\n]*)"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"(?P<separator>[ \t]*=[ \t]*)(?P<value>[^\s,;\]\}]+)"
)
_BEARER = re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{3,}")
_JWT = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}(?![A-Za-z0-9_-])")
_API_TOKEN = re.compile(r"(?i)(?<![A-Za-z0-9])(?:sk|pk|api)[_-](?:live[_-]|test[_-])?[A-Za-z0-9_-]{12,}")


def _bounded_text(value: str) -> str:
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return value
    keep = MAX_OUTPUT_BYTES - len(_TRUNCATED.encode("ascii"))
    return encoded[:keep].decode("utf-8", errors="ignore") + _TRUNCATED


def _secret_key(value: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    parts = {
        part for part in re.split(r"[^A-Za-z0-9]+", separated.casefold()) if part
    }
    compact = "".join(parts)
    return bool(parts & {"authorization", "cookie", "password", "passwd", "secret", "token"}) or compact in {
        "apikey", "xapikey", "accesstoken", "refreshtoken", "clientsecret",
        "proxyauthorization", "setcookie",
    }


class Redactor:
    __slots__ = ("_configured", "_configured_pattern")

    def __init__(self, configured: Sequence[str] = ()):
        if isinstance(configured, (str, bytes)) or not isinstance(configured, Sequence):
            raise ValueError("configured secrets must be a bounded sequence")
        if len(configured) > MAX_CONFIGURED_SECRETS:
            raise ValueError("configured secret count exceeds bound")
        normalized: list[str] = []
        configured_bytes = 0
        for secret in configured:
            if type(secret) is not str:
                raise ValueError("configured secret must be text")
            try:
                size = len(secret.encode("utf-8"))
            except UnicodeError:
                raise ValueError("configured secret must be valid UTF-8") from None
            if size < 4 or size > MAX_SECRET_BYTES:
                raise ValueError("configured secret length is outside the closed bound")
            configured_bytes += size
            normalized.append(secret)
        if configured_bytes > MAX_CONFIGURED_BYTES:
            raise ValueError("configured secret bytes exceed bound")
        if len(set(normalized)) != len(normalized):
            raise ValueError("configured secrets must be unique")
        self._configured = tuple(sorted(normalized, key=lambda item: (-len(item), item)))
        self._configured_pattern = (
            re.compile("|".join(re.escape(item) for item in self._configured))
            if self._configured else None
        )

    def __repr__(self) -> str:
        return f"Redactor(configured_count={len(self._configured)})"

    def _plain(self, value: str) -> tuple[str, int]:
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            raise ValueError("redaction input must be valid UTF-8") from None
        if size > MAX_INPUT_BYTES:
            raise ValueError("redaction input exceeds bound")
        spans: list[tuple[int, int]] = []
        if self._configured_pattern is not None:
            spans.extend(match.span() for match in self._configured_pattern.finditer(value))
        for pattern in (_HEADER, _ASSIGNMENT):
            spans.extend(match.span("value") for match in pattern.finditer(value))
        for pattern in (_BEARER, _JWT, _API_TOKEN):
            spans.extend(match.span() for match in pattern.finditer(value))
        merged: list[list[int]] = []
        for start, end in sorted(spans):
            if start == end:
                continue
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        if not merged:
            return _bounded_text(value), 0
        pieces: list[str] = []
        previous = 0
        for start, end in merged:
            pieces.extend((value[previous:start], _MARKER))
            previous = end
        pieces.append(value[previous:])
        return _bounded_text("".join(pieces)), len(merged)

    def redact(self, value: str) -> tuple[str, int]:
        if type(value) is not str:
            raise TypeError("redaction input must be text")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            raise ValueError("redaction input must be valid UTF-8") from None
        if size > MAX_INPUT_BYTES:
            raise ValueError("redaction input exceeds bound")
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            return self._plain(value)
        if not isinstance(parsed, (dict, list)):
            return self._plain(value)
        sanitized, count = _safe_json(parsed, self, state=[0], depth=0)
        serialized = json.dumps(
            sanitized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        return _bounded_text(serialized), count

    def count_bytes(self, *chunks: bytes) -> int:
        """Count redactions in bounded local evidence without returning response text."""
        if not chunks:
            raise ValueError("redaction byte count requires local evidence")
        total = 0
        for chunk in chunks:
            if type(chunk) is not bytes:
                raise TypeError("redaction evidence must be bytes")
            if len(chunk) > MAX_INPUT_BYTES:
                raise ValueError("redaction evidence exceeds bound")
            _, count = self.redact(chunk.decode("utf-8", errors="replace"))
            total += count
            if total > MAX_JSON_NODES:
                raise ValueError("redaction count exceeds bound")
        return total


def _safe_json(value: Any, redactor: Redactor, *, state: list[int], depth: int) -> tuple[Any, int]:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("safe JSON depth exceeds bound")
    state[0] += 1
    if state[0] > MAX_JSON_NODES:
        raise ValueError("safe JSON node count exceeds bound")
    if value is None or type(value) is bool:
        return value, 0
    if type(value) is int:
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError("safe JSON integer exceeds bound")
        return value, 0
    if type(value) is float:
        raise TypeError("safe JSON accepts bounded integers, not floats")
    if type(value) is str:
        return redactor._plain(value)
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ValueError("safe JSON object exceeds bound")
        result: dict[str, Any] = {}
        count = 0
        for key in sorted(value):
            if type(key) is not str:
                raise TypeError("safe JSON object keys must be text")
            if _secret_key(key):
                result[key] = _MARKER
                count += 1
            else:
                result[key], added = _safe_json(
                    value[key], redactor, state=state, depth=depth + 1,
                )
                count += added
        return result, count
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError("safe JSON array exceeds bound")
        result = []
        count = 0
        for item in value:
            safe, added = _safe_json(item, redactor, state=state, depth=depth + 1)
            result.append(safe)
            count += added
        return result, count
    raise TypeError("safe JSON value uses an unsupported type")


def safe_json_value(value: Any, redactor: Redactor) -> Any:
    if not isinstance(redactor, Redactor):
        raise TypeError("safe JSON requires a Redactor")
    result, _ = _safe_json(value, redactor, state=[0], depth=0)
    try:
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise TypeError("safe JSON value cannot be serialized") from None
    if len(encoded) > MAX_SAFE_JSON_BYTES:
        raise ValueError("safe JSON output exceeds bound")
    return result


__all__ = ["Redactor", "safe_json_value"]
