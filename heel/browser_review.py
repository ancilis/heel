"""Strict JSON-text adapter for browser-local Heel OpenAPI review."""
from __future__ import annotations

import json
import math
from typing import Any

from .openapi_model import OpenAPIImportError
from .review_answers import ReviewAnswerError, apply_review_answers, parse_review_answers
from .review_contract import stable_json, validate_review_envelope
from .review_service import review_openapi


MAX_BROWSER_INPUT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000

_PUBLIC_MESSAGES = {
    "invalid_json": "The OpenAPI input must be valid duplicate-free JSON.",
    "invalid_document": "The OpenAPI input must be a supported JSON object.",
    "invalid_unicode": "The submitted text contains invalid Unicode.",
    "input_too_large": "The OpenAPI input exceeds the browser review size limit.",
    "input_too_complex": "The OpenAPI input exceeds browser review complexity limits.",
    "invalid_openapi": "The document is not a supported OpenAPI 3.0 or 3.1 document.",
    "unsafe_document": "The OpenAPI document contains unsupported unsafe content.",
    "invalid_answers": "The submitted review answers are invalid or unsupported.",
    "review_failed": "The browser-local review could not be completed safely.",
}


class BrowserReviewError(ValueError):
    """A browser review failure with a stable code and redacted public message."""

    def __init__(self, code: str, public_message: str):
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class _DuplicateKeyError(ValueError):
    pass


def _error(code: str) -> BrowserReviewError:
    return BrowserReviewError(code, _PUBLIC_MESSAGES[code])


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _nesting_within_limit(payload: bytes) -> bool:
    """Bound nesting before the recursive standard-library JSON decoder runs."""
    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return True


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_graph(value: Any) -> None:
    """Validate Unicode, portable scalar values, and node count iteratively."""
    stack = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise _error("input_too_complex")
        if type(current) is dict:
            for key, child in current.items():
                if _contains_surrogate(key):
                    raise _error("invalid_unicode")
                stack.append(child)
        elif type(current) is list:
            stack.extend(current)
        elif type(current) is str:
            if _contains_surrogate(current):
                raise _error("invalid_unicode")
        elif type(current) is int:
            if not -(2**53 - 1) <= current <= 2**53 - 1:
                raise _error("invalid_document")
        elif type(current) is float:
            if not math.isfinite(current):
                raise _error("invalid_document")
        elif current is not None and type(current) is not bool:
            raise _error("invalid_document")


def _parse_source(source: str) -> dict[str, Any]:
    if type(source) is not str:
        raise _error("invalid_document")
    try:
        payload = source.encode("utf-8")
    except UnicodeError:
        raise _error("invalid_unicode") from None
    if len(payload) > MAX_BROWSER_INPUT_BYTES:
        raise _error("input_too_large")
    if not _nesting_within_limit(payload):
        raise _error("input_too_complex")
    try:
        parsed = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError:
        raise _error("invalid_json") from None
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise _error("invalid_json") from None
    if type(parsed) is not dict:
        raise _error("invalid_document")
    _validate_graph(parsed)
    return parsed


def _is_unsafe_openapi_error(error: OpenAPIImportError) -> bool:
    message = str(error).lower()
    return (
        "secret-looking" in message
        or "may only reference local" in message
        or "remote openapi references" in message
        or "no network calls or url fetching" in message
    )


def review_openapi_json(source: str, answers_json: str = "[]") -> str:
    """Return canonical ``heel.review.v1`` JSON without I/O or active execution."""
    spec = _parse_source(source)
    try:
        answers = parse_review_answers(answers_json)
    except ReviewAnswerError:
        raise _error("invalid_answers") from None

    try:
        if answers:
            initial = validate_review_envelope(
                review_openapi(spec, execution_mode="browser_local")
            )
            spec = apply_review_answers(spec, answers, initial["questions"])
        envelope = review_openapi(spec, execution_mode="browser_local")
        validated = validate_review_envelope(envelope)
        return stable_json(validated)
    except BrowserReviewError:
        raise
    except ReviewAnswerError:
        raise _error("invalid_answers") from None
    except OpenAPIImportError as exc:
        code = "unsafe_document" if _is_unsafe_openapi_error(exc) else "invalid_openapi"
        raise _error(code) from None
    except (RecursionError, UnicodeError, ValueError, TypeError):
        raise _error("review_failed") from None
    except Exception:
        raise _error("review_failed") from None
