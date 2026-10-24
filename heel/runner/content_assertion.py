"""Closed local protected-content predicate. No raw content enters shared projections.

It also holds the bounded error/denial-envelope recognizer, shared with the plan-differential
evaluator so that both read one vocabulary.
"""
from __future__ import annotations

import json
import re
from typing import Any


_ALLOW_KEYS = frozenset({"ok", "success", "allowed"})
_DENY_KEYS = frozenset({"upgraderequired", "paymentrequired", "denied", "forbidden"})
_ERROR_KEYS = frozenset({"error", "errors", "errorcode"})
_STATUS_KEYS = frozenset({"status", "statuscode", "code"})
_WRAPPER_KEYS = frozenset({"data", "result", "response"})
_MESSAGE_KEY = "message"
_DENIAL_WORDS = frozenset({
    "error", "fail", "failed", "failure", "denied", "forbidden", "unauthorized", "required",
})
_NO_STRINGS = frozenset({"false", "0", "no"})
_WORD_BREAK = re.compile(r"[^a-z0-9]+", flags=re.ASCII)
# Words and digit groups inside one run: ``PaymentRequired``, ``HTTPError``, ``E403``.
_CAMEL_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", flags=re.ASCII)
_MAX_ENVELOPE_DEPTH = 2


def _says_no(value: Any) -> bool:
    """An allow flag denies on any JSON-falsy value or a no-word."""
    if isinstance(value, str):
        word = value.strip().casefold()
        return not word or word in _NO_STRINGS
    return not value


def _says_yes(value: Any) -> bool:
    """A deny flag denies on any JSON-truthy value that is not a no-word."""
    if isinstance(value, str):
        word = value.strip().casefold()
        return bool(word) and word not in _NO_STRINGS
    return bool(value)


def _denial_status(value: Any) -> bool:
    if type(value) in {int, float}:
        return 400 <= value <= 599 and value == int(value)
    if not isinstance(value, str):
        return False
    words = {
        *_WORD_BREAK.split(value.casefold()),
        *(word.casefold() for word in _CAMEL_WORD.findall(value)),
    }
    return any(
        word in _DENIAL_WORDS or (word.isdigit() and len(word) == 3 and word[0] in "45")
        for word in words
    )


def _states_denial(value: Any, depth: int) -> bool:
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        name = key.casefold().replace("_", "").replace("-", "")
        if (
            (name in _ERROR_KEYS and bool(item))
            or (name in _ALLOW_KEYS and _says_no(item))
            or (name in _DENY_KEYS and _says_yes(item))
            or (name in _STATUS_KEYS and _denial_status(item))
            or (name in _WRAPPER_KEYS and depth < _MAX_ENVELOPE_DEPTH
                and _states_denial(item, depth + 1))
        ):
            return True
    return False


def is_denial_envelope(value: Any) -> bool:
    """A body that says no, at any status, in any JSON spelling of the small vocabulary above.

    Keys match without case, ``_`` or ``-``. An allow flag denies on any JSON-falsy value
    or no-word; a deny flag on any JSON-truthy value that is not a no-word. ``status``/
    ``code`` deny by an integral 4xx/5xx number, or by a denial word or 4xx/5xx digit group
    found across separators, camel-case and letter/digit boundaries. A ``data``/``result``/
    ``response`` wrapper is followed to a bounded depth. This only ever withholds a
    result (parity, or the protected-content predicate below, for either plan): it never
    creates a finding or a ``held`` verdict.
    """
    return _states_denial(value, 0)


def is_ambiguous_message(value: Any) -> bool:
    """An object that is only a message: undecidable, whatever the message says.

    This is a shape check, not a reading of the text. It holds for a JSON object whose keys
    all normalize (as above) to ``message``, at least one with a JSON-truthy value, beside
    at most the exact ``protected_canary`` field. Such a body neither shows that protected
    content was withheld nor that it was disclosed, for either plan and at any status.
    """
    if not isinstance(value, dict):
        return False
    names = [key.casefold().replace("_", "").replace("-", "") for key in value]
    messages = [
        bool(item) for key, name, item in zip(value, names, value.values())
        if key != "protected_canary" and name == _MESSAGE_KEY
    ]
    return any(messages) and len(messages) + ("protected_canary" in value) == len(value)


def protected_content(body: bytes, *, marker: str | None, status: int, method: str = 'GET') -> bool | None:
    """Check the exact synthetic protected field, never a reflected id or status alone.

    The fixture marker is bound in the approved route manifest. Products must place it
    in `protected_canary` only within protected output, never in public/error metadata.
    Unknown bodies remain inconclusive. False means absence for this complete read,
    not that every field, route, lifecycle, or aggregate limit is safe. A body that is a
    recognized error or denial envelope is inconclusive at every status and for either
    identity, even when it also carries the marker: it neither proves a disclosure nor a
    denial, and the status alone never decides it.
    """
    if method != 'GET' or not marker or not marker.startswith('heel-canary-') or len(body) > 256 * 1024:
        return None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        data = json.loads(body, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        return False if not body and status in {401, 402, 403, 404} else None
    if type(data) is not dict:
        return None
    # A body that says no, or only carries a message, is undetermined at any status, before
    # any marker is considered.
    if is_denial_envelope(data) or is_ambiguous_message(data):
        return None
    # A non-2xx body that is not an error envelope and carries the marker still discloses.
    if data.get('protected_canary') == marker:
        return True
    if status in {401, 402, 403, 404}:
        return False
    if status == 200 and (data.get('visibility') in {'public', 'redacted'} or data.get('protected_canary') is None and data.get('records') == []):
        return False
    return None
