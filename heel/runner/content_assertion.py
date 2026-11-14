"""Closed local protected-content predicate. No raw content enters shared projections.

It also holds the bounded error/denial-envelope recognizer, shared with the plan-differential
evaluator so that both read one vocabulary.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from decimal import Decimal, DecimalException
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


# ---------------------------------------------------------------------------------------
# E1: closed, versioned, bounded live-read response assertions (pure; not yet wired).
#
# Nothing below is called by the compiler, executor, API, UI or packaging path. It sends no
# traffic, logs nothing, and returns only booleans, tri-states, closed reason codes and an
# outcome: never a body, an expected value, or exception text. The legacy
# ``protected_content`` predicate and the envelope recognizers above are unchanged and are
# applied first, unweakened. Sealing local fixture references and binding the definition
# digest into a signed manifest is an E2 gate that does not exist yet.
# The design record lives with the private development specs, not in public source.
# ---------------------------------------------------------------------------------------

LIVE_READ_ASSERTION_SCHEMA = "heel.live-read-assertion.v1"
LIVE_READ_ROLE_POLICIES = frozenset({"anonymous_authenticated_read", "plan_entitlement_read"})
LIVE_READ_CONDITION_KINDS = frozenset({"json_field_present", "json_scalar_equals_fixture"})
LIVE_READ_MAX_PATH_SEGMENTS = 8
LIVE_READ_MAX_SEGMENT_CHARS = 128
LIVE_READ_MAX_SEGMENT_BYTES = 256
LIVE_READ_MAX_INDEX = 1023
LIVE_READ_MAX_DEFINITION_BYTES = 4096
LIVE_READ_MAX_RAW_DEFINITION_BYTES = 8192
LIVE_READ_MAX_FIXTURE_STRING_BYTES = 2048
LIVE_READ_MAX_FIXTURE_INT = 2 ** 63 - 1
LIVE_READ_MAX_BODY_BYTES = 256 * 1024
LIVE_READ_MAX_BODY_DEPTH = 32
LIVE_READ_MAX_BODY_NODES = 10_000
_LIVE_EMPTY_DENIAL_STATUSES = frozenset({401, 402, 403, 404})
_LIVE_RESERVED_SEGMENTS = frozenset({"*", "**", ".", "..", "$", "@"})
_LIVE_FIXTURE_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}", flags=re.ASCII)
_LIVE_TOP_KEYS = frozenset({"schema_version", "success_witness", "condition"})
_LIVE_WITNESS_KEYS = frozenset({"path", "expected_fixture"})
_LIVE_CONDITION_KEYS = {
    "json_field_present": frozenset({"kind", "path"}),
    "json_scalar_equals_fixture": frozenset({"kind", "path", "expected_fixture"}),
}

LIVE_READ_DEFINITION_ERRORS = frozenset({
    "definition_malformed", "definition_too_large", "field_type_invalid", "unknown_field",
    "missing_field", "schema_version_unsupported", "condition_kind_unsupported",
    "path_type_invalid", "path_length_invalid", "path_segment_invalid",
    "path_segment_reserved", "fixture_reference_invalid",
})
LIVE_READ_OBSERVATION_REASONS = frozenset({
    "configured_condition_true", "configured_condition_false", "empty_denial",
    "method_not_observable", "fixture_unbound", "fixtures_invalid", "fixture_missing",
    "fixture_invalid", "status_invalid", "body_invalid", "body_too_large", "body_empty",
    "body_malformed", "body_not_object", "denial_envelope", "ambiguous_message",
    "status_not_success", "witness_path_unresolved", "witness_not_matched",
    "path_parent_missing", "path_type_mismatch", "condition_value_not_scalar",
})
LIVE_READ_PAIR_REASONS = frozenset({
    "role_policy_unsupported", "method_not_observable", "fixture_unbound", "fixtures_invalid",
    "fixture_missing", "fixture_invalid", "positive_control_status",
    "positive_control_unknown", "positive_control_condition_false",
    "restricted_condition_true", "restricted_condition_false", "restricted_empty_denial",
    *(f"restricted_{reason}" for reason in LIVE_READ_OBSERVATION_REASONS),
})


class LiveAssertionError(ValueError):
    """A rejected definition. Its only content is one closed reason code, never input."""

    def __init__(self, reason: str) -> None:
        assert reason in LIVE_READ_DEFINITION_ERRORS
        super().__init__(reason)
        self.reason = reason


def _reject(reason: str) -> LiveAssertionError:
    return LiveAssertionError(reason)


@dataclass(frozen=True)
class LiveReadAssertion:
    """A validated ``heel.live-read-assertion.v1`` definition. Paths are immutable tuples."""

    witness_path: tuple
    witness_fixture: str
    kind: str
    condition_path: tuple
    condition_fixture: str | None

    def to_json(self) -> dict:
        condition: dict = {"kind": self.kind, "path": list(self.condition_path)}
        if self.condition_fixture is not None:
            condition["expected_fixture"] = self.condition_fixture
        return {
            "schema_version": LIVE_READ_ASSERTION_SCHEMA,
            "success_witness": {
                "path": list(self.witness_path), "expected_fixture": self.witness_fixture,
            },
            "condition": condition,
        }


def _exact_keys(value: Any, allowed: frozenset) -> dict:
    if type(value) is not dict:
        raise _reject("field_type_invalid")
    if any(type(key) is not str or key not in allowed for key in value):
        raise _reject("unknown_field")
    if len(value) != len(allowed):
        raise _reject("missing_field")
    return value


def _valid_segment_text(segment: str) -> bool:
    if not segment or len(segment) > LIVE_READ_MAX_SEGMENT_CHARS:
        return False
    try:
        encoded = segment.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) > LIVE_READ_MAX_SEGMENT_BYTES:
        return False
    return not any(unicodedata.category(char) in {"Cc", "Cs"} for char in segment)


def _path(value: Any) -> tuple:
    if type(value) not in {list, tuple}:
        raise _reject("path_type_invalid")
    if not 1 <= len(value) <= LIVE_READ_MAX_PATH_SEGMENTS:
        raise _reject("path_length_invalid")
    segments = []
    for segment in value:
        if type(segment) is int:
            if not 0 <= segment <= LIVE_READ_MAX_INDEX:
                raise _reject("path_segment_invalid")
        elif type(segment) is str:
            if not _valid_segment_text(segment):
                raise _reject("path_segment_invalid")
            if segment in _LIVE_RESERVED_SEGMENTS:
                raise _reject("path_segment_reserved")
        else:
            raise _reject("path_segment_invalid")
        segments.append(segment)
    return tuple(segments)


def _fixture_ref(value: Any) -> str:
    if type(value) is not str or not _LIVE_FIXTURE_REF.fullmatch(value):
        raise _reject("fixture_reference_invalid")
    return value


def validate_live_read_assertion(value: Any) -> LiveReadAssertion:
    """Validate a plain-``dict`` definition with fixed field names; raise a closed code."""
    top = _exact_keys(value, _LIVE_TOP_KEYS)
    if top["schema_version"] != LIVE_READ_ASSERTION_SCHEMA or type(top["schema_version"]) is not str:
        raise _reject("schema_version_unsupported")
    witness = _exact_keys(top["success_witness"], _LIVE_WITNESS_KEYS)
    condition = top["condition"]
    if type(condition) is not dict:
        raise _reject("field_type_invalid")
    kind = condition.get("kind")
    if type(kind) is not str or kind not in LIVE_READ_CONDITION_KINDS:
        raise _reject("condition_kind_unsupported")
    _exact_keys(condition, _LIVE_CONDITION_KEYS[kind])
    assertion = LiveReadAssertion(
        witness_path=_path(witness["path"]),
        witness_fixture=_fixture_ref(witness["expected_fixture"]),
        kind=kind,
        condition_path=_path(condition["path"]),
        condition_fixture=(
            _fixture_ref(condition["expected_fixture"])
            if kind == "json_scalar_equals_fixture" else None
        ),
    )
    if len(canonical_live_read_assertion(assertion)) > LIVE_READ_MAX_DEFINITION_BYTES:
        raise _reject("definition_too_large")
    return assertion


def _unique_pairs(pairs: list) -> dict:
    result: dict = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = item
    return result


def _no_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def parse_live_read_assertion(raw: bytes) -> LiveReadAssertion:
    """Parse raw JSON bytes strictly (UTF-8, no duplicate keys, finite), then validate."""
    if type(raw) is not bytes:
        raise _reject("definition_malformed")
    if len(raw) > LIVE_READ_MAX_RAW_DEFINITION_BYTES:
        raise _reject("definition_too_large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _reject("definition_malformed") from None
    return validate_live_read_assertion(value)


def canonical_live_read_assertion(assertion: LiveReadAssertion) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (not ASCII-escaped): the digest input."""
    return json.dumps(assertion.to_json(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def live_read_assertion_digest(assertion: LiveReadAssertion) -> str:
    return "sha256:" + hashlib.sha256(canonical_live_read_assertion(assertion)).hexdigest()


# --- local expected values -----------------------------------------------------------------

_MISSING = object()


def _fixture_value(value: Any) -> Any:
    """A valid local scalar, as stored for comparison; ``_MISSING`` when invalid."""
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return _MISSING
        return value if len(encoded) <= LIVE_READ_MAX_FIXTURE_STRING_BYTES else _MISSING
    if type(value) is int:
        return Decimal(value) if abs(value) <= LIVE_READ_MAX_FIXTURE_INT else _MISSING
    if type(value) is float:
        # The shortest round-trip text is the JSON number the operator meant.
        return Decimal(repr(value)) if math.isfinite(value) else _MISSING
    return _MISSING


@dataclass(frozen=True)
class LiveReadExpectations:
    """A snapshot of the local expected scalars one assertion needs, bound by digest.

    Values never appear in ``repr``; ``available``/``reason`` are the only public state.
    """

    assertion_digest: str
    available: bool
    reason: str
    _witness: Any = field(default=None, repr=False, compare=False)
    _condition: Any = field(default=None, repr=False, compare=False)


def resolve_local_fixtures(assertion: LiveReadAssertion, fixtures: Any) -> LiveReadExpectations:
    """Snapshot the referenced local values from an exact ``dict`` of reference -> scalar.

    Missing or invalid values make the expectations unavailable (``inconclusive``), never
    false. Unreferenced entries are neither validated nor retained.
    """
    digest = live_read_assertion_digest(assertion)

    def unavailable(reason: str) -> LiveReadExpectations:
        return LiveReadExpectations(digest, False, reason)

    if type(fixtures) is not dict:
        return unavailable("fixtures_invalid")
    refs = [assertion.witness_fixture]
    if assertion.condition_fixture is not None:
        refs.append(assertion.condition_fixture)
    values = []
    for ref in refs:
        if ref not in fixtures:
            return unavailable("fixture_missing")
        value = _fixture_value(fixtures[ref])
        if value is _MISSING:
            return unavailable("fixture_invalid")
        values.append(value)
    return LiveReadExpectations(
        digest, True, "fixtures_resolved", values[0], values[1] if len(values) > 1 else None,
    )


# --- one response --------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveReadResponse:
    status: int
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class LiveReadObservation:
    """``state``: condition_true | condition_false | empty_denial | unknown."""

    state: str
    reason: str
    witness: bool | None
    condition: bool | None


def _unknown(reason: str, witness: bool | None = None) -> LiveReadObservation:
    return LiveReadObservation("unknown", reason, witness, None)


class _BodyRejected(Exception):
    pass


def _strict_load(text: str, *, exact_numbers: bool) -> Any:
    hooks: dict = {"object_pairs_hook": _unique_pairs, "parse_constant": _no_constant}
    if exact_numbers:
        hooks["parse_float"] = Decimal
    return json.loads(text, **hooks)


def _check_tree(value: Any) -> None:
    """Depth, node count, finite floats, surrogate-free strings and keys."""
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > LIVE_READ_MAX_BODY_NODES or depth > LIVE_READ_MAX_BODY_DEPTH:
            raise _BodyRejected
        if type(item) is float and not math.isfinite(item):
            raise _BodyRejected
        if type(item) is str:
            item.encode("utf-8")
        elif type(item) is dict:
            for key, child in item.items():
                key.encode("utf-8")
                stack.append((child, depth + 1))
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)


_ABSENT = object()


def _lookup(value: Any, path: tuple) -> tuple[str, Any]:
    """('present', v) | ('absent', None) | ('parent_missing'|'type_mismatch', None).

    Every container above the last segment must exist with the right type: a string
    segment reads only an object key, an int segment only a list index. Only the final
    segment may be absent (key missing / index out of range); a JSON ``null`` there is
    present.
    """
    current = value
    last = len(path) - 1
    for position, segment in enumerate(path):
        if type(segment) is str:
            if type(current) is not dict:
                return "type_mismatch", None
            child = current.get(segment, _ABSENT)
        else:
            if type(current) is not list:
                return "type_mismatch", None
            child = current[segment] if segment < len(current) else _ABSENT
        if child is _ABSENT:
            return ("absent" if position == last else "parent_missing"), None
        current = child
    return "present", current


def _scalar_equal(actual: Any, expected: Any) -> bool | None:
    """Strict JSON scalar equality; ``None`` for a container. No coercion between types.

    Numbers compare by exact decimal value of their JSON text (``1`` == ``1.0`` == ``1e0``;
    ``1.0000000000000000001`` != ``1``). A boolean is never a number.
    """
    if type(actual) in {dict, list}:
        return None
    if expected is None or type(expected) is bool or type(expected) is str:
        return type(actual) is type(expected) and actual == expected
    if type(actual) is int:
        actual = Decimal(actual)
    if type(actual) is not Decimal:
        return False
    return actual == expected


def observe_live_read(
    response: LiveReadResponse,
    *,
    method: str,
    assertion: LiveReadAssertion,
    expectations: LiveReadExpectations,
) -> LiveReadObservation:
    """Observe one complete response against one configured assertion. Pure; no I/O.

    Order: method (only exact ``GET``; ``HEAD`` is always unknown), bound and available
    local fixtures, status, size, empty body, strict JSON, object shape, the existing
    denial/ambiguous envelope recognizers (any status), 2xx, success witness, condition.
    """
    if method != "GET":
        return _unknown("method_not_observable")
    if expectations.assertion_digest != live_read_assertion_digest(assertion):
        return _unknown("fixture_unbound")
    if not expectations.available:
        return _unknown(expectations.reason)
    status, raw = response.status, response.body
    if type(status) is not int or not 100 <= status <= 599:
        return _unknown("status_invalid")
    if type(raw) is not bytes:
        return _unknown("body_invalid")
    if len(raw) > LIVE_READ_MAX_BODY_BYTES:
        return _unknown("body_too_large")
    if not raw:
        if status in _LIVE_EMPTY_DENIAL_STATUSES:
            return LiveReadObservation("empty_denial", "empty_denial", None, None)
        return _unknown("body_empty")
    try:
        text = raw.decode("utf-8")
        envelope_view = _strict_load(text, exact_numbers=False)
        _check_tree(envelope_view)
        data = _strict_load(text, exact_numbers=True)
    except (ValueError, UnicodeError, RecursionError, DecimalException, _BodyRejected):
        # A number with no exact decimal representation is malformed here, never compared.
        return _unknown("body_malformed")
    if type(data) is not dict:
        return _unknown("body_not_object")
    if is_denial_envelope(envelope_view):
        return _unknown("denial_envelope")
    if is_ambiguous_message(envelope_view):
        return _unknown("ambiguous_message")
    if not 200 <= status <= 299:
        return _unknown("status_not_success")
    found, witness_value = _lookup(data, assertion.witness_path)
    if found != "present":
        return _unknown("witness_path_unresolved", False)
    if _scalar_equal(witness_value, expectations._witness) is not True:
        return _unknown("witness_not_matched", False)
    found, value = _lookup(data, assertion.condition_path)
    if found == "parent_missing":
        return _unknown("path_parent_missing", True)
    if found == "type_mismatch":
        return _unknown("path_type_mismatch", True)
    if assertion.kind == "json_field_present":
        holds = found == "present"
    elif found == "absent":
        holds = False
    else:
        holds = _scalar_equal(value, expectations._condition)
        if holds is None:
            return _unknown("condition_value_not_scalar", True)
    if holds:
        return LiveReadObservation("condition_true", "configured_condition_true", True, True)
    return LiveReadObservation("condition_false", "configured_condition_false", True, False)


# --- a pair --------------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveReadPairVerdict:
    """``outcome``: observed | blocked | inconclusive, with one closed reason code."""

    outcome: str
    reason: str
    positive_control: bool
    restricted_condition: bool | None


def _pair_inconclusive(reason: str, control: bool = False) -> LiveReadPairVerdict:
    return LiveReadPairVerdict("inconclusive", reason, control, None)


def evaluate_live_read_pair(
    *,
    role_policy: str,
    method: str,
    assertion: LiveReadAssertion,
    expectations: LiveReadExpectations,
    control: LiveReadResponse,
    restricted: LiveReadResponse,
) -> LiveReadPairVerdict:
    """Evaluate one already-captured control/restricted response pair. Sends no traffic.

    ``control`` is the authenticated (or higher-plan) read; ``restricted`` the anonymous
    (or lower-plan) read of the same route. The positive control requires status exactly
    200, the success witness and the configured condition true. Then the restricted
    response decides: condition true -> ``observed``; condition false with a valid success
    body, or an empty 401/402/403/404 -> ``blocked``; anything unknown -> ``inconclusive``.
    ``observed`` means only that the configured condition held for the restricted role; it
    is not a generic protected-content claim. Status alone never yields ``observed``.
    """
    if type(role_policy) is not str or role_policy not in LIVE_READ_ROLE_POLICIES:
        return _pair_inconclusive("role_policy_unsupported")
    if method != "GET":
        return _pair_inconclusive("method_not_observable")
    if expectations.assertion_digest != live_read_assertion_digest(assertion):
        return _pair_inconclusive("fixture_unbound")
    if not expectations.available:
        return _pair_inconclusive(expectations.reason)
    control_seen = observe_live_read(control, method=method, assertion=assertion,
                                     expectations=expectations)
    if control.status != 200 or type(control.status) is not int:
        return _pair_inconclusive("positive_control_status")
    if control_seen.state == "condition_false":
        return _pair_inconclusive("positive_control_condition_false")
    if control_seen.state != "condition_true":
        return _pair_inconclusive("positive_control_unknown")
    seen = observe_live_read(restricted, method=method, assertion=assertion,
                             expectations=expectations)
    if seen.state == "condition_true":
        return LiveReadPairVerdict("observed", "restricted_condition_true", True, True)
    if seen.state == "condition_false":
        return LiveReadPairVerdict("blocked", "restricted_condition_false", True, False)
    if seen.state == "empty_denial":
        return LiveReadPairVerdict("blocked", "restricted_empty_denial", True, None)
    return _pair_inconclusive(f"restricted_{seen.reason}", True)
