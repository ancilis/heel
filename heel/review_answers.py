"""Bounded, declarative enrichment of OpenAPI operation control metadata."""
from __future__ import annotations

import copy
import json
from typing import Any

from .openapi_model import operation_surface_id


MAX_REVIEW_ANSWERS_BYTES = 64 * 1024
MAX_REVIEW_ANSWER_COUNT = 64
MAX_REVIEW_ANSWER_DEPTH = 8

_ANSWER_FIELDS = frozenset({"surface", "field", "value"})
_SUPPORTED_FIELDS = frozenset({
    "tenant_filter", "entitlement_check", "rate_limit", "product_rule",
})
_ANSWER_VALUES = frozenset({"enforced", "not_enforced", "unknown"})
_HTTP_METHODS = frozenset({
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
})
_PATH_ITEM_REF_PREFIX = "#/components/pathItems/"
_MISSING_DECLARATIONS = frozenset({
    "", "missing", "none", "false", "disabled", "off", "no", "weak",
    "client", "client_only",
})
_ENTITLEMENT_CONTROL = "server_side_entitlement_check"
_RATE_CONTROL = "server_side_rate_limit"


class ReviewAnswerError(ValueError):
    """A submitted answer cannot be validated or safely applied."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewAnswerError("answers contain a duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ReviewAnswerError("answers contain a non-JSON numeric constant")


def _nesting_within_limit(payload: bytes) -> bool:
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
            if depth > MAX_REVIEW_ANSWER_DEPTH:
                return False
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return True


def parse_review_answers(source: str) -> list[dict[str, str]]:
    """Parse and detach a bounded JSON answer array with duplicate-key rejection."""
    if type(source) is not str:
        raise ReviewAnswerError("answers must be JSON text")
    try:
        payload = source.encode("utf-8")
    except UnicodeError as exc:
        raise ReviewAnswerError("answers contain invalid Unicode") from exc
    if len(payload) > MAX_REVIEW_ANSWERS_BYTES:
        raise ReviewAnswerError("answers exceed the maximum encoded size")
    if not _nesting_within_limit(payload):
        raise ReviewAnswerError("answers exceed the maximum nesting depth")
    try:
        parsed = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError, ReviewAnswerError) as exc:
        raise ReviewAnswerError("answers must be a valid JSON array") from exc
    return _normalize_answers(parsed)


def _normalize_answers(answers: Any) -> list[dict[str, str]]:
    if type(answers) is not list:
        raise ReviewAnswerError("answers must be a JSON array")
    if len(answers) > MAX_REVIEW_ANSWER_COUNT:
        raise ReviewAnswerError("too many review answers")

    by_question: dict[tuple[str, str], dict[str, str]] = {}
    for item in answers:
        if type(item) is not dict or frozenset(item) != _ANSWER_FIELDS:
            raise ReviewAnswerError("each answer must contain exactly the supported fields")
        if any(type(item[field]) is not str for field in _ANSWER_FIELDS):
            raise ReviewAnswerError("answer fields must be strings")
        surface = item["surface"]
        field = item["field"]
        value = item["value"]
        if not surface or field not in _SUPPORTED_FIELDS or value not in _ANSWER_VALUES:
            raise ReviewAnswerError("answer contains an unsupported field or value")
        try:
            surface.encode("utf-8")
            field.encode("utf-8")
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ReviewAnswerError("answer contains invalid Unicode") from exc
        normalized = {"surface": surface, "field": field, "value": value}
        key = (surface, field)
        previous = by_question.get(key)
        if previous is not None and previous["value"] != value:
            raise ReviewAnswerError("answers contain a contradiction")
        by_question[key] = normalized
    return [by_question[key] for key in sorted(by_question)]


def apply_review_answers(
    spec: dict[str, Any], answers: list[dict[str, str]],
    questions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Apply supported enforced answers to a detached OpenAPI document copy."""
    if type(spec) is not dict or type(questions) is not list:
        raise ReviewAnswerError("answers require an OpenAPI object and question array")
    normalized = _normalize_answers(answers)
    enriched = copy.deepcopy(spec)
    targets = _operation_targets(enriched)

    question_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for question in questions:
        if type(question) is not dict:
            raise ReviewAnswerError("review questions are malformed")
        surface = question.get("surface")
        field = question.get("field")
        prompt = question.get("prompt")
        if not all(type(value) is str and value for value in (surface, field, prompt)):
            raise ReviewAnswerError("review questions are malformed")
        question_index.setdefault((surface, field), []).append(question)

    for answer in normalized:
        surface = answer["surface"]
        field = answer["field"]
        matches = question_index.get((surface, field), [])
        if len(matches) != 1:
            raise ReviewAnswerError("answer does not identify one supported question")
        if field == "product_rule":
            raise ReviewAnswerError("product-rule answers cannot be applied safely")
        if surface == "product":
            raise ReviewAnswerError("product-level answers cannot be applied safely")
        operation_matches = targets.get(surface, [])
        if len(operation_matches) != 1:
            raise ReviewAnswerError("answer does not identify one existing operation")
        operation = operation_matches[0]
        declarations = operation.setdefault("x-heel-customer-declarations", {})
        if type(declarations) is not dict:
            raise ReviewAnswerError("customer declarations must be an object")
        declarations[field] = {"value": answer["value"], "source": "customer answer",
                               "evidence_state": "unknown" if answer["value"] == "unknown" else "customer_declared"}
        if answer["value"] != "enforced":
            continue

        if field == "tenant_filter":
            _declare_tenant_scope(operation)
        elif field == "entitlement_check":
            _declare_controls(operation, {_ENTITLEMENT_CONTROL})
        elif field == "rate_limit":
            _declare_controls(operation, {_RATE_CONTROL})
        else:  # Defensive in case the supported set and dispatch ever diverge.
            raise ReviewAnswerError("answer field cannot be enriched safely")
    return enriched


def _operation_targets(spec: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    paths = spec.get("paths")
    if type(paths) is not dict:
        raise ReviewAnswerError("OpenAPI paths are unavailable")
    targets: dict[str, list[dict[str, Any]]] = {}
    for route, path_item in paths.items():
        if type(route) is not str or not route.startswith("/") or type(path_item) is not dict:
            continue
        effective = _effective_operations(spec, path_item, ())
        for method, operation in effective.items():
            surface = operation_surface_id(method.upper(), route, operation)
            values = targets.setdefault(surface, [])
            if not any(candidate is operation for candidate in values):
                values.append(operation)
    return targets


def _effective_operations(
    spec: dict[str, Any], path_item: dict[str, Any], ref_chain: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    operations: dict[str, dict[str, Any]] = {}
    if "$ref" in path_item:
        reference = path_item["$ref"]
        if type(reference) is not str or not reference.startswith(_PATH_ITEM_REF_PREFIX):
            raise ReviewAnswerError("operation target contains an unsupported reference")
        if reference in ref_chain:
            raise ReviewAnswerError("operation target contains a cyclic reference")
        name = reference[len(_PATH_ITEM_REF_PREFIX):]
        if not name or "/" in name:
            raise ReviewAnswerError("operation target reference is invalid")
        name = _unescape_pointer_token(name)
        components = spec.get("components")
        path_items = components.get("pathItems") if type(components) is dict else None
        target = path_items.get(name) if type(path_items) is dict else None
        if type(target) is not dict:
            raise ReviewAnswerError("operation target reference is unavailable")
        operations.update(_effective_operations(spec, target, (*ref_chain, reference)))

    for key, value in path_item.items():
        method = str(key).lower()
        if method in _HTTP_METHODS:
            if type(value) is not dict:
                raise ReviewAnswerError("operation target is malformed")
            operations[method] = value
    return operations


def _unescape_pointer_token(token: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(token):
        character = token[index]
        if character != "~":
            output.append(character)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise ReviewAnswerError("operation target reference is invalid")
        output.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(output)


def _declare_tenant_scope(operation: dict[str, Any]) -> None:
    current = operation.get("x-heel-tenant-scope")
    if current is None or (
        type(current) is str and current.strip().lower() in _MISSING_DECLARATIONS
    ):
        operation["x-heel-tenant-scope"] = "tenant"
        return
    raise ReviewAnswerError("tenant declaration cannot be changed safely")


def _declare_controls(operation: dict[str, Any], additions: set[str]) -> None:
    current = operation.get("x-heel-control")
    if current is None:
        operation["x-heel-control"] = sorted(additions)
        return
    if type(current) is str:
        operation["x-heel-control"] = sorted({current, *additions})
        return
    if type(current) is list and all(type(value) is str for value in current):
        operation["x-heel-control"] = sorted({*current, *additions})
        return
    if type(current) is dict and all(
        type(key) is str and type(value) is bool for key, value in current.items()
    ):
        enriched = dict(current)
        enriched.update({control: True for control in additions})
        operation["x-heel-control"] = {
            key: enriched[key] for key in sorted(enriched)
        }
        return
    raise ReviewAnswerError("control declaration cannot be changed safely")
