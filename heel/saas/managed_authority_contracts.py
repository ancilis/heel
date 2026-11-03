"""Inert closed contracts for managed CP admission of every request attempt (C4 P01).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Pure standard-library codecs and validators for the corrected managed wire objects of design Q
(``46cefba0`` section 6) with the exact-admission fields it retains from EA (``c54f872a`` section 4),
the S (``2a71221`` section 14.2) ceremony payloads with their phase nullability, original-expiry
and predecessor rules, and the observational status object (``ed901650`` section 7, EA section 8).

This module performs no I/O. It opens no listener or database, sends no target request, reads
no key or clock and enables no admission. Nothing imports it into a serving path in P01.

A value accepted here is only structurally well formed. Validation does NOT prove a signature,
ownership, the existence or freshness of any CP record, CP admission, a quota/capacity reservation,
runtime capacity, kernel installation or transport safety; those remain the CP transaction, root,
executor and real-environment gates. Errors carry a fixed code and, where useful, a field name
from the closed schema below; they never echo a received value or an unrecognised key.

Domain classification is server-owned: a managed codec is selected only by the exact fixed host
route (or the fixed local message name), never by a caller-provided ``managed`` flag. Existing
public, connector and H3 codecs are unchanged and are not consulted or widened here.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable, Mapping

__all__ = (
    "CAPS", "MESSAGE_SCHEMAS", "ManagedContractError", "ROUTES", "RouteContract", "ATTEMPT_RECORD_COLUMNS",
    "action_digest", "canonical", "credential_binding_digest", "decode", "decode_route_request",
    "decode_route_response", "encode", "operation_digest", "request_digest", "request_identity_digest",
    "route_contract", "route_digest", "route_template_digest", "validate", "validate_status_request",
    "verify_attempt_binding", "verify_attempt_notification", "verify_attempt_response",
    "verify_window_binding", "verify_window_notification", "verify_window_response",
)


class ManagedContractError(ValueError):
    """Fail-closed refusal. ``code`` is fixed; ``field`` is a closed-schema name or ``None``."""

    def __init__(self, code: str, field: str | None = None):
        super().__init__(code if field is None else f"{code}:{field}")
        self.code = code
        self.field = field


def _fail(code: str, field: str | None = None):
    raise ManagedContractError(code, field)


# ---------------------------------------------------------------------------------------------
# Scalar grammars (Q section 6; EA section 4 / host_authority.py v1 identity grammar; S 14.2).

MAX_MS = 2 ** 53 - 1
MAX_NS = 2 ** 63 - 1
MAX_SEQUENCE = 2 ** 20
MAX_GENERATION = 2147483647
MAX_REVISION = 2147483647
MAX_U32 = 2 ** 32 - 1
MAX_U64 = 2 ** 64 - 1
ACTION_ORDINAL_MAX = 19

_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LONG_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")  # existing runner/key/grant grammar on the host wire
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
# The stricter H host slot grammar. S slot ids outside it (underscores, trailing hyphen) are refused
# for managed enrollment, never normalised.
_SLOT = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_SURROGATE = re.compile("[\ud800-\udfff]")  # code points with no UTF-8 encoding
_PATTERNS = {
    "hex32": _HEX32, "hex64": _HEX64, "long_id": _LONG_ID, "slot": _SLOT, "hostname": _HOSTNAME,
    "boot": re.compile(r"[a-z0-9-]{8,64}"),
    "workspace": re.compile(r"ws_[0-9a-f]{16}"),
    "project": re.compile(r"prj_[0-9a-f]{32}"),
    "environment": re.compile(r"env_[0-9a-f]{32}"),
    "binding": re.compile(r"rcb_[0-9a-f]{32}"),
    "run": re.compile(r"crun_[0-9a-f]{32}"),
    "managed": re.compile(r"mex_[0-9a-f]{32}"),
    "pairing": re.compile(r"pending_[0-9a-f]{32}"),
    "epoch": re.compile(r"epoch_[0-9a-f]{32}"),
    "s_runner": re.compile(r"runr_[0-9a-f]{32}"),
    "s_key": re.compile(r"k_[0-9a-f]{16}"),
}

SEMANTIC_ROLES = ("anonymous", "authenticated", "object_owner", "non_owner", "lower_privilege",
                  "higher_privilege", "lower_plan", "higher_plan")
METHODS = ("GET", "HEAD")
FAILURE_CODES = ("none", "connect_error", "timeout")
# Existing H v1 REASONS spelled exactly, plus the four managed reasons of EA section 4.
REASONS = ("none", "workspace_unknown", "project_unknown", "no_active_run", "multiple_active_runs", "run_not_active",
           "stop_requested", "grant_not_claimed", "grant_expired", "invalid_grant", "proof_expired", "proof_revoked",
           "verification_digest_replaced", "runner_revoked", "key_revoked", "binding_inactive", "binding_expired",
           "kill_switch_active", "kill_switch_generation_changed", "tuple_mismatch", "malformed_request", "cp_draining",
           "replayed_sequence", "clock_gap", "managed_terminal", "restore_mismatch", "resource_exhausted",
           "operation_mismatch")
MANAGED_STATES = ("offered", "pending", "active", "revoked", "aborted", "expired")
NONTERMINAL_STATES = ("offered", "pending", "active")
ABORT_REASONS = ("service_failed", "activation_deadline", "activation_rejected", "local_identity_unavailable",
                 "local_state_invalid", "delivery_failed")
RETIRED_ACK_STATES = ("retired", "cleanup_pending", "cleanup_failed", "capacity_unavailable")  # never active
DELIVERY_STATUSES = ("idle", "pending", "delivered", "failed")
HOST_ACK_STATES = ("active", "retired", "cleanup_pending", "cleanup_failed", "capacity_unavailable")
RECOVERY_CODES = ("cleanup_pending", "cleanup_failed", "capacity_unavailable", "waiting_for_pairing_expiry",
                  "delivery_failed")
CANCELLATION_PHASES = ("authority_revoked", "cleanup_pending", "completed")


@dataclasses.dataclass(frozen=True)
class _Field:
    check: Callable[[Any], bool]
    nullable: bool = False


def _str(pattern: str, nullable: bool = False) -> _Field:
    regex = _PATTERNS[pattern]
    return _Field(lambda v: isinstance(v, str) and regex.fullmatch(v) is not None, nullable)


def _int(low: int, high: int, nullable: bool = False) -> _Field:
    return _Field(lambda v: type(v) is int and low <= v <= high, nullable)


def _enum(values: tuple[str, ...], nullable: bool = False) -> _Field:
    return _Field(lambda v: isinstance(v, str) and v in values, nullable)


def _const(value: str) -> _Field:
    return _Field(lambda v: isinstance(v, str) and v == value)


def _ipv4(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]{7,15}", value):
        return False
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def _b64_32(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == value


_HEX32F, _HEX64F = _str("hex32"), _str("hex64")
_MS, _NS = _int(0, MAX_MS), _int(0, MAX_NS)
_S_MS = _int(1, MAX_MS)  # S section 14.2 ms are 1..2^53-1
_GEN = _int(0, MAX_GENERATION)

# ---------------------------------------------------------------------------------------------
# Exact schema versions, key sets and caps.

WINDOW_REQUEST_SCHEMA = "heel.managed-operation-request.v3"
ATTEMPT_REQUEST_SCHEMA = "heel.managed-attempt-request.v1"
WINDOW_RESPONSE_SCHEMA = "heel.managed-operation-response.v3"
ATTEMPT_RESPONSE_SCHEMA = "heel.managed-attempt-response.v1"
WINDOW_DESCRIPTOR_SCHEMA = "heel.managed-prepared-operation.v2"
ATTEMPT_DESCRIPTOR_SCHEMA = "heel.managed-prepared-attempt.v1"
WINDOW_NOTIFICATION_SCHEMA = "heel.managed-window-complete.v2"
ATTEMPT_NOTIFICATION_SCHEMA = "heel.managed-attempt-complete.v1"
CEREMONY_REQUEST_SCHEMA = "heel.managed-ceremony-request.v3"
CEREMONY_RESPONSE_SCHEMA = "heel.managed-ceremony-response.v3"
OBSERVATION_SCHEMA = "heel.managed-executor-observation.v1"
OBSERVATION_KIND = "historical_not_authorization"
KEY_OFFER_SCHEMA = "heel.managed-key-offer.v1"
PENDING_SCHEMA = "heel.managed-pending.v1"
REVOKED_SCHEMA = "heel.managed-revoked.v1"
ABORTED_SCHEMA = "heel.managed-aborted.v1"
HOST_ACK_SCHEMA = "heel.managed-host-ack.v1"
IDENTITY_OBSERVATION_SCHEMA = "heel.managed-identity-observation.v1"

_WINDOW_REQUEST = {
    "schema_version": _const(WINDOW_REQUEST_SCHEMA), "kind": _const("execute_window"),
    "restore_epoch": _HEX64F, "managed_executor_id": _str("managed"), "pairing_epoch": _str("epoch"),
    "pairing_id": _str("pairing"), "host_boot_epoch": _str("boot"), "slot_id": _str("slot"),
    "generation_id": _HEX32F, "bootstrap_fence": _HEX32F, "workspace_id": _str("workspace"),
    "project_id": _str("project"), "environment_id": _str("environment"),
    "verification_record_digest": _HEX64F, "runner_id": _str("long_id"), "runner_key_id": _str("long_id"),
    "binding_id": _str("binding"), "binding_digest": _HEX64F, "run_id": _str("run"),
    "grant_id": _str("long_id"), "grant_digest": _HEX64F, "kill_switch_generation": _MS,
    "sequence": _int(1, MAX_SEQUENCE), "request_nonce": _HEX32F, "monotonic_ms": _MS,
    "operation_digest": _HEX64F,
}
_ATTEMPT_ONLY = {
    "manifest_digest": _HEX64F, "window_operation_digest": _HEX64F,
    "action_ordinal": _int(0, ACTION_ORDINAL_MAX), "method": _enum(METHODS),
    "route_template_digest": _HEX64F, "route_digest": _HEX64F, "semantic_role": _enum(SEMANTIC_ROLES),
    "attempt": _int(1, 2), "previous_failure_code": _enum(FAILURE_CODES), "attempt_deadline_ns": _NS,
}
_ATTEMPT_REQUEST = {**_WINDOW_REQUEST, **_ATTEMPT_ONLY,
                    "schema_version": _const(ATTEMPT_REQUEST_SCHEMA), "kind": _const("execute_attempt")}

_RESPONSE_COMMON = {
    "decision": _enum(("admitted", "refused")), "reason": _enum(REASONS), "request_digest": _HEX64F,
    "operation_digest": _HEX64F, "sequence": _int(1, MAX_SEQUENCE), "authority_revision": _int(0, MAX_REVISION),
    "server_time_ms": _MS, "kill_switch_generation": _MS, "bootstrap_fence": _HEX32F,
}
# Exactly the H v1 active fields, with the tighter 2^53-1 integer ceiling.
_RESPONSE_ACTIVE = {
    "workspace_id": _str("workspace"), "project_id": _str("project"), "environment_id": _str("environment"),
    "verification_record_digest": _HEX64F, "runner_id": _str("long_id"), "runner_key_id": _str("long_id"),
    "public_key_digest": _HEX64F, "binding_id": _str("binding"), "binding_digest": _HEX64F,
    "run_id": _str("run"), "run_status": _enum(("claimed", "running")), "stop_reason": _const("none"),
    "grant_id": _str("long_id"), "grant_digest": _HEX64F, "egress_hostname": _str("hostname"),
    "proof_expires_at_ms": _MS, "binding_expires_at_ms": _MS, "grant_expires_at_ms": _MS,
    "egress_port": _int(443, 443),
}
# INTERPRETATION (recorded for review): the attempt identity echoes bind a refusal to its exact Q and
# appear in both decisions; the attempt deadline is authority-bearing and appears only when admitted.
_ATTEMPT_RESPONSE_COMMON = {"attempt_digest": _HEX64F, "window_operation_digest": _HEX64F}
_ATTEMPT_RESPONSE_ACTIVE = {"attempt_deadline_ns": _NS}

_WINDOW_DESCRIPTOR = {
    "schema_version": _const(WINDOW_DESCRIPTOR_SCHEMA), "request_identity_digest": _HEX64F,
    "handle_nonce": _HEX32F, "handle_mark": _int(1, MAX_U32), "namespace_dev": _int(0, MAX_U64),
    "namespace_ino": _int(0, MAX_U64), "process_instance": _HEX32F, "src": _Field(_ipv4), "dst": _Field(_ipv4),
    "prepared_ns": _NS, "prepare_return_ns": _NS, "request_start_ns": _NS, "tick_ns": _int(1, MAX_NS),
    "lease_ms": _int(3000, 3000), "exchange_deadline_ns": _NS, "scope_digest": _HEX64F,
    "bootstrap_fence": _HEX32F,
}
_ATTEMPT_DESCRIPTOR = {
    "schema_version": _const(ATTEMPT_DESCRIPTOR_SCHEMA), "request_identity_digest": _HEX64F,
    "window_operation_digest": _HEX64F, "bootstrap_fence": _HEX32F, "process_instance": _HEX32F,
    "manifest_digest": _HEX64F, "action_digest": _HEX64F, "route_digest": _HEX64F,
    "credential_binding_digest": _HEX64F, "action_ordinal": _int(0, ACTION_ORDINAL_MAX),
    "method": _enum(METHODS), "semantic_role": _enum(SEMANTIC_ROLES), "attempt": _int(1, 2),
    "attempt_deadline_ns": _NS, "request_start_ns": _NS,
}
_WINDOW_NOTIFICATION = {
    "schema_version": _const(WINDOW_NOTIFICATION_SCHEMA), "operation_digest": _HEX64F, "request_digest": _HEX64F,
    "generation_id": _HEX32F, "run_id": _str("run"), "sequence": _int(1, MAX_SEQUENCE), "deadline_ns": _NS,
    "bootstrap_fence": _HEX32F,
}
_ATTEMPT_NOTIFICATION = {
    "schema_version": _const(ATTEMPT_NOTIFICATION_SCHEMA), "request_digest": _HEX64F, "attempt_digest": _HEX64F,
    "window_operation_digest": _HEX64F, "bootstrap_fence": _HEX32F, "generation_id": _HEX32F,
    "run_id": _str("run"), "sequence": _int(1, MAX_SEQUENCE), "deadline_ns": _NS,
}
ATTEMPT_RECORD_COLUMNS = (
    "restore_epoch", "tuple_digest", "run_id", "generation_id", "ordinal", "method", "semantic_role", "attempt",
    "manifest_digest", "route_template_digest", "route_digest", "window_operation_digest", "operation_digest",
    "request_digest", "bootstrap_fence", "exchange_sequence", "authority_revision", "admitted_at_ms",
    "attempt_deadline_ns", "previous_failure_code",
)
_ATTEMPT_RECORD = {
    "restore_epoch": _HEX64F, "tuple_digest": _HEX64F, "run_id": _str("run"), "generation_id": _HEX32F,
    "ordinal": _int(0, ACTION_ORDINAL_MAX), "method": _enum(METHODS), "semantic_role": _enum(SEMANTIC_ROLES),
    "attempt": _int(1, 2), "manifest_digest": _HEX64F, "route_template_digest": _HEX64F, "route_digest": _HEX64F,
    "window_operation_digest": _HEX64F, "operation_digest": _HEX64F, "request_digest": _HEX64F,
    "bootstrap_fence": _HEX32F, "exchange_sequence": _int(1, MAX_SEQUENCE),
    "authority_revision": _int(0, MAX_REVISION), "admitted_at_ms": _MS, "attempt_deadline_ns": _NS,
    "previous_failure_code": _enum(FAILURE_CODES),
}
assert tuple(_ATTEMPT_RECORD) == ATTEMPT_RECORD_COLUMNS

# S section 14.2 ceremony payloads. T = {slot_id, epoch_id, managed_executor_id, workspace_id, pairing_id}.
_T = {"slot_id": _str("slot"), "epoch_id": _str("epoch"), "managed_executor_id": _str("managed"),
      "workspace_id": _str("workspace"), "pairing_id": _str("pairing", nullable=True)}
_CP_GENERATIONS = {"retry_generation": _GEN, "cleanup_generation": _GEN,
                   "previous_ack_generation": _int(0, MAX_GENERATION, nullable=True),
                   "original_pairing_expires_at_ms": _int(1, MAX_MS, nullable=True)}
_KEY_OFFER = {
    "schema_version": _const(KEY_OFFER_SCHEMA), "slot_id": _str("slot"), "epoch_id": _str("epoch"),
    "previous_managed_executor_id": _str("managed", nullable=True),
    "previous_epoch_id": _str("epoch", nullable=True),
    "previous_terminal_pairing_id": _str("pairing", nullable=True),
    "public_key_b64": _Field(_b64_32), "fingerprint": _HEX64F, "runner_key_id": _str("s_key"),
    "offered_at_ms": _S_MS,
}
_PENDING = {**_T, **_CP_GENERATIONS, "schema_version": _const(PENDING_SCHEMA), "runner_id": _str("s_runner"),
            "runner_key_id": _str("s_key"), "fingerprint": _HEX64F, "pairing_exchange_digest": _HEX64F,
            "activation_challenge": _Field(_b64_32), "challenge_expires_at_ms": _S_MS}
_TERMINAL_COMMON = {**_T, **_CP_GENERATIONS, "runner_id": _str("s_runner", nullable=True),
                    "runner_key_id": _str("s_key"), "terminal_at_ms": _S_MS}
_REVOKED = {**_TERMINAL_COMMON, "schema_version": _const(REVOKED_SCHEMA), "reason_code": _const("human_revocation")}
_ABORTED = {**_TERMINAL_COMMON, "schema_version": _const(ABORTED_SCHEMA), "reason_code": _enum(ABORT_REASONS)}
_RETIRED_ACK = {**_T, "schema_version": _const(HOST_ACK_SCHEMA), "state": _enum(RETIRED_ACK_STATES),
                "updated_at_ms": _S_MS, "retry_generation": _GEN, "cleanup_generation": _GEN}
_IDENTITY = {"schema_version": _const(IDENTITY_OBSERVATION_SCHEMA), "workspace_id": _str("workspace"),
             "pairing_id": _str("pairing"), "runner_id": _str("s_runner"), "runner_key_id": _str("s_key"),
             "public_key_digest": _HEX64F, "observed_at_ms": _S_MS}
_CEREMONY_REQUEST = {
    "schema_version": _const(CEREMONY_REQUEST_SCHEMA), "restore_epoch": _HEX64F, "slot_id": _str("slot"),
    "managed_executor_id": _str("managed", nullable=True), "pairing_epoch": _str("epoch"),
    "delivery_generation": _GEN, "kind": _enum(("poll", "public_key", "retired")),
    "payload": _Field(lambda v: isinstance(v, dict)), "bootstrap_fence": _HEX32F,
}
_CEREMONY_RESPONSE = {
    "schema_version": _const(CEREMONY_RESPONSE_SCHEMA), "restore_epoch": _HEX64F,
    "managed_executor_id": _str("managed", nullable=True), "pairing_epoch": _str("epoch"),
    "delivery_generation": _GEN, "kind": _enum(("none", "challenge", "terminal", "identity_observed")),
    "payload": _Field(lambda v: isinstance(v, dict)), "bootstrap_fence": _HEX32F,
}
_OBSERVATION = {
    "schema_version": _const(OBSERVATION_SCHEMA), "managed_executor_id": _str("managed"),
    "observation_kind": _const(OBSERVATION_KIND), "authority_revision": _int(0, MAX_REVISION),
    "observed_at_ms": _S_MS, "observed_state": _enum(MANAGED_STATES),
    "pairing_id": _str("pairing", nullable=True), "runner_id": _str("s_runner", nullable=True),
    "runner_key_id": _str("s_key", nullable=True), "delivery_status": _enum(DELIVERY_STATUSES),
    "host_ack_state": _enum(HOST_ACK_STATES, nullable=True), "recovery_code": _enum(RECOVERY_CODES, nullable=True),
    "retry_after_ms": _int(0, MAX_MS, nullable=True),
    "original_pairing_expires_at_ms": _int(1, MAX_MS, nullable=True),
    "cancellation_phase": _enum(CANCELLATION_PHASES, nullable=True),
}

# Route-specific receive caps (Q section 6). Header 8192, one request/connection, backlog 64 and the
# 5 s listener timeout are carried as constants only; they grant no execution time.
CAPS = {
    "window_request": 2048, "attempt_request": 2560, "attempt_forward": 2560,
    "window_response": 4096, "attempt_response": 4096,
    "window_descriptor": 2048, "attempt_descriptor": 2048,
    "window_notification": 1024, "attempt_notification": 1024,
    "ceremony_request": 4096, "ceremony_response": 4096, "observation": 4096,
    "attempt_record": 2048,
}
MAX_HEAD_BYTES = 8192
BACKLOG = 64
CONNECTION_TIMEOUT_SECONDS = 5.0

MESSAGE_SCHEMAS: Mapping[str, str] = {
    "window_request": WINDOW_REQUEST_SCHEMA, "attempt_request": ATTEMPT_REQUEST_SCHEMA,
    "attempt_forward": ATTEMPT_REQUEST_SCHEMA, "window_response": WINDOW_RESPONSE_SCHEMA,
    "attempt_response": ATTEMPT_RESPONSE_SCHEMA, "window_descriptor": WINDOW_DESCRIPTOR_SCHEMA,
    "attempt_descriptor": ATTEMPT_DESCRIPTOR_SCHEMA, "window_notification": WINDOW_NOTIFICATION_SCHEMA,
    "attempt_notification": ATTEMPT_NOTIFICATION_SCHEMA, "ceremony_request": CEREMONY_REQUEST_SCHEMA,
    "ceremony_response": CEREMONY_RESPONSE_SCHEMA, "observation": OBSERVATION_SCHEMA,
}


@dataclasses.dataclass(frozen=True)
class RouteContract:
    route: str
    request: str
    response: str


# The fixed managed host routes on the same peer-authenticated Unix owner. Peer authentication is not
# run authorization. Old v1 snapshot and failed v2 managed routes are deliberately absent.
ROUTES: Mapping[str, RouteContract] = {
    "/host/v3/managed-operation": RouteContract("/host/v3/managed-operation", "window_request", "window_response"),
    "/host/v1/managed-attempt": RouteContract("/host/v1/managed-attempt", "attempt_request", "attempt_response"),
    "/host/v3/managed-ceremony": RouteContract("/host/v3/managed-ceremony", "ceremony_request", "ceremony_response"),
}


def route_contract(route: str) -> RouteContract:
    contract = ROUTES.get(route) if isinstance(route, str) else None
    if contract is None:
        _fail("unknown_route")
    return contract


# ---------------------------------------------------------------------------------------------
# Canonical JSON.

def _strict(value: Any, depth: int = 0) -> None:
    if depth > 8:
        _fail("too_deep")
    if value is None or isinstance(value, (bool, str)):
        return
    if type(value) is int:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("non_string_key")
            _strict(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _strict(item, depth + 1)
        return
    _fail("unsupported_type")  # floats, bytes, int subclasses other than bool, tuples, ...


def canonical(document: Any) -> bytes:
    """Sorted-key compact ASCII JSON; floats and non-JSON types are refused, never coerced."""
    _strict(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _sha(document: Any) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _no_float(_text: str):
    _fail("float_forbidden")


def _no_constant(_text: str):
    _fail("float_forbidden")


def _parse(body: Any, cap: int) -> Any:
    if not isinstance(body, bytes):
        _fail("not_bytes")
    if len(body) > cap:  # refused before any parse; never truncated
        _fail("oversize")
    if not body:
        _fail("empty")
    if not body.isascii():
        _fail("non_ascii")
    # Refusals are raised outside the ``except`` blocks so no parser exception (whose ``doc`` holds the
    # received text) is chained as cause or context.
    document, refusal = None, None
    try:
        document = json.loads(body.decode("ascii"), object_pairs_hook=_pairs, parse_float=_no_float,
                              parse_constant=_no_constant)
    except ManagedContractError as error:
        refusal = error.code
    except (ValueError, RecursionError):
        refusal = "malformed_json"
    if refusal is not None:
        _fail(refusal)
    if canonical(document) != body:
        _fail("noncanonical")
    return document


# ---------------------------------------------------------------------------------------------
# Object validation.

def _check_fields(document: Any, spec: Mapping[str, _Field], nullable_ok: bool = True) -> dict:
    if not isinstance(document, dict):
        _fail("not_object")
    keys = set(document)
    if keys - set(spec):
        _fail("extra_key")
    for name in spec:
        if name not in document:
            _fail("missing_key", name)
    for name, field in spec.items():
        value = document[name]
        if value is None:
            if not (field.nullable and nullable_ok):
                _fail("null_forbidden", name)
            continue
        if not field.check(value):
            _fail("invalid_field", name)
    return document


def _window_request(document: Any) -> dict:
    return _check_fields(document, _WINDOW_REQUEST)


def _attempt_request(document: Any) -> dict:
    _check_fields(document, _ATTEMPT_REQUEST)
    attempt, failure = document["attempt"], document["previous_failure_code"]
    if (attempt == 1) != (failure == "none"):  # attempt 1 is none; attempt 2 is connect_error|timeout
        _fail("attempt_failure_mismatch", "previous_failure_code")
    return document


def _response(document: Any, common: Mapping[str, _Field], active: Mapping[str, _Field], schema: str) -> dict:
    if not isinstance(document, dict):
        _fail("not_object")
    admitted = document.get("decision") == "admitted"
    spec = {"schema_version": _const(schema), **common, **(active if admitted else {})}
    _check_fields(document, spec)
    if (document["reason"] == "none") != admitted:
        _fail("reason_decision_mismatch", "reason")
    return document


def _window_response(document: Any) -> dict:
    return _response(document, _RESPONSE_COMMON, _RESPONSE_ACTIVE, WINDOW_RESPONSE_SCHEMA)


def _attempt_response(document: Any) -> dict:
    return _response(document, {**_RESPONSE_COMMON, **_ATTEMPT_RESPONSE_COMMON},
                     {**_RESPONSE_ACTIVE, **_ATTEMPT_RESPONSE_ACTIVE}, ATTEMPT_RESPONSE_SCHEMA)


def _window_descriptor(document: Any) -> dict:
    return _check_fields(document, _WINDOW_DESCRIPTOR)


def _attempt_descriptor(document: Any) -> dict:
    return _check_fields(document, _ATTEMPT_DESCRIPTOR)


def _window_notification(document: Any) -> dict:
    return _check_fields(document, _WINDOW_NOTIFICATION)


def _attempt_notification(document: Any) -> dict:
    return _check_fields(document, _ATTEMPT_NOTIFICATION)


def _attempt_record(document: Any) -> dict:
    _check_fields(document, _ATTEMPT_RECORD)
    if (document["attempt"] == 1) != (document["previous_failure_code"] == "none"):
        _fail("attempt_failure_mismatch", "previous_failure_code")
    return document


def _identity_phase(payload: dict) -> None:
    """S section 14.2 adopted-identity matrix for CP->host bodies.

    pairing_id and original expiry are null together, only when no invitation ever existed
    (reserved pre-invite failure); a runner exists only after exchange, so it implies a pairing.
    """
    no_invite = payload["pairing_id"] is None
    if no_invite != (payload["original_pairing_expires_at_ms"] is None):
        _fail("phase_nullability", "original_pairing_expires_at_ms")
    if payload.get("runner_id") is not None and no_invite:
        _fail("phase_nullability", "runner_id")


def _pending(payload: Any) -> dict:
    _check_fields(payload, _PENDING)
    for name in ("pairing_id", "original_pairing_expires_at_ms"):
        if payload[name] is None:  # matched pending always has a pairing and the original expiry
            _fail("phase_nullability", name)
    if payload["challenge_expires_at_ms"] != payload["original_pairing_expires_at_ms"]:
        _fail("expiry_mismatch", "challenge_expires_at_ms")
    return payload


def _revoked(payload: Any) -> dict:
    _check_fields(payload, _REVOKED)
    if payload["pairing_id"] is None:  # revocation always names a matched pairing
        _fail("phase_nullability", "pairing_id")
    _identity_phase(payload)
    return payload


def _aborted(payload: Any) -> dict:
    _check_fields(payload, _ABORTED)
    _identity_phase(payload)
    return payload


def _key_offer(payload: Any) -> dict:
    _check_fields(payload, _KEY_OFFER)
    managed, epoch = payload["previous_managed_executor_id"], payload["previous_epoch_id"]
    if (managed is None) != (epoch is None):
        _fail("predecessor_nullability", "previous_epoch_id")
    if managed is None and payload["previous_terminal_pairing_id"] is not None:
        _fail("predecessor_nullability", "previous_terminal_pairing_id")
    if epoch is not None and epoch == payload["epoch_id"]:  # never reuse an epoch
        _fail("predecessor_reuse", "previous_epoch_id")
    return payload


def _retired_ack(payload: Any) -> dict:
    return _check_fields(payload, _RETIRED_ACK)


def _identity_observation(payload: Any) -> dict:
    return _check_fields(payload, _IDENTITY)


def _ceremony_request(document: Any) -> dict:
    _check_fields(document, _CEREMONY_REQUEST)
    kind, payload = document["kind"], document["payload"]
    if kind == "poll":
        if payload != {}:
            _fail("payload_mismatch", "payload")
    elif kind == "public_key":
        _key_offer(payload)
        if payload["slot_id"] != document["slot_id"] or payload["epoch_id"] != document["pairing_epoch"]:
            _fail("envelope_mismatch", "payload")
        if (payload["previous_managed_executor_id"] is not None
                and payload["previous_managed_executor_id"] == document["managed_executor_id"]):
            _fail("predecessor_reuse", "previous_managed_executor_id")
    else:  # retired: an exact retired ack for an adopted tuple, never active
        _retired_ack(payload)
        if (document["managed_executor_id"] is None
                or payload["managed_executor_id"] != document["managed_executor_id"]
                or payload["slot_id"] != document["slot_id"] or payload["epoch_id"] != document["pairing_epoch"]):
            _fail("envelope_mismatch", "payload")
    return document


def _ceremony_response(document: Any) -> dict:
    _check_fields(document, _CEREMONY_RESPONSE)
    kind, payload, managed = document["kind"], document["payload"], document["managed_executor_id"]
    if kind == "none":
        if payload != {}:
            _fail("payload_mismatch", "payload")
        return document
    if managed is None:  # only the association-free none answer may omit the managed identity
        _fail("null_forbidden", "managed_executor_id")
    if kind == "challenge":
        _pending(payload)
    elif kind == "terminal":
        schema = payload.get("schema_version") if isinstance(payload, dict) else None
        if schema == REVOKED_SCHEMA:
            _revoked(payload)
        elif schema == ABORTED_SCHEMA:
            _aborted(payload)
        else:
            _fail("payload_mismatch", "payload")  # no activated.v1 or other alternative exists
    else:
        _identity_observation(payload)
        return document
    if payload["managed_executor_id"] != managed or payload["epoch_id"] != document["pairing_epoch"]:
        _fail("envelope_mismatch", "payload")
    return document


def _observation(document: Any) -> dict:
    _check_fields(document, _OBSERVATION)
    state = document["observed_state"]
    if state in NONTERMINAL_STATES and document["cancellation_phase"] is not None:
        _fail("phase_nullability", "cancellation_phase")
    # S 14.2 matrix: CP pending follows exchange+approve, so pending/active are the matched phase.
    if state in ("pending", "active") and document["pairing_id"] is None:
        _fail("phase_nullability", "pairing_id")
    if state in ("pending", "active") and document["runner_id"] is None:
        _fail("phase_nullability", "runner_id")
    if (document["pairing_id"] is None) != (document["original_pairing_expires_at_ms"] is None):
        _fail("phase_nullability", "original_pairing_expires_at_ms")
    if document["runner_id"] is not None and document["pairing_id"] is None:
        _fail("phase_nullability", "runner_id")
    if state not in NONTERMINAL_STATES and document["cancellation_phase"] is None:
        _fail("phase_nullability", "cancellation_phase")
    if state == "revoked" and document["pairing_id"] is None:  # revocation always has a pairing
        _fail("phase_nullability", "pairing_id")
    # The key is fixed at reservation; only the pre-pair offered row is left nullable (see the
    # observation fixture), every matched and adopted-terminal row keeps it.
    if state != "offered" and document["runner_key_id"] is None:
        _fail("phase_nullability", "runner_key_id")
    # ``completed`` claims a matching retired ack in the same row; another ack state contradicts it.
    # A historical active ack remains legal on a terminal row that has not claimed completion. This
    # is structural only and does not prove a durable ack or auth reconciliation.
    if document["cancellation_phase"] == "completed" and document["host_ack_state"] != "retired":
        _fail("phase_nullability", "host_ack_state")
    return document


_VALIDATORS: Mapping[str, Callable[[Any], dict]] = {
    "window_request": _window_request, "attempt_request": _attempt_request, "attempt_forward": _attempt_request,
    "window_response": _window_response, "attempt_response": _attempt_response,
    "window_descriptor": _window_descriptor, "attempt_descriptor": _attempt_descriptor,
    "window_notification": _window_notification, "attempt_notification": _attempt_notification,
    "ceremony_request": _ceremony_request, "ceremony_response": _ceremony_response,
    "observation": _observation, "attempt_record": _attempt_record,
}


def _validator(message: str) -> Callable[[Any], dict]:
    validator = _VALIDATORS.get(message) if isinstance(message, str) else None
    if validator is None:
        _fail("unknown_message")
    return validator


def validate(message: str, document: Any) -> dict:
    """Validate an in-memory object against a fixed message contract, including its cap."""
    _validator(message)(document)
    if len(canonical(document)) > CAPS[message]:
        _fail("oversize")
    return document


def encode(message: str, document: Any) -> bytes:
    validate(message, document)
    return canonical(document)


def decode(message: str, body: bytes) -> dict:
    """Decode exactly one canonical body for a fixed message; the cap is checked before parsing."""
    validator = _validator(message)
    return validator(_parse(body, CAPS[message]))


def decode_route_request(route: str, body: bytes) -> dict:
    return decode(route_contract(route).request, body)


def decode_route_response(route: str, body: bytes) -> dict:
    return decode(route_contract(route).response, body)


def validate_status_request(body: bytes) -> None:
    """The observational status POST body is exactly ``{}``."""
    if not isinstance(body, bytes) or body != b"{}":
        _fail("invalid_status_request")


# ---------------------------------------------------------------------------------------------
# Commitments and non-cyclic digest ordering.
#
#   request_identity_digest = SHA256(canonical(request without operation_digest))
#   descriptor.request_identity_digest = request_identity_digest
#   operation_digest = SHA256(canonical(descriptor));  request.operation_digest = operation_digest
#   request_digest = SHA256(canonical(complete request))  (echoed by the response)
#
# The descriptor never contains operation_digest, so no digest depends on itself.

def request_identity_digest(request: Mapping[str, Any]) -> str:
    if not isinstance(request, Mapping) or "operation_digest" not in request:
        _fail("missing_key", "operation_digest")
    return _sha({k: v for k, v in request.items() if k != "operation_digest"})


def operation_digest(descriptor: Mapping[str, Any]) -> str:
    return _sha(dict(descriptor))


def request_digest(request: Mapping[str, Any]) -> str:
    return _sha(dict(request))


def route_template_digest(method: str, route_template: str) -> str:
    """Commitment to the signed projected template; CP can recompute it from the stored projection."""
    if method not in METHODS:
        _fail("invalid_field", "method")
    # Text with a lone surrogate has no UTF-8 form. Detect it without raising, so the fixed refusal
    # never chains (or retains) an encoder exception holding the supplied value. The code point
    # precheck bounds the scan; it cannot refuse a legal template (UTF-8 is >= 1 byte per point).
    if (not isinstance(route_template, str) or not route_template or len(route_template) > 1024
            or _SURROGATE.search(route_template) is not None or len(route_template.encode("utf-8")) > 1024):
        _fail("invalid_field", "route_template")
    return _sha({"method": method, "route_template": route_template})


def route_digest(method: str, route: str) -> str:
    """Commitment to the whole prepared private route after exact fixture substitution."""
    if method not in METHODS:
        _fail("invalid_field", "method")
    if not isinstance(route, str) or not route or not route.isascii() or len(route) > 2048:
        _fail("invalid_field", "route")
    return _sha({"method": method, "route": route})


def action_digest(action: Mapping[str, Any]) -> str:
    if not isinstance(action, Mapping) or not action:
        _fail("invalid_field", "action")
    return _sha(dict(action))


def credential_binding_digest(binding: Mapping[str, Any] | None) -> str:
    """Selected manifest credential binding commitment; anonymous (``None``) is canonical null.

    The binding is metadata naming a vault handle, never secret bytes; this function refuses nothing
    else about it and cannot tell a secret apart, so callers must pass the manifest binding only.
    """
    if binding is None:
        return _sha(None)
    if not isinstance(binding, Mapping) or not binding:
        _fail("invalid_field", "credential_binding")
    return _sha(dict(binding))


_ATTEMPT_SHARED = ("window_operation_digest", "bootstrap_fence", "manifest_digest", "route_digest", "action_ordinal",
                   "method", "semantic_role", "attempt", "attempt_deadline_ns")


def _binding(request: dict, descriptor: dict) -> None:
    if descriptor["request_identity_digest"] != request_identity_digest(request):
        _fail("binding_mismatch", "request_identity_digest")
    if request["operation_digest"] != operation_digest(descriptor):
        _fail("binding_mismatch", "operation_digest")
    if descriptor["bootstrap_fence"] != request["bootstrap_fence"]:
        _fail("binding_mismatch", "bootstrap_fence")


def verify_window_binding(request: Any, descriptor: Any) -> None:
    _binding(validate("window_request", request), validate("window_descriptor", descriptor))


def verify_attempt_binding(request: Any, descriptor: Any) -> None:
    """Exact Q <-> local descriptor association. Structural only: it cannot show that the descriptor's
    action/route/credential commitments describe the action actually prepared; the trusted executor
    re-verifies that against the manifest before requesting Q and before dispatch."""
    request, descriptor = validate("attempt_request", request), validate("attempt_descriptor", descriptor)
    _binding(request, descriptor)
    for name in _ATTEMPT_SHARED:
        if descriptor[name] != request[name]:
            _fail("binding_mismatch", name)


_ECHO_IDENTITY = ("workspace_id", "project_id", "environment_id", "verification_record_digest", "runner_id",
                  "runner_key_id", "binding_id", "binding_digest", "run_id", "grant_id", "grant_digest")


def _response_echo(response: dict, request: dict) -> None:
    if response["request_digest"] != request_digest(request):
        _fail("binding_mismatch", "request_digest")
    for name in ("operation_digest", "sequence", "bootstrap_fence"):
        if response[name] != request[name]:
            _fail("binding_mismatch", name)
    if response["decision"] == "admitted":
        for name in _ECHO_IDENTITY:
            if response[name] != request[name]:
                _fail("binding_mismatch", name)


def verify_window_response(response: Any, request: Any) -> None:
    request, response = validate("window_request", request), validate("window_response", response)
    _response_echo(response, request)


def verify_attempt_response(response: Any, request: Any) -> None:
    request, response = validate("attempt_request", request), validate("attempt_response", response)
    _response_echo(response, request)
    if response["attempt_digest"] != request["operation_digest"]:
        _fail("binding_mismatch", "attempt_digest")
    if response["window_operation_digest"] != request["window_operation_digest"]:
        _fail("binding_mismatch", "window_operation_digest")
    if response["decision"] == "admitted" and response["attempt_deadline_ns"] > request["attempt_deadline_ns"]:
        _fail("deadline_extension", "attempt_deadline_ns")  # a receipt can never extend D_Q


def verify_window_notification(notification: Any, request: Any) -> None:
    request = validate("window_request", request)
    notification = validate("window_notification", notification)
    if notification["request_digest"] != request_digest(request):
        _fail("binding_mismatch", "request_digest")
    for name in ("operation_digest", "generation_id", "run_id", "sequence", "bootstrap_fence"):
        if notification[name] != request[name]:
            _fail("binding_mismatch", name)


def verify_attempt_notification(notification: Any, request: Any) -> None:
    """Resolve only the exact already-pending Q; the notification itself creates nothing."""
    request = validate("attempt_request", request)
    notification = validate("attempt_notification", notification)
    if notification["request_digest"] != request_digest(request):
        _fail("binding_mismatch", "request_digest")
    if notification["attempt_digest"] != request["operation_digest"]:
        _fail("binding_mismatch", "attempt_digest")
    for name in ("window_operation_digest", "bootstrap_fence", "generation_id", "run_id", "sequence"):
        if notification[name] != request[name]:
            _fail("binding_mismatch", name)
    if notification["deadline_ns"] != request["attempt_deadline_ns"]:
        _fail("binding_mismatch", "deadline_ns")
