"""Plan-differential runner: one inventoried read, replayed as two canary plan identities.

The command surface is CLI only. Every request is one action of a manifest compiled by
``CanaryCompiler.compile_plan_differential_pair``, executed by ``LocalCanaryExecutor``
through ``TargetHTTPSClient`` under a human-created signed scope that lists the exact
host. Nothing here creates, edits, or re-signs a scope, and no caller input selects a
transport, scheme, port, resolver, trust store, header, method, or attempt ID.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any

from heel.canary_contracts import (
    EXECUTION_GRANT_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    canonical_bytes,
    canonical_digest,
)
from heel.containment import ContainmentLog, verify_chain
from heel.contracts import AbuseVector, Category, Severity
from heel.crypto import SigningAuthority, ed25519_key_id
from heel.scope import ensure_home, get_scope, heel_home, verify
from heel.store import Store

from .catalog import CATALOG_BY_ID, CATALOG_IDS
from .compiler import CanaryCompiler, plan_differential_pairs
from .containment import verify_containment_chain
from .content_assertion import is_ambiguous_message, is_denial_envelope, protected_content
from .execution import ExecutionBundle, ExecutionGate, LocalCanaryExecutor
from .http_transport import (
    DEFAULT_TIMEOUT_SECONDS,
    BoundedResolver,
    CancellationToken,
    TargetHTTPSClient,
    TransportFailure,
    normalize_target_origin,
)
from .identity import RunnerIdentity, SecureSigner, runner_phrase_words
from .redaction import MAX_INPUT_BYTES, Redactor, _secret_key
from .store import RunnerContext, RunnerStore
from .vault import EphemeralVault, VaultUnavailable, ephemeral_environment_name, select_vault


SCENARIO = "plan_entitlement_read"
ROLES = ("lower_plan", "higher_plan")
PREDICATES = ("body_superset", "marker_leak", "status_parity", "inconclusive")
SCENARIO_PREFIX = "plan_differential."
DEFAULT_MAX_OPS = 50
MIN_MAX_OPS = 2
MAX_MAX_OPS = 100
REPLAY_MAX_OPS = 4
MAX_KEY_PATH_DEPTH = 16
MAX_KEY_PATH_NODES = 4096
MIN_REDACTABLE_SECRET_BYTES = 8
_DENIAL_STATUSES = frozenset({401, 402, 403, 404})
_REDACTED = b"[REDACTED:secret]"
_LABEL = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}", flags=re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}", flags=re.ASCII)
_SIGNER_LABEL = "plan-differential-ephemeral"
_CONTEXT_KIND = "heel.local-plan-differential-context.v1"
_RECOMMENDED_CONTROL = (
    "Enforce the plan entitlement check server-side on this read before the response is "
    "serialized."
)
_OBSERVED_NOTE = (
    "The lower plan received every field the higher plan received on this one read. Heel "
    "holds no declaration that this route is plan-gated, so a route that is ungated by "
    "design is reported too."
)
_SEVERITY = {
    "verified": (0.9, 0.7, 0.1),
    "observed": (0.6, 0.6, 0.3),
    "inconclusive": (0.2, 0.4, 0.5),
}


class PlanDifferentialRejected(ValueError):
    """The command was refused. The message is never shown to the operator."""


class BodyTooComplex(ValueError):
    """A response body exceeded the bounded key-path walk."""


# --------------------------------------------------------------------------- #
# Predicates (pure; no I/O)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PlanObservation:
    """One stored, redacted response of one plan identity."""

    status: int
    body: bytes
    evidence_ref: str = ""


@dataclass(frozen=True, slots=True)
class ExecutorOutcome:
    execution_disposition: str
    assessment_outcome: str
    failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class PairVerdict:
    verdict: str                    # finding | held | inconclusive
    evidence_state: str | None      # verified | observed | inconclusive; None when held or row 1
    predicate: str
    reason: str
    candidate: bool
    stores_finding: bool
    row: int
    positive_control: bool = False
    status_parity: bool | None = None
    body_superset: bool | None = None
    marker_leak: bool | None = None


_PATH_ESCAPES = str.maketrans({"\\": "\\\\", ".": "\\.", "[": "\\[", "]": "\\]"})


def _path_segment(key: str) -> str:
    """One object key as a path segment, the renderer's four metacharacters escaped."""
    return key.translate(_PATH_ESCAPES)


def key_paths(value: Any) -> frozenset[str]:
    """Key paths of a parsed body, never descending below a secret-named key."""
    paths: set[str] = set()
    visited = 0
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    while stack:
        node, path, depth = stack.pop()
        visited += 1
        if visited > MAX_KEY_PATH_NODES or depth > MAX_KEY_PATH_DEPTH:
            raise BodyTooComplex("response body exceeds the key-path bound")
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{_path_segment(key)}"
                paths.add(child_path)
                if not _secret_key(key):
                    stack.append((child, child_path, depth + 1))
        elif isinstance(node, list):
            element_path = path + "[]"
            paths.add(element_path)
            for child in node:
                stack.append((child, element_path, depth + 1))
    return frozenset(paths)


def material_paths(value: Any) -> frozenset[str]:
    """The key paths of a parsed body at which the value is JSON-truthy; same walk and bounds."""
    paths: set[str] = set()
    visited = 0
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    while stack:
        node, path, depth = stack.pop()
        visited += 1
        if visited > MAX_KEY_PATH_NODES or depth > MAX_KEY_PATH_DEPTH:
            raise BodyTooComplex("response body exceeds the key-path bound")
        if isinstance(node, dict):
            for key, child in node.items():
                if not _secret_key(key):
                    child_path = f"{path}.{_path_segment(key)}"
                    if child:
                        paths.add(child_path)
                    stack.append((child, child_path, depth + 1))
        elif isinstance(node, list):
            element_path = path + "[]"
            for child in node:
                if child:
                    paths.add(element_path)
                stack.append((child, element_path, depth + 1))
    return frozenset(paths)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def _parsed(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(
            body.decode("utf-8"), object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError):
        return None


def _is_2xx(status: int) -> bool:
    return 200 <= status <= 299


def _denial_undecided(lower: PlanObservation, lower_json: Any, higher_json: Any) -> str | None:
    """Why a lower 401-404 on a markerless body read cannot be held, or None when it can.

    A denial status proves nothing on its own. It is held only against a higher body that
    is a bounded JSON object with material content, and only when the lower body is
    complete and empty, or a bounded JSON object whose material paths do not cover the
    higher body's. A lower body that still covers them, with or without an error field, is
    a status-only change: undecided, never held and never a finding. A non-empty lower body
    that is not a JSON object, a scalar or array included, cannot be compared at all. A
    lower body that is a recognized error or denial envelope is undecided at any status, and
    a message-only object cannot be assessed.
    """
    try:
        higher_material = (
            material_paths(higher_json) if isinstance(higher_json, dict) else frozenset()
        )
    except BodyTooComplex:
        higher_material = frozenset()
    if not higher_material:
        return "higher_control_unassessable"
    if not lower.body:
        return None
    if not isinstance(lower_json, dict):
        return "lower_denial_unassessable"
    try:
        lower_material = material_paths(lower_json)
    except BodyTooComplex:
        return "lower_denial_unassessable"
    if lower_material >= higher_material:
        return "lower_denied_payload_present"
    if is_denial_envelope(lower_json):
        return "lower_denial_envelope"
    return "lower_denial_unassessable" if is_ambiguous_message(lower_json) else None


def _row_one(reason: str) -> PairVerdict:
    return PairVerdict("inconclusive", None, "inconclusive", reason, False, False, 1)


def _evaluate(
    lower: PlanObservation,
    higher: PlanObservation,
    *,
    method: str,
    marker: str | None,
    assessment_outcome: str,
) -> PairVerdict:
    lower_json, higher_json = _parsed(lower.body), _parsed(higher.body)
    lower_denial = is_denial_envelope(lower_json)
    higher_marker = (
        protected_content(higher.body, marker=marker, status=higher.status, method=method)
        if marker else None
    )
    higher_ok = (
        _is_2xx(higher.status)
        and not is_denial_envelope(higher_json)
        and not is_ambiguous_message(higher_json)
    )
    positive_control = higher_ok and (
        not marker or (higher.status == 200 and higher_marker is True)
    )

    body_superset: bool | None = None
    hollow = False
    if positive_control and method != "HEAD" and isinstance(higher_json, dict):
        try:
            higher_paths = key_paths(higher_json)
            lower_paths = key_paths(lower_json) if isinstance(lower_json, dict) else frozenset()
            higher_material = material_paths(higher_json)
            lower_material = (
                material_paths(lower_json) if isinstance(lower_json, dict) else frozenset()
            )
        except BodyTooComplex:
            pass
        else:
            if higher_paths and not lower_denial:
                shape = (
                    _is_2xx(lower.status)
                    and isinstance(lower_json, dict)
                    and lower_paths >= higher_paths
                )
                # A lower body that echoes the higher key shape but is not truthy at a path
                # the higher body populates withholds parity, as a denial envelope does.
                hollow = shape and not lower_material >= higher_material
                body_superset = None if hollow else shape

    status_parity: bool | None = None
    if positive_control:
        if _is_2xx(lower.status):
            status_parity = None if lower_denial or hollow else True
        elif lower.status in _DENIAL_STATUSES:
            status_parity = False

    denial_undecided: str | None = None
    if status_parity is False and not marker:
        if method != "HEAD":
            denial_undecided = _denial_undecided(lower, lower_json, higher_json)
        elif lower_denial:
            denial_undecided = "lower_denial_envelope"
        elif is_ambiguous_message(lower_json):
            denial_undecided = "lower_denial_unassessable"

    marker_leak: bool | None = None
    if marker and method != "HEAD" and positive_control:
        lower_marker = protected_content(
            lower.body, marker=marker, status=lower.status, method=method,
        )
        if lower_marker is True and assessment_outcome == "observed":
            marker_leak = True
        elif lower_marker is False and assessment_outcome == "blocked":
            marker_leak = False

    common = {
        "positive_control": positive_control,
        "status_parity": status_parity,
        "body_superset": body_superset,
        "marker_leak": marker_leak,
    }
    if not positive_control:
        reason = (
            "positive_control_missing_marker" if marker and higher_ok else "no_positive_control"
        )
        return PairVerdict("inconclusive", "inconclusive", "inconclusive", reason, False, False, 2, **common)
    if marker_leak is True:
        return PairVerdict("finding", "verified", "marker_leak", "marker_present", False, True, 3, **common)
    if marker_leak is False:
        return PairVerdict("held", None, "marker_leak", "marker_absent", False, False, 4, **common)
    if marker:
        return PairVerdict(
            "inconclusive", "inconclusive", "inconclusive", "marker_undetermined", False, False, 5,
            **common,
        )
    if body_superset is True:
        return PairVerdict("finding", "observed", "body_superset", "lower_superset", False, True, 6, **common)
    if status_parity is False and denial_undecided is not None:
        return PairVerdict(
            "inconclusive", "inconclusive", "inconclusive", denial_undecided, False, False, 9,
            **common,
        )
    if status_parity is False:
        return PairVerdict("held", None, "status_parity", "lower_denied", False, False, 7, **common)
    if status_parity is True:
        reason = (
            "head_status_only" if method == "HEAD"
            else "lower_subset" if body_superset is False
            else "status_only"
        )
        # Status parity alone is a candidate, never a stored finding.
        return PairVerdict("inconclusive", "inconclusive", "status_parity", reason, True, False, 8, **common)
    reason = (
        "lower_denial_envelope" if _is_2xx(lower.status) and lower_denial
        else "lower_hollow_shape" if hollow
        else "unexpected_status" if not _is_2xx(lower.status)
        else "body_too_complex"
    )
    return PairVerdict("inconclusive", "inconclusive", "inconclusive", reason, False, False, 9, **common)


def evaluate_plan_pair(
    lower: PlanObservation | None,
    higher: PlanObservation | None,
    *,
    method: str,
    marker: str | None,
    executor_outcome: ExecutorOutcome,
) -> PairVerdict:
    """Three-valued, fail-closed verdict for one lower/higher pair. First matching row wins."""
    completed = (
        getattr(executor_outcome, "execution_disposition", None) == "completed"
        and isinstance(lower, PlanObservation)
        and isinstance(higher, PlanObservation)
    )
    if not completed:
        reason = getattr(executor_outcome, "failure_reason", None)
        return _row_one(reason if isinstance(reason, str) and reason else "evidence_unavailable")
    try:
        return _evaluate(
            lower, higher, method=method, marker=marker,
            assessment_outcome=executor_outcome.assessment_outcome,
        )
    except Exception:
        return PairVerdict("inconclusive", "inconclusive", "inconclusive", "predicate_error", False, False, 9)


# --------------------------------------------------------------------------- #
# Authorization, origin, context
# --------------------------------------------------------------------------- #
def _require_caller(caller: object) -> str:
    if type(caller) is not str or not caller.startswith("cli:") or len(caller) <= len("cli:"):
        raise PlanDifferentialRejected("plan-differential runs are CLI only")
    return caller


def _verified_scope(scope_id: object):
    """Re-read the signed scope from disk on every call and verify it."""
    if type(scope_id) is not str or not scope_id:
        raise PlanDifferentialRejected("signed scope is required")
    try:
        scope = get_scope(scope_id)
        valid = scope is not None and verify(scope)[0] is True
    except Exception:
        valid = False
    if not valid:
        raise PlanDifferentialRejected("signed scope is unknown, invalid, unbound, or expired")
    return scope


def _authorize(scope_id: str, host: str):
    """Verify the signed scope as it is on disk now and test exact host membership."""
    scope = _verified_scope(scope_id)
    allowlist = scope.target_allowlist
    listed = type(host) is str and bool(host) and isinstance(allowlist, list) and any(
        type(entry) is str and entry == host for entry in allowlist
    )
    return scope, listed


def _origin(base_url: object) -> tuple[str, str]:
    try:
        origin = normalize_target_origin(base_url)  # type: ignore[arg-type]
    except TransportFailure:
        raise PlanDifferentialRejected("base URL is not an exact public https origin") from None
    return origin, origin[len("https://"):]


def _context(origin: str, host: str) -> RunnerContext:
    return RunnerContext(
        "workspace_local",
        "project_plan_differential",
        "env_" + hashlib.sha256(host.encode("ascii")).hexdigest()[:16],
        origin,
        canonical_digest({"kind": _CONTEXT_KIND, "host": host}),
        "staging",
    )


class _EphemeralSigner(SecureSigner):
    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self._private = Ed25519PrivateKey.generate()
        self.public_key = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload: bytes) -> bytes:
        return self._private.sign(payload)


def _ephemeral_identity(signer: SecureSigner) -> RunnerIdentity:
    return RunnerIdentity(
        "runner_plan_differential",
        "workspace_local",
        "1",
        {scenario_id: CATALOG_BY_ID[scenario_id]["adapter_version"] for scenario_id in CATALOG_IDS},
        base64.b64encode(signer.public_key).decode("ascii"),
        hashlib.sha256(signer.public_key).hexdigest(),
        signer.key_id,
        runner_phrase_words()[:6],
    )


def _setup_store(origin: str, host: str, *, bind: bool) -> tuple[RunnerStore | None, str]:
    """Open the setup store for exactly this origin. Never rebinds or overwrites."""
    expected = _context(origin, host)
    try:
        store = RunnerStore()
    except Exception:
        return None, "mismatch"
    if not store.is_context_bound:
        if not bind:
            return None, "unbound"
        # The private key is discarded: the setup store never executes.
        signer = _EphemeralSigner()
        store.bind_context(
            expected, identity=_ephemeral_identity(signer), signer=signer,
            signer_label=_SIGNER_LABEL,
        )
        return store, "bound"
    try:
        binding = store.load_binding()
    except Exception:
        return None, "mismatch"
    if (
        binding.get("schema_version") != "heel.bound-runner-context.v1"
        or binding.get("context") != expected.as_dict()
    ):
        return None, "mismatch"
    return store, "already_bound"


def _open_db() -> Store:
    return Store(os.path.join(ensure_home(), "heel.db"))


def _security_log(db: Store, caller: str, detail: dict[str, Any]) -> None:
    try:
        ContainmentLog(db, "security", caller).append("reject_run", detail)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Plan construction (no network)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _Identity:
    label: str
    role: str
    handle: str
    record: Mapping[str, Any]

    def public(self) -> dict[str, str]:
        return {"label": self.label, "role": self.role, "credential_handle": self.handle}


@dataclass(frozen=True, slots=True)
class _Pair:
    method: str
    route_template: str
    fixture_bindings: Mapping[str, str]
    marker: str | None
    bindings_sha256: str


@dataclass(slots=True)
class _Plan:
    scope_id: str
    origin: str
    host: str
    authorized: bool
    context_state: str
    setup: RunnerStore | None
    identities: list[_Identity]
    inventory: dict[str, Any] | None
    inventory_source: str
    pairs: list[_Pair]
    not_executed: list[dict[str, str]]
    max_ops: int
    effective_max_ops: int
    plan_sha256: str = ""


def _credential_source(record: Mapping[str, Any]) -> dict[str, str]:
    handle = record["credential_handle_id"]
    if record["backend"] == "ephemeral_env":
        return {
            "kind": "environment",
            "variable": ephemeral_environment_name(handle, source_kind="environment"),
        }
    if record["backend"] == "ephemeral_fd":
        return {
            "kind": "inherited_fd",
            "variable": ephemeral_environment_name(handle, source_kind="inherited_fd"),
        }
    return {"kind": "os_vault"}


def _plan_arguments(plans: object) -> list[tuple[str, str]]:
    if isinstance(plans, (str, bytes)) or not isinstance(plans, Sequence):
        raise PlanDifferentialRejected("plans must be label and handle pairs")
    result: list[tuple[str, str]] = []
    for item in plans:
        if (
            isinstance(item, (str, bytes))
            or not isinstance(item, Sequence)
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or _LABEL.fullmatch(item[0]) is None
            or _HEX32.fullmatch(item[1]) is None
        ):
            raise PlanDifferentialRejected("plan must be a label and a credential handle")
        result.append((item[0], item[1]))
    if len(result) not in {0, 2}:
        raise PlanDifferentialRejected("exactly two plans are required")
    if result and (result[0][0] == result[1][0] or result[0][1] == result[1][1]):
        raise PlanDifferentialRejected("plan labels and handles must differ")
    return result


def _resolve_identities(setup: RunnerStore, plans: list[tuple[str, str]]) -> list[_Identity]:
    records: dict[str, list[dict[str, Any]]] = {}
    for record in setup.list_credentials():
        records.setdefault(record["credential_handle_id"], []).append(record)
    identities: list[_Identity] = []
    for (label, handle), role in zip(plans, ROLES, strict=True):
        matches = records.get(handle, [])
        if (
            len(matches) != 1
            or matches[0]["state"] != "active"
            or matches[0]["semantic_role"] != role
        ):
            raise PlanDifferentialRejected("credential handle does not resolve to its plan role")
        identities.append(_Identity(label, role, handle, matches[0]))
    if len({identity.record["auth_profile"] for identity in identities}) != 1:
        raise PlanDifferentialRejected("both plans require the same auth profile")
    return identities


def _bindings_sha256(bindings: Mapping[str, str]) -> str:
    return canonical_digest([
        {"parameter_name": name, "fixture_id": bindings[name]} for name in sorted(bindings)
    ])


def _marker(bindings: Mapping[str, str]) -> str | None:
    markers = [value for value in bindings.values() if value.startswith("heel-canary-")]
    return markers[0] if len(markers) == 1 else None


def _effective_max_ops(scope: Any, max_ops: int, db: Store, scope_id: str) -> int:
    limits = scope.rate_and_resource_limits
    limit = limits.get("max_requests") if isinstance(limits, Mapping) else None
    effective = max_ops
    if type(limit) is int:
        effective = min(max_ops, limit)
        if db.scope_run_count(scope_id) >= limit:
            raise PlanDifferentialRejected("scope run budget is exhausted")
    if effective < MIN_MAX_OPS:
        raise PlanDifferentialRejected("scope permits fewer than two requests")
    return effective


def _prepare(
    scope_id: object,
    base_url: object,
    plans: object,
    *,
    caller: str,
    routes_artifact: Mapping[str, Any] | None,
    max_ops: object,
    bind: bool,
    db: Store,
    only: tuple[str, str] | None = None,
) -> _Plan:
    # Mode 1: the signed scope.
    try:
        _verified_scope(scope_id)
    except PlanDifferentialRejected:
        _security_log(db, caller, {
            "command": "runner run", "reason": "scope unknown, invalid, unbound or expired",
        })
        raise
    # Mode 2: arguments.
    origin, host = _origin(base_url)
    if type(max_ops) is not int or not MIN_MAX_OPS <= max_ops <= MAX_MAX_OPS:
        raise PlanDifferentialRejected("max ops must be an integer from 2 to 100")
    arguments = _plan_arguments(plans)
    if routes_artifact is not None and not isinstance(routes_artifact, Mapping):
        raise PlanDifferentialRejected("routes must be an imported inventory artifact")
    scope, authorized = _authorize(scope_id, host)  # type: ignore[arg-type]
    effective = _effective_max_ops(scope, max_ops, db, scope_id)  # type: ignore[arg-type]

    setup, state = _setup_store(origin, host, bind=False)
    if state == "unbound" and authorized and bind and not arguments:
        setup, state = _setup_store(origin, host, bind=True)
    plan = _Plan(
        scope_id=scope_id, origin=origin, host=host, authorized=authorized,  # type: ignore[arg-type]
        context_state=state, setup=setup, identities=[], inventory=None,
        inventory_source="default" if routes_artifact is None else "file",
        pairs=[], not_executed=[], max_ops=max_ops, effective_max_ops=effective,
    )
    if setup is None:
        if arguments and state == "unbound":
            # Handles cannot exist before the setup store is bound.
            raise PlanDifferentialRejected("credential handles require a bound setup store")
        return _digest_plan(plan)

    plan.identities = _resolve_identities(setup, arguments) if arguments else []
    try:
        if routes_artifact is None:
            routes: Any = setup.route_inventory()["routes"]
        else:
            # The compiler allowlist sees the raw artifact routes before the store does.
            inventory = routes_artifact.get("inventory")
            routes = inventory.get("routes") if isinstance(inventory, Mapping) else None
        mapping = next(
            (item for item in setup.list_mappings() if item["scenario_id"] == SCENARIO), None,
        )
        planned, skipped = plan_differential_pairs(routes, mapping=mapping)
        plan.inventory = setup.route_inventory(routes_artifact)
    except Exception:
        if routes_artifact is not None or plan.identities:
            raise PlanDifferentialRejected("imported route inventory is unavailable") from None
        return _digest_plan(plan)
    if not plan.identities:
        return _digest_plan(plan)

    pairs = [
        _Pair(
            item["method"], item["route_template"], dict(item["fixture_bindings"]),
            None if item["method"] == "HEAD" else _marker(item["fixture_bindings"]),
            _bindings_sha256(item["fixture_bindings"]),
        )
        for item in planned
    ]
    if only is not None:
        pairs = [pair for pair in pairs if (pair.method, pair.route_template) == only]
        skipped = []
    allowed = effective // 2
    plan.pairs = pairs[:allowed]
    plan.not_executed = list(skipped) + [
        {"method": pair.method, "route_template": pair.route_template, "reason": "over_budget"}
        for pair in pairs[allowed:]
    ]
    return _digest_plan(plan)


def _digest_plan(plan: _Plan) -> _Plan:
    plan.plan_sha256 = canonical_digest({
        "origin": plan.origin,
        "scope_id": plan.scope_id,
        "plans": [identity.public() for identity in plan.identities],
        "inventory_source_digest": plan.inventory["source_digest"] if plan.inventory else None,
        "pairs": [
            {
                "method": pair.method,
                "route_template": pair.route_template,
                "fixture_bindings_sha256": pair.bindings_sha256,
            }
            for pair in plan.pairs
        ],
        "effective_max_ops": plan.effective_max_ops,
    })
    return plan


def _dry_run_object(plan: _Plan) -> dict[str, Any]:
    default_path = (
        str(plan.setup.route_inventory_path())
        if plan.setup is not None and plan.inventory_source == "default" else None
    )
    return {
        "mode": "dry_run",
        "authorized": plan.authorized,
        "scope_id": plan.scope_id,
        "origin": plan.origin,
        "context": plan.context_state,
        "inventory": {
            "path": default_path,
            "source_digest": plan.inventory["source_digest"] if plan.inventory else None,
            "route_count": len(plan.inventory["routes"]) if plan.inventory else 0,
            "source": plan.inventory_source,
        },
        "plans": [
            {**identity.public(), "credential_source": _credential_source(identity.record)}
            for identity in plan.identities
        ],
        "max_ops": plan.max_ops,
        "effective_max_ops": plan.effective_max_ops,
        "pairs": [
            {
                "ordinal": ordinal,
                "method": pair.method,
                "route_template": pair.route_template,
                "requests": 2,
                "marker_supplied": pair.marker is not None,
            }
            for ordinal, pair in enumerate(plan.pairs)
        ],
        "not_executed": list(plan.not_executed),
        "requests_planned": 2 * len(plan.pairs),
        "requests_sent": 0,
        "plan_sha256": plan.plan_sha256,
    }


def _forced_dry_run(plan: _Plan, db: Store, caller: str) -> dict[str, Any]:
    _security_log(db, caller, {
        "command": "runner run", "reason": "host not in scope allowlist",
        "scope_id": plan.scope_id, "requested_host": plan.host,
    })
    return _dry_run_object(plan)


def plan_differential(
    scope_id: str,
    base_url: str,
    plans: Sequence[tuple[str, str]],
    *,
    caller: str,
    routes_artifact: Mapping[str, Any] | None = None,
    max_ops: int = DEFAULT_MAX_OPS,
) -> dict[str, Any]:
    """Verify the scope, decide the mode, bind the setup store when allowed, build the plan.

    Opens no socket, resolves no name, loads no credential, and reserves no attempt.
    """
    caller = _require_caller(caller)
    db = _open_db()
    try:
        plan = _prepare(
            scope_id, base_url, plans, caller=caller, routes_artifact=routes_artifact,
            max_ops=max_ops, bind=True, db=db,
        )
        if not plan.authorized:
            return _forced_dry_run(plan, db, caller)
        return _dry_run_object(plan)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
def _build_client(origin: str) -> TargetHTTPSClient:
    """The only client constructor: default resolver, sockets, and verified TLS."""
    hostname = origin[len("https://"):]
    answers = BoundedResolver()(hostname, deadline=time.monotonic() + DEFAULT_TIMEOUT_SECONDS)
    return TargetHTTPSClient(origin=origin, preflight_addresses=answers)


_RESERVATION_TOKEN = object()


@dataclass(frozen=True, slots=True)
class _AttemptReservation:
    attempt_id: str
    root: Path
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _RESERVATION_TOKEN:
            raise PlanDifferentialRejected("attempt reservations come from the exclusive mkdir")

    def held(self) -> bool:
        try:
            status = os.lstat(self.root)
        except OSError:
            return False
        return stat.S_ISDIR(status.st_mode)


def _reserve_attempt(attempt_id: str) -> _AttemptReservation:
    if type(attempt_id) is not str or _HEX32.fullmatch(attempt_id) is None:
        raise PlanDifferentialRejected("attempt ID is invalid")
    base = Path(os.path.abspath(heel_home())) / "plan-runs"
    # RunnerStore opens and verifies every path component without following symlinks.
    RunnerStore(base)
    root = base / attempt_id
    try:
        os.mkdir(root, 0o700)  # exclusive, durable one-shot attempt barrier (also after crashes)
    except FileExistsError:
        raise PlanDifferentialRejected("attempt ID was already consumed") from None
    return _AttemptReservation(attempt_id, root, _RESERVATION_TOKEN)


class _Budget:
    """Invocation-wide count of request attempts on the wire, retries included."""

    def __init__(self, limit: int) -> None:
        self._lock = threading.Lock()
        self._limit = limit
        self._used = 0

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._limit - self._used

    def take(self) -> int:
        with self._lock:
            if self._used >= self._limit:
                raise ValueError("budget exhausted")
            self._used += 1
            return self._used - 1


class _RunLog:
    """Serialize the HMAC chain between the main thread and bounded gate callbacks."""

    def __init__(self, delegate: ContainmentLog) -> None:
        self._delegate = delegate
        self._lock = threading.Lock()

    def append(self, action: str, detail: dict[str, Any]) -> None:
        with self._lock:
            self._delegate.append(action, detail)


_JSON_SHORT_ESCAPES = {
    '"': b'\\"', "\\": b"\\\\", "/": b"\\/", "\b": b"\\b", "\f": b"\\f", "\n": b"\\n",
    "\r": b"\\r", "\t": b"\\t",
}


def _unit_escape(unit: int) -> bytes:
    """Regex for one UTF-16 code unit written ``\\uXXXX`` with hex digits in either case."""
    return b"\\\\u" + b"".join(
        b"[" + digit.encode("ascii") + digit.upper().encode("ascii") + b"]"
        if digit.isalpha() else digit.encode("ascii")
        for digit in f"{unit:04x}"
    )


def _secret_pattern(text: str) -> re.Pattern[bytes]:
    """Match every spelling of a secret that a JSON parser decodes to it, and its raw bytes.

    Each character independently matches its UTF-8 bytes, its ``\\uXXXX`` escape (a
    surrogate pair outside the BMP) or its short escape, so mixed escaping matches too.
    No body is parsed; the pattern has no repetition, so matching is bounded.
    """
    parts: list[bytes] = []
    for character in text:
        code = ord(character)
        units = (
            (0xD800 + ((code - 0x10000) >> 10), 0xDC00 + ((code - 0x10000) & 0x3FF))
            if code > 0xFFFF else (code,)
        )
        forms = [
            re.escape(character.encode("utf-8")),
            b"".join(_unit_escape(unit) for unit in units),
        ]
        short = _JSON_SHORT_ESCAPES.get(character)
        if short is not None:
            forms.append(re.escape(short))
        parts.append(b"(?:" + b"|".join(forms) + b")")
    return re.compile(b"".join(parts))


def _secret_patterns(secrets: Sequence[str]) -> tuple[re.Pattern[bytes], ...]:
    # Longest first, so a secret that contains another is replaced whole.
    return tuple(
        _secret_pattern(secret)
        for secret in sorted(set(secrets), key=lambda item: (-len(item), item))
    )


class _TolerantRedactor(Redactor):
    """Count redactions for bodies the inherited count refuses, such as floats.

    The count is only a number in local results. What reaches disk is decided by
    ``_RedactingRunnerStore`` for every body shape.
    """

    __slots__ = ("_patterns",)

    def __init__(self, secrets: Sequence[str] = ()) -> None:
        super().__init__(secrets)
        self._patterns = _secret_patterns(secrets)

    def count_bytes(self, *chunks: bytes) -> int:
        try:
            return super().count_bytes(*chunks)
        except (TypeError, ValueError):
            if not chunks:
                raise
            for chunk in chunks:
                if type(chunk) is not bytes or len(chunk) > MAX_INPUT_BYTES:
                    raise
        total = 0
        for chunk in chunks:
            for pattern in self._patterns:
                chunk, count = pattern.subn(_REDACTED, chunk)
                total += count
        return min(1024, total)


class _RedactingRunnerStore(RunnerStore):
    """Attempt store that never persists a registered credential, raw or JSON-escaped."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self._secrets: set[str] = set()
        self._patterns: tuple[re.Pattern[bytes], ...] = ()

    def register_secret(self, value: bytes) -> None:
        self._secrets.add(value.decode("utf-8"))
        self._patterns = _secret_patterns(tuple(self._secrets))

    def registered_secrets(self) -> tuple[str, ...]:
        return tuple(sorted(self._secrets))

    def clear_secrets(self) -> None:
        self._secrets.clear()
        self._patterns = ()

    def _redact(self, value: bytes) -> bytes:
        for pattern in self._patterns:
            value = pattern.sub(_REDACTED, value)
        return value

    def store_response_evidence(
        self,
        run_id: str,
        *,
        action_ordinal: int,
        attempt: int,
        status_code: int,
        raw_headers: bytes,
        raw_body: bytes,
        expires_at_ms: int,
    ) -> str:
        return super().store_response_evidence(
            run_id, action_ordinal=action_ordinal, attempt=attempt, status_code=status_code,
            raw_headers=self._redact(raw_headers), raw_body=self._redact(raw_body),
            expires_at_ms=expires_at_ms,
        )


class _PlanVault:
    """Serve attempt-store handles from the operator's real setup-store credentials."""

    supported = True
    backend_id = "ephemeral_env"

    def __init__(self, store: _RedactingRunnerStore) -> None:
        self._store = store
        self._records: dict[str, Mapping[str, Any]] = {}
        self._secrets: dict[str, bytes] = {}

    def bind(self, attempt_handle: str, setup_record: Mapping[str, Any]) -> None:
        self._records[attempt_handle] = setup_record

    def _register(self, profile: str, secret: bytes) -> None:
        if profile == "cookie_jar":
            try:
                values = [
                    cookie["value"].encode("utf-8")
                    for cookie in json.loads(secret.decode("utf-8"))["cookies"]
                ]
            except Exception:
                raise VaultUnavailable("credential cannot be redacted reliably") from None
        else:
            values = [secret]
        if not values or any(len(value) < MIN_REDACTABLE_SECRET_BYTES for value in values):
            raise VaultUnavailable("credential cannot be redacted reliably")
        try:
            for value in values:
                self._store.register_secret(value)
        except UnicodeError:
            raise VaultUnavailable("credential cannot be redacted reliably") from None

    def load(self, handle: str) -> bytes:
        record = self._records.get(handle)
        if record is None:
            raise VaultUnavailable("credential handle is not part of this attempt")
        cached = self._secrets.get(handle)
        if cached is not None:
            return cached
        setup_handle = record["credential_handle_id"]
        if record["backend"] in {"ephemeral_env", "ephemeral_fd"}:
            secret = EphemeralVault(setup_handle, source_kind=record["source_kind"]).load(setup_handle)
        else:
            secret = select_vault(record["backend"]).load(setup_handle)
        self._register(record["auth_profile"], secret)
        self._secrets[handle] = secret
        return secret

    def close(self) -> None:
        self._secrets.clear()
        self._store.clear_secrets()


class _ScopedTransport:
    """Admit only the frozen pair, under a held reservation, scope, budget, and log entry."""

    def __init__(
        self,
        client: Any,
        *,
        compiled: Any,
        reservation: _AttemptReservation | None,
        authorize: Callable[[], bool],
        budget: _Budget,
        log: _RunLog,
        labels: Mapping[str, str],
        runner_run_id: str,
        secrets: Callable[[], Sequence[str]],
    ) -> None:
        actions = compiled.manifest["actions"]
        pairs = {(action["method"], action["route_template"]) for action in actions}
        if len(actions) != 2 or len(pairs) != 1:
            raise PlanDifferentialRejected("transport requires one compiled pair")
        self._client = client
        self._reservation = reservation
        self._pair = next(iter(pairs))
        self._secrets = secrets
        self._authorize = authorize
        self._budget = budget
        self._log = log
        self._labels = dict(labels)
        self._runner_run_id = runner_run_id
        self.failure_code: str | None = None

    def request(
        self, action, *, credential, cancellation, retry_policy, remaining_requests,
        before_attempt, evidence_context, evidence_sink, redactor,
    ):
        try:
            return self._request(
                action, credential=credential, cancellation=cancellation,
                retry_policy=retry_policy, remaining_requests=remaining_requests,
                before_attempt=before_attempt, evidence_context=evidence_context,
                evidence_sink=evidence_sink, redactor=redactor,
            )
        except TransportFailure as failure:
            self.failure_code = failure.code
            raise

    def _request(
        self, action, *, credential, cancellation, retry_policy, remaining_requests,
        before_attempt, evidence_context, evidence_sink, redactor,
    ):
        reservation = self._reservation
        if not isinstance(reservation, _AttemptReservation) or not reservation.held():
            raise TransportFailure("gate_rejected")
        if (
            getattr(action, "scenario_id", None) != SCENARIO
            or getattr(action, "method", None) not in {"GET", "HEAD"}
            or getattr(action, "semantic_auth_role", None) not in ROLES
            or action.semantic_auth_role not in self._labels
            or (action.method, getattr(evidence_context, "route_template", None)) != self._pair
        ):
            raise TransportFailure("gate_rejected")
        method, route_template = self._pair
        role = action.semantic_auth_role

        def gated(attempt: int, previous_failure_code: str | None):
            if not reservation.held() or not self._authorize():
                raise TransportFailure("gate_rejected")
            try:
                op_index = self._budget.take()
            except ValueError:
                exhausted = TransportFailure("gate_rejected")
                exhausted.gate_error = "budget_exhausted"
                raise exhausted from None
            permit = before_attempt(attempt, previous_failure_code)
            try:
                self._log.append("plan_differential_request", {
                    "method": method,
                    "route_template": route_template,
                    "label": self._labels[role],
                    "role": role,
                    "attempt": reservation.attempt_id,
                    "request_attempt": attempt,
                    "runner_run_id": self._runner_run_id,
                    "op_index": op_index,
                })
            except Exception:
                raise TransportFailure("gate_rejected") from None
            return permit

        if not isinstance(redactor, Redactor):
            raise TransportFailure("gate_rejected")
        return self._client.request(
            action, credential=credential, cancellation=cancellation,
            retry_policy=retry_policy, remaining_requests=remaining_requests,
            before_attempt=gated, evidence_context=evidence_context,
            evidence_sink=evidence_sink, redactor=_TolerantRedactor(self._secrets()),
        )


def _gate(scope_id: str, host: str, issued_at_ms: int) -> Callable[[], ExecutionGate]:
    def source() -> ExecutionGate:
        now = int(time.time() * 1000)
        expires = issued_at_ms + 30_000
        try:
            scope, active = _authorize(scope_id, host)
            expires = min(int(scope.expiry * 1000), expires)
        except Exception:
            active = False
        return ExecutionGate(active, "active", "valid", max(0, expires), 0, "none", now)
    return source


def _grant(manifest, projection, identity, authority, run_suffix: str, scope_id: str, now: int):
    unsigned = {
        "schema_version": EXECUTION_GRANT_SCHEMA,
        "grant_id": "grant_" + run_suffix,
        "run_id": "crun_" + run_suffix,
        "workspace_id": manifest["workspace_id"],
        "project_id": manifest["project_id"],
        "approval": {
            "projection_id": projection["projection_id"],
            "projection_digest": projection["projection_digest"],
            "manifest_digest": manifest["manifest_digest"],
        },
        "environment": manifest["environment"],
        "runner_binding": {
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        },
        "approval_actor": {"user_id": "local_operator", "role": "owner"},
        "approval_reason": "Operator-run plan-differential read under signed local scope " + scope_id,
        "consented_at_ms": now,
        "budgets": manifest["budgets"],
        "egress": manifest["egress"],
        "retry_policy": manifest["retry_policy"],
        "grant_nonce": "nonce_" + run_suffix,
        "kill_switch_generation": 0,
        "operational_receipt_policy": {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "maximum_bytes": 32768,
            "allowed_error_categories": sorted([
                "none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired",
                "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted",
                "containment_rejected", "cloud_disconnected",
            ]),
            "allowed_stop_reasons": sorted([
                "none", "local_emergency_stop", "cloud_stop", "runner_revoked",
                "target_revoked", "kill_switch",
            ]),
            "allowed_containment_codes": sorted([
                "admitted", "action_started", "action_completed", "action_rejected",
                "budget_exhausted", "dns_changed", "stop_observed", "response_truncated",
                "redacted",
            ]),
        },
        "issued_at_ms": now,
        "expires_at_ms": now + 30_000,
    }
    return {
        **unsigned,
        "grant_digest": canonical_digest(unsigned),
        **authority.sign(canonical_bytes(unsigned)),
    }


@dataclass(slots=True)
class _PairOutcome:
    pair: _Pair
    verdict: PairVerdict
    execution_disposition: str
    runner_run_id: str | None = None
    finding_id: str | None = None
    lower: PlanObservation | None = None
    higher: PlanObservation | None = None
    chain_valid: bool = True
    continues: bool = True
    not_executed_reason: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "method": self.pair.method,
            "route_template": self.pair.route_template,
            "verdict": self.verdict.verdict,
            "predicate": self.verdict.predicate,
            "reason": self.verdict.reason,
            "execution_disposition": self.execution_disposition,
            "candidate": self.verdict.candidate,
            "finding_id": self.finding_id,
            "runner_run_ids": [] if self.runner_run_id is None else [self.runner_run_id],
        }


def _load_observations(
    store: RunnerStore, runner_run_id: str, result: Any,
) -> tuple[PlanObservation | None, PlanObservation | None]:
    try:
        scenarios = result.findings_projection["scenario_results"]
        if len(scenarios) != 1:
            return None, None
        by_ordinal: dict[int, PlanObservation] = {}
        for reference in scenarios[0]["local_evidence_refs"]:
            # References are unordered in projections. Match by the action ordinal the
            # executor wrote into bounded evidence metadata, never by body vocabulary.
            metadata = json.loads(
                (store.run_path(runner_run_id) / "evidence" / (reference + ".meta")).read_text()
            )
            _, body = store.load_response_evidence(
                runner_run_id, reference, now_ms=int(time.time() * 1000),
            )
            ordinal = metadata["action_ordinal"]
            if ordinal in by_ordinal or ordinal not in {0, 1}:
                return None, None
            by_ordinal[ordinal] = PlanObservation(metadata["status_code"], body, reference)
        return by_ordinal.get(0), by_ordinal.get(1)
    except Exception:
        return None, None


def _failure_reason(disposition: str, error_category: str, transport: _ScopedTransport) -> str | None:
    if disposition == "completed":
        return None
    if error_category == "budget_exhausted":
        return "budget_exhausted"
    if disposition == "stopped":
        return "stopped"
    if transport.failure_code is not None:
        return "transport:" + transport.failure_code
    if error_category == "credential_unavailable":
        return "credential_unavailable"
    return "executor:" + error_category


def _observation_view(
    observation: PlanObservation, identity: _Identity, pair: _Pair, host: str,
) -> dict[str, Any]:
    parsed = _parsed(observation.body)
    try:
        count: int | None = len(key_paths(parsed)) if isinstance(parsed, dict) else 0
    except BodyTooComplex:
        count = None
    return {
        "label": identity.label,
        "role": identity.role,
        "status_code": observation.status,
        "body_shape": "json_object" if observation.body else "absent",
        "key_path_count": count,
        "response_bytes": len(observation.body),
        "request_ref": {
            "method": pair.method,
            "route_template": pair.route_template,
            "host": host,
            "credential": _REDACTED.decode("ascii"),
        },
        "response_ref": observation.evidence_ref,
    }


def _finding(
    plan: _Plan, outcome: _PairOutcome, *, run_id: str, attempt_id: str,
) -> AbuseVector:
    pair, verdict = outcome.pair, outcome.verdict
    assert verdict.evidence_state is not None and outcome.lower and outcome.higher
    likelihood, impact, uncertainty = _SEVERITY[verdict.evidence_state]
    reachable = verdict.evidence_state in {"verified", "observed"}
    vector_id = "pdv-" + hashlib.sha256(
        f"{run_id}:{pair.method}:{pair.route_template}".encode("utf-8")
    ).hexdigest()[:12]
    reproduction = {
        "contained": True,
        "sample": "canary_only",
        "evidence_state": verdict.evidence_state,
        # Copied from the executor result; a pair with any other disposition stores nothing.
        "execution_disposition": outcome.execution_disposition,
        "predicate": verdict.predicate,
        "reason": verdict.reason,
        "candidate": verdict.candidate,
        "hypothesis": (
            "export_without_entitlement" if pair.marker is not None
            else "endpoint_without_plan_gate"
        ),
        "operator_declared": False,
        "observations": [
            _observation_view(outcome.lower, plan.identities[0], pair, plan.host),
            _observation_view(outcome.higher, plan.identities[1], pair, plan.host),
        ],
        "observed": {
            "predicate": verdict.predicate,
            "method": pair.method,
            "route_template": pair.route_template,
            "base_origin": plan.origin,
            "scope_id": plan.scope_id,
            "plans": [identity.public() for identity in plan.identities],
            "marker_supplied": pair.marker is not None,
            "fixture_bindings_sha256": pair.bindings_sha256,
            "inventory_source_digest": plan.inventory["source_digest"] if plan.inventory else None,
            "lower_status": outcome.lower.status,
            "higher_status": outcome.higher.status,
        },
        "attempt_id": attempt_id,
        "runner_run_ids": [outcome.runner_run_id],
        "plan_sha256": plan.plan_sha256,
        "provenance": {
            "kind": "plan_differential_execution",
            "network_calls": True,
            "target_verification": "signed_local_scope_only",
        },
    }
    return AbuseVector(
        id=vector_id,
        scenario_id=SCENARIO_PREFIX + verdict.predicate,
        category=Category.LICENSE_ENTITLEMENT,
        reproduction=reproduction,
        severity=Severity(likelihood, impact, uncertainty),
        reachability_score=1.0 if reachable else 0.3,
        plausible=reachable,
        recommended_control=_RECOMMENDED_CONTROL,
        target_id=plan.origin,
        affordance_id=f"{pair.method} {pair.route_template}",
        notes=_OBSERVED_NOTE if verdict.evidence_state == "observed" else "",
    )


def _execute(
    plan: _Plan, *, caller: str, attempt: str | None, db: Store,
) -> tuple[dict[str, Any], list[_PairOutcome]]:
    if (
        not plan.authorized
        or plan.context_state != "already_bound"
        or plan.setup is None
        or plan.inventory is None
        or len(plan.identities) != 2
        or not plan.pairs
    ):
        raise PlanDifferentialRejected("nothing is authorized and planned for execution")
    attempt_id = secrets.token_hex(16) if attempt is None else attempt
    # Nothing above this line touches the network; nothing below runs without it.
    reservation = _reserve_attempt(attempt_id)
    run_id = "pdrun-" + attempt_id
    log: _RunLog | None = None
    vault: _PlanVault | None = None
    try:
        db.add_run(run_id, plan.scope_id, plan.origin, caller, "running", time.time())
        log = _RunLog(ContainmentLog(db, run_id, caller))
        log.append("run_start", {
            "kind": "plan_differential", "scope_id": plan.scope_id, "target": plan.origin,
            "attempt": attempt_id, "plan_sha256": plan.plan_sha256,
            "pairs_planned": len(plan.pairs), "effective_max_ops": plan.effective_max_ops,
            "canary_only": True,
        })
        signer = _EphemeralSigner()
        identity = _ephemeral_identity(signer)
        store = _RedactingRunnerStore(reservation.root)
        store.bind_context(
            _context(plan.origin, plan.host), identity=identity, signer=signer,
            signer_label=_SIGNER_LABEL,
        )
        store.replace_routes(
            plan.inventory["routes"], source_digest=plan.inventory["source_digest"],
        )
        vault = _PlanVault(store)
        for planned in plan.identities:
            record = store.register_ephemeral_credential(
                semantic_role=planned.role, auth_profile=planned.record["auth_profile"],
                source_kind="environment", label=planned.role.replace("_", " "),
            )
            vault.bind(record["credential_handle_id"], planned.record)
        authority = SigningAuthority.generate()
        executor = LocalCanaryExecutor(
            store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key},
            vaults={_PlanVault.backend_id: vault},
        )
        cancellation = CancellationToken()
        budget = _Budget(plan.effective_max_ops)
        labels = {planned.role: planned.label for planned in plan.identities}

        def authorized() -> bool:
            try:
                return _authorize(plan.scope_id, plan.host)[1]
            except PlanDifferentialRejected:
                return False

        client: Any = None
        preflight: str | None = None
        stopped = False
        try:
            # One DNS preflight pins the address set for the whole invocation.
            client = _build_client(plan.origin)
        except TransportFailure as failure:
            preflight = "transport:" + failure.code

        outcomes: list[_PairOutcome] = []
        for ordinal, pair in enumerate(plan.pairs):
            # A pair that never starts is inconclusive with a row-1 reason and is also
            # listed as not executed; both reason lists are closed.
            unstarted: tuple[str, str] | None = None
            if preflight is not None:
                unstarted, preflight, stopped = (preflight, "run_stopped"), None, True
            elif stopped:
                unstarted = ("stopped", "run_stopped")
            elif budget.remaining < 2:
                unstarted = ("budget_exhausted", "budget_exhausted")
            elif not authorized():
                unstarted, stopped = ("stopped", "run_stopped"), True
            if unstarted is not None:
                outcome = _PairOutcome(
                    pair, _row_one(unstarted[0]), "not_started",
                    not_executed_reason=unstarted[1],
                )
            else:
                outcome = _run_pair(
                    plan, pair, ordinal, attempt_id=attempt_id, store=store,
                    identity=identity, signer=signer, authority=authority, executor=executor,
                    client=client, reservation=reservation, authorized=authorized,
                    budget=budget, log=log, labels=labels, cancellation=cancellation,
                )
            outcomes.append(outcome)
            log.append("plan_differential_pair", {
                "method": pair.method,
                "route_template": pair.route_template,
                "runner_run_id": outcome.runner_run_id,
                "verdict": outcome.verdict.verdict,
                "predicate": outcome.verdict.predicate,
                "reason": outcome.verdict.reason,
                "execution_disposition": outcome.execution_disposition,
            })
            # Only a completed, verified or observed finding is stored or counted.
            if (
                outcome.verdict.stores_finding
                and outcome.verdict.verdict == "finding"
                and outcome.verdict.evidence_state in {"verified", "observed"}
                and outcome.execution_disposition == "completed"
            ):
                finding = _finding(plan, outcome, run_id=run_id, attempt_id=attempt_id)
                db.add_finding(run_id, finding)
                outcome.finding_id = finding.id
                log.append("finding", {
                    "vector_id": finding.id,
                    "scenario_id": finding.scenario_id,
                    "evidence_state": outcome.verdict.evidence_state,
                    "canary_only": True,
                })
            if not outcome.continues:
                stopped = True

        skipped = list(plan.not_executed) + [
            {
                "method": outcome.pair.method,
                "route_template": outcome.pair.route_template,
                "reason": outcome.not_executed_reason,
            }
            for outcome in outcomes if outcome.not_executed_reason is not None
        ]
        findings = [
            {
                "id": outcome.finding_id,
                "predicate": outcome.verdict.predicate,
                "evidence_state": outcome.verdict.evidence_state,
                "method": outcome.pair.method,
                "route_template": outcome.pair.route_template,
            }
            for outcome in outcomes if outcome.finding_id is not None
        ]
        db.set_run_status(run_id, "complete")
        log.append("run_complete", {
            "requests_sent": budget.used, "findings": len(findings),
            "pairs": len(outcomes), "canary_only": True,
        })
        report_path = reservation.root / "report.json"
        result = {
            "mode": "executed",
            "run_id": run_id,
            "attempt_id": attempt_id,
            "scope_id": plan.scope_id,
            "origin": plan.origin,
            "plan_sha256": plan.plan_sha256,
            "requests_sent": budget.used,
            "effective_max_ops": plan.effective_max_ops,
            "pairs": [outcome.public() for outcome in outcomes],
            "not_executed": skipped,
            "findings": findings,
            "chain_valid": (
                verify_chain(db)[0] and all(outcome.chain_valid for outcome in outcomes)
            ),
            "report_path": str(report_path),
        }
        report = {
            **result,
            "plans": [planned.public() for planned in plan.identities],
            "observations": [
                {
                    "method": outcome.pair.method,
                    "route_template": outcome.pair.route_template,
                    "observations": [
                        _observation_view(observation, planned, outcome.pair, plan.host)
                        for observation, planned in zip(
                            (outcome.lower, outcome.higher), plan.identities, strict=True,
                        )
                        if observation is not None
                    ],
                }
                for outcome in outcomes
            ],
            "uploaded": False,
        }
        # The report holds only redacted references. Raw evidence stays in the attempt store.
        descriptor = os.open(
            report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
        with os.fdopen(descriptor, "w") as output:
            json.dump(report, output, indent=2, sort_keys=True)
        return result, outcomes
    except BaseException:
        try:
            db.set_run_status(run_id, "rejected", error="plan-differential run failed")
            (log or _RunLog(ContainmentLog(db, run_id, caller))).append(
                "run_failed", {"reason": "internal_failure", "canary_only": True},
            )
        except Exception:
            pass
        raise
    finally:
        if vault is not None:
            vault.close()


def _run_pair(
    plan: _Plan,
    pair: _Pair,
    ordinal: int,
    *,
    attempt_id: str,
    store: _RedactingRunnerStore,
    identity: RunnerIdentity,
    signer: SecureSigner,
    authority: SigningAuthority,
    executor: LocalCanaryExecutor,
    client: Any,
    reservation: _AttemptReservation,
    authorized: Callable[[], bool],
    budget: _Budget,
    log: _RunLog,
    labels: Mapping[str, str],
    cancellation: CancellationToken,
) -> _PairOutcome:
    run_suffix = f"{attempt_id}_{ordinal:02d}"
    runner_run_id = "crun_" + run_suffix
    try:
        now = int(time.time() * 1000)
        compiled = CanaryCompiler(
            store=store, identity=identity, signer=signer, now_ms=now,
        ).compile_plan_differential_pair(
            method=pair.method, route_template=pair.route_template,
            fixture_bindings=pair.fixture_bindings,
        )
        transport = _ScopedTransport(
            client, compiled=compiled, reservation=reservation, authorize=authorized,
            budget=budget, log=log, labels=labels, runner_run_id=runner_run_id,
            secrets=store.registered_secrets,
        )
        grant = _grant(
            compiled.manifest, compiled.projection, identity, authority, run_suffix,
            plan.scope_id, now,
        )
        result = executor.execute(
            ExecutionBundle(compiled.manifest, compiled.projection, grant),
            transport=transport, gate_source=_gate(plan.scope_id, plan.host, now),
            cancellation=cancellation,
        )
    except Exception:
        # The executor refused before producing a result: nothing was sent for this pair.
        return _PairOutcome(
            pair, _row_one("executor_rejected"), "not_started", continues=False,
            not_executed_reason="run_stopped",
        )

    disposition = result.execution_disposition
    error_category = result.operational_projection["error_category"]
    lower, higher = (
        _load_observations(store, runner_run_id, result) if disposition == "completed"
        else (None, None)
    )
    verdict = evaluate_plan_pair(
        lower, higher, method=pair.method, marker=pair.marker,
        executor_outcome=ExecutorOutcome(
            disposition, result.assessment_outcome,
            _failure_reason(disposition, error_category, transport),
        ),
    )
    chain_valid = True
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        verify_containment_chain(
            store.load_run_events(runner_run_id),
            public_key=Ed25519PublicKey.from_public_bytes(signer.public_key),
            runner_key_id=identity.key_id, run_id=runner_run_id, grant_id=grant["grant_id"],
            manifest_digest=compiled.manifest["manifest_digest"],
        )
    except Exception:
        chain_valid = False
    return _PairOutcome(
        pair, verdict, disposition, runner_run_id=runner_run_id, lower=lower, higher=higher,
        chain_valid=chain_valid,
        continues=disposition == "completed" or (
            disposition == "failed" and error_category == "containment_rejected"
        ),
    )


def run_plan_differential(
    scope_id: str,
    base_url: str,
    plans: Sequence[tuple[str, str]],
    *,
    caller: str,
    routes_artifact: Mapping[str, Any] | None = None,
    max_ops: int = DEFAULT_MAX_OPS,
    attempt: str | None = None,
) -> dict[str, Any]:
    """Execute every planned pair once per identity and return the executed object.

    A host outside the scope allowlist returns the forced dry-run object and sends nothing.
    """
    caller = _require_caller(caller)
    db = _open_db()
    try:
        if len(_plan_arguments(plans)) != 2:
            raise PlanDifferentialRejected("execution requires exactly two plans")
        plan = _prepare(
            scope_id, base_url, plans, caller=caller, routes_artifact=routes_artifact,
            max_ops=max_ops, bind=False, db=db,
        )
        if not plan.authorized:
            return _forced_dry_run(plan, db, caller)
        return _execute(plan, caller=caller, attempt=attempt, db=db)[0]
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Regression replay
# --------------------------------------------------------------------------- #
def _replay_record(
    regression: Mapping[str, Any], *, scope_id: str, target: str, run_id: str | None,
    result: str, current_status: str, summary: str,
) -> dict[str, Any]:
    return {
        "regression_id": regression["regression_id"],
        "name": regression["name"],
        "source_run_id": regression["source_run_id"],
        "original_vector_id": regression["original_vector_id"],
        "scenario_id": regression["scenario_id"],
        "scope_id": scope_id,
        "target": target,
        "run_id": run_id,
        "previously_reachable": True,
        "result": result,
        "current_status": current_status,
        "control_likely": {
            "blocked": "present", "still_reachable": "absent",
        }.get(current_status, "unknown"),
        "expected_status": regression["expected_status"],
        "matches_expected": current_status == regression["expected_status"],
        "evidence_summary": summary,
        "created_at": time.time(),
        "safety_flags": dict(regression["safety_flags"]),
    }


def replay_plan_differential(
    store: Store,
    regression: Mapping[str, Any],
    *,
    scope_id: str,
    target: str,
    caller: str,
) -> dict[str, Any]:
    """Replay one saved pair under the same scope and origin; re-evaluate the saved predicate."""
    caller = _require_caller(caller)

    def record(result: str, status: str, summary: str, run_id: str | None = None):
        return _replay_record(
            regression, scope_id=scope_id, target=target, run_id=run_id, result=result,
            current_status=status, summary=summary,
        )

    mismatch = record(
        "fail", "inconclusive",
        "The saved plan-differential pair could not be replayed exactly as saved; no request "
        "was sent.",
    )
    try:
        vector = store.find_vector(
            regression["original_vector_id"], run_id=regression["source_run_id"],
        )
        saved = vector["reproduction"]["observed"]
        predicate = saved["predicate"]
        saved_plans = saved["plans"]
        if (
            predicate not in PREDICATES
            or regression["scenario_id"] != SCENARIO_PREFIX + predicate
            or target != saved["base_origin"]
            or scope_id != saved["scope_id"]
            or [item["role"] for item in saved_plans] != list(ROLES)
        ):
            return mismatch
        plan = _prepare(
            scope_id, target,
            [(item["label"], item["credential_handle"]) for item in saved_plans],
            caller=caller, routes_artifact=None, max_ops=REPLAY_MAX_OPS, bind=False, db=store,
            only=(saved["method"], saved["route_template"]),
        )
        if (
            not plan.authorized
            or plan.origin != target
            or plan.context_state != "already_bound"
            or len(plan.pairs) != 1
            or plan.pairs[0].bindings_sha256 != saved["fixture_bindings_sha256"]
            or (plan.pairs[0].marker is not None) is not saved["marker_supplied"]
        ):
            return mismatch
    except Exception:
        return mismatch

    incomplete = (
        "The replayed pair did not complete; inspect the run and its containment log."
    )
    try:
        executed, outcomes = _execute(plan, caller=caller, attempt=None, db=store)
    except Exception:
        return record("fail", "inconclusive", incomplete)
    outcome = outcomes[0]
    verdict = outcome.verdict
    run_id = executed["run_id"]
    if outcome.execution_disposition != "completed" or verdict.row == 1:
        return record("fail", "inconclusive", incomplete, run_id)
    # The saved predicate is re-evaluated; an inconclusive finding saved none. Only a pair
    # that is itself a finding still holds: status parity alone (row 8) stays undecided.
    value = None if predicate == "inconclusive" else getattr(verdict, predicate)
    if value is True and verdict.verdict == "finding":
        return record(
            "fail", "still_reachable",
            f"The saved predicate {predicate} still holds for the lower plan on this read; "
            "reproduction details are omitted.",
            run_id,
        )
    # A pass needs an affirmative denial: the higher plan returned a material body and the
    # lower plan was denied by status without it, or the supplied marker was absent. A 2xx
    # denial body, or a denial status still carrying the payload, is not one.
    if verdict.verdict == "held":
        return record(
            "pass", "blocked",
            "With a valid higher-plan positive control, the lower plan was denied on this "
            "read.",
            run_id,
        )
    return record(
        "fail", "inconclusive",
        f"The saved predicate {predicate} could not be decided on the replayed responses.",
        run_id,
    )


__all__ = [
    "BodyTooComplex", "ExecutorOutcome", "PairVerdict", "PlanDifferentialRejected",
    "PlanObservation", "evaluate_plan_pair", "is_denial_envelope", "key_paths",
    "material_paths", "plan_differential", "replay_plan_differential", "run_plan_differential",
]
