"""Signed append-only containment records for customer-local canary execution."""
from __future__ import annotations

import base64
from collections.abc import Mapping
import copy
from typing import Any, Callable

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import ed25519_key_id
from heel.runner.identity import SecureSigner


LOCAL_EVENT_SCHEMA = "heel.local-containment-event.v1"
LOCAL_EVENT_DOMAIN = b"heel.local-containment-event.v1\0"
LOCAL_EVENT_CODES = frozenset({
    "grant_verified", "run_started", "admitted", "action_started", "action_completed",
    "action_rejected", "budget_exhausted", "dns_changed", "stop_observed",
    "response_truncated", "redacted", "run_finalized", "local_result_ready",
})
OPERATIONAL_EVENT_CODES = frozenset({
    "admitted", "action_started", "action_completed", "action_rejected",
    "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted",
})
_CORE_FIELDS = {
    "schema_version", "run_id", "grant_id", "manifest_digest", "sequence",
    "occurred_at_ms", "event_code", "action_ordinal", "scenario_id", "semantic_role",
    "attempt", "detail_code", "counters", "previous_event_digest",
}
_COUNTER_FIELDS = {
    "requests_started", "requests_completed", "response_bytes_read",
    "actions_contained", "retries_used",
}
_FULL_FIELDS = _CORE_FIELDS | {"event_digest", "signing_key_id", "signature_b64"}


class ContainmentError(ValueError):
    """A local containment chain is invalid or has been changed."""


def operational_containment_codes(events: list[Mapping[str, Any]]) -> list[str]:
    return sorted({
        event["event_code"] for event in events
        if isinstance(event, Mapping) and event.get("event_code") in OPERATIONAL_EVENT_CODES
    })


def _identifier(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > 128
        or any(ord(character) < 0x21 or ord(character) == 0x7f for character in value)
    ):
        raise ContainmentError(f"invalid {label}")
    return value


def _digest(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContainmentError(f"invalid {label}")
    return value


def _integer(value: Any, label: str, *, maximum: int = (1 << 53) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ContainmentError(f"invalid {label}")
    return value


def _validate_event(value: Any, *, expected_sequence: int, previous_digest: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FULL_FIELDS:
        raise ContainmentError("invalid containment event fields")
    event = copy.deepcopy(dict(value))
    if event["schema_version"] != LOCAL_EVENT_SCHEMA:
        raise ContainmentError("invalid containment event schema")
    _identifier(event["run_id"], "run ID")
    _identifier(event["grant_id"], "grant ID")
    _digest(event["manifest_digest"], "manifest digest")
    if _integer(event["sequence"], "event sequence", maximum=99_999) != expected_sequence:
        raise ContainmentError("invalid containment event sequence")
    _integer(event["occurred_at_ms"], "event timestamp")
    if event["event_code"] not in LOCAL_EVENT_CODES:
        raise ContainmentError("invalid containment event code")
    nullable = ("action_ordinal", "scenario_id", "semantic_role", "attempt")
    present = [event[field] is not None for field in nullable]
    if any(present) and not all(present):
        raise ContainmentError("incomplete containment action binding")
    if all(present):
        _integer(event["action_ordinal"], "action ordinal", maximum=19)
        _identifier(event["scenario_id"], "scenario ID")
        _identifier(event["semantic_role"], "semantic role")
        _integer(event["attempt"], "attempt", maximum=2)
        if event["attempt"] < 1:
            raise ContainmentError("invalid attempt")
    _identifier(event["detail_code"], "detail code")
    counters = event["counters"]
    if not isinstance(counters, Mapping) or set(counters) != _COUNTER_FIELDS:
        raise ContainmentError("invalid containment counters")
    for name, counter in counters.items():
        maximum = 1 if name == "retries_used" else ((1 << 53) - 1 if name == "response_bytes_read" else 20)
        _integer(counter, f"{name} counter", maximum=maximum)
    if counters["requests_completed"] > counters["requests_started"]:
        raise ContainmentError("invalid containment counters")
    if event["previous_event_digest"] != previous_digest:
        raise ContainmentError("containment chain link mismatch")
    core = {key: event[key] for key in _CORE_FIELDS}
    if event["event_digest"] != canonical_digest(core):
        raise ContainmentError("containment event digest mismatch")
    _identifier(event["signing_key_id"], "signing key ID")
    try:
        signature = base64.b64decode(event["signature_b64"], validate=True)
    except (TypeError, ValueError):
        raise ContainmentError("invalid containment signature") from None
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != event["signature_b64"]:
        raise ContainmentError("invalid containment signature")
    return event


class ContainmentLog:
    """Append and fully verify the signed chain stored under one local run."""

    def __init__(
        self,
        *,
        store: Any,
        signer: SecureSigner,
        run_id: str,
        grant_id: str,
        manifest_digest: str,
        clock_ms: Callable[[], int],
    ):
        if not isinstance(signer, SecureSigner):
            raise ValueError("runner SecureSigner is required")
        if (
            not isinstance(signer.public_key, bytes)
            or len(signer.public_key) != 32
            or signer.key_id != ed25519_key_id(signer.public_key)
        ):
            raise ValueError("runner signer identity is invalid")
        self.store = store
        self.signer = signer
        self.run_id = _identifier(run_id, "run ID")
        self.grant_id = _identifier(grant_id, "grant ID")
        self.manifest_digest = _digest(manifest_digest, "manifest digest")
        self.clock_ms = clock_ms

    def load(self) -> list[dict[str, Any]]:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = Ed25519PublicKey.from_public_bytes(self.signer.public_key)
        previous = "0" * 64
        result: list[dict[str, Any]] = []
        previous_counters = {key: 0 for key in _COUNTER_FIELDS}
        previous_time = 0
        for sequence, raw in enumerate(self.store.load_run_events(self.run_id)):
            event = _validate_event(raw, expected_sequence=sequence, previous_digest=previous)
            if (
                event["run_id"] != self.run_id
                or event["grant_id"] != self.grant_id
                or event["manifest_digest"] != self.manifest_digest
                or event["signing_key_id"] != self.signer.key_id
                or event["occurred_at_ms"] < previous_time
                or any(event["counters"][key] < previous_counters[key] for key in _COUNTER_FIELDS)
            ):
                raise ContainmentError("containment event binding mismatch")
            signed = {
                **{key: event[key] for key in _CORE_FIELDS},
                "event_digest": event["event_digest"],
                "signing_key_id": event["signing_key_id"],
            }
            try:
                public.verify(
                    base64.b64decode(event["signature_b64"], validate=True),
                    LOCAL_EVENT_DOMAIN + canonical_bytes(signed),
                )
            except (InvalidSignature, TypeError, ValueError):
                raise ContainmentError("containment signature verification failed") from None
            if sequence == 0 and event["event_code"] != "grant_verified":
                raise ContainmentError("containment chain must begin with grant verification")
            result.append(event)
            previous = event["event_digest"]
            previous_counters = event["counters"]
            previous_time = event["occurred_at_ms"]
        return result

    def append(
        self,
        event_code: str,
        *,
        detail_code: str,
        action_ordinal: int | None = None,
        scenario_id: str | None = None,
        semantic_role: str | None = None,
        attempt: int | None = None,
        counters: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        if event_code not in LOCAL_EVENT_CODES:
            raise ValueError("invalid containment event code")
        events = self.load()
        previous = events[-1] if events else None
        current_counters = (
            {key: previous["counters"][key] for key in _COUNTER_FIELDS}
            if previous else {key: 0 for key in _COUNTER_FIELDS}
        )
        for name, value in ({} if counters is None else counters).items():
            if name not in _COUNTER_FIELDS:
                raise ValueError("invalid containment counter")
            current_counters[name] = value
        core = {
            "schema_version": LOCAL_EVENT_SCHEMA,
            "run_id": self.run_id,
            "grant_id": self.grant_id,
            "manifest_digest": self.manifest_digest,
            "sequence": len(events),
            "occurred_at_ms": self.clock_ms(),
            "event_code": event_code,
            "action_ordinal": action_ordinal,
            "scenario_id": scenario_id,
            "semantic_role": semantic_role,
            "attempt": attempt,
            "detail_code": detail_code,
            "counters": current_counters,
            "previous_event_digest": previous["event_digest"] if previous else "0" * 64,
        }
        digest = canonical_digest(core)
        signed = {**core, "event_digest": digest, "signing_key_id": self.signer.key_id}
        signature = self.signer.sign(LOCAL_EVENT_DOMAIN + canonical_bytes(signed))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("runner signer returned an invalid containment signature")
        event = {
            **signed,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        _validate_event(
            event, expected_sequence=len(events),
            previous_digest=previous["event_digest"] if previous else "0" * 64,
        )
        self.store.append_run_event(self.run_id, event)
        return event


__all__ = [
    "ContainmentError", "ContainmentLog", "LOCAL_EVENT_CODES", "LOCAL_EVENT_SCHEMA",
    "OPERATIONAL_EVENT_CODES", "operational_containment_codes",
]
