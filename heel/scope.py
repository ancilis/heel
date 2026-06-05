"""
HEEL — authorization scope (spec §6, §10.1). The core of the agent-caller safety model.

An `AuthorizationScope` is created OUT-OF-BAND by a human only — via the CLI, with explicit
confirmation, written as a SIGNED file under `.heel/scopes/`. It is **never** created or
modified through the MCP server, the REST API, or any agent instruction.

Tamper-evidence: the scope file is HMAC-signed over its canonical content. Editing a scope
file by hand (e.g. to add a target or relax a limit) breaks the signature, so a tampered or
widened scope simply fails verification and cannot run. The MCP server only ever READS and
VERIFIES scopes (`load_scopes`, `verify`); it has no write path here by construction.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

from .contracts import AuthorizationScope, DataHandlingMode

def heel_home() -> str:
    return os.environ.get("HEEL_HOME", os.path.join(os.getcwd(), ".heel"))


def _paths():
    home = heel_home()
    return home, os.path.join(home, "signing.key"), os.path.join(home, "scopes")


def _signing_key() -> bytes:
    home, keyfile, _ = _paths()
    os.makedirs(home, exist_ok=True)
    if not os.path.exists(keyfile):
        # created on first out-of-band use; 0600. Demo determinism: stable per repo.
        key = hashlib.sha256(os.urandom(32)).hexdigest().encode()
        with open(keyfile, "wb") as fh:
            fh.write(key)
        os.chmod(keyfile, 0o600)
    with open(keyfile, "rb") as fh:
        return fh.read()


def _canonical(d: dict) -> str:
    """Stable serialization of scope content (excludes the signature) for signing."""
    return json.dumps({
        "scope_id": d["scope_id"],
        "target_allowlist": sorted(d["target_allowlist"]),
        "operator_confirmation": d["operator_confirmation"],
        "rate_and_resource_limits": dict(sorted(d["rate_and_resource_limits"].items())),
        "data_handling_mode": d["data_handling_mode"],
        "expiry": d["expiry"],
        "created_ts": d["created_ts"],
    }, sort_keys=True)


def _sign(content: str) -> str:
    return hmac.new(_signing_key(), content.encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# OUT-OF-BAND creation (CLI only; NEVER reachable from MCP/REST/agent)
# --------------------------------------------------------------------------- #
def create_scope(target_allowlist: list[str], operator: str, limits: dict | None = None,
                 data_mode: DataHandlingMode = DataHandlingMode.SYNTHETIC_ONLY,
                 ttl_seconds: int = 7 * 24 * 3600, now: float | None = None) -> AuthorizationScope:
    home, _, scopedir = _paths()
    os.makedirs(scopedir, exist_ok=True)
    now = now if now is not None else time.time()
    limits = limits or {"max_requests": 200, "max_concurrency": 8, "backoff": True}
    body = {
        "scope_id": "scope-" + hashlib.sha1(f"{operator}{sorted(target_allowlist)}{now}".encode()).hexdigest()[:10],
        "target_allowlist": list(target_allowlist),
        "operator_confirmation": operator,
        "rate_and_resource_limits": limits,
        "data_handling_mode": data_mode.value,
        "expiry": now + ttl_seconds,
        "created_ts": now,
    }
    body["signature"] = _sign(_canonical(body))
    with open(os.path.join(scopedir, body["scope_id"] + ".json"), "w") as fh:
        json.dump(body, fh, indent=2)
    return _from_dict(body)


def _from_dict(d: dict) -> AuthorizationScope:
    return AuthorizationScope(
        scope_id=d["scope_id"], target_allowlist=list(d["target_allowlist"]),
        operator_confirmation=d["operator_confirmation"], signature=d["signature"],
        rate_and_resource_limits=dict(d["rate_and_resource_limits"]),
        data_handling_mode=DataHandlingMode(d["data_handling_mode"]),
        expiry=d["expiry"], created_ts=d.get("created_ts", 0.0),
    )


# --------------------------------------------------------------------------- #
# READ + VERIFY (the only operations the MCP server performs on scopes)
# --------------------------------------------------------------------------- #
def load_scopes() -> list[AuthorizationScope]:
    _, _, scopedir = _paths()
    if not os.path.isdir(scopedir):
        return []
    out = []
    for fn in sorted(os.listdir(scopedir)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(scopedir, fn)) as fh:
                d = json.load(fh)
            out.append(_from_dict(d))
        except Exception:
            continue
    return out


def get_scope(scope_id: str) -> AuthorizationScope | None:
    for s in load_scopes():
        if s.scope_id == scope_id:
            return s
    return None


def verify(scope: AuthorizationScope, now: float | None = None) -> tuple[bool, str]:
    """Signature intact (tamper-evident) + bound to an approver + not expired."""
    now = now if now is not None else time.time()
    body = {
        "scope_id": scope.scope_id, "target_allowlist": scope.target_allowlist,
        "operator_confirmation": scope.operator_confirmation,
        "rate_and_resource_limits": scope.rate_and_resource_limits,
        "data_handling_mode": scope.data_handling_mode.value,
        "expiry": scope.expiry, "created_ts": scope.created_ts,
    }
    if not hmac.compare_digest(scope.signature, _sign(_canonical(body))):
        return False, "signature invalid (scope tampered or unsigned)"
    if not scope.operator_confirmation:
        return False, "scope not bound to an approver"
    if now > scope.expiry:
        return False, "scope expired"
    return True, "ok"


def target_in_scope(scope: AuthorizationScope, target: str) -> bool:
    return target in scope.target_allowlist
