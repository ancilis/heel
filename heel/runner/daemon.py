"""Runner-side pairing lifecycle: ``heel runner pair``, ``status`` and ``unpair``.

This module only composes existing authority. The ceremony is the server's
invite → exchange → human approve (phrase + fingerprint) → activate protocol; the signed
local journal, paired identity and runtime cursor are the existing ``RunnerStore`` and
``RunnerRuntimeState`` records; the Ed25519 seed lives only in the OS secret store behind
``SystemSecureSigner``; every network call is ``HTTPSControlTransport`` to one origin.

The small daemon record (``$HEEL_HOME/runner-daemon/pairing.json``) holds only public
coordinates: the pinned origin, the random installation ID that names the OS secret-store
account, and the IDs the cloud assigned. It never holds key material, tokens or labels.

No ``serve`` loop exists here yet (T2b). Test code may inject a secret backend or an
explicit CA bundle through the constructor; the CLI never passes either.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id, load_public_key_base64
from heel.scope import heel_home

from . import identity as _identity
from .catalog import CATALOG
from .control_client import RunnerControlClient
from .control_transport import ControlTransportError, HTTPSControlTransport, validate_control_origin
from .identity import (
    LinuxSecretServiceBackend, MacOSKeychainSecretBackend, OSSecretBackend, SystemSecureSigner,
    create_runner_pairing_material, runner_pairing_signer_label,
)
from .runtime import RunnerRuntimeState, RunnerRuntimeStateError
from .store import (
    PLAN_LABEL_ROLES, RunnerStore, RunnerStoreError, _flock, _open_child, _read_json,
    _secure_directory, _write_json,
)


_DAEMON_DIRECTORY = "runner-daemon"
_DAEMON_RECORD = "pairing.json"
_DAEMON_RECORD_SCHEMA = "heel.runner-daemon-pairing.v1"
_RUNTIME_FILENAME = "runtime.sqlite3"
_STORE_PAIRING_FILES = (
    "paired-identity.json", "pairing-activation.json", "pairing-activation-abort-request.json",
)
_INVITATION = re.compile(r"^[A-Za-z0-9+/]{43}=$", flags=re.ASCII)
_PAIRING_ID = re.compile(r"^pending_[0-9a-f]{32}$", flags=re.ASCII)
_RUNNER_ID = re.compile(r"^runr_[0-9a-f]{32}$", flags=re.ASCII)
_PENDING_V3_FIELDS = frozenset({
    "schema_version", "pairing_id", "runner_id", "fingerprint", "status",
    "activation_challenge", "control_protocol", "pairing_exchange_digest",
    "challenge_expires_at_ms",
})
_RECORD_FIELDS = frozenset({
    "schema_version", "state", "origin", "installation_id", "display_name", "created_at_ms",
    "pairing_id", "runner_id", "workspace_id", "runner_key_id", "fingerprint",
})
# Written with an active record from a v4 activation. A record without both (paired before the
# grant-authority bootstrap) stays loadable so it can be inspected and unpaired.
_AUTHORITY_FIELDS = frozenset({"grant_authority_key_id", "grant_authority_public_key_b64"})
_REPAIR_STEPS = ["heel runner unpair", "heel runner pair --origin <origin> --invite <new token>"]
_PLAN_ROLES = ("lower_plan", "higher_plan")
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
NO_SECRET_SERVICE = "no supported runner OS secret service"


class RunnerPairingError(RuntimeError):
    """A closed, secret-free pairing lifecycle failure."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


class _RecordOwnershipLost(RunnerPairingError):
    """The daemon record no longer names this pair attempt (unpaired or replaced meanwhile)."""

    def __init__(self):
        super().__init__("local_state_invalid")


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _random_nonce(_key: object) -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _adapter_versions() -> dict[str, str]:
    return {entry["scenario_id"]: entry["adapter_version"] for entry in CATALOG}


def _delete_signer_seed(backend: OSSecretBackend, label: str) -> None:
    """Remove one pairing seed; a missing seed is already removed."""
    delete = getattr(backend, "delete", None)
    if callable(delete):
        delete(label)
        return
    if isinstance(backend, MacOSKeychainSecretBackend):
        result = _identity._run_bounded_security(
            ("delete-generic-password", "-s", backend.service, "-a", backend._label(label)),
            payload=None, popen=backend._popen,
        )
        if result.returncode not in (0, 44):
            raise RuntimeError("runner OS secret service unavailable")
        return
    if isinstance(backend, LinuxSecretServiceBackend):
        result = _identity._run_bounded_secret_tool(
            ("clear", "heel", "runner", "label", backend._label(label)),
            payload=None, popen=backend._popen,
        )
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")
        return
    raise RuntimeError("runner signing key cannot be removed")


def self_serve_access(store: RunnerStore) -> dict[str, Any]:
    """Report whether both plan roles carry operator plan labels (labels only, never handles)."""
    records: list[dict[str, Any]] = []
    if store.is_context_bound:
        records = [item for item in store.list_credentials() if item["state"] == "active"]
    by_role = {item["semantic_role"]: item for item in records if item["semantic_role"] in PLAN_LABEL_ROLES}
    labels = [
        {"role": role, "label": by_role[role]["plan_label"]}
        for role in _PLAN_ROLES if role in by_role and "plan_label" in by_role[role]
    ]
    if len(labels) == len(_PLAN_ROLES):
        return {"state": "access.ready", "plan_labels": labels}
    missing_credential = [role for role in _PLAN_ROLES if role not in by_role]
    return {
        "state": "access.incomplete",
        "reason": "credential_missing" if missing_credential else "plan_label_missing",
        "plan_labels": labels,
        "next_steps": [
            f"heel runner credential add --role {role} --plan-label <your {role.replace('_', '-')} name>"
            " --profile <bearer|cookie_jar|x_api_key> --backend <keychain|secret-service>"
            for role in _PLAN_ROLES if role in missing_credential
        ],
    }


class RunnerDaemon:
    """Pair, inspect and unpair the one local runner identity under ``HEEL_HOME``."""

    def __init__(
        self, root: Path | str | None = None, *,
        secret_backend: OSSecretBackend | None = None,
        ca_bundle: Path | str | None = None,
        clock_ms: Callable[[], int] = _now_ms,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        transport_timeout_seconds: float | None = None,
    ):
        self.root = Path(heel_home()) if root is None else Path(root)
        self._secret_backend = secret_backend
        self._ca_bundle = ca_bundle
        self._clock_ms = clock_ms
        self._sleep = sleep
        self._poll_interval = poll_interval_seconds
        self._transport_timeout = transport_timeout_seconds

    # ------------------------------------------------------------------ local state
    def _store(self) -> RunnerStore:
        return RunnerStore(self.root)

    @property
    def runtime_path(self) -> Path:
        return self._store().root / "runner" / _RUNTIME_FILENAME

    def _transport(self, origin: str) -> HTTPSControlTransport:
        options: dict[str, Any] = {"ca_bundle": self._ca_bundle}
        if self._transport_timeout is not None:
            options["timeout_seconds"] = self._transport_timeout
        return HTTPSControlTransport(origin, **options)

    def _backend(self) -> OSSecretBackend:
        try:
            return SystemSecureSigner._backend(self._secret_backend)
        except RuntimeError:
            raise RunnerPairingError("no_supported_secret_service", NO_SECRET_SERVICE) from None

    def _daemon_fd(self, store: RunnerStore, *, create: bool) -> int | None:
        root_fd = store._open_root(create=create)
        if root_fd is None:
            return None
        try:
            directory = _open_child(root_fd, _DAEMON_DIRECTORY, create=create)
            if directory is not None:
                _secure_directory(directory, "Heel runner daemon directory")
            return directory
        finally:
            os.close(root_fd)

    def _load_record(self, store: RunnerStore) -> dict[str, Any] | None:
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            return None
        try:
            with _flock(directory, ".daemon.lock", exclusive=False):
                value = _read_json(directory, _DAEMON_RECORD, None)
        finally:
            os.close(directory)
        if value is None:
            return None
        return self._validate_record(value)

    @staticmethod
    def _validate_record(value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) not in (_RECORD_FIELDS, _RECORD_FIELDS | _AUTHORITY_FIELDS):
            raise RunnerPairingError("local_state_invalid")
        record = dict(value)
        if _AUTHORITY_FIELDS <= set(record) and (
            record["state"] != "active"
            or not all(type(record[field]) is str for field in _AUTHORITY_FIELDS)
        ):
            raise RunnerPairingError("local_state_invalid")
        try:
            validate_control_origin(record["origin"])
            runner_pairing_signer_label(record["installation_id"])
        except (ControlTransportError, ValueError):
            raise RunnerPairingError("local_state_invalid") from None
        if (
            record["schema_version"] != _DAEMON_RECORD_SCHEMA
            or record["state"] not in {"preparing", "exchanged", "active"}
            or type(record["created_at_ms"]) is not int
            or type(record["display_name"]) is not str
        ):
            raise RunnerPairingError("local_state_invalid")
        if record["state"] == "active" and not all(
            type(record[field]) is str and record[field]
            for field in ("pairing_id", "runner_id", "workspace_id", "runner_key_id", "fingerprint")
        ):
            raise RunnerPairingError("local_state_invalid")
        return record

    @staticmethod
    def _grant_authority(record: Mapping[str, Any]) -> dict[str, str] | None:
        """The record's cloud grant-signing key, or None when absent or inconsistent."""
        if not _AUTHORITY_FIELDS <= set(record):
            return None
        key_id, public_key_b64 = record["grant_authority_key_id"], record["grant_authority_public_key_b64"]
        try:
            if len(public_key_b64) != 44:
                return None
            load_public_key_base64(public_key_b64)
            if ed25519_key_id(base64.b64decode(public_key_b64, validate=True)) != key_id:
                return None
        except (TypeError, ValueError):
            return None
        return {"key_id": key_id, "public_key_b64": public_key_b64}

    def _reserve_record(self, store: RunnerStore, record: Mapping[str, Any]) -> None:
        """Check for local pairing state and write this attempt's record in one critical section."""
        validated = self._validate_record(record)
        directory = self._daemon_fd(store, create=True)
        assert directory is not None
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                existing = _read_json(directory, _DAEMON_RECORD, None)
                if existing is not None:
                    existing = self._validate_record(existing)
                    raise RunnerPairingError(
                        "already_paired" if existing["state"] == "active" else "pairing_incomplete",
                    )
                if self._store_pairing_files(store) or store.is_context_bound:
                    raise RunnerPairingError("local_state_invalid")
                _write_json(directory, _DAEMON_RECORD, validated)
        finally:
            os.close(directory)

    def _write_record(self, store: RunnerStore, record: Mapping[str, Any]) -> None:
        """Update this attempt's record; never write over another attempt's or a removed one."""
        validated = self._validate_record(record)
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            raise _RecordOwnershipLost()
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                current = _read_json(directory, _DAEMON_RECORD, None)
                if not isinstance(current, Mapping) or current.get("installation_id") != validated["installation_id"]:
                    raise _RecordOwnershipLost()
                _write_json(directory, _DAEMON_RECORD, validated)
        finally:
            os.close(directory)

    def _remove_record(self, store: RunnerStore, installation_id: str) -> bool:
        """Remove the record only while it still names ``installation_id``."""
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            return False
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                current = _read_json(directory, _DAEMON_RECORD, None)
                if not isinstance(current, Mapping) or current.get("installation_id") != installation_id:
                    return False
                os.unlink(_DAEMON_RECORD, dir_fd=directory)
                os.fsync(directory)
                return True
        finally:
            os.close(directory)

    @staticmethod
    def _store_pairing_files(store: RunnerStore) -> list[str]:
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                return [name for name in _STORE_PAIRING_FILES if _read_json(runner_fd, name, None) is not None]

    # ------------------------------------------------------------------ pair
    def pair(
        self, origin: str, invitation_token: str, *, display_name: str | None = None,
        emit: Callable[[dict[str, Any]], None] = lambda _event: None,
    ) -> dict[str, Any]:
        try:
            origin = validate_control_origin(origin)[0]
        except ControlTransportError:
            raise RunnerPairingError("invalid_origin") from None
        if type(invitation_token) is not str or _INVITATION.fullmatch(invitation_token) is None:
            raise RunnerPairingError("invalid_invitation")
        name = display_name or "Heel runner"
        store = self._store()
        existing = self._load_record(store)
        if existing is not None:
            raise RunnerPairingError(
                "already_paired" if existing["state"] == "active" else "pairing_incomplete",
            )
        if self._store_pairing_files(store) or store.is_context_bound:
            raise RunnerPairingError("local_state_invalid")
        backend = self._backend()
        transport = self._transport(origin)
        installation_id = secrets.token_hex(16)
        label = runner_pairing_signer_label(installation_id)
        record: dict[str, Any] = {
            "schema_version": _DAEMON_RECORD_SCHEMA, "state": "preparing", "origin": origin,
            "installation_id": installation_id, "display_name": name,
            "created_at_ms": self._clock_ms(), "pairing_id": None, "runner_id": None,
            "workspace_id": None, "runner_key_id": None, "fingerprint": None,
        }
        # The record is reserved before the seed so an interrupted pair can always be unpaired,
        # and a concurrent pair on this HEEL_HOME either sees it or is seen by it.
        self._reserve_record(store, record)
        exchanged = seed_created = False
        try:
            try:
                signer = SystemSecureSigner.create_new(label, backend=backend)
            except (RuntimeError, ValueError):
                raise RunnerPairingError("no_supported_secret_service", NO_SECRET_SERVICE) from None
            seed_created = True
            # Pair only a key the OS store can give back: a seed that does not reload to the same
            # key would activate a runner whose identity is lost on the next restart.
            try:
                reloaded = SystemSecureSigner.load_existing(label, backend=backend)
            except (RuntimeError, ValueError):
                reloaded = None
            if reloaded is None or reloaded.key_id != signer.key_id:
                raise RunnerPairingError("secret_store_unverified")
            from heel import __version__
            material = create_runner_pairing_material(
                name, __version__, _adapter_versions(), signer,
            )
            exchange = material.executable_exchange_request(invitation_token)
            exchange_bytes = canonical_bytes(exchange)
            pending = self._exchange(transport, exchange_bytes, material.fingerprint)
            exchanged = True
            record.update(state="exchanged", pairing_id=pending["pairing_id"], runner_id=pending["runner_id"])
            self._write_record(store, record)
            emit({
                "event": "pairing_pending", "pairing_id": pending["pairing_id"],
                "pairing_phrase": " ".join(material.pairing_phrase),
                "fingerprint": material.fingerprint,
                "approve_before_ms": pending["challenge_expires_at_ms"],
            })
            try:
                activation = material.prepare_executable_activation(
                    pending, store=store, now_ms=self._clock_ms(),
                )
            except (RunnerStoreError, ValueError):
                raise RunnerPairingError("local_state_invalid") from None
            response = self._await_activation(
                transport, pending["pairing_id"], canonical_bytes(dict(activation.request)),
                deadline_ms=pending["challenge_expires_at_ms"],
            )
            try:
                identity = store.accept_pairing_activation(activation, response, now_ms=self._clock_ms())
                runtime = RunnerRuntimeState(self.runtime_path, identity, signer)
                try:
                    store.finish_pairing_activation(runtime)
                finally:
                    runtime.close()
            except (RunnerStoreError, RunnerRuntimeStateError, ValueError):
                raise RunnerPairingError("response_rejected") from None
            # ``accept_pairing_activation`` validated this exact response (v4 only), including the
            # derived key ID; the record keeps the same public key for status and serve.
            authority = response["grant_authority"]
            authority = self._grant_authority({
                "grant_authority_key_id": authority["key_id"],
                "grant_authority_public_key_b64": authority["public_key_b64"],
            })
            if authority is None:
                raise RunnerPairingError("response_rejected")
        except BaseException as error:
            if not exchanged or isinstance(error, _RecordOwnershipLost):
                # Nothing reached the cloud's pairing state, or no record names this seed any more
                # (a concurrent unpair removed it): drop the seed, then our record if it is still
                # ours. If the seed cannot be removed the record stays so unpair can retry.
                try:
                    if seed_created:
                        _delete_signer_seed(backend, label)
                    self._remove_record(store, installation_id)
                except Exception:
                    pass
            raise
        record.update(
            state="active", workspace_id=identity.workspace_id, runner_id=identity.runner_id,
            runner_key_id=identity.key_id, fingerprint=identity.fingerprint,
            grant_authority_key_id=authority["key_id"],
            grant_authority_public_key_b64=authority["public_key_b64"],
        )
        try:
            self._write_record(store, record)
        except _RecordOwnershipLost:
            try:
                _delete_signer_seed(backend, label)
            except Exception:
                pass
            raise
        result = {
            "event": "paired", "state": "active", "origin": origin,
            "workspace_id": identity.workspace_id, "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id, "fingerprint": identity.fingerprint,
        }
        emit(result)
        return result

    @staticmethod
    def _exchange(transport: HTTPSControlTransport, body: bytes, fingerprint: str) -> dict[str, Any]:
        try:
            status, _headers, payload = transport.post(
                "/v1/runner-pairings/exchange", headers={"Content-Type": "application/json"}, body=body,
            )
        except ControlTransportError as error:
            raise RunnerPairingError(error.code) from None
        if status == 400:
            # One-time, expired, wrong-workspace or reused invitations are indistinguishable.
            raise RunnerPairingError("invitation_rejected")
        if (
            status != 201 or not isinstance(payload, dict) or set(payload) != _PENDING_V3_FIELDS
            or payload["schema_version"] != "heel.runner-pairing-pending.v3"
            or type(payload["pairing_id"]) is not str or _PAIRING_ID.fullmatch(payload["pairing_id"]) is None
            or type(payload["runner_id"]) is not str or _RUNNER_ID.fullmatch(payload["runner_id"]) is None
            or payload["fingerprint"] != fingerprint or payload["status"] != "pending"
            or payload["control_protocol"] != "heel.runner-control.v2"
            or payload["pairing_exchange_digest"] != hashlib.sha256(body).hexdigest()
            or type(payload["challenge_expires_at_ms"]) is not int
            or payload["challenge_expires_at_ms"] <= 0
        ):
            raise RunnerPairingError("response_rejected")
        return dict(payload)

    def _await_activation(
        self, transport: HTTPSControlTransport, pairing_id: str, body: bytes, *, deadline_ms: int,
    ) -> dict[str, Any]:
        """Resend the one sealed activation until the human approves or the challenge expires."""
        path = f"/v1/runner-pairings/{pairing_id}/activate"
        while True:
            try:
                status, _headers, payload = transport.post(
                    path, headers={"Content-Type": "application/json"}, body=body,
                )
            except ControlTransportError as error:
                if error.code not in {"connection_failed", "timeout"}:
                    raise RunnerPairingError(error.code) from None
                status, payload = None, None
            if status == 200 and isinstance(payload, dict):
                return payload
            if status not in {None, 400}:
                raise RunnerPairingError("approval_timeout" if status == 410 else "response_rejected")
            if self._clock_ms() >= deadline_ms:
                raise RunnerPairingError("approval_timeout")
            self._sleep(self._poll_interval)

    # ------------------------------------------------------------------ status
    def _active_identity(self, store: RunnerStore, record: Mapping[str, Any]):
        label = runner_pairing_signer_label(record["installation_id"])
        backend = self._backend()
        try:
            signer = SystemSecureSigner.load_existing(label, backend=backend)
        except (RuntimeError, ValueError):
            raise RunnerPairingError("local_identity_unavailable") from None
        if signer.key_id != record["runner_key_id"]:
            raise RunnerPairingError("local_identity_unavailable")
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                paired = _read_json(runner_fd, "paired-identity.json", None)
        try:
            if not isinstance(paired, Mapping):
                raise RunnerStoreError("paired runner identity requires recovery")
            identity = RunnerStore._rotation_identity_from_record(paired.get("identity"), pairing_phrase=())
            RunnerStore._verify_paired_rotation_identity(paired, identity=identity, signer=signer)
        except RunnerStoreError:
            raise RunnerPairingError("local_identity_unavailable") from None
        if (
            identity.runner_id != record["runner_id"] or identity.workspace_id != record["workspace_id"]
            or identity.fingerprint != record["fingerprint"]
        ):
            raise RunnerPairingError("local_identity_unavailable")
        return identity, signer

    def status(self, *, check_control_plane: bool = True) -> dict[str, Any]:
        store = self._store()
        record = self._load_record(store)
        if record is None:
            return {"state": "unpaired"}
        if record["state"] != "active":
            return {
                "state": "pairing_incomplete", "origin": record["origin"],
                "next_steps": list(_REPAIR_STEPS),
            }
        coordinates = {
            "origin": record["origin"], "workspace_id": record["workspace_id"],
            "runner_id": record["runner_id"], "runner_key_id": record["runner_key_id"],
            "fingerprint": record["fingerprint"],
        }
        authority = self._grant_authority(record)
        if authority is None:
            # Paired before the grant-authority bootstrap (or the key is inconsistent): nothing the
            # cloud signs can be verified, so no secret store or network is touched. Re-pair.
            return {"state": "cloud_authority_missing", **coordinates, "next_steps": list(_REPAIR_STEPS)}
        coordinates["grant_authority_key_id"] = authority["key_id"]
        try:
            identity, signer = self._active_identity(store, record)
        except RunnerPairingError as error:
            return {"state": error.code, **coordinates}
        result: dict[str, Any] = {"state": "active", **coordinates}
        try:
            result["access"] = self_serve_access(store)
        except (RunnerStoreError, ValueError):
            result["access"] = {"state": "access.incomplete", "reason": "local_state_invalid"}
        if not check_control_plane:
            result["control_plane"] = {"state": "not_checked"}
            return result
        try:
            runtime = RunnerRuntimeState(self.runtime_path, identity, signer)
        except RunnerRuntimeStateError:
            return {"state": "local_identity_unavailable", **coordinates}
        try:
            result["control_plane"] = self._live_check(record, identity, signer, runtime)
        finally:
            runtime.close()
        if result["control_plane"]["state"] == "rejected" and result["control_plane"].get("reason") == "runner_revoked":
            result["state"] = "runner_revoked"
        elif result["control_plane"]["state"] == "unreachable":
            result["state"] = "offline"
        return result

    def _live_check(self, record, identity, signer, runtime) -> dict[str, Any]:
        transport = self._transport(record["origin"])
        try:
            client = RunnerControlClient(
                origin=record["origin"], workspace_id=identity.workspace_id,
                runner_id=identity.runner_id, signer=signer, clock=self._clock_ms,
                transport=transport, nonce_source=_random_nonce, runtime=runtime,
            )
            if runtime.load_pending_calls():
                client.replay_all_pending(now_ms=self._clock_ms())
            listed = client.list_contexts()
        except ControlTransportError as error:
            if error.code in {"connection_failed", "timeout"}:
                return {"state": "unreachable", "reason": error.code}
            return {"state": "rejected", "reason": error.code}
        except (ValueError, RunnerRuntimeStateError):
            if transport.last_status == 401 and transport.last_error_code == "invalid_runner_auth":
                # The control plane no longer accepts this key: revoked (or never known).
                return {"state": "rejected", "reason": "runner_revoked"}
            if transport.last_status == 403 and transport.last_error_code == "runner_protocol_upgrade_required":
                return {"state": "rejected", "reason": "protocol_upgrade_required"}
            return {"state": "rejected", "reason": "response_rejected"}
        return {
            "state": "confirmed", "server_time_ms": listed["server_time_ms"],
            "context_bindings": len(listed["contexts"]),
        }

    # ------------------------------------------------------------------ unpair
    def unpair(self) -> dict[str, Any]:
        """Forget the local identity and remove its OS-stored seed; the owner revokes in Cloud."""
        store = self._store()
        record = self._load_record(store)
        files = self._store_pairing_files(store)
        if record is None and not files:
            return {"state": "unpaired", "removed": False}
        if store.is_context_bound:
            raise RunnerPairingError("context_bound")
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                try:
                    RunnerStore._assert_no_context_authority_locked(runner_fd)
                except RunnerStoreError:
                    raise RunnerPairingError("context_bound") from None
                for name in (*_STORE_PAIRING_FILES, _RUNTIME_FILENAME,
                             *(_RUNTIME_FILENAME + suffix for suffix in ("-wal", "-shm", "-journal"))):
                    try:
                        os.unlink(name, dir_fd=runner_fd)
                    except FileNotFoundError:
                        pass
                os.fsync(runner_fd)
        if record is not None:
            backend = self._backend()
            try:
                _delete_signer_seed(backend, runner_pairing_signer_label(record["installation_id"]))
            except (RuntimeError, ValueError):
                raise RunnerPairingError("secret_removal_failed") from None
            # A record written by a newer pair attempt after our read is left alone.
            self._remove_record(store, record["installation_id"])
        result = {"state": "unpaired", "removed": True}
        if record is not None and record.get("runner_id"):
            result["runner_id"] = record["runner_id"]
            result["next_steps"] = ["Revoke this runner in the Heel dashboard if it is still listed."]
        return result


__all__ = [
    "NO_SECRET_SERVICE", "RunnerDaemon", "RunnerPairingError", "self_serve_access",
]
