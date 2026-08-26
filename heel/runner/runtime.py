"""Durable, authenticated runner control state.

The runtime database deliberately stores only opaque routing keys and AEAD sealed
state.  It is a local replay barrier, not a second control-plane authority.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
from types import MappingProxyType
from typing import Any, Iterator, Mapping

from heel.canary_contracts import canonical_bytes
from heel.runner.identity import AcceptedRotationJournal, RunnerIdentity, SecureSigner


_SCHEMA_V1 = "heel.runner-runtime-state.v1"
_SCHEMA = "heel.runner-runtime-state.v2"
_SEAL_DOMAIN = b"heel.runner-runtime-state-seal.v1\0"
_STATE_KEY_WRAP_DOMAIN = b"heel.runner-runtime-state-key-wrap.v1\0"
_DIGEST_DOMAIN = b"heel.runner-runtime-state-digest.v1\0"
_MAX_SAFE_INT = 9_007_199_254_740_991
_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_RUN_ID = re.compile(r"^crun_[0-9a-f]{32}$", re.ASCII)
_B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$", re.ASCII)


class RunnerRuntimeStateError(ValueError):
    """Caller-visible runtime-state failure."""


class RunnerRuntimeUnavailable(RuntimeError):
    """The authenticated runtime cannot operate without its cryptographic extra."""


class RunnerRuntimeConflict(RunnerRuntimeStateError):
    """Retryable compare-and-swap, pending-call, or capacity conflict."""


class RunnerRuntimeCorrupt(RunnerRuntimeStateError):
    """A durable record, identity binding, or local invariant is unsafe."""


class TerminalDisclosureUnavailable(RunnerRuntimeStateError):
    """A terminal disclosure has been consumed, pruned, expired, or is absent."""


@dataclass(frozen=True, slots=True)
class _RuntimeCrypto:
    aead: Any
    hashes: Any
    hkdf: Any


def _load_runtime_crypto() -> _RuntimeCrypto:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise RunnerRuntimeUnavailable(
            "authenticated runner runtime requires the 'runner' extra (install heel-sim[runner])"
        ) from None
    return _RuntimeCrypto(aead=ChaCha20Poly1305, hashes=hashes, hkdf=HKDF)


@dataclass(frozen=True, slots=True)
class RunnerChainCursor:
    operation: str
    run_id: str | None
    next_nonce_b64: str
    next_sequence: int
    generation: int
    updated_at_ms: int
    state_digest: str


@dataclass(frozen=True, slots=True)
class PendingSignedCall:
    call_id: str
    request_operation: str
    chain_operation: str
    run_id: str | None
    path: str
    capability: str
    headers: Mapping[str, str]
    body: bytes
    sequence: int
    generation: int
    prior_chain_state_digest: str | None
    created_at_ms: int


@dataclass(frozen=True, slots=True)
class TerminalDisclosureState:
    schema_version: str
    state: str
    workspace_id: str
    runner_id: str
    runner_key_id: str
    run_id: str
    run_hash: str
    project_id: str | None
    grant_id: str | None
    approval_projection_digest: str | None
    terminal_projection_digest: str
    terminal_record_digest: str
    terminal_at_ms: int
    retention_expires_at_ms: int
    result_chain: Mapping[str, Any] | None
    available_at_ms: int | None
    permit_id: str | None
    findings_projection_digest: str | None
    receipt_digest: str | None
    disclosed_at_ms: int | None
    revision: int
    prior_state_digest: str | None
    state_digest: str


class _TerminalDisclosureLease:
    """Nominal, process-local capability minted only by ``lease_terminal_disclosure``."""

    __slots__ = ("_backend", "_token", "_run_hash", "_state_digest", "_lease_id", "_used")

    def __init__(
        self, token: object, backend: "RunnerRuntimeState", run_hash: str,
        state_digest: str, lease_id: bytes,
    ) -> None:
        self._backend = backend
        self._token = token
        self._run_hash = run_hash
        self._state_digest = state_digest
        self._lease_id = lease_id
        self._used = False


def _safe_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_SAFE_INT:
        raise RunnerRuntimeStateError(f"invalid {label}")
    return value


def _text(value: object, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if type(value) is not str or not value or len(value.encode("utf-8")) > 128:
        raise RunnerRuntimeStateError(f"invalid {label}")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RunnerRuntimeStateError(f"invalid {label}")
    return value


def _nonce(value: object, label: str = "runner nonce") -> str:
    if type(value) is not str or _B64_32.fullmatch(value) is None:
        raise RunnerRuntimeStateError(f"invalid {label}")
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError
    except (ValueError, TypeError):
        raise RunnerRuntimeStateError(f"invalid {label}") from None
    return value


def _run_id(value: object, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if type(value) is not str or _RUN_ID.fullmatch(value) is None:
        raise RunnerRuntimeStateError("invalid runner run ID")
    return value


def _run_hash(run_id: str) -> str:
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _state_digest(core: Mapping[str, Any]) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_bytes(dict(core))).hexdigest()


class RunnerRuntimeState:
    """A sealed SQLite replay ledger tied to one exact runner identity."""

    def __init__(
        self, path: Path | str, identity: RunnerIdentity, signer: SecureSigner,
        random_source=os.urandom,
    ) -> None:
        self._crypto = _load_runtime_crypto()
        self.path = Path(path).expanduser().resolve(strict=False)
        self.identity = identity
        self.signer = signer
        self._random_source = random_source
        self._token = object()
        self._state_lock = threading.RLock()
        self._poisoned = False
        self._validate_identity()
        self._kek = self._derive_key()
        self._key = b""
        self._prepare_path()
        with self._connection() as conn:
            self._initialize(conn)

    def _validate_identity(self) -> None:
        self._validate_identity_pair(self.identity, self.signer)

    @staticmethod
    def _validate_identity_pair(identity: RunnerIdentity, signer: SecureSigner) -> None:
        if not isinstance(identity, RunnerIdentity) or not isinstance(signer, SecureSigner):
            raise RunnerRuntimeCorrupt("runtime signer does not match runner identity")
        _text(identity.workspace_id, "runtime workspace ID")
        _text(identity.runner_id, "runtime runner ID")
        _text(identity.key_id, "runtime runner key ID")
        _digest(identity.fingerprint, "runtime public key digest")
        public_key = getattr(signer, "public_key", None)
        if (
            type(public_key) is not bytes or len(public_key) != 32
            or getattr(signer, "key_id", None) != identity.key_id
            or hashlib.sha256(public_key).hexdigest() != identity.fingerprint
        ):
            raise RunnerRuntimeCorrupt("runtime signer does not match runner identity")

    def _derive_key(self) -> bytes:
        return self._derive_key_for(self.identity, self.signer)

    def _derive_key_for(self, identity: RunnerIdentity, signer: SecureSigner) -> bytes:
        RunnerRuntimeState._validate_identity_pair(identity, signer)
        public_key = signer.public_key
        seal = {
            "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        }
        signature = signer.sign(_SEAL_DOMAIN + canonical_bytes(seal))
        if type(signature) is not bytes or len(signature) != 64:
            raise RunnerRuntimeCorrupt("runner signer returned an invalid runtime seal")
        return self._crypto.hkdf(
            algorithm=self._crypto.hashes.SHA256(), length=32, salt=hashlib.sha256(public_key).digest(),
            info=_SEAL_DOMAIN,
        ).derive(signature)

    @staticmethod
    def _state_key_aad_for(identity: RunnerIdentity) -> bytes:
        return _STATE_KEY_WRAP_DOMAIN + canonical_bytes({
            "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        })

    def _state_key_aad(self) -> bytes:
        return self._state_key_aad_for(self.identity)

    def _wrap_state_key(self, state_key: bytes) -> bytes:
        return self._wrap_state_key_for(self._kek, self.identity, state_key)

    def _wrap_state_key_for(self, kek: bytes, identity: RunnerIdentity, state_key: bytes) -> bytes:
        if type(state_key) is not bytes or len(state_key) != 32:
            raise RunnerRuntimeCorrupt("runtime state key is invalid")
        nonce = self._random_source(12)
        if type(nonce) is not bytes or len(nonce) != 12:
            raise RunnerRuntimeCorrupt("runtime state random source returned an invalid nonce")
        return nonce + self._crypto.aead(kek).encrypt(
            nonce, state_key, self._state_key_aad_for(identity),
        )

    def _unwrap_state_key(self, sealed: object) -> bytes:
        if type(sealed) is not bytes or len(sealed) != 60:
            raise RunnerRuntimeCorrupt("runtime state key is invalid")
        try:
            state_key = self._crypto.aead(self._kek).decrypt(
                sealed[:12], sealed[12:], self._state_key_aad(),
            )
        except Exception as exc:
            raise RunnerRuntimeCorrupt("runtime state key is invalid") from exc
        if len(state_key) != 32:
            raise RunnerRuntimeCorrupt("runtime state key is invalid")
        return state_key

    def _prepare_path(self) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state parent is unavailable") from exc
        try:
            parent_stat = os.lstat(parent)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state parent is unavailable") from exc
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise RunnerRuntimeCorrupt("runtime state parent is unsafe")
        if parent_stat.st_mode & 0o077:
            raise RunnerRuntimeCorrupt("runtime state parent permissions are unsafe")
        if self.path.exists() or self.path.is_symlink():
            try:
                file_stat = os.lstat(self.path)
            except OSError as exc:
                raise RunnerRuntimeCorrupt("runtime state is unavailable") from exc
            if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
                raise RunnerRuntimeCorrupt("runtime state is unsafe")
            if file_stat.st_mode & 0o077:
                raise RunnerRuntimeCorrupt("runtime state permissions are unsafe")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._poisoned:
            raise RunnerRuntimeCorrupt("runtime state requires reconstruction")
        conn = sqlite3.connect(str(self.path), isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        except sqlite3.DatabaseError as exc:
            raise RunnerRuntimeCorrupt("runtime state database is invalid") from exc
        finally:
            conn.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state permissions are unsafe") from exc

    def _initialize(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            metadata_exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
            ).fetchone() is not None
            if not metadata_exists:
                conn.execute(
                    "CREATE TABLE metadata("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                    "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v2'),"
                    "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
                    "public_key_digest TEXT NOT NULL,state_key_ciphertext BLOB NOT NULL)"
                )
            for statement in (
                "CREATE TABLE IF NOT EXISTS control_chains("
                "chain TEXT PRIMARY KEY,run_hash TEXT NULL,operation TEXT NOT NULL,"
                "next_sequence INTEGER NOT NULL,generation INTEGER NOT NULL,sealed_blob BLOB NOT NULL,"
                "updated_at_ms INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS pending_calls("
                "call_id TEXT PRIMARY KEY,chain TEXT NOT NULL UNIQUE,run_hash TEXT NULL,operation TEXT NOT NULL,"
                "sequence INTEGER NOT NULL,generation INTEGER NOT NULL,sealed_blob BLOB NOT NULL,"
                "created_at_ms INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS terminal_disclosures("
                "run_hash TEXT PRIMARY KEY,retention_expires_at_ms INTEGER NOT NULL,"
                "state TEXT NOT NULL CHECK(state IN ('local_terminal','available','consumed','prune_pending')),"
                "sealed_blob BLOB NOT NULL,updated_at_ms INTEGER NOT NULL)",
                "CREATE INDEX IF NOT EXISTS idx_terminal_disclosures_state_retention "
                "ON terminal_disclosures(state,retention_expires_at_ms,run_hash)",
            ):
                conn.execute(statement)
            columns = tuple(row[1] for row in conn.execute("PRAGMA table_info(metadata)"))
            v1_columns = (
                "singleton", "schema_version", "workspace_id", "runner_id", "runner_key_id",
                "public_key_digest",
            )
            v2_columns = v1_columns + ("state_key_ciphertext",)
            if columns not in {v1_columns, v2_columns}:
                raise RunnerRuntimeCorrupt("runtime state metadata is invalid")
            row = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
            identity_values = (
                self.identity.workspace_id, self.identity.runner_id, self.identity.key_id,
                self.identity.fingerprint,
            )
            if row is None:
                if columns != v2_columns:
                    raise RunnerRuntimeCorrupt("runtime state metadata is invalid")
                state_key = self._random_source(32)
                if type(state_key) is not bytes or len(state_key) != 32:
                    raise RunnerRuntimeCorrupt("runtime state random source returned an invalid key")
                self._key = state_key
                conn.execute(
                    "INSERT INTO metadata(singleton,schema_version,workspace_id,runner_id,runner_key_id,public_key_digest,state_key_ciphertext) "
                    "VALUES(1,?,?,?,?,?,?)",
                    (_SCHEMA, *identity_values, self._wrap_state_key(state_key)),
                )
            elif columns == v1_columns:
                if (
                    row["schema_version"] != _SCHEMA_V1
                    or tuple(row[key] for key in v1_columns[2:]) != identity_values
                ):
                    raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
                # v1 rows were sealed with the signer-derived key.  Preserve it as the
                # stable v2 key and change only metadata; sealed authority records stay put.
                self._key = self._kek
                wrapped = self._wrap_state_key(self._key)
                conn.execute(
                    "CREATE TABLE metadata_v2("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                    "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v2'),"
                    "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
                    "public_key_digest TEXT NOT NULL,state_key_ciphertext BLOB NOT NULL)"
                )
                conn.execute(
                    "INSERT INTO metadata_v2 VALUES(1,?,?,?,?,?,?)",
                    (_SCHEMA, *identity_values, wrapped),
                )
                conn.execute("DROP TABLE metadata")
                conn.execute("ALTER TABLE metadata_v2 RENAME TO metadata")
            else:
                if (
                    row["schema_version"] != _SCHEMA
                    or tuple(row[key] for key in v2_columns[2:6]) != identity_values
                ):
                    raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
                self._key = self._unwrap_state_key(row["state_key_ciphertext"])
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _aad_for(identity: RunnerIdentity, schema: str, *primary_fields: str) -> bytes:
        return "\0".join((schema, identity.workspace_id, identity.runner_id,
                           identity.key_id, *primary_fields)).encode("utf-8")

    def _aad(self, schema: str, *primary_fields: str) -> bytes:
        return self._aad_for(self.identity, schema, *primary_fields)

    def _seal(self, core: Mapping[str, Any], *, schema: str, primary_fields: tuple[str, ...]) -> bytes:
        return self._seal_for(
            self._key, self.identity, core, schema=schema, primary_fields=primary_fields,
        )

    def _seal_for(
        self, key: bytes, identity: RunnerIdentity, core: Mapping[str, Any], *, schema: str,
        primary_fields: tuple[str, ...],
    ) -> bytes:
        nonce = self._random_source(12)
        if type(nonce) is not bytes or len(nonce) != 12:
            raise RunnerRuntimeCorrupt("runtime state random source returned an invalid nonce")
        plaintext = canonical_bytes(dict(core))
        return nonce + self._crypto.aead(key).encrypt(
            nonce, plaintext, self._aad_for(identity, schema, *primary_fields),
        )

    def _open(self, value: object, *, schema: str, primary_fields: tuple[str, ...]) -> dict[str, Any]:
        if type(value) is not bytes or len(value) <= 28:
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid")
        try:
            plaintext = self._crypto.aead(self._key).decrypt(
                value[:12], value[12:], self._aad(schema, *primary_fields),
            )
            decoded = __import__("json").loads(plaintext)
        except Exception as exc:
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid") from exc
        if canonical_bytes(decoded) != plaintext or not isinstance(decoded, dict):
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid")
        return decoded

    @staticmethod
    def _chain_key(operation: str, run_id: str | None) -> str:
        return hashlib.sha256(canonical_bytes({"operation": operation, "run_id": run_id})).hexdigest()

    def _validate_chain_core(self, value: Mapping[str, Any]) -> RunnerChainCursor:
        fields = {
            "schema_version", "workspace_id", "runner_id", "runner_key_id", "operation", "run_id",
            "next_nonce_b64", "next_sequence", "generation", "updated_at_ms", "state_digest",
        }
        if set(value) != fields or value.get("schema_version") != "heel.runner-control-chain-state.v1":
            raise RunnerRuntimeCorrupt("runtime chain state is invalid")
        operation = value["operation"]
        if operation not in {"claim", "heartbeat", "progress", "result", "stop-ack"}:
            raise RunnerRuntimeCorrupt("runtime chain state is invalid")
        run_id = _run_id(value["run_id"], nullable=True)
        if (operation == "claim") != (run_id is None):
            raise RunnerRuntimeCorrupt("runtime chain state is invalid")
        if (
            value["workspace_id"] != self.identity.workspace_id
            or value["runner_id"] != self.identity.runner_id
            or value["runner_key_id"] != self.identity.key_id
        ):
            raise RunnerRuntimeCorrupt("runtime chain state belongs to another runner identity")
        core = {key: value[key] for key in fields if key != "state_digest"}
        if value["state_digest"] != _state_digest(core):
            raise RunnerRuntimeCorrupt("runtime chain state digest is invalid")
        return RunnerChainCursor(
            operation=operation, run_id=run_id, next_nonce_b64=_nonce(value["next_nonce_b64"]),
            next_sequence=_safe_int(value["next_sequence"], "runtime chain sequence", minimum=1),
            generation=_safe_int(value["generation"], "runtime chain generation"),
            updated_at_ms=_safe_int(value["updated_at_ms"], "runtime chain time"),
            state_digest=_digest(value["state_digest"], "runtime chain state digest"),
        )

    def load_chain(self, operation: str, run_id: str | None) -> RunnerChainCursor | None:
        if operation not in {"claim", "heartbeat", "progress", "result", "stop-ack"}:
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if (operation == "claim") != (run_id is None):
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if run_id is not None:
            _run_id(run_id)
        chain = self._chain_key(operation, run_id)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT run_hash,operation,sealed_blob FROM control_chains WHERE chain=?", (chain,),
            ).fetchone()
        if row is None:
            return None
        expected_hash = None if run_id is None else _run_hash(run_id)
        if row["operation"] != operation or row["run_hash"] != expected_hash:
            raise RunnerRuntimeCorrupt("runtime chain index is invalid")
        core = self._open(
            row["sealed_blob"], schema="heel.runner-control-chain-state.v1", primary_fields=(chain,),
        )
        cursor = self._validate_chain_core(core)
        if cursor.operation != operation or cursor.run_id != run_id:
            raise RunnerRuntimeCorrupt("runtime chain index is invalid")
        return cursor

    def install_chain(
        self, *, operation: str, run_id: str | None, next_nonce_b64: str,
        next_sequence: int, generation: int, now_ms: int,
    ) -> RunnerChainCursor:
        if operation not in {"claim", "heartbeat", "progress", "result", "stop-ack"}:
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if (operation == "claim") != (run_id is None):
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if run_id is not None:
            _run_id(run_id)
        core_without_digest = {
            "schema_version": "heel.runner-control-chain-state.v1",
            "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id, "operation": operation, "run_id": run_id,
            "next_nonce_b64": _nonce(next_nonce_b64),
            "next_sequence": _safe_int(next_sequence, "runtime chain sequence", minimum=1),
            "generation": _safe_int(generation, "runtime chain generation"),
            "updated_at_ms": _safe_int(now_ms, "runtime chain time"),
        }
        core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
        cursor = self._validate_chain_core(core)
        chain = self._chain_key(operation, run_id)
        run_hash = None if run_id is None else _run_hash(run_id)
        blob = self._seal(core, schema=core["schema_version"], primary_fields=(chain,))
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT run_hash,operation,sealed_blob FROM control_chains WHERE chain=?", (chain,),
                ).fetchone()
                if existing is not None:
                    if existing["run_hash"] != run_hash or existing["operation"] != operation:
                        raise RunnerRuntimeCorrupt("runtime chain index is invalid")
                    prior = self._validate_chain_core(self._open(
                        existing["sealed_blob"], schema=core["schema_version"], primary_fields=(chain,),
                    ))
                    if prior != cursor:
                        raise RunnerRuntimeConflict("runtime chain already exists")
                else:
                    conn.execute(
                        "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (chain, run_hash, operation, cursor.next_sequence, cursor.generation, blob, cursor.updated_at_ms),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return cursor

    def _install_rotation_claim(
        self, *, next_nonce_b64: str, next_sequence: int, generation: int, now_ms: int,
    ) -> RunnerChainCursor:
        """Install the separately authenticated rotation activation cursor.

        This is deliberately private: only the fixed rotation activation path may
        replace the persisted claim chain.
        """
        next_nonce_b64 = _nonce(next_nonce_b64)
        next_sequence = _safe_int(next_sequence, "runtime rotation claim sequence", minimum=1)
        generation = _safe_int(generation, "runtime rotation claim generation")
        now_ms = _safe_int(now_ms, "runtime rotation claim time")
        chain = self._chain_key("claim", None)
        core_without_digest = {
            "schema_version": "heel.runner-control-chain-state.v1",
            "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id, "operation": "claim", "run_id": None,
            "next_nonce_b64": next_nonce_b64, "next_sequence": next_sequence,
            "generation": generation, "updated_at_ms": now_ms,
        }
        core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
        cursor = self._validate_chain_core(core)
        blob = self._seal(core, schema=core["schema_version"], primary_fields=(chain,))
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if conn.execute("SELECT 1 FROM pending_calls WHERE chain=?", (chain,)).fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime claim rotation has a pending call")
                current = self._load_chain_locked(conn, "claim", None)
                if current is not None:
                    if current == cursor:
                        conn.execute("COMMIT")
                        return cursor
                    if generation <= current.generation:
                        raise RunnerRuntimeCorrupt("runtime claim rotation did not advance")
                    conn.execute(
                        "UPDATE control_chains SET next_sequence=?,generation=?,sealed_blob=?,updated_at_ms=? WHERE chain=?",
                        (next_sequence, generation, blob, now_ms, chain),
                    )
                else:
                    conn.execute(
                        "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (chain, None, "claim", next_sequence, generation, blob, now_ms),
                    )
                conn.execute("COMMIT")
                return cursor
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _same_identity(left: RunnerIdentity, right: RunnerIdentity) -> bool:
        """Compare the signed identity record, excluding the local display-only phrase."""
        return (
            left.runner_id == right.runner_id
            and left.workspace_id == right.workspace_id
            and left.runner_version == right.runner_version
            and left.adapter_versions == right.adapter_versions
            and left.public_key_b64 == right.public_key_b64
            and left.fingerprint == right.fingerprint
            and left.key_id == right.key_id
            and left.capabilities == right.capabilities
        )

    @staticmethod
    def _rotation_response(
        journal: AcceptedRotationJournal, *, identity: RunnerIdentity,
    ) -> tuple[str, int, int]:
        if not isinstance(journal.activation_response, Mapping):
            raise RunnerRuntimeCorrupt("runtime rotation journal is invalid")
        response = journal.activation_response
        fields = {
            "schema_version", "workspace_id", "runner_id", "initial_claim_nonce",
            "initial_claim_sequence", "initial_claim_generation",
        }
        if set(response) != fields or (
            response.get("schema_version") != "heel.runner-rotation-activated.v2"
            or response.get("workspace_id") != identity.workspace_id
            or response.get("runner_id") != identity.runner_id
        ):
            raise RunnerRuntimeCorrupt("runtime rotation journal is invalid")
        return (
            _nonce(response["initial_claim_nonce"], "runtime rotation claim nonce"),
            _safe_int(response["initial_claim_sequence"], "runtime rotation claim sequence", minimum=1),
            _safe_int(response["initial_claim_generation"], "runtime rotation claim generation"),
        )

    @staticmethod
    def _rotation_cursor(
        identity: RunnerIdentity, *, next_nonce_b64: str, next_sequence: int,
        generation: int, now_ms: int,
    ) -> RunnerChainCursor:
        core_without_digest = {
            "schema_version": "heel.runner-control-chain-state.v1",
            "workspace_id": identity.workspace_id, "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id, "operation": "claim", "run_id": None,
            "next_nonce_b64": next_nonce_b64, "next_sequence": next_sequence,
            "generation": generation, "updated_at_ms": now_ms,
        }
        return RunnerChainCursor(
            operation="claim", run_id=None, next_nonce_b64=next_nonce_b64,
            next_sequence=next_sequence, generation=generation, updated_at_ms=now_ms,
            state_digest=_state_digest(core_without_digest),
        )

    def finish_rotation(
        self, journal: AcceptedRotationJournal, *, new_identity: RunnerIdentity,
        new_signer: SecureSigner,
    ) -> RunnerChainCursor:
        """Atomically rewrap the stable runtime key and install the accepted claim cursor.

        The caller supplies the live replacement signer explicitly.  Nothing serialized in
        the rotation journal can synthesize or replace that capability during recovery.
        """
        if not isinstance(journal, AcceptedRotationJournal):
            raise RunnerRuntimeCorrupt("runtime rotation journal is invalid")
        if not isinstance(new_identity, RunnerIdentity) or not isinstance(new_signer, SecureSigner):
            raise RunnerRuntimeCorrupt("runtime rotation signer is invalid")
        if not self._same_identity(journal.new_identity, new_identity):
            raise RunnerRuntimeCorrupt("runtime rotation signer is invalid")
        self._validate_identity_pair(new_identity, new_signer)
        if (
            journal.old_identity.workspace_id != new_identity.workspace_id
            or journal.old_identity.runner_id != new_identity.runner_id
            or journal.old_identity.key_id == new_identity.key_id
        ):
            raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
        _text(journal.pairing_id, "runtime rotation pairing ID")
        _text(journal.new_signer_label, "runtime rotation signer label")
        accepted_at_ms = _safe_int(journal.updated_at_ms, "runtime rotation journal time")
        _safe_int(journal.created_at_ms, "runtime rotation journal time")
        nonce, sequence, generation = self._rotation_response(journal, identity=new_identity)
        expected = self._rotation_cursor(
            new_identity, next_nonce_b64=nonce, next_sequence=sequence,
            generation=generation, now_ms=accepted_at_ms,
        )

        with self._state_lock:
            if self._poisoned:
                raise RunnerRuntimeCorrupt("runtime state requires reconstruction")
            old_metadata = self._same_identity(self.identity, journal.old_identity)
            new_metadata = self._same_identity(self.identity, new_identity)
            if old_metadata == new_metadata:
                raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
            if new_metadata:
                # A factory may reconstruct with the replacement signer after the database
                # committed but before its paired-identity selector/journal cleanup finished.
                current = self.load_chain("claim", None)
                if current != expected:
                    raise RunnerRuntimeCorrupt("runtime rotation cursor is invalid")
                return current

            old_identity = self.identity
            old_signer = self.signer
            old_kek = self._kek
            try:
                new_kek = self._derive_key_for(new_identity, new_signer)
                chain = self._chain_key("claim", None)
                next_core = {
                    "schema_version": "heel.runner-control-chain-state.v1",
                    "workspace_id": new_identity.workspace_id, "runner_id": new_identity.runner_id,
                    "runner_key_id": new_identity.key_id, "operation": "claim", "run_id": None,
                    "next_nonce_b64": expected.next_nonce_b64, "next_sequence": expected.next_sequence,
                    "generation": expected.generation, "updated_at_ms": expected.updated_at_ms,
                    "state_digest": expected.state_digest,
                }
                next_blob = self._seal_for(
                    self._key, new_identity, next_core,
                    schema="heel.runner-control-chain-state.v1", primary_fields=(chain,),
                )
                wrapped_key = self._wrap_state_key_for(new_kek, new_identity, self._key)
                with self._connection() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        metadata = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
                        if metadata is None or metadata["schema_version"] != _SCHEMA or tuple(
                            metadata[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
                        ) != (
                            old_identity.workspace_id, old_identity.runner_id,
                            old_identity.key_id, old_identity.fingerprint,
                        ):
                            raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
                        if self._unwrap_state_key(metadata["state_key_ciphertext"]) != self._key:
                            raise RunnerRuntimeCorrupt("runtime state key is invalid")
                        if conn.execute("SELECT 1 FROM pending_calls LIMIT 1").fetchone() is not None:
                            raise RunnerRuntimeConflict("runtime rotation has pending calls")
                        rows = conn.execute(
                            "SELECT chain,run_hash,operation,sealed_blob FROM control_chains"
                        ).fetchall()
                        if len(rows) != 1 or rows[0]["chain"] != chain or rows[0]["run_hash"] is not None or rows[0]["operation"] != "claim":
                            raise RunnerRuntimeConflict("runtime rotation has active runs")
                        current = self._load_chain_locked(conn, "claim", None)
                        if current is None or generation != current.generation + 1:
                            raise RunnerRuntimeCorrupt("runtime rotation did not advance")
                        if conn.execute("SELECT 1 FROM terminal_disclosures LIMIT 1").fetchone() is not None:
                            raise RunnerRuntimeConflict("runtime rotation has terminal disclosures")
                        updated = conn.execute(
                            "UPDATE control_chains SET next_sequence=?,generation=?,sealed_blob=?,updated_at_ms=? WHERE chain=?",
                            (expected.next_sequence, expected.generation, next_blob, expected.updated_at_ms, chain),
                        )
                        if updated.rowcount != 1:
                            raise RunnerRuntimeConflict("runtime rotation cursor is unavailable")
                        metadata_updated = conn.execute(
                            "UPDATE metadata SET workspace_id=?,runner_id=?,runner_key_id=?,public_key_digest=?,state_key_ciphertext=? "
                            "WHERE singleton=1",
                            (
                                new_identity.workspace_id, new_identity.runner_id, new_identity.key_id,
                                new_identity.fingerprint, wrapped_key,
                            ),
                        )
                        if metadata_updated.rowcount != 1:
                            raise RunnerRuntimeConflict("runtime rotation metadata is unavailable")
                        conn.execute("COMMIT")
                    except BaseException:
                        conn.execute("ROLLBACK")
                        raise
                self.identity = new_identity
                self.signer = new_signer
                self._kek = new_kek
                return expected
            except BaseException:
                # If a future fault is injected after the durable metadata switch but before
                # these in-memory assignments, the old object must never sign again.
                if self._same_identity(self.identity, old_identity) and self._kek == old_kek:
                    raise
                self._poisoned = True
                raise

    def _commit_resync_chain(
        self, *, operation: str, run_id: str | None, next_nonce_b64: str,
        next_sequence: int, generation: int, now_ms: int,
    ) -> RunnerChainCursor:
        """Persist one authenticated generation-advancing resynchronization.

        This is intentionally private: only the fixed resync completion protocol
        may replace a live cursor with a server-authoritative generation.
        """
        if operation not in {"claim", "heartbeat", "progress", "result", "stop-ack"}:
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if (operation == "claim") != (run_id is None):
            raise RunnerRuntimeStateError("invalid runtime chain operation")
        if run_id is not None:
            _run_id(run_id)
        next_nonce_b64 = _nonce(next_nonce_b64)
        next_sequence = _safe_int(next_sequence, "runtime resync sequence", minimum=1)
        generation = _safe_int(generation, "runtime resync generation")
        now_ms = _safe_int(now_ms, "runtime resync time")
        chain = self._chain_key(operation, run_id)
        core_without_digest = {
            "schema_version": "heel.runner-control-chain-state.v1",
            "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id, "operation": operation, "run_id": run_id,
            "next_nonce_b64": next_nonce_b64, "next_sequence": next_sequence,
            "generation": generation, "updated_at_ms": now_ms,
        }
        core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
        cursor = self._validate_chain_core(core)
        blob = self._seal(core, schema=core["schema_version"], primary_fields=(chain,))
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_chain_locked(conn, operation, run_id)
                if current is None:
                    raise RunnerRuntimeConflict("runtime resync chain is unavailable")
                if generation == current.generation:
                    if cursor != current:
                        raise RunnerRuntimeCorrupt("runtime resync generation did not advance")
                    conn.execute("COMMIT")
                    return current
                if generation < current.generation:
                    raise RunnerRuntimeCorrupt("runtime resync generation did not advance")
                if generation != current.generation + 1:
                    raise RunnerRuntimeCorrupt("runtime resync generation is invalid")
                conn.execute(
                    "UPDATE control_chains SET next_sequence=?,generation=?,sealed_blob=?,updated_at_ms=? "
                    "WHERE chain=?",
                    (cursor.next_sequence, cursor.generation, blob, cursor.updated_at_ms, chain),
                )
                conn.execute("COMMIT")
                return cursor
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _load_chain_locked(
        self, conn: sqlite3.Connection, operation: str, run_id: str | None,
    ) -> RunnerChainCursor | None:
        chain = self._chain_key(operation, run_id)
        row = conn.execute(
            "SELECT run_hash,operation,sealed_blob FROM control_chains WHERE chain=?", (chain,),
        ).fetchone()
        if row is None:
            return None
        if row["operation"] != operation or row["run_hash"] != (None if run_id is None else _run_hash(run_id)):
            raise RunnerRuntimeCorrupt("runtime chain index is invalid")
        cursor = self._validate_chain_core(self._open(
            row["sealed_blob"], schema="heel.runner-control-chain-state.v1", primary_fields=(chain,),
        ))
        if cursor.operation != operation or cursor.run_id != run_id:
            raise RunnerRuntimeCorrupt("runtime chain index is invalid")
        return cursor

    @staticmethod
    def _canonical_b64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    def _validate_pending_core(self, value: Mapping[str, Any]) -> tuple[PendingSignedCall, dict[str, Any]]:
        fields = {
            "schema_version", "workspace_id", "runner_id", "runner_key_id", "call_id",
            "request_operation", "chain_operation", "run_id", "path", "capability", "method",
            "headers", "body_b64", "body_sha256", "server_nonce_b64", "sequence", "generation",
            "prior_chain_state_digest", "created_at_ms", "state_digest",
        }
        if set(value) != fields or value.get("schema_version") != "heel.runner-pending-call.v1":
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        if (
            value["workspace_id"] != self.identity.workspace_id
            or value["runner_id"] != self.identity.runner_id
            or value["runner_key_id"] != self.identity.key_id
            or value["method"] != "POST"
        ):
            raise RunnerRuntimeCorrupt("runtime pending call belongs to another runner identity")
        request_operation = value["request_operation"]
        chain_operation = value["chain_operation"]
        valid_requests = {
            "claim", "heartbeat", "progress", "result", "stop-ack", "upload-findings",
            "list-contexts", "claim-context", "submit-context-approval-projection",
        }
        if request_operation not in valid_requests or chain_operation not in {
            "claim", "heartbeat", "progress", "result", "stop-ack",
        }:
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        run_id = _run_id(value["run_id"], nullable=True)
        expected_chain = (
            "claim" if request_operation in {"claim", "list-contexts", "claim-context", "submit-context-approval-projection"}
            else "result" if request_operation == "upload-findings" else request_operation
        )
        if chain_operation != expected_chain or ((chain_operation == "claim") != (run_id is None)):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        if type(value["headers"]) is not dict or any(type(key) is not str or type(item) is not str for key, item in value["headers"].items()):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        try:
            body = base64.b64decode(value["body_b64"], validate=True)
        except (TypeError, ValueError):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid") from None
        if self._canonical_b64(body) != value["body_b64"] or len(body) > 272 * 1024:
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        if hashlib.sha256(body).hexdigest() != _digest(value["body_sha256"], "runtime pending body digest"):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        if (
            type(value["path"]) is not str or not value["path"]
            or not self._expected_path(request_operation, run_id, value["path"])
        ):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        prior = value["prior_chain_state_digest"]
        if prior is not None:
            _digest(prior, "runtime pending prior state digest")
        elif not (request_operation == "claim" and chain_operation == "claim"):
            raise RunnerRuntimeCorrupt("runtime pending call is invalid")
        core_without_digest = {key: value[key] for key in fields if key != "state_digest"}
        if value["state_digest"] != _state_digest(core_without_digest):
            raise RunnerRuntimeCorrupt("runtime pending call digest is invalid")
        call_id = _digest(value["call_id"], "runtime pending call ID")
        pending = PendingSignedCall(
            call_id=call_id, request_operation=request_operation, chain_operation=chain_operation,
            run_id=run_id, path=value["path"], capability=_text(value["capability"], "runtime capability") or "",
            headers=MappingProxyType(dict(value["headers"])), body=body,
            sequence=_safe_int(value["sequence"], "runtime pending sequence", minimum=1),
            generation=_safe_int(value["generation"], "runtime pending generation"),
            prior_chain_state_digest=prior,
            created_at_ms=_safe_int(value["created_at_ms"], "runtime pending time"),
        )
        _nonce(value["server_nonce_b64"])
        return pending, dict(value)

    def _validate_signed_headers(
        self, *, capability: str, path: str, body: bytes, headers: Mapping[str, str],
        nonce: str, sequence: int,
    ) -> dict[str, str]:
        expected = {
            "Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id",
            "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature",
            "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence",
        }
        if not isinstance(headers, Mapping) or set(headers) != expected or any(
            type(key) is not str or type(value) is not str for key, value in headers.items()
        ):
            raise RunnerRuntimeStateError("invalid runtime pending headers")
        values = dict(headers)
        if (
            values["Content-Type"] != "application/json"
            or values["X-Heel-Runner-Id"] != self.identity.runner_id
            or values["X-Heel-Runner-Key-Id"] != self.identity.key_id
            or values["X-Heel-Runner-Nonce"] != nonce
            or values["X-Heel-Runner-Sequence"] != str(sequence)
        ):
            raise RunnerRuntimeStateError("invalid runtime pending headers")
        try:
            timestamp = int(values["X-Heel-Runner-Timestamp-Ms"])
        except ValueError:
            raise RunnerRuntimeStateError("invalid runtime pending headers") from None
        if str(timestamp) != values["X-Heel-Runner-Timestamp-Ms"]:
            raise RunnerRuntimeStateError("invalid runtime pending headers")
        _safe_int(timestamp, "runtime pending timestamp")
        signature_text = values["X-Heel-Runner-Signature"]
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (TypeError, ValueError):
            raise RunnerRuntimeStateError("invalid runtime pending headers") from None
        if len(signature) != 64 or self._canonical_b64(signature) != signature_text:
            raise RunnerRuntimeStateError("invalid runtime pending headers")
        proof = {
            "schema_version": "heel.runner-request-proof.v1", "workspace_id": self.identity.workspace_id,
            "runner_id": self.identity.runner_id, "key_id": self.identity.key_id,
            "capability": capability, "method": "POST", "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp,
            "server_nonce": nonce, "sequence": sequence,
        }
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(self.signer.public_key).verify(
                signature, b"heel.runner-pop.v1\0" + canonical_bytes(proof),
            )
        except Exception as exc:
            raise RunnerRuntimeStateError("invalid runtime pending headers") from exc
        return values

    def _expected_path(self, request_operation: str, run_id: str | None, path: str) -> bool:
        prefix = f"/v1/workspaces/{self.identity.workspace_id}/runners/{self.identity.runner_id}"
        if request_operation == "claim":
            return path == f"{prefix}/claim"
        if request_operation in {"heartbeat", "progress", "result", "stop-ack"}:
            return run_id is not None and path == f"{prefix}/runs/{run_id}/{request_operation}"
        if request_operation == "upload-findings":
            return run_id is not None and path == f"{prefix}/runs/{run_id}/result-projection"
        if request_operation == "list-contexts":
            return path == f"{prefix}/contexts/list"
        if request_operation == "claim-context":
            return path.startswith(f"{prefix}/contexts/rcb_") and path.endswith("/claim")
        if request_operation == "submit-context-approval-projection":
            return path.startswith(f"{prefix}/contexts/rcb_") and path.endswith("/approval-projections")
        return False

    def stage_call(
        self, *, request_operation: str, chain_operation: str, run_id: str | None,
        path: str, capability: str, headers: Mapping[str, str], body: bytes,
        expected_state_digest: str | None, now_ms: int,
    ) -> PendingSignedCall:
        if type(body) is not bytes or len(body) > 272 * 1024:
            raise RunnerRuntimeStateError("invalid runtime pending body")
        _safe_int(now_ms, "runtime pending time")
        if request_operation not in {
            "claim", "heartbeat", "progress", "result", "stop-ack", "upload-findings",
            "list-contexts", "claim-context", "submit-context-approval-projection",
        } or not self._expected_path(request_operation, run_id, path):
            raise RunnerRuntimeStateError("invalid runtime pending call")
        expected_chain = (
            "claim" if request_operation in {"claim", "list-contexts", "claim-context", "submit-context-approval-projection"}
            else "result" if request_operation == "upload-findings" else request_operation
        )
        if chain_operation != expected_chain or ((chain_operation == "claim") != (run_id is None)):
            raise RunnerRuntimeStateError("invalid runtime pending call")
        if run_id is not None:
            _run_id(run_id)
        _digest(expected_state_digest, "runtime expected state digest")
        chain = self._chain_key(chain_operation, run_id)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_chain_locked(conn, chain_operation, run_id)
                if current is None:
                    raise RunnerRuntimeConflict("runtime chain is unavailable")
                nonce = current.next_nonce_b64
                sequence = current.next_sequence
                generation = current.generation
                prior_state_digest = current.state_digest
                if current.state_digest != expected_state_digest:
                    raise RunnerRuntimeConflict("runtime chain state changed")
                if conn.execute("SELECT 1 FROM pending_calls WHERE chain=?", (chain,)).fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime call is already pending")
                if conn.execute("SELECT COUNT(*) FROM pending_calls").fetchone()[0] >= 74:
                    raise RunnerRuntimeConflict("runtime pending call capacity is exhausted")
                validated_headers = self._validate_signed_headers(
                    capability=capability, path=path, body=body, headers=headers,
                    nonce=nonce, sequence=sequence,
                )
                body_digest = hashlib.sha256(body).hexdigest()
                call_id = hashlib.sha256(
                    b"heel.runner-pending-call-id.v1\0" + canonical_bytes({
                        "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
                        "runner_key_id": self.identity.key_id, "request_operation": request_operation,
                        "chain_operation": chain_operation, "run_id": run_id, "path": path,
                        "body_sha256": body_digest, "server_nonce_b64": nonce,
                        "sequence": sequence, "generation": generation,
                    })
                ).hexdigest()
                core_without_digest = {
                    "schema_version": "heel.runner-pending-call.v1", "workspace_id": self.identity.workspace_id,
                    "runner_id": self.identity.runner_id, "runner_key_id": self.identity.key_id,
                    "call_id": call_id, "request_operation": request_operation, "chain_operation": chain_operation,
                    "run_id": run_id, "path": path, "capability": capability, "method": "POST",
                    "headers": validated_headers, "body_b64": self._canonical_b64(body),
                    "body_sha256": body_digest, "server_nonce_b64": nonce,
                    "sequence": sequence, "generation": generation,
                    "prior_chain_state_digest": prior_state_digest, "created_at_ms": now_ms,
                }
                core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
                pending, _ = self._validate_pending_core(core)
                blob = self._seal(core, schema=core["schema_version"], primary_fields=(call_id,))
                if len(blob) > 384 * 1024:
                    raise RunnerRuntimeStateError("runtime pending call exceeds size limit")
                conn.execute(
                    "INSERT INTO pending_calls(call_id,chain,run_hash,operation,sequence,generation,sealed_blob,created_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (call_id, chain, None if run_id is None else _run_hash(run_id), request_operation,
                     sequence, generation, blob, now_ms),
                )
                conn.execute("COMMIT")
                return pending
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def load_pending_calls(self, *, limit: int = 74) -> tuple[PendingSignedCall, ...]:
        if type(limit) is not int or not 1 <= limit <= 74:
            raise RunnerRuntimeStateError("invalid runtime pending call limit")
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT call_id,chain,run_hash,operation,sealed_blob FROM pending_calls "
                "ORDER BY created_at_ms,call_id LIMIT ?", (limit,),
            ).fetchall()
        pending: list[PendingSignedCall] = []
        for row in rows:
            item, _core = self._validate_pending_core(self._open(
                row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(row["call_id"],),
            ))
            if row["call_id"] != item.call_id or row["chain"] != self._chain_key(item.chain_operation, item.run_id):
                raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
            pending.append(item)
        return tuple(pending)

    def _cursor_core(self, cursor: RunnerChainCursor, *, next_nonce_b64: str, now_ms: int) -> dict[str, Any]:
        core_without_digest = {
            "schema_version": "heel.runner-control-chain-state.v1",
            "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id, "operation": cursor.operation,
            "run_id": cursor.run_id, "next_nonce_b64": _nonce(next_nonce_b64),
            "next_sequence": cursor.next_sequence + 1, "generation": cursor.generation,
            "updated_at_ms": _safe_int(now_ms, "runtime chain time"),
        }
        return {**core_without_digest, "state_digest": _state_digest(core_without_digest)}

    def commit_call(
        self, call_id: str, *, next_nonce_b64: str, now_ms: int,
        installed_chains: tuple[tuple[str, str, str, int, int], ...] = (),
    ) -> RunnerChainCursor:
        call_id = _digest(call_id, "runtime pending call ID")
        _safe_int(now_ms, "runtime chain time")
        next_nonce_b64 = _nonce(next_nonce_b64)
        if type(installed_chains) is not tuple:
            raise RunnerRuntimeStateError("invalid runtime installed claim chains")
        parsed_installed: tuple[tuple[str, str, str, int, int], ...] = ()
        if installed_chains:
            if len(installed_chains) != 4:
                raise RunnerRuntimeStateError("invalid runtime installed claim chains")
            values: list[tuple[str, str, str, int, int]] = []
            for item in installed_chains:
                if type(item) is not tuple or len(item) != 5:
                    raise RunnerRuntimeStateError("invalid runtime installed claim chains")
                operation, run_id, nonce, sequence, generation = item
                if operation not in {"heartbeat", "progress", "result", "stop-ack"}:
                    raise RunnerRuntimeStateError("invalid runtime installed claim chains")
                checked_run_id = _run_id(run_id)
                assert checked_run_id is not None
                values.append((
                    operation, checked_run_id, _nonce(nonce),
                    _safe_int(sequence, "runtime installed chain sequence", minimum=1),
                    _safe_int(generation, "runtime installed chain generation"),
                ))
            if len({item[0] for item in values}) != 4 or len({item[1] for item in values}) != 1:
                raise RunnerRuntimeStateError("invalid runtime installed claim chains")
            parsed_installed = tuple(values)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT chain,sealed_blob FROM pending_calls WHERE call_id=?", (call_id,),
                ).fetchone()
                if row is None:
                    raise RunnerRuntimeConflict("runtime pending call is unavailable")
                pending, _pending_core = self._validate_pending_core(self._open(
                    row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(call_id,),
                ))
                if parsed_installed and not (
                    pending.request_operation == "claim" and pending.chain_operation == "claim"
                    and pending.run_id is None
                ):
                    raise RunnerRuntimeCorrupt("runtime installed claim chains do not match pending call")
                chain = self._chain_key(pending.chain_operation, pending.run_id)
                if row["chain"] != chain:
                    raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
                current = self._load_chain_locked(conn, pending.chain_operation, pending.run_id)
                initial_claim = current is None and (
                    pending.request_operation == "claim" and pending.chain_operation == "claim"
                    and pending.run_id is None and pending.prior_chain_state_digest is None
                )
                if initial_claim:
                    initial_without_digest = {
                        "schema_version": "heel.runner-control-chain-state.v1",
                        "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
                        "runner_key_id": self.identity.key_id, "operation": "claim", "run_id": None,
                        "next_nonce_b64": pending.headers["X-Heel-Runner-Nonce"],
                        "next_sequence": pending.sequence, "generation": pending.generation,
                        "updated_at_ms": pending.created_at_ms,
                    }
                    initial = {**initial_without_digest, "state_digest": _state_digest(initial_without_digest)}
                    current = self._validate_chain_core(initial)
                if (
                    current is None
                    or (not initial_claim and pending.prior_chain_state_digest != current.state_digest)
                    or pending.sequence != current.next_sequence or pending.generation != current.generation
                    or pending.headers["X-Heel-Runner-Nonce"] != current.next_nonce_b64
                    or next_nonce_b64 == current.next_nonce_b64
                ):
                    raise RunnerRuntimeCorrupt("runtime pending call no longer matches its chain")
                next_core = self._cursor_core(current, next_nonce_b64=next_nonce_b64, now_ms=now_ms)
                next_cursor = self._validate_chain_core(next_core)
                blob = self._seal(next_core, schema=next_core["schema_version"], primary_fields=(chain,))
                if initial_claim:
                    conn.execute(
                        "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (chain, None, "claim", next_cursor.next_sequence, next_cursor.generation,
                         blob, next_cursor.updated_at_ms),
                    )
                else:
                    conn.execute(
                        "UPDATE control_chains SET next_sequence=?,generation=?,sealed_blob=?,updated_at_ms=? WHERE chain=?",
                        (next_cursor.next_sequence, next_cursor.generation, blob, next_cursor.updated_at_ms, chain),
                    )
                for operation, run_id, installed_nonce, installed_sequence, installed_generation in parsed_installed:
                    installed_without_digest = {
                        "schema_version": "heel.runner-control-chain-state.v1",
                        "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
                        "runner_key_id": self.identity.key_id, "operation": operation, "run_id": run_id,
                        "next_nonce_b64": installed_nonce, "next_sequence": installed_sequence,
                        "generation": installed_generation, "updated_at_ms": now_ms,
                    }
                    installed_core = {
                        **installed_without_digest,
                        "state_digest": _state_digest(installed_without_digest),
                    }
                    installed_cursor = self._validate_chain_core(installed_core)
                    installed_key = self._chain_key(operation, run_id)
                    existing = conn.execute(
                        "SELECT sealed_blob FROM control_chains WHERE chain=?", (installed_key,),
                    ).fetchone()
                    if existing is not None:
                        prior = self._validate_chain_core(self._open(
                            existing["sealed_blob"], schema=installed_core["schema_version"],
                            primary_fields=(installed_key,),
                        ))
                        if prior != installed_cursor:
                            raise RunnerRuntimeConflict("runtime installed claim chain already exists")
                    else:
                        installed_blob = self._seal(
                            installed_core, schema=installed_core["schema_version"],
                            primary_fields=(installed_key,),
                        )
                        conn.execute(
                            "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
                            "VALUES(?,?,?,?,?,?,?)",
                            (installed_key, _run_hash(run_id), operation, installed_cursor.next_sequence,
                             installed_cursor.generation, installed_blob, installed_cursor.updated_at_ms),
                        )
                conn.execute("DELETE FROM pending_calls WHERE call_id=?", (call_id,))
                conn.execute("COMMIT")
                return next_cursor
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _validate_terminal_core(self, value: Mapping[str, Any]) -> TerminalDisclosureState:
        fields = {
            "schema_version", "state", "workspace_id", "runner_id", "runner_key_id", "run_id",
            "run_hash", "project_id", "grant_id", "approval_projection_digest",
            "terminal_projection_digest", "terminal_record_digest", "terminal_at_ms",
            "retention_expires_at_ms", "result_chain", "available_at_ms", "permit_id",
            "findings_projection_digest", "receipt_digest", "disclosed_at_ms", "revision",
            "prior_state_digest", "state_digest",
        }
        if set(value) != fields or value.get("schema_version") != "heel.runner-terminal-disclosure-state.v1":
            raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
        state = value["state"]
        if state not in {"local_terminal", "available", "consumed", "prune_pending"}:
            raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
        run_id = _run_id(value["run_id"])
        assert run_id is not None
        if (
            value["workspace_id"] != self.identity.workspace_id
            or value["runner_id"] != self.identity.runner_id
            or value["runner_key_id"] != self.identity.key_id
            or value["run_hash"] != _run_hash(run_id)
        ):
            raise RunnerRuntimeCorrupt("runtime terminal disclosure belongs to another runner identity")
        project_id = _text(value["project_id"], "runtime terminal project ID", nullable=True)
        grant_id = _text(value["grant_id"], "runtime terminal grant ID", nullable=True)
        approval_digest = value["approval_projection_digest"]
        if approval_digest is not None:
            _digest(approval_digest, "runtime terminal approval digest")
        terminal_projection = _digest(value["terminal_projection_digest"], "runtime terminal projection digest")
        terminal_record = _digest(value["terminal_record_digest"], "runtime terminal record digest")
        terminal_at = _safe_int(value["terminal_at_ms"], "runtime terminal time")
        retention = _safe_int(value["retention_expires_at_ms"], "runtime terminal retention")
        if terminal_at >= retention:
            raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
        revision = _safe_int(value["revision"], "runtime terminal revision", minimum=1)
        prior = value["prior_state_digest"]
        if prior is not None:
            _digest(prior, "runtime terminal prior state digest")
        result_chain = value["result_chain"]
        available_at = value["available_at_ms"]
        permit_id = value["permit_id"]
        findings = value["findings_projection_digest"]
        receipt = value["receipt_digest"]
        disclosed = value["disclosed_at_ms"]
        if result_chain is not None:
            if not isinstance(result_chain, Mapping) or set(result_chain) != {
                "operation", "run_id", "next_nonce_b64", "next_sequence", "generation",
            } or result_chain["operation"] != "result" or result_chain["run_id"] != run_id:
                raise RunnerRuntimeCorrupt("runtime terminal result chain is invalid")
            _nonce(result_chain["next_nonce_b64"])
            _safe_int(result_chain["next_sequence"], "runtime terminal result sequence", minimum=1)
            _safe_int(result_chain["generation"], "runtime terminal result generation")
            result_chain = dict(result_chain)
        if state == "local_terminal":
            if (
                result_chain is not None or available_at is not None or permit_id is not None
                or findings is not None or receipt is not None or disclosed is not None
                or prior is not None or revision != 1
            ):
                raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
        elif state == "available":
            if (
                result_chain is None or type(available_at) is not int or available_at < terminal_at
                or permit_id is not None or findings is not None or receipt is not None or disclosed is not None
                or prior is None or revision != 2
            ):
                raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
            _safe_int(available_at, "runtime terminal available time")
        elif state == "consumed":
            if (
                result_chain is not None or type(available_at) is not int or permit_id is None
                or findings is None or receipt is None or type(disclosed) is not int
                or not terminal_at <= disclosed < retention or prior is None or revision != 3
            ):
                raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
            _safe_int(available_at, "runtime terminal available time")
            _text(permit_id, "runtime disclosure permit ID")
            _digest(findings, "runtime findings projection digest")
            _digest(receipt, "runtime disclosure receipt digest")
            _safe_int(disclosed, "runtime disclosure time")
        else:  # prune_pending retains the predecessor payload but never a nonce.
            if result_chain is not None or prior is None or revision < 2:
                raise RunnerRuntimeCorrupt("runtime terminal disclosure state is invalid")
        core_without_digest = {key: value[key] for key in fields if key != "state_digest"}
        if value["state_digest"] != _state_digest(core_without_digest):
            raise RunnerRuntimeCorrupt("runtime terminal disclosure digest is invalid")
        return TerminalDisclosureState(
            schema_version=value["schema_version"], state=state,
            workspace_id=value["workspace_id"], runner_id=value["runner_id"],
            runner_key_id=value["runner_key_id"], run_id=run_id, run_hash=value["run_hash"],
            project_id=project_id, grant_id=grant_id, approval_projection_digest=approval_digest,
            terminal_projection_digest=terminal_projection, terminal_record_digest=terminal_record,
            terminal_at_ms=terminal_at, retention_expires_at_ms=retention,
            result_chain=MappingProxyType(result_chain) if result_chain is not None else None,
            available_at_ms=available_at, permit_id=permit_id, findings_projection_digest=findings,
            receipt_digest=receipt, disclosed_at_ms=disclosed, revision=revision,
            prior_state_digest=prior, state_digest=_digest(value["state_digest"], "runtime terminal state digest"),
        )

    def _load_terminal_locked(
        self, conn: sqlite3.Connection, run_id: str,
    ) -> TerminalDisclosureState | None:
        run_hash = _run_hash(run_id)
        row = conn.execute(
            "SELECT retention_expires_at_ms,state,sealed_blob,updated_at_ms FROM terminal_disclosures WHERE run_hash=?",
            (run_hash,),
        ).fetchone()
        if row is None:
            return None
        state = self._validate_terminal_core(self._open(
            row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1", primary_fields=(run_hash,),
        ))
        if (
            state.run_id != run_id or row["state"] != state.state
            or row["retention_expires_at_ms"] != state.retention_expires_at_ms
            or (state.state == "local_terminal" and row["updated_at_ms"] != state.terminal_at_ms)
        ):
            raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")
        return state

    def load_terminal_state(self, run_id: str) -> TerminalDisclosureState | None:
        """Load one authenticated terminal disclosure without changing its state."""
        run_id = _run_id(run_id)
        assert run_id is not None
        with self._connection() as conn:
            return self._load_terminal_locked(conn, run_id)

    def _terminal_core(self, **values: Any) -> dict[str, Any]:
        core_without_digest = {
            "schema_version": "heel.runner-terminal-disclosure-state.v1", **values,
        }
        return {**core_without_digest, "state_digest": _state_digest(core_without_digest)}

    def register_local_terminal(
        self, *, run_id: str, project_id: str, grant_id: str,
        approval_projection_digest: str, terminal_projection_digest: str,
        terminal_record_digest: str, terminal_at_ms: int,
        retention_expires_at_ms: int,
    ) -> TerminalDisclosureState:
        run_id = _run_id(run_id)
        assert run_id is not None
        project_id = _text(project_id, "runtime terminal project ID") or ""
        grant_id = _text(grant_id, "runtime terminal grant ID") or ""
        approval_projection_digest = _digest(approval_projection_digest, "runtime terminal approval digest")
        terminal_projection_digest = _digest(terminal_projection_digest, "runtime terminal projection digest")
        terminal_record_digest = _digest(terminal_record_digest, "runtime terminal record digest")
        terminal_at_ms = _safe_int(terminal_at_ms, "runtime terminal time")
        retention_expires_at_ms = _safe_int(retention_expires_at_ms, "runtime terminal retention")
        if terminal_at_ms >= retention_expires_at_ms:
            raise RunnerRuntimeStateError("invalid runtime terminal retention")
        core = self._terminal_core(
            state="local_terminal", workspace_id=self.identity.workspace_id,
            runner_id=self.identity.runner_id, runner_key_id=self.identity.key_id,
            run_id=run_id, run_hash=_run_hash(run_id), project_id=project_id, grant_id=grant_id,
            approval_projection_digest=approval_projection_digest,
            terminal_projection_digest=terminal_projection_digest,
            terminal_record_digest=terminal_record_digest, terminal_at_ms=terminal_at_ms,
            retention_expires_at_ms=retention_expires_at_ms, result_chain=None,
            available_at_ms=None, permit_id=None, findings_projection_digest=None,
            receipt_digest=None, disclosed_at_ms=None, revision=1, prior_state_digest=None,
        )
        state = self._validate_terminal_core(core)
        blob = self._seal(core, schema=core["schema_version"], primary_fields=(state.run_hash,))
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._load_terminal_locked(conn, run_id)
                if existing is not None:
                    if existing != state:
                        raise RunnerRuntimeCorrupt("runtime terminal disclosure differs from local terminal")
                else:
                    conn.execute(
                        "INSERT INTO terminal_disclosures(run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms) "
                        "VALUES(?,?,?,?,?)",
                        (state.run_hash, state.retention_expires_at_ms, state.state, blob, terminal_at_ms),
                    )
                conn.execute("COMMIT")
                return state
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def commit_terminal_response(
        self, call_id: str, *, next_nonce_b64: str, now_ms: int,
    ) -> TerminalDisclosureState:
        """Persist the accepted result cursor and retire every local run chain."""
        call_id = _digest(call_id, "runtime pending call ID")
        next_nonce_b64 = _nonce(next_nonce_b64)
        now_ms = _safe_int(now_ms, "runtime terminal response time")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT chain,run_hash,sealed_blob FROM pending_calls WHERE call_id=?", (call_id,),
                ).fetchone()
                if row is None:
                    raise RunnerRuntimeConflict("runtime pending call is unavailable")
                pending, _pending_core = self._validate_pending_core(self._open(
                    row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(call_id,),
                ))
                if pending.request_operation != "result" or pending.chain_operation != "result" or pending.run_id is None:
                    raise RunnerRuntimeCorrupt("runtime pending call is not a result")
                run_id = pending.run_id
                run_hash = _run_hash(run_id)
                if row["chain"] != self._chain_key("result", run_id) or row["run_hash"] != run_hash:
                    raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
                current = self._load_chain_locked(conn, "result", run_id)
                local = self._load_terminal_locked(conn, run_id)
                if (
                    current is None or local is None or local.state != "local_terminal"
                    or pending.prior_chain_state_digest != current.state_digest
                    or pending.sequence != current.next_sequence or pending.generation != current.generation
                    or pending.headers["X-Heel-Runner-Nonce"] != current.next_nonce_b64
                    or next_nonce_b64 == current.next_nonce_b64
                    or now_ms < local.terminal_at_ms
                ):
                    raise RunnerRuntimeCorrupt("runtime terminal result does not match local authority")
                result_chain = {
                    "operation": "result", "run_id": run_id, "next_nonce_b64": next_nonce_b64,
                    "next_sequence": current.next_sequence + 1, "generation": current.generation,
                }
                core = self._terminal_core(
                    state="available", workspace_id=self.identity.workspace_id,
                    runner_id=self.identity.runner_id, runner_key_id=self.identity.key_id,
                    run_id=run_id, run_hash=run_hash, project_id=local.project_id,
                    grant_id=local.grant_id, approval_projection_digest=local.approval_projection_digest,
                    terminal_projection_digest=local.terminal_projection_digest,
                    terminal_record_digest=local.terminal_record_digest,
                    terminal_at_ms=local.terminal_at_ms,
                    retention_expires_at_ms=local.retention_expires_at_ms,
                    result_chain=result_chain, available_at_ms=now_ms, permit_id=None,
                    findings_projection_digest=None, receipt_digest=None, disclosed_at_ms=None,
                    revision=2, prior_state_digest=local.state_digest,
                )
                available = self._validate_terminal_core(core)
                blob = self._seal(core, schema=core["schema_version"], primary_fields=(run_hash,))
                conn.execute(
                    "UPDATE terminal_disclosures SET state=?,sealed_blob=?,updated_at_ms=? WHERE run_hash=?",
                    (available.state, blob, now_ms, run_hash),
                )
                conn.execute("DELETE FROM control_chains WHERE run_hash=?", (run_hash,))
                conn.execute("DELETE FROM pending_calls WHERE run_hash=?", (run_hash,))
                conn.execute("COMMIT")
                return available
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def lease_terminal_disclosure(
        self, run_id: str, *, expected_project_id: str, expected_grant_id: str,
        expected_approval_projection_digest: str, now_ms: int,
    ) -> _TerminalDisclosureLease:
        run_id = _run_id(run_id)
        assert run_id is not None
        expected_project_id = _text(expected_project_id, "runtime disclosure project ID") or ""
        expected_grant_id = _text(expected_grant_id, "runtime disclosure grant ID") or ""
        expected_approval_projection_digest = _digest(
            expected_approval_projection_digest, "runtime disclosure approval digest",
        )
        now_ms = _safe_int(now_ms, "runtime disclosure time")
        with self._connection() as conn:
            state = self._load_terminal_locked(conn, run_id)
        if (
            state is None or state.state != "available" or now_ms >= state.retention_expires_at_ms
            or state.project_id != expected_project_id or state.grant_id != expected_grant_id
            or state.approval_projection_digest != expected_approval_projection_digest
        ):
            raise TerminalDisclosureUnavailable("terminal disclosure is unavailable")
        lease_id = self._random_source(32)
        if type(lease_id) is not bytes or len(lease_id) != 32:
            raise RunnerRuntimeCorrupt("runtime state random source returned an invalid lease")
        return _TerminalDisclosureLease(self._token, self, state.run_hash, state.state_digest, lease_id)

    def _disclosure_result_cursor(
        self, lease: _TerminalDisclosureLease,
    ) -> Mapping[str, Any]:
        """Return the sealed result cursor for this single in-process lease.

        The cursor is never recovered from a mutable client mirror.  Staging
        rechecks the exact same state digest in its own writer transaction.
        """
        lease = self._require_lease(lease, require_unused=True)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT sealed_blob FROM terminal_disclosures WHERE run_hash=?",
                (lease._run_hash,),
            ).fetchone()
            if row is None:
                raise TerminalDisclosureUnavailable("terminal disclosure is unavailable")
            state = self._validate_terminal_core(self._open(
                row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1",
                primary_fields=(lease._run_hash,),
            ))
        if (
            state.state != "available" or state.state_digest != lease._state_digest
            or state.result_chain is None
        ):
            raise TerminalDisclosureUnavailable("terminal disclosure is unavailable")
        return MappingProxyType(dict(state.result_chain))

    def _require_lease(
        self, lease: object, *, require_unused: bool,
    ) -> _TerminalDisclosureLease:
        if (
            type(lease) is not _TerminalDisclosureLease or lease._backend is not self
            or lease._token is not self._token or len(lease._lease_id) != 32
            or (require_unused and lease._used)
        ):
            raise RunnerRuntimeConflict("runtime disclosure lease is unavailable")
        return lease

    def stage_disclosure_call(
        self, lease: _TerminalDisclosureLease, *, path: str, headers: Mapping[str, str],
        body: bytes, now_ms: int,
    ) -> PendingSignedCall:
        lease = self._require_lease(lease, require_unused=True)
        if type(body) is not bytes or len(body) > 272 * 1024:
            raise RunnerRuntimeStateError("invalid runtime pending body")
        now_ms = _safe_int(now_ms, "runtime disclosure time")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT sealed_blob FROM terminal_disclosures WHERE run_hash=?", (lease._run_hash,),
                ).fetchone()
                if row is None:
                    raise TerminalDisclosureUnavailable("terminal disclosure is unavailable")
                state = self._validate_terminal_core(self._open(
                    row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1",
                    primary_fields=(lease._run_hash,),
                ))
                if (
                    state.state != "available" or state.state_digest != lease._state_digest
                    or state.result_chain is None or now_ms >= state.retention_expires_at_ms
                ):
                    raise TerminalDisclosureUnavailable("terminal disclosure is unavailable")
                run_id = state.run_id
                if not self._expected_path("upload-findings", run_id, path):
                    raise RunnerRuntimeStateError("invalid runtime pending call")
                sequence = state.result_chain["next_sequence"]
                generation = state.result_chain["generation"]
                nonce = state.result_chain["next_nonce_b64"]
                validated_headers = self._validate_signed_headers(
                    capability="runner_result", path=path, body=body, headers=headers,
                    nonce=nonce, sequence=sequence,
                )
                chain = self._chain_key("result", run_id)
                if conn.execute("SELECT 1 FROM pending_calls WHERE chain=?", (chain,)).fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime call is already pending")
                if conn.execute("SELECT COUNT(*) FROM pending_calls").fetchone()[0] >= 74:
                    raise RunnerRuntimeConflict("runtime pending call capacity is exhausted")
                body_digest = hashlib.sha256(body).hexdigest()
                call_id = hashlib.sha256(
                    b"heel.runner-pending-call-id.v1\0" + canonical_bytes({
                        "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
                        "runner_key_id": self.identity.key_id, "request_operation": "upload-findings",
                        "chain_operation": "result", "run_id": run_id, "path": path,
                        "body_sha256": body_digest, "server_nonce_b64": nonce,
                        "sequence": sequence, "generation": generation,
                    })
                ).hexdigest()
                core_without_digest = {
                    "schema_version": "heel.runner-pending-call.v1", "workspace_id": self.identity.workspace_id,
                    "runner_id": self.identity.runner_id, "runner_key_id": self.identity.key_id,
                    "call_id": call_id, "request_operation": "upload-findings", "chain_operation": "result",
                    "run_id": run_id, "path": path, "capability": "runner_result", "method": "POST",
                    "headers": validated_headers, "body_b64": self._canonical_b64(body),
                    "body_sha256": body_digest, "server_nonce_b64": nonce,
                    "sequence": sequence, "generation": generation,
                    "prior_chain_state_digest": state.state_digest, "created_at_ms": now_ms,
                }
                core = {**core_without_digest, "state_digest": _state_digest(core_without_digest)}
                pending, _ = self._validate_pending_core(core)
                blob = self._seal(core, schema=core["schema_version"], primary_fields=(call_id,))
                if len(blob) > 384 * 1024:
                    raise RunnerRuntimeStateError("runtime pending call exceeds size limit")
                conn.execute(
                    "INSERT INTO pending_calls(call_id,chain,run_hash,operation,sequence,generation,sealed_blob,created_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (call_id, chain, state.run_hash, "upload-findings", sequence, generation, blob, now_ms),
                )
                conn.execute("COMMIT")
                lease._used = True
                return pending
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def commit_disclosure(
        self, call_id: str, lease: _TerminalDisclosureLease, *, next_nonce_b64: str,
        permit_id: str, findings_projection_digest: str, receipt_digest: str,
        disclosed_at_ms: int,
    ) -> TerminalDisclosureState:
        call_id = _digest(call_id, "runtime pending call ID")
        lease = self._require_lease(lease, require_unused=False)
        next_nonce_b64 = _nonce(next_nonce_b64)
        permit_id = _text(permit_id, "runtime disclosure permit ID") or ""
        findings_projection_digest = _digest(findings_projection_digest, "runtime findings projection digest")
        receipt_digest = _digest(receipt_digest, "runtime disclosure receipt digest")
        disclosed_at_ms = _safe_int(disclosed_at_ms, "runtime disclosure time")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT chain,run_hash,sealed_blob FROM pending_calls WHERE call_id=?", (call_id,),
                ).fetchone()
                if row is None:
                    raise RunnerRuntimeConflict("runtime pending call is unavailable")
                pending, _pending_core = self._validate_pending_core(self._open(
                    row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(call_id,),
                ))
                if (
                    pending.request_operation != "upload-findings" or pending.chain_operation != "result"
                    or pending.run_id is None or row["run_hash"] != lease._run_hash
                    or row["chain"] != self._chain_key("result", pending.run_id)
                ):
                    raise RunnerRuntimeCorrupt("runtime pending disclosure is invalid")
                state = self._load_terminal_locked(conn, pending.run_id)
                if (
                    state is None or state.state != "available" or state.state_digest != lease._state_digest
                    or state.result_chain is None or pending.prior_chain_state_digest != state.state_digest
                    or pending.sequence != state.result_chain["next_sequence"]
                    or pending.generation != state.result_chain["generation"]
                    or pending.headers["X-Heel-Runner-Nonce"] != state.result_chain["next_nonce_b64"]
                    or next_nonce_b64 == state.result_chain["next_nonce_b64"]
                    or not state.terminal_at_ms <= disclosed_at_ms < state.retention_expires_at_ms
                ):
                    raise RunnerRuntimeCorrupt("runtime disclosure does not match local authority")
                core = self._terminal_core(
                    state="consumed", workspace_id=self.identity.workspace_id,
                    runner_id=self.identity.runner_id, runner_key_id=self.identity.key_id,
                    run_id=state.run_id, run_hash=state.run_hash, project_id=state.project_id,
                    grant_id=state.grant_id, approval_projection_digest=state.approval_projection_digest,
                    terminal_projection_digest=state.terminal_projection_digest,
                    terminal_record_digest=state.terminal_record_digest,
                    terminal_at_ms=state.terminal_at_ms,
                    retention_expires_at_ms=state.retention_expires_at_ms,
                    result_chain=None, available_at_ms=state.available_at_ms, permit_id=permit_id,
                    findings_projection_digest=findings_projection_digest, receipt_digest=receipt_digest,
                    disclosed_at_ms=disclosed_at_ms, revision=3, prior_state_digest=state.state_digest,
                )
                consumed = self._validate_terminal_core(core)
                blob = self._seal(core, schema=core["schema_version"], primary_fields=(state.run_hash,))
                conn.execute(
                    "UPDATE terminal_disclosures SET state=?,sealed_blob=?,updated_at_ms=? WHERE run_hash=?",
                    (consumed.state, blob, disclosed_at_ms, state.run_hash),
                )
                conn.execute("DELETE FROM pending_calls WHERE call_id=?", (call_id,))
                conn.execute("COMMIT")
                return consumed
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _prune_pending_core(self, state: TerminalDisclosureState) -> dict[str, Any]:
        return self._terminal_core(
            state="prune_pending", workspace_id=state.workspace_id,
            runner_id=state.runner_id, runner_key_id=state.runner_key_id,
            run_id=state.run_id, run_hash=state.run_hash, project_id=state.project_id,
            grant_id=state.grant_id, approval_projection_digest=state.approval_projection_digest,
            terminal_projection_digest=state.terminal_projection_digest,
            terminal_record_digest=state.terminal_record_digest,
            terminal_at_ms=state.terminal_at_ms,
            retention_expires_at_ms=state.retention_expires_at_ms,
            result_chain=None, available_at_ms=state.available_at_ms, permit_id=state.permit_id,
            findings_projection_digest=state.findings_projection_digest,
            receipt_digest=state.receipt_digest, disclosed_at_ms=state.disclosed_at_ms,
            revision=state.revision + 1, prior_state_digest=state.state_digest,
        )

    def claim_due_prune(
        self, *, now_ms: int, limit: int = 16,
    ) -> tuple[TerminalDisclosureState, ...]:
        now_ms = _safe_int(now_ms, "runtime prune time")
        if type(limit) is not int or not 1 <= limit <= 16:
            raise RunnerRuntimeStateError("invalid runtime prune limit")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    "SELECT run_hash,sealed_blob FROM terminal_disclosures "
                    "WHERE state IN ('local_terminal','available','consumed') "
                    "AND retention_expires_at_ms<=? ORDER BY retention_expires_at_ms,run_hash LIMIT ?",
                    (now_ms, limit),
                ).fetchall()
                claimed: list[TerminalDisclosureState] = []
                for row in rows:
                    state = self._validate_terminal_core(self._open(
                        row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1",
                        primary_fields=(row["run_hash"],),
                    ))
                    if state.run_hash != row["run_hash"] or state.state == "prune_pending":
                        raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")
                    core = self._prune_pending_core(state)
                    pending = self._validate_terminal_core(core)
                    blob = self._seal(core, schema=core["schema_version"], primary_fields=(state.run_hash,))
                    conn.execute(
                        "UPDATE terminal_disclosures SET state=?,sealed_blob=?,updated_at_ms=? "
                        "WHERE run_hash=? AND state=?",
                        (pending.state, blob, now_ms, state.run_hash, state.state),
                    )
                    claimed.append(pending)
                conn.execute("COMMIT")
                return tuple(claimed)
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def finish_prune(
        self, run_id: str, *, expected_state_digest: str, pruned_record_digest: str,
        now_ms: int,
    ) -> None:
        run_id = _run_id(run_id)
        assert run_id is not None
        expected_state_digest = _digest(expected_state_digest, "runtime prune state digest")
        _digest(pruned_record_digest, "runtime pruned record digest")
        now_ms = _safe_int(now_ms, "runtime prune time")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                state = self._load_terminal_locked(conn, run_id)
                if (
                    state is None or state.state != "prune_pending"
                    or state.state_digest != expected_state_digest
                    or now_ms < state.retention_expires_at_ms
                ):
                    raise RunnerRuntimeCorrupt("runtime terminal prune does not match local authority")
                conn.execute("DELETE FROM terminal_disclosures WHERE run_hash=?", (state.run_hash,))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
