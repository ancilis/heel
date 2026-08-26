"""Durable, authenticated runner control state.

The runtime database deliberately stores only opaque routing keys and AEAD sealed
state.  It is a local replay barrier, not a second control-plane authority.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Protocol
import unicodedata

from heel.canary_contracts import (
    canonical_bytes, validate_approval_projection, validate_execution_grant,
)
from heel.crypto import load_public_key_base64, verify_envelope
from heel.runner.identity import (
    AcceptedRotationAbortTombstone, AcceptedRotationJournal, RunnerIdentity, SecureSigner,
)


_SCHEMA_V1 = "heel.runner-runtime-state.v1"
_SCHEMA_V2 = "heel.runner-runtime-state.v2"
_SCHEMA = "heel.runner-runtime-state.v3"
_SEAL_DOMAIN = b"heel.runner-runtime-state-seal.v1\0"
_STATE_KEY_WRAP_DOMAIN = b"heel.runner-runtime-state-key-wrap.v1\0"
_DIGEST_DOMAIN = b"heel.runner-runtime-state-digest.v1\0"
_ACTIVE_STATE_DIGEST_DOMAIN = b"heel.runner-active-run-state-digest.v1\0"
_AUTHORITY_IDENTITY_DOMAIN = b"heel.runner-runtime-authority-identity.v1\0"
_RUNTIME_PRUNED_RECEIPT_DOMAIN = b"heel.local-run-pruned.v2\0"
_MAX_SAFE_INT = 9_007_199_254_740_991
_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_RUN_ID = re.compile(r"^crun_[0-9a-f]{32}$", re.ASCII)
_B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$", re.ASCII)

# This child deliberately has no package imports or ambient-process inputs.  It
# receives only the pinned database leaf and a private AF_UNIX socket, then
# tests whether SQLite locked that exact leaf's PENDING/RESERVED/SHARED range.
_RUNTIME_INODE_GUARD_BOOTSTRAP = (
    "import errno,fcntl,os,socket,stat,sys\n"
    "leaf_fd=-1\n"
    "control_fd=-1\n"
    "control=None\n"
    "try:\n"
    " if len(sys.argv)!=3: raise ValueError()\n"
    " def parse_fd(value):\n"
    "  if not value.isascii() or not value.isdecimal(): raise ValueError()\n"
    "  descriptor=int(value)\n"
    "  if descriptor<=2 or str(descriptor)!=value: raise ValueError()\n"
    "  return descriptor\n"
    " leaf_fd=parse_fd(sys.argv[1])\n"
    " control_fd=parse_fd(sys.argv[2])\n"
    " if leaf_fd==control_fd: raise ValueError()\n"
    " leaf_stat=os.fstat(leaf_fd)\n"
    " if (not stat.S_ISREG(leaf_stat.st_mode) or leaf_stat.st_uid!=os.geteuid() "
    "or leaf_stat.st_nlink!=1 or (stat.S_IMODE(leaf_stat.st_mode)&0o077)): raise ValueError()\n"
    " control=socket.socket(fileno=control_fd)\n"
    " if control.family!=socket.AF_UNIX or (control.type&0xf)!=socket.SOCK_STREAM: raise ValueError()\n"
    " os.set_inheritable(leaf_fd,False)\n"
    " os.set_inheritable(control_fd,False)\n"
    " while True:\n"
    "  request=control.recv(2)\n"
    "  if len(request)!=1: raise ValueError()\n"
    "  if request==b'Q': break\n"
    "  if request!=b'P': raise ValueError()\n"
    "  try:\n"
    "   fcntl.lockf(leaf_fd,fcntl.LOCK_EX|fcntl.LOCK_NB,512,0x40000000,os.SEEK_SET)\n"
    "  except OSError as error:\n"
    "   if error.errno not in (errno.EACCES,errno.EAGAIN): raise\n"
    "   control.sendall(b'L')\n"
    "  else:\n"
    "   fcntl.lockf(leaf_fd,fcntl.LOCK_UN,512,0x40000000,os.SEEK_SET)\n"
    "   control.sendall(b'U')\n"
    "except BaseException:\n"
    " raise SystemExit(2)\n"
    "finally:\n"
    " if control is not None:\n"
    "  control.close()\n"
    " elif control_fd>2:\n"
    "  os.close(control_fd)\n"
    " if leaf_fd>2:\n"
    "  os.close(leaf_fd)\n"
)


_RUNTIME_TABLES = (
    "metadata", "control_chains", "pending_calls", "terminal_disclosures", "active_runs",
)
_RUNTIME_INDEXES = (
    "idx_pending_calls_created", "idx_terminal_disclosures_state_retention",
    "idx_terminal_disclosures_due_retention", "idx_pending_calls_run_operation",
)
_RUNTIME_OWNED_NAMES = frozenset((*_RUNTIME_TABLES, *_RUNTIME_INDEXES))

# These literals are deliberately also used to build the in-memory parity reference.
# Keep the SQL constraints closed: a permissive pre-created database is never a migration
# candidate and therefore can never acquire runner authority by being opened.
_V3_SCHEMA_SQL = (
    "CREATE TABLE metadata("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v3'),"
    "workspace_id TEXT NOT NULL CHECK(length(CAST(workspace_id AS BLOB)) BETWEEN 1 AND 128 AND instr(workspace_id,char(0))=0),"
    "runner_id TEXT NOT NULL CHECK(length(CAST(runner_id AS BLOB)) BETWEEN 1 AND 128 AND instr(runner_id,char(0))=0),"
    "runner_key_id TEXT NOT NULL CHECK(length(CAST(runner_key_id AS BLOB)) BETWEEN 1 AND 128 AND instr(runner_key_id,char(0))=0),"
    "public_key_digest TEXT NOT NULL CHECK(length(public_key_digest)=64 AND public_key_digest NOT GLOB '*[^0-9a-f]*'),"
    "authority_epoch INTEGER NOT NULL CHECK(authority_epoch BETWEEN 1 AND 9007199254740991),"
    "authority_identity_digest TEXT NOT NULL CHECK(length(authority_identity_digest)=64 AND authority_identity_digest NOT GLOB '*[^0-9a-f]*'),"
    "rotation_fence_digest TEXT CHECK(rotation_fence_digest IS NULL OR (length(rotation_fence_digest)=64 AND rotation_fence_digest NOT GLOB '*[^0-9a-f]*')),"
    "state_key_ciphertext BLOB NOT NULL CHECK(typeof(state_key_ciphertext)='blob' AND length(state_key_ciphertext)=60))",
    "CREATE TABLE control_chains("
    "chain TEXT PRIMARY KEY CHECK(length(chain)=64 AND chain NOT GLOB '*[^0-9a-f]*'),"
    "run_hash TEXT CHECK(run_hash IS NULL OR (length(run_hash)=64 AND run_hash NOT GLOB '*[^0-9a-f]*')),"
    "operation TEXT NOT NULL CHECK(operation IN ('claim','heartbeat','progress','result','stop-ack')),"
    "next_sequence INTEGER NOT NULL CHECK(next_sequence BETWEEN 1 AND 9007199254740991),"
    "generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 9007199254740991),"
    "sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob)='blob' AND length(sealed_blob) BETWEEN 29 AND 4096),"
    "updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN 0 AND 9007199254740991),"
    "CHECK(operation='claim' AND run_hash IS NULL OR operation!='claim' AND run_hash IS NOT NULL))",
    "CREATE TABLE pending_calls("
    "call_id TEXT PRIMARY KEY CHECK(length(call_id)=64 AND call_id NOT GLOB '*[^0-9a-f]*'),"
    "chain TEXT NOT NULL UNIQUE CHECK(length(chain)=64 AND chain NOT GLOB '*[^0-9a-f]*'),"
    "run_hash TEXT CHECK(run_hash IS NULL OR (length(run_hash)=64 AND run_hash NOT GLOB '*[^0-9a-f]*')),"
    "operation TEXT NOT NULL CHECK(operation IN ('claim','heartbeat','progress','result','stop-ack','upload-findings','list-contexts','claim-context','submit-context-approval-projection')),"
    "sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),"
    "generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 9007199254740991),"
    "sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob)='blob' AND length(sealed_blob) BETWEEN 29 AND 393216),"
    "created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9007199254740991),"
    "CHECK(run_hash IS NULL AND operation IN ('claim','list-contexts','claim-context','submit-context-approval-projection') OR run_hash IS NOT NULL AND operation IN ('heartbeat','progress','result','stop-ack','upload-findings')))",
    "CREATE TABLE terminal_disclosures("
    "run_hash TEXT PRIMARY KEY CHECK(length(run_hash)=64 AND run_hash NOT GLOB '*[^0-9a-f]*'),"
    "retention_expires_at_ms INTEGER NOT NULL CHECK(retention_expires_at_ms BETWEEN 0 AND 9007199254740991),"
    "state TEXT NOT NULL CHECK(state IN ('local_terminal','available','consumed','prune_pending')),"
    "sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob)='blob' AND length(sealed_blob) BETWEEN 29 AND 393216),"
    "updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN 0 AND 9007199254740991))",
    "CREATE TABLE active_runs("
    "run_hash TEXT PRIMARY KEY CHECK(length(run_hash)=64 AND run_hash NOT GLOB '*[^0-9a-f]*'),"
    "sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob)='blob' AND length(sealed_blob) BETWEEN 29 AND 393216),"
    "updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN 0 AND 9007199254740991))",
    "CREATE INDEX idx_pending_calls_created ON pending_calls(created_at_ms,call_id)",
    "CREATE INDEX idx_pending_calls_run_operation ON pending_calls(run_hash,operation,call_id) WHERE run_hash IS NOT NULL",
    "CREATE INDEX idx_terminal_disclosures_state_retention ON terminal_disclosures(state,retention_expires_at_ms,run_hash)",
    "CREATE INDEX idx_terminal_disclosures_due_retention ON terminal_disclosures(retention_expires_at_ms,run_hash) WHERE state IN ('local_terminal','available','consumed')",
)

_V2_SCHEMA_SQL = (
    "CREATE TABLE metadata("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v2'),"
    "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
    "public_key_digest TEXT NOT NULL,state_key_ciphertext BLOB NOT NULL)",
    "CREATE TABLE control_chains("
    "chain TEXT PRIMARY KEY,run_hash TEXT NULL,operation TEXT NOT NULL,"
    "next_sequence INTEGER NOT NULL,generation INTEGER NOT NULL,sealed_blob BLOB NOT NULL,"
    "updated_at_ms INTEGER NOT NULL)",
    "CREATE TABLE pending_calls("
    "call_id TEXT PRIMARY KEY,chain TEXT NOT NULL UNIQUE,run_hash TEXT NULL,operation TEXT NOT NULL,"
    "sequence INTEGER NOT NULL,generation INTEGER NOT NULL,sealed_blob BLOB NOT NULL,"
    "created_at_ms INTEGER NOT NULL)",
    "CREATE TABLE terminal_disclosures("
    "run_hash TEXT PRIMARY KEY,retention_expires_at_ms INTEGER NOT NULL,"
    "state TEXT NOT NULL CHECK(state IN ('local_terminal','available','consumed','prune_pending')),"
    "sealed_blob BLOB NOT NULL,updated_at_ms INTEGER NOT NULL)",
    "CREATE INDEX idx_terminal_disclosures_state_retention ON terminal_disclosures(state,retention_expires_at_ms,run_hash)",
)

_V1_SCHEMA_SQL = (
    "CREATE TABLE metadata("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "schema_version TEXT NOT NULL CHECK(schema_version='heel.runner-runtime-state.v1'),"
    "workspace_id TEXT NOT NULL,runner_id TEXT NOT NULL,runner_key_id TEXT NOT NULL,"
    "public_key_digest TEXT NOT NULL)",
    _V2_SCHEMA_SQL[1],
)


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


class _RuntimeSqliteConnection(sqlite3.Connection):
    """Connection that authenticates authority after each transaction begins."""

    _runtime: Any | None = None
    _allow_rotation_fence = False
    _authority_guard_enabled = False

    def configure_runtime_guard(
        self, runtime: "RunnerRuntimeState", *, allow_rotation_fence: bool,
    ) -> None:
        self._runtime = runtime
        self._allow_rotation_fence = allow_rotation_fence
        self._authority_guard_enabled = True

    @staticmethod
    def _is_transaction_begin(statement: object) -> bool:
        return type(statement) is str and statement.lstrip().upper().startswith("BEGIN")

    @staticmethod
    def _is_transaction_end(statement: object) -> bool:
        return type(statement) is str and statement.lstrip().upper().startswith(("COMMIT", "ROLLBACK"))

    def _validate_after_begin(self) -> None:
        runtime = self._runtime
        if runtime is None:
            raise RunnerRuntimeCorrupt("runtime state database is invalid")
        runtime._validate_transaction_authority_locked(
            self, allow_rotation_fence=self._allow_rotation_fence,
        )

    def execute(self, sql: str, parameters: object = ()) -> sqlite3.Cursor:
        if not self._authority_guard_enabled:
            return super().execute(sql, parameters)
        if self._is_transaction_begin(sql):
            cursor = super().execute(sql, parameters)
            self._validate_after_begin()
            return cursor
        # Callers that only read do not otherwise issue BEGIN.  Start a snapshot
        # and authenticate its metadata before their first child-row access.
        if not self.in_transaction and not self._is_transaction_end(sql):
            super().execute("BEGIN")
            self._validate_after_begin()
        return super().execute(sql, parameters)


@dataclass(frozen=True, slots=True)
class RotationEligibility:
    authority_epoch: int
    authority_identity_digest: str
    claim_state_digest: str
    runtime_rotation_intent_digest: str
    prepared_journal_digest: str


@dataclass(frozen=True, slots=True)
class RotationEligibilityProbe:
    authority_epoch: int
    authority_identity_digest: str
    claim_state_digest: str


@dataclass(frozen=True, slots=True)
class RuntimePruneCompletion:
    """Nominal proof that one exact runtime prune CAS committed."""

    run_hash: str
    pruned_record_digest: str
    runtime_prune_pending_state_digest: str
    authority_epoch: int
    _issuer: object = field(repr=False, compare=False)

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("runtime prune completion cannot be serialized")


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
    state_digest: str

    @property
    def pending_state_digest(self) -> str:
        """The authenticated sealed pending-record digest used by recovery CAS."""
        return self.state_digest


@dataclass(frozen=True, slots=True)
class PendingResultReplayAuthority:
    """Nominal, single-attempt Store authority for one sealed terminal replay."""

    call_id: str
    pending_state_digest: str
    run_id: str
    body_sha256: str
    active_state_digest: str
    runtime_terminal_state_digest: str
    terminal_record_digest: str
    detached_record_digest: str
    terminal_projection_digest: str
    retention_expires_at_ms: int
    _issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class TerminalResultStageEvidence:
    """Nominal Store authority to stage exactly one recovered terminal result."""

    run_id: str
    operational_projection: Mapping[str, object]
    body_sha256: str
    active_state_digest: str
    runtime_terminal_state_digest: str
    terminal_record_digest: str
    detached_record_digest: str
    terminal_projection_digest: str
    retention_expires_at_ms: int
    _issuer: object = field(repr=False, compare=False)


class PendingResultReplayVerifier(Protocol):
    """Opaque coordinator/Store bridge; clients never receive a RunnerStore."""

    def authorize_pending_result_replay(
        self, pending: PendingSignedCall, *, now_ms: int,
    ) -> PendingResultReplayAuthority: ...

    def consume(
        self, authority: PendingResultReplayAuthority, *, expected_fields: Mapping[str, object],
    ) -> None: ...

    def authorize_unstaged_terminal_result(
        self, run_id: str, *, now_ms: int,
    ) -> TerminalResultStageEvidence: ...

    def consume_stage(
        self, evidence: TerminalResultStageEvidence, *, expected_fields: Mapping[str, object],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ActiveRunInstall:
    """Authenticated claim-200 authority to be committed with its four cursors."""

    run_id: str
    approval_projection: Mapping[str, Any]
    grant: Mapping[str, Any]
    gate: Mapping[str, Any]
    claim_response_digest: str
    gate_response_digest: str
    claimed_at_ms: int
    gate_received_at_ms: int


@dataclass(frozen=True, slots=True)
class ActiveGateUpdate:
    gate: Mapping[str, Any]
    gate_response_digest: str
    received_at_ms: int


@dataclass(frozen=True, slots=True)
class ActiveRunControl:
    run_id: str
    project_id: str
    approval_id: str
    grant_id: str
    grant_digest: str
    approval_projection_digest: str
    approval_projection: Mapping[str, Any]
    grant: Mapping[str, Any]
    gate: Mapping[str, Any]
    claim_response_digest: str
    latest_gate_response_digest: str
    claimed_at_ms: int
    gate_received_at_ms: int
    revision: int
    prior_state_digest: str | None
    state_digest: str
    chains: Mapping[str, RunnerChainCursor]


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


@dataclass(frozen=True, slots=True)
class PrunePendingBatch:
    items: tuple[TerminalDisclosureState, ...]
    has_more: bool

    # Existing local callers treated the old tuple result as a sequence.  The durable
    # batch is still bounded and exposes that read-only convenience while callers move
    # to the explicit ``items``/``has_more`` contract.
    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, index: int) -> TerminalDisclosureState:
        return self.items[index]


@dataclass(frozen=True, slots=True)
class TerminalDisclosureBatch:
    """Bounded read-only local-terminal recovery work."""

    items: tuple[TerminalDisclosureState, ...]
    has_more: bool


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


def _active_state_digest(core: Mapping[str, Any]) -> str:
    """Digest a sealed active record whose protocol gate deliberately contains Booleans."""
    try:
        payload = _active_json_bytes(core)
    except (TypeError, ValueError):
        raise RunnerRuntimeCorrupt("runtime active run state is invalid") from None
    return hashlib.sha256(_ACTIVE_STATE_DIGEST_DOMAIN + payload).hexdigest()


def _active_json_value(value: Any, *, depth: int = 0) -> Any:
    """Validate the deliberately narrow Boolean-capable active-state JSON grammar."""
    if depth > 16:
        raise ValueError("runtime active value nesting is invalid")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not 0 <= value <= _MAX_SAFE_INT:
            raise ValueError("runtime active integer is invalid")
        return value
    if type(value) is str:
        if (
            unicodedata.normalize("NFC", value) != value
            or any(
                unicodedata.category(char) == "Cc" or 0xD800 <= ord(char) <= 0xDFFF
                for char in value
            )
            or len(value.encode("utf-8")) > 4096
        ):
            raise ValueError("runtime active text is invalid")
        return value
    if type(value) is list:
        return [_active_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or key in output:
                raise ValueError("runtime active mapping is invalid")
            output[_active_json_value(key, depth=depth + 1)] = _active_json_value(
                item, depth=depth + 1,
            )
        return output
    raise ValueError("runtime active value is invalid")


def _active_json_bytes(core: Mapping[str, Any]) -> bytes:
    """Encode active rows without widening the public runner canonicalizer."""
    if not isinstance(core, Mapping):
        raise ValueError("runtime active core is invalid")
    encoded = json.dumps(
        _active_json_value(core), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    # The active table's sealed blob cap includes the 12-byte AEAD nonce and
    # the 16-byte authentication tag.
    if len(encoded) + 28 > 393_216:
        raise ValueError("runtime active state is too large")
    return encoded


def _active_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("runtime active JSON has duplicate keys")
        result[key] = value
    return result


def _active_json_parse(plaintext: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(
            plaintext.decode("utf-8"), object_pairs_hook=_active_json_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("runtime active float is invalid")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("runtime active constant is invalid")),
        )
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("runtime active JSON is invalid") from exc
    if not isinstance(decoded, dict) or _active_json_bytes(decoded) != plaintext:
        raise ValueError("runtime active JSON is not canonical")
    return decoded


class RunnerRuntimeState:
    """A sealed SQLite replay ledger tied to one exact runner identity."""

    def __init__(
        self, path: Path | str, identity: RunnerIdentity, signer: SecureSigner,
        random_source=os.urandom, *, _allow_rotation_recovery: bool = False,
    ) -> None:
        self._crypto = _load_runtime_crypto()
        self.path = self._lexical_runtime_path(path)
        self.identity = identity
        self.signer = signer
        self._random_source = random_source
        self._allow_rotation_recovery = _allow_rotation_recovery is True
        self._token = object()
        self._state_lock = threading.RLock()
        self._poisoned = False
        self._initialized = False
        self._authority_epoch = 0
        self._authority_identity_digest = ""
        self._parent_fd: int | None = None
        self._leaf_fd: int | None = None
        self._leaf_identity: tuple[int, int, int, int, int] | None = None
        self._parent_identities: tuple[tuple[Path, tuple[int, int, int, int]], ...] = ()
        self._created_leaf = False
        self._inode_guard_process: subprocess.Popen[bytes] | None = None
        self._inode_guard_control: socket.socket | None = None
        self._closed = False
        self._validate_identity()
        self._kek = self._derive_key()
        self._key = b""
        try:
            self._prepare_path()
            with self._connection() as conn:
                self._initialize(conn, allow_rotation_fence=self._allow_rotation_recovery)
            self._assert_secure_path_unchanged()
            self._initialized = True
        except Exception:
            self._cleanup_failed_path()
            raise

    @staticmethod
    def _lexical_runtime_path(path: Path | str) -> Path:
        try:
            raw_path = os.fspath(path)
        except TypeError as exc:
            raise RunnerRuntimeCorrupt("runtime state path is invalid") from exc
        if type(raw_path) is not str or "\0" in raw_path:
            raise RunnerRuntimeCorrupt("runtime state path is invalid")
        expanded = os.path.expanduser(raw_path)
        if any(component in {".", ".."} for component in expanded.split(os.sep)):
            raise RunnerRuntimeCorrupt("runtime state path is invalid")
        absolute = os.path.abspath(expanded)
        runtime_path = Path(absolute)
        if not runtime_path.name:
            raise RunnerRuntimeCorrupt("runtime state path is invalid")
        return runtime_path

    @staticmethod
    def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev, value.st_ino, value.st_uid,
            stat.S_IFMT(value.st_mode), value.st_nlink,
        )

    @staticmethod
    def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
        return value.st_dev, value.st_ino, value.st_uid, stat.S_IFMT(value.st_mode)

    @staticmethod
    def _private_directory(value: os.stat_result) -> bool:
        return (
            stat.S_ISDIR(value.st_mode)
            and not stat.S_ISLNK(value.st_mode)
            and value.st_uid == os.geteuid()
            and not (stat.S_IMODE(value.st_mode) & 0o077)
        )

    @staticmethod
    def _private_runtime_leaf(value: os.stat_result) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and not stat.S_ISLNK(value.st_mode)
            and value.st_uid == os.geteuid()
            and value.st_nlink == 1
            and not (stat.S_IMODE(value.st_mode) & 0o077)
        )

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
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(self.path.anchor, flags)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state parent is unavailable") from exc
        identities: list[tuple[Path, tuple[int, int, int, int]]] = []
        current = Path(self.path.anchor)
        try:
            for component in self.path.parts[1:-1]:
                current = current / component
                try:
                    component_stat = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                    component_stat = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(component_stat.st_mode) or not stat.S_ISDIR(component_stat.st_mode):
                    raise RunnerRuntimeCorrupt("runtime state parent is unsafe")
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
                identities.append((current, self._directory_identity(component_stat)))
            parent_stat = os.fstat(directory_fd)
            if not self._private_directory(parent_stat):
                raise RunnerRuntimeCorrupt("runtime state parent is unsafe")
            try:
                leaf_stat = os.stat(self.path.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    leaf_fd = os.open(
                        self.path.name,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise RunnerRuntimeCorrupt("runtime state is unsafe") from exc
                self._created_leaf = True
                leaf_stat = os.fstat(leaf_fd)
            else:
                if not self._private_runtime_leaf(leaf_stat):
                    raise RunnerRuntimeCorrupt("runtime state is unsafe")
                try:
                    leaf_fd = os.open(
                        self.path.name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise RunnerRuntimeCorrupt("runtime state is unsafe") from exc
            leaf_fd_stat = os.fstat(leaf_fd)
            if not self._private_runtime_leaf(leaf_stat) or self._file_identity(leaf_stat) != self._file_identity(leaf_fd_stat):
                os.close(leaf_fd)
                raise RunnerRuntimeCorrupt("runtime state is unsafe")
        except Exception:
            os.close(directory_fd)
            raise
        self._parent_fd = directory_fd
        self._leaf_fd = leaf_fd
        self._leaf_identity = self._file_identity(leaf_fd_stat)
        self._parent_identities = tuple(identities)
        self._start_inode_guard()

    def _start_inode_guard(self) -> None:
        if self._leaf_fd is None or self._inode_guard_process is not None or self._inode_guard_control is not None:
            raise RunnerRuntimeCorrupt("runtime state helper is invalid")
        executable = sys.executable
        if type(executable) is not str or "\0" in executable or not os.path.isabs(executable):
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable")
        try:
            executable_stat = os.stat(executable)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable") from exc
        if not stat.S_ISREG(executable_stat.st_mode) or executable_stat.st_uid != os.geteuid():
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable")
        try:
            parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable") from exc
        child_fd = child_control.fileno()
        pass_fds = tuple(sorted((self._leaf_fd, child_fd)))
        if len(pass_fds) != 2 or pass_fds[0] <= 2 or pass_fds[1] <= 2:
            parent_control.close()
            child_control.close()
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable")
        argv = [
            executable,
            "-I", "-S", "-B", "-c", _RUNTIME_INODE_GUARD_BOOTSTRAP,
            str(self._leaf_fd), str(child_fd),
        ]
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=pass_fds,
                cwd="/",
                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
                start_new_session=True,
                restore_signals=True,
            )
        except OSError as exc:
            parent_control.close()
            child_control.close()
            raise RunnerRuntimeCorrupt("runtime state helper is unavailable") from exc
        child_control.close()
        self._inode_guard_process = process
        self._inode_guard_control = parent_control

    def _stop_inode_guard(self) -> None:
        control = self._inode_guard_control
        process = self._inode_guard_process
        self._inode_guard_control = None
        self._inode_guard_process = None
        if control is not None:
            try:
                control.settimeout(1.0)
                control.sendall(b"Q")
            except OSError:
                pass
            finally:
                control.close()
        if process is not None:
            try:
                process.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    process.terminate()
                    process.wait(timeout=1.0)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        process.kill()
                        process.wait(timeout=1.0)
                    except (subprocess.TimeoutExpired, OSError):
                        pass

    def _poison_inode_guard(self, message: str) -> None:
        self._poisoned = True
        self._stop_inode_guard()
        raise RunnerRuntimeCorrupt(message)

    def _probe_inode_guard(self) -> None:
        process = self._inode_guard_process
        control = self._inode_guard_control
        if process is None or control is None or process.poll() is not None:
            self._poison_inode_guard("runtime state helper is unavailable")
        try:
            control.settimeout(1.0)
            control.sendall(b"P")
            response = control.recv(2)
            control.setblocking(False)
            try:
                extra = control.recv(1)
            except BlockingIOError:
                extra = None
            finally:
                control.settimeout(None)
        except (OSError, socket.timeout) as exc:
            self._poison_inode_guard("runtime state helper is unavailable")
            raise AssertionError("unreachable") from exc
        if len(response) != 1 or extra is not None or process.poll() is not None:
            self._poison_inode_guard("runtime state helper is unavailable")
        if response != b"L":
            self._poison_inode_guard("runtime state is unsafe")

    def _assert_secure_path_unchanged(self) -> None:
        if self._parent_fd is None or self._leaf_fd is None or self._leaf_identity is None:
            raise RunnerRuntimeCorrupt("runtime state is unsafe")
        try:
            for path, expected in self._parent_identities:
                current = os.lstat(path)
                if self._directory_identity(current) != expected or stat.S_ISLNK(current.st_mode):
                    raise RunnerRuntimeCorrupt("runtime state parent is unsafe")
            lexical = os.lstat(self.path)
            from_parent = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            from_fd = os.fstat(self._leaf_fd)
        except OSError as exc:
            raise RunnerRuntimeCorrupt("runtime state is unavailable") from exc
        if (
            not self._private_runtime_leaf(lexical)
            or self._file_identity(lexical) != self._leaf_identity
            or self._file_identity(from_parent) != self._leaf_identity
            or self._file_identity(from_fd) != self._leaf_identity
        ):
            raise RunnerRuntimeCorrupt("runtime state is unsafe")

    def _cleanup_failed_path(self) -> None:
        try:
            if self._created_leaf and self._parent_fd is not None and self._leaf_fd is not None:
                leaf_stat = os.fstat(self._leaf_fd)
                if leaf_stat.st_size == 0 and self._file_identity(leaf_stat) == self._leaf_identity:
                    os.unlink(self.path.name, dir_fd=self._parent_fd)
        except OSError:
            pass
        finally:
            self._stop_inode_guard()
            for name in ("_leaf_fd", "_parent_fd"):
                descriptor = getattr(self, name, None)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, name, None)

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._stop_inode_guard()
            for name in ("_leaf_fd", "_parent_fd"):
                descriptor = getattr(self, name, None)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, name, None)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @contextmanager
    def _connection(self, *, allow_rotation_fence: bool = False) -> Iterator[sqlite3.Connection]:
        if self._poisoned or self._closed:
            raise RunnerRuntimeCorrupt("runtime state requires reconstruction")
        with self._state_lock:
            self._assert_secure_path_unchanged()
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(
                    str(self.path), isolation_level=None, factory=_RuntimeSqliteConnection,
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout=0")
                locking_mode = conn.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
                if locking_mode is None or type(locking_mode[0]) is not str or locking_mode[0].lower() != "exclusive":
                    self._poison_inode_guard("runtime state helper is unavailable")
                conn.execute("BEGIN EXCLUSIVE")
                try:
                    self._probe_inode_guard()
                    self._assert_secure_path_unchanged()
                    conn.execute("COMMIT")
                except BaseException:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.DatabaseError:
                        pass
                    raise
                self._assert_secure_path_unchanged()
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA secure_delete=ON")
                conn.execute("PRAGMA synchronous=FULL")
                journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
                if journal_mode is None or type(journal_mode[0]) is not str or journal_mode[0].lower() != "wal":
                    self._poison_inode_guard("runtime state helper is unavailable")
                if self._initialized:
                    self._validate_open_runtime(
                        conn, allow_rotation_fence=allow_rotation_fence or self._allow_rotation_recovery,
                    )
                    conn.configure_runtime_guard(
                        self,
                        allow_rotation_fence=allow_rotation_fence or self._allow_rotation_recovery,
                    )
                yield conn
            except sqlite3.DatabaseError as exc:
                raise RunnerRuntimeCorrupt("runtime state database is invalid") from exc
            finally:
                if conn is not None:
                    conn.close()

    @staticmethod
    def _normalized_sql(value: object) -> str:
        if type(value) is not str:
            raise RunnerRuntimeCorrupt("runtime state schema is invalid")
        return "".join(character for character in value if character not in " \t\n\r\f\v")

    @staticmethod
    def _reference_schema(statements: tuple[str, ...]) -> sqlite3.Connection:
        reference = sqlite3.connect(":memory:")
        try:
            for statement in statements:
                reference.execute(statement)
        except sqlite3.DatabaseError as exc:  # Literal programming mistake, never recover a disk file.
            reference.close()
            raise RunnerRuntimeCorrupt("runtime state schema is invalid") from exc
        return reference

    @classmethod
    def _schema_matches(cls, conn: sqlite3.Connection, statements: tuple[str, ...]) -> bool:
        try:
            cls._assert_schema_parity(conn, statements)
        except RunnerRuntimeCorrupt:
            return False
        return True

    @classmethod
    def _assert_schema_parity(cls, conn: sqlite3.Connection, statements: tuple[str, ...]) -> None:
        reference = cls._reference_schema(statements)
        try:
            def rows(connection: sqlite3.Connection, statement: str) -> list[tuple[Any, ...]]:
                return [tuple(item) for item in connection.execute(statement).fetchall()]

            expected_rows = reference.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index') ORDER BY type,name"
            ).fetchall()
            actual_rows = conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index') ORDER BY type,name"
            ).fetchall()
            if [(row[0], row[1], row[2]) for row in actual_rows] != [
                (row[0], row[1], row[2]) for row in expected_rows
            ]:
                raise RunnerRuntimeCorrupt("runtime state schema is invalid")
            for actual, expected in zip(actual_rows, expected_rows, strict=True):
                if cls._normalized_sql(actual[3]) != cls._normalized_sql(expected[3]):
                    raise RunnerRuntimeCorrupt("runtime state schema is invalid")
            for table in tuple(row[1] for row in expected_rows if row[0] == "table"):
                for pragma in ("table_info", "table_xinfo", "index_list", "foreign_key_list"):
                    if rows(conn, f"PRAGMA {pragma}({table})") != rows(reference, f"PRAGMA {pragma}({table})"):
                        raise RunnerRuntimeCorrupt("runtime state schema is invalid")
                for index in conn.execute(f"PRAGMA index_list({table})").fetchall():
                    name = index[1]
                    if rows(conn, f"PRAGMA index_xinfo({name})") != rows(reference, f"PRAGMA index_xinfo({name})"):
                        raise RunnerRuntimeCorrupt("runtime state schema is invalid")
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1"
            ).fetchone() is not None:
                raise RunnerRuntimeCorrupt("runtime state schema is invalid")
        finally:
            reference.close()

    def _classify_schema(self, conn: sqlite3.Connection) -> str:
        objects = conn.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
            "AND type IN ('table','index','trigger','view')"
        ).fetchall()
        if not objects:
            return "none"
        if self._schema_matches(conn, _V1_SCHEMA_SQL):
            return "v1"
        if self._schema_matches(conn, _V2_SCHEMA_SQL):
            return "v2"
        if self._schema_matches(conn, _V3_SCHEMA_SQL):
            return "v3"
        raise RunnerRuntimeCorrupt("runtime state schema is invalid")

    @staticmethod
    def _execute_schema(conn: sqlite3.Connection, statements: tuple[str, ...]) -> None:
        for statement in statements:
            conn.execute(statement)

    def _identity_values(self) -> tuple[str, str, str, str]:
        return (
            self.identity.workspace_id, self.identity.runner_id, self.identity.key_id,
            self.identity.fingerprint,
        )

    @staticmethod
    def _authority_digest_for(identity: RunnerIdentity) -> str:
        return hashlib.sha256(_AUTHORITY_IDENTITY_DOMAIN + canonical_bytes({
            "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        })).hexdigest()

    def _upgrade_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
        if row is None or row["schema_version"] != _SCHEMA_V1 or tuple(
            row[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
        ) != self._identity_values():
            raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
        self._key = self._kek
        conn.execute("ALTER TABLE metadata RENAME TO metadata_v1")
        self._execute_schema(conn, (_V2_SCHEMA_SQL[0], *_V2_SCHEMA_SQL[2:]))
        conn.execute(
            "INSERT INTO metadata(singleton,schema_version,workspace_id,runner_id,runner_key_id,public_key_digest,state_key_ciphertext) "
            "VALUES(1,?,?,?,?,?,?)",
            (_SCHEMA_V2, *self._identity_values(), self._wrap_state_key(self._key)),
        )
        conn.execute("DROP TABLE metadata_v1")

    def _upgrade_v2_to_v3(self, conn: sqlite3.Connection) -> None:
        if not self._schema_matches(conn, _V2_SCHEMA_SQL):
            raise RunnerRuntimeCorrupt("runtime state schema is invalid")
        self._validate_opaque_authority_rows(conn)
        conn.execute("ALTER TABLE metadata RENAME TO metadata_v2")
        conn.execute("ALTER TABLE control_chains RENAME TO control_chains_v2")
        conn.execute("ALTER TABLE pending_calls RENAME TO pending_calls_v2")
        conn.execute("DROP INDEX idx_terminal_disclosures_state_retention")
        conn.execute("ALTER TABLE terminal_disclosures RENAME TO terminal_disclosures_v2")
        self._execute_schema(conn, _V3_SCHEMA_SQL)
        conn.execute(
            "INSERT INTO metadata(singleton,schema_version,workspace_id,runner_id,runner_key_id,public_key_digest,authority_epoch,authority_identity_digest,rotation_fence_digest,state_key_ciphertext) "
            "SELECT singleton,?,workspace_id,runner_id,runner_key_id,public_key_digest,1,?,NULL,state_key_ciphertext FROM metadata_v2",
            (_SCHEMA, self._authority_digest_for(self.identity)),
        )
        conn.execute(
            "INSERT INTO control_chains(chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms) "
            "SELECT chain,run_hash,operation,next_sequence,generation,sealed_blob,updated_at_ms FROM control_chains_v2"
        )
        conn.execute(
            "INSERT INTO pending_calls(call_id,chain,run_hash,operation,sequence,generation,sealed_blob,created_at_ms) "
            "SELECT call_id,chain,run_hash,operation,sequence,generation,sealed_blob,created_at_ms FROM pending_calls_v2"
        )
        conn.execute(
            "INSERT INTO terminal_disclosures(run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms) "
            "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms FROM terminal_disclosures_v2"
        )
        for table in ("metadata_v2", "control_chains_v2", "pending_calls_v2", "terminal_disclosures_v2"):
            conn.execute(f"DROP TABLE {table}")
        self._assert_schema_parity(conn, _V3_SCHEMA_SQL)

    def _validate_opaque_authority_rows(self, conn: sqlite3.Connection) -> None:
        """Authenticate the legacy opaque index before a byte-for-byte v3 copy."""
        for row in conn.execute(
            "SELECT chain,run_hash,operation,sealed_blob FROM control_chains"
        ).fetchall():
            cursor = self._validate_chain_core(self._open(
                row["sealed_blob"], schema="heel.runner-control-chain-state.v1",
                primary_fields=(row["chain"],),
            ))
            if (
                row["chain"] != self._chain_key(cursor.operation, cursor.run_id)
                or row["operation"] != cursor.operation
                or row["run_hash"] != (None if cursor.run_id is None else _run_hash(cursor.run_id))
            ):
                raise RunnerRuntimeCorrupt("runtime chain index is invalid")
        for row in conn.execute(
            "SELECT call_id,chain,run_hash,operation,sealed_blob FROM pending_calls"
        ).fetchall():
            pending, _core = self._validate_pending_core(self._open(
                row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(row["call_id"],),
            ))
            if (
                row["call_id"] != pending.call_id
                or row["chain"] != self._chain_key(pending.chain_operation, pending.run_id)
                or row["run_hash"] != (None if pending.run_id is None else _run_hash(pending.run_id))
                or row["operation"] != pending.request_operation
            ):
                raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
        for row in conn.execute(
            "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms FROM terminal_disclosures"
        ).fetchall():
            state = self._validate_terminal_core(self._open(
                row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1",
                primary_fields=(row["run_hash"],),
            ))
            if (
                row["run_hash"] != state.run_hash
                or row["retention_expires_at_ms"] != state.retention_expires_at_ms
                or row["state"] != state.state
                or (state.state == "local_terminal" and row["updated_at_ms"] != state.terminal_at_ms)
            ):
                raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")

    def _validate_open_runtime(self, conn: sqlite3.Connection, *, allow_rotation_fence: bool = False) -> None:
        self._assert_schema_parity(conn, _V3_SCHEMA_SQL)
        if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal" or conn.execute(
            "PRAGMA secure_delete"
        ).fetchone()[0] != 1 or conn.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise RunnerRuntimeCorrupt("runtime state schema is invalid")
        rows = conn.execute("SELECT * FROM metadata").fetchall()
        if len(rows) != 1:
            raise RunnerRuntimeCorrupt("runtime state schema is invalid")
        row = rows[0]
        if row["singleton"] != 1 or row["schema_version"] != _SCHEMA or tuple(
            row[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
        ) != self._identity_values() or row["authority_identity_digest"] != self._authority_digest_for(self.identity):
            raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
        authority_epoch = _safe_int(row["authority_epoch"], "runtime authority epoch", minimum=1)
        if self._initialized and (
            authority_epoch != self._authority_epoch
            or row["authority_identity_digest"] != self._authority_identity_digest
        ):
            self._poisoned = True
            raise RunnerRuntimeCorrupt("runtime state authority changed")
        if self._unwrap_state_key(row["state_key_ciphertext"]) != self._key:
            raise RunnerRuntimeCorrupt("runtime state key is invalid")
        self._authority_epoch = authority_epoch
        self._authority_identity_digest = row["authority_identity_digest"]
        if row["rotation_fence_digest"] is not None and not allow_rotation_fence:
            _digest(row["rotation_fence_digest"], "runtime rotation fence digest")
            raise RunnerRuntimeConflict("runtime rotation is in progress")
        limits = {"control_chains": 257, "pending_calls": 74, "active_runs": 64}
        for table, limit in limits.items():
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] > limit:
                raise RunnerRuntimeCorrupt("runtime state capacity is invalid")

    def _initialize(self, conn: sqlite3.Connection, *, allow_rotation_fence: bool = False) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            state = self._classify_schema(conn)
            if state == "none":
                self._execute_schema(conn, _V3_SCHEMA_SQL)
                state_key = self._random_source(32)
                if type(state_key) is not bytes or len(state_key) != 32:
                    raise RunnerRuntimeCorrupt("runtime state random source returned an invalid key")
                self._key = state_key
                conn.execute(
                    "INSERT INTO metadata(singleton,schema_version,workspace_id,runner_id,runner_key_id,public_key_digest,authority_epoch,authority_identity_digest,rotation_fence_digest,state_key_ciphertext) "
                    "VALUES(1,?,?,?,?,?,?,?,?,?)",
                    (
                        _SCHEMA, *self._identity_values(), 1,
                        self._authority_digest_for(self.identity), None, self._wrap_state_key(state_key),
                    ),
                )
            elif state == "v1":
                self._upgrade_v1_to_v2(conn)
                state = "v2"
            if state == "v2":
                row = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
                if row is None or row["schema_version"] != _SCHEMA_V2 or tuple(
                    row[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
                ) != self._identity_values():
                    raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
                if not self._key:
                    self._key = self._unwrap_state_key(row["state_key_ciphertext"])
                self._upgrade_v2_to_v3(conn)
            elif state == "v3":
                row = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
                if row is None or row["schema_version"] != _SCHEMA or tuple(
                    row[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
                ) != self._identity_values():
                    raise RunnerRuntimeCorrupt("runtime state belongs to another runner identity")
                self._key = self._unwrap_state_key(row["state_key_ciphertext"])
            self._validate_open_runtime(conn, allow_rotation_fence=allow_rotation_fence)
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
        plaintext = (
            _active_json_bytes(core) if schema == "heel.runner-active-run-state.v1"
            else canonical_bytes(dict(core))
        )
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
            decoded = (
                _active_json_parse(plaintext)
                if schema == "heel.runner-active-run-state.v1"
                else json.loads(plaintext)
            )
        except Exception as exc:
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid") from exc
        if not isinstance(decoded, dict):
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid")
        try:
            expected_plaintext = (
                _active_json_bytes(decoded) if schema == "heel.runner-active-run-state.v1"
                else canonical_bytes(decoded)
            )
        except (TypeError, ValueError) as exc:
            raise RunnerRuntimeCorrupt("runtime state sealed record is invalid") from exc
        if expected_plaintext != plaintext:
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

    def _current_metadata_locked(self, conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
        if row is None or row["schema_version"] != _SCHEMA or tuple(
            row[key] for key in ("workspace_id", "runner_id", "runner_key_id", "public_key_digest")
        ) != self._identity_values() or row["authority_identity_digest"] != self._authority_identity_digest or (
            row["authority_epoch"] != self._authority_epoch
        ):
            self._poisoned = True
            raise RunnerRuntimeCorrupt("runtime state authority changed")
        if self._unwrap_state_key(row["state_key_ciphertext"]) != self._key:
            self._poisoned = True
            raise RunnerRuntimeCorrupt("runtime state key is invalid")
        return row

    def _validate_transaction_authority_locked(
        self, conn: sqlite3.Connection, *, allow_rotation_fence: bool,
    ) -> None:
        """Validate the cached authority tuple inside the caller's transaction.

        This deliberately runs after SQLite has acquired the transaction snapshot
        or writer lock.  A second runtime object can otherwise rotate the
        metadata after `_connection` validates it but before a child row is read
        or written.
        """
        metadata = self._current_metadata_locked(conn)
        if metadata["rotation_fence_digest"] is not None and not allow_rotation_fence:
            _digest(metadata["rotation_fence_digest"], "runtime rotation fence digest")
            raise RunnerRuntimeConflict("runtime rotation is in progress")

    def rotation_authority_snapshot(self) -> tuple[int, str]:
        """Return the authenticated pre-fence authority tuple for rotation preparation."""
        with self._connection(allow_rotation_fence=True) as conn:
            conn.execute("BEGIN")
            try:
                self._current_metadata_locked(conn)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return self._authority_epoch, self._authority_identity_digest

    def rotation_fence_snapshot(self) -> tuple[int, str, str | None]:
        """Read the authenticated fence after a failed rotation CAS without using authority rows."""
        with self._connection(allow_rotation_fence=True) as conn:
            conn.execute("BEGIN")
            try:
                metadata = self._current_metadata_locked(conn)
                fence = metadata["rotation_fence_digest"]
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return self._authority_epoch, self._authority_identity_digest, fence

    def probe_rotation_eligible(self, *, old_identity: RunnerIdentity) -> RotationEligibilityProbe:
        if not isinstance(old_identity, RunnerIdentity) or not self._same_identity(self.identity, old_identity):
            raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
        with self._connection(allow_rotation_fence=True) as conn:
            conn.execute("BEGIN")
            try:
                metadata = self._current_metadata_locked(conn)
                if metadata["rotation_fence_digest"] is not None:
                    raise RunnerRuntimeConflict("runtime rotation is in progress")
                if conn.execute("SELECT 1 FROM pending_calls LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has pending calls")
                if conn.execute("SELECT 1 FROM active_runs LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has active runs")
                if conn.execute("SELECT 1 FROM terminal_disclosures LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has terminal disclosures")
                chain = self._chain_key("claim", None)
                rows = conn.execute("SELECT chain,run_hash,operation FROM control_chains").fetchall()
                if len(rows) != 1 or tuple(rows[0]) != (chain, None, "claim"):
                    raise RunnerRuntimeConflict("runtime rotation has active runs")
                claim = self._load_chain_locked(conn, "claim", None)
                if claim is None:
                    raise RunnerRuntimeConflict("runtime rotation has active runs")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return RotationEligibilityProbe(
            authority_epoch=self._authority_epoch,
            authority_identity_digest=self._authority_identity_digest,
            claim_state_digest=claim.state_digest,
        )

    def assert_rotation_eligible(
        self, *, old_identity: RunnerIdentity, probe: RotationEligibilityProbe,
        prepared_journal_digest: str, runtime_rotation_intent_digest: str, now_ms: int,
    ) -> RotationEligibility:
        if not isinstance(old_identity, RunnerIdentity) or not self._same_identity(self.identity, old_identity):
            raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
        if not isinstance(probe, RotationEligibilityProbe):
            raise RunnerRuntimeCorrupt("runtime rotation eligibility is invalid")
        prepared_journal_digest = _digest(prepared_journal_digest, "runtime rotation journal digest")
        runtime_rotation_intent_digest = _digest(
            runtime_rotation_intent_digest, "runtime rotation intent digest",
        )
        _safe_int(now_ms, "runtime rotation preparation time")
        with self._connection(allow_rotation_fence=True) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                metadata = self._current_metadata_locked(conn)
                if (
                    probe.authority_epoch != self._authority_epoch
                    or probe.authority_identity_digest != self._authority_identity_digest
                ):
                    raise RunnerRuntimeConflict("runtime rotation is unavailable")
                if metadata["rotation_fence_digest"] not in {None, runtime_rotation_intent_digest}:
                    raise RunnerRuntimeConflict("runtime rotation is in progress")
                if conn.execute("SELECT 1 FROM pending_calls LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has pending calls")
                if conn.execute("SELECT 1 FROM active_runs LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has active runs")
                if conn.execute("SELECT 1 FROM terminal_disclosures LIMIT 1").fetchone() is not None:
                    raise RunnerRuntimeConflict("runtime rotation has terminal disclosures")
                chain = self._chain_key("claim", None)
                rows = conn.execute("SELECT chain,run_hash,operation FROM control_chains").fetchall()
                if len(rows) != 1 or tuple(rows[0]) != (chain, None, "claim"):
                    raise RunnerRuntimeConflict("runtime rotation has active runs")
                claim = self._load_chain_locked(conn, "claim", None)
                if claim is None or claim.state_digest != probe.claim_state_digest:
                    raise RunnerRuntimeConflict("runtime rotation is unavailable")
                if metadata["rotation_fence_digest"] is None:
                    updated = conn.execute(
                        "UPDATE metadata SET rotation_fence_digest=? WHERE singleton=1 "
                        "AND authority_epoch=? AND authority_identity_digest=? AND rotation_fence_digest IS NULL",
                        (runtime_rotation_intent_digest, self._authority_epoch, self._authority_identity_digest),
                    )
                    if updated.rowcount != 1:
                        raise RunnerRuntimeConflict("runtime rotation is unavailable")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return RotationEligibility(
            authority_epoch=self._authority_epoch,
            authority_identity_digest=self._authority_identity_digest,
            claim_state_digest=probe.claim_state_digest,
            runtime_rotation_intent_digest=runtime_rotation_intent_digest,
            prepared_journal_digest=prepared_journal_digest,
        )

    def finish_rotation(
        self, journal: AcceptedRotationJournal, *, new_identity: RunnerIdentity,
        new_signer: SecureSigner, eligibility: RotationEligibility,
    ) -> RunnerChainCursor:
        """Atomically rewrap the stable runtime key and install the accepted claim cursor.

        The caller supplies the live replacement signer explicitly.  Nothing serialized in
        the rotation journal can synthesize or replace that capability during recovery.
        """
        if not isinstance(journal, AcceptedRotationJournal) or not isinstance(eligibility, RotationEligibility):
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
        if (
            eligibility.prepared_journal_digest != _digest(
                journal.prepared_journal_digest, "runtime rotation journal digest",
            )
            or eligibility.runtime_rotation_intent_digest != _digest(
                journal.runtime_rotation_intent_digest, "runtime rotation intent digest",
            )
        ):
            raise RunnerRuntimeCorrupt("runtime rotation eligibility is invalid")
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
                if (
                    eligibility.authority_epoch + 1 != self._authority_epoch
                    or eligibility.authority_identity_digest != self._authority_digest_for(journal.old_identity)
                ):
                    raise RunnerRuntimeCorrupt("runtime rotation identity is invalid")
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
                with self._connection(allow_rotation_fence=True) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        metadata = self._current_metadata_locked(conn)
                        if (
                            eligibility.authority_epoch != self._authority_epoch
                            or eligibility.authority_identity_digest != self._authority_identity_digest
                            or metadata["rotation_fence_digest"] != eligibility.runtime_rotation_intent_digest
                        ):
                            raise RunnerRuntimeCorrupt("runtime rotation eligibility is invalid")
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
                        if conn.execute("SELECT 1 FROM active_runs LIMIT 1").fetchone() is not None:
                            raise RunnerRuntimeConflict("runtime rotation has active runs")
                        updated = conn.execute(
                            "UPDATE control_chains SET next_sequence=?,generation=?,sealed_blob=?,updated_at_ms=? WHERE chain=?",
                            (expected.next_sequence, expected.generation, next_blob, expected.updated_at_ms, chain),
                        )
                        if updated.rowcount != 1:
                            raise RunnerRuntimeConflict("runtime rotation cursor is unavailable")
                        new_authority_digest = self._authority_digest_for(new_identity)
                        metadata_updated = conn.execute(
                            "UPDATE metadata SET workspace_id=?,runner_id=?,runner_key_id=?,public_key_digest=?,"
                            "authority_epoch=?,authority_identity_digest=?,rotation_fence_digest=NULL,state_key_ciphertext=? "
                            "WHERE singleton=1 AND authority_epoch=? AND authority_identity_digest=? AND rotation_fence_digest=?",
                            (
                                new_identity.workspace_id, new_identity.runner_id, new_identity.key_id,
                                new_identity.fingerprint, self._authority_epoch + 1, new_authority_digest,
                                wrapped_key, self._authority_epoch, self._authority_identity_digest,
                                eligibility.runtime_rotation_intent_digest,
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
                self._authority_epoch += 1
                self._authority_identity_digest = self._authority_digest_for(new_identity)
                return expected
            except BaseException:
                # If a future fault is injected after the durable metadata switch but before
                # these in-memory assignments, the old object must never sign again.
                if self._same_identity(self.identity, old_identity) and self._kek == old_kek:
                    raise
                self._poisoned = True
                raise

    def abort_rotation(
        self, *, eligibility: RotationEligibility,
        abort_tombstone: AcceptedRotationAbortTombstone,
    ) -> None:
        """Clear only the exact durable prepare fence after a Cloud-signed abort."""
        if not isinstance(eligibility, RotationEligibility) or not isinstance(
            abort_tombstone, AcceptedRotationAbortTombstone,
        ):
            raise RunnerRuntimeCorrupt("runtime rotation abort is invalid")
        if (
            not self._same_identity(self.identity, abort_tombstone.old_identity)
            or abort_tombstone.old_identity.workspace_id != abort_tombstone.new_identity.workspace_id
            or abort_tombstone.old_identity.runner_id != abort_tombstone.new_identity.runner_id
            or abort_tombstone.old_identity.key_id == abort_tombstone.new_identity.key_id
            or eligibility.prepared_journal_digest != _digest(
                abort_tombstone.prepared_journal_digest, "runtime rotation journal digest",
            )
            or eligibility.runtime_rotation_intent_digest != _digest(
                abort_tombstone.runtime_rotation_intent_digest, "runtime rotation intent digest",
            )
        ):
            raise RunnerRuntimeCorrupt("runtime rotation abort is invalid")
        record = abort_tombstone.record
        required = {
            "schema_version", "workspace_id", "runner_id", "pairing_id", "old_runner_key_id",
            "new_runner_key_id", "prepared_journal_digest", "runtime_rotation_intent_digest",
            "runtime_authority_epoch", "runtime_authority_identity_digest",
        }
        if not isinstance(record, Mapping) or not required <= set(record) or (
            record.get("schema_version") != "heel.runner-rotation-activation-abort-tombstone.v1"
            or record.get("pairing_id") != abort_tombstone.pairing_id
            or record.get("workspace_id") != self.identity.workspace_id
            or record.get("runner_id") != self.identity.runner_id
            or record.get("old_runner_key_id") != self.identity.key_id
            or record.get("new_runner_key_id") != abort_tombstone.new_identity.key_id
            or record.get("prepared_journal_digest") != eligibility.prepared_journal_digest
            or record.get("runtime_rotation_intent_digest") != eligibility.runtime_rotation_intent_digest
            or record.get("runtime_authority_epoch") != eligibility.authority_epoch
            or record.get("runtime_authority_identity_digest") != eligibility.authority_identity_digest
        ):
            raise RunnerRuntimeCorrupt("runtime rotation abort is invalid")
        with self._state_lock:
            with self._connection(allow_rotation_fence=True) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    metadata = self._current_metadata_locked(conn)
                    if (
                        self._authority_epoch != eligibility.authority_epoch
                        or self._authority_identity_digest != eligibility.authority_identity_digest
                        or metadata["rotation_fence_digest"] != eligibility.runtime_rotation_intent_digest
                        or conn.execute("SELECT 1 FROM pending_calls LIMIT 1").fetchone() is not None
                        or conn.execute("SELECT 1 FROM active_runs LIMIT 1").fetchone() is not None
                        or conn.execute("SELECT 1 FROM terminal_disclosures LIMIT 1").fetchone() is not None
                    ):
                        raise RunnerRuntimeConflict("runtime rotation abort is unavailable")
                    chain = self._chain_key("claim", None)
                    rows = conn.execute("SELECT chain,run_hash,operation FROM control_chains").fetchall()
                    claim = self._load_chain_locked(conn, "claim", None)
                    if (
                        len(rows) != 1 or tuple(rows[0]) != (chain, None, "claim")
                        or claim is None or claim.state_digest != eligibility.claim_state_digest
                    ):
                        raise RunnerRuntimeConflict("runtime rotation abort is unavailable")
                    cleared = conn.execute(
                        "UPDATE metadata SET rotation_fence_digest=NULL WHERE singleton=1 "
                        "AND authority_epoch=? AND authority_identity_digest=? AND rotation_fence_digest=?",
                        (
                            eligibility.authority_epoch, eligibility.authority_identity_digest,
                            eligibility.runtime_rotation_intent_digest,
                        ),
                    )
                    if cleared.rowcount != 1:
                        raise RunnerRuntimeConflict("runtime rotation abort is unavailable")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
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
            state_digest=_digest(value["state_digest"], "runtime pending state digest"),
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

    def _pending_from_row_locked(self, row: sqlite3.Row) -> PendingSignedCall:
        item, _core = self._validate_pending_core(self._open(
            row["sealed_blob"], schema="heel.runner-pending-call.v1", primary_fields=(row["call_id"],),
        ))
        if (
            row["call_id"] != item.call_id
            or row["chain"] != self._chain_key(item.chain_operation, item.run_id)
            or row["run_hash"] != (None if item.run_id is None else _run_hash(item.run_id))
            or row["operation"] != item.request_operation
            or row["sequence"] != item.sequence
            or row["generation"] != item.generation
            or row["created_at_ms"] != item.created_at_ms
        ):
            raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
        return item

    def get_pending_call(self, call_id: str) -> PendingSignedCall:
        """Load one fully authenticated immutable request, or fail rather than treating loss as success."""
        call_id = _digest(call_id, "runtime pending call ID")
        with self._connection() as conn:
            row = conn.execute(
                "SELECT call_id,chain,run_hash,operation,sequence,generation,created_at_ms,sealed_blob "
                "FROM pending_calls WHERE call_id=?", (call_id,),
            ).fetchone()
        if row is None:
            raise RunnerRuntimeConflict("runtime pending call is unavailable")
        return self._pending_from_row_locked(row)

    def load_pending_calls(self, *, limit: int = 74) -> tuple[PendingSignedCall, ...]:
        if type(limit) is not int or not 1 <= limit <= 74:
            raise RunnerRuntimeStateError("invalid runtime pending call limit")
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT call_id,chain,run_hash,operation,sequence,generation,created_at_ms,sealed_blob FROM pending_calls "
                "ORDER BY created_at_ms,call_id LIMIT ?", (limit,),
            ).fetchall()
        pending: list[PendingSignedCall] = []
        for row in rows:
            pending.append(self._pending_from_row_locked(row))
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
        active_run: ActiveRunInstall | None = None,
        gate_update: ActiveGateUpdate | None = None,
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
        if active_run is not None and not isinstance(active_run, ActiveRunInstall):
            raise RunnerRuntimeStateError("invalid runtime active run install")
        if gate_update is not None and not isinstance(gate_update, ActiveGateUpdate):
            raise RunnerRuntimeStateError("invalid runtime active gate update")
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
                if active_run is not None and not (
                    pending.request_operation == "claim" and pending.chain_operation == "claim"
                    and pending.run_id is None and parsed_installed
                    and {item[1] for item in parsed_installed} == {active_run.run_id}
                ):
                    raise RunnerRuntimeCorrupt("runtime active run install does not match pending claim")
                if gate_update is not None and not (
                    pending.request_operation == "heartbeat" and pending.run_id is not None
                ):
                    raise RunnerRuntimeCorrupt("runtime active gate update does not match pending heartbeat")
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
                if active_run is not None:
                    active_core = self._active_core(
                        run_id=active_run.run_id, approval_projection=active_run.approval_projection,
                        grant=active_run.grant, gate=active_run.gate,
                        claim_response_digest=active_run.claim_response_digest,
                        latest_gate_response_digest=active_run.gate_response_digest,
                        claimed_at_ms=active_run.claimed_at_ms,
                        gate_received_at_ms=active_run.gate_received_at_ms,
                        revision=1, prior_state_digest=None,
                    )
                    active_hash = active_core["run_hash"]
                    if conn.execute("SELECT 1 FROM active_runs WHERE run_hash=?", (active_hash,)).fetchone() is not None:
                        raise RunnerRuntimeConflict("runtime active run already exists")
                    if conn.execute("SELECT COUNT(*) FROM active_runs").fetchone()[0] >= 64:
                        raise RunnerRuntimeConflict("runtime active run capacity is exhausted")
                    active_blob = self._seal(
                        active_core, schema="heel.runner-active-run-state.v1", primary_fields=(active_hash,),
                    )
                    conn.execute(
                        "INSERT INTO active_runs(run_hash,sealed_blob,updated_at_ms) VALUES(?,?,?)",
                        (active_hash, active_blob, active_core["gate_received_at_ms"]),
                    )
                if gate_update is not None:
                    assert pending.run_id is not None
                    prior_active = self._load_active_locked(conn, pending.run_id)
                    if prior_active is None:
                        raise RunnerRuntimeCorrupt("runtime active run is unavailable")
                    if gate_update.gate["server_time_ms"] <= prior_active["gate"]["server_time_ms"]:
                        raise RunnerRuntimeCorrupt("runtime active gate server time did not advance")
                    if (
                        gate_update.gate["kill_switch_generation"]
                        < prior_active["gate"]["kill_switch_generation"]
                    ):
                        raise RunnerRuntimeCorrupt("runtime active gate control generation regressed")
                    next_active = self._active_core(
                        run_id=pending.run_id, approval_projection=prior_active["approval_projection"],
                        grant=prior_active["grant"], gate=gate_update.gate,
                        claim_response_digest=prior_active["claim_response_digest"],
                        latest_gate_response_digest=gate_update.gate_response_digest,
                        claimed_at_ms=prior_active["claimed_at_ms"],
                        gate_received_at_ms=gate_update.received_at_ms,
                        revision=prior_active["revision"] + 1,
                        prior_state_digest=prior_active["state_digest"],
                    )
                    active_blob = self._seal(
                        next_active, schema="heel.runner-active-run-state.v1",
                        primary_fields=(next_active["run_hash"],),
                    )
                    updated_active = conn.execute(
                        "UPDATE active_runs SET sealed_blob=?,updated_at_ms=? WHERE run_hash=?",
                        (active_blob, next_active["gate_received_at_ms"], next_active["run_hash"]),
                    )
                    if updated_active.rowcount != 1:
                        raise RunnerRuntimeConflict("runtime active run is unavailable")
                conn.execute("DELETE FROM pending_calls WHERE call_id=?", (call_id,))
                conn.execute("COMMIT")
                return next_cursor
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _validate_active_gate(value: object) -> dict[str, Any]:
        fields = {
            "active", "runner_state", "proof_state", "proof_expires_at_ms",
            "kill_switch_generation", "stop_reason", "server_time_ms",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerRuntimeCorrupt("runtime active gate is invalid")
        gate = dict(value)
        if (
            type(gate["active"]) is not bool
            or gate["runner_state"] not in {"active", "revoked", "replaced"}
            or gate["proof_state"] not in {"valid", "expired", "revoked"}
            or gate["stop_reason"] not in {
                "none", "local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch",
            }
            or any(type(gate[name]) is not int or gate[name] < 0 for name in (
                "proof_expires_at_ms", "kill_switch_generation", "server_time_ms",
            ))
        ):
            raise RunnerRuntimeCorrupt("runtime active gate is invalid")
        return gate

    def _active_core(
        self, *, run_id: str, approval_projection: Mapping[str, Any], grant: Mapping[str, Any],
        gate: Mapping[str, Any], claim_response_digest: str, latest_gate_response_digest: str,
        claimed_at_ms: int, gate_received_at_ms: int, revision: int,
        prior_state_digest: str | None,
    ) -> dict[str, Any]:
        checked_projection = validate_approval_projection(approval_projection)
        checked_grant = validate_execution_grant(grant)
        checked_gate = self._validate_active_gate(gate)
        run_id = _run_id(run_id)
        assert run_id is not None
        if (
            checked_grant["run_id"] != run_id
            or checked_projection["workspace_id"] != self.identity.workspace_id
            or checked_grant["workspace_id"] != self.identity.workspace_id
            or checked_projection["project_id"] != checked_grant["project_id"]
            or checked_projection["runner"]["runner_id"] != self.identity.runner_id
            or checked_projection["runner"]["runner_key_id"] != self.identity.key_id
            or checked_grant["runner_binding"]["runner_id"] != self.identity.runner_id
            or checked_grant["runner_binding"]["runner_key_id"] != self.identity.key_id
            or checked_grant["approval"] != {
                "projection_id": checked_projection["projection_id"],
                "projection_digest": checked_projection["projection_digest"],
                "manifest_digest": checked_projection["manifest_digest"],
            }
        ):
            raise RunnerRuntimeCorrupt("runtime active run authority is invalid")
        grant_generation = checked_grant["kill_switch_generation"]
        gate_generation = checked_gate["kill_switch_generation"]
        if (
            gate_generation < grant_generation
            or (
                gate_generation > grant_generation
                and (
                    checked_gate["active"] is not False
                    or checked_gate["stop_reason"] == "none"
                )
            )
        ):
            raise RunnerRuntimeCorrupt("runtime active gate is inconsistent")
        claim_response_digest = _digest(claim_response_digest, "runtime claim response digest")
        latest_gate_response_digest = _digest(latest_gate_response_digest, "runtime gate response digest")
        claimed_at_ms = _safe_int(claimed_at_ms, "runtime claimed time")
        gate_received_at_ms = _safe_int(gate_received_at_ms, "runtime gate time")
        revision = _safe_int(revision, "runtime active revision", minimum=1)
        if prior_state_digest is not None:
            _digest(prior_state_digest, "runtime active prior state digest")
        core_without_digest = {
            "schema_version": "heel.runner-active-run-state.v1", "state": "active",
            "workspace_id": self.identity.workspace_id, "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id, "run_id": run_id, "run_hash": _run_hash(run_id),
            "project_id": checked_grant["project_id"], "approval_id": checked_projection["projection_id"],
            "grant_id": checked_grant["grant_id"], "grant_digest": checked_grant["grant_digest"],
            "approval_projection_digest": checked_projection["projection_digest"],
            "approval_projection": checked_projection, "grant": checked_grant, "gate": checked_gate,
            "claim_response_digest": claim_response_digest,
            "latest_gate_response_digest": latest_gate_response_digest,
            "claimed_at_ms": claimed_at_ms, "gate_received_at_ms": gate_received_at_ms,
            "revision": revision, "prior_state_digest": prior_state_digest,
        }
        return {**core_without_digest, "state_digest": _active_state_digest(core_without_digest)}

    def _validate_active_core(self, value: Mapping[str, Any]) -> dict[str, Any]:
        fields = {
            "schema_version", "state", "workspace_id", "runner_id", "runner_key_id", "run_id", "run_hash",
            "project_id", "approval_id", "grant_id", "grant_digest", "approval_projection_digest",
            "approval_projection", "grant", "gate", "claim_response_digest", "latest_gate_response_digest",
            "claimed_at_ms", "gate_received_at_ms", "revision", "prior_state_digest", "state_digest",
        }
        if (
            set(value) != fields or value.get("schema_version") != "heel.runner-active-run-state.v1"
            or value.get("state") != "active"
            or value.get("workspace_id") != self.identity.workspace_id
            or value.get("runner_id") != self.identity.runner_id
            or value.get("runner_key_id") != self.identity.key_id
        ):
            raise RunnerRuntimeCorrupt("runtime active run state is invalid")
        run_id = _run_id(value.get("run_id"))
        assert run_id is not None
        if value.get("run_hash") != _run_hash(run_id):
            raise RunnerRuntimeCorrupt("runtime active run state is invalid")
        core = self._active_core(
            run_id=run_id, approval_projection=value["approval_projection"], grant=value["grant"],
            gate=value["gate"], claim_response_digest=value["claim_response_digest"],
            latest_gate_response_digest=value["latest_gate_response_digest"],
            claimed_at_ms=value["claimed_at_ms"], gate_received_at_ms=value["gate_received_at_ms"],
            revision=value["revision"], prior_state_digest=value["prior_state_digest"],
        )
        if value != core:
            raise RunnerRuntimeCorrupt("runtime active run state is invalid")
        return core

    def _load_active_locked(self, conn: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
        run_hash = _run_hash(run_id)
        row = conn.execute(
            "SELECT run_hash,sealed_blob,updated_at_ms FROM active_runs WHERE run_hash=?", (run_hash,),
        ).fetchone()
        if row is None:
            return None
        core = self._validate_active_core(self._open(
            row["sealed_blob"], schema="heel.runner-active-run-state.v1", primary_fields=(run_hash,),
        ))
        if core["run_hash"] != row["run_hash"] or core["run_id"] != run_id or row["updated_at_ms"] != core["gate_received_at_ms"]:
            raise RunnerRuntimeCorrupt("runtime active run index is invalid")
        return core

    def load_active_run_controls(self, *, limit: int = 64) -> tuple[ActiveRunControl, ...]:
        if type(limit) is not int or not 1 <= limit <= 64:
            raise RunnerRuntimeStateError("invalid runtime active run limit")
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT run_hash,sealed_blob,updated_at_ms FROM active_runs ORDER BY run_hash LIMIT 65",
            ).fetchall()
            if len(rows) > 64:
                raise RunnerRuntimeCorrupt("runtime active run capacity is invalid")
            active_by_hash: dict[str, dict[str, Any]] = {}
            for row in rows:
                core = self._validate_active_core(self._open(
                    row["sealed_blob"], schema="heel.runner-active-run-state.v1", primary_fields=(row["run_hash"],),
                ))
                if core["run_hash"] != row["run_hash"] or row["updated_at_ms"] != core["gate_received_at_ms"]:
                    raise RunnerRuntimeCorrupt("runtime active run index is invalid")
                if core["run_hash"] in active_by_hash:
                    raise RunnerRuntimeCorrupt("runtime active run index is invalid")
                active_by_hash[core["run_hash"]] = core

            # Validate the whole run-scoped cursor relation, not only the cursors
            # reached from active rows.  A surviving cursor-only group (or an
            # extra opaque index key) is authority loss, never an empty restart.
            chains_by_hash: dict[str, dict[str, RunnerChainCursor]] = {
                run_hash: {} for run_hash in active_by_hash
            }
            cursor_rows = conn.execute(
                "SELECT chain,run_hash,operation FROM control_chains WHERE run_hash IS NOT NULL",
            ).fetchall()
            for cursor_row in cursor_rows:
                run_hash = cursor_row["run_hash"]
                operation = cursor_row["operation"]
                core = active_by_hash.get(run_hash)
                if core is None or operation not in {"heartbeat", "progress", "result", "stop-ack"}:
                    raise RunnerRuntimeCorrupt("runtime active run cursor group is invalid")
                if cursor_row["chain"] != self._chain_key(operation, core["run_id"]):
                    raise RunnerRuntimeCorrupt("runtime active run cursor group is invalid")
                group = chains_by_hash[run_hash]
                if operation in group:
                    raise RunnerRuntimeCorrupt("runtime active run cursor group is invalid")
                cursor = self._load_chain_locked(conn, operation, core["run_id"])
                if cursor is None:
                    raise RunnerRuntimeCorrupt("runtime active run cursor group is invalid")
                group[operation] = cursor

            values: list[ActiveRunControl] = []
            for core in active_by_hash.values():
                chains = chains_by_hash[core["run_hash"]]
                if set(chains) != {"heartbeat", "progress", "result", "stop-ack"}:
                    raise RunnerRuntimeCorrupt("runtime active run cursor group is invalid")
                terminal = self._load_terminal_locked(conn, core["run_id"])
                if terminal is not None and terminal.state != "local_terminal":
                    # A result commit removes the whole active group in the
                    # same transaction that makes disclosure available.  Any
                    # later terminal state beside live cursors is rollback or
                    # cross-row tampering, not restartable authority.
                    raise RunnerRuntimeCorrupt("runtime active run terminal state is invalid")
                values.append(ActiveRunControl(
                    run_id=core["run_id"], project_id=core["project_id"], approval_id=core["approval_id"],
                    grant_id=core["grant_id"], grant_digest=core["grant_digest"],
                    approval_projection_digest=core["approval_projection_digest"],
                    approval_projection=MappingProxyType(dict(core["approval_projection"])),
                    grant=MappingProxyType(dict(core["grant"])), gate=MappingProxyType(dict(core["gate"])),
                    claim_response_digest=core["claim_response_digest"],
                    latest_gate_response_digest=core["latest_gate_response_digest"],
                    claimed_at_ms=core["claimed_at_ms"], gate_received_at_ms=core["gate_received_at_ms"],
                    revision=core["revision"], prior_state_digest=core["prior_state_digest"],
                    state_digest=core["state_digest"], chains=MappingProxyType(chains),
                ))
            if len(values) > limit:
                return tuple(sorted(values, key=lambda item: (item.run_id, _run_hash(item.run_id)))[:limit])
            return tuple(sorted(values, key=lambda item: (item.run_id, _run_hash(item.run_id))))

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

    def _load_terminal_row_locked(
        self, row: sqlite3.Row,
    ) -> TerminalDisclosureState:
        run_hash = row["run_hash"]
        state = self._validate_terminal_core(self._open(
            row["sealed_blob"], schema="heel.runner-terminal-disclosure-state.v1",
            primary_fields=(run_hash,),
        ))
        if (
            state.run_hash != run_hash or row["state"] != state.state
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

    def load_unstaged_local_terminals(
        self, *, limit: int = 16,
    ) -> TerminalDisclosureBatch:
        """Return bounded, zero-pending terminal result work without mutating it."""
        if type(limit) is not int or not 1 <= limit <= 16:
            raise RunnerRuntimeStateError("invalid runtime terminal recovery limit")
        with self._connection() as conn:
            conn.execute("BEGIN")
            try:
                rows = conn.execute(
                    "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms "
                    "FROM terminal_disclosures INDEXED BY idx_terminal_disclosures_state_retention "
                    "WHERE state='local_terminal' AND NOT EXISTS ("
                    "SELECT 1 FROM pending_calls INDEXED BY idx_pending_calls_run_operation "
                    "WHERE pending_calls.run_hash=terminal_disclosures.run_hash"
                    ") ORDER BY retention_expires_at_ms,run_hash LIMIT ?",
                    (limit + 1,),
                ).fetchall()
                states = tuple(self._load_terminal_row_locked(row) for row in rows[:limit])
                if any(state.state != "local_terminal" for state in states):
                    raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return TerminalDisclosureBatch(items=states, has_more=len(rows) > limit)

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
                removed_active = conn.execute(
                    "DELETE FROM active_runs WHERE run_hash=?", (run_hash,),
                )
                if removed_active.rowcount != 1:
                    raise RunnerRuntimeCorrupt("runtime terminal result has no active run authority")
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

    @staticmethod
    def _prune_limit(limit: object) -> int:
        if type(limit) is not int or not 1 <= limit <= 16:
            raise RunnerRuntimeStateError("invalid runtime prune limit")
        return limit

    def load_prune_pending(self, *, limit: int = 16) -> PrunePendingBatch:
        """Read the bounded, authenticated set of durable prune work without changing it."""
        limit = self._prune_limit(limit)
        with self._connection() as conn:
            conn.execute("BEGIN")
            try:
                rows = conn.execute(
                    "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms "
                    "FROM terminal_disclosures WHERE state='prune_pending' "
                    "ORDER BY retention_expires_at_ms,run_hash LIMIT ?",
                    (limit + 1,),
                ).fetchall()
                states = tuple(self._load_terminal_row_locked(row) for row in rows[:limit])
                if any(state.state != "prune_pending" for state in states):
                    raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return PrunePendingBatch(items=states, has_more=len(rows) > limit)

    def claim_due_prune(
        self, *, now_ms: int, limit: int = 16,
    ) -> PrunePendingBatch:
        return self._claim_due_prune(now_ms=now_ms, limit=limit)

    def claim_specific_due_prune(
        self, run_id: str, *, expected_state_digest: str, now_ms: int,
    ) -> TerminalDisclosureState:
        """Atomically claim one known expired disclosure without scanning history."""
        run_id = _run_id(run_id) or ""
        expected_state_digest = _digest(
            expected_state_digest, "runtime prune state digest",
        )
        claimed = self._claim_due_prune(
            now_ms=now_ms, limit=1, only_run_hash=_run_hash(run_id),
            expected_state_digest=expected_state_digest,
        )
        if not claimed.items:
            raise RunnerRuntimeConflict("runtime terminal prune state changed")
        return claimed.items[0]

    def _claim_due_prune(
        self, *, now_ms: int, limit: int,
        only_run_hash: str | None = None,
        expected_state_digest: str | None = None,
    ) -> PrunePendingBatch:
        now_ms = _safe_int(now_ms, "runtime prune time")
        limit = self._prune_limit(limit)
        if only_run_hash is not None:
            only_run_hash = _digest(only_run_hash, "runtime run hash")
        if expected_state_digest is not None:
            expected_state_digest = _digest(
                expected_state_digest, "runtime prune state digest",
            )
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if only_run_hash is None:
                    rows = conn.execute(
                        "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms FROM terminal_disclosures "
                        "INDEXED BY idx_terminal_disclosures_due_retention "
                        "WHERE state IN ('local_terminal','available','consumed') "
                        "AND retention_expires_at_ms<=? ORDER BY retention_expires_at_ms,run_hash LIMIT ?",
                        (now_ms, limit + 1),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT run_hash,retention_expires_at_ms,state,sealed_blob,updated_at_ms FROM terminal_disclosures "
                        "WHERE run_hash=? AND state IN ('local_terminal','available','consumed') "
                        "AND retention_expires_at_ms<=? LIMIT ?",
                        (only_run_hash, now_ms, limit + 1),
                    ).fetchall()
                claimed: list[TerminalDisclosureState] = []
                for row in rows[:limit]:
                    state = self._load_terminal_row_locked(row)
                    if state.run_hash != row["run_hash"] or state.state == "prune_pending":
                        raise RunnerRuntimeCorrupt("runtime terminal disclosure index is invalid")
                    if expected_state_digest is not None and state.state_digest != expected_state_digest:
                        raise RunnerRuntimeConflict("runtime terminal prune state changed")
                    chain_rows = conn.execute(
                        "SELECT chain,run_hash,operation,next_sequence,generation,sealed_blob "
                        "FROM control_chains WHERE run_hash=?", (state.run_hash,),
                    ).fetchall()
                    chains: dict[str, RunnerChainCursor] = {}
                    for chain_row in chain_rows:
                        cursor = self._validate_chain_core(self._open(
                            chain_row["sealed_blob"],
                            schema="heel.runner-control-chain-state.v1",
                            primary_fields=(chain_row["chain"],),
                        ))
                        if (
                            chain_row["chain"] != self._chain_key(cursor.operation, cursor.run_id)
                            or chain_row["run_hash"] != state.run_hash
                            or chain_row["operation"] != cursor.operation
                            or cursor.run_id != state.run_id
                            or chain_row["next_sequence"] != cursor.next_sequence
                            or chain_row["generation"] != cursor.generation
                            or cursor.operation in chains
                        ):
                            raise RunnerRuntimeCorrupt("runtime run control state is invalid")
                        chains[cursor.operation] = cursor
                    pending_rows = conn.execute(
                        "SELECT call_id,chain,run_hash,operation,sealed_blob FROM pending_calls WHERE run_hash=?",
                        (state.run_hash,),
                    ).fetchall()
                    pending_calls: list[PendingSignedCall] = []
                    for pending_row in pending_rows:
                        call, _pending_core = self._validate_pending_core(self._open(
                            pending_row["sealed_blob"], schema="heel.runner-pending-call.v1",
                            primary_fields=(pending_row["call_id"],),
                        ))
                        if (
                            pending_row["call_id"] != call.call_id
                            or pending_row["chain"] != self._chain_key(
                                call.chain_operation, call.run_id,
                            )
                            or pending_row["run_hash"] != state.run_hash
                            or pending_row["operation"] != call.request_operation
                            or call.run_id != state.run_id
                        ):
                            raise RunnerRuntimeCorrupt("runtime pending call index is invalid")
                        pending_calls.append(call)
                    if state.state == "local_terminal":
                        if len(chains) not in {0, 4} or (
                            chains and set(chains) != {"heartbeat", "progress", "result", "stop-ack"}
                        ) or len(pending_calls) > 1:
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact run")
                        active = self._load_active_locked(conn, state.run_id)
                        if active is None or not chains or any((
                            active["project_id"] != state.project_id,
                            active["grant_id"] != state.grant_id,
                            active["approval_projection_digest"] != state.approval_projection_digest,
                        )):
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact run")
                        if pending_calls:
                            call = pending_calls[0]
                            result = chains.get("result")
                            if (
                                result is None or call.request_operation != "result"
                                or call.chain_operation != "result"
                                or call.prior_chain_state_digest != result.state_digest
                                or call.sequence != result.next_sequence
                                or call.generation != result.generation
                                or call.headers["X-Heel-Runner-Nonce"] != result.next_nonce_b64
                            ):
                                raise RunnerRuntimeCorrupt("runtime terminal prune does not own the result")
                    elif state.state == "available":
                        if chains or len(pending_calls) > 1:
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact disclosure")
                        if pending_calls:
                            call = pending_calls[0]
                            result = state.result_chain
                            if (
                                result is None or call.request_operation != "upload-findings"
                                or call.chain_operation != "result"
                                or call.prior_chain_state_digest != state.state_digest
                                or call.sequence != result["next_sequence"]
                                or call.generation != result["generation"]
                                or call.headers["X-Heel-Runner-Nonce"] != result["next_nonce_b64"]
                            ):
                                raise RunnerRuntimeCorrupt("runtime terminal prune does not own the disclosure")
                    elif state.state == "consumed" and (chains or pending_calls):
                        raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact disclosure")
                    core = self._prune_pending_core(state)
                    pending = self._validate_terminal_core(core)
                    blob = self._seal(core, schema=core["schema_version"], primary_fields=(state.run_hash,))
                    conn.execute(
                        "UPDATE terminal_disclosures SET state=?,sealed_blob=?,updated_at_ms=? "
                        "WHERE run_hash=? AND state=?",
                        (pending.state, blob, now_ms, state.run_hash, state.state),
                    )
                    if state.state == "local_terminal":
                        removed_active = conn.execute(
                            "DELETE FROM active_runs WHERE run_hash=?", (state.run_hash,),
                        )
                        if removed_active.rowcount != 1:
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact run")
                        removed_chains = conn.execute(
                            "DELETE FROM control_chains WHERE run_hash=?", (state.run_hash,),
                        )
                        if removed_chains.rowcount != 4:
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact run")
                    if pending_calls:
                        removed_pending = conn.execute(
                            "DELETE FROM pending_calls WHERE run_hash=?", (state.run_hash,),
                        )
                        if removed_pending.rowcount != len(pending_calls):
                            raise RunnerRuntimeCorrupt("runtime terminal prune does not own an exact run")
                    claimed.append(pending)
                conn.execute("COMMIT")
                return PrunePendingBatch(items=tuple(claimed), has_more=len(rows) > limit)
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _validated_pruned_receipt(self, receipt: object) -> dict[str, object]:
        from heel.runner.store import VerifiedPrunedRunReceipt

        if type(receipt) is not VerifiedPrunedRunReceipt or not isinstance(receipt.record, Mapping):
            raise RunnerRuntimeCorrupt("runtime prune receipt is invalid")
        record = receipt.record
        fields = {
            "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
            "run_id", "run_hash", "grant_id", "grant_digest", "retention_expires_at_ms",
            "prior_head_digest", "terminal_record_digest", "terminal_projection_digest",
            "terminal_at_ms", "detached_record_digest", "runtime_state_schema",
            "runtime_prune_pending_state_digest", "pruned_at_ms", "record_digest",
            "signing_key_id", "signature_b64",
        }
        if (
            set(record) != fields
            or record.get("schema_version") != "heel.local-run-pruned.v2"
            or record.get("workspace_id") != self.identity.workspace_id
            or record.get("runner_id") != self.identity.runner_id
            or record.get("runner_key_id") != self.identity.key_id
            or record.get("signing_key_id") != self.identity.key_id
            or record.get("runtime_state_schema") != "heel.runner-terminal-disclosure-state.v1"
        ):
            raise RunnerRuntimeCorrupt("runtime prune receipt is invalid")
        try:
            run_id = _run_id(record["run_id"])
            assert run_id is not None
            if _run_hash(run_id) != record["run_hash"]:
                raise ValueError
            for field in (
                "run_hash", "grant_digest", "prior_head_digest", "terminal_record_digest",
                "terminal_projection_digest", "detached_record_digest",
                "runtime_prune_pending_state_digest", "record_digest",
            ):
                _digest(record[field], "runtime prune receipt digest")
            terminal_at = _safe_int(record["terminal_at_ms"], "runtime prune terminal time")
            retention = _safe_int(record["retention_expires_at_ms"], "runtime prune retention time")
            pruned_at = _safe_int(record["pruned_at_ms"], "runtime prune receipt time")
            if not terminal_at <= retention <= pruned_at:
                raise ValueError
            core = {key: record[key] for key in fields - {"record_digest", "signing_key_id", "signature_b64"}}
            if record["record_digest"] != hashlib.sha256(
                _RUNTIME_PRUNED_RECEIPT_DOMAIN + canonical_bytes(core)
            ).hexdigest():
                raise ValueError
            signature = record["signature_b64"]
            if type(signature) is not str or base64.b64encode(
                base64.b64decode(signature, validate=True)
            ).decode("ascii") != signature:
                raise ValueError
            verify_envelope(
                {self.identity.key_id: load_public_key_base64(self.identity.public_key_b64)},
                {"signing_key_id": record["signing_key_id"], "signature_b64": signature},
                _RUNTIME_PRUNED_RECEIPT_DOMAIN + canonical_bytes({**core, "record_digest": record["record_digest"]}),
            )
        except (AssertionError, TypeError, ValueError):
            raise RunnerRuntimeCorrupt("runtime prune receipt is invalid") from None
        return dict(record)

    def finish_prune(
        self, *, receipt: object, expected_prune_pending_state_digest: str,
    ) -> RuntimePruneCompletion:
        record = self._validated_pruned_receipt(receipt)
        run_id = _run_id(record["run_id"])
        assert run_id is not None
        expected_state_digest = _digest(
            expected_prune_pending_state_digest, "runtime prune state digest",
        )
        if record["runtime_prune_pending_state_digest"] != expected_state_digest:
            raise RunnerRuntimeCorrupt("runtime terminal prune does not match local authority")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                state = self._load_terminal_locked(conn, run_id)
                if state is None:
                    if (
                        conn.execute("SELECT 1 FROM pending_calls WHERE run_hash=? LIMIT 1", (record["run_hash"],)).fetchone() is not None
                        or conn.execute("SELECT 1 FROM active_runs WHERE run_hash=? LIMIT 1", (record["run_hash"],)).fetchone() is not None
                        or conn.execute("SELECT 1 FROM control_chains WHERE run_hash=? LIMIT 1", (record["run_hash"],)).fetchone() is not None
                    ):
                        raise RunnerRuntimeCorrupt("runtime terminal prune does not match local authority")
                    conn.execute("COMMIT")
                    return RuntimePruneCompletion(
                        run_hash=record["run_hash"], pruned_record_digest=record["record_digest"],
                        runtime_prune_pending_state_digest=expected_state_digest,
                        authority_epoch=self._authority_epoch, _issuer=self._token,
                    )
                if (
                    state.state != "prune_pending" or state.state_digest != expected_state_digest
                    or state.run_hash != record["run_hash"]
                    or state.terminal_record_digest != record["terminal_record_digest"]
                    or state.terminal_projection_digest != record["terminal_projection_digest"]
                    or state.terminal_at_ms != record["terminal_at_ms"]
                    or state.retention_expires_at_ms != record["retention_expires_at_ms"]
                ):
                    raise RunnerRuntimeCorrupt("runtime terminal prune does not match local authority")
                conn.execute("DELETE FROM terminal_disclosures WHERE run_hash=?", (state.run_hash,))
                conn.execute("COMMIT")
                return RuntimePruneCompletion(
                    run_hash=record["run_hash"], pruned_record_digest=record["record_digest"],
                    runtime_prune_pending_state_digest=expected_state_digest,
                    authority_epoch=self._authority_epoch, _issuer=self._token,
                )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
