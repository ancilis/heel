"""Host-authority Unix listener and peer rule (H1A-1, H1AD section 3 with H1ADR section 3.2).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

A second, host-only listener for the control plane: ``AF_UNIX``, HTTP/1.1, one request per
connection, ``POST /host/v1/authority-snapshot`` only. The caller's credential is its kernel
identity, read with ``SO_PEERCRED`` before any byte is read and checked against one configured
peer profile; nothing reads ``Authorization``, cookies or the edge header, and nothing here opens
a database. The decision is injected (``decide``); H1A-2 adds the control-plane snapshot. This
module is not wired into ``build_server`` in H1A-1.

Publication order is fixed: bind a temporary name under umask 0177, chmod and verify it, listen,
then atomically rename the already-listening inode onto the final path and verify it. A listen
failure removes only the temporary inode; close unlinks the final path only while it is still
this listener's inode.
"""
import contextlib
import dataclasses
import enum
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
import threading
from pathlib import Path
from typing import Callable

__all__ = (
    "HostAuthorityConfig", "HostAuthorityConfigurationError", "HostAuthorityListener", "PeerProfile",
    "REASONS", "REQUEST_SCHEMA", "RESPONSE_SCHEMA", "ROUTE", "admit_peer", "check_startup", "read_peer",
    "request_digest", "validate_request", "validate_response",
)

ROUTE = "/host/v1/authority-snapshot"
REQUEST_SCHEMA = "heel.host-authority-request.v1"
RESPONSE_SCHEMA = "heel.host-authority-snapshot.v1"
MAX_REQUEST_BYTES = 2048
MAX_RESPONSE_BYTES = 4096
MAX_HEAD_BYTES = 8192
CONNECTION_TIMEOUT_SECONDS = 5.0
BACKLOG = 64
SAFE_INT = 2 ** 53
IDENTITY_UID_MAP = ["0", "0", "4294967295"]

# H1D section 2.2 plus the two H1ADR section 2.5 reasons (additive; same inactive shape on the wire).
REASONS = ("none", "workspace_unknown", "project_unknown", "no_active_run", "multiple_active_runs", "run_not_active",
           "stop_requested", "grant_not_claimed", "grant_expired", "invalid_grant", "proof_expired", "proof_revoked",
           "verification_digest_replaced", "runner_revoked", "key_revoked", "binding_inactive", "binding_expired",
           "kill_switch_active", "kill_switch_generation_changed", "tuple_mismatch", "malformed_request", "cp_draining",
           "replayed_sequence", "clock_gap")

_HEX32, _HEX64 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{64}")
_STRINGS = {
    "host_boot_epoch": re.compile(r"[a-z0-9-]{8,64}"),
    "slot_id": re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?"),
    "request_nonce": _HEX32,
    "generation_id": _HEX32,
    "workspace_id": re.compile(r"ws_[0-9a-f]{16}"),
    "project_id": re.compile(r"prj_[0-9a-f]{32}"),
    "environment_id": re.compile(r"env_[0-9a-f]{32}"),
    "verification_record_digest": _HEX64,
    "runner_id": re.compile(r"[A-Za-z0-9_-]{1,128}"),
    "runner_key_id": re.compile(r"[A-Za-z0-9_-]{1,128}"),
    "binding_id": re.compile(r"rcb_[0-9a-f]{32}"),
    "binding_digest": _HEX64,
    "run_id": re.compile(r"crun_[0-9a-f]{32}"),
    "grant_id": re.compile(r"[A-Za-z0-9_-]{1,128}"),
    "grant_digest": _HEX64,
}
# name -> (minimum, maximum), all inclusive integers.
_INTEGERS = {"sequence": (1, SAFE_INT), "monotonic_ms": (0, SAFE_INT), "kill_switch_generation": (0, SAFE_INT)}
REQUEST_FIELDS = frozenset({"schema_version", *_STRINGS, *_INTEGERS})

_ACTIVE_STRINGS = {
    "workspace_id": _STRINGS["workspace_id"], "project_id": _STRINGS["project_id"],
    "environment_id": _STRINGS["environment_id"], "verification_record_digest": _HEX64,
    "runner_id": _STRINGS["runner_id"], "runner_key_id": _STRINGS["runner_key_id"], "public_key_digest": _HEX64,
    "binding_id": _STRINGS["binding_id"], "binding_digest": _HEX64, "run_id": _STRINGS["run_id"],
    "run_status": re.compile(r"claimed|running"), "stop_reason": re.compile(r"none"),
    "grant_id": _STRINGS["grant_id"], "grant_digest": _HEX64,
    "egress_hostname": re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"),
}
_ACTIVE_INTEGERS = {"proof_expires_at_ms": (0, SAFE_INT), "binding_expires_at_ms": (0, SAFE_INT),
                    "grant_expires_at_ms": (0, SAFE_INT), "egress_port": (443, 443)}
_COMMON = {"schema_version", "decision", "reason", "sequence", "request_digest", "server_time_ms", "kill_switch_generation"}


class HostAuthorityConfigurationError(RuntimeError):
    """Fail-closed startup refusal with a fixed code (H1A-2 maps it to ProductionConfigurationError)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class PeerProfile(enum.Enum):
    EXTERNAL_PIDNS = "external-pidns"  # host supervisor outside the CP's PID namespace: pid must be 0
    SHARED_PIDNS = "shared-pidns"  # same PID namespace: pid must be non-zero


@dataclasses.dataclass(frozen=True)
class HostAuthorityConfig:
    socket_path: str
    peer_uid: int
    profile: PeerProfile


def _read_overflowuid(path: str) -> int:
    try:
        text = Path(path).read_text(encoding="ascii").strip()
    except OSError as error:
        raise HostAuthorityConfigurationError("overflowuid_unreadable") from error
    if not re.fullmatch(r"[0-9]{1,10}", text):
        raise HostAuthorityConfigurationError("overflowuid_unreadable")
    return int(text)


def check_startup(config: HostAuthorityConfig, *, uid_map_path: str = "/proc/self/uid_map",
                  overflowuid_path: str = "/proc/sys/kernel/overflowuid") -> int:
    """Every refusal of H1AD section 3.3; returns the overflowuid the peer rule must exclude."""
    if not isinstance(config, HostAuthorityConfig) or not isinstance(config.profile, PeerProfile):
        raise HostAuthorityConfigurationError("profile_invalid")
    if type(config.peer_uid) is not int or not 0 <= config.peer_uid < 2 ** 32 - 1:
        raise HostAuthorityConfigurationError("peer_uid_invalid")
    if not isinstance(config.socket_path, str) or not os.path.isabs(config.socket_path) or "\0" in config.socket_path:
        raise HostAuthorityConfigurationError("socket_path_invalid")
    try:
        uid_map = Path(uid_map_path).read_text(encoding="ascii")
    except OSError as error:
        raise HostAuthorityConfigurationError("uid_map_unreadable") from error
    if uid_map.split() != IDENTITY_UID_MAP:
        raise HostAuthorityConfigurationError("user_namespace_translation_unsupported")
    overflowuid = _read_overflowuid(overflowuid_path)
    if config.peer_uid == overflowuid:
        raise HostAuthorityConfigurationError("peer_uid_is_overflowuid")
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        raise HostAuthorityConfigurationError("platform_unsupported")
    _check_directory(os.path.dirname(config.socket_path))
    return overflowuid


def _check_directory(directory: str) -> None:
    try:
        info = os.lstat(directory)
    except OSError as error:
        raise HostAuthorityConfigurationError("socket_directory_missing") from error
    if not stat.S_ISDIR(info.st_mode):
        raise HostAuthorityConfigurationError("socket_directory_not_directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise HostAuthorityConfigurationError("socket_directory_profile")


def read_peer(sock: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of the connected peer, translated by the kernel into this process's
    namespaces. The only credential reader in this module; it has no switch."""
    pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return pid, uid, gid


def admit_peer(config: HostAuthorityConfig, pid: int, uid: int, overflowuid: int) -> bool:
    if uid != config.peer_uid or uid == overflowuid:
        return False
    if config.profile is PeerProfile.EXTERNAL_PIDNS:
        return pid == 0
    if config.profile is PeerProfile.SHARED_PIDNS:
        return pid != 0
    return False


# ---------------------------------------------------------------------------------------------
# Closed codec.

def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def request_digest(request: dict) -> str:
    return hashlib.sha256(canonical(request)).hexdigest()


def _no_constant(_name: str):
    raise ValueError("non-finite number")


def validate_request(body: bytes) -> dict | None:
    """The request iff ``body`` is the canonical encoding of exactly the closed schema."""
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_REQUEST_BYTES:
        return None
    try:
        request = json.loads(body.decode("ascii"), parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS or request["schema_version"] != REQUEST_SCHEMA:
        return None
    for name, pattern in _STRINGS.items():
        if not isinstance(request[name], str) or not pattern.fullmatch(request[name]):
            return None
    for name, (low, high) in _INTEGERS.items():
        if type(request[name]) is not int or not low <= request[name] <= high:
            return None
    return request if canonical(request) == body else None


def validate_response(response: object, request: dict) -> bool:
    """A ``decide`` result is sent only if it is a closed snapshot that echoes this request."""
    if not isinstance(response, dict) or response.get("decision") not in ("active", "inactive"):
        return False
    active = response["decision"] == "active"
    expected = _COMMON | (set(_ACTIVE_STRINGS) | set(_ACTIVE_INTEGERS) if active else set())
    if set(response) != expected or response["schema_version"] != RESPONSE_SCHEMA:
        return False
    if response["reason"] not in REASONS or (response["reason"] == "none") != active:
        return False
    if response["sequence"] != request["sequence"] or type(response["sequence"]) is not int:
        return False
    if response["request_digest"] != request_digest(request):
        return False
    for name in ("server_time_ms", "kill_switch_generation"):
        if type(response[name]) is not int or not 0 <= response[name] <= SAFE_INT:
            return False
    if active:
        for name, pattern in _ACTIVE_STRINGS.items():
            if not isinstance(response[name], str) or not pattern.fullmatch(response[name]):
                return False
        for name, (low, high) in _ACTIVE_INTEGERS.items():
            if type(response[name]) is not int or not low <= response[name] <= high:
                return False
    return len(canonical(response)) <= MAX_RESPONSE_BYTES


_REQUEST_LINE = re.compile(rb"POST " + re.escape(ROUTE.encode()) + rb" HTTP/1\.1")
_HEADER = re.compile(rb"([A-Za-z0-9-]{1,64}):[ \t]*([\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?)?[ \t]*")
_STATUS = {200: b"OK", 400: b"Bad Request", 404: b"Not Found", 413: b"Payload Too Large", 500: b"Internal Server Error"}
MALFORMED = {"schema_version": RESPONSE_SCHEMA, "decision": "inactive", "reason": "malformed_request"}


# ---------------------------------------------------------------------------------------------
# The listener.

class HostAuthorityListener:
    """``start()`` runs the startup checks and publishes; ``serve_forever()`` serves until
    ``close()``. ``_listen_for_tests`` is the labelled seam SEAM-LISTEN-FAILURE t4f only, an
    injected replacement for ``listen``; production code never passes it."""

    def __init__(self, config: HostAuthorityConfig, decide: Callable[[dict], dict], *,
                 _listen_for_tests: Callable[[socket.socket, int], None] | None = None):
        if not callable(decide):
            raise TypeError("decide must be callable")
        self.config = config
        self._decide = decide
        self._listen = _listen_for_tests
        self._sock: socket.socket | None = None
        self._own: tuple[int, int] | None = None
        self._overflowuid: int | None = None
        self._stop = threading.Event()
        self.counters = {"refused_peer": 0, "malformed": 0, "answered": 0, "decide_failed": 0}

    @property
    def own_inode(self) -> tuple[int, int] | None:
        return self._own

    def start(self) -> None:
        self._overflowuid = check_startup(self.config)
        self._publish()

    def _publish(self) -> None:
        """bind(tmp) -> chmod/verify -> listen -> rename(tmp, path) -> verify. No other order."""
        path = self.config.socket_path
        directory = os.path.dirname(path)
        tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        own = None
        try:
            previous = os.umask(0o177)
            try:
                sock.bind(tmp)
            finally:
                os.umask(previous)
            info = os.lstat(tmp)
            own = (info.st_dev, info.st_ino)
            os.chmod(tmp, 0o600)
            info = os.lstat(tmp)
            parent = os.lstat(directory)
            if not (stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                    and (info.st_dev, info.st_ino) == own and stat.S_ISDIR(parent.st_mode)
                    and parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700):
                raise HostAuthorityConfigurationError("socket_profile")
            if self._listen is not None:
                self._listen(sock, BACKLOG)
            else:
                sock.listen(BACKLOG)
        except BaseException:
            sock.close()
            if own is not None:
                _unlink_if_own(tmp, own)
            raise
        # The final path is written exactly once, here, after listen returned.
        try:
            os.rename(tmp, path)
            published = os.lstat(path)
        except BaseException:
            sock.close()
            _unlink_if_own(tmp, own)
            raise
        if (published.st_dev, published.st_ino) != own:
            sock.close()
            raise HostAuthorityConfigurationError("publication_replaced")
        self._sock, self._own = sock, own

    def close(self) -> None:
        self._stop.set()
        sock, own = self._sock, self._own
        self._sock = None
        if sock is None:
            return
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        _unlink_if_own(self.config.socket_path, own)

    def serve_forever(self, poll_seconds: float = 0.2) -> None:
        sock = self._sock
        if sock is None:
            raise RuntimeError("listener not started")
        sock.settimeout(poll_seconds)
        while not self._stop.is_set():
            try:
                connection, _address = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            with connection:
                self._handle(connection)

    def _handle(self, connection: socket.socket) -> None:
        """The peer rule runs on the accepted socket before any byte is read."""
        try:
            pid, uid, _gid = read_peer(connection)
            admitted = self._overflowuid is not None and admit_peer(self.config, pid, uid, self._overflowuid)
        except (OSError, AttributeError, struct.error):
            admitted = False
        if not admitted:
            self.counters["refused_peer"] += 1
            return
        self._serve_request(connection)

    def _serve_request(self, connection: socket.socket) -> None:
        connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
        try:
            status, body = self._answer(connection)
        except (OSError, ValueError):
            return
        payload = canonical(body) if body is not None else b""
        head = (b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                b"Cache-Control: no-store\r\nConnection: close\r\n\r\n" % (status, _STATUS[status], len(payload)))
        with contextlib.suppress(OSError):
            connection.sendall(head + payload)

    def _answer(self, connection: socket.socket) -> tuple[int, dict | None]:
        head, rest = _read_head(connection)
        if head is None:
            self.counters["malformed"] += 1
            return 400, MALFORMED
        lines = head.split(b"\r\n")
        if not _REQUEST_LINE.fullmatch(lines[0]):
            self.counters["malformed"] += 1
            return 404, MALFORMED
        length = content_type = None
        for line in lines[1:]:
            match = _HEADER.fullmatch(line)
            if match is None:
                self.counters["malformed"] += 1
                return 400, MALFORMED
            # Only three names are ever looked at; every other header is dropped unread.
            name, value = match.group(1).lower(), match.group(2) or b""
            if name == b"content-length":
                if length is not None or not re.fullmatch(rb"0|[1-9][0-9]{0,5}", value):
                    return 400, MALFORMED
                length = int(value)
            elif name == b"content-type":
                content_type = value
            elif name == b"transfer-encoding":
                return 400, MALFORMED
        if length is None or content_type != b"application/json":
            self.counters["malformed"] += 1
            return 400, MALFORMED
        if length > MAX_REQUEST_BYTES:
            self.counters["malformed"] += 1
            return 413, MALFORMED
        body = _read_exact(connection, rest, length)
        request = validate_request(body) if body is not None else None
        if request is None:
            self.counters["malformed"] += 1
            return 400, MALFORMED
        try:
            response = self._decide(dict(request))
        except Exception:  # noqa: BLE001 - the decision failed; the host sees "CP unavailable"
            response = None
        if not validate_response(response, request):
            self.counters["decide_failed"] += 1
            return 500, None
        self.counters["answered"] += 1
        return 200, response


def _read_head(connection: socket.socket) -> tuple[bytes | None, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > MAX_HEAD_BYTES:
            return None, b""
        chunk = connection.recv(4096)
        if not chunk:
            return None, b""
        data += chunk
    head, _separator, rest = data.partition(b"\r\n\r\n")
    return (head if len(head) <= MAX_HEAD_BYTES else None), rest


def _read_exact(connection: socket.socket, data: bytes, length: int) -> bytes | None:
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data if len(data) == length else None


def _unlink_if_own(path: str, own: tuple[int, int] | None) -> None:
    """Unlink ``path`` only while it still names ``own``; a replaced endpoint is left alone."""
    if own is None:
        return
    with contextlib.suppress(OSError):
        info = os.lstat(path)
        if (info.st_dev, info.st_ino) == own and stat.S_ISSOCK(info.st_mode):
            os.unlink(path)
