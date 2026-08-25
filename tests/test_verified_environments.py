import hashlib
import ipaddress
import os
import socket
import sqlite3
from dataclasses import dataclass

import pytest

from heel.saas.network_guard import (
    AddressSetValidationError,
    CHALLENGE_PATH,
    OriginValidationError,
    PeerMismatch,
    PinnedHTTPSVerifier,
    VerificationError,
    VerificationTimeout,
    normalize_verified_origin,
    select_safe_addresses,
)
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.verification import EnvironmentCooldown, OWNERSHIP_ATTESTATION, VerifiedEnvironmentService


PIN = hashlib.sha256(b"certificate").hexdigest()
TOKEN = "staging-token-123"
RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    f'Content-Length: {len(TOKEN) + 1}\r\n'
    "\r\n"
    f"{TOKEN}\n"
).encode("ascii")


def verifier(**changes):
    tls_socket = changes.pop("tls_socket", None)
    sockets_response = changes.pop("sockets_response", None)
    values = {
        "pin_sha256_hex": PIN,
        "clock": lambda: 100.0,
        "resolver": lambda hostname: ["93.184.216.34"],
        "sockets": FakeSockets(tls_socket or FakeTLSSocket(sockets_response or RESPONSE, PIN)),
        "tls": None,
    }
    values.update(changes)
    guard = PinnedHTTPSVerifier(**values)
    if values["tls"] is None:
        guard = PinnedHTTPSVerifier(
            **{**values, "tls": FakeTLS(values["sockets"].tls_socket)}
        )
    return guard


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("https://Staging.Example.COM", "https://staging.example.com"),
    ],
)
def test_normalize_exact_https_origin(origin, expected):
    assert normalize_verified_origin(origin) == expected


@pytest.mark.parametrize(
    "origin",
    [
        "",
        " http://example.com",
        "https://example.com ",
        "http://example.com",
        "HTTPS://example.com",
        "example.com",
        "https://example.com/",
        "https://user@example.com",
        "https://:pass@example.com",
        "https://example.com:443",
        "https://example.com:",
        "https://192.0.2.1",
        "https://[2001:db8::1]",
        "https://example.com/path",
        "https://example.com?query",
        "https://example.com#fragment",
        "https://ex%41mple.com",
        "https://ex ample.com",
        "https://例え.com",
        "https://xn--r8jz45g.com",
        "https://example.com.",
        "https://localhost",
        "https://foo.localhost",
        "https://metadata.google.internal",
        "https://-.example.com",
        "https://example..com",
    ],
)
def test_normalize_rejects_disallowed_origins(origin):
    with pytest.raises(OriginValidationError):
        normalize_verified_origin(origin)


def test_select_addresses_sorts_and_deduplicates():
    addresses = select_safe_addresses(
        [
            "2606:4700::6810:85e5",
            "104.16.133.229",
            "104.16.133.229",
            "104.16.132.229",
        ]
    )
    assert [address.compressed for address in addresses] == [
        "104.16.132.229",
        "104.16.133.229",
        "2606:4700::6810:85e5",
    ]


@pytest.mark.parametrize("text", ["10.0.0.1", "fe80::1"])
def test_select_addresses_poisons_mixed_answer(text):
    with pytest.raises(AddressSetValidationError):
        select_safe_addresses(["93.184.216.34", text])


class FakeSocket:
    def __init__(self):
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


class FakeConnectedSocket(FakeSocket):
    pass


class FakeTLSSocket(FakeSocket):
    def __init__(self, response, pin):
        super().__init__()
        self.response = response
        self.pin = pin
        self.requests = []
        self.offset = 0
        self.delay_reads_until = None

    def getpeercert(self, binary_form=False):
        return b"certificate"

    def getpeername(self):
        return ("93.184.216.34", 443)

    def sendall(self, request):
        self.requests.append(request)

    def recv(self, size):
        if self.delay_reads_until is not None and self.offset < len(self.response):
            raise socket.timeout()
        chunk = self.response[self.offset : self.offset + size]
        self.offset += len(chunk)
        return bytes(chunk)


class FakeSockets:
    def __init__(self, tls_socket):
        self.connected_to = None
        self.tls_socket = tls_socket
        self.configured_timeout = None

    def connect(self, address, timeout):
        self.connected_to = address
        self.connect_timeout = timeout
        return FakeConnectedSocket()

    def configure(self, connected_socket, timeout):
        connected_socket.settimeout(timeout)
        self.configured_timeout = timeout


class FakeTLS:
    def __init__(self, tls_socket):
        self.tls_socket = tls_socket
        self.hostname = None
        self.context_checks_hostname = True

    def wrap(self, connected_socket, hostname, timeout):
        self.hostname = hostname
        self.wrap_timeout = timeout
        return self.tls_socket


def test_verify_selects_stable_ip_and_accepts_exact_token():
    fake_tls_socket = FakeTLSSocket(RESPONSE, PIN)
    fake_sockets = FakeSockets(fake_tls_socket)
    result = verifier(resolver=lambda hostname: ["2606:4700::20", "93.184.216.34", "93.184.216.34"], sockets=fake_sockets).verify(
        "https://Example.COM"
    )
    assert result == TOKEN
    assert fake_sockets.connected_to == ("93.184.216.34", 443)
    assert fake_sockets.configured_timeout == 5.0
    assert fake_tls_socket.requests[0].startswith(f"GET {CHALLENGE_PATH} HTTP/1.1\r\n".encode())
    assert b"\r\nHost: example.com\r\n" in fake_tls_socket.requests[0]
    assert b"Accept-Encoding: identity\r\n" in fake_tls_socket.requests[0]


@pytest.mark.parametrize(
    "response",
    [
        RESPONSE.replace(b"HTTP/1.1 200 OK", b"HTTP/1.1 302 Found"),
        RESPONSE.replace(b"Content-Type", b"Content-Encoding"),
    ],
)
def test_verify_rejects_redirect_and_compression(response):
    with pytest.raises(VerificationError):
        verifier(sockets_response=response).verify("https://example.com")


def test_verify_rejects_oversize():
    body = b"x" * (4097 + 1)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 4098\r\n\r\n" + body
    )
    with pytest.raises(VerificationError, match="streaming bound"):
        verifier(sockets_response=response).verify("https://example.com")


def test_verify_maps_deadline_to_timeout():
    fake_tls_socket = FakeTLSSocket(RESPONSE, PIN)
    fake_tls_socket.delay_reads_until = True
    with pytest.raises(VerificationTimeout):
        verifier(sockets=FakeSockets(fake_tls_socket), tls=FakeTLS(fake_tls_socket)).verify(
            "https://example.com"
        )


def test_verify_rejects_peer_mismatch():
    fake_tls_socket = FakeTLSSocket(RESPONSE, PIN)
    with pytest.raises(PeerMismatch):
        PinnedHTTPSVerifier(
            pin_sha256_hex=hashlib.sha256(b"other").hexdigest(),
            resolver=lambda hostname: ["93.184.216.34"],
            sockets=FakeSockets(fake_tls_socket),
            tls=FakeTLS(fake_tls_socket),
        ).verify("https://example.com")


def test_verify_ignores_proxy_environment():
    old_environment = os.environ.copy()
    os.environ.update(
        HTTPS_PROXY="http://proxy.example.net:3128",
        https_proxy="http://proxy.example.net:3128",
        ALL_PROXY="socks5://proxy.example.net:1080",
        NO_PROXY="example.com",
    )
    try:
        result = verifier().verify("https://Example.COM")
    finally:
        os.environ.clear()
        os.environ.update(old_environment)
    assert result == TOKEN


def test_verify_uses_fixed_challenge_path_and_rejects_extra_lf():
    response = RESPONSE[:-1] + b"\n\n"
    with pytest.raises(VerificationError):
        verifier(sockets_response=response).verify("https://example.com")
    guard = verifier()
    assert guard.verify("https://example.com") == TOKEN
    assert CHALLENGE_PATH == "/.well-known/heel-verify.txt"


def test_environment_proof_is_project_bound_and_clears_pending_token():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    seen = []
    class Proof:
        def verify(self, origin):
            seen.append(origin)
            return token[0]
    token = [""]
    service = VerifiedEnvironmentService(conn, https_verifier=Proof())
    challenge = service.start("ws", "prj", "https://Staging.Example.COM", "staging", actor="owner")
    token[0] = challenge.token
    assert service.check("ws", "prj", challenge.environment_id, max_verified=1)
    row = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()
    assert seen == ["https://staging.example.com"]
    assert row["challenge_token"] is None
    assert row["attestation_text"] == OWNERSHIP_ATTESTATION
    assert service.is_executable("ws", "prj", challenge.environment_id)
    replacement = service.start("ws", "prj", "https://staging.example.com", "production", actor="owner")
    assert replacement.environment_id == challenge.environment_id
    assert not service.is_executable("ws", "prj", challenge.environment_id)
    conn.close()


def test_environment_check_claims_cooldown_before_a_failed_network_call():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    class FailingProof:
        def verify(self, origin):
            raise TimeoutError
    service = VerifiedEnvironmentService(conn, https_verifier=FailingProof())
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner")
    assert not service.check("ws", "prj", challenge.environment_id)
    with pytest.raises(EnvironmentCooldown):
        service.check("ws", "prj", challenge.environment_id)
    conn.close()
