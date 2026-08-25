import hashlib
import ipaddress
import os
import socket
import sqlite3
import http.client
import json
import threading
import time
from dataclasses import dataclass

import pytest

from heel.saas.network_guard import (
    AddressSetValidationError,
    BoundedDNSResolver,
    CHALLENGE_PATH,
    OriginValidationError,
    PeerMismatch,
    PinnedHTTPSVerifier,
    VerificationError,
    VerificationTimeout,
    VerificationTimeout,
    normalize_verified_origin,
    select_safe_addresses,
)
from heel.saas.iana_root_tlds import (
    IANA_ROOT_TLDS,
    IANA_TLD_LINE_COUNT,
    IANA_TLD_SHA256,
    IANA_TLD_VERSION,
)
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.verification import (
    EnvironmentCooldown, HostnameReuseExceeded, OWNERSHIP_ATTESTATION, TargetLimitExceeded,
    VerifiedEnvironmentService,
)
from heel.saas.http_api import ControlPlane, serve
from heel.saas.tenancy import Role


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
        "resolver": lambda hostname, *, timeout_seconds=None: ["93.184.216.34"],
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


def test_normalize_requires_frozen_iana_public_root_zone_tld():
    assert IANA_TLD_VERSION == "2026082301"
    assert IANA_TLD_SHA256 == "1e296954a3bbe1525756893e68e3b5917604c299a696b2e59390a8a2e99289ef"
    assert IANA_TLD_LINE_COUNT == 1439
    assert {"com", "zip"} <= IANA_ROOT_TLDS
    assert normalize_verified_origin("https://staging.example.com") == "https://staging.example.com"
    assert normalize_verified_origin("https://launch.zip") == "https://launch.zip"
    for origin in ("https://staging.private", "https://staging.intranet", "https://staging.acmeinternal", "https://service.arpa"):
        with pytest.raises(OriginValidationError):
            normalize_verified_origin(origin)


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
        "https://printer",
        "https://svc.corp",
        "https://x.example",
        "https://x.onion",
        "https://x.home.arpa",
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


def test_bounded_dns_txt_uses_absolute_names_and_rejects_private_answers():
    class TXT:
        strings = (b"heel-verify=token",)
    class Resolver:
        def __init__(self): self.calls = []
        def resolve(self, name, kind, **kwargs):
            self.calls.append((name, kind, kwargs))
            return {"A": ["93.184.216.34"], "AAAA": [], "TXT": [TXT()]}[kind]
    fake = Resolver()
    resolver = BoundedDNSResolver(resolver=fake)
    assert resolver.txt("staging.example.com") == ["heel-verify=token"]
    assert [call[0] for call in fake.calls] == ["staging.example.com.", "staging.example.com.", "_heel.staging.example.com."]
    assert all(call[2]["search"] is False for call in fake.calls)
    class PrivateResolver(Resolver):
        def resolve(self, name, kind, **kwargs):
            return ["10.0.0.1"] if kind == "A" else []
    with pytest.raises(AddressSetValidationError):
        BoundedDNSResolver(resolver=PrivateResolver()).txt("staging.example.com")


def test_bounded_dns_consumes_verifier_deadline_for_each_query():
    class Resolver:
        def __init__(self): self.calls = []
        def resolve(self, name, kind, **kwargs):
            self.calls.append(kwargs)
            return ["93.184.216.34"] if kind == "A" else []
    fake = Resolver()
    bounded = BoundedDNSResolver(resolver=fake, lifetime=1, clock=lambda: 100)
    bounded("staging.example.com", deadline=100.05)
    assert [call["lifetime"] for call in fake.calls] == [pytest.approx(0.05), pytest.approx(0.05)]


def test_bounded_dns_deadline_between_a_and_aaaa_is_typed_timeout_for_service():
    class Resolver:
        def resolve(self, name, kind, **kwargs):
            return ["93.184.216.34"] if kind == "A" else []
    clock_values = iter((0.0, 0.0, 6.0))
    bounded = BoundedDNSResolver(resolver=Resolver(), lifetime=5, clock=lambda: next(clock_values))
    guard = PinnedHTTPSVerifier(resolver=bounded)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    service = VerifiedEnvironmentService(conn, https_verifier=guard)
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    assert not service.check("ws", "prj", challenge.environment_id)
    assert conn.execute("SELECT last_failure_code FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()[0] == "network_timeout"
    conn.close()


def test_pinned_verifier_passes_remaining_time_to_bounded_dns_contract():
    class Resolver:
        def __init__(self): self.calls = []
        def resolve(self, name, kind, **kwargs):
            self.calls.append(kwargs)
            return ["93.184.216.34"] if kind == "A" else []
    dns = Resolver()
    bounded = BoundedDNSResolver(resolver=dns, lifetime=1, clock=lambda: 100)
    tls_socket = FakeTLSSocket(RESPONSE, PIN)
    guard = PinnedHTTPSVerifier(
        pin_sha256_hex=PIN, timeout_seconds=0.05, clock=lambda: 0,
        resolver=bounded, sockets=FakeSockets(tls_socket), tls=FakeTLS(tls_socket),
    )
    assert guard.verify("https://example.com") == TOKEN
    assert [call["lifetime"] for call in dns.calls] == [pytest.approx(0.05), pytest.approx(0.05)]


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
    result = verifier(resolver=lambda hostname, *, timeout_seconds=None: ["2606:4700::20", "93.184.216.34", "93.184.216.34"], sockets=fake_sockets).verify(
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


@pytest.mark.parametrize(
    "response",
    [
        RESPONSE.replace(b"Content-Type: text/plain", b"Transfer-Encoding : chunked"),
        RESPONSE.replace(b"Content-Type: text/plain", b"Transfer-Encoding: identity\r\nContent-Type: text/plain"),
        RESPONSE.replace(b"Content-Type: text/plain", b"Bad Header: text/plain"),
        RESPONSE.replace(b"Content-Type: text/plain", b"Bad-\x01: text/plain"),
        RESPONSE.replace(b"Content-Type: text/plain", b"Content-Type: text/plain\x01"),
        RESPONSE.replace(b"Content-Type: text/plain", b"Content-Type:  text/plain"),
    ],
)
def test_verify_rejects_ambiguous_or_invalid_response_headers(response):
    with pytest.raises(VerificationError):
        verifier(sockets_response=response).verify("https://example.com")


def test_verify_rejects_resolver_without_deadline_contract():
    with pytest.raises(ValueError, match="deadline-aware"):
        PinnedHTTPSVerifier(resolver=lambda hostname: ["93.184.216.34"])


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
            resolver=lambda hostname, *, timeout_seconds=None: ["93.184.216.34"],
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
    challenge = service.start("ws", "prj", "https://Staging.Example.COM", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    token[0] = challenge.token
    assert service.check("ws", "prj", challenge.environment_id, max_verified=1)
    row = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()
    assert seen == ["https://staging.example.com"]
    assert row["challenge_token"] is None
    assert row["attestation_text"] == OWNERSHIP_ATTESTATION
    assert service.is_executable("ws", "prj", challenge.environment_id)
    replacement = service.start("ws", "prj", "https://staging.example.com", "production", actor="owner",
                                attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                                attestation_acknowledgement="accepted")
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
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    assert not service.check("ws", "prj", challenge.environment_id)
    with pytest.raises(EnvironmentCooldown):
        service.check("ws", "prj", challenge.environment_id)
    conn.close()


def test_environment_records_typed_network_timeout_code():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    class TimedOut:
        def verify(self, origin): raise VerificationTimeout("late")
    service = VerifiedEnvironmentService(conn, https_verifier=TimedOut())
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    assert not service.check("ws", "prj", challenge.environment_id)
    assert conn.execute("SELECT last_failure_code FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()[0] == "network_timeout"
    conn.close()


def test_environment_quota_counts_the_whole_workspace_not_one_project():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.executemany("INSERT INTO projects VALUES(?,?,?,?,?)", [("ws", "one", "one", "owner", 1), ("ws", "two", "two", "owner", 1)])
    token = [""]
    class Proof:
        def verify(self, origin): return token[0]
    service = VerifiedEnvironmentService(conn, https_verifier=Proof())
    fields = {"attestation_text": OWNERSHIP_ATTESTATION, "attestation_version": "v1", "attestation_acknowledgement": "accepted"}
    first = service.start("ws", "one", "https://one.example.com", "staging", actor="owner", **fields)
    token[0] = first.token
    assert service.check("ws", "one", first.environment_id, max_verified=1)
    second = service.start("ws", "two", "https://two.example.com", "staging", actor="owner", **fields)
    token[0] = second.token
    with pytest.raises(TargetLimitExceeded):
        service.check("ws", "two", second.environment_id, max_verified=1)
    assert conn.execute("SELECT last_failure_code FROM canary_environments WHERE environment_id=?", (second.environment_id,)).fetchone()[0] == "quota_exceeded"
    conn.close()


def test_environment_hostname_reuse_finalization_is_persisted():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.executemany("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", [("one", "org", "one", "free", CATALOG_VERSION, 1), ("two", "org", "two", "free", CATALOG_VERSION, 1)])
    conn.executemany("INSERT INTO projects VALUES(?,?,?,?,?)", [("one", "prj", "project", "owner", 1), ("two", "prj", "project", "owner", 1)])
    token = [""]
    class Proof:
        def verify(self, origin): return token[0]
    service = VerifiedEnvironmentService(conn, https_verifier=Proof(), max_workspaces_per_hostname=0)
    fields = {"attestation_text": OWNERSHIP_ATTESTATION, "attestation_version": "v1", "attestation_acknowledgement": "accepted"}
    first = service.start("one", "prj", "https://shared.example.com", "staging", actor="owner", **fields)
    token[0] = first.token
    # Seed an active other-workspace proof without relaxing the target service's enforcement.
    conn.execute("UPDATE canary_environments SET status='verified',verified_at=1,proof_expires_at=? WHERE environment_id=?", (time.time() + 3600, first.environment_id))
    conn.commit()
    second = service.start("two", "prj", "https://shared.example.com", "staging", actor="owner", **fields)
    token[0] = second.token
    with pytest.raises(HostnameReuseExceeded):
        service.check("two", "prj", second.environment_id)
    assert conn.execute("SELECT last_failure_code FROM canary_environments WHERE environment_id=?", (second.environment_id,)).fetchone()[0] == "hostname_reuse_exceeded"
    conn.close()


def test_replaced_environment_challenge_is_auditable_without_touching_new_token():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    fields = {"attestation_text": OWNERSHIP_ATTESTATION, "attestation_version": "v1", "attestation_acknowledgement": "accepted"}
    replacement = [None]
    class ReplacingProof:
        def verify(self, origin):
            replacement[0] = service.start("ws", "prj", origin, "staging", actor="owner", **fields)
            return original.token
    service = VerifiedEnvironmentService(conn, https_verifier=ReplacingProof())
    original = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner", **fields)
    assert not service.check("ws", "prj", original.environment_id)
    current = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (original.environment_id,)).fetchone()
    assert current["challenge_generation"] == replacement[0].generation
    assert current["challenge_token"] == replacement[0].token
    assert current["last_failure_code"] == "challenge_replaced"
    public = service.public_record(current)
    assert public["status"] == "pending"
    assert "challenge_token" not in public
    assert replacement[0].token not in json.dumps(public)
    conn.close()


def test_finalization_expiry_is_recorded_as_expired_not_replaced():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    now = [100.0]
    class ExpiringProof:
        token = ""
        def verify(self, origin):
            now[0] += 24 * 3600 + 1
            return self.token
    proof = ExpiringProof()
    service = VerifiedEnvironmentService(conn, https_verifier=proof, clock=lambda: now[0])
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    proof.token = challenge.token
    assert not service.check("ws", "prj", challenge.environment_id)
    row = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()
    assert row["last_failure_code"] == "challenge_expired"
    assert row["challenge_token"] == challenge.token
    assert row["status"] == "pending"
    conn.close()


def test_finalization_revocation_preserves_proof_revoked_closed_state():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    challenge = [None]
    class RevokingProof:
        def verify(self, origin):
            assert service.revoke("ws", "prj", challenge[0].environment_id, actor="owner", reason="changed")
            return challenge[0].token
    service = VerifiedEnvironmentService(conn, https_verifier=RevokingProof())
    challenge[0] = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                                 attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                                 attestation_acknowledgement="accepted")
    assert not service.check("ws", "prj", challenge[0].environment_id)
    row = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (challenge[0].environment_id,)).fetchone()
    assert row["status"] == "revoked"
    assert row["last_failure_code"] == "proof_revoked"
    assert row["challenge_token"] is None
    conn.close()


def test_environment_start_requires_exact_user_attestation_fields():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))
    service = VerifiedEnvironmentService(conn)
    with pytest.raises(ValueError):
        service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                      attestation_text="forged", attestation_version="v1", attestation_acknowledgement="accepted")
    challenge = service.start("ws", "prj", "https://staging.example.com", "staging", actor="owner",
                              attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
                              attestation_acknowledgement="accepted")
    row = conn.execute("SELECT * FROM canary_environments WHERE environment_id=?", (challenge.environment_id,)).fetchone()
    assert row["attestation_text"] == OWNERSHIP_ATTESTATION
    assert row["attestation_version"] == "v1"
    assert row["attestation_acknowledgement"] == "accepted"
    conn.close()


def test_dns_txt_cannot_verify_nonpublic_root_zone_origin():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,org_id TEXT,name TEXT,plan_id TEXT,catalog_version TEXT,created_at REAL);"
        "CREATE TABLE projects(workspace_id TEXT,project_ref TEXT,name TEXT,created_by TEXT,created_at REAL,PRIMARY KEY(workspace_id,project_ref));"
    )
    conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", ("ws", "prj", "project", "owner", 1))

    class FakePublicDNS:
        calls = []
        def __call__(self, hostname):
            self.calls.append(("address", hostname))
            return ["93.184.216.34"]
        def txt(self, hostname):
            self.calls.append(("txt", hostname))
            return ["heel-verify=would-be-exact-token"]

    dns = FakePublicDNS()
    service = VerifiedEnvironmentService(conn, dns_txt=dns)
    with pytest.raises(ValueError, match="exact public https origin"):
        service.start(
            "ws", "prj", "https://staging.private", "staging", actor="owner", proof_method="dns-txt",
            attestation_text=OWNERSHIP_ATTESTATION, attestation_version="v1",
            attestation_acknowledgement="accepted",
        )
    assert dns.calls == []
    assert conn.execute("SELECT count(*) FROM canary_environments").fetchone()[0] == 0
    assert not service.is_executable("ws", "prj", "env_private")
    conn.close()


def test_environment_http_ceremony_is_closed_and_token_is_pending_only():
    class Proof:
        token = ""
        def verify(self, origin):
            return self.token
    proof = Proof()
    cp = ControlPlane(device_token_pepper=b"p" * 32, enable_device_auth=True,
                      public_origin="https://heel.example", environment_https_verifier=proof)
    oid = cp.store.create_org("org")
    owner = cp.store.create_user("owner@example.com")
    wid = cp.store.create_workspace(oid, "ws", "free", CATALOG_VERSION)
    cp.store.add_member(wid, owner, Role.OWNER)
    project = cp.projects.create(wid, "project", created_by=owner)
    session = cp.auth.create_session(owner)
    server = serve(cp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def request(method, path, body=None, headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            wire = None if body is None else json.dumps(body)
            connection.request(method, path, body=wire, headers=headers or {})
            response = connection.getresponse()
            result = json.loads(response.read())
            connection.close()
            return response.status, result
        base = {"Cookie": f"heel_session={session.token}", "Origin": "https://heel.example",
                "X-Heel-Internal-Origin": "same-origin", "Content-Type": "application/json"}
        start_body = {"schema_version": "heel.verified-environment-start.v1", "origin": "https://staging.example.com",
                      "environment_class": "staging", "proof_method": "https-file",
                      "attestation_text": OWNERSHIP_ATTESTATION, "attestation_version": "v1",
                      "attestation_acknowledgement": "accepted"}
        path = f"/v1/workspaces/{wid}/projects/{project.project_ref}/environments"
        status, failed = request("POST", path, start_body, {k: v for k, v in base.items() if k != "Origin"})
        assert status == 403 and failed["code"] == "same_origin_required"
        status, failed = request("POST", path, start_body, {**base, "Origin": "https://evil.example"})
        assert status == 403 and failed["code"] == "same_origin_required"
        member = cp.store.create_user("member@example.com")
        cp.store.add_member(wid, member, Role.MEMBER)
        member_session = cp.auth.create_session(member)
        status, failed = request("POST", path, start_body, {**base, "Cookie": f"heel_session={member_session.token}"})
        assert status == 403 and failed["code"] == "recent_auth_required"
        bad = dict(start_body, attestation_text="forged")
        status, failed = request("POST", path, bad, base)
        assert status == 400 and failed["code"] == "invalid_environment_request"
        status, challenge = request("POST", path, start_body, base)
        assert status == 201 and challenge["token"]
        proof.token = challenge["token"]
        eid = challenge["environment_id"]
        check_path = path + f"/{eid}/check"
        status, checked = request("POST", check_path, {"schema_version": "heel.verified-environment-check.v1"}, base)
        assert status == 200 and checked["verified"] is True
        status, listed = request("GET", path, headers={"Cookie": f"heel_session={session.token}"})
        assert status == 200 and listed["environments"][0]["is_executable"] is True
        assert "token" not in listed["environments"][0]
        revoke_path = path + f"/{eid}/revoke"
        status, revoked = request("POST", revoke_path, {"schema_version": "heel.verified-environment-revoke.v1", "reason": "done"}, base)
        assert status == 200 and revoked["revoked"] is True
    finally:
        server.shutdown()
        server.server_close()
