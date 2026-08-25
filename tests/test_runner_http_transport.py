from __future__ import annotations

import os
import socket
import threading

import pytest

from heel.runner.adapters import PreparedAction
from heel.runner.http_transport import (
    CancellationToken,
    TargetHTTPSClient,
    TransportFailure,
    normalize_target_origin,
    select_public_addresses,
)


PUBLIC = "93.184.216.34"


def prepared(*, method="GET", profile="anonymous", route="/health"):
    return PreparedAction(
        scenario_id="anonymous_authenticated_read",
        adapter_version="1",
        method=method,
        route=route,
        semantic_auth_role="anonymous" if profile == "anonymous" else "authenticated",
        auth_profile=profile,
        side_effect_class="read_only",
    )


def response(status=200, body=b"{}", extra=b""):
    return (
        f"HTTP/1.1 {status} Status\r\nContent-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n\r\n"
    ).encode("ascii") + body + extra


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class Resolver:
    def __init__(self, answers=None):
        self.answers = list(answers or [[PUBLIC]])
        self.calls = []

    def __call__(self, hostname, *, deadline):
        self.calls.append((hostname, deadline))
        answer = self.answers[min(len(self.calls) - 1, len(self.answers) - 1)]
        if isinstance(answer, BaseException):
            raise answer
        return answer


class RawSocket:
    def __init__(self):
        self.closed = False
        self.shutdown_called = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, how):
        self.shutdown_called = True

    def close(self):
        self.closed = True


class TLSSocket(RawSocket):
    def __init__(self, payload, *, peer=PUBLIC, block=None):
        super().__init__()
        self.payload = payload
        self.peer = peer
        self.offset = 0
        self.sent = []
        self.sent_event = threading.Event()
        self.block = block

    def getpeername(self):
        return (self.peer, 443)

    def sendall(self, value):
        self.sent.append(value)
        self.sent_event.set()

    def recv(self, size):
        if self.block is not None:
            self.block.wait(2)
            if self.closed:
                raise OSError("closed")
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class Sockets:
    def __init__(self, tls_sockets, failures=()):
        self.tls_sockets = list(tls_sockets)
        self.failures = list(failures)
        self.calls = []
        self.raw = []

    def connect(self, address, timeout, cancellation):
        self.calls.append((address, timeout))
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure
        raw = RawSocket()
        self.raw.append(raw)
        return raw


class TLS:
    def __init__(self, sockets):
        self.sockets = sockets
        self.hostnames = []
        self.wrapped = []

    def wrap(self, raw, hostname, timeout):
        self.hostnames.append((hostname, timeout))
        wrapped = self.sockets.tls_sockets.pop(0)
        self.wrapped.append(wrapped)
        return wrapped


def client(
    *, payloads=None, resolver=None, sockets=None, clock=None, gate=None,
    preflight=(PUBLIC,), maximum_response_bytes=256 * 1024,
):
    tls_sockets = [TLSSocket(value) for value in (payloads or [response()])]
    sockets = sockets or Sockets(tls_sockets)
    return TargetHTTPSClient(
        origin="https://staging.example.com",
        preflight_addresses=preflight,
        resolver=resolver or Resolver(),
        sockets=sockets,
        tls=TLS(sockets),
        clock=clock or Clock(),
        fresh_gate=gate or (lambda: True),
        maximum_response_bytes=maximum_response_bytes,
    ), sockets


def assert_code(code, callable_):
    with pytest.raises(TransportFailure) as raised:
        callable_()
    assert raised.value.code == code
    assert str(raised.value) == code


def test_origin_and_address_corpus_matches_frozen_task3_behavior():
    assert normalize_target_origin("https://Staging.Example.COM") == "https://staging.example.com"
    assert [item.compressed for item in select_public_addresses([PUBLIC, PUBLIC, "2606:4700::6810:85e5"])] == [
        PUBLIC, "2606:4700::6810:85e5",
    ]
    for value in (
        "http://example.com", "https://example.com/", "https://example.com:443",
        "https://x.internal", "https://x.unknownprivate", "https://10.0.0.1",
        "https://xn--r8jz45g.com", "https://example.com?x=1",
    ):
        assert_code("invalid_origin", lambda value=value: normalize_target_origin(value))
    for answer in (
        [PUBLIC, "10.0.0.1"], ["::ffff:93.184.216.34"], [], [PUBLIC] * 17,
    ):
        assert_code("unsafe_dns", lambda answer=answer: select_public_addresses(answer))


def test_open_core_origin_and_address_corpus_is_differentially_equal_to_task3():
    from heel.saas.network_guard import normalize_verified_origin, select_safe_addresses

    origins = (
        "https://Staging.Example.COM", "https://launch.zip", "", "http://example.com",
        "https://example.com/", "https://example.com:443", "https://192.0.2.1",
        "https://x.internal", "https://x.unknownprivate", "https://xn--r8jz45g.com",
    )
    for origin in origins:
        try:
            commercial = ("ok", normalize_verified_origin(origin))
        except Exception:
            commercial = ("rejected", None)
        try:
            runner = ("ok", normalize_target_origin(origin))
        except TransportFailure:
            runner = ("rejected", None)
        assert runner == commercial

    address_sets = (
        [PUBLIC], [PUBLIC, PUBLIC, "2606:4700::6810:85e5"], [],
        [PUBLIC, "10.0.0.1"], ["::ffff:93.184.216.34"], [PUBLIC] * 17,
    )
    for values in address_sets:
        try:
            commercial = ("ok", [item.compressed for item in select_safe_addresses(values)])
        except Exception:
            commercial = ("rejected", None)
        try:
            runner = ("ok", [item.compressed for item in select_public_addresses(values)])
        except TransportFailure:
            runner = ("rejected", None)
        assert runner == commercial


@pytest.mark.parametrize(
    "profile,credential,expected",
    [
        ("anonymous", None, b""),
        ("bearer", "top-secret", b"Authorization: Bearer top-secret\r\n"),
        ("x_api_key", "top-secret", b"X-API-Key: top-secret\r\n"),
        ("cookie_jar", {"z": "last", "a": "first"}, b"Cookie: a=first; z=last\r\n"),
    ],
)
def test_request_is_exact_direct_pinned_tls_and_auth_is_closed(profile, credential, expected):
    resolver = Resolver()
    target, sockets = client(resolver=resolver)
    old = os.environ.copy()
    os.environ.update(HTTPS_PROXY="http://proxy.invalid", ALL_PROXY="socks://proxy.invalid")
    try:
        result = target.request(prepared(profile=profile), credential=credential)
    finally:
        os.environ.clear()
        os.environ.update(old)
    assert result.status_code == 200 and result.body_shape == "json_object"
    assert result.requests_made == 1
    assert resolver.calls == [("staging.example.com", 105.0)]
    assert sockets.calls[0][0] == (PUBLIC, 443)
    assert target.tls.hostnames[0][0] == "staging.example.com"
    request_bytes = target.tls.wrapped[0].sent[0]
    assert request_bytes == (
        b"GET /health HTTP/1.1\r\n"
        b"Host: staging.example.com\r\n"
        b"Accept: application/json\r\n"
        b"Accept-Encoding: identity\r\n"
        b"Connection: close\r\n" + expected + b"\r\n"
    )


def test_dns_is_full_set_pinned_and_rechecked_before_retry_with_one_global_retry():
    resolver = Resolver([[PUBLIC], [PUBLIC], [PUBLIC]])
    tls_sockets = [TLSSocket(response()), TLSSocket(response())]
    sockets = Sockets(tls_sockets, failures=(OSError("connect"), None, OSError("connect")))
    gates = []
    target = TargetHTTPSClient(
        origin="https://staging.example.com", preflight_addresses=[PUBLIC],
        resolver=resolver, sockets=sockets, tls=TLS(sockets), clock=Clock(),
        fresh_gate=lambda: gates.append("gate") or True,
    )
    result = target.request(prepared())
    assert result.requests_made == 2
    assert len(resolver.calls) == 2 and gates == ["gate", "gate"]
    assert_code("connect_error", lambda: target.request(prepared()))
    assert len(resolver.calls) == 3


def test_dns_drift_mixed_answer_and_peer_mismatch_fail_closed():
    target, _ = client(resolver=Resolver([["1.1.1.1"]]))
    assert_code("dns_changed", lambda: target.request(prepared()))

    mixed, _ = client(resolver=Resolver([[PUBLIC, "10.0.0.1"]]))
    assert_code("unsafe_dns", lambda: mixed.request(prepared()))

    sockets = Sockets([TLSSocket(response(), peer="1.1.1.1")])
    peer, _ = client(sockets=sockets)
    assert_code("peer_mismatch", lambda: peer.request(prepared()))


@pytest.mark.parametrize(
    "payload",
    [
        response(302),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n Bad: fold\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Test: x\x01\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        response(body=b"[]"),
        response(body=b"text"),
        response(body=b"{}", extra=b"x"),
    ],
)
def test_strict_response_framing_and_shape_rejections(payload):
    target, _ = client(payloads=[payload])
    assert_code("response_rejected", lambda: target.request(prepared()))


def test_head_requires_zero_body_and_routes_are_exact_relative_reads():
    target, _ = client(payloads=[response(body=b"")])
    assert target.request(prepared(method="HEAD")).body_shape == "absent"
    for route in (
        "https://other.example/x", "//other.example/x", "/a//b", "/a/../b",
        "/x?y=1", "/x#f", "/x%2f", "/x\\y",
    ):
        target, _ = client()
        assert_code("invalid_route", lambda route=route, target=target: target.request(prepared(route=route)))


def test_response_header_and_body_caps_are_streaming_bounds():
    headers = b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 16_384 + b"\r\nContent-Length: 0\r\n\r\n"
    target, _ = client(payloads=[headers])
    assert_code("response_rejected", lambda: target.request(prepared()))
    body = b'{' + b'"x":"' + b"a" * 257 + b'"}'
    target, _ = client(payloads=[response(body=body)], maximum_response_bytes=256)
    assert_code("response_too_large", lambda: target.request(prepared()))


def test_response_ceiling_cannot_be_raised_after_construction():
    target, _ = client(maximum_response_bytes=256)
    with pytest.raises(AttributeError):
        target.maximum_response_bytes = 256 * 1024


def test_one_absolute_deadline_covers_dns_through_body_and_timeout_is_constant():
    clock = Clock()

    class LateResolver(Resolver):
        def __call__(self, hostname, *, deadline):
            answer = super().__call__(hostname, deadline=deadline)
            clock.value = deadline
            return answer

    target, _ = client(resolver=LateResolver(), clock=clock)
    assert_code("timeout", lambda: target.request(prepared()))


def test_absolute_deadline_also_bounds_fresh_gate_without_reclassifying_timeout():
    clock = Clock()

    def late_gate():
        clock.value = 105.0
        return True

    target, sockets = client(clock=clock, gate=late_gate)
    assert_code("timeout", lambda: target.request(prepared()))
    assert sockets.calls == []


def test_production_resolver_requests_absolute_dual_stack_results(monkeypatch):
    from heel.runner.http_transport import BoundedResolver

    calls = []

    def getaddrinfo(host, port, *, family, type, proto):
        calls.append((host, port, family, type, proto))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC, 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700::6810:85e5", 443, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    assert BoundedResolver(clock=lambda: 0)("staging.example.com", deadline=1) == [
        PUBLIC, "2606:4700::6810:85e5",
    ]
    assert calls == [(
        "staging.example.com.", 443, socket.AF_UNSPEC,
        socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )]


def test_cancellation_shutdowns_and_closes_registered_inflight_socket():
    release = threading.Event()
    tls_socket = TLSSocket(response(), block=release)
    sockets = Sockets([tls_socket])
    target, _ = client(sockets=sockets)
    cancellation = CancellationToken()
    failures = []
    thread = threading.Thread(
        target=lambda: failures.append(pytest.raises(TransportFailure, target.request, prepared(), cancellation=cancellation)),
        daemon=True,
    )
    thread.start()
    assert tls_socket.sent_event.wait(1)
    cancellation.cancel()
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert tls_socket.shutdown_called and tls_socket.closed
    assert failures and failures[0].value.code == "cancelled"


def test_cancellation_during_dns_returns_without_waiting_for_the_resolver():
    started = threading.Event()
    release = threading.Event()

    class BlockingResolver:
        def __call__(self, hostname, *, deadline):
            started.set()
            release.wait(2)
            return [PUBLIC]

    target, sockets = client(resolver=BlockingResolver())
    cancellation = CancellationToken()
    failures = []

    def invoke():
        try:
            target.request(prepared(), cancellation=cancellation)
        except TransportFailure as exc:
            failures.append(exc)

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    assert started.wait(1)
    cancellation.cancel()
    thread.join(0.5)
    release.set()
    assert not thread.is_alive()
    assert failures and failures[0].code == "cancelled"
    assert sockets.calls == []


def test_transport_rejects_parallel_request_without_opening_second_socket():
    release = threading.Event()
    sockets = Sockets([TLSSocket(response(), block=release)])
    target, _ = client(sockets=sockets)
    first = threading.Thread(target=lambda: target.request(prepared()), daemon=True)
    first.start()
    for _ in range(1000):
        if sockets.calls:
            break
    assert_code("concurrency_exceeded", lambda: target.request(prepared()))
    release.set()
    first.join(2)
    assert len(sockets.calls) == 1
