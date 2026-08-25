from __future__ import annotations

import os
import socket
import threading

import pytest

from heel.runner.adapters import PreparedAction
from heel.runner.http_transport import (
    AttemptPermit,
    BoundedResponseEvidence,
    CancellationToken,
    EvidenceContext,
    RetryPolicy,
    TargetHTTPSClient,
    TransportFailure,
    normalize_target_origin,
    select_public_addresses,
)
from heel.runner.redaction import Redactor


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
    *, payloads=None, resolver=None, sockets=None, clock=None,
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
        maximum_response_bytes=maximum_response_bytes,
    ), sockets


class EvidenceSink:
    def __init__(self):
        self.records = []

    def __call__(self, record):
        assert isinstance(record, BoundedResponseEvidence)
        self.records.append(record)
        return "ev1_" + f"{len(self.records):064x}"


def authorized(
    target,
    action=None,
    *,
    credential=None,
    cancellation=None,
    retry_policy=None,
    remaining_requests=2,
    before_attempt=None,
    evidence_sink=None,
    redactor=None,
):
    action = action or prepared()
    evidence_sink = evidence_sink or EvidenceSink()
    configured = []
    if isinstance(credential, str):
        configured.append(credential)
    elif isinstance(credential, dict):
        configured.extend(credential.values())
    return target.request(
        action,
        credential=credential,
        cancellation=cancellation or CancellationToken(),
        retry_policy=retry_policy or RetryPolicy(1, ("connect_error", "timeout")),
        remaining_requests=remaining_requests,
        before_attempt=before_attempt or (
            lambda attempt, previous_failure_code: AttemptPermit(105.0)
        ),
        evidence_context=EvidenceContext(0, "/health"),
        evidence_sink=evidence_sink,
        redactor=redactor or Redactor(tuple(configured)),
    )


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
        result = authorized(target, prepared(profile=profile), credential=credential)
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


def test_dns_is_full_set_pinned_and_rechecked_before_authorized_retry():
    resolver = Resolver([[PUBLIC], [PUBLIC], [PUBLIC]])
    tls_sockets = [TLSSocket(response()), TLSSocket(response())]
    sockets = Sockets(tls_sockets, failures=(OSError("connect"), None, OSError("connect")))
    target = TargetHTTPSClient(
        origin="https://staging.example.com", preflight_addresses=[PUBLIC],
        resolver=resolver, sockets=sockets, tls=TLS(sockets), clock=Clock(),
    )
    attempts = []
    result = authorized(
        target,
        before_attempt=lambda attempt, previous: (
            attempts.append((attempt, previous)) or AttemptPermit(105.0)
        ),
    )
    assert result.requests_made == 2
    assert len(resolver.calls) == 2
    assert attempts == [(1, None), (2, "connect_error")]


def test_retry_policy_is_immutable_exact_and_zero_disables_retry():
    policy = RetryPolicy.from_mapping({
        "maximum_retries": 0,
        "retryable_failure_codes": ["connect_error", "timeout"],
    })
    assert policy == RetryPolicy(0, ("connect_error", "timeout"))
    with pytest.raises((AttributeError, TypeError)):
        policy.maximum_retries = 1  # type: ignore[misc]
    for invalid in (
        {"maximum_retries": 2, "retryable_failure_codes": ["connect_error"]},
        {"maximum_retries": 1, "retryable_failure_codes": ["tls_error"]},
        {"maximum_retries": 1, "retryable_failure_codes": ["timeout", "connect_error"]},
        {"maximum_retries": 1, "retryable_failure_codes": ["timeout"], "extra": 1},
    ):
        with pytest.raises(ValueError):
            RetryPolicy.from_mapping(invalid)

    sockets = Sockets([], failures=(OSError("connect"), OSError("second")))
    target, _ = client(sockets=sockets)
    calls = []
    assert_code("connect_error", lambda: authorized(
        target,
        retry_policy=policy,
        before_attempt=lambda attempt, previous: (
            calls.append((attempt, previous)) or AttemptPermit(105.0)
        ),
    ))
    assert calls == [(1, None)] and len(sockets.calls) == 1


def test_remaining_request_budget_blocks_zero_and_never_widens_last_request():
    target, sockets = client(sockets=Sockets([], failures=(OSError("connect"),)))
    callback_calls = []
    assert_code("gate_rejected", lambda: authorized(
        target,
        remaining_requests=0,
        before_attempt=lambda attempt, previous: callback_calls.append(attempt),
    ))
    assert callback_calls == [] and sockets.calls == []

    sockets = Sockets([], failures=(OSError("connect"), OSError("retry")))
    target, _ = client(sockets=sockets)
    assert_code("connect_error", lambda: authorized(target, remaining_requests=1))
    assert len(sockets.calls) == 1


@pytest.mark.parametrize("changed_authority", ["grant_expired", "kill_switch", "proof_expired"])
def test_executor_authority_is_rechecked_before_retry_dns_or_socket(changed_authority):
    resolver = Resolver([[PUBLIC], [PUBLIC]])
    sockets = Sockets([], failures=(OSError("connect"), None))
    target, _ = client(resolver=resolver, sockets=sockets)
    calls = []

    def before_attempt(attempt, previous):
        calls.append((attempt, previous))
        if attempt == 2:
            failure = TransportFailure("gate_rejected")
            failure.authority_code = changed_authority
            raise failure
        return AttemptPermit(105.0)

    with pytest.raises(TransportFailure) as raised:
        authorized(target, before_attempt=before_attempt)
    assert raised.value.code == "gate_rejected"
    assert getattr(raised.value, "authority_code") == changed_authority
    assert calls == [(1, None), (2, "connect_error")]
    assert len(resolver.calls) == 1 and len(sockets.calls) == 1


def test_required_authority_arguments_are_non_bypassable_before_network():
    target, sockets = client()
    with pytest.raises(TypeError):
        target.request(prepared())
    assert sockets.calls == []


def test_transport_failure_carries_executor_gate_and_stop_metadata_without_reflection():
    failure = TransportFailure("gate_rejected")
    assert failure.gate_error is None and failure.stop_reason == "none"
    failure.gate_error = "proof_expired"
    failure.stop_reason = "cloud_stop"
    assert failure.gate_error == "proof_expired" and failure.stop_reason == "cloud_stop"
    assert "proof_expired" not in str(failure) and "cloud_stop" not in repr(failure)


def test_dns_drift_mixed_answer_and_peer_mismatch_fail_closed():
    target, _ = client(resolver=Resolver([["1.1.1.1"]]))
    assert_code("dns_changed", lambda: authorized(target))

    mixed, _ = client(resolver=Resolver([[PUBLIC, "10.0.0.1"]]))
    assert_code("unsafe_dns", lambda: authorized(mixed))

    sockets = Sockets([TLSSocket(response(), peer="1.1.1.1")])
    peer, _ = client(sockets=sockets)
    assert_code("peer_mismatch", lambda: authorized(peer))


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
        b"HTTP/1.1 200 OK\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n",
        response(body=b"[]"),
        response(body=b"text"),
        response(body=b"{}", extra=b"x"),
    ],
)
def test_strict_response_framing_and_shape_rejections(payload):
    target, _ = client(payloads=[payload])
    assert_code("response_rejected", lambda: authorized(target))


def test_head_requires_zero_body_and_routes_are_exact_relative_reads():
    target, _ = client(payloads=[response(body=b"")])
    assert authorized(target, prepared(method="HEAD")).body_shape == "absent"
    for route in (
        "https://other.example/x", "//other.example/x", "/a//b", "/a/../b",
        "/x?y=1", "/x#f", "/x%2f", "/x\\y",
    ):
        target, _ = client()
        assert_code("invalid_route", lambda route=route, target=target: authorized(target, prepared(route=route)))


def test_head_accepts_bounded_content_length_metadata_but_rejects_any_actual_body():
    metadata_only = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n"
        b"Content-Type: application/json\r\n\r\n"
    )
    sink = EvidenceSink()
    target, _ = client(payloads=[metadata_only])
    result = authorized(target, prepared(method="HEAD"), evidence_sink=sink)
    assert result.body_shape == "absent" and result.response_bytes == 0
    assert sink.records[0].raw_body == b""

    without_metadata = b"HTTP/1.1 204 No Content\r\nX-Safe: yes\r\n\r\n"
    target, _ = client(payloads=[without_metadata])
    assert authorized(target, prepared(method="HEAD")).body_shape == "absent"

    with_body = metadata_only + b"x"
    target, _ = client(payloads=[with_body])
    assert_code("response_rejected", lambda: authorized(target, prepared(method="HEAD")))


def test_completed_response_is_written_only_to_required_local_evidence_sink():
    secret = "reflected-secret-value"
    body = ('{"token":"' + secret + '"}').encode()
    payload = (
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
        "Set-Cookie: sid=response-cookie\r\n\r\n"
    ).encode() + body
    sink = EvidenceSink()
    target, _ = client(payloads=[payload])
    result = authorized(
        target,
        prepared(profile="bearer"),
        credential=secret,
        evidence_sink=sink,
        redactor=Redactor((secret,)),
    )
    assert result.evidence_ref == "ev1_" + "1".zfill(64)
    assert result.redaction_count == 2
    assert set(result.__dataclass_fields__) == {
        "status_code", "body_shape", "response_bytes", "requests_made",
        "evidence_ref", "redaction_count",
    }
    record = sink.records[0]
    assert record.action_ordinal == 0 and record.attempt == 1
    assert record.method == "GET" and record.route_template == "/health"
    assert record.raw_headers.startswith(b"HTTP/1.1 200 OK") and record.raw_body == body
    assert b"Authorization" not in record.raw_headers
    assert secret not in repr(result)


def test_full_task5_credential_bound_is_counted_in_response_without_cloud_reflection():
    secret = "s" * (16 * 1024)
    body = ('{"echo":"' + secret + '"}').encode()
    sink = EvidenceSink()
    target, _ = client(payloads=[response(body=body)])
    result = authorized(
        target,
        prepared(profile="bearer"),
        credential=secret,
        evidence_sink=sink,
        redactor=Redactor((secret,)),
    )
    assert result.redaction_count == 1 and result.evidence_ref.startswith("ev1_")
    assert secret.encode() in sink.records[0].raw_body
    assert secret not in repr(result)


def test_evidence_template_must_match_the_exact_prepared_action_route():
    action = PreparedAction(
        scenario_id="object_ownership_read",
        adapter_version="1",
        method="GET",
        route="/items/local-id",
        semantic_auth_role="object_owner",
        auth_profile="bearer",
        side_effect_class="read_only",
    )
    target, _ = client()
    sink = EvidenceSink()
    result = target.request(
        action,
        credential="credential",
        cancellation=CancellationToken(),
        retry_policy=RetryPolicy(0, ()),
        remaining_requests=1,
        before_attempt=lambda attempt, previous: AttemptPermit(105.0),
        evidence_context=EvidenceContext(7, "/items/{id}"),
        evidence_sink=sink,
        redactor=Redactor(("credential",)),
    )
    assert result.status_code == 200 and sink.records[0].route_template == "/items/{id}"

    target, sockets = client()
    with pytest.raises(TransportFailure) as raised:
        target.request(
            action,
            credential="credential",
            cancellation=CancellationToken(),
            retry_policy=RetryPolicy(0, ()),
            remaining_requests=1,
            before_attempt=lambda attempt, previous: AttemptPermit(105.0),
            evidence_context=EvidenceContext(7, "/other/{id}"),
            evidence_sink=sink,
            redactor=Redactor(("credential",)),
        )
    assert raised.value.code == "gate_rejected" and sockets.calls == []


def test_completed_but_unsupported_body_is_stored_locally_before_rejection():
    sink = EvidenceSink()
    target, _ = client(payloads=[response(body=b"[]")])
    assert_code("response_rejected", lambda: authorized(target, evidence_sink=sink))
    assert len(sink.records) == 1 and sink.records[0].raw_body == b"[]"


def test_evidence_sink_failure_is_constant_and_never_reflects_raw_response():
    secret = "raw-local-only-secret"
    target, _ = client(payloads=[response(body=("{\"x\":\"" + secret + "\"}").encode())])

    def failing_sink(record):
        raise RuntimeError(record.raw_body.decode())

    with pytest.raises(TransportFailure) as raised:
        authorized(target, evidence_sink=failing_sink, redactor=Redactor((secret,)))
    assert raised.value.code == "evidence_rejected"
    assert secret not in str(raised.value) and secret not in repr(raised.value)


def test_response_header_and_body_caps_are_streaming_bounds():
    headers = b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 16_384 + b"\r\nContent-Length: 0\r\n\r\n"
    target, _ = client(payloads=[headers])
    assert_code("response_rejected", lambda: authorized(target))
    body = b'{' + b'"x":"' + b"a" * 257 + b'"}'
    target, _ = client(payloads=[response(body=body)], maximum_response_bytes=256)
    assert_code("response_too_large", lambda: authorized(target))


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
    assert_code("timeout", lambda: authorized(target))


def test_absolute_deadline_is_clamped_by_executor_permit():
    clock = Clock()
    target, sockets = client(clock=clock)
    result = authorized(
        target,
        before_attempt=lambda attempt, previous: AttemptPermit(100.25),
    )
    assert result.status_code == 200
    assert sockets.calls[0][1] == pytest.approx(0.25)


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
        target=lambda: failures.append(pytest.raises(
            TransportFailure, authorized, target, cancellation=cancellation,
        )),
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
            authorized(target, cancellation=cancellation)
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
    first = threading.Thread(target=lambda: authorized(target), daemon=True)
    first.start()
    for _ in range(1000):
        if sockets.calls:
            break
    assert_code("concurrency_exceeded", lambda: authorized(target))
    release.set()
    first.join(2)
    assert len(sockets.calls) == 1
