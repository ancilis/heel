#!/usr/bin/env python3
"""Fail-closed deployed customer-acceptance preflight (C9-prep).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

An unauthenticated operator check of the Heel public origin; it is not a customer-target scanner.
Writes one closed ``heel.customer-acceptance-preflight.v1`` report for a canonical public HTTPS
origin. The only network action is one bounded, header-oriented ``GET /`` through the ownership
verifier's guards in ``heel.saas.network_guard``: exact public origin policy, a bounded DNS answer
whose every address is public, a connection to that pinned address, TLS 1.2+ with certificate and
hostname verification, one 5-second deadline, and no redirect following.

Receives stop at the end of the header block and never exceed ``MAX_CHALLENGE_HEADER_BYTES + 4``
bytes in total. TLS/TCP has no boundary between headers and body, so a receive can also deliver a
bounded body prefix coalesced with the headers into a transient in-memory receive buffer (the TLS
library and kernel may buffer more until close). Only the status line is parsed; header values and
any body prefix are not parsed, and are never persisted, reported or logged.

A 2xx answer shows reachability, not that the origin is Heel, which release it runs, or that it is
ready: ``GET /`` cannot bind any of those, so ``public_https`` stays ``blocked`` with
``heel_identity_unproven``. Every later stage is blocked on its named dependency, so the result is
normally ``BLOCKED`` (or ``FAIL``) and is never acceptance. No credential, token, target URL,
target body, provider or account input is accepted from the command line or the environment.

Supported environment: run from the root of a Heel source checkout with Python 3.11+ and the
pinned control-plane ``dnspython==2.8.0`` wheel (installed by hash in ``.github/workflows/ci.yml``
and ``deploy/Dockerfile.control-plane``; ``pyproject.toml`` declares no extra for it). It imports
``heel.saas.network_guard`` from that checkout. It is not part of the public runner install and is
not a no-checkout customer command.

Run: python scripts/customer_acceptance_preflight.py --public-origin https://HOST --output DIR
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import time
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heel.saas.network_guard import (  # noqa: E402
    HTTPS_PORT,
    MAX_CHALLENGE_HEADER_BYTES,
    AddressSetValidationError,
    BoundedDNSResolver,
    DNSResolutionTimeout,
    OriginValidationError,
    SocketTransport,
    TLSTransport,
    normalize_verified_origin,
    select_safe_addresses,
)

SCHEMA_VERSION = "heel.customer-acceptance-preflight.v1"
REPORT_NAME = "customer-acceptance-preflight.json"
PROBE_TIMEOUT_SECONDS = 5.0
EXIT_READY = 0
EXIT_FAIL = 1
EXIT_INVALID_ORIGIN = 2
EXIT_BLOCKED = 3
EXIT_INVALID_OUTPUT = 4

# RFC 2606 second-level names, and the owner-private local-review Sites deployment
# (docs/saas/OPERATIONS.md, "Owner-private local review deployment"): never customer acceptance.
_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
_REFERENCE_ORIGINS = frozenset({"https://heel-agent-first-private.hellostella.chatgpt.site"})
_STATUS_LINE = re.compile(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?\Z")

_LATER_STAGES = (
    ("browser_auth", "deployed_browser_session_unproven",
     "Signup/login/session are proven only over loopback (apps/heel-cloud/README.md:80-83; "
     "tests/test_customer_onboarding_acceptance.py is local HTTP). Needs released browser + Worker "
     "evidence on the public origin."),
    ("onboarding_target", "ownership_proof_and_authorization_unrecorded",
     "Target registration issues a challenge only; product-recorded ownership proof and the "
     "customer authorization/provenance statement are required "
     "(docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:82,615-624)."),
    ("discovery_plan", "blocked_on_c2_c3",
     "No route discovery or plan approval on the default path "
     "(docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:85,674-675)."),
    ("managed_scan", "blocked_on_c4",
     "No managed executor; serve is an execution-unavailable bridge "
     "(docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:86,676)."),
    ("findings_evidence", "blocked_on_c6",
     "No default-path findings/evidence view (docs/CAPABILITIES.md:11-16; "
     "docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:88,678)."),
    ("regression", "blocked_on_c6",
     "No default-path regression replay "
     "(docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:608-611,678)."),
    ("delete_and_revoke", "blocked_on_c5_decision_and_c6",
     "Credential/evidence delete is absent and revoke is component-only; the credential-custody "
     "decision and C5/C6 come first "
     "(docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md:89,634-639,677-678)."),
)

_EXTERNAL_BLOCKERS = (
    ("Release/deployment owner",
     "Provision the canonical origin, Worker, VPC service and Tunnel; record the release identity "
     "and immutable revision; rerun this preflight against that origin."),
    ("Release/deployment owner",
     "Provide deployed Heel identity/readiness evidence bound to that release; GET / cannot prove it."),
    ("Operations owner",
     "Verified pre-run backup, restore drill and rollback point per docs/saas/RUNBOOKS.md; "
     "name the kill-switch owner and record a no-mutation readiness check."),
    ("C2/C3/C4 integration",
     "Deployed Layer 1 synthetic known-positive discovery and managed scan with real target logs."),
    ("Credential-custody decision owner and C5",
     "Record the credential-custody decision, then C5 privacy and managed-login gates before any "
     "credentialed live step."),
    ("C6 owner", "Deployed Layer 1 patch/replay and Layer 2 evidence-view test."),
    ("Customer/target owner",
     "Product-recorded ownership proof plus the customer authorization and provenance statement."),
)


class ProbeFailure(Exception):
    def __init__(self, reason_code: str, evidence: str):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.evidence = evidence


@dataclass(frozen=True)
class ProbeSeams:
    """Network seams; any injected seam makes the report ``local-synthetic-test`` evidence."""
    resolver: Callable[..., Any] | None = None
    sockets: Any = None
    tls: Any = None
    clock: Callable[[], float] = time.monotonic

    @property
    def synthetic(self) -> bool:
        return any(seam is not None for seam in (self.resolver, self.sockets, self.tls))


def canonical_public_origin(value: object) -> str | None:
    """The exact ``https://host`` spelling the verifier accepts, minus reserved and reference hosts."""
    if not isinstance(value, str):
        return None
    try:
        normalized = normalize_verified_origin(value)
    except OriginValidationError:
        return None
    host = normalized[len("https://"):]
    if (normalized != value or normalized in _REFERENCE_ORIGINS
            or any(host == name or host.endswith("." + name) for name in _RESERVED_DOMAINS)):
        return None
    return normalized


def classify(stages: list[dict], evidence_class: str) -> str:
    states = [stage["state"] for stage in stages]
    if "failed" in states:
        return "FAIL"
    if evidence_class != "deployed-preflight" or any(state != "proven" for state in states):
        return "BLOCKED"
    return "READY_FOR_LIVE_ACCEPTANCE"


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise ProbeFailure("transport_timeout", "The bounded probe deadline expired.")
    return remaining


def _read_status(connection: Any, deadline: float, clock: Callable[[], float]) -> int:
    # Receives stop at the header terminator, but TLS/TCP has no header/body boundary, so a
    # receive can also return a body prefix; that prefix is never parsed and is dropped on return.
    response = bytearray()
    while response.find(b"\r\n\r\n") < 0:
        if len(response) > MAX_CHALLENGE_HEADER_BYTES:
            raise ProbeFailure("malformed_response", "Response headers exceed the bound.")
        connection.settimeout(_remaining(deadline, clock))
        chunk = connection.recv(min(4096, MAX_CHALLENGE_HEADER_BYTES + 4 - len(response)))
        if not chunk:
            raise ProbeFailure("malformed_response", "Response headers are incomplete.")
        response.extend(chunk)
    status_line = bytes(response[:response.find(b"\r\n")]).decode("latin-1")
    match = _STATUS_LINE.fullmatch(status_line)
    if match is None:
        raise ProbeFailure("malformed_response", "Response is not an HTTP/1.x status line.")
    return int(match.group(1))


def probe_public_https(origin: str, seams: ProbeSeams) -> tuple[int, str]:
    """One pinned, verified ``GET /``; returns the 2xx status and negotiated TLS version."""
    host = origin[len("https://"):]
    clock = seams.clock
    deadline = clock() + PROBE_TIMEOUT_SECONDS
    raw_socket = tls_socket = None
    try:
        try:
            resolver = seams.resolver or BoundedDNSResolver()
            answer = resolver(host, timeout_seconds=_remaining(deadline, clock))
        except DNSResolutionTimeout:
            raise ProbeFailure("transport_timeout", "DNS resolution timed out.") from None
        except AddressSetValidationError as error:
            if str(error).startswith("unsafe DNS answer"):
                raise ProbeFailure("non_public_address", "DNS answer includes a non-public address.") from None
            raise ProbeFailure("dns_resolution_failed", "DNS resolution failed.") from None
        except RuntimeError:
            # BoundedDNSResolver without its pinned dnspython dependency.
            raise ProbeFailure("dns_resolution_failed", "The bounded DNS resolver is unavailable.") from None
        try:
            selected = select_safe_addresses(answer)[0]
        except AddressSetValidationError as error:
            if str(error).startswith("unsafe DNS answer"):
                raise ProbeFailure("non_public_address", "DNS answer includes a non-public address.") from None
            raise ProbeFailure("dns_resolution_failed", "DNS answer is empty or unusable.") from None
        transport = seams.sockets or SocketTransport()
        raw_socket = transport.connect((selected.compressed, HTTPS_PORT), _remaining(deadline, clock))
        transport.configure(raw_socket, _remaining(deadline, clock))
        tls_socket = (seams.tls or TLSTransport()).wrap(raw_socket, host, _remaining(deadline, clock))
        raw_socket = None
        if ipaddress.ip_address(tls_socket.getpeername()[0]) != selected:
            raise ProbeFailure("peer_mismatch", "Connected peer differs from the selected DNS address.")
        request = (f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\n"
                   "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
        tls_socket.settimeout(_remaining(deadline, clock))
        tls_socket.sendall(request)
        status = _read_status(tls_socket, deadline, clock)
        version = tls_socket.version() or "unknown"
    except ProbeFailure:
        raise
    except ssl.SSLCertVerificationError:
        raise ProbeFailure("tls_verification_failed", "Certificate or hostname verification failed.") from None
    except ssl.SSLError:
        raise ProbeFailure("tls_failed", "TLS handshake or record failure.") from None
    except (socket.timeout, TimeoutError):
        raise ProbeFailure("transport_timeout", "The bounded probe deadline expired.") from None
    except OSError:
        raise ProbeFailure("transport_failed", "Connection to the public address failed.") from None
    finally:
        for closable in (tls_socket, raw_socket):
            if closable is not None:
                try:
                    closable.close()
                except OSError:
                    pass
    if 300 <= status < 400:
        raise ProbeFailure("redirect_refused", f"GET / answered HTTP {status}; redirects are not followed.")
    if not 200 <= status < 300:
        raise ProbeFailure("non_2xx_status", f"GET / answered HTTP {status}.")
    return status, version


def _stage(stage_id: str, state: str, reason_code: str, evidence: str) -> dict:
    return {"id": stage_id, "state": state, "reason_code": reason_code, "evidence": evidence}


def run_preflight(public_origin: str, *, seams: ProbeSeams | None = None) -> dict:
    seams = seams or ProbeSeams()
    evidence_class = "local-synthetic-test" if seams.synthetic else "deployed-preflight"
    origin = canonical_public_origin(public_origin)
    if origin is None:
        first = _stage("public_https", "failed", "origin_rejected",
                       "Not one canonical public https://host origin, or a reserved, local or "
                       "reference host; no network request was made.")
    else:
        try:
            status, version = probe_public_https(origin, seams)
        except ProbeFailure as failure:
            first = _stage("public_https", "failed", failure.reason_code, failure.evidence)
        else:
            first = _stage(
                "public_https", "blocked", "heel_identity_unproven",
                f"GET / answered HTTP {status} over verified {version} from a pinned public address. "
                "This shows reachability only: no public route binds Heel identity, release revision "
                "or readiness (the Worker exposes no health route, apps/heel-cloud/worker/index.ts; "
                "the readiness probe is private, docs/saas/OPERATIONS.md).",
            )
    stages = [first, *(_stage(stage_id, "blocked", reason, evidence)
                       for stage_id, reason, evidence in _LATER_STAGES)]
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": classify(stages, evidence_class),
        "public_origin": origin,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_class": evidence_class,
        "stages": stages,
        "external_blockers": [{"owner": owner, "next_test": next_test}
                              for owner, next_test in _EXTERNAL_BLOCKERS],
    }


def _output_directory(value: str) -> Path | None:
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        return None
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        return None
    return None if path.is_symlink() or not path.is_dir() else path


def _write_report(directory: Path, report: dict) -> Path:
    destination = directory / REPORT_NAME
    descriptor, temporary = tempfile.mkstemp(prefix=".preflight-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=False)
            handle.write("\n")
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return destination


def main(argv: list[str] | None = None, *, seams: ProbeSeams | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed deployed customer-acceptance preflight (never acceptance by itself): "
                    "one unauthenticated, bounded, header-oriented GET / of the Heel public origin.",
        epilog="A bounded body prefix coalesced with the headers may be received into a transient "
               "buffer; it is not parsed, persisted, reported or logged. Operator command: run from "
               "a Heel source checkout with Python 3.11+ and the pinned dnspython==2.8.0 wheel "
               "(see docs/saas/CUSTOMER_ACCEPTANCE_READINESS.md); not part of the public runner "
               "install and not a no-checkout customer command.",
        allow_abbrev=False,
    )
    parser.add_argument("--public-origin", required=True, help="canonical https://HOST origin")
    parser.add_argument("--output", required=True, help="directory for the redacted JSON report")
    args = parser.parse_args(argv)
    directory = _output_directory(args.output)
    if directory is None:
        print("output must be a real directory (not a symlink or file)", file=sys.stderr)
        return EXIT_INVALID_OUTPUT
    report = run_preflight(args.public_origin, seams=seams)
    path = _write_report(directory, report)
    print(json.dumps({"classification": report["classification"],
                      "evidence_class": report["evidence_class"], "report": str(path)}))
    if report["public_origin"] is None:
        return EXIT_INVALID_ORIGIN
    return {"READY_FOR_LIVE_ACCEPTANCE": EXIT_READY, "BLOCKED": EXIT_BLOCKED}.get(
        report["classification"], EXIT_FAIL)


if __name__ == "__main__":
    raise SystemExit(main())
