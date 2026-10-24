"""Fail-closed customer-acceptance preflight: closed report, origin policy and probe outcomes.

Every probe here runs through LOCAL/SYNTHETIC fakes injected at the ``heel.saas.network_guard``
seams (resolver, sockets, TLS). No test opens a network connection, and every report they
produce is ``local-synthetic-test`` evidence, never acceptance evidence.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/customer_acceptance_preflight.py"
STAGE_IDS = [
    "public_https", "browser_auth", "onboarding_target", "discovery_plan",
    "managed_scan", "findings_evidence", "regression", "delete_and_revoke",
]
ORIGIN = "https://acceptance-customer.com"
PUBLIC_IP = "93.184.215.14"


def _load_preflight():
    spec = importlib.util.spec_from_file_location("customer_acceptance_preflight", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


preflight = _load_preflight()


class SyntheticResolver:
    """LOCAL/SYNTHETIC DNS answer; records every lookup."""

    def __init__(self, answers=(PUBLIC_IP,), error=None):
        self.answers = list(answers)
        self.error = error
        self.calls = []

    def __call__(self, hostname, *, timeout_seconds):
        self.calls.append((hostname, timeout_seconds))
        if self.error is not None:
            raise self.error
        return list(self.answers)


class SyntheticSocket:
    """LOCAL/SYNTHETIC connected socket: replays canned response bytes."""

    def __init__(self, peer, response, version="TLSv1.3"):
        self.peer = peer
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False
        self._version = version

    def settimeout(self, _timeout):
        return None

    def getpeername(self):
        return (self.peer, 443)

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        chunk = bytes(self.response[:size])
        del self.response[:size]
        return chunk

    def version(self):
        return self._version

    def close(self):
        self.closed = True


class SyntheticSockets:
    """LOCAL/SYNTHETIC replacement for ``network_guard.SocketTransport``."""

    def __init__(self, response=b"", peer=None, error=None):
        self.response = response
        self.peer = peer
        self.error = error
        self.connects = []
        self.socket = None

    def connect(self, address, timeout):
        self.connects.append(address)
        if self.error is not None:
            raise self.error
        self.socket = SyntheticSocket(self.peer or address[0], self.response)
        return self.socket

    def configure(self, connected_socket, timeout):
        connected_socket.settimeout(timeout)


class SyntheticTLS:
    """LOCAL/SYNTHETIC replacement for ``network_guard.TLSTransport``."""

    def __init__(self, error=None):
        self.error = error
        self.server_names = []

    def wrap(self, connected_socket, hostname, timeout):
        self.server_names.append(hostname)
        if self.error is not None:
            raise self.error
        return connected_socket


def http_response(status_line, headers=(), body=b""):
    lines = [status_line, *headers, f"Content-Length: {len(body)}", "", ""]
    return "\r\n".join(lines).encode("latin-1") + body


def synthetic_network(response=None, **overrides):
    response = http_response("HTTP/1.1 200 OK", ["Content-Type: text/html"], b"<h1>Heel</h1>") \
        if response is None else response
    return preflight.ProbeSeams(
        resolver=overrides.get("resolver", SyntheticResolver()),
        sockets=overrides.get("sockets", SyntheticSockets(response)),
        tls=overrides.get("tls", SyntheticTLS()),
        clock=overrides.get("clock", lambda: 0.0),
    )


class ReportShapeTests(unittest.TestCase):
    def test_reachable_200_is_blocked_local_synthetic_evidence_with_every_stage_in_order(self):
        seams = synthetic_network()
        report = preflight.run_preflight(ORIGIN, seams=seams)

        self.assertEqual(set(report), {
            "schema_version", "classification", "public_origin", "observed_at",
            "evidence_class", "stages", "external_blockers",
        })
        self.assertEqual(report["schema_version"], "heel.customer-acceptance-preflight.v1")
        self.assertEqual(report["classification"], "BLOCKED")
        self.assertEqual(report["evidence_class"], "local-synthetic-test")
        self.assertEqual(report["public_origin"], ORIGIN)
        self.assertRegex(report["observed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual([stage["id"] for stage in report["stages"]], STAGE_IDS)
        for stage in report["stages"]:
            self.assertEqual(set(stage), {"id", "state", "reason_code", "evidence"})
            self.assertEqual(stage["state"], "blocked", stage["id"])
            self.assertRegex(stage["reason_code"], r"^[a-z0-9_]+$")
            self.assertTrue(stage["evidence"])
        self.assertTrue(report["external_blockers"])
        for blocker in report["external_blockers"]:
            self.assertEqual(set(blocker), {"owner", "next_test"})
            self.assertTrue(blocker["owner"] and blocker["next_test"])

    def test_an_arbitrary_200_page_never_proves_heel_identity_or_readiness(self):
        imitation = http_response(
            "HTTP/1.1 200 OK",
            ["Content-Type: application/json", "X-Heel-Release: 1.3.0rc2", "Server: heel"],
            b'{"ready":true,"schema_version":31,"catalog_version":"heel"}',
        )
        report = preflight.run_preflight(ORIGIN, seams=synthetic_network(imitation))

        public = report["stages"][0]
        self.assertEqual((public["state"], public["reason_code"]), ("blocked", "heel_identity_unproven"))
        self.assertIn("200", public["evidence"])
        self.assertNotEqual(report["classification"], "READY_FOR_LIVE_ACCEPTANCE")
        self.assertNotIn("proven", {stage["state"] for stage in report["stages"]})

    def test_later_stages_name_their_dependency(self):
        report = preflight.run_preflight(ORIGIN, seams=synthetic_network())
        reasons = {stage["id"]: stage["reason_code"] for stage in report["stages"]}
        self.assertEqual(reasons["browser_auth"], "deployed_browser_session_unproven")
        self.assertEqual(reasons["onboarding_target"], "ownership_proof_and_authorization_unrecorded")
        self.assertEqual(reasons["discovery_plan"], "blocked_on_c2_c3")
        self.assertEqual(reasons["managed_scan"], "blocked_on_c4")
        self.assertEqual(reasons["findings_evidence"], "blocked_on_c6")
        self.assertEqual(reasons["regression"], "blocked_on_c6")
        self.assertEqual(reasons["delete_and_revoke"], "blocked_on_c5_decision_and_c6")

    def test_classification_is_never_ready_for_local_synthetic_or_any_blocked_stage(self):
        proven = [{"id": stage, "state": "proven"} for stage in STAGE_IDS]
        self.assertEqual(preflight.classify(proven, "local-synthetic-test"), "BLOCKED")
        self.assertEqual(preflight.classify(proven, "deployed-preflight"), "READY_FOR_LIVE_ACCEPTANCE")
        blocked = [dict(proven[0], state="blocked"), *proven[1:]]
        self.assertEqual(preflight.classify(blocked, "deployed-preflight"), "BLOCKED")
        failed = [*blocked[:-1], dict(proven[-1], state="failed")]
        self.assertEqual(preflight.classify(failed, "deployed-preflight"), "FAIL")


class ProbeTests(unittest.TestCase):
    def test_probe_is_one_unauthenticated_get_of_slash_to_the_pinned_public_address(self):
        seams = synthetic_network()
        preflight.run_preflight(ORIGIN, seams=seams)

        self.assertEqual(seams.resolver.calls[0][0], "acceptance-customer.com")
        self.assertEqual(seams.sockets.connects, [(PUBLIC_IP, 443)])
        self.assertEqual(seams.tls.server_names, ["acceptance-customer.com"])
        request = bytes(seams.sockets.socket.sent).decode("ascii")
        self.assertEqual(request.count("\r\n\r\n"), 1)
        self.assertTrue(request.endswith("\r\n\r\n"))
        lines = request.split("\r\n")
        self.assertEqual(lines[0], "GET / HTTP/1.1")
        self.assertIn("Host: acceptance-customer.com", lines)
        lowered = request.lower()
        for forbidden in ("cookie", "authorization", "x-heel-", "password", "token"):
            self.assertNotIn(forbidden, lowered)
        self.assertTrue(seams.sockets.socket.closed)

    def test_report_records_response_metadata_but_never_body_or_location(self):
        body = b"<p>SYNTHETIC-BODY-MARKER</p>"
        report = preflight.run_preflight(ORIGIN, seams=synthetic_network(
            http_response("HTTP/1.1 200 OK", ["Set-Cookie: s=SYNTHETIC-COOKIE"], body),
        ))
        serialized = json.dumps(report)
        self.assertNotIn("SYNTHETIC-BODY-MARKER", serialized)
        self.assertNotIn("SYNTHETIC-COOKIE", serialized)

        for status in ("301 Moved Permanently", "302 Found", "307 Temporary Redirect", "308 Permanent Redirect"):
            report = preflight.run_preflight(ORIGIN, seams=synthetic_network(http_response(
                f"HTTP/1.1 {status}", ["Location: https://elsewhere-redirect.com/SYNTHETIC-LOCATION"],
            )))
            self.assertEqual(report["classification"], "FAIL", status)
            self.assertEqual(report["stages"][0]["reason_code"], "redirect_refused")
            self.assertNotIn("SYNTHETIC-LOCATION", json.dumps(report))
            self.assertNotIn("elsewhere-redirect", json.dumps(report))

    def test_non_2xx_responses_fail(self):
        for status in ("404 Not Found", "500 Internal Server Error", "503 Service Unavailable", "101 Switching Protocols"):
            report = preflight.run_preflight(ORIGIN, seams=synthetic_network(
                http_response(f"HTTP/1.1 {status}"),
            ))
            self.assertEqual(report["classification"], "FAIL", status)
            self.assertEqual(report["stages"][0]["state"], "failed")
            self.assertEqual(report["stages"][0]["reason_code"], "non_2xx_status", status)
            self.assertEqual([stage["state"] for stage in report["stages"][1:]], ["blocked"] * 7)

    def test_local_or_special_dns_answers_fail_before_any_connection(self):
        for answers in (["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["::1"], ["fd00::1"],
                        [PUBLIC_IP, "192.168.1.10"], ["100.64.0.1"]):
            sockets = SyntheticSockets(http_response("HTTP/1.1 200 OK"))
            report = preflight.run_preflight(ORIGIN, seams=synthetic_network(
                resolver=SyntheticResolver(answers), sockets=sockets,
            ))
            self.assertEqual(report["classification"], "FAIL", answers)
            self.assertEqual(report["stages"][0]["reason_code"], "non_public_address", answers)
            self.assertEqual(sockets.connects, [], answers)

    def test_transport_failures_fail_closed_with_a_reason(self):
        from heel.saas.network_guard import AddressSetValidationError, DNSResolutionTimeout

        cases = [
            ("dns_resolution_failed", dict(resolver=SyntheticResolver(error=AddressSetValidationError("DNS resolution failed")))),
            ("dns_resolution_failed", dict(resolver=SyntheticResolver(answers=[]))),
            ("dns_resolution_failed", dict(resolver=SyntheticResolver(error=RuntimeError("dnspython missing")))),
            ("transport_timeout", dict(resolver=SyntheticResolver(error=DNSResolutionTimeout("slow")))),
            ("transport_failed", dict(sockets=SyntheticSockets(error=ConnectionRefusedError()))),
            ("transport_timeout", dict(sockets=SyntheticSockets(error=TimeoutError()))),
            ("tls_verification_failed", dict(tls=SyntheticTLS(error=ssl.SSLCertVerificationError("bad certificate")))),
            ("tls_failed", dict(tls=SyntheticTLS(error=ssl.SSLError("handshake failure")))),
            ("peer_mismatch", dict(sockets=SyntheticSockets(http_response("HTTP/1.1 200 OK"), peer="93.184.215.99"))),
            ("malformed_response", dict(sockets=SyntheticSockets(b"HTTP/1.1 200 OK\r\n"))),
            ("malformed_response", dict(sockets=SyntheticSockets(b"SSH-2.0-OpenSSH\r\n\r\n"))),
            ("malformed_response", dict(sockets=SyntheticSockets(b"HTTP/2 200\r\n\r\n"))),
            ("malformed_response", dict(sockets=SyntheticSockets(b"HTTP/1.1 200 OK\r\nX: " + b"a" * 20000))),
        ]
        for reason, overrides in cases:
            report = preflight.run_preflight(ORIGIN, seams=synthetic_network(**overrides))
            self.assertEqual(report["classification"], "FAIL", reason)
            self.assertEqual(report["stages"][0]["state"], "failed", reason)
            self.assertEqual(report["stages"][0]["reason_code"], reason, overrides)

    def test_the_whole_probe_shares_one_bounded_deadline(self):
        ticks = itertools.chain([0.0, 0.0], itertools.repeat(6.0))
        report = preflight.run_preflight(ORIGIN, seams=synthetic_network(clock=lambda: next(ticks)))
        self.assertEqual(report["stages"][0]["reason_code"], "transport_timeout")
        self.assertLessEqual(preflight.PROBE_TIMEOUT_SECONDS, 10)


class OriginPolicyTests(unittest.TestCase):
    REJECTED = [
        "", "heel.com", "http://acceptance-customer.com", "HTTPS://acceptance-customer.com",
        "https://Acceptance-Customer.com", "https://acceptance-customer.com/",
        "https://acceptance-customer.com/app", "https://acceptance-customer.com?x=1",
        "https://acceptance-customer.com#top", "https://user:pass@acceptance-customer.com",
        "https://acceptance-customer.com:443", "https://acceptance-customer.com:8443",
        "https://acceptance-customer.com.", "https://localhost", "https://heel.localhost",
        "https://127.0.0.1", "https://[::1]", "https://10.0.0.1", "https://2130706433",
        "https://heel", "https://heel.example", "https://not-deployed.example", "https://heel.test",
        "https://app.local", "https://app.internal", "https://app.invalid", "https://example.com",
        "https://www.example.org", "https://staging.example.net", "https://heel.notarealtld",
        "https://xn--hel-ula.com", "https://heel-agent-first-private.hellostella.chatgpt.site",
        " https://acceptance-customer.com", "https://acceptance customer.com",
    ]

    def test_rejected_origins_fail_without_any_network_activity(self):
        for origin in self.REJECTED:
            seams = synthetic_network()
            report = preflight.run_preflight(origin, seams=seams)
            self.assertEqual(report["classification"], "FAIL", origin)
            self.assertIsNone(report["public_origin"], origin)
            self.assertEqual(report["stages"][0]["reason_code"], "origin_rejected", origin)
            self.assertEqual(seams.resolver.calls, [], origin)
            self.assertEqual(seams.sockets.connects, [], origin)
            if origin:
                self.assertNotIn(origin.strip(), json.dumps(report), origin)

    def test_accepted_origins_are_the_canonical_shared_policy(self):
        from heel.saas.network_guard import normalize_verified_origin

        for origin in (ORIGIN, "https://app.heel-security.io", "https://heel.dev"):
            self.assertEqual(preflight.canonical_public_origin(origin), origin)
            self.assertEqual(normalize_verified_origin(origin), origin)


class CommandLineTests(unittest.TestCase):
    def test_cli_writes_one_report_and_exit_code_tracks_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve(strict=True) / "evidence"
            code = preflight.main(
                ["--public-origin", ORIGIN, "--output", str(output)], seams=synthetic_network(),
            )
            self.assertEqual(code, preflight.EXIT_BLOCKED)
            self.assertEqual(sorted(os.listdir(output)), ["customer-acceptance-preflight.json"])
            report = json.loads((output / "customer-acceptance-preflight.json").read_text(encoding="utf-8"))
            self.assertEqual((report["classification"], report["evidence_class"]),
                             ("BLOCKED", "local-synthetic-test"))

            code = preflight.main(
                ["--public-origin", "https://heel.example", "--output", str(output)],
                seams=synthetic_network(),
            )
            self.assertEqual(code, preflight.EXIT_INVALID_ORIGIN)
            report = json.loads((output / "customer-acceptance-preflight.json").read_text(encoding="utf-8"))
            self.assertEqual(report["classification"], "FAIL")

            code = preflight.main(
                ["--public-origin", ORIGIN, "--output", str(output)],
                seams=synthetic_network(http_response("HTTP/1.1 404 Not Found")),
            )
            self.assertEqual(code, preflight.EXIT_FAIL)
        self.assertEqual(len({preflight.EXIT_BLOCKED, preflight.EXIT_FAIL, preflight.EXIT_INVALID_ORIGIN, 0}), 4)

    def test_cli_accepts_no_credential_target_or_extra_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve(strict=True) / "evidence"
            base = ["--public-origin", ORIGIN, "--output", str(output)]
            for extra in (["--password", "x"], ["--token", "x"], ["--target-url", ORIGIN],
                          ["--credential", "x"], ["--attestation", "x"], ["positional"]):
                with self.assertRaises(SystemExit) as raised:
                    preflight.main(base + extra, seams=synthetic_network())
                self.assertEqual(raised.exception.code, 2, extra)
            for missing in (["--output", str(output)], ["--public-origin", ORIGIN],
                            ["--public", ORIGIN, "--output", str(output)]):
                with self.assertRaises(SystemExit) as raised:
                    preflight.main(missing, seams=synthetic_network())
                self.assertEqual(raised.exception.code, 2, missing)
            self.assertFalse(output.exists())

    def test_cli_refuses_a_symlinked_or_non_directory_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real")
            (root / "file").write_text("x", encoding="utf-8")
            for target in (root / "link", root / "file"):
                code = preflight.main(["--public-origin", ORIGIN, "--output", str(target)],
                                      seams=synthetic_network())
                self.assertEqual(code, preflight.EXIT_INVALID_OUTPUT, target)
            self.assertEqual(os.listdir(root / "real"), [])

    def test_source_reads_no_environment_and_names_no_product_action_route(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("os.environ", "getenv", "/v1/", "urllib.request", "http.client", "requests"):
            self.assertNotIn(forbidden, source)


class ReadinessDocumentTests(unittest.TestCase):
    def test_readiness_checklist_requires_every_pre_run_gate_and_redacted_evidence(self):
        text = (ROOT / "docs/saas/CUSTOMER_ACCEPTANCE_READINESS.md").read_text(encoding="utf-8")
        for required in (
            "heel.customer-acceptance-preflight.v1", "scripts/customer_acceptance_preflight.py",
            "release identity", "immutable revision", "verified pre-run backup", "restore drill",
            "rollback point", "kill-switch owner", "customer authorization", "provenance statement",
            "findings.none", "redacted", "docs/saas/OPERATIONS.md", "docs/saas/RUNBOOKS.md",
            "tests/test_customer_onboarding_acceptance.py",
        ):
            self.assertTrue(required.lower() in text.lower(), required)
        for stage in STAGE_IDS:
            self.assertIn(f"`{stage}`", text)
        self.assertNotRegex(text, r"heel_(?:at|rt|ses|sk)_[A-Za-z0-9_-]+")
        self.assertNotIn("zonal-acceptance", text)


if __name__ == "__main__":
    unittest.main()
