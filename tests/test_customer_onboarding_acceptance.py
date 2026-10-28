"""Local HTTP onboarding acceptance through the real production control-plane process.

Evidence class: LOCAL HTTP INTEGRATION. Never deployed or customer-acceptance evidence.

The driver starts the unmodified production entrypoint ``python -m heel.saas.server`` with a
synthetic configuration over a temporary SQLite volume, stops it with SIGTERM and starts it again
on the same volume. The customer side is plain ``http.client`` against public routes only: no
repository import, database edit, seed or admin call. Synthetic account values only; no password,
cookie or challenge token is printed or asserted into a message.

Controlled seams standing in for the deployed path:

- EDGE: the client sends ``X-Heel-Edge-Auth``, ``X-Heel-Client-Key`` and the same-origin ceremony
  headers that the public Worker (``apps/heel-cloud/worker/index.ts``) would add; there is no
  Worker, browser, TLS or public DNS.
- TRANSPORT: plain HTTP to a loopback port instead of the VPC/Tunnel private service.
- ORIGIN: ``HEEL_PUBLIC_ORIGIN`` is the synthetic ``https://heel.example``.
- TARGET: ``https://staging.example.com`` is an RFC 2606 reserved name that is registered but
  never contacted. Ownership proof is not placed and ``check`` is not called.

Proven here (local only): signup, session, logout, login, project creation, target registration
(challenge issued, unverified, not executable) and their persistence across a process restart,
plus tenant isolation. Blocked, not attempted: ownership verification (no controlled target),
discovery/plan (C2/C3), managed scan (C4), findings/evidence and regression (C6), credential/
evidence delete and target revoke on the default path (C5 decision, C6).
"""
from __future__ import annotations

import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ORIGIN = "https://heel.example"
TARGET_ORIGIN = "https://staging.example.com"
EMAIL = "onboarding-acceptance@example.com"
PASSWORD = "synthetic-" + secrets.token_hex(12)
OWNERSHIP_ATTESTATION = "ownership verified; environment classification supplied by you"


def _secret_b64(size: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def _synthetic_environment(database: Path, port: int) -> dict[str, str]:
    """Driver infrastructure: one-off synthetic production configuration."""
    from heel.crypto import SigningAuthority

    signing = SigningAuthority.generate()
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "HEEL_DATABASE_PATH": str(database),
        "HEEL_PUBLIC_ORIGIN": PUBLIC_ORIGIN,
        "HEEL_DEVICE_TOKEN_PEPPER_B64": _secret_b64(),
        "HEEL_RUNNER_AUTH_PEPPER_B64": _secret_b64(),
        "HEEL_API_KEY_PEPPER": _secret_b64(),
        "HEEL_EDGE_AUTH_SECRET_B64": _secret_b64(),
        "HEEL_CONTROL_PLANE_HOST": "127.0.0.1",
        "HEEL_CONTROL_PLANE_PORT": str(port),
        "HEEL_BILLING_MODE": "free_launch",
        "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64": signing.canonical_private_key,
        "HEEL_GRANT_SIGNING_KEY_ID": signing.key_id,
        "HEEL_GRANT_TRUSTED_PUBLIC_KEYS": json.dumps(
            {signing.key_id: signing.canonical_public_key}, separators=(",", ":"),
        ),
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ControlPlaneProcess:
    """Driver: the real ``heel.saas.server`` process; the only thing allowed to know the repo."""

    def __init__(self, environment: dict[str, str], log_path: Path):
        self.environment = environment
        self.port = int(environment["HEEL_CONTROL_PLANE_PORT"])
        self.log_path = log_path
        self.process = None

    def start(self) -> None:
        log = self.log_path.open("ab")
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-m", "heel.saas.server"], cwd=ROOT, env=self.environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            )
        finally:
            log.close()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"control plane exited during startup: {self.process.returncode}")
            try:
                status, body, _ = request(self.port, "GET", "/v1/readyz")
            except OSError:
                time.sleep(0.1)
                continue
            if status == 200 and body.get("ready") is True:
                return
            time.sleep(0.1)
        raise AssertionError("control plane did not become ready")

    def stop(self) -> int:
        if self.process is None or self.process.poll() is not None:
            return self.process.returncode if self.process else 0
        self.process.send_signal(signal.SIGTERM)
        try:
            return self.process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
            raise


def request(port, method, path, body=None, headers=None):
    """Customer client: one public route over plain HTTP; returns status, JSON body, cookie."""
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers.update({"Content-Type": "application/json", "Content-Length": str(len(payload))})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, payload, request_headers)
        response = connection.getresponse()
        raw = response.read()
        cookie = response.getheader("Set-Cookie")
        return response.status, (json.loads(raw) if raw else {}), cookie
    finally:
        connection.close()


class CustomerOnboardingAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        volume = Path(temporary.name).resolve(strict=True)
        self.log_path = volume / "control-plane.log"
        self.environment = _synthetic_environment(volume / "control-plane.sqlite3", _free_port())
        self.edge = {"X-Heel-Edge-Auth": self.environment["HEEL_EDGE_AUTH_SECRET_B64"]}
        self.server = ControlPlaneProcess(self.environment, self.log_path)
        self.addCleanup(self.server.stop)
        self.server.start()

    def call(self, method, path, body=None, cookie=None, ceremony=False, extra=None):
        headers = dict(self.edge)
        if cookie is not None:
            headers["Cookie"] = cookie
        if ceremony:
            headers.update({"Origin": PUBLIC_ORIGIN, "X-Heel-Internal-Origin": "same-origin"})
        headers.update(extra or {})
        return request(self.server.port, method, path, body, headers)

    def session(self, set_cookie):
        self.assertIsNotNone(set_cookie)
        attributes = [part.strip() for part in set_cookie.split(";")]
        self.assertTrue(attributes[0].startswith("heel_session="))
        self.assertIn("HttpOnly", attributes)
        self.assertIn("SameSite=Lax", attributes)
        return attributes[0]

    def test_customer_signs_up_creates_a_project_and_registers_a_target_that_survives_restart(self):
        port = self.server.port
        self.assertEqual(request(port, "POST", "/v1/signup", {"email": EMAIL, "password": PASSWORD})[0], 401)

        status, account, set_cookie = self.call(
            "POST", "/v1/signup", {"email": EMAIL, "password": PASSWORD},
            extra={"X-Heel-Client-Key": secrets.token_hex(32)},
        )
        self.assertEqual(status, 201)
        self.assertEqual(set(account), {"user_id", "workspace_id"})
        workspace, user = account["workspace_id"], account["user_id"]
        cookie = self.session(set_cookie)
        sessions = [cookie]

        status, me, _ = self.call("GET", "/v1/me", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(me["workspaces"], [{"workspace_id": workspace, "role": "owner"}])
        status, summary, _ = self.call("GET", f"/v1/workspaces/{workspace}/summary", cookie=cookie)
        self.assertEqual((status, summary["plan"]), (200, "free"))

        projects_path = f"/v1/workspaces/{workspace}/projects"
        self.assertEqual(self.call("POST", projects_path, {"name": "Onboarding API"})[0], 401)
        status, project, _ = self.call("POST", projects_path, {"name": "Onboarding API"}, cookie=cookie)
        self.assertEqual(status, 201)
        project_ref = project["project_ref"]
        self.assertEqual((project["workspace_id"], project["name"]), (workspace, "Onboarding API"))

        environments_path = f"{projects_path}/{project_ref}/environments"
        start = {
            "schema_version": "heel.verified-environment-start.v1", "origin": TARGET_ORIGIN,
            "environment_class": "staging", "proof_method": "https-file",
            "attestation_text": OWNERSHIP_ATTESTATION, "attestation_version": "v1",
            "attestation_acknowledgement": "accepted",
        }
        status, refused, _ = self.call("POST", environments_path, start, cookie=cookie)
        self.assertEqual((status, refused["code"]), (403, "same_origin_required"))
        status, challenge, _ = self.call("POST", environments_path, start, cookie=cookie, ceremony=True)
        self.assertEqual(status, 201)
        self.assertEqual(challenge["schema_version"], "heel.verified-environment-challenge.v1")
        self.assertEqual((challenge["origin"], challenge["environment_class"], challenge["proof_method"]),
                         (TARGET_ORIGIN, "staging", "https-file"))
        self.assertTrue(challenge["http_url"].startswith(TARGET_ORIGIN + "/"))
        environment_id = challenge["environment_id"]
        challenge_token = challenge["token"]

        registered = self.assert_registered_unverified(cookie, environments_path, environment_id)

        status, _, cleared = self.call("POST", "/v1/logout", {}, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", cleared)
        self.assertEqual(self.call("GET", "/v1/me", cookie=cookie)[0], 401)

        self.assertEqual(self.server.stop(), 0)
        self.server.start()

        status, refused, set_cookie = self.call("POST", "/v1/login", {"email": EMAIL, "password": "wrong-" + PASSWORD})
        self.assertEqual((status, refused, set_cookie), (403, {"error": "invalid email or password"}, None))
        status, login, set_cookie = self.call("POST", "/v1/login", {"email": EMAIL, "password": PASSWORD})
        self.assertEqual((status, login), (200, {"user_id": user}))
        cookie = self.session(set_cookie)
        sessions.append(cookie)
        status, me, _ = self.call("GET", "/v1/me", cookie=cookie)
        self.assertEqual(me["workspaces"], [{"workspace_id": workspace, "role": "owner"}])
        status, listed, _ = self.call("GET", projects_path, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual([item["project_ref"] for item in listed["projects"]], [project_ref])
        self.assertEqual(self.assert_registered_unverified(cookie, environments_path, environment_id), registered)

        status, other, other_cookie = self.call(
            "POST", "/v1/signup", {"email": "other-tenant@example.com", "password": PASSWORD},
            extra={"X-Heel-Client-Key": secrets.token_hex(32)},
        )
        self.assertEqual(status, 201)
        other_cookie = self.session(other_cookie)
        sessions.append(other_cookie)
        self.assertNotEqual(other["workspace_id"], workspace)
        self.assertIn(self.call("GET", projects_path, cookie=other_cookie)[0], {403, 404})
        self.assertIn(self.call("GET", environments_path, cookie=other_cookie)[0], {403, 404})

        self.assertEqual(self.server.stop(), 0)
        log = self.log_path.read_bytes()
        for secret in (PASSWORD, challenge_token, self.environment["HEEL_EDGE_AUTH_SECRET_B64"],
                       *(session.split("=", 1)[1] for session in sessions)):
            self.assertNotIn(secret.encode(), log)

    def assert_registered_unverified(self, cookie, environments_path, environment_id):
        status, listed, _ = self.call("GET", environments_path, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(listed["schema_version"], "heel.verified-environment-list.v1")
        [record] = listed["environments"]
        self.assertEqual((record["environment_id"], record["origin"]), (environment_id, TARGET_ORIGIN))
        self.assertNotEqual(record["status"], "verified")
        self.assertIsNone(record["verified_at"])
        self.assertIsNone(record["verification_record_digest"])
        self.assertIs(record["is_executable"], False)
        self.assertNotIn("token", record)
        return {key: record[key] for key in ("environment_id", "origin", "environment_class", "status",
                                             "proof_method", "challenge_generation")}


if __name__ == "__main__":
    unittest.main()
