"""Device authorization and machine-principal security contract."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

from heel.saas.device_auth import (
    ACCESS_TTL,
    DEVICE_GRANT_TTL,
    DeviceAuthStore,
    DeviceDenied,
    DeviceExpired,
    DevicePending,
    DeviceRateLimited,
    RefreshReuseDetected,
    SlowDown,
)
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.http_api import ControlPlane, serve
from heel.saas.tenancy import Role


def _verifier(seed: bytes = b"v" * 32) -> str:
    return "heel_dv_" + base64.urlsafe_b64encode(seed).decode("ascii").rstrip("=")


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")


class DeviceAuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.store = DeviceAuthStore(self.conn, pepper=b"p" * 32)
        self.verifier = _verifier()
        self.challenge = _challenge(self.verifier)

    def tearDown(self):
        self.conn.close()

    def _approved_tokens(self, *, now: float = 1_000.0):
        started = self.store.start("Alice's Mac", self.challenge, now=now)
        claim = self.store.inspect(started.user_code, "usr_1", now=now + 1)
        self.store.decide(
            started.user_code,
            claim.confirmation_nonce,
            "usr_1",
            action="approve",
            workspace_id="ws_1",
            now=now + 2,
        )
        return started, self.store.exchange(started.device_code, self.verifier, now=now + 3)

    def test_start_uses_strict_high_entropy_formats_and_persists_no_secret(self):
        started = self.store.start("Alice's Mac", self.challenge, now=100)

        self.assertRegex(started.device_code, r"heel_dev_[A-Za-z0-9_-]{43}\Z")
        self.assertRegex(started.user_code, r"[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\Z")
        self.assertEqual(started.expires_in, DEVICE_GRANT_TTL)
        self.assertEqual(started.interval, 5)
        rendered = " ".join(
            str(value)
            for row in self.conn.execute("SELECT * FROM device_authorizations")
            for value in row
        )
        self.assertNotIn(started.device_code, rendered)
        self.assertNotIn(started.user_code, rendered)

    def test_poll_requires_verifier_and_throttles_early_polling(self):
        started = self.store.start("CLI", self.challenge, now=100)
        with self.assertRaises(PermissionError):
            self.store.poll(started.device_code, _verifier(b"x" * 32), now=101)
        self.assertEqual(self.store.poll(started.device_code, self.verifier, now=101).status,
                         "pending")
        with self.assertRaises(SlowDown) as caught:
            self.store.poll(started.device_code, self.verifier, now=102)
        self.assertEqual(caught.exception.interval, 10)

    def test_start_rate_limit_caps_one_client_and_repeated_challenge(self):
        client_key = "1" * 64
        for index in range(3):
            self.store.start(
                f"CLI {index}", self.challenge, client_key=client_key, now=100 + index,
            )
        with self.assertRaises(DeviceRateLimited):
            self.store.start("Fourth", self.challenge, client_key=client_key, now=104)

        second_client = "2" * 64
        for index in range(10):
            self.store.start(
                f"CLI {index}", _challenge(_verifier(bytes([index + 1]) * 32)),
                client_key=second_client, now=200 + index,
            )
        with self.assertRaises(DeviceRateLimited):
            self.store.start(
                "Eleventh", _challenge(_verifier(b"z" * 32)),
                client_key=second_client, now=211,
            )

    def test_inspect_never_approves_and_decision_is_nonce_and_user_bound(self):
        started = self.store.start("CLI", self.challenge, now=100)
        claim = self.store.inspect(started.user_code, "usr_1", now=101)
        self.assertEqual(claim.device_name, "CLI")
        self.assertRegex(claim.device_fingerprint, r"[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\Z")
        with self.assertRaises(DevicePending):
            self.store.exchange(started.device_code, self.verifier, now=102)
        with self.assertRaises(PermissionError):
            self.store.decide(started.user_code, claim.confirmation_nonce, "usr_2",
                              action="approve", workspace_id="ws_1", now=102)
        self.store.decide(started.user_code, claim.confirmation_nonce, "usr_1",
                          action="approve", workspace_id="ws_1", now=102)
        with self.assertRaises(PermissionError):
            self.store.decide(started.user_code, claim.confirmation_nonce, "usr_1",
                              action="approve", workspace_id="ws_1", now=103)

    def test_denied_and_expired_grants_never_mint_tokens(self):
        denied = self.store.start("CLI", self.challenge, now=100)
        claim = self.store.inspect(denied.user_code, "usr_1", now=101)
        self.store.decide(denied.user_code, claim.confirmation_nonce, "usr_1",
                          action="deny", now=102)
        with self.assertRaises(DeviceDenied):
            self.store.exchange(denied.device_code, self.verifier, now=103)

        expired = self.store.start("CLI", self.challenge, now=200)
        with self.assertRaises(DeviceExpired):
            self.store.exchange(expired.device_code, self.verifier,
                                now=200 + DEVICE_GRANT_TTL + 1)

    def test_exchange_is_one_time_and_access_is_workspace_bound(self):
        started, tokens = self._approved_tokens()
        self.assertRegex(tokens.access_token, r"heel_at_[A-Za-z0-9_-]{43}\Z")
        self.assertRegex(tokens.refresh_token, r"heel_rt_[A-Za-z0-9_-]{64}\Z")
        self.assertEqual(tokens.expires_in, ACCESS_TTL)
        self.assertEqual(tokens.workspace_id, "ws_1")
        principal = self.store.resolve_access(tokens.access_token, now=1_004)
        self.assertEqual((principal.user_id, principal.workspace_id), ("usr_1", "ws_1"))
        with self.assertRaises(PermissionError):
            self.store.exchange(started.device_code, self.verifier, now=1_005)

    def test_refresh_rotates_both_tokens_and_reuse_revokes_family(self):
        _, first = self._approved_tokens()
        second = self.store.refresh(first.refresh_token, now=1_010)
        self.assertNotEqual(second.access_token, first.access_token)
        self.assertNotEqual(second.refresh_token, first.refresh_token)
        self.assertIsNone(self.store.resolve_access(first.access_token, now=1_011))
        self.assertIsNotNone(self.store.resolve_access(second.access_token, now=1_011))

        with self.assertRaises(RefreshReuseDetected):
            self.store.refresh(first.refresh_token, now=1_012)
        self.assertIsNone(self.store.resolve_access(second.access_token, now=1_013))
        with self.assertRaises(PermissionError):
            self.store.refresh(second.refresh_token, now=1_013)

    def test_revoke_is_idempotent_even_for_unknown_tokens(self):
        _, tokens = self._approved_tokens()
        self.store.revoke(tokens.refresh_token, now=1_010)
        self.store.revoke(tokens.refresh_token, now=1_011)
        self.store.revoke("heel_rt_" + "x" * 64, now=1_012)
        self.assertIsNone(self.store.resolve_access(tokens.access_token, now=1_013))

    def test_production_requires_a_strong_server_pepper(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                DeviceAuthStore(conn)
        with self.assertRaises(ValueError):
            DeviceAuthStore(conn, pepper=b"short")
        encoded = base64.urlsafe_b64encode(b"z" * 32).decode().rstrip("=")
        with patch.dict(os.environ, {"HEEL_DEVICE_TOKEN_PEPPER_B64": encoded}, clear=True):
            configured = DeviceAuthStore(conn)
        self.assertIsNotNone(configured)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                ControlPlane(enable_device_auth=True, public_origin="https://heel.test")
            disabled = ControlPlane()
            self.addCleanup(disabled.close)
            self.assertIsNone(disabled.device_auth)


class DeviceAuthHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane(
            device_token_pepper=b"t" * 32,
            public_origin="https://heel.test",
        )
        cls.org = cls.cp.store.create_org("Device Org")
        cls.workspace = cls.cp.store.create_workspace(
            cls.org, "Device Workspace", "pro", CATALOG_VERSION
        )
        cls.other_workspace = cls.cp.store.create_workspace(
            cls.org, "Other Workspace", "pro", CATALOG_VERSION
        )
        cls.user_id = cls.cp.store.create_user("device@example.test")
        cls.cp.store.add_member(cls.workspace, cls.user_id, Role.MEMBER)
        cls.session = cls.cp.auth.create_session(cls.user_id)
        cls.browser_headers = {
            "Cookie": f"heel_session={cls.session.token}",
            "X-Heel-Internal-Origin": "same-origin",
            "Origin": "https://heel.test",
        }
        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=10)

    def request(self, path: str, body: dict, headers: dict[str, str] | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        connection.request("POST", path, raw, request_headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        status = response.status
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        connection.close()
        return status, payload

    def start(self):
        verifier = _verifier(os.urandom(32))
        status, payload = self.request("/v1/device/start", {
            "schema_version": "heel.device-start.v1",
            "client_id": "heel-agent",
            "device_name": "Test CLI",
            "device_challenge": _challenge(verifier),
        })
        self.assertEqual(status, 201, payload)
        self.assertEqual(set(payload), {
            "schema_version", "device_code", "user_code", "verification_uri",
            "expires_in", "interval",
        })
        return verifier, payload

    def authorize(self):
        verifier, started = self.start()
        status, view = self.request("/v1/device/verify", {
            "schema_version": "heel.device-verify.v1",
            "user_code": started["user_code"],
            "action": "inspect",
        }, self.browser_headers)
        self.assertEqual(status, 200, view)
        self.assertEqual(view["status"], "pending")
        self.assertEqual(view["capabilities"], ["sync_findings", "view_synced_reviews"])
        status, decision = self.request("/v1/device/verify", {
            "schema_version": "heel.device-verify.v1",
            "user_code": started["user_code"],
            "action": "approve",
            "workspace_id": self.workspace,
            "confirmation_nonce": view["confirmation_nonce"],
        }, self.browser_headers)
        self.assertEqual((status, decision["status"]), (200, "approved"))
        return verifier, started

    def exchange(self):
        verifier, started = self.authorize()
        status, tokens = self.request("/v1/device/token", {
            "schema_version": "heel.device-token.v1",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": started["device_code"],
            "device_verifier": verifier,
        })
        self.assertEqual(status, 200, tokens)
        return tokens

    def test_complete_flow_mints_workspace_bound_live_principal(self):
        verifier, started = self.authorize()
        status, poll = self.request("/v1/device/poll", {
            "schema_version": "heel.device-poll.v1",
            "device_code": started["device_code"],
            "device_verifier": verifier,
        })
        self.assertEqual((status, poll["status"]), (200, "approved"))

        status, tokens = self.request("/v1/device/token", {
            "schema_version": "heel.device-token.v1",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": started["device_code"],
            "device_verifier": verifier,
        })
        self.assertEqual(status, 200, tokens)
        self.assertEqual(tokens["workspace_id"], self.workspace)

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/v1/me", headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        })
        response = connection.getresponse()
        me = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 200, me)
        self.assertEqual(me["workspace_id"], self.workspace)
        self.assertEqual(me["role"], "member")
        self.assertEqual(me["principal"], "device_session")

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", f"/v1/workspaces/{self.other_workspace}/summary", headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        })
        response = connection.getresponse()
        denied = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 403, denied)

    def test_verify_requires_browser_session_same_origin_and_live_sync_role(self):
        _, started = self.start()
        inspect = {
            "schema_version": "heel.device-verify.v1",
            "user_code": started["user_code"],
            "action": "inspect",
        }
        self.assertEqual(self.request("/v1/device/verify", inspect)[0], 401)
        self.assertEqual(self.request(
            "/v1/device/verify", inspect,
            {"Cookie": f"heel_session={self.session.token}"},
        )[0], 403)

        viewer = self.cp.store.create_user("device-viewer@example.test")
        self.cp.store.add_member(self.workspace, viewer, Role.VIEWER)
        viewer_session = self.cp.auth.create_session(viewer)
        headers = {
            "Cookie": f"heel_session={viewer_session.token}",
            "X-Heel-Internal-Origin": "same-origin",
            "Origin": "https://heel.test",
        }
        status, view = self.request("/v1/device/verify", inspect, headers)
        self.assertEqual(status, 200, view)
        status, denied = self.request("/v1/device/verify", {
            "schema_version": "heel.device-verify.v1",
            "user_code": started["user_code"],
            "action": "approve",
            "workspace_id": self.workspace,
            "confirmation_nonce": view["confirmation_nonce"],
        }, headers)
        self.assertEqual(status, 403, denied)

    def test_verify_requires_recent_browser_authentication(self):
        _, started = self.start()
        self.cp.store.conn.execute(
            "UPDATE sessions SET created_at=? WHERE session_id=?",
            (time.time() - 901, self.session.session_id),
        )
        self.cp.store.conn.commit()
        try:
            status, denied = self.request("/v1/device/verify", {
                "schema_version": "heel.device-verify.v1",
                "user_code": started["user_code"],
                "action": "inspect",
            }, self.browser_headers)
            self.assertEqual(status, 403, denied)
            self.assertEqual(denied, {
                "schema_version": "heel.device-error.v1",
                "code": "recent_auth_required",
            })
        finally:
            self.cp.store.conn.execute(
                "UPDATE sessions SET created_at=? WHERE session_id=?",
                (time.time(), self.session.session_id),
            )
            self.cp.store.conn.commit()

    def test_refresh_rotation_reuse_and_ambiguous_authentication_fail_closed(self):
        first = self.exchange()
        status, second = self.request("/v1/device/refresh", {
            "schema_version": "heel.device-refresh.v1",
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
        })
        self.assertEqual(status, 200, second)
        status, reused = self.request("/v1/device/refresh", {
            "schema_version": "heel.device-refresh.v1",
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
        })
        self.assertEqual((status, reused["code"]), (401, "refresh_reuse_detected"))

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/v1/me", headers={
            "Authorization": f"Bearer {second['access_token']}",
            "Cookie": f"heel_session={self.session.token}",
        })
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 400, payload)
        self.assertEqual(payload["code"], "ambiguous_request_headers")

    def test_device_session_can_request_exact_findings_consent_but_does_not_receive_it_at_login(self):
        tokens = self.exchange()
        project = self.cp.projects.create(
            self.workspace, "Device consent project", created_by=self.user_id,
        )
        digest = "d" * 64
        status, approval = self.request(
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}"
            "/findings-sync/approve",
            {"request_digest": digest},
            {"Authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(status, 201, approval)
        self.assertEqual(approval["request_digest"], digest)
        self.assertEqual(approval["project_ref"], project.project_ref)
        self.assertNotIn("approval_id", tokens)
        self.assertNotIn("request_digest", tokens)

    def test_closed_requests_and_revoke_are_non_oracular(self):
        status, error = self.request("/v1/device/start", {
            "schema_version": "heel.device-start.v1",
            "client_id": "heel-agent",
            "device_name": "CLI",
            "device_challenge": self.challenge if hasattr(self, "challenge") else _challenge(_verifier()),
            "extra": True,
        })
        self.assertEqual((status, error), (400, {
            "schema_version": "heel.device-error.v1", "code": "invalid_request",
        }))
        for token in ("heel_rt_" + "x" * 64, "not-a-token"):
            status, payload = self.request("/v1/device/revoke", {
                "schema_version": "heel.device-revoke.v1",
                "refresh_token": token,
            })
            self.assertEqual((status, payload), (200, {
                "schema_version": "heel.device-revoke-response.v1", "ok": True,
            }))


if __name__ == "__main__":
    unittest.main()
