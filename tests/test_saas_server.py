"""Production entrypoint and fail-closed deployment configuration."""
from __future__ import annotations

import base64
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
import io
from unittest import mock

from heel.crypto import SigningAuthority
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.tenancy import Role


def _pepper(byte: bytes) -> str:
    return base64.urlsafe_b64encode(byte * 32).decode("ascii").rstrip("=")


class ProductionConfigurationTests(unittest.TestCase):
    def valid_environment(self, root: Path) -> dict[str, str]:
        signing = SigningAuthority.generate()
        return {
            "HEEL_DATABASE_PATH": str(root / "heel.sqlite3"),
            "HEEL_PUBLIC_ORIGIN": "https://heel.example",
            "HEEL_DEVICE_TOKEN_PEPPER_B64": _pepper(b"d"),
            "HEEL_RUNNER_AUTH_PEPPER_B64": _pepper(b"r"),
            "HEEL_API_KEY_PEPPER": _pepper(b"a"),
            "HEEL_EDGE_AUTH_SECRET_B64": _pepper(b"e"),
            "HEEL_CONTROL_PLANE_HOST": "127.0.0.1",
            "HEEL_CONTROL_PLANE_PORT": "8080",
            "HEEL_BILLING_MODE": "free_launch",
            "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64": signing.canonical_private_key,
            "HEEL_GRANT_SIGNING_KEY_ID": signing.key_id,
            "HEEL_GRANT_TRUSTED_PUBLIC_KEYS": json.dumps({
                signing.key_id: signing.canonical_public_key,
            }, separators=(",", ":")),
        }

    def test_loads_one_node_private_free_launch_configuration(self):
        from heel.saas.server import ProductionConfiguration

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            config = ProductionConfiguration.from_environment(self.valid_environment(root))

        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.port, 8080)
        self.assertEqual(config.public_origin, "https://heel.example")
        self.assertEqual(config.billing_mode, "free_launch")
        self.assertIn(config.grant_authority.key_id, config.grant_trusted_keys)

    def test_migrations_describe_every_runtime_table_and_column(self):
        from heel.saas.http_api import ControlPlane
        from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator

        migrated = sqlite3.connect(":memory:")
        runtime = ControlPlane(
            device_token_pepper=b"d" * 32,
            enable_device_auth=True,
            public_origin="https://heel.example",
        )
        self.addCleanup(migrated.close)
        self.addCleanup(runtime.close)
        self.assertEqual(Migrator(migrated, CONTROL_PLANE_MIGRATIONS).apply_all(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22])

        def schema(connection: sqlite3.Connection) -> dict[str, tuple[tuple, ...]]:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'"
                )
            }
            return {
                table: tuple(tuple(column) for column in connection.execute(
                    f"PRAGMA table_info({table})"
                ))
                for table in sorted(tables)
            }

        self.assertEqual(schema(migrated), schema(runtime.store.conn))
        self.assertIs(runtime.canary_store.conn, runtime.store.conn)
        self.assertIsNone(runtime.grant_authority)

    def test_migration_cli_reports_pending_then_applies_real_schema(self):
        from heel.saas import migrate

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp).resolve(strict=True) / "migrate.sqlite3"
            database.touch(mode=0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(migrate.main(["status", str(database)]), 1)
                self.assertEqual(migrate.main(["up", str(database)]), 0)
                self.assertEqual(migrate.main(["status", str(database)]), 0)
            self.assertIn("current=0 target=22", output.getvalue())
            self.assertIn("applied=1,2,3,4,5,6,7,8,9,10", output.getvalue())
            self.assertIn("current=22 target=22", output.getvalue())

    def test_restore_verification_is_read_only_and_rejects_pending_schema(self):
        from heel.saas import migrate
        from scripts import saas_backup

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            current = root / "current.sqlite3"
            pending = root / "pending.sqlite3"
            self.assertEqual(migrate.main(["up", str(current)]), 0)
            sqlite3.connect(pending).close()

            current_before = current.read_bytes()
            pending_before = pending.read_bytes()
            self.assertEqual(saas_backup.verify(str(current)), 0)
            self.assertEqual(saas_backup.verify(str(pending)), 1)
            self.assertEqual(current.read_bytes(), current_before)
            self.assertEqual(pending.read_bytes(), pending_before)

    def test_missing_or_unsafe_configuration_fails_before_binding(self):
        from heel.saas.server import ProductionConfiguration, ProductionConfigurationError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            valid = self.valid_environment(root)
            cases = (
                ({}, "HEEL_DATABASE_PATH"),
                ({**valid, "HEEL_DATABASE_PATH": ":memory:"}, "HEEL_DATABASE_PATH"),
                ({**valid, "HEEL_DATABASE_PATH": "relative.sqlite3"}, "HEEL_DATABASE_PATH"),
                ({**valid, "HEEL_PUBLIC_ORIGIN": "http://heel.example"}, "HEEL_PUBLIC_ORIGIN"),
                ({**valid, "HEEL_PUBLIC_ORIGIN": "https://heel.example/path"}, "HEEL_PUBLIC_ORIGIN"),
                ({**valid, "HEEL_DEVICE_TOKEN_PEPPER_B64": "short"}, "HEEL_DEVICE_TOKEN_PEPPER_B64"),
                ({**valid, "HEEL_RUNNER_AUTH_PEPPER_B64": "short"}, "HEEL_RUNNER_AUTH_PEPPER_B64"),
                ({**valid, "HEEL_API_KEY_PEPPER": "short"}, "HEEL_API_KEY_PEPPER"),
                ({**valid, "HEEL_EDGE_AUTH_SECRET_B64": "short"}, "HEEL_EDGE_AUTH_SECRET_B64"),
                ({**valid, "HEEL_CONTROL_PLANE_PORT": "0"}, "HEEL_CONTROL_PLANE_PORT"),
                ({**valid, "HEEL_BILLING_MODE": "stub"}, "HEEL_BILLING_MODE"),
                ({**valid, "HEEL_CONTROL_PLANE_HOST": "0.0.0.0"}, "HEEL_PRIVATE_NETWORK_ACK"),
                ({**valid, "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64": ""}, "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64"),
                ({**valid, "HEEL_GRANT_SIGNING_KEY_ID": ""}, "HEEL_GRANT_SIGNING_KEY_ID"),
                ({**valid, "HEEL_GRANT_TRUSTED_PUBLIC_KEYS": ""}, "HEEL_GRANT_TRUSTED_PUBLIC_KEYS"),
            )
            for environment, field in cases:
                with self.subTest(field=field), self.assertRaises(ProductionConfigurationError) as caught:
                    ProductionConfiguration.from_environment(environment)
                self.assertIn(field, str(caught.exception))

            config = ProductionConfiguration.from_environment(valid)
            self.assertEqual(config.grant_authority.key_id, valid["HEEL_GRANT_SIGNING_KEY_ID"])

            mismatched = {**valid, "HEEL_GRANT_SIGNING_KEY_ID": "k_wrong"}
            with self.assertRaises(ProductionConfigurationError):
                ProductionConfiguration.from_environment(mismatched)

    def test_non_loopback_bind_requires_explicit_private_network_acknowledgement(self):
        from heel.saas.server import ProductionConfiguration

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            environment = {
                **self.valid_environment(root),
                "HEEL_CONTROL_PLANE_HOST": "0.0.0.0",
                "HEEL_PRIVATE_NETWORK_ACK": "private-vpc-only",
            }
            config = ProductionConfiguration.from_environment(environment)

        self.assertEqual(config.host, "0.0.0.0")

    def test_build_server_uses_durable_sqlite_and_never_stub_checkout(self):
        from heel.saas.billing import DisabledBilling
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            config = ProductionConfiguration.from_environment(self.valid_environment(root))
            server = build_server(config)
            try:
                self.assertIsInstance(server.control_plane.billing, DisabledBilling)
                self.assertIs(server.control_plane.grant_authority, config.grant_authority)
                self.assertIs(
                    server.control_plane.canary_runs.signing,
                    config.grant_authority,
                )
                self.assertIs(
                    server.control_plane.canary_disclosure.signing,
                    config.grant_authority,
                )
                self.assertIs(server.control_plane.canary_store.conn, server.control_plane.store.conn)
                mode = server.control_plane.store.conn.execute("PRAGMA journal_mode").fetchone()[0]
                self.assertEqual(mode.lower(), "wal")
                self.assertTrue(Path(config.database_path).is_file())
                self.assertTrue(server.reaper_ready)
                self.assertTrue(server.canary_reaper.alive)
                self.assertFalse(server.canary_reaper.thread.daemon)
            finally:
                server.server_close()

        self.assertFalse(server.canary_reaper.alive)

    def test_reaper_startup_failure_closes_listener_database_and_process_lock(self):
        from heel.saas.canary_reaper import CanaryReaperError
        from heel.saas.server import (
            ProductionConfiguration,
            ProductionConfigurationError,
            build_server,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            config = ProductionConfiguration.from_environment(self.valid_environment(root))
            with mock.patch(
                "heel.saas.server.CanaryReaper.start",
                side_effect=CanaryReaperError("cycle failed"),
            ), self.assertRaises(ProductionConfigurationError):
                build_server(config)

            # A failed construction released both ownership layers; a clean retry is possible.
            server = build_server(config)
            server.server_close()

    def test_unexpected_reaper_death_removes_readiness_and_is_not_silently_abandoned(self):
        from heel.saas.server import ProductionConfiguration, build_server

        class ReaperDouble:
            def __init__(self, _path, *, on_unexpected_death, **_kwargs):
                self.on_unexpected_death = on_unexpected_death
                self.alive = False
                self.thread = threading.Thread(target=lambda: None, daemon=False)
                self.stopped = False

            def start(self):
                self.alive = True

            def die(self):
                self.alive = False
                self.on_unexpected_death(RuntimeError("reaper died"))

            def stop(self, *, timeout=5):
                self.stopped = True
                self.alive = False
                return True

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            config = ProductionConfiguration.from_environment(self.valid_environment(root))
            with mock.patch("heel.saas.server.CanaryReaper", ReaperDouble):
                server = build_server(config)
                self.assertTrue(server.reaper_ready)
                server.canary_reaper.die()
                self.assertFalse(server.reaper_ready)
                self.assertTrue(server.control_plane.draining)
                self.assertIsInstance(server.reaper_failure, RuntimeError)
                server.server_close()
                self.assertTrue(server.canary_reaper.stopped)

    def test_server_close_joins_reaper_before_checkpointing_and_closing_control_plane(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            order = []
            original_stop = server.canary_reaper.stop
            original_close = server.control_plane.close

            def stop(*, timeout=5):
                order.append("reaper")
                return original_stop(timeout=timeout)

            def close():
                order.append("control-plane")
                return original_close()

            server.canary_reaper.stop = stop
            server.control_plane.close = close
            server.server_close()

            self.assertEqual(order, ["reaper", "control-plane"])
            with self.assertRaises(sqlite3.ProgrammingError):
                server.control_plane.store.conn.execute("SELECT 1")

    def test_database_has_one_process_owner_and_persists_across_restart(self):
        from heel.saas.server import (
            ProductionConfiguration,
            ProductionConfigurationError,
            build_server,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            environment = self.valid_environment(root)
            config = ProductionConfiguration.from_environment(environment)
            first = build_server(config)
            user_id = first.control_plane.store.create_user("persisted@example.com")
            with self.assertRaises(ProductionConfigurationError):
                build_server(config)
            first.server_close()

            restarted = build_server(config)
            try:
                row = restarted.control_plane.user_by_email("persisted@example.com")
                self.assertEqual(row["user_id"], user_id)
                version = restarted.control_plane.store.conn.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                self.assertEqual(version, 22)
            finally:
                restarted.server_close()

    def test_production_checkout_returns_service_unavailable_not_a_stub_url(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            cp = server.control_plane
            user_id = cp.store.create_user("owner@example.com")
            org_id = cp.store.create_org("owner@example.com")
            workspace_id = cp.store.create_workspace(
                org_id, "default", "free", CATALOG_VERSION,
            )
            cp.store.add_member(workspace_id, user_id, Role.OWNER)
            session = cp.auth.create_session(user_id)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection(
                    server.server_address[0], server.server_address[1], timeout=5,
                )
                payload = json.dumps({"plan": "pro", "interval": "month"}).encode()
                connection.request(
                    "POST",
                    f"/v1/workspaces/{workspace_id}/billing/checkout",
                    payload,
                    {
                        "Content-Type": "application/json",
                        "Content-Length": str(len(payload)),
                        "Cookie": f"heel_session={session.token}",
                        "X-Heel-Edge-Auth": _pepper(b"e"),
                    },
                )
                response = connection.getresponse()
                body = response.read().decode()
                connection.close()
                self.assertEqual(response.status, 503)
                self.assertNotIn("stub.local", body)
            finally:
                server.shutdown()
                server.server_close()

    def test_production_plan_catalog_marks_only_free_as_available(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection(
                    server.server_address[0], server.server_address[1], timeout=5,
                )
                connection.request("GET", "/v1/plans", headers={
                    "X-Heel-Edge-Auth": _pepper(b"e"),
                })
                response = connection.getresponse()
                body = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200)
                availability = {plan["id"]: plan["availability"] for plan in body["plans"]}
                self.assertEqual(availability, {
                    "free": "available",
                    "pro": "coming_soon",
                    "team": "coming_soon",
                })
            finally:
                server.shutdown()
                server.server_close()

    def test_unexpected_failures_emit_only_redacted_request_diagnostics(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            server.control_plane.metrics.render = mock.Mock(
                side_effect=RuntimeError("super-secret-customer-value")
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertLogs("heel.saas.control_plane", level="ERROR") as captured:
                    connection = http.client.HTTPConnection(
                        server.server_address[0], server.server_address[1], timeout=5,
                    )
                    connection.request("GET", "/v1/metrics")
                    response = connection.getresponse()
                    body = json.loads(response.read())
                    request_id = response.getheader("X-Heel-Request-Id")
                    connection.close()

                self.assertEqual(response.status, 500)
                self.assertEqual(body, {"error": "internal error"})
                self.assertRegex(request_id or "", r"^[0-9a-f]{32}$")
                event = json.loads(captured.records[-1].getMessage())
                self.assertEqual(event["event"], "control_plane_internal_error")
                self.assertEqual(event["exception_type"], "RuntimeError")
                self.assertEqual(event["method"], "GET")
                self.assertEqual(event["request_id"], request_id)
                self.assertNotIn("super-secret-customer-value", captured.output[-1])
                self.assertNotIn("metrics", captured.output[-1])
            finally:
                server.shutdown()
                server.server_close()

    def test_signup_rolls_back_the_complete_account_graph_on_every_failure(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def signup(email: str, password: str) -> tuple[int, dict]:
                payload = json.dumps({"email": email, "password": password}).encode()
                connection = http.client.HTTPConnection(
                    server.server_address[0], server.server_address[1], timeout=5,
                )
                connection.request(
                    "POST",
                    "/v1/signup",
                    payload,
                    {
                        "Content-Type": "application/json",
                        "Content-Length": str(len(payload)),
                        "X-Heel-Client-Key": "1" * 64,
                        "X-Heel-Edge-Auth": _pepper(b"e"),
                    },
                )
                response = connection.getresponse()
                result = response.status, json.loads(response.read())
                connection.close()
                return result

            try:
                status, _ = signup("weak@example.com", "short")
                self.assertEqual(status, 400)
                self.assertIsNone(server.control_plane.user_by_email("weak@example.com"))

                with mock.patch.object(
                    server.control_plane.store,
                    "create_workspace",
                    side_effect=RuntimeError("late-signup-failure"),
                ), self.assertLogs("heel.saas.control_plane", level="ERROR"):
                    status, body = signup(
                        "retryable@example.com", "correct-horse-staple-42"
                    )
                self.assertEqual(status, 500)
                self.assertEqual(body, {"error": "internal error"})
                self.assertIsNone(server.control_plane.user_by_email("retryable@example.com"))
                for table in ("credentials", "orgs", "workspaces", "memberships", "sessions"):
                    count = server.control_plane.store.conn.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    self.assertEqual(count, 0, table)

                status, _ = signup("retryable@example.com", "correct-horse-staple-42")
                self.assertEqual(status, 201)
            finally:
                server.shutdown()
                server.server_close()

    def test_server_close_waits_for_an_accepted_request_before_closing_sqlite(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            entered = threading.Event()
            release = threading.Event()

            def blocked_metrics() -> str:
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("test request was not released")
                return "# drained\n"

            server.control_plane.metrics.render = blocked_metrics
            serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
            serve_thread.start()
            result: dict[str, object] = {}

            def request() -> None:
                connection = http.client.HTTPConnection(
                    server.server_address[0], server.server_address[1], timeout=5,
                )
                connection.request("GET", "/v1/metrics")
                response = connection.getresponse()
                result["status"] = response.status
                result["body"] = response.read().decode()
                connection.close()

            request_thread = threading.Thread(target=request)
            request_thread.start()
            self.assertTrue(entered.wait(timeout=2))
            server.control_plane.draining = True
            server.shutdown()

            closed = threading.Event()

            def close() -> None:
                server.server_close()
                closed.set()

            close_thread = threading.Thread(target=close)
            close_thread.start()
            self.assertFalse(closed.wait(timeout=0.1))
            release.set()
            request_thread.join(timeout=3)
            close_thread.join(timeout=3)

            self.assertTrue(closed.is_set())
            self.assertEqual(result, {"status": 200, "body": "# drained\n"})
            with self.assertRaises(sqlite3.ProgrammingError):
                server.control_plane.store.conn.execute("SELECT 1")

    def test_production_signup_requires_the_edges_non_reversible_client_key(self):
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server = build_server(
                ProductionConfiguration.from_environment(self.valid_environment(root))
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            payload = json.dumps({
                "email": "new@example.com",
                "password": "correct-horse-staple-42",
            }).encode()

            def signup(extra_headers: dict[str, str]) -> int:
                connection = http.client.HTTPConnection(
                    server.server_address[0], server.server_address[1], timeout=5,
                )
                connection.request("POST", "/v1/signup", payload, {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                    **extra_headers,
                })
                response = connection.getresponse()
                response.read()
                connection.close()
                return response.status

            try:
                self.assertEqual(signup({}), 401)
                self.assertEqual(signup({"X-Heel-Edge-Auth": "A" * 43}), 401)
                self.assertEqual(signup({"X-Heel-Edge-Auth": _pepper(b"e")}), 400)
                self.assertEqual(signup({
                    "X-Heel-Edge-Auth": _pepper(b"e"),
                    "X-Heel-Client-Key": "a" * 64,
                }), 201)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
