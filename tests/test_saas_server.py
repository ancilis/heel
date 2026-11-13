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
    def test_startup_log_excludes_listener_address_details(self):
        source = Path("heel/saas/server.py").read_text(encoding="utf-8")
        self.assertNotIn('"host": config.host', source)
        self.assertNotIn('"port": server.server_address[1]', source)

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
        self.assertEqual(Migrator(migrated, CONTROL_PLANE_MIGRATIONS).apply_all(), list(range(1, 35)))

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
            self.assertIn("current=0 target=34", output.getvalue())
            self.assertIn("applied=1,2,3,4,5,6,7,8,9,10", output.getvalue())
            self.assertIn(",31,32,33,34\n", output.getvalue())
            self.assertIn("current=34 target=34", output.getvalue())

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
                self.assertEqual(server.canary_reaper.runner_auth_pepper, config.runner_auth_pepper)
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
                self.assertEqual(version, 34)
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

    def test_ci_uses_private_scratch_and_one_full_pytest_acceptance_gate(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn('install -d -m 700 "${RUNNER_TEMP}/heel-pytest"', workflow)
        self.assertIn('echo "TMPDIR=${RUNNER_TEMP}/heel-pytest" >> "$GITHUB_ENV"', workflow)
        self.assertIn('python -m venv --copies "${RUNNER_TEMP}/heel-pytest/venv"', workflow)
        self.assertIn(
            "- name: Full Python acceptance + security suite\n"
            "        run: >-\n"
            '          "${RUNNER_TEMP}/heel-pytest/venv/bin/python" -m pytest -q tests',
            workflow,
        )
        self.assertNotIn("python -m unittest discover -s tests -p 'test_*.py' -v", workflow)
        production_build = (
            "- name: Build Cloudflare-compatible production artifact\n"
            "        working-directory: apps/heel-cloud\n"
            "        env:\n"
            "          # Syntax-valid non-secret fixture. Production supplies the VPC service\n"
            "          # UUID created for the private Heel control-plane tunnel.\n"
            "          HEEL_CONTROL_PLANE_VPC_SERVICE_ID: 00000000-0000-4000-8000-000000000001\n"
            "          HEEL_PUBLIC_ORIGIN: https://heel.example\n"
            "        run: npm run build"
        )
        self.assertIn(production_build, workflow)



def _real_lock_error() -> sqlite3.OperationalError:
    """A genuine SQLITE_BUSY from two connections, exactly as the reaper's BEGIN IMMEDIATE sees it."""
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "busy.sqlite3")
        holder = sqlite3.connect(path)
        holder.execute("PRAGMA journal_mode=WAL")
        holder.execute("BEGIN IMMEDIATE")
        waiter = sqlite3.connect(path)
        waiter.execute("PRAGMA busy_timeout=0")
        try:
            waiter.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            return error
        finally:
            waiter.close()
            holder.rollback()
            holder.close()
    raise AssertionError("expected SQLITE_BUSY")


class _RecoveryReaperDouble:
    """Production reaper seam: start, unexpected death callback, bounded stop/join result."""

    instances: list = []
    stop_result = True

    def __init__(self, _path, *, on_unexpected_death, **_kwargs):
        self.on_unexpected_death = on_unexpected_death
        self.alive = False
        self.thread = threading.Thread(target=lambda: None, daemon=False)
        self.stopped = False
        type(self).instances.append(self)

    def start(self):
        self.alive = True

    def die(self, error):
        self.alive = False
        self.on_unexpected_death(error)

    def stop(self, *, timeout=5):
        self.stopped = True
        self.alive = False
        return type(self).stop_result


class ReaperLockRecoveryTests(unittest.TestCase):
    valid_environment = ProductionConfigurationTests.valid_environment

    def setUp(self):
        _RecoveryReaperDouble.instances = []
        _RecoveryReaperDouble.stop_result = True

    def budget_path(self, root: Path) -> Path:
        return root / "heel.sqlite3.recovery.json"

    def write_budget(self, root: Path, exits_at) -> bytes:
        raw = json.dumps({
            "schema_version": "heel.control-plane-recovery-budget.v1", "exits_at": exits_at,
        }, separators=(",", ":")).encode()
        self.budget_path(root).write_bytes(raw)
        return raw

    def run_main(self, root: Path):
        """Run the real ``main()`` on a worker thread with captured signal handlers."""
        from heel.saas import server as server_module

        handlers: dict = {}
        built: dict = {}
        outcome: dict = {}
        original_build = server_module.build_server

        def capture_build(config):
            built["server"] = original_build(config)
            return built["server"]

        def run():
            try:
                outcome["code"] = server_module.main()
            except BaseException as error:  # noqa: BLE001 - asserted by the caller
                outcome["error"] = error

        patches = [
            mock.patch.dict("os.environ", self.valid_environment(root), clear=True),
            mock.patch("heel.saas.server.CanaryReaper", _RecoveryReaperDouble),
            mock.patch("heel.saas.server.build_server", capture_build),
            mock.patch("heel.saas.server.signal.signal", lambda sig, handler: handlers.__setitem__(sig, handler)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        for _ in range(500):
            if "server" in built and handlers:
                break
            thread.join(0.01)
        self.assertIn("server", built, outcome)
        return built["server"], thread, outcome, handlers

    def readyz(self, server) -> int:
        connection = http.client.HTTPConnection(*server.server_address[:2], timeout=5)
        connection.request("GET", "/v1/readyz")
        status = connection.getresponse().status
        connection.close()
        return status

    def test_only_sqlite_busy_or_locked_primary_codes_are_recovery_eligible(self):
        from heel.saas.server import _is_reaper_lock_exhaustion

        real = _real_lock_error()
        self.assertEqual(real.sqlite_errorcode & 0xFF, sqlite3.SQLITE_BUSY)
        self.assertTrue(_is_reaper_lock_exhaustion(real))
        for code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, 261, 517, 262):
            error = sqlite3.OperationalError("opaque")
            error.sqlite_errorcode = code
            self.assertTrue(_is_reaper_lock_exhaustion(error), code)
        # Message text alone never qualifies; neither do other codes or other exception types.
        message_only = sqlite3.OperationalError("database is locked")
        no_table = sqlite3.OperationalError("no such table: canary_runs")
        no_table.sqlite_errorcode = sqlite3.SQLITE_ERROR
        bool_code = sqlite3.OperationalError("database is locked")
        bool_code.sqlite_errorcode = True
        integrity = sqlite3.DatabaseError("database is locked")
        integrity.sqlite_errorcode = sqlite3.SQLITE_BUSY
        for error in (message_only, no_table, bool_code, integrity,
                      RuntimeError("database is locked"), TimeoutError("busy")):
            self.assertFalse(_is_reaper_lock_exhaustion(error), repr(error))

    def test_lock_exhaustion_persists_budget_then_gracefully_exits_75_after_inflight_drain(self):
        from heel.saas import http_api
        from heel.saas.server import ProductionConfigurationError, _SingleProcessDatabaseLock

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            entered, release = threading.Event(), threading.Event()
            original_readyz = http_api._Handler._readyz

            def held_readyz(handler):
                entered.set()
                release.wait(5)
                return original_readyz(handler)

            with mock.patch.object(http_api._Handler, "_readyz", held_readyz):
                server, thread, outcome, _ = self.run_main(root)
                inflight: dict = {}
                request = threading.Thread(target=lambda: inflight.__setitem__("status", self.readyz(server)))
                request.start()
                self.assertTrue(entered.wait(5))
                with self.assertLogs("heel.saas.control_plane", "INFO") as logs:
                    _RecoveryReaperDouble.instances[0].die(_real_lock_error())
                # The counter is durable before any shutdown work starts.
                budget = json.loads(self.budget_path(root).read_text())
                self.assertEqual(budget["schema_version"], "heel.control-plane-recovery-budget.v1")
                self.assertEqual(len(budget["exits_at"]), 1)
                self.assertEqual(self.budget_path(root).stat().st_mode & 0o777, 0o600)
                self.assertTrue(server.control_plane.draining)
                self.assertFalse(server.reaper_ready)
                # While the accepted request is active, nothing is closed and ownership is held.
                thread.join(0.5)
                self.assertTrue(thread.is_alive())
                server.control_plane.store.conn.execute("SELECT 1")
                with self.assertRaises(ProductionConfigurationError):
                    _SingleProcessDatabaseLock.acquire(str(root / "heel.sqlite3"))
                release.set()
                request.join(5)
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcome, {"code": 75})
            self.assertEqual(inflight["status"], 503)
            self.assertTrue(_RecoveryReaperDouble.instances[0].stopped)
            with self.assertRaises(sqlite3.ProgrammingError):
                server.control_plane.store.conn.execute("SELECT 1")
            _SingleProcessDatabaseLock.acquire(str(root / "heel.sqlite3")).close()
            events = [json.loads(line.split(":", 2)[2]) for line in logs.output]
            recovery = [event for event in events if event.get("event") == "control_plane_recovery_exit"]
            self.assertEqual(recovery, [{
                "attempt": 1, "budget": 3, "event": "control_plane_recovery_exit", "window_seconds": 3600,
            }])
            self.assertNotIn(str(root), "\n".join(logs.output))

    def test_exhausted_budget_keeps_fail_closed_draining_without_exit_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            now = 1_800_000_000
            raw = self.write_budget(root, [now - 3599, now - 60, now - 1])
            with mock.patch("heel.saas.server._recovery_now", return_value=now):
                server, thread, outcome, handlers = self.run_main(root)
                with self.assertLogs("heel.saas.control_plane", "INFO") as logs:
                    _RecoveryReaperDouble.instances[0].die(_real_lock_error())
                thread.join(0.5)
                self.assertTrue(thread.is_alive())
                self.assertEqual(self.readyz(server), 503)
                self.assertEqual(self.budget_path(root).read_bytes(), raw)
                self.assertIn('"event":"control_plane_recovery_budget_exhausted"', "\n".join(logs.output))
                self.assertIn('"reason":"budget_exhausted"', "\n".join(logs.output))
                handlers[next(iter(handlers))](15, None)
                thread.join(10)
            self.assertEqual(outcome, {"code": 0})
            self.assertEqual(self.budget_path(root).read_bytes(), raw)

    def test_budget_window_boundary_prunes_old_and_conservatively_counts_future_entries(self):
        from heel.saas.server import _RecoveryBudget

        now = 1_800_000_000
        cases = [
            ([now - 3600, now - 7200, now - 3601], True, 1),   # exactly one window old is expired
            ([now - 3599, now - 10], True, 3),
            ([now + 600, now - 10, now - 3599], False, 3),     # a future entry still counts
            ([now + 10 ** 6, now + 1, now + 2], False, 3),
        ]
        for exits, allowed, count in cases:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(strict=True)
                raw = self.write_budget(root, exits)
                budget = _RecoveryBudget(str(root / "heel.sqlite3"))
                result = budget.consume(now)
                self.assertEqual((result.allowed, result.exits_in_window), (allowed, count), exits)
                stored = self.budget_path(root).read_bytes()
                if allowed:
                    self.assertEqual(json.loads(stored)["exits_at"][-1], now)
                    self.assertTrue(all(value > now - 3600 for value in json.loads(stored)["exits_at"]))
                else:
                    self.assertEqual(stored, raw)

    def test_malformed_symlinked_oversized_or_unwritable_budget_fails_closed(self):
        from heel.saas.server import _RecoveryBudget

        now = 1_800_000_000
        valid = {"schema_version": "heel.control-plane-recovery-budget.v1", "exits_at": []}
        payloads = [
            b"not json", b"[]", b"\xff\xfe", json.dumps({**valid, "extra": 1}).encode(),
            json.dumps({**valid, "schema_version": "v0"}).encode(),
            json.dumps({**valid, "exits_at": [True]}).encode(),
            json.dumps({**valid, "exits_at": [-1]}).encode(),
            json.dumps({**valid, "exits_at": [1.5]}).encode(),
            json.dumps({**valid, "exits_at": [1, 2, 3, 4]}).encode(),
            json.dumps({**valid, "exits_at": "1"}).encode(),
            b" " * 4097,
        ]
        for payload in payloads:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(strict=True)
                self.budget_path(root).write_bytes(payload)
                result = _RecoveryBudget(str(root / "heel.sqlite3")).consume(now)
                self.assertEqual((result.allowed, result.reason), (False, "budget_unreadable"), payload[:40])
                self.assertEqual(self.budget_path(root).read_bytes(), payload)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            target = root / "elsewhere.json"
            target.write_text(json.dumps(valid))
            self.budget_path(root).symlink_to(target)
            self.assertFalse(_RecoveryBudget(str(root / "heel.sqlite3")).consume(now).allowed)
            self.assertEqual(json.loads(target.read_text()), valid)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            self.budget_path(root).mkdir()
            self.assertFalse(_RecoveryBudget(str(root / "heel.sqlite3")).consume(now).allowed)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            # The staging file cannot be created: the durable counter cannot be persisted.
            Path(str(self.budget_path(root)) + ".tmp").mkdir()
            result = _RecoveryBudget(str(root / "heel.sqlite3")).consume(now)
            self.assertEqual((result.allowed, result.reason), (False, "budget_unwritable"))
            self.assertFalse(self.budget_path(root).exists())

    def test_unwritable_budget_keeps_draining_and_does_not_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            Path(str(self.budget_path(root)) + ".tmp").mkdir()
            server, thread, outcome, handlers = self.run_main(root)
            _RecoveryReaperDouble.instances[0].die(_real_lock_error())
            thread.join(0.5)
            self.assertTrue(thread.is_alive())
            self.assertEqual(self.readyz(server), 503)
            self.assertFalse(self.budget_path(root).exists())
            handlers[next(iter(handlers))](15, None)
            thread.join(10)
            self.assertEqual(outcome, {"code": 0})

    def test_non_lock_reaper_death_keeps_existing_permanent_draining(self):
        no_table = sqlite3.OperationalError("no such table: canary_runs")
        no_table.sqlite_errorcode = sqlite3.SQLITE_ERROR
        for error in (RuntimeError("runner context purge readiness lost serialization"), no_table,
                      sqlite3.OperationalError("database is locked")):
            with self.subTest(error=repr(error)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(strict=True)
                server, thread, outcome, handlers = self.run_main(root)
                _RecoveryReaperDouble.instances[-1].die(error)
                thread.join(0.5)
                self.assertTrue(thread.is_alive())
                self.assertTrue(server.control_plane.draining)
                self.assertIs(server.reaper_failure, error)
                self.assertEqual(self.readyz(server), 503)
                self.assertFalse(self.budget_path(root).exists())
                handlers[next(iter(handlers))](15, None)
                thread.join(10)
                self.assertEqual(outcome, {"code": 0})

    def test_manual_sigterm_is_never_an_automatic_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server, thread, outcome, handlers = self.run_main(root)
            self.assertEqual(self.readyz(server), 200)
            handlers[next(iter(handlers))](15, None)
            thread.join(10)
            self.assertEqual(outcome, {"code": 0})
            self.assertFalse(self.budget_path(root).exists())
            self.assertEqual(server.exit_code, 0)

    def test_worker_that_does_not_join_retains_ownership_and_never_exits_75(self):
        from heel.saas.canary_reaper import CanaryReaperError
        from heel.saas.server import ProductionConfigurationError, _SingleProcessDatabaseLock

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server, thread, outcome, _ = self.run_main(root)
            _RecoveryReaperDouble.stop_result = False
            _RecoveryReaperDouble.instances[0].die(_real_lock_error())
            thread.join(10)
            self.assertIsInstance(outcome.get("error"), CanaryReaperError)
            self.assertNotIn("code", outcome)
            server.control_plane.store.conn.execute("SELECT 1")
            with self.assertRaises(ProductionConfigurationError):
                _SingleProcessDatabaseLock.acquire(str(root / "heel.sqlite3"))

    def test_recovery_restart_preserves_nonces_revocations_and_kill_switch(self):
        from canary_test_support import seed_authority
        from heel.saas.ops import KillSwitchTripped
        from heel.saas.server import ProductionConfiguration, build_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            server, thread, outcome, _ = self.run_main(root)
            cp = server.control_plane
            user = cp.store.create_user("owner@example.com")
            workspace = cp.store.create_workspace(cp.store.create_org("o"), "default", "free", CATALOG_VERSION)
            cp.store.add_member(workspace, user, Role.OWNER)
            revoked = cp.auth.create_session(user)
            cp.auth.revoke_session(revoked.token)
            project = cp.projects.create(workspace, "p", created_by=user).project_ref
            seed_authority(cp.store.conn, workspace_id=workspace, project_ref=project)
            cp.store.conn.execute(
                "INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
                (workspace, "runr_canary", "claim", "a" * 64, 7, 4_000_000_000),
            )
            cp.store.conn.commit()
            cp.ops.trip("global", actor=user, reason="incident")
            tables = ("sessions", "kill_switches", "canary_runner_nonce_chains", "canary_runner_keys",
                      "canary_runners", "canary_environments")
            dump = lambda conn: {t: sorted(map(tuple, conn.execute(f"SELECT * FROM {t}").fetchall())) for t in tables}
            before = dump(cp.store.conn)
            _RecoveryReaperDouble.instances[0].die(_real_lock_error())
            thread.join(10)
            self.assertEqual(outcome, {"code": 75})
            budget = self.budget_path(root).read_bytes()
            restarted = build_server(ProductionConfiguration.from_environment(self.valid_environment(root)))
            try:
                self.assertTrue(restarted.reaper_ready)
                self.assertEqual(dump(restarted.control_plane.store.conn), before)
                with self.assertRaises(KillSwitchTripped):
                    restarted.control_plane.ops.check(workspace)
                self.assertIsNone(restarted.control_plane.auth.resolve_session(revoked.token))
                self.assertEqual(self.budget_path(root).read_bytes(), budget)
            finally:
                restarted.server_close()


if __name__ == "__main__":
    unittest.main()
