import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from heel.local_projects import LocalProjectStore
from heel.mcp_server import MAX_OPENAPI_PAYLOAD_BYTES, HeelServer, ToolError
from heel.review_export import review_to_markdown
from heel.store import Store


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"
SAFE_FAILURE = (
    "Heel OpenAPI review failed: input could not be read or reviewed safely.\n"
)


def _run_cli(home: Path, input_path: Path, *arguments: str, timeout: int = 10):
    environment = os.environ.copy()
    environment["HEEL_HOME"] = str(home.resolve())
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "heel.cli",
            "review",
            "openapi",
            str(input_path),
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


class LocalAgentJourneyTests(unittest.TestCase):
    def test_cli_json_review_is_pure_persisted_local_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "heel-home"
            result = _run_cli(home, OPENAPI_FIXTURE, "--json")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            review = json.loads(result.stdout)
            self.assertEqual(review["schema_version"], "heel.review.v1")
            self.assertEqual(review["execution_mode"], "machine_local")
            self.assertGreater(review["summary"]["findings"], 0)
            self.assertTrue(review["recommended_controls"])
            self.assertEqual(review["privacy"], {
                "execution": "machine_local",
                "network_calls": False,
                "uploaded": False,
                "sync_intent": "none",
            })
            saved = home / "reviews" / f"{review['review_id']}.json"
            self.assertEqual(json.loads(saved.read_text(encoding="utf-8")), review)
            self.assertFalse((home / "scopes").exists())
            self.assertFalse((home / "signing.key").exists())
            self.assertFalse((home / "heel.db").exists())

    def test_cli_markdown_uses_the_shared_validated_exporter(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "heel-home"
            result = _run_cli(home, OPENAPI_FIXTURE)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            review_path = next((home / "reviews").glob("review_*.json"))
            review = json.loads(review_path.read_text(encoding="utf-8"))
            self.assertEqual(result.stdout, review_to_markdown(review))
            self.assertIn("Recommended control:", result.stdout)

    def test_cli_and_mcp_produce_the_exact_same_envelope(self):
        spec = json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(strict=True)
            cli_result = _run_cli(base / "cli-home", OPENAPI_FIXTURE, "--json")
            self.assertEqual(cli_result.returncode, 0, cli_result.stderr)
            cli_review = json.loads(cli_result.stdout)

            mcp_home = base / "mcp-home"
            mcp_home.mkdir(mode=0o700)
            projects = LocalProjectStore(mcp_home)
            audit = Store(str(mcp_home / "heel.db"))
            try:
                mcp_review = HeelServer(
                    store=audit,
                    projects=projects,
                ).call_tool(
                    "heel_review_openapi",
                    {"openapi": spec},
                    "mcp:parity-test",
                )
            finally:
                audit.close()

            self.assertEqual(cli_review, mcp_review)

    def test_cli_and_mcp_both_reject_a_review_over_the_transport_limit(self):
        specification = {
            "openapi": "3.1.0",
            "info": {"title": "Many exports", "version": "1"},
            "paths": {
                f"/exports/{index}": {
                    "get": {"operationId": f"exportRecord{index}"},
                }
                for index in range(300)
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            input_path = root / "many-exports.json"
            input_path.write_text(json.dumps(specification), encoding="utf-8")

            cli_home = root / "cli-home"
            cli_result = _run_cli(cli_home, input_path, "--json")
            self.assertEqual(cli_result.returncode, 2)
            self.assertEqual(cli_result.stdout, "")
            self.assertEqual(cli_result.stderr, SAFE_FAILURE)
            self.assertFalse((cli_home / "reviews").exists())

            mcp_home = root / "mcp-home"
            mcp_home.mkdir(mode=0o700)
            audit = Store(str(mcp_home / "heel.db"))
            try:
                server = HeelServer(
                    store=audit,
                    projects=LocalProjectStore(mcp_home),
                )
                with self.assertRaises(ToolError) as raised:
                    server.call_tool(
                        "heel_review_openapi",
                        {"openapi": specification},
                        "mcp:parity-limit-test",
                    )
            finally:
                audit.close()

            self.assertEqual(raised.exception.code, "result_too_large")
            self.assertFalse((mcp_home / "reviews").exists())

    def test_cli_handler_has_no_network_path(self):
        from heel import cli

        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.dict(
                    os.environ,
                    {"HEEL_HOME": str(Path(temporary).resolve(strict=True))},
                ),
                mock.patch.object(
                    socket,
                    "socket",
                    side_effect=AssertionError("network access attempted"),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                code = cli._review_openapi_file(str(OPENAPI_FIXTURE), as_json=True)

            self.assertEqual(code, 0, stderr.getvalue())
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(json.loads(stdout.getvalue())["schema_version"], "heel.review.v1")

    def test_cli_rejects_unsafe_or_invalid_inputs_without_disclosure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "heel-home"
            secret = "sk-live-never-print-1234567890abcdef"

            oversized = root / "oversized-secret.json"
            oversized.write_bytes(b"{" + b"x" * MAX_OPENAPI_PAYLOAD_BYTES)
            malformed = root / "malformed-secret.json"
            malformed.write_text("{not-json " + secret, encoding="utf-8")
            secret_spec = root / "secret-spec.json"
            secret_spec.write_text(json.dumps({
                "openapi": "3.1.0",
                "info": {"title": "Secret", "version": "1"},
                "paths": {},
                "components": {"examples": {"credential": {"value": secret}}},
            }), encoding="utf-8")
            directory = root / "directory-input"
            directory.mkdir()
            missing = root / "missing-secret-path.json"

            for input_path in (oversized, malformed, secret_spec, directory, missing):
                with self.subTest(input_path=input_path.name):
                    result = _run_cli(home, input_path, "--json")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, SAFE_FAILURE)
                    self.assertNotIn(secret, result.stderr)
                    self.assertNotIn(str(input_path), result.stderr)

            self.assertFalse((home / "reviews").exists())

    def test_cli_redacts_an_unresolvable_heel_home_failure(self):
        unavailable_user = "heel-user-that-cannot-exist-93f06f"
        environment = os.environ.copy()
        environment["HEEL_HOME"] = f"~{unavailable_user}/private-review-data"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "heel.cli",
                "review",
                "openapi",
                str(OPENAPI_FIXTURE),
                "--json",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, SAFE_FAILURE)
        self.assertNotIn(unavailable_user, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "mkfifo"), "POSIX files")
    def test_cli_rejects_symlinks_and_fifos_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "heel-home"
            symlink = root / "spec-link.json"
            symlink.symlink_to(OPENAPI_FIXTURE)
            fifo = root / "spec.fifo"
            os.mkfifo(fifo)

            for input_path in (symlink, fifo):
                with self.subTest(input_path=input_path.name):
                    result = _run_cli(home, input_path, "--json", timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, SAFE_FAILURE)

    def test_cli_help_exposes_the_exact_review_command(self):
        result = subprocess.run(
            [sys.executable, "-m", "heel.cli", "review", "openapi", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PATH", result.stdout)
        self.assertIn("--json", result.stdout)

    def test_manifest_matches_the_installable_local_review_product(self):
        manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        package = manifest["packages"][0]

        self.assertEqual(manifest["name"], "io.github.ancilis/heel")
        self.assertTrue(manifest["description"].startswith(
            "Heel reviews a SaaS product model before launch and returns ranked abuse "
            "paths, missing controls, and regression tests."
        ))
        self.assertEqual(package["identifier"], "heel-sim")
        self.assertEqual(package["package_arguments"], [
            {"type": "named", "name": "--from", "value": "heel-sim"},
            {"type": "positional", "value": "heel-mcp"},
        ])

    def test_readme_and_mcp_quickstart_are_honest_and_runnable(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs/MCP_QUICKSTART.md").read_text(encoding="utf-8")

        self.assertIn("heel review openapi", readme)
        self.assertIn(
            ".venv/bin/python -m pip install ./heel_sim-1.1.1-py3-none-any.whl",
            readme,
        )
        self.assertIn("/downloads/heel_sim-1.1.1-py3-none-any.whl", readme)
        self.assertIn("not yet published", readme.lower())
        self.assertNotIn("git clone https://github.com/ancilis/heel", readme)
        self.assertIn("python3 -m pip install heel-sim", quickstart)
        self.assertIn("only after an actual pypi release", quickstart.lower())
        self.assertIn('"command": "heel-mcp"', quickstart)
        self.assertIn('"HEEL_HOME": "/absolute/path/to/private/heel-data"', quickstart)
        self.assertIn("no Heel Cloud account", quickstart)
        self.assertIn("no network calls", quickstart)
        self.assertIn("must not contain credentials or customer data", quickstart)

    def test_release_smoke_has_a_make_target(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        script = ROOT / "scripts/release_smoke.py"

        self.assertTrue(script.is_file())
        self.assertIn("release-smoke:", makefile)
        self.assertIn("scripts/release_smoke.py", makefile)


if __name__ == "__main__":
    unittest.main()
