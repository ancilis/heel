from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import socket

from heel import cli


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/canary/staging-openapi.json"


def invoke(*arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(["runner", *arguments])
    return code, stdout.getvalue(), stderr.getvalue()


def test_runner_cli_import_credential_map_and_static_prepare_are_local(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    monkeypatch.setenv("HEEL_CLI_EPHEMERAL", "cli-secret-value")
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))

    code, output, error = invoke("import-openapi", str(FIXTURE))
    assert code == 0 and error == ""
    assert json.loads(output) == {"methods": ["GET", "HEAD"], "routes": 6}

    code, output, error = invoke(
        "credential", "add",
        "--profile", "bearer",
        "--label", "CI bearer",
        "--handle-id", "a" * 32,
        "--vault", "ephemeral-env",
        "--env-name", "HEEL_CLI_EPHEMERAL",
    )
    assert code == 0 and error == ""
    credential = json.loads(output)
    assert credential == {
        "auth_profile": "bearer",
        "credential_handle_id": "a" * 32,
        "label": "ci-bearer",
    }
    assert "HEEL_CLI_EPHEMERAL" not in os.environ
    assert "cli-secret-value" not in output

    code, output, error = invoke(
        "map", "--scenario", "anonymous_authenticated_read",
        "--method", "HEAD", "--route", "/health",
        "--handle-id", "a" * 32,
    )
    assert code == 0 and error == ""
    assert json.loads(output) == {
        "auth_profile": "anonymous",
        "method": "HEAD",
        "route_template": "/health",
        "semantic_role": "anonymous_authenticated_read",
    }

    code, output, error = invoke("prepare")
    assert code == 0 and error == ""
    assert json.loads(output) == {
        "live": False,
        "mapped_scenarios": 1,
        "network_calls": False,
        "ready_for_live": False,
        "routes": 6,
    }


def test_runner_cli_never_accepts_secret_argv_and_live_failure_is_constant(tmp_path, monkeypatch):
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "heel-home"))
    code, output, error = invoke(
        "credential", "add", "--profile", "bearer", "--label", "Bearer",
        "--secret", "must-not-be-an-argument",
    )
    assert code == 2
    assert "must-not-be-an-argument" not in output + error

    code, output, error = invoke(
        "credential", "add", "--profile", "bearer", "--label", "Bearer",
        "--password", "another-secret-value",
    )
    assert code == 2
    assert output == ""
    assert error == "Heel runner command was rejected.\n"

    code, output, error = invoke("prepare", "--live")
    assert code == 2 and output == ""
    assert error == "Heel runner live preparation is unavailable.\n"


def test_credential_add_accepts_secret_only_from_inherited_fd(tmp_path, monkeypatch):
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "heel-home"))
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(b"fd-only-secret")
    descriptor = os.open(secret_file, os.O_RDONLY)
    os.set_inheritable(descriptor, True)
    try:
        code, output, error = invoke(
            "credential", "add", "--profile", "x_api_key", "--label", "API key",
            "--handle-id", "b" * 32, "--vault", "ephemeral-fd",
            "--secret-fd", str(descriptor),
        )
    finally:
        os.close(descriptor)
    assert code == 0 and error == ""
    assert "fd-only-secret" not in output
    assert json.loads(output)["credential_handle_id"] == "b" * 32
