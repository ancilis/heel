#!/usr/bin/env python3
"""Build and exercise an installable Heel wheel from a clean tracked-source copy."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = Path("tests/fixtures/openapi/saas_api.json")


class SmokeFailure(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=180,
    )
    if completed.returncode:
        executable = Path(command[0]).name
        details = (completed.stderr or completed.stdout).strip()
        raise SmokeFailure(f"{executable} failed ({completed.returncode}): {details}")
    return completed


def _copy_tracked_source(destination: Path) -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    for encoded_path in listed:
        if not encoded_path:
            continue
        relative = Path(os.fsdecode(encoded_path))
        source = ROOT / relative
        if not source.exists() and not source.is_symlink():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target)


def _build_wheel(source: Path, wheelhouse: Path) -> Path:
    uv = shutil.which("uv")
    if uv:
        command = [uv, "build", "--wheel", "--out-dir", str(wheelhouse)]
    else:
        command = [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(wheelhouse),
        ]
    _run(command, cwd=source)
    wheels = sorted(wheelhouse.glob("heel_sim-*.whl"))
    if len(wheels) != 1:
        raise SmokeFailure(f"expected one heel_sim wheel; found {len(wheels)}")
    return wheels[0]


def _inspect_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    required = {
        "heel/__init__.py",
        "heel/cli.py",
        "heel/mcp_server.py",
        "heel/runner/__init__.py",
        "heel/runner/runtime.py",
    }
    missing = sorted(required - names)
    if missing:
        raise SmokeFailure(f"wheel is missing required files: {', '.join(missing)}")
    former_namespace = "arc" + "eo/"
    if any(name.startswith(former_namespace) for name in names):
        raise SmokeFailure("wheel contains the former package namespace")


def _installed_scripts(environment_root: Path) -> tuple[Path, Path, Path]:
    scripts = environment_root / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    return (
        scripts / f"python{suffix}",
        scripts / f"heel{suffix}",
        scripts / f"heel-mcp{suffix}",
    )


def _exercise_installed_wheel(
    wheel: Path,
    source: Path,
    environment_root: Path,
    scratch: Path,
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise SmokeFailure("uv is required for isolated release smoke")
    found_python = _run(
        [
            uv,
            "python",
            "find",
            "--system",
            "--resolve-links",
            "--no-project",
            "--no-config",
            "--no-python-downloads",
            "--offline",
            ">=3.11",
        ],
        cwd=scratch,
    ).stdout.splitlines()
    if len(found_python) != 1 or not found_python[0]:
        raise SmokeFailure("an installed system Python >=3.11 is required for release smoke")
    base_python = Path(found_python[0])
    if not base_python.is_absolute() or not base_python.is_file() or not os.access(base_python, os.X_OK):
        raise SmokeFailure("an installed system Python >=3.11 is required for release smoke")
    _run(
        [
            uv,
            "venv",
            "--no-project",
            "--no-config",
            "--no-python-downloads",
            "--offline",
            "--no-cache",
            "--python",
            str(base_python),
            str(environment_root.resolve()),
        ],
        cwd=scratch,
    )
    python, heel, heel_mcp = _installed_scripts(environment_root)
    _run(
        [
            uv,
            "pip",
            "install",
            "--no-config",
            "--no-python-downloads",
            "--offline",
            "--no-cache",
            "--no-index",
            "--python",
            str(python.absolute()),
            "--no-deps",
            str(wheel.resolve()),
        ],
        cwd=scratch,
    )

    base_environment = os.environ.copy()
    base_environment.pop("PYTHONPATH", None)
    base_environment.pop("PYTHONHOME", None)

    _run(
        [
            str(python), "-I", "-c",
            (
                "import importlib,importlib.util;"
                "[importlib.import_module(name) for name in "
                "('heel','heel.cli','heel.mcp_server','heel.runner','heel.runner.runtime')];"
                "assert importlib.util.find_spec('heel.saas') is None"
            ),
        ],
        cwd=scratch,
        environment=base_environment,
    )

    cli_home = (scratch / "cli-home").resolve()
    cli_environment = dict(base_environment, HEEL_HOME=str(cli_home))
    cli_result = _run(
        [str(heel), "review", "openapi", str(source / OPENAPI_FIXTURE), "--json"],
        cwd=scratch,
        environment=cli_environment,
    )
    try:
        cli_review = json.loads(cli_result.stdout)
    except json.JSONDecodeError as error:
        raise SmokeFailure("installed heel --json did not emit pure JSON") from error
    if cli_review.get("schema_version") != "heel.review.v1":
        raise SmokeFailure("installed heel returned the wrong review schema")
    if not (cli_home / "reviews" / f"{cli_review['review_id']}.json").is_file():
        raise SmokeFailure("installed heel did not persist its review")

    specification = json.loads((source / OPENAPI_FIXTURE).read_text(encoding="utf-8"))
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "release-smoke", "version": "1"},
            },
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "heel_review_openapi",
                "arguments": {"openapi": specification},
            },
        },
    ]
    mcp_home = (scratch / "mcp-home").resolve()
    mcp_environment = dict(base_environment, HEEL_HOME=str(mcp_home))
    mcp_result = _run(
        [str(heel_mcp)],
        cwd=scratch,
        environment=mcp_environment,
        input_text="".join(json.dumps(request) + "\n" for request in requests),
    )
    try:
        responses = [json.loads(line) for line in mcp_result.stdout.splitlines()]
    except json.JSONDecodeError as error:
        raise SmokeFailure("installed heel-mcp did not emit JSON-RPC lines") from error
    if len(responses) != 3 or [response.get("id") for response in responses] != [1, 2, 3]:
        raise SmokeFailure("installed heel-mcp returned an unexpected response sequence")
    if responses[0]["result"]["serverInfo"]["name"] != "heel":
        raise SmokeFailure("installed heel-mcp returned the wrong server identity")
    tools = {tool["name"] for tool in responses[1]["result"]["tools"]}
    if "heel_review_openapi" not in tools:
        raise SmokeFailure("installed heel-mcp did not expose heel_review_openapi")
    mcp_review = responses[2]["result"]["structuredContent"]
    if mcp_review != cli_review:
        raise SmokeFailure("installed CLI and MCP returned different review envelopes")
    if not (mcp_home / "reviews" / f"{mcp_review['review_id']}.json").is_file():
        raise SmokeFailure("installed heel-mcp did not persist its review")


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="heel-release-smoke-") as temporary:
            scratch = Path(temporary).resolve(strict=True)
            source = scratch / "source"
            wheelhouse = scratch / "wheelhouse"
            source.mkdir()
            wheelhouse.mkdir()
            _copy_tracked_source(source)
            wheel = _build_wheel(source, wheelhouse)
            _inspect_wheel(wheel)
            _exercise_installed_wheel(
                wheel,
                source,
                scratch / "venv",
                scratch,
            )
    except (OSError, SmokeFailure, subprocess.SubprocessError) as error:
        print(f"release smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print("release smoke: PASS (clean wheel, installed CLI, installed MCP)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
