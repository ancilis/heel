from __future__ import annotations

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import socket

from heel import cli
from heel.crypto import ed25519_key_id
from heel.runner.catalog import CATALOG_IDS
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.store import RunnerContext, RunnerStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/canary/staging-openapi.json"


class Signer(SecureSigner):
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)
    def sign(self, payload): return self._key.sign(payload)


def bind_home(home: Path):
    signer = Signer()
    identity = RunnerIdentity(
        runner_id="runner_123456789", workspace_id="ws_123456789", runner_version="1",
        adapter_versions={scenario: "1" for scenario in CATALOG_IDS},
        public_key_b64=base64.b64encode(signer.public_key).decode(),
        fingerprint=__import__("hashlib").sha256(signer.public_key).hexdigest(),
        key_id=signer.key_id, pairing_phrase=runner_phrase_words()[:6],
    )
    RunnerStore(home).bind_context(RunnerContext(
        workspace_id="ws_123456789", project_id="prj_123456789",
        environment_id="env_123456789", origin="https://staging.acme.dev",
        verification_record_digest="0" * 64, environment_class="staging",
    ), identity=identity, signer=signer, signer_label="cli-test-signer")
    return signer, identity


def invoke(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_outputs_only_counts_digests_and_scenario_ids_with_no_network(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    bind_home(home)
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")),
    )

    code, output, error = invoke("runner", "import-openapi", str(FIXTURE))
    assert (code, error) == (0, "")
    assert json.loads(output) == {"route_count": 6}

    code, output, error = invoke(
        "runner", "credential", "add", "--role", "authenticated",
        "--profile", "bearer", "--label", "LOCAL SECRET LABEL",
        "--backend", "ephemeral-env",
    )
    assert (code, error) == (0, "")
    handle = json.loads(output)["credential_handle"]
    assert json.loads(output) == {
        "credential_handle": handle,
        "credential_source": {
            "kind": "environment",
            "variable": "HEEL_RUNNER_CREDENTIAL_" + handle.upper(),
        },
        "registered_count": 1,
    }
    assert "LOCAL SECRET LABEL" not in output

    code, output, error = invoke(
        "runner", "map", "--scenario", "anonymous_authenticated_read",
        "--method", "HEAD", "--route", "/health",
    )
    assert (code, error) == (0, "")
    assert json.loads(output) == {
        "mapping_count": 1,
        "scenario_ids": ["anonymous_authenticated_read"],
    }

    code, output, error = invoke("runner", "prepare")
    assert (code, error) == (0, "")
    assert json.loads(output) == {
        "credential_count": 1,
        "mapping_count": 1,
        "route_count": 6,
        "scenario_ids": ["anonymous_authenticated_read"],
    }
    rendered = output.lower()
    for forbidden in ("handle", "label", "fixture", "/health", "path", "route_template"):
        assert forbidden not in rendered


def test_map_reads_fixture_ids_only_from_bounded_inherited_fd(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    bind_home(home)
    assert invoke("runner", "import-openapi", str(FIXTURE))[0] == 0

    fixture_file = tmp_path / "fixtures"
    fixture_file.write_text('{"item_id":"private-local-fixture"}', encoding="utf-8")
    descriptor = os.open(fixture_file, os.O_RDONLY)
    os.set_inheritable(descriptor, True)
    try:
        code, output, error = invoke(
            "runner", "map", "--scenario", "object_ownership_read",
            "--method", "GET", "--route", "/items/{item_id}",
            "--fixture-fd", str(descriptor),
        )
    finally:
        os.close(descriptor)
    assert (code, error) == (0, "")
    assert "private-local-fixture" not in output
    assert json.loads(output)["scenario_ids"] == ["object_ownership_read"]


def test_runner_parser_disables_abbreviations_and_never_reflects_secret_shaped_argv(tmp_path, monkeypatch):
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "home"))
    marker = "super-private-marker"
    hostile_commands = (
        ("runner", "credential", "add", "--role", "authenticated", "--prof", "bearer"),
        ("runner", "credential", "add", "--password", marker),
        ("--token=" + marker, "runner", "prepare"),
        ("runner", "map", "--fixture", marker),
        ("runner", "prepare", "--origin", marker),
        ("runner", "prepare", "--runner-id", marker),
        ("runner", "credential", "add", "--handle-id", marker),
        (
            "runner", "credential", "add", "--role", "authenticated",
            "--profile", "anonymous", "--label", "local", "--backend", "ephemeral-env",
        ),
    )
    for command in hostile_commands:
        code, output, error = invoke(*command)
        assert code == 2
        assert output == ""
        assert error in {
            "Heel runner command was rejected.\n",
            "Heel runner credential could not be stored safely.\n",
        }
        assert marker not in error


def test_credential_add_plan_label_is_printed_and_the_secret_never_is(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    bind_home(home)
    secret = "private-plan-secret-0001"
    monkeypatch.setenv("HEEL_PRIVATE_SECRET", secret)
    code, output, error = invoke(
        "runner", "credential", "add", "--role", "lower_plan", "--profile", "bearer",
        "--label", "PRIVATE LOCAL LABEL", "--plan-label", "free", "--backend", "ephemeral-env",
    )
    assert (code, error) == (0, "")
    printed = json.loads(output)
    handle = printed["credential_handle"]
    assert printed == {
        "credential_handle": handle,
        "credential_source": {"kind": "environment", "variable": "HEEL_RUNNER_CREDENTIAL_" + handle.upper()},
        "plan_label": "free",
        "registered_count": 1,
        "role": "lower_plan",
    }
    assert secret not in output and "PRIVATE LOCAL LABEL" not in output
    # Labels are the operator's own words, not a closed set; roles stay fixed.
    code, output, error = invoke(
        "runner", "credential", "add", "--role", "higher_plan", "--profile", "bearer",
        "--label", "local", "--plan-label", "Team Plus 2026", "--backend", "ephemeral-env",
    )
    assert code == 0 and json.loads(output)["plan_label"] == "Team Plus 2026"
    labels = {item["semantic_role"]: item["plan_label"] for item in RunnerStore(home).list_credentials()}
    assert labels == {"lower_plan": "free", "higher_plan": "Team Plus 2026"}


def test_credential_add_rejects_invalid_or_duplicate_plan_labels_without_echo(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    bind_home(home)
    failure = "Heel runner credential could not be stored safely.\n"
    for role, plan_label in (
        ("lower_plan", "x" * 33), ("lower_plan", " free"), ("lower_plan", "free "), ("lower_plan", ""),
        ("lower_plan", "frée"), ("lower_plan", "fr\tee"), ("authenticated", "free"),
    ):
        code, output, error = invoke(
            "runner", "credential", "add", "--role", role, "--profile", "bearer",
            "--label", "local", "--plan-label", plan_label, "--backend", "ephemeral-env",
        )
        assert (code, output, error) == (2, "", failure), (role, plan_label)
    assert RunnerStore(home).list_credentials() == []
    assert invoke(
        "runner", "credential", "add", "--role", "lower_plan", "--profile", "bearer",
        "--label", "local", "--plan-label", "pro", "--backend", "ephemeral-env",
    )[0] == 0
    code, output, error = invoke(
        "runner", "credential", "add", "--role", "higher_plan", "--profile", "bearer",
        "--label", "local", "--plan-label", "pro", "--backend", "ephemeral-env",
    )
    assert (code, output, error) == (2, "", failure)


def test_legacy_credential_records_without_plan_label_stay_usable(tmp_path, monkeypatch):
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    bind_home(home)
    code, output, _ = invoke(
        "runner", "credential", "add", "--role", "lower_plan", "--profile", "bearer",
        "--label", "free", "--backend", "ephemeral-env",
    )
    assert code == 0 and set(json.loads(output)) == {"credential_handle", "credential_source", "registered_count"}
    (record,) = RunnerStore(home).list_credentials()
    assert set(record) == {
        "credential_handle_id", "semantic_role", "auth_profile", "label", "backend", "source_kind", "state",
    }
    # The on-disk record keeps the pre-T2a field set exactly.
    assert "plan_label" not in next((home / "runner" / "contexts").rglob("credentials.json")).read_text()
