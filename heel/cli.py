"""Heel CLI over the shared review and abuse-rehearsal capabilities.

`heel scope create` is the only path that can mint an authorization scope. It requires
explicit human confirmation and remains unavailable through the MCP and REST surfaces.
"""
from __future__ import annotations

import argparse
import contextlib
import getpass
import io
import json
import os
import platform
import stat
import sys
import time
import webbrowser

from . import __version__
from . import scope as scopemod
from .contracts import DataHandlingMode
from .mcp_server import (
    MAX_OPENAPI_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
    HeelServer,
    _json_within_limit,
    _success_tool_result,
)
from .store import Store


_SAFE_REVIEW_FAILURE = (
    "Heel OpenAPI review failed: input could not be read or reviewed safely."
)
_SAFE_CLOUD_FAILURE = "Heel Cloud could not complete the request safely."
_SAFE_RUNNER_IMPORT_FAILURE = "Heel runner OpenAPI import failed."
_SAFE_RUNNER_CREDENTIAL_FAILURE = "Heel runner credential could not be stored safely."
_SAFE_RUNNER_MAPPING_FAILURE = "Heel runner mapping could not be saved safely."
_SAFE_RUNNER_LIVE_FAILURE = "Heel runner live preparation is unavailable."
_OPENAPI_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load_bounded_openapi(path: str) -> dict:
    """Read one regular, non-symlink JSON file without exceeding the MCP limit."""
    descriptor = os.open(path, _OPENAPI_READ_FLAGS)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("OpenAPI input must be a regular file")
        if status.st_size > MAX_OPENAPI_PAYLOAD_BYTES:
            raise ValueError("OpenAPI input exceeds the local review limit")

        chunks = []
        remaining = MAX_OPENAPI_PAYLOAD_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_OPENAPI_PAYLOAD_BYTES:
            raise ValueError("OpenAPI input exceeds the local review limit")
    finally:
        os.close(descriptor)

    value = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    if type(value) is not dict:
        raise ValueError("OpenAPI input must be a JSON object")
    return value


def _review_openapi_file(path: str, *, as_json: bool) -> int:
    """Review a local file through the same pure service and exporters as MCP."""
    from .local_projects import LocalProjectStore
    from .review_export import review_to_json, review_to_markdown
    from .review_service import review_openapi

    try:
        specification = _load_bounded_openapi(path)
        review = review_openapi(specification, execution_mode="machine_local")
        if not _json_within_limit(
            _success_tool_result("heel_review_openapi", review),
            MAX_RESULT_BYTES,
        ):
            raise ValueError("review exceeds the shared MCP result limit")
        LocalProjectStore().save_review(review)
        rendered = review_to_json(review) if as_json else review_to_markdown(review)
    # This is the command's trust boundary: parser, analyzer, exporter, and storage errors
    # must fail closed without reflecting a path, OpenAPI value, or traceback.
    except Exception:
        print(_SAFE_REVIEW_FAILURE, file=sys.stderr)
        return 2

    sys.stdout.write(rendered)
    return 0


def _runner_store():
    from .runner.store import RunnerStore

    return RunnerStore()


def _runner_import_openapi(path: str) -> int:
    """Persist only the minimized local GET/HEAD inventory, never the document."""
    from .runner.openapi_routes import RouteInventory

    try:
        inventory = RouteInventory(_load_bounded_openapi(path))
        routes = inventory.read_routes()
        _runner_store().replace_routes(routes, source_digest=inventory.source_digest)
    except Exception:
        print(_SAFE_RUNNER_IMPORT_FAILURE, file=sys.stderr)
        return 2
    print(json.dumps({
        "methods": sorted({route["method"] for route in routes}),
        "routes": len(routes),
    }, sort_keys=True))
    return 0


def _runner_secret_from_fd(descriptor: int) -> bytes:
    from .runner.vault import EphemeralVault

    return EphemeralVault(fd=descriptor).load("0" * 32)


def _runner_credential_add(args) -> int:
    from .runner.store import new_credential_handle_id
    from .runner.vault import select_vault

    handle_id = args.handle_id or new_credential_handle_id()
    try:
        store = _runner_store()
        if any(
            item["credential_handle_id"] == handle_id
            for item in store.list_credentials()
        ):
            raise ValueError("duplicate credential handle")
        vault = select_vault(
            args.vault,
            env_name=args.env_name,
            fd=args.secret_fd,
        )
        if args.vault.startswith("ephemeral-"):
            # Resolve once now so a missing/oversized source cannot create metadata
            # that appears live-ready. The value is never attached to the record.
            vault.load(handle_id)
        else:
            if args.env_name is not None:
                raise ValueError("OS vault input must use getpass or an inherited FD")
            if args.secret_fd is not None:
                secret = _runner_secret_from_fd(args.secret_fd)
            else:
                if not sys.stdin.isatty():
                    raise ValueError("interactive secret input requires a TTY")
                secret = getpass.getpass("Canary credential: ").encode("utf-8")
            vault.store(handle_id, secret)
        record = store.add_credential(
            label=args.label,
            auth_profile=args.profile,
            handle_id=handle_id,
        )
    except Exception:
        print(_SAFE_RUNNER_CREDENTIAL_FAILURE, file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


def _runner_fixture_bindings(values: list[str]) -> list[dict[str, str]]:
    bindings: list[dict[str, str]] = []
    for value in values:
        if "=" not in value:
            raise ValueError("fixture binding must use NAME=LOCAL_ID")
        parameter_name, fixture_id = value.split("=", 1)
        bindings.append({"parameter_name": parameter_name, "fixture_id": fixture_id})
    return bindings


def _runner_map(args) -> int:
    from .runner.catalog import CATALOG_BY_ID

    try:
        catalog = CATALOG_BY_ID[args.scenario]
        record = _runner_store().save_mapping({
            "scenario_id": args.scenario,
            "method": args.method,
            "route_template": args.route,
            "semantic_auth_role": catalog["semantic_auth_role"],
            "auth_profile": catalog["auth_profile"],
            "credential_handle_id": args.handle_id,
            "fixture_bindings": _runner_fixture_bindings(args.fixture),
        })
    except Exception:
        print(_SAFE_RUNNER_MAPPING_FAILURE, file=sys.stderr)
        return 2
    print(json.dumps({
        "auth_profile": record["auth_profile"],
        "method": record["method"],
        "route_template": record["route_template"],
        "semantic_role": record["semantic_auth_role"],
    }, sort_keys=True))
    return 0


def _runner_prepare(args) -> int:
    try:
        store = _runner_store()
        routes = store.list_routes()
        mappings = store.list_mappings()
    except Exception:
        if args.live:
            print(_SAFE_RUNNER_LIVE_FAILURE, file=sys.stderr)
        else:
            print("Heel runner preparation failed.", file=sys.stderr)
        return 2
    if not args.live:
        print(json.dumps({
            "live": False,
            "mapped_scenarios": len(mappings),
            "network_calls": False,
            "ready_for_live": len(mappings) == 4,
            "routes": len(routes),
        }, sort_keys=True))
        return 0

    # Task 5 is a local compilation boundary. It creates no network authority and
    # uploads nothing; later control-plane tasks consume the safe projection.
    try:
        from .runner.catalog import CATALOG_IDS
        from .runner.compiler import CanaryCompiler
        from .runner.identity import SystemSecureSigner
        from .runner.vault import select_vault

        required = (
            args.workspace, args.project, args.environment_id,
            args.verification_digest, args.origin, args.runner_id,
            args.signer_label,
        )
        if any(value is None for value in required) or len(mappings) != 4:
            raise ValueError("live preparation inputs are incomplete")
        signer = SystemSecureSigner(args.signer_label)
        vault = select_vault(args.vault, env_name=args.env_name, fd=args.secret_fd)
        CanaryCompiler(signer, now_ms=int(time.time() * 1000), store=store, vault=vault).prepare_live()
        mapping_table = {item["scenario_id"]: item for item in mappings}
        handles = {
            scenario_id: mapping_table[scenario_id]["credential_handle_id"]
            for scenario_id in CATALOG_IDS
        }
        if any(value is None for value in handles.values()):
            raise ValueError("credential handles are incomplete")
        fixtures = {
            scenario_id: {
                item["parameter_name"]: item["fixture_id"]
                for item in mapping_table[scenario_id]["fixture_bindings"]
            }
            for scenario_id in CATALOG_IDS
        }
        result = CanaryCompiler(
            signer, now_ms=int(time.time() * 1000), store=store, vault=vault,
        ).compile_routes(
            routes,
            {
                "workspace_id": args.workspace,
                "project_id": args.project,
                "environment": {
                    "environment_id": args.environment_id,
                    "verification_record_digest": args.verification_digest,
                    "origin": args.origin,
                    "environment_class": args.environment_class,
                },
                "runner": {
                    "runner_id": args.runner_id,
                    "runner_key_id": signer.key_id,
                    "minimum_runner_version": "1",
                },
                "compiler": {"compiler_version": "1", "engine_version": "1"},
            },
            mappings=mapping_table,
            credential_handle_ids=handles,
            fixture_ids=fixtures,
        )
    except Exception:
        print(_SAFE_RUNNER_LIVE_FAILURE, file=sys.stderr)
        return 2
    print(json.dumps({
        "live": True,
        "manifest_digest": result.manifest["manifest_digest"],
        "network_calls": False,
        "projection": result.projection,
        "uploaded": False,
    }, sort_keys=True))
    return 0


def _cloud_services(origin: str):
    """Construct the one-origin machine continuity boundary lazily."""
    from .cloud_auth import CredentialStore
    from .cloud_client import CloudClient
    from .local_projects import LocalProjectStore
    from .sync_queue import SyncQueue

    store = CredentialStore(origin)
    return CloudClient(origin, store), SyncQueue(), LocalProjectStore()


def _cloud_login(client, *, device_name: str | None = None, open_browser: bool = True) -> int:
    from .cloud_client import CloudClientError

    selected_name = (device_name or platform.node() or "Heel device").strip()[:64]
    try:
        login = client.start_device_login(selected_name)
        print(f"Open {login.verification_uri}")
        print(f"Enter code: {login.user_code}")
        print("Heel will receive findings-sync access only after you approve in the browser.")
        if open_browser:
            try:
                webbrowser.open(login.verification_uri, new=2)
            except Exception:
                pass
        deadline = time.monotonic() + login.expires_in
        interval = login.interval
        while time.monotonic() < deadline:
            time.sleep(interval)
            try:
                poll = client.poll_device_login(login)
            except CloudClientError as error:
                if error.code == "slow_down" and error.interval is not None:
                    interval = error.interval
                    continue
                raise
            if poll.status == "pending":
                interval = poll.interval or interval
                continue
            if poll.status != "approved":
                print(f"Device authorization {poll.status}.", file=sys.stderr)
                return 2
            exchange = client.exchange_device_login(login)
            print(json.dumps({
                "authenticated": True,
                "workspace_ref": exchange.workspace_id,
                "capabilities": list(exchange.capabilities),
            }, indent=2))
            return 0
        print("Device authorization expired.", file=sys.stderr)
        return 2
    except CloudClientError as error:
        print(f"{_SAFE_CLOUD_FAILURE} ({error.code})", file=sys.stderr)
        return 1


def _cloud_status(client) -> int:
    from .cloud_client import CloudClientError

    try:
        status = client.account_status()
    except CloudClientError as error:
        if error.code == "auth_required":
            print(json.dumps({"authenticated": False}, indent=2))
            return 1
        print(f"{_SAFE_CLOUD_FAILURE} ({error.code})", file=sys.stderr)
        return 1
    print(json.dumps({
        "authenticated": True,
        "device_id": status.device_id,
        "workspace_ref": status.workspace_ref,
        "role": status.role,
        "capabilities": list(status.capabilities),
    }, indent=2))
    return 0


def _cloud_projects(client, workspace_ref: str | None) -> int:
    from .cloud_client import CloudClientError

    try:
        workspace = workspace_ref or client.account_status().workspace_ref
        projects = client.list_projects(workspace)
    except CloudClientError as error:
        print(f"{_SAFE_CLOUD_FAILURE} ({error.code})", file=sys.stderr)
        return 1
    print(json.dumps({"workspace_ref": workspace, "projects": [
        {
            "project_ref": project.project_ref,
            "name": project.name,
            "created_by": project.created_by,
            "created_at": project.created_at,
        }
        for project in projects
    ]}, indent=2))
    return 0


def _cloud_sync_prepare(
    client, queue, projects, review_id: str, workspace_ref: str, project_ref: str
) -> int:
    from .findings_sync import project_findings_sync
    from .review_contract import validate_review_envelope

    try:
        review = projects.get_review(review_id)
        if review is None:
            raise ValueError("review not found")
        review = validate_review_envelope(review)
        namespace_key = client.namespace_key(workspace_ref, project_ref)
        request = project_findings_sync(review, project_ref, namespace_key)
        record = queue.prepare(request, namespace_key, workspace_ref)
    except Exception:
        print(_SAFE_CLOUD_FAILURE, file=sys.stderr)
        return 1
    print(json.dumps({
        "state": "prepared",
        "workspace_ref": record.workspace_ref,
        "project_ref": record.project_ref,
        "request_digest": record.request_digest,
        "request": request,
        "privacy": "source documents and local review context stay on this machine",
        "next": (
            "Run heel cloud sync approve --workspace <workspace> --project <project> "
            f"--digest {record.request_digest} in an interactive terminal."
        ),
    }, indent=2))
    return 0


def _schedule_cloud_retry(queue, lease, error_code: str) -> None:
    code = (
        "approval_expired"
        if error_code == "approval_expired"
        else "transport_error"
        if error_code in {"unavailable", "temporarily_unavailable", "rate_limited"}
        else "server_rejected"
    )
    try:
        queue.schedule_retry(lease, time.time() + 30, code)
    except Exception:
        pass


def _cloud_sync_send(client, queue, lease) -> int:
    from .cloud_client import CloudClientError

    record = lease.record
    active_authority = lease
    if (
        record.human_approval is None
        or record.human_approval.expires_at <= time.time()
    ):
        print("The local approval expired; run the interactive approve command again.", file=sys.stderr)
        return 2
    try:
        approval = client.approve_findings(
            record.workspace_ref, record.project_ref, record.request_digest
        )
        bound = queue.bind_transport_approval(lease, approval)
        if bound is None:
            raise RuntimeError("sync lease was lost")
        active_authority = bound
        namespace_key = client.namespace_key(record.workspace_ref, record.project_ref)
        renewed = queue.renew(bound)
        if renewed is None:
            raise RuntimeError("sync lease was lost")
        active_authority = renewed
        if renewed.record.human_approval.expires_at <= time.time():
            print(
                "The local approval expired; run the interactive approve command again.",
                file=sys.stderr,
            )
            return 2
        permit = queue.begin_transmission(renewed)
        if permit is None:
            raise RuntimeError("sync transmission authority was lost")
        active_authority = permit
        receipt = client.sync_findings(permit, namespace_key)
        if not queue.complete(permit, receipt):
            raise RuntimeError("sync lease was lost")
    except CloudClientError as error:
        _schedule_cloud_retry(queue, active_authority, error.code)
        print(f"{_SAFE_CLOUD_FAILURE} ({error.code})", file=sys.stderr)
        return 1
    except Exception:
        _schedule_cloud_retry(queue, active_authority, "unavailable")
        print(_SAFE_CLOUD_FAILURE, file=sys.stderr)
        return 1
    print(json.dumps({
        "state": "synced",
        "workspace_ref": record.workspace_ref,
        "project_ref": record.project_ref,
        "request_digest": record.request_digest,
        "receipt": receipt,
    }, indent=2))
    return 0


def _cloud_sync_approve(
    client, queue, workspace_ref: str, project_ref: str, request_digest: str
) -> int:
    from .sync_queue import HumanSyncApproval

    record = queue.get(workspace_ref, project_ref, request_digest)
    if record is None:
        print("Prepared findings sync was not found.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive terminal input and output are required for sync approval.", file=sys.stderr)
        return 2
    print("Heel will send exactly this canonical findings-only JSON:")
    print(record.request_json)
    print(f"Cloud origin: {client.cloud_base_url}")
    print(f"Workspace: {record.workspace_ref}")
    print(f"Project: {record.project_ref}")
    print(f"SHA-256 digest: {record.request_digest}")
    print(
        "This never includes raw OpenAPI, routes, descriptions, examples, answers, "
        "reasons, secrets, or credentials."
    )
    phrase = f"SYNC {record.request_digest[:12]}"
    typed = input(f"Type {phrase} to approve for up to 10 minutes: ")
    if typed != phrase:
        print("Approval phrase did not match; nothing was sent.", file=sys.stderr)
        return 2
    approved_at = time.time()
    try:
        queue.record_human_approval(HumanSyncApproval(
            record.workspace_ref,
            record.project_ref,
            record.request_digest,
            approved_at,
            approved_at + 600,
        ))
        lease = queue.claim(
            record.workspace_ref, record.project_ref, record.request_digest
        )
        if lease is None:
            raise RuntimeError("approved sync was not claimable")
    except Exception:
        print(_SAFE_CLOUD_FAILURE, file=sys.stderr)
        return 1
    return _cloud_sync_send(client, queue, lease)


def _sync_record_public(record) -> dict:
    now = time.time()
    if record.receipt is not None:
        state = "synced"
    elif record.human_approval is None or record.human_approval.expires_at <= now:
        state = "prepared"
    elif record.retry.lease_expires_at is not None and record.retry.lease_expires_at > now:
        state = "sending"
    elif record.retry.next_attempt_at is not None:
        state = "retry_ready" if record.retry.next_attempt_at <= now else "retry_scheduled"
    else:
        state = "approved"
    return {
        "state": state,
        "workspace_ref": record.workspace_ref,
        "project_ref": record.project_ref,
        "request_digest": record.request_digest,
        "attempts": record.retry.attempts,
        "last_error_code": record.retry.last_error_code,
        "receipt": record.receipt,
    }


def _cloud_sync_status(queue, workspace_ref: str, project_ref: str | None, digest: str | None) -> int:
    if (project_ref is None) != (digest is None):
        print("--project and --digest must be provided together.", file=sys.stderr)
        return 2
    try:
        records = (
            [queue.get(workspace_ref, project_ref, digest)]
            if project_ref is not None and digest is not None
            else queue.list(workspace_ref)
        )
        public = [_sync_record_public(record) for record in records if record is not None]
    except Exception:
        print(_SAFE_CLOUD_FAILURE, file=sys.stderr)
        return 1
    print(json.dumps({"syncs": public}, indent=2))
    return 0


def _cloud_sync_retry(client, queue, workspace_ref: str, project_ref: str, digest: str) -> int:
    try:
        lease = queue.claim(workspace_ref, project_ref, digest)
    except Exception:
        lease = None
    if lease is None:
        print("No live human-approved sync is ready to retry.", file=sys.stderr)
        return 2
    return _cloud_sync_send(client, queue, lease)


def _cloud_reviews(client, workspace_ref: str, project_ref: str) -> int:
    from .cloud_client import CloudClientError

    try:
        reviews = client.list_history(workspace_ref, project_ref)
    except CloudClientError as error:
        print(f"{_SAFE_CLOUD_FAILURE} ({error.code})", file=sys.stderr)
        return 1
    print(json.dumps({
        "workspace_ref": workspace_ref,
        "project_ref": project_ref,
        "reviews": list(reviews),
    }, indent=2))
    return 0


def _doctor() -> int:
    """Self-check: install, data dir, signing-key posture, scenario library, capability."""
    ok, warn = [], []
    ok.append(f"heel {__version__} · python ok")
    home = scopemod.heel_home()
    try:
        os.makedirs(home, exist_ok=True)
        t = os.path.join(home, ".doctor"); open(t, "w").close(); os.remove(t)
        ok.append(f"HEEL_HOME writable: {home}")
    except Exception as e:
        warn.append(f"HEEL_HOME not writable ({home}): {e}")
    if os.environ.get("HEEL_SIGNING_KEY"):
        ok.append("signing key: external (HEEL_SIGNING_KEY): production posture ✓")
    else:
        warn.append("signing key is co-located in HEEL_HOME. For production set HEEL_SIGNING_KEY to a "
                    "path OUTSIDE the data dir (key+data separation). See SECURITY.md.")
    from .scenarios import all_seed_scenarios
    scs = all_seed_scenarios()
    cats = {s.category.value for s in scs}
    (ok if len(cats) == 10 else warn).append(f"scenario library: {len(scs)} scenarios across {len(cats)}/10 categories")
    try:
        from .agents import run_adversarial
        from .backtest import score_target
        from .targets import get_target
        out = run_adversarial(get_target("synthetic-saas"), scs, lambda *a: None, "doctor")
        cov = score_target(get_target("synthetic-saas"), out)["coverage"]
        ok.append(f"capability self-check: synthetic backtest ran (coverage {cov})")
    except Exception as e:
        warn.append(f"capability self-check FAILED: {e}")
    for line in ok:
        print(f"  [ok]   {line}")
    for line in warn:
        print(f"  [warn] {line}")
    print(f"\nheel doctor: {'OK' if not any('FAILED' in w or 'not writable' in w for w in warn) else 'PROBLEMS'}"
          f" ({len(ok)} ok, {len(warn)} warnings)")
    return 0 if not any("FAILED" in w or "not writable" in w for w in warn) else 1


def _server():
    home = scopemod.ensure_home()
    return HeelServer(Store(os.path.join(home, "heel.db")))


def _caller():
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:operator"


def _import_validate(path: str) -> int:
    from .importers import ProductModelError, load_product_model, target_from_product_model, validate_product_model
    try:
        model = load_product_model(path)
    except ProductModelError as e:
        print(f"ProductModel validation: FAIL ({e})")
        return 1
    result = validate_product_model(model)
    print(f"ProductModel validation: {'PASS' if result.ok else 'FAIL'}")
    print(f"  schema: {result.schema_version}")
    print(f"  summary: {result.summary}")
    if result.errors:
        print("  errors:")
        for err in result.errors:
            print(f"    - {err}")
    if result.warnings:
        print("  warnings:")
        for warn in result.warnings:
            print(f"    - {warn}")
    if not result.ok:
        return 1
    target = target_from_product_model(model)
    print(f"  target id: {target.id}")
    print(f"  affordances: {len(target.affordances)}")
    print(f"  safety notes: {len(target.safety_notes)}")
    print("  mode: imported-model rehearsal only; no live probing or network calls")
    print("  authorization: signed human-created scope required before any run")
    return 0


def _openapi_import(path: str, out_path: str) -> int:
    from .openapi_import import OpenAPIImportError, import_openapi_file, write_product_model
    try:
        model = import_openapi_file(path)
        write_product_model(model, out_path)
    except OpenAPIImportError as e:
        print(f"OpenAPI import: FAIL ({e})")
        return 1
    warnings = model.get("import_warnings", [])
    print("OpenAPI import: PASS")
    print(f"  wrote: {out_path}")
    print(f"  product_id: {model['product_id']}")
    print(f"  affordance draft count: {sum(len(model.get(f, [])) for f in ('exports', 'identity_auth_flows', 'billing_objects', 'meters', 'roles', 'integration_oauth_apps', 'webhooks', 'support_admin_actions', 'agent_tools'))}")
    print(f"  warnings: {len(warnings)}")
    for warning in warnings:
        print(f"    - {warning}")
    print("  mode: local OpenAPI-to-ProductModel draft only; no live probing or network calls")
    return 0


def _scenario_validate(path: str) -> int:
    from .scenario_validate import render_validation_report, validate_scenario_file

    results = validate_scenario_file(path)
    print(render_validation_report(results))
    return 0 if results and all(result.ok for result in results) else 1


def _scenario_explain(scenario_id: str) -> int:
    from .scenario_validate import explain_scenario

    explanation = explain_scenario(scenario_id)
    if explanation is None:
        print(f"Scenario explain: FAIL (unknown scenario id '{scenario_id}')")
        return 1
    print(explanation)
    return 0


def _mode_payload(mode, target_source: str, resolved_target: str | None = None) -> dict:
    payload = mode.to_dict()
    payload["target_source"] = target_source
    if resolved_target:
        payload["resolved_target"] = resolved_target
    return payload


def _resolve_run_target_for_mode(mode, target_arg: str | None) -> tuple[str | None, str, dict | None, str | None]:
    if not target_arg:
        return None, "", None, f"Mode {mode.id} requires --target"
    if target_arg.lower().endswith(".json") and os.path.isfile(target_arg):
        from .importers import ProductModelError, load_product_model, target_from_product_model
        from .targets import register_imported_target

        try:
            model = load_product_model(target_arg)
            target = register_imported_target(target_from_product_model(model))
        except ProductModelError as e:
            return None, "", None, f"ProductModel validation: FAIL ({e})"
        except Exception as e:
            return None, "", None, f"ProductModel target registration: FAIL ({e})"
        return target.id, "ProductModel/EntitlementGraph import; no live probing", model, None
    if mode.id == "existing-imported":
        return None, "", None, "Mode existing-imported requires --target to be a ProductModel JSON file"
    if mode.id == "staging":
        return target_arg, "canary staging target", None, None
    return target_arg, "built-in synthetic target", None, None


def _scope_for_mode(mode, scope_id: str | None):
    if not mode.requires_scope:
        return None, None
    if not scope_id:
        return None, f"Mode {mode.id} requires --scope with a human-created signed AuthorizationScope"
    scope = scopemod.get_scope(scope_id)
    if scope is None:
        return None, f"Mode {mode.id} rejected: unknown scope_id '{scope_id}'"
    ok, reason = scopemod.verify(scope)
    if not ok:
        return None, f"Mode {mode.id} rejected: scope invalid: {reason}"
    if mode.id == "staging":
        from .modes import scope_limit_errors

        violations = scope_limit_errors(mode, scope.rate_and_resource_limits)
        if violations:
            return None, (
                "Mode staging requires stricter signed scope limits: "
                + ", ".join(violations)
            )
    return scope, None


def _canary_errors_for_mode(mode, model: dict | None, canary_accounts: list[str] | None) -> list[str]:
    if not mode.requires_canary_accounts:
        return []
    if canary_accounts:
        return []
    if model and model.get("canary_accounts"):
        return []
    return [f"Mode {mode.id} requires canary account metadata"]


def _run_with_mode(args) -> int:
    from .modes import get_mode

    try:
        mode = get_mode(args.mode)
    except ValueError as e:
        print(f"REJECTED: {e}")
        return 2

    if mode.id == "launch-review":
        if not args.before or not args.after:
            print("Mode launch-review requires --before and --after ProductModel JSON files")
            return 2
        print("mode: launch-review")
        print("safety: static ProductModel diff; no live probing")
        return _launch_review(args)

    scope, scope_error = _scope_for_mode(mode, args.scope)
    if scope_error:
        print(scope_error)
        return 2

    if mode.id == "incident-regression":
        if not args.target:
            print("Mode incident-regression requires --target")
            return 2
        from .regressions import resolve_target_argument, run_regressions

        srv = _server()
        caller = _caller()
        try:
            target = resolve_target_argument(args.target)
            results = run_regressions(srv.store, srv, args.scope, target, caller)
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1
        print(json.dumps({
            "mode": _mode_payload(mode, "stored abuse regressions", target),
            "results": results,
        }, indent=2, default=str))
        return 0

    target, target_source, model, target_error = _resolve_run_target_for_mode(mode, args.target)
    if target_error:
        print(target_error)
        return 2
    canary_errors = _canary_errors_for_mode(mode, model, args.canary_account)
    if canary_errors:
        print("; ".join(canary_errors))
        return 2

    srv = _server()
    caller = _caller()
    try:
        run_args = {"scope_id": args.scope, "target": target, "scenario_ids": args.scenario}
        if args.packs:
            run_args["packs"] = [p.strip() for p in args.packs.split(",") if p.strip()]
        r = srv.heel_run(run_args, caller)
        r = dict(r)
        r["mode"] = _mode_payload(mode, target_source, target)
        if args.economic:
            r["economic_report"] = _report(srv, r["run_id"], caller, economic=True,
                                           economic_assumptions=args.economic_assumptions)
        print(json.dumps(r, indent=2))
    except Exception as e:
        print(f"REJECTED: {e}")
        return 1
    return 0


def _launch_review(args) -> int:
    from .importers import ProductModelError
    from .launch_review import load_and_review, render_human_summary, review_git_diff, review_to_json
    try:
        if getattr(args, "diff", None):
            review = review_git_diff(args.diff)
        else:
            review = load_and_review(args.before, args.after)
    except ProductModelError as e:
        print(f"Launch review: FAIL ({e})")
        return 2
    print(render_human_summary(review))
    print("JSON report:")
    print(review_to_json(review))
    return 2 if review.launch_gate_status == "block" else 1 if review.launch_gate_status == "warn" else 0


def _report(srv: HeelServer, run_id: str, caller: str, economic: bool = False,
            economic_assumptions: str | None = None) -> dict:
    findings = srv.heel_get_findings({"run_id": run_id}, caller)["findings"]
    row = srv.store.get_run(run_id)
    report = {
        "run_id": run_id,
        "status": row["status"] if row else None,
        "target": row["target"] if row else None,
        "caller": row["caller"] if row else None,
        "economic": bool(economic),
        "findings": findings,
    }
    try:
        report["coverage"] = srv.heel_get_coverage({"run_id": run_id}, caller)["coverage"]
    except Exception:
        report["coverage"] = None
    if not economic:
        return report

    from .economics import estimate_economic_impact, load_assumptions, rank_by_economic_risk

    assumptions = load_assumptions(economic_assumptions)
    enriched = []
    for finding in findings:
        f = dict(finding)
        f["economic_impact"] = estimate_economic_impact(f, assumptions=assumptions).to_dict()
        enriched.append(f)
    ranked = rank_by_economic_risk(enriched)
    report["findings"] = ranked
    report["economic_summary"] = {
        "top_label": ranked[0]["economic_impact"]["label"] if ranked else None,
        "top_estimated_monthly_range": ranked[0]["economic_impact"]["estimated_monthly_range"] if ranked else None,
        "unknowns_present": any(f["economic_impact"]["unknowns"] for f in ranked),
        "note": "Economic impact is directional and separate from security severity; assumptions and unknowns are shown per finding.",
    }
    return report


def main(argv=None):
    selected_argv = list(sys.argv[1:] if argv is None else argv)
    if selected_argv[:1] == ["runner"] and any(
        value == "--secret" or value.startswith("--secret=")
        for value in selected_argv
    ):
        print(_SAFE_RUNNER_CREDENTIAL_FAILURE, file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(prog="heel", description="Heel: agent-native abuse-simulation tool")
    ap.add_argument("--version", action="version", version=f"heel {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("doctor", help="self-check: install, data dir, signing-key posture, capability")
    sub.add_parser("eval", help="run the honest held-out detection eval and print the headline")
    bench = sub.add_parser("bench", help="run or render the HeelBench public benchmark")
    bench_sub = bench.add_subparsers(dest="bcmd", required=True)
    bench_run = bench_sub.add_parser("run", help="run HeelBench and emit canonical JSON")
    bench_run.add_argument("--blind-targets", type=int, default=24, help="number of blind synthetic targets")
    bench_run.add_argument("--workers", type=int, default=6, help="blind-eval worker threads")
    bench_report = bench_sub.add_parser("report", help="render a HeelBench report")
    bench_report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    bench_report.add_argument("--blind-targets", type=int, default=24, help="number of blind synthetic targets")
    bench_report.add_argument("--workers", type=int, default=6, help="blind-eval worker threads")

    review = sub.add_parser(
        "review",
        help="review local product definitions without an account or network access",
    )
    review_sub = review.add_subparsers(dest="reviewcmd", required=True)
    review_openapi_parser = review_sub.add_parser(
        "openapi",
        help="review a local OpenAPI JSON file and save the result under HEEL_HOME",
    )
    review_openapi_parser.add_argument("path", metavar="PATH")
    review_openapi_parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="emit the canonical heel.review.v1 JSON envelope",
    )

    runner = sub.add_parser(
        "runner", help="prepare customer-local verified canary rehearsals",
    )
    runner_sub = runner.add_subparsers(dest="runnercmd", required=True)
    runner_import = runner_sub.add_parser(
        "import-openapi", help="import only a minimized local GET/HEAD route inventory",
    )
    runner_import.add_argument("path", metavar="PATH")
    runner_credential = runner_sub.add_parser(
        "credential", help="manage opaque local canary credential handles",
    )
    runner_credential_sub = runner_credential.add_subparsers(
        dest="runnercredentialcmd", required=True,
    )
    runner_credential_add = runner_credential_sub.add_parser(
        "add", help="store a canary credential in a secure or ephemeral provider",
    )
    runner_credential_add.add_argument(
        "--profile", required=True,
        choices=("anonymous", "bearer", "cookie_jar", "x_api_key"),
    )
    runner_credential_add.add_argument("--label", required=True)
    runner_credential_add.add_argument("--handle-id")
    runner_credential_add.add_argument(
        "--vault", required=True,
        choices=("keychain", "secret-service", "ephemeral-env", "ephemeral-fd"),
    )
    runner_credential_add.add_argument("--env-name")
    runner_credential_add.add_argument("--secret-fd", type=int)
    runner_map = runner_sub.add_parser(
        "map", help="bind one immutable scenario to one imported read route",
    )
    runner_map.add_argument(
        "--scenario", required=True,
        choices=(
            "anonymous_authenticated_read", "object_ownership_read",
            "role_bound_read", "plan_entitlement_read",
        ),
    )
    runner_map.add_argument("--method", required=True, choices=("GET", "HEAD"))
    runner_map.add_argument("--route", required=True)
    runner_map.add_argument("--handle-id")
    runner_map.add_argument("--fixture", action="append", default=[])
    runner_prepare = runner_sub.add_parser(
        "prepare", help="review readiness or compile one local immutable rehearsal",
    )
    runner_prepare.add_argument("--live", action="store_true")
    runner_prepare.add_argument("--workspace")
    runner_prepare.add_argument("--project")
    runner_prepare.add_argument("--environment-id")
    runner_prepare.add_argument("--environment-class", choices=("staging", "sandbox"), default="staging")
    runner_prepare.add_argument("--verification-digest")
    runner_prepare.add_argument("--origin")
    runner_prepare.add_argument("--runner-id")
    runner_prepare.add_argument("--signer-label")
    runner_prepare.add_argument(
        "--vault", choices=("keychain", "secret-service", "ephemeral-env", "ephemeral-fd"),
        default="keychain" if platform.system() == "Darwin" else "secret-service",
    )
    runner_prepare.add_argument("--env-name")
    runner_prepare.add_argument("--secret-fd", type=int)

    cloud = sub.add_parser(
        "cloud",
        help="connect the local Heel agent to findings-only hosted continuity",
    )
    cloud.add_argument(
        "--origin",
        default=os.environ.get("HEEL_CLOUD_ORIGIN"),
        help="canonical Heel Cloud origin (or set HEEL_CLOUD_ORIGIN)",
    )
    cloud_sub = cloud.add_subparsers(dest="cloudcmd", required=True)
    cloud_login = cloud_sub.add_parser("login", help="authorize this machine in the browser")
    cloud_login.add_argument("--device-name")
    cloud_login.add_argument(
        "--no-open", action="store_true", help="print the verification URL without opening it"
    )
    cloud_sub.add_parser("status", help="show the live device/workspace authorization")
    cloud_sub.add_parser("logout", help="revoke this device grant and delete local credentials")
    cloud_projects = cloud_sub.add_parser("projects", help="list authorized cloud projects")
    cloud_projects.add_argument("--workspace")
    cloud_reviews = cloud_sub.add_parser("reviews", help="list findings-only hosted history")
    cloud_reviews.add_argument("--workspace", required=True)
    cloud_reviews.add_argument("--project", required=True)
    cloud_sync = cloud_sub.add_parser("sync", help="prepare and explicitly approve findings-only sync")
    cloud_sync_sub = cloud_sync.add_subparsers(dest="syncmd", required=True)
    sync_prepare = cloud_sync_sub.add_parser(
        "prepare", help="prepare an immutable findings-only request; sends no findings"
    )
    sync_prepare.add_argument("--review", required=True)
    sync_prepare.add_argument("--workspace", required=True)
    sync_prepare.add_argument("--project", required=True)
    sync_approve = cloud_sync_sub.add_parser(
        "approve", help="interactive human approval and send for one exact digest"
    )
    sync_approve.add_argument("--workspace", required=True)
    sync_approve.add_argument("--project", required=True)
    sync_approve.add_argument("--digest", required=True)
    sync_retry = cloud_sync_sub.add_parser(
        "retry", help="retry a still-live, previously human-approved exact digest"
    )
    sync_retry.add_argument("--workspace", required=True)
    sync_retry.add_argument("--project", required=True)
    sync_retry.add_argument("--digest", required=True)
    sync_status = cloud_sync_sub.add_parser("status", help="show local sync state")
    sync_status.add_argument("--workspace", required=True)
    sync_status.add_argument("--project")
    sync_status.add_argument("--digest")
    sync_receipt = cloud_sync_sub.add_parser("receipt", help="show one local validated receipt")
    sync_receipt.add_argument("--workspace", required=True)
    sync_receipt.add_argument("--project", required=True)
    sync_receipt.add_argument("--digest", required=True)

    init = sub.add_parser("init", help="initialize local Heel artifacts")
    init.add_argument("--from-openapi", dest="from_openapi", help="local OpenAPI JSON/YAML file to convert into a ProductModel draft")
    init.add_argument("--out", required=True, help="ProductModel JSON output path")

    sc = sub.add_parser("scope", help="manage authorization scopes (creation is out-of-band, human-only)")
    scs = sc.add_subparsers(dest="scmd", required=True)
    sccreate = scs.add_parser("create", help="OUT-OF-BAND human scope creation (requires --confirm)")
    sccreate.add_argument("--target", action="append", required=True, help="allowlisted target id (repeatable)")
    sccreate.add_argument("--operator", default=None, help="approver identity (defaults to current user)")
    sccreate.add_argument("--ttl", type=int, default=7 * 24 * 3600)
    sccreate.add_argument("--confirm", action="store_true", help="explicit human confirmation (required)")
    scs.add_parser("list", help="list scopes (read; no secrets)")

    from .modes import MODES

    runp = sub.add_parser("run", help="run an abuse sim or static mode workflow")
    runp.add_argument("--mode", choices=sorted(MODES), default="synthetic")
    runp.add_argument("--scope")
    runp.add_argument("--target")
    runp.add_argument("--before", help="before ProductModel JSON for --mode launch-review")
    runp.add_argument("--after", help="after ProductModel JSON for --mode launch-review")
    runp.add_argument("--canary-account", action="append", help="canary account metadata for staging modes")
    runp.add_argument("--scenario", action="append")
    runp.add_argument("--packs", help="comma-separated scenario packs to run")
    runp.add_argument("--economic", action="store_true", help="include economic severity in the run output")
    runp.add_argument("--economic-assumptions", help="optional EconomicAssumptions JSON file")

    for name in ("findings", "coverage", "log"):
        p = sub.add_parser(name)
        p.add_argument("--run", required=True)
    report = sub.add_parser("report", help="print a run report with optional economic severity")
    report.add_argument("--run", required=True)
    report.add_argument("--economic", action="store_true")
    report.add_argument("--economic-assumptions", help="optional EconomicAssumptions JSON file")
    scn = sub.add_parser("scenarios")
    scn.add_argument("--filter")
    scn.add_argument("--pack")
    scenario = sub.add_parser("scenario", help="validate and explain declarative scenario pack entries")
    scenario_sub = scenario.add_subparsers(dest="scenariocmd", required=True)
    scenario_validate = scenario_sub.add_parser("validate", help="validate a scenario JSON object or list")
    scenario_validate.add_argument("path")
    scenario_explain = scenario_sub.add_parser("explain", help="explain a known scenario id")
    scenario_explain.add_argument("scenario_id")
    imp = sub.add_parser("import", help="validate sanitized target import models; no live probing")
    imps = imp.add_subparsers(dest="icmd", required=True)
    impv = imps.add_parser("validate", help="validate a ProductModel JSON file")
    impv.add_argument("path")
    impo = imps.add_parser("openapi", help="convert a local OpenAPI spec into a ProductModel JSON draft")
    impo.add_argument("path")
    impo.add_argument("--out", required=True, help="ProductModel JSON output path")
    incident = sub.add_parser("incident", help="turn sanitized abuse incidents into local scenario drafts")
    incidents = incident.add_subparsers(dest="incmd", required=True)
    incident_import = incidents.add_parser("import", help="validate and store a sanitized incident JSON file")
    incident_import.add_argument("path")
    incident_draft = incidents.add_parser("draft-scenario", help="write and print a local scenario draft")
    incident_draft.add_argument("incident_id")
    incident_reg = incidents.add_parser("add-regression", help="write and print a canary-only regression draft")
    incident_reg.add_argument("incident_id")
    incident_review = incidents.add_parser("review", help="print exactly what incident drafts would add")
    incident_review.add_argument("incident_id")
    launch = sub.add_parser("launch-review", help="compare ProductModel changes before launch")
    launch_inputs = launch.add_mutually_exclusive_group(required=True)
    launch_inputs.add_argument("--diff", help="git revision range containing a ProductModel JSON change")
    launch_inputs.add_argument("--before", help="ProductModel JSON before the launch change")
    launch.add_argument("--after", help="ProductModel JSON after the launch change")
    reg = sub.add_parser("regress", help="turn findings into reusable abuse regression tests")
    regs = reg.add_subparsers(dest="rcmd", required=True)
    regadd = regs.add_parser("add", help="create a regression from a stored finding")
    regadd.add_argument("--run", required=True)
    regadd.add_argument("--vector", required=True)
    regadd.add_argument("--name", required=True)
    regs.add_parser("list", help="list abuse regressions")
    regrun = regs.add_parser("run", help="run stored regressions within an existing signed scope")
    regrun.add_argument("--target", required=True)
    regrun.add_argument("--scope", required=True)
    regexp = regs.add_parser("export", help="export regression specs and results")
    regexp.add_argument("--format", choices=["json"], required=True)
    controls = sub.add_parser("controls", help="simulate candidate controls for stored or imported findings")
    control_sub = controls.add_subparsers(dest="ccmd", required=True)
    control_sim = control_sub.add_parser("simulate", help="offline control simulation; no live target is touched")
    control_input = control_sim.add_mutually_exclusive_group(required=True)
    control_input.add_argument("--vector", help="stored vector id to simulate")
    control_input.add_argument("--finding-json", help="path to one finding JSON object")
    control_input.add_argument("--run", help="stored run id to simulate")

    if selected_argv[:1] == ["runner"]:
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                args = ap.parse_args(selected_argv)
        except SystemExit as error:
            if error.code == 0:
                return 0
            print("Heel runner command was rejected.", file=sys.stderr)
            return 2
    else:
        args = ap.parse_args(selected_argv)
    if args.cmd is None:
        ap.print_help()
        return 0
    if args.cmd == "doctor":
        return _doctor()
    if args.cmd == "eval":
        from .heldout_eval import heldout_eval
        print(heldout_eval().get("headline", "(no held-out test set installed)"))
        return 0
    if args.cmd == "bench":
        from .bench import format_report, run_benchmark
        report = run_benchmark(blind_targets=args.blind_targets, blind_workers=args.workers)
        output_format = "json" if args.bcmd == "run" else args.format
        print(format_report(report, output_format))
        return 0
    if args.cmd == "review" and args.reviewcmd == "openapi":
        return _review_openapi_file(args.path, as_json=args.as_json)
    if args.cmd == "runner":
        if args.runnercmd == "import-openapi":
            return _runner_import_openapi(args.path)
        if args.runnercmd == "credential" and args.runnercredentialcmd == "add":
            return _runner_credential_add(args)
        if args.runnercmd == "map":
            return _runner_map(args)
        if args.runnercmd == "prepare":
            return _runner_prepare(args)
    if args.cmd == "cloud":
        if not args.origin:
            print(
                "Heel Cloud origin is required; set HEEL_CLOUD_ORIGIN or pass --origin.",
                file=sys.stderr,
            )
            return 2
        try:
            client, queue, projects = _cloud_services(args.origin)
            if args.cloudcmd == "login":
                return _cloud_login(
                    client,
                    device_name=args.device_name,
                    open_browser=not args.no_open,
                )
            if args.cloudcmd == "status":
                return _cloud_status(client)
            if args.cloudcmd == "logout":
                client.logout()
                print(json.dumps({"authenticated": False, "revoked": True}, indent=2))
                return 0
            if args.cloudcmd == "projects":
                return _cloud_projects(client, args.workspace)
            if args.cloudcmd == "reviews":
                return _cloud_reviews(client, args.workspace, args.project)
            if args.cloudcmd == "sync" and args.syncmd == "prepare":
                return _cloud_sync_prepare(
                    client, queue, projects, args.review, args.workspace, args.project
                )
            if args.cloudcmd == "sync" and args.syncmd == "approve":
                return _cloud_sync_approve(
                    client, queue, args.workspace, args.project, args.digest
                )
            if args.cloudcmd == "sync" and args.syncmd == "retry":
                return _cloud_sync_retry(
                    client, queue, args.workspace, args.project, args.digest
                )
            if args.cloudcmd == "sync" and args.syncmd == "status":
                return _cloud_sync_status(
                    queue, args.workspace, args.project, args.digest
                )
            if args.cloudcmd == "sync" and args.syncmd == "receipt":
                record = queue.get(args.workspace, args.project, args.digest)
                if record is None or record.receipt is None:
                    print("A validated receipt was not found.", file=sys.stderr)
                    return 1
                print(json.dumps({
                    "workspace_ref": record.workspace_ref,
                    "project_ref": record.project_ref,
                    "request_digest": record.request_digest,
                    "receipt": record.receipt,
                }, indent=2))
                return 0
        except Exception:
            print(_SAFE_CLOUD_FAILURE, file=sys.stderr)
            return 1
    if args.cmd == "init":
        if not args.from_openapi:
            print("OpenAPI import: FAIL (--from-openapi is required for init)")
            return 2
        return _openapi_import(args.from_openapi, args.out)
    if args.cmd == "launch-review":
        if not args.diff and not args.after:
            print("Launch review: FAIL (--after is required with --before)")
            return 2
        return _launch_review(args)
    if args.cmd == "import" and args.icmd == "validate":
        return _import_validate(args.path)
    if args.cmd == "import" and args.icmd == "openapi":
        return _openapi_import(args.path, args.out)
    if args.cmd == "scenario" and args.scenariocmd == "validate":
        return _scenario_validate(args.path)
    if args.cmd == "scenario" and args.scenariocmd == "explain":
        return _scenario_explain(args.scenario_id)

    if args.cmd == "incident":
        from .incident import IncidentError, add_regression_draft, draft_scenario, import_incident, review_incident
        try:
            if args.incmd == "import":
                print(json.dumps(import_incident(args.path), indent=2, default=str))
                return 0
            if args.incmd == "draft-scenario":
                print(json.dumps(draft_scenario(args.incident_id), indent=2, default=str))
                return 0
            if args.incmd == "add-regression":
                print(json.dumps(add_regression_draft(args.incident_id), indent=2, default=str))
                return 0
            if args.incmd == "review":
                print(json.dumps(review_incident(args.incident_id), indent=2, default=str))
                return 0
        except IncidentError as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "regress":
        from .regressions import (
            add_regression_from_finding,
            export_regressions,
            resolve_target_argument,
            run_regressions,
        )
        srv = _server()
        caller = _caller()
        try:
            if args.rcmd == "add":
                reg = add_regression_from_finding(srv.store, args.run, args.vector, args.name)
                print(json.dumps({"regression": reg}, indent=2, default=str))
                return 0
            if args.rcmd == "list":
                print(json.dumps({"regressions": srv.store.list_regressions()}, indent=2, default=str))
                return 0
            if args.rcmd == "run":
                target = resolve_target_argument(args.target)
                results = run_regressions(srv.store, srv, args.scope, target, caller)
                print(json.dumps({"results": results}, indent=2, default=str))
                return 0
            if args.rcmd == "export":
                print(json.dumps(export_regressions(srv.store), indent=2, default=str))
                return 0
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "controls" and args.ccmd == "simulate":
        from .control_simulator import load_finding_json, simulate_finding, simulate_run
        srv = _server()
        try:
            if args.finding_json:
                finding, options = load_finding_json(args.finding_json)
                print(json.dumps(simulate_finding(finding, **options), indent=2, default=str))
                return 0
            if args.vector:
                vector = srv.store.find_vector(args.vector)
                if not vector:
                    raise ValueError(f"unknown vector_id '{args.vector}'")
                print(json.dumps(simulate_finding(vector), indent=2, default=str))
                return 0
            if args.run:
                if not srv.store.get_run(args.run):
                    raise ValueError(f"unknown run_id '{args.run}'")
                print(json.dumps(simulate_run(srv.store.get_findings(args.run), run_id=args.run), indent=2, default=str))
                return 0
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1

    if args.cmd == "scope" and args.scmd == "create":
        if not args.confirm:
            print("REFUSED: scope creation is an out-of-band human action and requires --confirm.")
            print("This is intentional (§10.1): no agent/MCP/REST path can create or widen a scope.")
            return 2
        operator = args.operator or _caller()
        s = scopemod.create_scope(args.target, operator, ttl_seconds=args.ttl,
                                  data_mode=DataHandlingMode.SYNTHETIC_ONLY)
        print(json.dumps({"created_scope": s.scope_id, "allowlist": s.target_allowlist,
                          "operator": s.operator_confirmation, "expiry": s.expiry}, indent=2))
        return 0

    if args.cmd == "scope" and args.scmd == "list":
        srv = _server()
        print(json.dumps(srv.heel_list_scopes({}, _caller()), indent=2))
        return 0

    if args.cmd == "run":
        return _run_with_mode(args)

    srv = _server()
    caller = _caller()
    if args.cmd == "report":
        try:
            print(json.dumps(_report(srv, args.run, caller, economic=args.economic,
                                     economic_assumptions=args.economic_assumptions),
                             indent=2, default=str))
        except Exception as e:
            print(f"REJECTED: {e}")
            return 1
        return 0
    if args.cmd == "findings":
        print(json.dumps(srv.heel_get_findings({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "coverage":
        print(json.dumps(srv.heel_get_coverage({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "log":
        print(json.dumps(srv.heel_get_containment_log({"run_id": args.run}, caller), indent=2, default=str)); return 0
    if args.cmd == "scenarios":
        print(json.dumps(srv.heel_list_scenarios({"filter": args.filter, "pack": args.pack}, caller), indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
