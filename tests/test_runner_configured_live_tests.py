"""E2: signed configured live-read test instances in the existing paired executor.

Real: RunnerStore, CanaryCompiler, signed manifest/projection, cloud-signed grant,
LocalCanaryExecutor, TargetHTTPSClient over a real TLS handshake to a loopback HTTP/1.1 JSON
server, containment log, redaction and signed findings. Seams: the public-DNS answer is pinned
to the loopback socket (TargetHTTPSClient refuses non-public addresses by design), the test CA
is trusted explicitly, and the OS vault is an in-memory object with the OS backend id.
"""
from __future__ import annotations

import copy
import itertools
import json
import socket
import ssl
import threading

import pytest

from heel.canary_contracts import (
    CANARY_FINDINGS_SCHEMA,
    CONFIGURED_APPROVAL_PROJECTION_SCHEMA,
    CONFIGURED_FINDINGS_SCHEMA,
    CONFIGURED_TEST_MANIFEST_SCHEMA,
    ContractError,
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_canary_findings,
    validate_configured_approval_projection,
    validate_configured_findings,
    validate_configured_test_manifest,
    validate_test_manifest,
)
from heel.crypto import SigningAuthority
from heel.runner.compiler import CanaryCompiler, new_test_instance_id
from heel.runner.execution import ExecutionBundle, ExecutionGate, LocalCanaryExecutor
from heel.runner.http_transport import TargetHTTPSClient, TLSTransport
from heel.runner.openapi_routes import RouteInventory
from heel.runner.store import LiveInputUnavailable, RunnerStore, RunnerStoreError
from tests.plan_differential_support import make_test_ca
from tests.test_runner_compiler import FixedSigner, bound_store, context, specification
from tests.test_runner_compiler import identity as make_identity
from tests.test_runner_coordinator import _signed_context_binding
from tests.test_runner_stop import signed_grant

HOST = "staging.acme.dev"
PUBLIC = "93.184.216.34"
ROUTE = "/billing/features"
PLAN = "plan_entitlement_read"
TOKENS = {"lower_plan": "synthetic-free-plan-token-01", "higher_plan": "synthetic-pro-plan-token-02"}
SECRET_HINT = "4421-SECRET-HINT"
VALUES = {"export_ok": "ok", "secret_hint": SECRET_HINT, "pro_plan": "pro"}


def body(plan: str, *, hint: str = SECRET_HINT) -> bytes:
    return json.dumps({
        "meta": {"state": "ok"},
        "export": {"plan": plan, "rows": [{"ssn_hint": hint}]},
    }).encode()


def assertion(condition: dict) -> dict:
    return {
        "schema_version": "heel.live-read-assertion.v1",
        "success_witness": {"path": ["meta", "state"], "expected_fixture": "export_ok"},
        "condition": condition,
    }


HINT_EQUALS = assertion({
    "kind": "json_scalar_equals_fixture", "path": ["export", "rows", 0, "ssn_hint"],
    "expected_fixture": "secret_hint",
})
PLAN_EQUALS = assertion({
    "kind": "json_scalar_equals_fixture", "path": ["export", "plan"], "expected_fixture": "pro_plan",
})
FIELD_PRESENT = assertion({"kind": "json_field_present", "path": ["export", "rows", 0, "ssn_hint"]})


class MemoryOSVault:
    """SEAM-VAULT: in-memory stand-in carrying the OS backend id; stores bytes by handle."""

    supported = True
    backend_id = "macos_keychain"

    def __init__(self):
        self.items: dict[str, bytes] = {}

    def store(self, handle_id, secret):
        assert handle_id not in self.items
        self.items[handle_id] = bytes(secret)

    def load(self, handle_id):
        from heel.runner.vault import VaultUnavailable

        if handle_id not in self.items:
            raise VaultUnavailable("secure credential was not found")
        return self.items[handle_id]

    def exists(self, handle_id):
        return handle_id in self.items

    def delete(self, handle_id):
        self.items.pop(handle_id, None)


class TokenVault:
    """SEAM-VAULT: the ephemeral credential convention, one exact token per handle."""

    supported = True
    backend_id = "ephemeral_env"

    def __init__(self, tokens):
        self.tokens = tokens

    def load(self, handle_id):
        return self.tokens[handle_id].encode()


class JSONTarget:
    """A real TLS + HTTP/1.1 loopback server that answers by bearer token, then closes."""

    def __init__(self, tmp_path, certificate, key):
        (tmp_path / "srv.pem").write_bytes(certificate)
        (tmp_path / "srv.key").write_bytes(key)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(tmp_path / "srv.pem", tmp_path / "srv.key")
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.answers = {"lower_plan": (200, body("free")), "higher_plan": (200, body("pro"))}
        self.requests: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.listener.settimeout(0.1)
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except OSError:
                continue
            try:
                raw.settimeout(5)
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    self.requests.append(request)
                    role = next(r for r, t in TOKENS.items() if f"Bearer {t}".encode() in request)
                    status, payload = self.answers[role]
                    head = request.startswith(b"HEAD ")
                    tls.sendall((
                        f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
                    ).encode() + (b"" if head else payload))
            except (OSError, ssl.SSLError, StopIteration):
                pass
            finally:
                raw.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join(5)
        self.listener.close()


class PinnedSockets:
    """SEAM-DNS: the exact public preflight address dials the loopback TLS listener."""

    def __init__(self, port):
        self.port = port

    def connect(self, address, timeout, cancellation):
        assert address == (PUBLIC, 443)
        raw = socket.create_connection(("127.0.0.1", self.port), timeout)
        cancellation.register(raw)
        return raw


class PinnedPeerTLS:
    """Real TLSTransport handshake (chain + hostname verified); only getpeername is pinned."""

    def __init__(self, ca: bytes):
        self.transport = TLSTransport()
        self.transport.context.load_verify_locations(cadata=ca.decode("ascii"))
        self.handshakes = 0

    def wrap(self, raw, hostname, timeout):
        wrapped = self.transport.wrap(raw, hostname, timeout)
        self.handshakes += 1
        return _PinnedPeer(wrapped)


class _PinnedPeer:
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def getpeername(self):
        return (PUBLIC, 443)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def gate_source():
    clock = itertools.count(2_000, 1)
    return lambda: ExecutionGate(
        active=True, runner_state="active", proof_state="valid", proof_expires_at_ms=60_000,
        kill_switch_generation=7, stop_reason="none", server_time_ms=next(clock),
    )


class World:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        # Bound through a real cloud-signed context binding so replay queuing is the real path.
        self.signer = FixedSigner()
        self.identity = make_identity(self.signer)
        self.store = RunnerStore(tmp_path / "heel-home")
        self.cloud = SigningAuthority.generate()
        self.binding = _signed_context_binding(self.identity, self.cloud)
        self.store.install_cloud_context_binding(
            self.binding, identity=self.identity, signer=self.signer,
            signer_label=self.identity.key_id,
            trusted_cloud_keys={self.cloud.key_id: self.cloud.public_key}, now_ms=2_000,
        )
        inventory = RouteInventory(specification())
        self.store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
        self.vault = MemoryOSVault()
        tokens = {}
        for role in ("lower_plan", "higher_plan"):
            record = self.store.register_ephemeral_credential(
                semantic_role=role, auth_profile="bearer", source_kind="environment",
                label=f"local {role}",
            )
            tokens[record["credential_handle_id"]] = TOKENS[role]
        self.tokens = TokenVault(tokens)
        self.inputs = {
            name: self.store.create_live_input(name=name, value=value, vault=self.vault)
            for name, value in VALUES.items()
        }
        self.authority = SigningAuthority.generate()
        self.ca, self.certificate, self.key = make_test_ca(HOST)
        self.runs = itertools.count(1)

    def compiler(self, now_ms=1_000):
        return CanaryCompiler(
            store=self.store, identity=self.identity, signer=self.signer, now_ms=now_ms,
        )

    def instance(self, definition, *, instance_id=None, revision=1, method="GET", source="sc.export.entitlement"):
        refs = {"export_ok": "export_ok"}
        condition = definition["condition"]
        if "expected_fixture" in condition:
            refs[condition["expected_fixture"]] = condition["expected_fixture"]
        return {
            "test_instance_id": instance_id or new_test_instance_id(),
            "scenario_id": PLAN,
            "source_scenario_id": source,
            "source_revision": revision,
            "method": method,
            "route_template": ROUTE,
            "assertion": copy.deepcopy(definition),
            "local_inputs": refs,
        }

    def compile(self, *instances, now_ms=1_000):
        return self.compiler(now_ms).compile_configured(list(instances))

    def execute(self, compiled, target):
        run = next(self.runs)
        grant = signed_grant(compiled.manifest, compiled.projection, self.identity, self.authority)
        grant = dict(grant)
        unsigned = {k: v for k, v in grant.items() if k not in {"grant_digest", "signing_key_id", "signature_b64"}}
        unsigned["run_id"] = "crun_" + f"{run:032x}"
        unsigned["grant_id"] = f"grant_{run:09d}"
        grant = {
            **unsigned, "grant_digest": canonical_digest(unsigned),
            **self.authority.sign(canonical_bytes(unsigned)),
        }
        tls = self.tls = PinnedPeerTLS(self.ca)
        client = TargetHTTPSClient(
            origin="https://" + HOST, preflight_addresses=[PUBLIC],
            resolver=lambda hostname, *, deadline: [PUBLIC],
            sockets=PinnedSockets(target.port), tls=tls,
        )
        return LocalCanaryExecutor(
            store=self.store, identity=self.identity, signer=self.signer,
            trusted_grant_keys={self.authority.key_id: self.authority.public_key},
            vaults={"ephemeral_env": self.tokens, "macos_keychain": self.vault},
            clock_ms=lambda: 2_000,
        ).execute(
            ExecutionBundle(compiled.manifest, compiled.projection, grant),
            transport=client, gate_source=gate_source(),
        )

    def target(self):
        return JSONTarget(self.tmp_path, self.certificate, self.key)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def results_by_instance(result):
    findings = result.findings_projection
    assert findings["schema_version"] == CONFIGURED_FINDINGS_SCHEMA
    return {item["test_instance_id"]: item for item in findings["test_results"]}


def assert_no_values(*records):
    text = json.dumps(records, sort_keys=True)
    for value in (SECRET_HINT, *TOKENS.values(), "protected_canary", "free"):
        assert value not in text


# --------------------------------------------------------------------------- #
# Thin real-executor journey
# --------------------------------------------------------------------------- #
def test_two_same_primitive_route_instances_execute_independently_over_real_tls(world):
    hint = world.instance(HINT_EQUALS)
    plan = world.instance(PLAN_EQUALS)
    compiled = world.compile(hint, plan)
    assert compiled.manifest["schema_version"] == CONFIGURED_TEST_MANIFEST_SCHEMA
    assert compiled.projection["schema_version"] == CONFIGURED_APPROVAL_PROJECTION_SCHEMA
    with world.target() as target:
        result = world.execute(compiled, target)
        assert len(target.requests) == 4
        assert world.tls.handshakes == 4
        assert all(b"protected_canary" not in item for item in target.requests)
    assert result.execution_disposition == "completed"
    by_id = results_by_instance(result)
    observed, blocked = by_id[hint["test_instance_id"]], by_id[plan["test_instance_id"]]
    assert (observed["scenario_id"], blocked["scenario_id"]) == (PLAN, PLAN)
    assert observed["route"] == blocked["route"] == {"method": "GET", "route_template": ROUTE}
    assert (observed["assessment_outcome"], observed["reason"]) == ("observed", "restricted_condition_true")
    assert (blocked["assessment_outcome"], blocked["reason"]) == ("blocked", "restricted_condition_false")
    assert observed["finding"] is not None and blocked["finding"] is None
    # Each instance is attributed to its own two signed action ordinals and evidence refs.
    assert [o["action_ordinal"] for o in observed["observations"]] == [0, 1]
    assert [o["action_ordinal"] for o in blocked["observations"]] == [2, 3]
    assert not set(observed["local_evidence_refs"]) & set(blocked["local_evidence_refs"])
    assert result.assessment_outcome == "observed"
    assert_no_values(result.findings_projection, result.operational_projection, compiled.projection,
                     compiled.manifest)
    # The signed finals reload through the store and the local view.
    stored = world.store.load_final_projections(result.findings_projection["run_id"])
    assert stored["findings_projection"] == result.findings_projection
    assert validate_configured_findings(result.findings_projection) == result.findings_projection


def run_once(world, compiled, *, lower=None, higher=None):
    with world.target() as target:
        if lower is not None:
            target.answers["lower_plan"] = lower
        if higher is not None:
            target.answers["higher_plan"] = higher
        result = world.execute(compiled, target)
        return result, list(target.requests)


# --------------------------------------------------------------------------- #
# Configuration, not code, decides; old runs keep their frozen configuration
# --------------------------------------------------------------------------- #
def test_config_only_revision_change_alters_outcome_and_old_run_keeps_frozen_definition(world):
    instance_id = new_test_instance_id()
    first = world.compile(world.instance(PLAN_EQUALS, instance_id=instance_id, revision=1))
    old, _ = run_once(world, first)
    second = world.compile(
        world.instance(HINT_EQUALS, instance_id=instance_id, revision=2), now_ms=1_001,
    )
    new, _ = run_once(world, second)
    old_result = results_by_instance(old)[instance_id]
    new_result = results_by_instance(new)[instance_id]
    assert old_result["assessment_outcome"] == "blocked"
    assert new_result["assessment_outcome"] == "observed"
    assert old_result["source"]["source_revision"] == 1 and new_result["source"]["source_revision"] == 2
    assert old_result["assertion_digest"] != new_result["assertion_digest"]
    # The earlier signed run still binds revision 1 and its exact definition.
    stored = world.store.load_final_projections(old.findings_projection["run_id"])
    reloaded = {i["test_instance_id"]: i for i in stored["findings_projection"]["test_results"]}
    assert reloaded[instance_id] == old_result
    manifest = world.store.load_manifest(first.manifest["manifest_digest"])
    assert manifest["test_instances"][0]["assertion"] == PLAN_EQUALS


def test_distinct_conditions_on_one_primitive_and_route_need_no_protected_canary(world):
    present, plan = world.instance(FIELD_PRESENT), world.instance(PLAN_EQUALS)
    result, requests = run_once(world, world.compile(present, plan))
    by_id = results_by_instance(result)
    assert by_id[present["test_instance_id"]]["assessment_outcome"] == "observed"
    assert by_id[plan["test_instance_id"]]["assessment_outcome"] == "blocked"
    assert by_id[present["test_instance_id"]]["condition_kind"] == "json_field_present"
    assert all(b"protected_canary" not in item for item in requests)


# --------------------------------------------------------------------------- #
# Versions: old validators refuse new records; unknown versions fail closed
# --------------------------------------------------------------------------- #
def test_old_validators_refuse_configured_records_and_new_fields(world):
    compiled = world.compile(world.instance(HINT_EQUALS))
    result, _ = run_once(world, compiled)
    with pytest.raises(ContractError):
        validate_test_manifest(compiled.manifest)
    with pytest.raises(ContractError):
        validate_approval_projection(compiled.projection)
    with pytest.raises(ContractError):
        validate_canary_findings(result.findings_projection)
    # A v1 manifest with a smuggled instance field is not v1.
    v1_store, v1_identity, v1_signer = bound_store(world.tmp_path / "v1")
    v1_store.save_mapping("anonymous_authenticated_read", method="HEAD", route_template="/health")
    v1_store.register_ephemeral_credential(
        semantic_role="authenticated", auth_profile="bearer", source_kind="environment", label="a",
    )
    v1 = CanaryCompiler(store=v1_store, identity=v1_identity, signer=v1_signer).compile(
        ["anonymous_authenticated_read"], persist=False,
    )
    smuggled = copy.deepcopy(v1.manifest)
    smuggled["actions"][0]["test_instance_id"] = new_test_instance_id()
    smuggled["manifest_digest"] = canonical_digest({k: v for k, v in smuggled.items() if k != "manifest_digest"})
    with pytest.raises(ContractError):
        validate_test_manifest(smuggled)
    for validator, record in (
        (validate_configured_test_manifest, v1.manifest),
        (validate_configured_approval_projection, v1.projection),
    ):
        with pytest.raises(ContractError):
            validator(record)
    assert validate_test_manifest(v1.manifest) == v1.manifest  # v1 behavior unchanged


def test_unsupported_compiler_engine_schema_and_assertion_versions_fail_closed(world):
    compiled = world.compile(world.instance(HINT_EQUALS), )
    for mutate in (
        lambda m: m["compiler"].update(compiler_version="3"),
        lambda m: m["compiler"].update(engine_version="1"),
        lambda m: m.update(schema_version="heel.test-manifest.v9"),
        lambda m: m["test_instances"][0]["assertion"].update(schema_version="heel.live-read-assertion.v2"),
    ):
        manifest = copy.deepcopy(compiled.manifest)
        mutate(manifest)
        manifest["manifest_digest"] = canonical_digest({k: v for k, v in manifest.items() if k != "manifest_digest"})
        with pytest.raises(ContractError):
            validate_configured_test_manifest(manifest)
        with pytest.raises(ContractError):
            from heel.canary_contracts import validate_runner_test_manifest
            validate_runner_test_manifest(manifest)
    bad = world.instance(HINT_EQUALS)
    bad["assertion"]["schema_version"] = "heel.live-read-assertion.v2"
    with pytest.raises(ValueError):
        world.compile(bad)
    with pytest.raises(ValueError):
        world.compile(*[world.instance(HINT_EQUALS) for _ in range(5)])
    duplicate = world.instance(HINT_EQUALS)
    with pytest.raises(ValueError):
        world.compile(duplicate, dict(duplicate))
    unknown = world.instance(HINT_EQUALS)
    unknown["scenario_id"] = "object_ownership_read"
    with pytest.raises(ValueError):
        world.compile(unknown)


# --------------------------------------------------------------------------- #
# Tamper and ref-widening are rejected before any target request
# --------------------------------------------------------------------------- #
def _redigest(manifest):
    manifest["manifest_digest"] = canonical_digest({k: v for k, v in manifest.items() if k != "manifest_digest"})
    return manifest


def test_tampered_configuration_identity_role_route_and_input_refs_are_rejected(world):
    other = world.store.create_live_input(name="other_value", value="x", vault=world.vault)
    first, second = world.instance(HINT_EQUALS), world.instance(PLAN_EQUALS)
    compiled = world.compile(first, second)
    mutations = {
        "assertion": lambda m: m["test_instances"][0]["assertion"]["condition"].update(path=["export", "plan"]),
        "assertion_digest": lambda m: m["test_instances"][0].update(assertion_digest="sha256:" + "0" * 64),
        "instance": lambda m: [m["test_instances"][0].update(test_instance_id=new_test_instance_id())],
        "role": lambda m: m["actions"][0].update(semantic_auth_role="higher_plan"),
        "route": lambda m: [a.update(route_template="/items") for a in m["actions"][:2]]
        + [m["test_instances"][0].update(route_template="/items")],
        "input_ref": lambda m: m["test_instances"][0]["local_inputs"][1].update(
            input_handle_id=other["input_handle_id"]),
        "swap_instances": lambda m: m.update(test_instances=list(reversed(m["test_instances"]))),
    }
    with world.target() as target:
        for name, mutate in mutations.items():
            manifest = copy.deepcopy(compiled.manifest)
            mutate(manifest)
            _redigest(manifest)
            with pytest.raises((ValueError, RunnerStoreError)):
                world.execute(compiled.__class__(manifest, compiled.projection), target)
            with pytest.raises((ValueError, RunnerStoreError)):
                world.store.save_approved_pair(manifest, compiled.projection)
        # A projection edited after signing never verifies.
        projection = copy.deepcopy(compiled.projection)
        projection["test_instances"][0]["local_input_refs"] = ["export_ok"]
        with pytest.raises((ValueError, RunnerStoreError)):
            world.execute(compiled.__class__(compiled.manifest, projection), target)
        projection = copy.deepcopy(compiled.projection)
        projection["test_instances"][1]["source"]["source_revision"] = 9
        with pytest.raises((ValueError, RunnerStoreError)):
            world.execute(compiled.__class__(compiled.manifest, projection), target)
        assert target.requests == []


def test_cross_context_local_input_metadata_is_refused(world, tmp_path):
    path = world.store.root / "runner" / "contexts" / world.store.namespace / "live-inputs.json"
    original = path.read_bytes()
    envelope = json.loads(original)
    envelope["inputs"][0]["workspace_id"] = "ws_other_context"
    path.write_text(json.dumps(envelope))
    with pytest.raises(RunnerStoreError):
        world.store.list_live_inputs()
    path.write_bytes(original)
    other_store, _identity, _signer = bound_store(
        tmp_path / "other", selected_context=context(environment_id="env_other_9876"),
    )
    other_path = other_store.root / "runner" / "contexts" / other_store.namespace / "live-inputs.json"
    other_path.write_bytes(original)
    # Records copied from another bound context (other environment/namespace) are refused.
    with pytest.raises(RunnerStoreError):
        other_store.list_live_inputs()
    # Even with the envelope re-pointed at this namespace, the record context still differs.
    envelope = json.loads(original)
    envelope["namespace"] = other_store.namespace
    other_path.write_text(json.dumps(envelope))
    with pytest.raises(RunnerStoreError):
        other_store.list_live_inputs()
    assert world.store.list_live_inputs()


# --------------------------------------------------------------------------- #
# HEAD, error envelopes and missing positive controls stay inconclusive
# --------------------------------------------------------------------------- #
def test_head_error_envelope_and_failed_positive_control_are_inconclusive(world):
    head = world.instance(HINT_EQUALS, method="HEAD")
    head["route_template"] = "/health"
    result, _ = run_once(world, world.compile(head))
    item = results_by_instance(result)[head["test_instance_id"]]
    assert (item["assessment_outcome"], item["reason"]) == ("inconclusive", "method_not_observable")

    hint = world.instance(HINT_EQUALS)
    compiled = world.compile(hint, now_ms=1_002)
    envelope = json.dumps({"meta": {"state": "ok"}, "error": "upgrade required",
                           "export": {"plan": "pro", "rows": [{"ssn_hint": SECRET_HINT}]}}).encode()
    result, _ = run_once(world, compiled, lower=(200, envelope))
    item = results_by_instance(result)[hint["test_instance_id"]]
    assert item["assessment_outcome"] == "inconclusive"
    assert item["reason"] == "restricted_denial_envelope"
    assert item["positive_control"] == "established" and item["finding"] is None

    compiled = world.compile(hint, now_ms=1_003)
    result, _ = run_once(world, compiled, higher=(403, b""))
    item = results_by_instance(result)[hint["test_instance_id"]]
    assert (item["assessment_outcome"], item["reason"]) == ("inconclusive", "positive_control_status")
    assert item["positive_control"] == "not_established"

    compiled = world.compile(hint, now_ms=1_004)
    result, _ = run_once(world, compiled, higher=(200, body("pro", hint="other")))
    item = results_by_instance(result)[hint["test_instance_id"]]
    assert (item["assessment_outcome"], item["reason"]) == ("inconclusive", "positive_control_condition_false")


# --------------------------------------------------------------------------- #
# Local values: rotation and revocation never silently change an approval
# --------------------------------------------------------------------------- #
def test_rotation_keeps_old_approval_on_old_handle_and_revocation_refuses_it(world):
    hint = world.instance(HINT_EQUALS)
    old = world.compile(hint)
    old_handle = old.manifest["test_instances"][0]["local_inputs"][1]["input_handle_id"]
    rotated = world.store.create_live_input(name="secret_hint", value="9999", vault=world.vault)
    assert rotated["input_handle_id"] != old_handle
    new = world.compile(hint, now_ms=1_005)
    assert new.manifest["test_instances"][0]["local_inputs"][1]["input_handle_id"] == rotated["input_handle_id"]
    # The old approval still resolves only its frozen handle (old value matches the target).
    result, _ = run_once(world, old)
    assert results_by_instance(result)[hint["test_instance_id"]]["assessment_outcome"] == "observed"
    result, _ = run_once(world, new)
    assert results_by_instance(result)[hint["test_instance_id"]]["reason"] == "positive_control_condition_false"
    # Explicit revocation: the old approval is refused for that instance, never false/pass.
    world.store.revoke_live_input(old_handle, vault=world.vault)
    assert old_handle not in world.vault.items
    plan = world.instance(PLAN_EQUALS)
    both = world.compile(hint, plan, now_ms=1_006)  # uses the CURRENT (rotated) handle
    assert both.manifest["test_instances"][0]["local_inputs"][1]["input_handle_id"] != old_handle
    result, requests = run_once(world, old)
    item = results_by_instance(result)[hint["test_instance_id"]]
    assert (item["assessment_outcome"], item["reason"]) == ("inconclusive", "local_input_unavailable")
    assert item["observations"] == [] and requests == []
    assert "action_rejected" in item["containment_codes"]
    with pytest.raises(LiveInputUnavailable):
        world.store.load_live_input_values({"secret_hint": old_handle}, vaults={"macos_keychain": world.vault})


def test_local_input_setup_rejects_non_scalars_and_unsupported_vaults(world):
    for value in ({"a": 1}, [1], float("nan"), "x" * 3000, b"raw"):
        with pytest.raises(ValueError):
            world.store.create_live_input(name="bad", value=value, vault=world.vault)
    ephemeral = TokenVault({})
    with pytest.raises(Exception):
        world.store.create_live_input(name="bad", value="x", vault=ephemeral)
    assert all(item["name"] != "bad" for item in world.store.list_live_inputs())


# --------------------------------------------------------------------------- #
# Saved regression keeps the exact instance and observes the patched transition
# --------------------------------------------------------------------------- #
def test_configured_regression_preserves_frozen_instance_and_replay_holds_after_patch(world):
    from heel.runner.regressions import CONFIGURED_REGRESSION_SCHEMA

    hint, plan = world.instance(HINT_EQUALS), world.instance(PLAN_EQUALS)
    source, _ = run_once(world, world.compile(hint, plan))
    run_id = source.findings_projection["run_id"]
    with pytest.raises(Exception):  # a blocked instance is not a regression source
        world.store.add_saved_regression(
            run_id=run_id, test_instance_id=plan["test_instance_id"], name="plan", now_ms=3_000,
        )
    record, created = world.store.add_saved_regression(
        run_id=run_id, test_instance_id=hint["test_instance_id"], name="hint leak", now_ms=3_000,
    )
    assert created and record["record_schema"] == CONFIGURED_REGRESSION_SCHEMA
    assert record["assertion"] == HINT_EQUALS and record["source"]["source_revision"] == 1
    frozen_handles = record["local_inputs"]
    # A later rotation of the name does not touch the definition or its replay.
    world.store.create_live_input(name="secret_hint", value="rotated", vault=world.vault)
    replay = world.compiler(now_ms=4_000).compile_configured_replay(record)
    assert replay.manifest["test_instances"][0]["local_inputs"] == frozen_handles
    assert replay.manifest["test_instances"][0]["test_instance_id"] == hint["test_instance_id"]
    submission, association = world.store.queue_regression_replay(
        record["regression_id"], replay.projection["projection_id"],
        binding_digest=world.binding["binding_digest"], now_ms=4_000,
    )
    assert submission["projection_digest"] == replay.projection["projection_digest"]
    # Patched target: the lower plan is now denied. A fresh grant is required for the replay.
    patched, _ = run_once(world, replay, lower=(403, b""))
    item = results_by_instance(patched)[hint["test_instance_id"]]
    assert (item["assessment_outcome"], item["reason"]) == ("blocked", "restricted_empty_denial")
    outcome, _ = world.store.record_regression_result(
        regression_id=record["regression_id"], run_id=patched.findings_projection["run_id"], now_ms=5_000,
    )
    assert outcome["outcome"] == "pass"
    assert world.store.list_saved_regressions() == [record]
    # Revoking a frozen input makes replay refuse with no substitution by name.
    world.store.revoke_live_input(frozen_handles[1]["input_handle_id"], vault=world.vault)
    with pytest.raises(Exception):
        world.compiler(now_ms=6_000).compile_configured_replay(record)


# --------------------------------------------------------------------------- #
# Privacy: no expected values in manifests, projections, logs, findings or local state
# --------------------------------------------------------------------------- #
def test_expected_values_never_leave_the_vault(world):
    hint = world.instance(HINT_EQUALS)
    compiled = world.compile(hint)
    result, _ = run_once(world, compiled)
    # Raw response evidence stays local by design; every other local file holds no value.
    leaked = []
    for path in world.store.root.rglob("*"):
        if path.is_file() and "evidence" not in path.parts and SECRET_HINT.encode() in path.read_bytes():
            leaked.append(str(path.relative_to(world.store.root)))
    assert leaked == []
    for record in world.store.list_live_inputs():
        assert set(record) == {
            "input_handle_id", "name", "backend", "state", "selection",
            "workspace_id", "project_id", "environment_id", "runner_id",
        }
    assert_no_values(result.local_view, result.disclosure_preview)
    error = None
    try:
        world.store.load_live_input_values({"x": "0" * 32}, vaults={"macos_keychain": world.vault})
    except LiveInputUnavailable as exc:
        error = exc
    assert error is not None and SECRET_HINT not in repr(error)


def test_cli_local_input_setup_reads_fd_only_prints_handles_and_revokes(world, monkeypatch, capsys):
    import os

    from heel import cli
    import heel.runner.vault as vault_module

    monkeypatch.setenv("HEEL_HOME", str(world.store.root))
    monkeypatch.setattr(vault_module, "select_vault", lambda kind, **_: world.vault)
    read, write = os.pipe()
    os.write(write, b'"cli-only-expected-0001"')
    os.close(write)
    os.set_inheritable(read, True)
    try:
        code = cli.main(["runner", "input", "add", "--name", "cli_value", "--backend", "keychain",
                         "--secret-fd", str(read)])
    finally:
        os.close(read)
    out, err = capsys.readouterr()
    assert code == 0, err
    printed = json.loads(out)
    assert "cli-only-expected-0001" not in out + err
    handle = printed["input_handle"]
    assert world.vault.items[handle] == b'"cli-only-expected-0001"'
    assert cli.main(["runner", "input", "list"]) == 0
    listed = capsys.readouterr().out
    assert handle in listed and "cli-only-expected-0001" not in listed
    assert cli.main(["runner", "input", "revoke", "--handle", handle, "--backend", "keychain"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "revoked"
    assert handle not in world.vault.items
    # A value on argv is never accepted.
    try:
        refused = cli.main(["runner", "input", "add", "--name", "x", "--backend", "keychain",
                            "--value", "cli-only-expected-0001"])
    except SystemExit as exit_:
        refused = exit_.code
    assert refused == 2
    out, err = capsys.readouterr()
    assert "cli-only-expected-0001" not in out + err
    assert all(item["name"] != "x" for item in world.store.list_live_inputs())


def test_target_failure_after_inputs_resolve_is_run_incomplete_not_a_verdict(world):
    hint = world.instance(HINT_EQUALS)
    compiled = world.compile(hint)
    with world.target() as target:
        port = target.port
    # The listener is closed: every connect fails after local activation and input snapshot.
    closed = type("Closed", (), {"port": port, "requests": []})()
    result = world.execute(compiled, closed)
    item = results_by_instance(result)[hint["test_instance_id"]]
    assert result.execution_disposition == "incomplete"
    assert (item["assessment_outcome"], item["reason"]) == ("inconclusive", "run_incomplete")
    assert item["finding"] is None
