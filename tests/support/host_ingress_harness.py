"""Real host-ingress proof harness (H0B): actual nginx+njs ingress, real CP, runner and Worker.

``IngressEnvironment`` composes, inside the isolated namespaces that ``scripts/host_ingress_proof.py``
created, one real ``serve(ControlPlane(...))`` process on the constant private backend, the
reviewed ``deploy/host/ingress`` nginx (management TLS 8443 and one runner TLS 443 listener per
slot), the compiled Worker artifact under Node with a fixed private TLS adapter as the management
client, and real ``RunnerDaemon``/``RunnerCoordinator`` children in their own runner namespaces.
Every product process runs as its own unprivileged UID; the test driver only talks to them over
pipes and probes the network from inside a named namespace.

Explicit seams (never product fallbacks): the ephemeral test CA (constructor/explicit-option
trust only), the in-memory runner secret backend that reports its generated public key to the
fixture controller before exchange, the trusted fixture registry controller (the production
slot-state supplier is later H1/H3/C4 work), the Node fake VPC adapter (not Cloudflare/workerd),
the environment DNS-TXT seam, and a scripted backend used only for response-parser negatives.
Nothing here patches a validator, approval, receipt or grant check.
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
HOST = "heel.example"
ALIAS_HOST = "cp.heel.example"
ORIGIN = "https://" + HOST
INGRESS_DIR = ROOT / "deploy" / "host" / "ingress"
TEMPLATE_PATH = INGRESS_DIR / "nginx.conf"
POLICY_PATH = INGRESS_DIR / "policy.js"
LOCK_PATH = INGRESS_DIR / "runtime-lock.json"
BACKEND_PORT = 8080
MANAGEMENT_PORT = 8443
RUNNER_PORT = 443
OPS_PORT = 9901
REQUIRED_ENV = "HEEL_REQUIRE_HOST_INGRESS"
ENVIRONMENT_FILE_ENV = "HEEL_HOST_INGRESS_ENVIRONMENT"
CHILD_TIMEOUT_SECONDS = 30.0

# Fixed private fixture subnets and identities (never routable outside the outer namespace).
ADDRESS_PLAN = {
    "cp": ("10.77.0.2", "10.77.0.1"),
    "management": ("10.77.1.2", "10.77.1.1"),
    "slot-a": ("10.77.2.2", "10.77.2.1"),
    "slot-b": ("10.77.3.2", "10.77.3.1"),
}
UIDS = {"cp": 61001, "ingress": 61002, "management": 61003, "slot-a": 61011, "slot-b": 61012}
SLOT_IDS = ("slot-a", "slot-b")


# ---------------------------------------------------------------------------------------------
# Test TLS material. ``tests/support/edge_tls_harness.EphemeralCA`` (unchanged) supplies an
# unrelated CA for wrong-trust cases; this CA can issue the several leaves the matrix needs.

class IngressCA:
    """A throwaway CA that issues named, alias, wrong-name and expired leaves for H."""

    def __init__(self, directory: Path, label: str = "heel ingress test CA"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509, self._hashes, self._serialization, self._ec, self._oid = x509, hashes, serialization, ec, NameOID
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        now = datetime.datetime.now(datetime.timezone.utc)
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label + " " + secrets.token_hex(4))])
        self._cert = (
            x509.CertificateBuilder().subject_name(self._name).issuer_name(self._name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(hours=6))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self.ca_path = directory / "ca.pem"
        self.ca_path.write_bytes(self._cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, label: str, names: tuple[str, ...], *, expired: bool = False) -> tuple[Path, Path]:
        x509, hashes, serialization, ec = self._x509, self._hashes, self._serialization, self._ec
        now = datetime.datetime.now(datetime.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        start, end = (now - datetime.timedelta(days=2), now - datetime.timedelta(days=1)) if expired else (
            now - datetime.timedelta(minutes=5), now + datetime.timedelta(hours=3))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self._oid.COMMON_NAME, names[0])]))
            .issuer_name(self._name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        cert_path = self.directory / f"{label}.pem"
        key_path = self.directory / f"{label}-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        key_path.chmod(0o600)
        return cert_path, key_path

    @staticmethod
    def fingerprint(cert_path: Path) -> str:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


# ---------------------------------------------------------------------------------------------
# Trusted renderer: only @@TOKEN@@ substitution from closed grammars; slot sections repeated.

_TOKEN = re.compile(r"@@([A-Z_]+)@@")
_PATH_GRAMMAR = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
_IPV4 = re.compile(r"^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$")
TOKEN_GRAMMARS: dict[str, re.Pattern[str]] = {
    "STATE_DIR": _PATH_GRAMMAR,
    "POLICY_DIR": _PATH_GRAMMAR,
    "REGISTRY_PATH": _PATH_GRAMMAR,
    "CERT_PATH": _PATH_GRAMMAR,
    "KEY_PATH": _PATH_GRAMMAR,
    "REGISTRY_OWNER_UID": re.compile(r"^(?:0|[1-9][0-9]{0,9})$"),
    "BOOT_EPOCH": re.compile(r"^[a-z0-9-]{8,64}$"),
    "PUBLIC_HOST": re.compile(r"^heel\.example$"),
    "BACKEND_ADDRESS": _IPV4,
    "BACKEND_PORT": re.compile(r"^[1-9][0-9]{0,4}$"),
    "MANAGEMENT_ADDRESS": _IPV4,
    "MANAGEMENT_PORT": re.compile(r"^[1-9][0-9]{0,4}$"),
    "MANAGEMENT_PEER": _IPV4,
    "EDGE_SECRET": re.compile(r"^[A-Za-z0-9_-]{43,86}$"),
    "OPS_PORT": re.compile(r"^[1-9][0-9]{0,4}$"),
}
SLOT_TOKEN_GRAMMARS: dict[str, re.Pattern[str]] = {
    "SLOT_ID": re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$"),
    "SLOT_ADDRESS": _IPV4,
    "SLOT_PORT": re.compile(r"^[1-9][0-9]{0,4}$"),
    "SLOT_PEER": _IPV4,
}
_SECTIONS = ("SLOT MAP", "SLOT SERVER")


class RenderError(ValueError):
    """A template or value outside the reviewed grammar."""


def _substitute(text: str, values: dict[str, str], grammars: dict[str, re.Pattern[str]],
                deferred: frozenset[str] = frozenset()) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in deferred:
            return match.group(0)
        if name not in grammars or name not in values:
            raise RenderError(f"unreviewed template token {name}")
        value = values[name]
        if type(value) is not str or grammars[name].fullmatch(value) is None:
            raise RenderError(f"value outside the reviewed grammar for {name}")
        return value
    return _TOKEN.sub(replace, text)


def render_nginx_config(template: str, values: dict[str, str], slots: list[dict[str, str]]) -> str:
    """Return the rendered configuration; refuse any unknown token, value or section shape."""
    if set(values) != set(TOKEN_GRAMMARS):
        raise RenderError("render values must name exactly the reviewed tokens")
    if not 1 <= len(slots) <= 20:
        raise RenderError("slot count outside the reviewed bound")
    for slot in slots:
        if set(slot) != set(SLOT_TOKEN_GRAMMARS):
            raise RenderError("slot values must name exactly the reviewed slot tokens")
    output = template
    for section in _SECTIONS:
        begin, end = f"# BEGIN {section}\n", f"# END {section}\n"
        if output.count(begin) != 1 or output.count(end) != 1:
            raise RenderError(f"template must contain exactly one {section} section")
        head, rest = output.split(begin, 1)
        body, tail = rest.split(end, 1)
        indent = head[head.rfind("\n") + 1:]
        if indent.strip():
            raise RenderError("section markers must start their own line")
        head = head[: len(head) - len(indent)]
        tail = tail.lstrip(" ")
        body = indent + body
        repeated = "".join(_substitute(body, slot, SLOT_TOKEN_GRAMMARS, frozenset(TOKEN_GRAMMARS)) for slot in slots)
        output = head + repeated + tail
    output = _substitute(output, values, TOKEN_GRAMMARS)
    if "@@" in output:
        raise RenderError("unrendered token remains")
    return output


def config_digest(rendered: str, secret: str) -> str:
    """Digest of the rendered configuration with the private secret replaced by a fixed label."""
    return hashlib.sha256(rendered.replace(secret, "<edge-secret>").encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------------------------
# Trusted registry. Mirrors policy.js checkRegistry so the controller never publishes a document
# the ingress would refuse by accident; deliberate malformed documents go through write_raw.

REGISTRY_SCHEMA = "heel.ingress-registry.v1"
PHASES = ("closed", "invited", "pending", "active", "rotating", "stopping", "retired")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_registry_bytes(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_registry(document: dict, *, boot_epoch: str, backend: str, management: str, peer: str) -> None:
    def want(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError("registry: " + message)

    def keys(value: object, names: set[str], label: str) -> None:
        want(isinstance(value, dict) and set(value) == names, label + " fields")

    keys(document, {"schema_version", "host_boot_epoch", "config_generation", "public_origin",
                    "backend", "management", "expires_at_ms", "slots"}, "document")
    want(document["schema_version"] == REGISTRY_SCHEMA, "schema")
    want(document["host_boot_epoch"] == boot_epoch, "boot")
    want(type(document["config_generation"]) is int and document["config_generation"] >= 1, "generation")
    want(document["public_origin"] == ORIGIN, "origin")
    want(f"{document['backend']['address']}:{document['backend']['port']}" == backend, "backend")
    want(f"{document['management']['address']}:{document['management']['port']}" == management, "management")
    want(document["management"]["peer"] == peer, "management peer")
    want(1 <= len(document["slots"]) <= 20, "slot count")
    seen: set[str] = set()
    for slot in document["slots"]:
        keys(slot, {"slot_id", "listener", "peer", "namespace_id", "workspace_id", "phase", "runner",
                    "invitation", "pairing", "rotation", "projects", "contexts", "runs"}, "slot")
        want(slot["phase"] in PHASES, "phase")
        for kind, value in (("slot", slot["slot_id"]), ("peer", slot["peer"]), ("ns", slot["namespace_id"]),
                            ("listener", f"{slot['listener']['address']}:{slot['listener']['port']}")):
            want((kind, value) not in seen, "duplicate " + kind)
            seen.add((kind, value))
        want(len(slot["projects"]) <= 8 and len(slot["contexts"]) <= 8 and len(slot["runs"]) <= 8, "caps")
        want(sum(1 for run in slot["runs"] if run["state"] == "admitted") <= 1, "one admitted run")
        phase = slot["phase"]
        if phase in {"closed", "retired"}:
            want(all(slot[k] is None for k in ("runner", "invitation", "pairing", "rotation")), "closed shape")
        elif phase == "invited":
            want(slot["invitation"] is not None and slot["runner"] is None and slot["pairing"] is None, "invited shape")
        elif phase == "pending":
            want(slot["pairing"] is not None and slot["runner"] is None and slot["invitation"] is None, "pending shape")
        else:
            want(slot["runner"] is not None and slot["invitation"] is None, "active shape")
            want((slot["rotation"] is not None) == (phase == "rotating"), "rotation shape")
    want(len(canonical_registry_bytes(document)) <= 64 * 1024, "size")


@dataclass
class SlotState:
    slot_id: str
    address: str
    port: int
    peer: str
    namespace_id: str
    workspace_id: str | None = None
    phase: str = "closed"
    runner: dict | None = None
    invitation: dict | None = None
    pairing: dict | None = None
    rotation: dict | None = None
    projects: list = field(default_factory=list)
    contexts: list = field(default_factory=list)
    runs: list = field(default_factory=list)

    def document(self) -> dict:
        return {
            "slot_id": self.slot_id, "listener": {"address": self.address, "port": self.port},
            "peer": self.peer, "namespace_id": self.namespace_id, "workspace_id": self.workspace_id,
            "phase": self.phase, "runner": self.runner, "invitation": self.invitation,
            "pairing": self.pairing, "rotation": self.rotation, "projects": list(self.projects),
            "contexts": list(self.contexts), "runs": list(self.runs),
        }


class RegistryController:
    """The trusted fixture controller (SEAM-REGISTRY). Transitions use only confirmed CP state."""

    def __init__(self, path: Path, *, owner_uid: int, boot_epoch: str, backend: tuple[str, int],
                 management: tuple[str, int], management_peer: str, slots: list[SlotState],
                 chown: Callable[[Path, int], None] | None = None):
        self.path = path
        self.owner_uid = owner_uid
        self.boot_epoch = boot_epoch
        self.backend = backend
        self.management = management
        self.management_peer = management_peer
        self.slots = {slot.slot_id: slot for slot in slots}
        self.generation = 0
        self.expires_at_ms = int(time.time() * 1000) + 3 * 3600 * 1000
        self._chown = chown
        self.lock = threading.Lock()

    def document(self, generation: int | None = None) -> dict:
        return {
            "schema_version": REGISTRY_SCHEMA, "host_boot_epoch": self.boot_epoch,
            "config_generation": self.generation if generation is None else generation,
            "public_origin": ORIGIN,
            "backend": {"address": self.backend[0], "port": self.backend[1]},
            "management": {"address": self.management[0], "port": self.management[1], "peer": self.management_peer},
            "expires_at_ms": self.expires_at_ms,
            "slots": [slot.document() for slot in self.slots.values()],
        }

    def publish(self) -> int:
        with self.lock:
            self.generation += 1
            document = self.document()
            validate_registry(
                document, boot_epoch=self.boot_epoch, backend=f"{self.backend[0]}:{self.backend[1]}",
                management=f"{self.management[0]}:{self.management[1]}", peer=self.management_peer,
            )
            self.write_raw(canonical_registry_bytes(document))
            return self.generation

    def write_raw(self, data: bytes, *, mode: int = 0o644) -> None:
        """Atomically replace the fixed registry path (also used for deliberate negatives)."""
        temporary = self.path.with_name(f".registry-{secrets.token_hex(6)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self._chown is not None:
            self._chown(temporary, self.owner_uid)
        os.chmod(temporary, mode)
        os.replace(temporary, self.path)

    def replace_with_symlink(self, target: Path) -> None:
        temporary = self.path.with_name(f".registry-{secrets.token_hex(6)}.lnk")
        os.symlink(target, temporary)
        os.replace(temporary, self.path)

    def slot(self, slot_id: str) -> SlotState:
        return self.slots[slot_id]

    # Transitions -------------------------------------------------------------------------
    def invite(self, slot_id: str, *, workspace_id: str, token: str, pairing_id: str,
               public_key_b64: str, expires_at_ms: int) -> int:
        slot = self.slots[slot_id]
        raw = base64.b64decode(public_key_b64, validate=True)
        slot.workspace_id, slot.phase = workspace_id, "invited"
        slot.runner = slot.pairing = slot.rotation = None
        slot.invitation = {
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(), "pairing_id": pairing_id,
            "expires_at_ms": expires_at_ms, "expected_public_key_b64": public_key_b64,
            "expected_fingerprint": hashlib.sha256(raw).hexdigest(),
        }
        return self.publish()

    def pending(self, slot_id: str, row: dict) -> int:
        slot = self.slots[slot_id]
        slot.phase, slot.invitation = "pending", None
        slot.pairing = {
            "pairing_id": row["pairing_id"], "runner_id": row["runner_id"], "runner_key_id": row["key_id"],
            "fingerprint": row["fingerprint"], "control_protocol": "heel.runner-control.v2",
            "pairing_exchange_digest": row["exchange_digest"], "expires_at_ms": row["expires_at_ms"],
        }
        return self.publish()

    def activate(self, slot_id: str, identity: dict) -> int:
        slot = self.slots[slot_id]
        slot.phase = "active"
        if slot.pairing is not None:
            # Bounded receipt recovery: the activated ceremony stays registered for exact retries.
            slot.pairing = dict(slot.pairing, expires_at_ms=min(self.expires_at_ms, int(time.time() * 1000) + 3600 * 1000))
        slot.runner = {"runner_id": identity["runner_id"], "runner_key_id": identity["key_id"],
                       "public_key_digest": identity["public_key_digest"]}
        return self.publish()

    def add_project(self, slot_id: str, project: dict) -> int:
        slot = self.slots[slot_id]
        if project not in slot.projects:
            slot.projects.append(project)
        return self.publish()

    def add_context(self, slot_id: str, context: dict) -> int:
        slot = self.slots[slot_id]
        slot.contexts = [item for item in slot.contexts if item["binding_id"] != context["binding_id"]] + [context]
        return self.publish()

    def add_run(self, slot_id: str, run: dict) -> int:
        slot = self.slots[slot_id]
        for existing in slot.runs:
            if existing["state"] == "admitted":
                existing["state"] = "retained"
        slot.runs = [item for item in slot.runs if item["run_id"] != run["run_id"]][-7:] + [dict(run, state="admitted")]
        return self.publish()

    def rotating(self, slot_id: str, rotation: dict) -> int:
        slot = self.slots[slot_id]
        slot.phase, slot.rotation = "rotating", rotation
        return self.publish()

    def rotated(self, slot_id: str, identity: dict) -> int:
        slot = self.slots[slot_id]
        slot.phase, slot.rotation = "active", None
        slot.runner = {"runner_id": identity["runner_id"], "runner_key_id": identity["key_id"],
                       "public_key_digest": identity["public_key_digest"]}
        return self.publish()

    def set_phase(self, slot_id: str, phase: str) -> int:
        self.slots[slot_id].phase = phase
        return self.publish()

    def close(self, slot_id: str) -> int:
        slot = self.slots[slot_id]
        slot.phase, slot.workspace_id = "closed", None
        slot.runner = slot.invitation = slot.pairing = slot.rotation = None
        slot.projects, slot.contexts, slot.runs = [], [], []
        return self.publish()


# ---------------------------------------------------------------------------------------------
# Child programs. Each runs as ``python -I host_ingress_harness.py <role>`` with one JSON config
# line on stdin, then JSON-line RPC on stdin/stdout. Secrets cross only these private pipes.

def _child_send(message: dict, lock=threading.Lock()) -> None:  # noqa: B008 - one lock per process
    with lock:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def _child_lines():
    for line in sys.stdin:
        line = line.strip()
        if line:
            yield json.loads(line)


_RUNNER_TABLES = (
    "canary_runner_pairings", "canary_runner_pairing_protocols", "canary_runner_pairing_activation_receipts",
    "canary_runner_pairing_activation_abort_receipts", "canary_runner_keys", "canary_runners",
    "canary_runner_identity_records", "canary_runner_execution_protocols", "canary_runner_nonce_chains",
    "canary_runner_chain_cursors", "canary_runner_request_ledger", "canary_runner_resync_challenges",
    "canary_runner_rotations", "canary_runner_rotation_activation_receipts",
    "canary_runner_rotation_activation_abort_receipts", "canary_runner_audit_records",
    "canary_runner_context_bindings", "canary_runner_context_events", "canary_runs", "canary_run_events",
    "canary_execution_grants", "canary_approval_projections", "canary_operational_receipts",
)


def _cp_child(config: dict) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from heel.crypto import SigningAuthority, ed25519_key_id
    from heel.saas.http_api import ControlPlane, serve

    zone: dict[str, list[str]] = {}
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config["grant_seed"]))
    authority = SigningAuthority.from_private_key(
        private, ed25519_key_id(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
    control_plane = ControlPlane(
        config["database"], public_origin=ORIGIN, edge_auth_secret=config["edge_secret"],
        device_token_pepper=bytes.fromhex(config["device_pepper"]),
        runner_auth_pepper=bytes.fromhex(config["runner_pepper"]), enable_device_auth=True,
        trust_edge_client_key=True, grant_authority=authority,
        grant_trusted_keys={authority.key_id: authority.public_key},
        environment_dns_txt=lambda name: list(zone.get(name, ())),  # SEAM-ENV-DNS
    )
    server = serve(control_plane, config["address"], config["port"])
    seen: list[str] = []
    base = server.RequestHandlerClass

    class Observed(base):  # observation only: counts what reached the backend
        def parse_request(self):
            ok = super().parse_request()
            if ok:
                seen.append(f"{self.command} {self.path}")
            return ok

    server.RequestHandlerClass = Observed
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def query(sql: str, args: tuple = ()) -> list[dict]:
        with control_plane.request_lock:
            cursor = control_plane.store.conn.execute(sql, args)
            names = [item[0] for item in cursor.description]
            return [dict(zip(names, row)) for row in cursor.fetchall()]

    def state() -> dict[str, str]:
        digests = {}
        with control_plane.request_lock:
            for table in _RUNNER_TABLES:
                rows = control_plane.store.conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608 - fixed names
                digests[table] = hashlib.sha256(json.dumps(sorted(repr(tuple(row)) for row in rows)).encode()).hexdigest()
        return digests

    _child_send({"event": "ready", "grant_key_id": authority.key_id,
                 "grant_public_key_b64": base64.b64encode(authority.public_key.public_bytes_raw()).decode()})
    for message in _child_lines():
        command, reply = message["cmd"], {"id": message.get("id")}
        try:
            if command == "zone":
                zone[message["name"]] = list(message["values"])
            elif command == "snapshot":
                reply.update(requests=len(seen), seen=list(seen), state=state())
            elif command == "pairing_for_token":
                token_hash = control_plane.runner_auth._hash("invitation", message["token"])
                rows = query("SELECT pairing_id, expires_at FROM canary_runner_pairings WHERE invitation_hash=?", (token_hash,))
                reply.update(rows=rows)
            elif command == "pairing":
                reply.update(rows=query(
                    "SELECT p.pairing_id, p.workspace_id, p.runner_id, p.status, p.fingerprint, p.key_id, p.expires_at,"
                    " q.exchange_digest FROM canary_runner_pairings p LEFT JOIN canary_runner_pairing_protocols q"
                    " ON q.pairing_id=p.pairing_id WHERE p.pairing_id=?", (message["pairing_id"],)))
            elif command == "identity":
                reply.update(rows=query(
                    "SELECT key_id, public_key, status FROM canary_runner_keys WHERE workspace_id=? AND runner_id=?"
                    " AND status='active' AND revoked_at IS NULL", (message["workspace_id"], message["runner_id"])))
            elif command == "binding":
                reply.update(rows=query(
                    "SELECT rcb_id, binding_digest, project_ref, environment_id, runner_id, runner_key_id,"
                    " verification_record_digest FROM canary_runner_context_bindings WHERE rcb_id=?",
                    (message["binding_id"],)))
            elif command == "run":
                reply.update(rows=query(
                    "SELECT r.run_id, r.project_ref, r.status, r.grant_id, r.approval_id, a.projection_digest,"
                    " a.manifest_digest FROM canary_runs r JOIN canary_approval_projections a"
                    " ON a.approval_id=r.approval_id WHERE r.run_id=?", (message["run_id"],)))
            elif command == "rotation":
                reply.update(rows=query(
                    "SELECT pairing_id, workspace_id, runner_id, key_id, fingerprint, status, expires_at"
                    " FROM canary_runner_rotations WHERE pairing_id=?", (message["rotation_id"],)))
            elif command == "stop":
                server.shutdown()
                server.server_close()
                _child_send(reply)
                return
            else:
                raise ValueError("unknown command")
            reply["ok"] = True
        except Exception as error:  # reported to the driver as a fixed class name only
            reply.update(ok=False, error=type(error).__name__)
        _child_send(reply)


class _ReportingSecretBackend:
    """SEAM-RUNNER-SECRET: RAM-only seeds; the public half is reported before exchange."""

    def __init__(self, on_store: Callable[[str, bytes], None]):
        self.values: dict[str, bytes] = {}
        self._on_store = on_store

    def load(self, label):
        value = self.values.get(label)
        return None if value is None else bytes(value)

    def store(self, label, seed):
        if label in self.values:
            raise ValueError("runner signing identity already exists")
        self._on_store(label, bytes(seed))
        self.values[label] = bytes(seed)

    def delete(self, label):
        self.values.pop(label, None)


class _RecordingTransport:
    """Records exact wire requests for replay negatives; delegates to the real HTTPS transport."""

    def __init__(self, inner, log: list):
        self._inner = inner
        self._log = log

    def post(self, path, *, headers=None, body=b""):
        entry = {"path": path, "headers": dict(headers or {}), "body": bytes(body), "status": None, "digest": None}
        self._log.append(entry)
        status, response_headers, payload = self._inner.post(path, headers=headers, body=body)
        entry["status"] = status
        entry["digest"] = None if payload is None else hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return status, response_headers, payload

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _runner_child(config: dict) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from heel.canary_contracts import canonical_bytes
    from heel.crypto import ed25519_key_id, load_public_key_base64
    from heel.runner.compiler import CanaryCompiler
    from heel.runner.control_client import RunnerControlClient
    from heel.runner.control_transport import ControlTransportError, HTTPSControlTransport
    from heel.runner.coordinator import RunnerCoordinator
    from heel.runner.daemon import RunnerDaemon, _random_nonce
    from heel.runner.openapi_routes import RouteInventory
    from heel.runner.runtime import RunnerRuntimeState

    home = Path(config["home"])
    wire: list[dict] = []
    gates = {"key": threading.Event(), "pending": threading.Event()}
    gate_answer: dict[str, bool] = {}

    def wait_gate(name: str) -> None:
        # The trusted controller registers each ceremony step before the runner may continue.
        if not gates[name].wait(CHILD_TIMEOUT_SECONDS) or not gate_answer.get(name):
            raise ValueError("fixture controller did not register the ceremony step")

    def on_store(label: str, seed: bytes) -> None:
        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        _child_send({"event": "key", "public_key_b64": base64.b64encode(public).decode(),
                     "fingerprint": hashlib.sha256(public).hexdigest()})
        wait_gate("key")

    backend = _ReportingSecretBackend(on_store)

    class Daemon(RunnerDaemon):
        def _transport(self, origin):
            return _RecordingTransport(super()._transport(origin), wire)

    def daemon(ca: str | None = None) -> RunnerDaemon:
        return Daemon(home, secret_backend=backend, ca_bundle=ca or config["ca"], poll_interval_seconds=0.05)

    state: dict[str, Any] = {}
    run_lock = threading.RLock()

    def fresh_chain(operation: str, run_id: str | None) -> None:
        # CP nonces live 60 s. Like the serve loop, never use a chain idle past that window: resync
        # it through the real protocol first (CP owns challenge, generation and replay).
        cursor = state["runtime"].load_chain(operation, run_id)
        if cursor is not None and state["daemon"]._clock_ms() - cursor.updated_at_ms < 40_000:
            return
        control = state["control"]
        control.complete_resync(control.start_resync(operation=operation, run_id=run_id))

    def open_coordinator() -> None:
        close_coordinator()
        runner = daemon()
        record = runner._load_record(runner._store())
        identity, signer = runner._active_identity(runner._store(), record)
        authority = runner._grant_authority(record)
        trusted = {authority["key_id"]: load_public_key_base64(authority["public_key_b64"])}
        runtime = RunnerRuntimeState(runner.runtime_path, identity, signer)
        control = RunnerControlClient(
            origin=record["origin"], workspace_id=identity.workspace_id, runner_id=identity.runner_id,
            signer=signer, clock=runner._clock_ms, transport=runner._transport(record["origin"]),
            nonce_source=_random_nonce, runtime=runtime, trusted_disclosure_keys=trusted,
        )
        coordinator = RunnerCoordinator(control=control, store=runner._store(), identity=identity, signer=signer,
                                        trusted_grant_keys=trusted, clock_ms=runner._clock_ms)
        state.update(daemon=runner, record=record, identity=identity, signer=signer, runtime=runtime,
                     control=control, coordinator=coordinator, trusted=trusted)

    def close_coordinator() -> None:
        runtime = state.pop("runtime", None)
        for name in ("daemon", "record", "identity", "signer", "control", "coordinator", "trusted"):
            state.pop(name, None)
        if runtime is not None:
            runtime.close()

    def error_code(error: BaseException) -> str:
        if isinstance(error, ControlTransportError):
            return "transport:" + error.code
        code = getattr(error, "code", None)
        return type(error).__name__ + (":" + code if isinstance(code, str) else "")

    def run_pair(token: str, display_name: str) -> None:
        events = []

        def emit(event):
            events.append(event)
            if event.get("event") == "pairing_pending":
                _child_send({"event": "pairing_pending", "pairing_id": event["pairing_id"],
                             "pairing_phrase": event["pairing_phrase"], "fingerprint": event["fingerprint"]})
                wait_gate("pending")
        try:
            result = daemon().pair(ORIGIN, token, display_name=display_name, emit=emit)
            record = daemon()._load_record(daemon()._store())
            _child_send({"event": "pair_done", "ok": True, "state": result.get("state"),
                         "runner_id": record["runner_id"], "runner_key_id": record["runner_key_id"],
                         "workspace_id": record["workspace_id"],
                         "grant_authority_key_id": record.get("grant_authority_key_id")})
        except BaseException as error:  # noqa: BLE001 - reported as a fixed code
            _child_send({"event": "pair_done", "ok": False, "error": error_code(error)})

    _child_send({"event": "ready"})
    for message in _child_lines():
        command, reply = message["cmd"], {"id": message.get("id")}
        try:
            if command == "pair":
                for event in gates.values():
                    event.clear()
                gate_answer.clear()
                threading.Thread(target=run_pair, args=(message["token"], message["display_name"]), daemon=True).start()
            elif command == "continue":
                gate_answer[message["gate"]] = bool(message["value"])
                gates[message["gate"]].set()
            elif command == "status":
                reply.update(status=daemon().status(check_control_plane=bool(message.get("check", True))))
            elif command == "open":
                open_coordinator()
                record = state["record"]
                reply.update(runner_id=record["runner_id"], runner_key_id=record["runner_key_id"],
                             grant_authority_key_id=record["grant_authority_key_id"],
                             seeds=len(backend.values))
            elif command == "ensure_context":
                reply.update(value=state["coordinator"].ensure_runner_context())
            elif command == "compile_submit":
                store = state["coordinator"].store
                specification = json.loads(Path(config["openapi"]).read_text(encoding="utf-8"))
                inventory = RouteInventory(specification)
                store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
                store.save_mapping("anonymous_authenticated_read", method="HEAD", route_template="/health")
                store.save_mapping("object_ownership_read", method="GET", route_template="/items/{item_id}",
                                   fixture_bindings={"item_id": "canary-a-item-0137"})
                for role in ("authenticated", "object_owner", "non_owner"):
                    with contextlib.suppress(Exception):
                        store.register_ephemeral_credential(semantic_role=role, auth_profile="bearer",
                                                            source_kind="environment", label=f"local {role}")
                result = CanaryCompiler(store=store, identity=state["identity"], signer=state["signer"],
                                        now_ms=state["daemon"]._clock_ms()).compile(
                    ["anonymous_authenticated_read", "object_ownership_read"], projection_id=message.get("projection_id"))
                submitted = state["coordinator"].submit_cloud_context_approval(result.projection)
                state["compiled_projection"] = result.projection
                reply.update(run_id=submitted["run_id"], approval_id=submitted["approval_id"], projection=result.projection,
                             projection_id=result.projection["projection_id"],
                             projection_digest=result.projection["projection_digest"],
                             manifest_digest=result.manifest["manifest_digest"])
            elif command == "claim":
                with run_lock:
                    fresh_chain("claim", None)
                    lease = state["coordinator"].claim()
                if lease is None:
                    reply.update(lease=None)
                else:
                    state["lease"] = lease
                    grant = lease.bundle.grant
                    reply.update(lease={"run_id": lease.run_id, "grant_id": grant["grant_id"],
                                        "grant_digest": grant["grant_digest"],
                                        "signing_key_id": grant["signing_key_id"], "verified": True})
            elif command == "heartbeat":
                lease = state["lease"]
                with run_lock:
                    fresh_chain("heartbeat", lease.run_id)
                    gate_value = state["coordinator"].heartbeat(lease.run_id, state.get("projection") or lease.operational_projection)
                reply.update(active=bool(getattr(gate_value, "active", False)))
            elif command == "progress":
                # The runner signs its own next operational projection; the CP verifies it.
                from heel.canary_contracts import canonical_digest, validate_operational_run

                lease = state["lease"]
                previous = state.get("projection") or lease.operational_projection
                unsigned = {key: json.loads(json.dumps(value)) for key, value in previous.items()
                            if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
                now_ms = state["daemon"]._clock_ms()
                unsigned["event_sequence"] += 1
                unsigned["lifecycle_phase"] = "running"
                unsigned["timestamps"]["started_at_ms"] = unsigned["timestamps"]["started_at_ms"] or now_ms
                unsigned["timestamps"]["updated_at_ms"] = now_ms
                signed = validate_operational_run({
                    **unsigned, "projection_digest": canonical_digest(unsigned),
                    "signing_key_id": state["signer"].key_id,
                    "signature_b64": base64.b64encode(state["signer"].sign(canonical_bytes(unsigned))).decode(),
                })
                with run_lock:
                    fresh_chain("progress", lease.run_id)
                    response = state["coordinator"].progress(lease.run_id, signed)
                    state["projection"] = signed
                reply.update(status=response.get("status") if isinstance(response, dict) else None)
            elif command == "stop_ack":
                # After the owner's stop, the next heartbeat carries the stop gate; acknowledge it.
                from heel.canary_contracts import canonical_digest, validate_operational_run

                lease = state["lease"]
                previous = state.get("projection") or lease.operational_projection
                unsigned = {key: json.loads(json.dumps(value)) for key, value in previous.items()
                            if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
                now_ms = state["daemon"]._clock_ms()
                unsigned["event_sequence"] += 1
                unsigned["lifecycle_phase"] = "stop_requested"
                unsigned["stop_reason"] = "cloud_stop"
                unsigned["timestamps"]["started_at_ms"] = unsigned["timestamps"]["started_at_ms"] or now_ms
                unsigned["timestamps"]["updated_at_ms"] = now_ms
                unsigned["timestamps"]["stop_requested_at_ms"] = now_ms
                signed = validate_operational_run({
                    **unsigned, "projection_digest": canonical_digest(unsigned),
                    "signing_key_id": state["signer"].key_id,
                    "signature_b64": base64.b64encode(state["signer"].sign(canonical_bytes(unsigned))).decode(),
                })
                with run_lock:
                    fresh_chain("stop-ack", lease.run_id)
                    ack = state["coordinator"].stop_ack(lease.run_id, signed, deadline=time.monotonic() + 20)
                    # The coordinator sent `signed` plus its acknowledgement time; Ed25519 is
                    # deterministic, so re-signing that exact projection reproduces what CP received.
                    acked = {key: json.loads(json.dumps(value)) for key, value in signed.items()
                             if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
                    acked["timestamps"]["stop_acknowledged_at_ms"] = ack.acknowledged_at_ms
                    acked["timestamps"]["updated_at_ms"] = max(acked["timestamps"]["updated_at_ms"], ack.acknowledged_at_ms)
                    state["projection"] = validate_operational_run({
                        **acked, "projection_digest": canonical_digest(acked), "signing_key_id": state["signer"].key_id,
                        "signature_b64": base64.b64encode(state["signer"].sign(canonical_bytes(acked))).decode(),
                    })
                reply.update(accepted=bool(ack.accepted), deadline_met=bool(ack.deadline_met))
            elif command == "terminal_result":
                # Runner-built, runner-signed ordinary terminal result on its live result chain. No
                # executor exists in H0B, so the runner's local terminal anchor is not exercised.
                from heel.canary_contracts import canonical_digest, validate_operational_run

                lease = state["lease"]
                previous = state.get("projection") or lease.operational_projection
                unsigned = {key: json.loads(json.dumps(value)) for key, value in previous.items()
                            if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
                now_ms = state["daemon"]._clock_ms()
                unsigned["event_sequence"] += 1
                unsigned["lifecycle_phase"] = "terminal"
                unsigned["execution_disposition"] = message.get("disposition", "completed")
                unsigned["timestamps"]["started_at_ms"] = unsigned["timestamps"]["started_at_ms"] or now_ms
                unsigned["timestamps"]["updated_at_ms"] = now_ms
                unsigned["timestamps"]["terminal_at_ms"] = now_ms
                signed = validate_operational_run({
                    **unsigned, "projection_digest": canonical_digest(unsigned),
                    "signing_key_id": state["signer"].key_id,
                    "signature_b64": base64.b64encode(state["signer"].sign(canonical_bytes(unsigned))).decode(),
                })
                with run_lock:
                    fresh_chain("result", lease.run_id)
                    cursor = state["runtime"].load_chain("result", lease.run_id)
                path = f"/v1/workspaces/{state['identity'].workspace_id}/runners/{state['identity'].runner_id}/runs/{lease.run_id}/result"
                body = canonical_bytes({"schema_version": "heel.runner-result-request.v1", "run_id": lease.run_id,
                                        "operational_projection": signed})
                proof = {
                    "schema_version": "heel.runner-request-proof.v1", "workspace_id": state["identity"].workspace_id,
                    "runner_id": state["identity"].runner_id, "key_id": state["signer"].key_id,
                    "capability": "runner_result", "method": "POST", "path": path,
                    "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": now_ms,
                    "server_nonce": cursor.next_nonce_b64, "sequence": cursor.next_sequence,
                }
                signature = state["signer"].sign(b"heel.runner-pop.v1\0" + canonical_bytes(proof))
                headers = {
                    "Content-Type": "application/json", "X-Heel-Runner-Id": state["identity"].runner_id,
                    "X-Heel-Runner-Key-Id": state["signer"].key_id, "X-Heel-Runner-Timestamp-Ms": str(now_ms),
                    "X-Heel-Runner-Nonce": cursor.next_nonce_b64, "X-Heel-Runner-Sequence": str(cursor.next_sequence),
                    "X-Heel-Runner-Signature": base64.b64encode(signature).decode(),
                }
                with run_lock:
                    status, _h, payload = HTTPSControlTransport(ORIGIN, ca_bundle=config["ca"]).post(path, headers=headers, body=body)
                if status == 200:
                    state["terminal"] = True
                reply.update(status=status, run_status=(payload or {}).get("status"))
            elif command == "pop_send":
                # One request signed by this runner's real key on its live chain cursor; afterwards the
                # chain is realigned through the real resync protocol (CP decides what was consumed).
                path, body = message["path"], base64.b64decode(message["body_b64"])
                operation, run_id = message["operation"], message.get("run_id")
                with run_lock:
                    fresh_chain(operation, run_id)
                    cursor = state["runtime"].load_chain(operation, run_id)
                    now_ms = state["daemon"]._clock_ms()
                    proof = {
                        "schema_version": "heel.runner-request-proof.v1", "workspace_id": state["identity"].workspace_id,
                        "runner_id": state["identity"].runner_id, "key_id": state["signer"].key_id,
                        "capability": message["capability"], "method": "POST", "path": path,
                        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": now_ms,
                        "server_nonce": cursor.next_nonce_b64, "sequence": cursor.next_sequence,
                    }
                    headers = {
                        "Content-Type": "application/json", "X-Heel-Runner-Id": state["identity"].runner_id,
                        "X-Heel-Runner-Key-Id": state["signer"].key_id, "X-Heel-Runner-Timestamp-Ms": str(now_ms),
                        "X-Heel-Runner-Nonce": cursor.next_nonce_b64, "X-Heel-Runner-Sequence": str(cursor.next_sequence),
                        "X-Heel-Runner-Signature": base64.b64encode(state["signer"].sign(
                            b"heel.runner-pop.v1\0" + canonical_bytes(proof))).decode(),
                    }
                    transport = HTTPSControlTransport(ORIGIN, ca_bundle=config["ca"])
                    try:
                        status, _h, _payload = transport.post(path, headers=headers, body=body)
                        reply.update(status=status, code=transport.last_error_code, error=None)
                    except ControlTransportError as error:
                        reply.update(status=None, error=error.code)
                    if message.get("realign", True):
                        control = state["control"]
                        control.complete_resync(control.start_resync(operation=operation, run_id=run_id))
            elif command == "chain":
                cursor = state["runtime"].load_chain(message["operation"], message.get("run_id"))
                reply.update(nonce=None if cursor is None else cursor.next_nonce_b64,
                             sequence=None if cursor is None else cursor.next_sequence)
            elif command == "resync_chain":
                with run_lock:
                    control = state["control"]
                    recovered = control.complete_resync(control.start_resync(operation=message["operation"],
                                                                             run_id=message.get("run_id")))
                reply.update(generation=recovered.generation)
            elif command == "resync":
                control = state["control"]
                pending = control.start_resync(operation="claim")
                recovered = control.complete_resync(pending)
                reply.update(generation=recovered.generation)
            elif command == "idle_claim":
                status, _headers, payload = state["control"].claim()
                reply.update(status=status, payload_present=payload is not None)
            elif command == "restart":
                with run_lock:
                    open_coordinator()
                record = state["record"]
                reply.update(runner_key_id=record["runner_key_id"],
                             grant_authority_key_id=record["grant_authority_key_id"], seeds=len(backend.values))
            elif command == "wire":
                index = message["index"]
                entry = wire[index]
                reply.update(count=len(wire), path=entry["path"], headers=entry["headers"],
                             body_b64=base64.b64encode(entry["body"]).decode(), status=entry["status"],
                             digest=entry["digest"])
            elif command == "wire_find":
                matches = [index for index, entry in enumerate(wire) if entry["path"].endswith(message["suffix"])
                           and (message.get("status") is None or entry["status"] == message["status"])]
                reply.update(indexes=matches)
            elif command == "wire_count":
                reply.update(count=len(wire))
            elif command == "send":
                # Re-send exact or mutated bytes through the same real HTTPS transport.
                transport = HTTPSControlTransport(ORIGIN, ca_bundle=config["ca"])
                try:
                    status, headers, payload = transport.post(
                        message["path"], headers=message["headers"], body=base64.b64decode(message["body_b64"]))
                    reply.update(status=status, error=None, code=transport.last_error_code,
                                 digest=None if payload is None else hashlib.sha256(json.dumps(
                                     payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                                 next_nonce=headers.get("X-Heel-Runner-Next-Nonce") is not None)
                except ControlTransportError as error:
                    reply.update(status=None, error=error.code)
            elif command == "sign_pop":
                # A well-formed proof for this slot's runner signed by a fresh, unregistered key
                # (or by the real key when ``real`` is set): ingress syntax passes; CP decides.
                signer = state["signer"]
                path, body = message["path"], base64.b64decode(message["body_b64"])
                private = None if message.get("real") else Ed25519PrivateKey.generate()
                proof = {
                    "schema_version": "heel.runner-request-proof.v1", "workspace_id": state["identity"].workspace_id,
                    "runner_id": state["identity"].runner_id, "key_id": signer.key_id,
                    "capability": message["capability"], "method": "POST", "path": path,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "timestamp_ms": int(message.get("timestamp_ms") or time.time() * 1000),
                    "server_nonce": message["nonce"], "sequence": message["sequence"],
                }
                payload = b"heel.runner-pop.v1\0" + canonical_bytes(proof)
                signature = signer.sign(payload) if private is None else private.sign(payload)
                reply.update(headers={
                    "Content-Type": "application/json", "X-Heel-Runner-Id": state["identity"].runner_id,
                    "X-Heel-Runner-Key-Id": signer.key_id, "X-Heel-Runner-Timestamp-Ms": str(proof["timestamp_ms"]),
                    "X-Heel-Runner-Nonce": message["nonce"], "X-Heel-Runner-Sequence": str(message["sequence"]),
                    "X-Heel-Runner-Signature": base64.b64encode(signature).decode(),
                })
            elif command == "trust_failure":
                # Real transport against the ingress with a substituted constructor CA bundle.
                transport = HTTPSControlTransport(ORIGIN, ca_bundle=message["ca"])
                try:
                    transport.post("/v1/runner-pairings/exchange", headers={"Content-Type": "application/json"}, body=b"{}")
                    reply.update(error=None)
                except ControlTransportError as error:
                    reply.update(error=error.code)
            elif command == "rotation_keys":
                fresh = Ed25519PrivateKey.generate()
                raw = fresh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                state["rotation_private"] = fresh
                reply.update(public_key_b64=base64.b64encode(raw).decode(), key_id=ed25519_key_id(raw),
                             fingerprint=hashlib.sha256(raw).hexdigest(),
                             old_fingerprint=state["identity"].fingerprint)
            elif command == "rotation_activate":
                rotation_id, challenge = message["rotation_id"], message.get("challenge")
                transport = HTTPSControlTransport(ORIGIN, ca_bundle=config["ca"])
                path = f"/v1/runner-rotations/{rotation_id}/poll"
                status, _h, polled = transport.post(path, headers={"Content-Type": "application/json"}, body=b"{}")
                reply.update(poll_status=status)
                if status == 200:
                    challenge = polled["activation_challenge"]
                    proof = b"heel.runner-rotation-activate.v2\0" + canonical_bytes(
                        {"pairing_id": rotation_id, "challenge": challenge})
                    request = canonical_bytes({"schema_version": "heel.runner-rotation-activate.v2",
                                               "signature_b64": base64.b64encode(state["rotation_private"].sign(proof)).decode()})
                    status, _h, activated = transport.post(f"/v1/runner-rotations/{rotation_id}/activate",
                                                           headers={"Content-Type": "application/json"}, body=request)
                    reply.update(activate_status=status, activated=activated if status == 200 else None)
            elif command == "stop":
                with run_lock:
                    close_coordinator()
                _child_send(reply)
                return
            else:
                raise ValueError("unknown command")
            reply["ok"] = True
        except Exception as error:  # noqa: BLE001 - fixed code only
            reply.update(ok=False, error=error_code(error))
        _child_send(reply)


def _probe_child(config: dict) -> None:
    """One bounded raw TCP/TLS exchange from inside this namespace; reports bytes to the driver."""
    started = time.monotonic()
    result: dict[str, Any] = {"connected": False, "tls": None, "error": None, "received_b64": "", "elapsed_ms": 0}
    raw = None
    try:
        raw = socket.create_connection((config["address"], config["port"]), timeout=config.get("connect_timeout", 3))
        result["connected"] = True
        sock: socket.socket = raw
        if config["mode"] == "tls":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if config.get("ca"):
                context.load_verify_locations(cafile=config["ca"])
                context.check_hostname = bool(config.get("check_hostname", True)) and config.get("server_name") is not None
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # only for handshake-shape probes; never product trust
            sock.settimeout(config.get("handshake_timeout", 5))
            try:
                sock = context.wrap_socket(raw, server_hostname=config.get("server_name"))
                certificate = sock.getpeercert(binary_form=True)
                result["tls"] = {"ok": True, "version": sock.version(),
                                 "certificate_sha256": hashlib.sha256(certificate).hexdigest() if certificate else None}
            except (ssl.SSLError, OSError) as error:
                result["tls"] = {"ok": False, "error": type(error).__name__,
                                 "verify": getattr(error, "verify_message", None)}
                raise
        # Wall-clock marks (comparable with the scripted backend's): when each chunk was sent, the
        # first response byte arrived and the peer closed. Reading interleaves with the send
        # schedule, so a response or close during a dribble is observed when it happens.
        wall = result["wall"] = {"sent": [], "first_byte": None, "closed": None}
        received = bytearray()
        limit = config.get("max_bytes", 512 * 1024)
        deadline = None

        def pump(until: float) -> bool:
            """Read until ``until`` (monotonic); False once the peer closed or failed."""
            while len(received) < limit:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return True
                sock.settimeout(max(0.01, remaining))
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    return True
                except (ssl.SSLError, OSError) as error:
                    result["error"] = type(error).__name__
                    wall["closed"] = time.time()
                    return False
                if not data:
                    result["peer_closed"] = True
                    wall["closed"] = time.time()
                    return False
                if wall["first_byte"] is None:
                    wall["first_byte"] = time.time()
                received.extend(data)
            return True

        open_ = True
        for delay_ms, chunk in config.get("chunks", []):
            if delay_ms:
                if open_ and not config.get("close_after_send"):
                    open_ = pump(time.monotonic() + delay_ms / 1000)
                else:
                    time.sleep(delay_ms / 1000)
            if not open_ and not config.get("send_after_close"):
                break
            try:
                sock.sendall(base64.b64decode(chunk))
                wall["sent"].append(time.time())
            except (ssl.SSLError, OSError) as error:
                result["send_error"] = type(error).__name__
                wall["sent"].append(None)
                if not config.get("send_after_close"):
                    break
        if config.get("shutdown_write"):
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
        if config.get("close_after_send"):
            sock.close()
            result["closed_by_client"] = True
        else:
            deadline = time.monotonic() + config.get("read_timeout", 10)
            if open_ and pump(deadline) and wall["closed"] is None and len(received) < limit:
                result["error"] = "read_timeout"
            result["received_b64"] = base64.b64encode(bytes(received)).decode()
    except Exception as error:  # noqa: BLE001 - classified, not raised
        if result["error"] is None:
            result["error"] = type(error).__name__
    finally:
        if raw is not None:
            with contextlib.suppress(OSError):
                raw.close()
    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    _child_send(result)


def _scripted_child(config: dict) -> None:
    """SEAM-SCRIPTED-BACKEND (response-parser negatives only, labelled separately): answers at the
    backend address either with fixed raw responses or by forwarding to the real CP and mutating
    one named field of its reply. It never stands in for the real G3 chain."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from heel.canary_contracts import canonical_bytes
    from heel.crypto import SigningAuthority, ed25519_key_id

    seen: list[str] = []
    events: list[dict] = []
    rules = list(config.get("rules", []))
    other = SigningAuthority.generate()

    def paced(connection: socket.socket, pieces: list, event: dict) -> None:
        """Write ``pieces`` ([delay_ms, b64] each) on schedule, watching for the peer's EOF/RST in
        every gap; record wall-clock times only (never bytes)."""
        for delay_ms, piece in pieces:
            until = time.monotonic() + delay_ms / 1000
            while (remaining := until - time.monotonic()) > 0:
                ready, _, _ = select.select([connection], [], [], remaining)
                if not ready:
                    continue
                try:
                    peeked = connection.recv(1, socket.MSG_PEEK)
                except OSError:
                    peeked = b""
                if not peeked:
                    event["eof"] = time.time()
                    return
                connection.recv(65536)
            try:
                connection.sendall(base64.b64decode(piece))
            except OSError:
                event["eof"] = time.time()
                return
        event["completed"] = time.time()

    def mutate(kind: str, payload: dict) -> dict:
        if kind == "grant_authority":
            fresh = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            payload["grant_authority"] = {"key_id": ed25519_key_id(fresh), "public_key_b64": base64.b64encode(fresh).decode()}
        elif kind == "resign_grant":
            grant = payload["grant"]
            unsigned = {key: value for key, value in grant.items() if key not in {"signing_key_id", "signature_b64"}}
            unsigned.pop("grant_digest", None)
            payload["grant"] = {**unsigned, "grant_digest": grant["grant_digest"],
                                **other.sign(canonical_bytes(unsigned))}
        return payload

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            return

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            seen.append(f"{self.command} {self.path}")
            for rule in rules:
                if re.search(rule["path_re"], self.path) is None:
                    continue
                if rule.get("pieces"):
                    event = {"received": time.time(), "eof": None, "completed": None}
                    events.append(event)
                    self.wfile.flush()
                    paced(self.connection, rule["pieces"], event)
                    return
                if rule.get("delay_ms"):
                    time.sleep(rule["delay_ms"] / 1000)
                if "raw_b64" in rule:
                    with contextlib.suppress(OSError):
                        self.wfile.write(base64.b64decode(rule["raw_b64"]))
                    return
                upstream = http.client.HTTPConnection(config["upstream"][0], config["upstream"][1], timeout=10)
                forwarded = {name: value for name, value in self.headers.items()}
                upstream.request(self.command, self.path, body or None, forwarded)
                response = upstream.getresponse()
                raw = response.read()
                headers = [(name, value) for name, value in response.getheaders()
                           if name.lower() not in {"content-length", "connection", "date", "server"}]
                upstream.close()
                if response.status == 200 and rule.get("mutate"):
                    raw = json.dumps(mutate(rule["mutate"], json.loads(raw))).encode()
                self.send_response(response.status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = do_DELETE = _answer

    server = ThreadingHTTPServer((config["address"], config["port"]), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _child_send({"event": "ready"})
    for message in _child_lines():
        reply = {"id": message.get("id"), "ok": True}
        if message["cmd"] == "seen":
            reply.update(seen=list(seen), events=[dict(event) for event in events])
        elif message["cmd"] == "stop":
            server.shutdown()
            server.server_close()
            _child_send(reply)
            return
        _child_send(reply)


def _holder_child(_config: dict) -> None:
    """Keep this (already unshared) network namespace alive until stdin closes."""
    _child_send({"event": "ready", "pid": os.getpid()})
    sys.stdin.read()


_CHILD_ROLES = {"cp": _cp_child, "runner": _runner_child, "probe": _probe_child, "holder": _holder_child,
                "scripted": _scripted_child}


def child_main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in _CHILD_ROLES:
        return 2
    sys.path.insert(0, str(ROOT))
    config = json.loads(sys.stdin.readline())
    _CHILD_ROLES[argv[0]](config)
    return 0


# ---------------------------------------------------------------------------------------------
# Management client: the compiled Worker artifact under Node with the fixed private TLS adapter.
# The adapter block is extracted byte-for-byte by apps/heel-cloud/tests/host-ingress.test.ts.

FAKE_VPC_ADAPTER_JS = r"""
// BEGIN HEEL_FAKE_VPC_ADAPTER
// SEAM-FAKE-VPC: stands in for the Cloudflare VPC service binding. The binding selects the
// network destination (one fixed private address and port); the request URL supplies the TLS
// name and Host, verified against an explicitly supplied CA. Bytes are carried unchanged.
import tls from "node:tls";

export function createFakeVpcAdapter({ host, address, port, ca, timeoutMs = 25000, maxResponseBytes = 1048576 }) {
  const observations = [];
  async function fetch(request) {
    const url = new URL(request.url);
    if (url.origin !== `https://${host}` || url.search !== "" || url.hash !== "" || !url.pathname.startsWith("/v1/")) {
      throw new TypeError("unexpected control-plane request URL");
    }
    if (request.redirect !== "manual") throw new TypeError("control-plane requests never follow redirects");
    const body = request.method === "POST" ? new Uint8Array(await request.arrayBuffer()) : new Uint8Array();
    const lines = [`${request.method} ${url.pathname} HTTP/1.1`, `host: ${host}`];
    for (const [name, value] of request.headers) {
      if (name === "host" || name === "connection") throw new TypeError("binding request carries a transport header");
      lines.push(`${name}: ${value}`);
    }
    if (request.method === "POST" && request.headers.get("content-length") !== String(body.byteLength)) {
      throw new TypeError("binding request body differs from its declared length");
    }
    lines.push("connection: close");
    const head = Buffer.from(lines.join("\r\n") + "\r\n\r\n", "latin1");
    const raw = await new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: address, port, servername: host, ca, minVersion: "TLSv1.2", rejectUnauthorized: true,
        checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity(host, certificate),
        ALPNProtocols: ["http/1.1"],
      });
      const chunks = [];
      let total = 0;
      const timer = setTimeout(() => { socket.destroy(); reject(new Error("control-plane request timed out")); }, timeoutMs);
      socket.on("secureConnect", () => {
        observations.push({ servername: socket.servername, remote: `${socket.remoteAddress}:${socket.remotePort}`,
          authorized: socket.authorized, protocol: socket.getProtocol(), method: request.method, path: url.pathname,
          sent_bytes: head.byteLength + body.byteLength });
        socket.write(head);
        if (body.byteLength) socket.write(body);
      });
      socket.on("data", (chunk) => {
        total += chunk.byteLength;
        if (total > maxResponseBytes) { socket.destroy(); reject(new Error("control-plane response too large")); return; }
        chunks.push(chunk);
      });
      socket.on("error", (error) => { clearTimeout(timer); reject(error); });
      socket.on("end", () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    });
    const split = raw.indexOf("\r\n\r\n");
    if (split < 0) throw new TypeError("malformed control-plane response");
    const [statusLine, ...headerLines] = raw.subarray(0, split).toString("latin1").split("\r\n");
    const match = /^HTTP\/1\.[01] ([0-9]{3}) /.exec(statusLine + " ");
    if (match === null) throw new TypeError("malformed control-plane status");
    const headers = new Headers();
    let declared = null;
    for (const line of headerLines) {
      const colon = line.indexOf(":");
      if (colon <= 0) throw new TypeError("malformed control-plane header");
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (name === "content-length") {
        if (declared !== null) throw new TypeError("duplicate control-plane length");
        declared = Number(value);
      }
      if (name === "transfer-encoding") throw new TypeError("unsupported control-plane framing");
      if (name !== "connection") headers.append(name, value);
    }
    const payload = raw.subarray(split + 4);
    if (declared !== null && declared !== payload.byteLength) throw new TypeError("control-plane length mismatch");
    const status = Number(match[1]);
    return new Response(status === 204 || status === 304 ? null : payload, { status, headers });
  }
  return { fetch, observations };
}
// END HEEL_FAKE_VPC_ADAPTER
"""


def adapter_block() -> str:
    """The exact adapter source between its markers (hash-pinned by both test suites)."""
    begin = FAKE_VPC_ADAPTER_JS.index("// BEGIN HEEL_FAKE_VPC_ADAPTER")
    end = FAKE_VPC_ADAPTER_JS.index("// END HEEL_FAKE_VPC_ADAPTER") + len("// END HEEL_FAKE_VPC_ADAPTER")
    return FAKE_VPC_ADAPTER_JS[begin:end] + "\n"


WORKER_DRIVER_JS = r"""
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import readline from "node:readline";
import { createFakeVpcAdapter } from "./fake-vpc-adapter.mjs";

if (globalThis.FixedLengthStream === undefined) {
  globalThis.FixedLengthStream = class FixedLengthStream extends TransformStream {
    constructor(expectedLength) {
      let received = 0;
      super({
        transform(chunk, controller) {
          received += chunk.byteLength;
          if (received > expectedLength) throw new TypeError("fixed-length body overflow");
          controller.enqueue(chunk);
        },
        flush() { if (received !== expectedLength) throw new TypeError("fixed-length body underflow"); },
      });
    }
  };
}
globalThis.fetch = async () => { throw new Error("public fetch is not a control-plane path"); };
const context = { waitUntil() {}, passThroughOnException() {} };
let started = null;

async function start(config) {
  const adapter = createFakeVpcAdapter({ host: config.host, address: config.address, port: config.port,
    ca: fs.readFileSync(config.ca, "utf8") });
  const artifact = await import(pathToFileURL(config.server_index).href);
  const env = {
    ASSETS: { fetch: async () => new Response("not found", { status: 404 }) },
    IMAGES: { input: () => { throw new Error("image transform is not used by the control-plane route"); } },
    PUBLIC_ORIGIN: config.public_origin,
    CONTROL_PLANE_EDGE_SECRET: config.edge_secret,
    CONTROL_PLANE: adapter,
  };
  process.stdout.write(JSON.stringify({ event: "ready" }) + "\n");
  return { adapter, artifact, env, config };
}

// The first stdin line is the configuration; every later line is one browser request.
const input = readline.createInterface({ input: process.stdin });
input.on("line", (line) => {
  if (started === null) {
    started = start(JSON.parse(line));
    return;
  }
  started.then((state) => handle(state, JSON.parse(line)));
});

async function handle({ adapter, artifact, env, config }, message) {
  const reply = { id: message.id };
  try {
    const before = adapter.observations.length;
    const init = { method: message.method, headers: message.headers };
    if (message.body_b64 !== undefined && message.body_b64 !== null) init.body = Buffer.from(message.body_b64, "base64");
    const response = await artifact.default.fetch(new Request(`${config.public_origin}${message.path}`, init), env, context);
    const bytes = new Uint8Array(await response.arrayBuffer());
    reply.ok = true;
    reply.status = response.status;
    reply.headers = [...response.headers];
    reply.set_cookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    reply.body_b64 = Buffer.from(bytes).toString("base64");
    reply.observations = adapter.observations.slice(before);
  } catch (error) {
    reply.ok = false;
    reply.error = error && error.name ? error.name : "Error";
  }
  process.stdout.write(JSON.stringify(reply) + "\n");
}
"""


# ---------------------------------------------------------------------------------------------
# Processes and topology.

@dataclass
class ChildProcess:
    role: str
    process: subprocess.Popen
    identity: str
    rpc_in: Any = None
    rpc_out: Any = None
    _counter: int = 0
    _events: list = field(default_factory=list)

    def send(self, message: dict) -> None:
        self.rpc_in.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.rpc_in.flush()

    def read(self, timeout: float = CHILD_TIMEOUT_SECONDS) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{self.role} child did not answer")
            ready, _, _ = select.select([self.rpc_out], [], [], remaining)
            if ready:
                line = self.rpc_out.readline()
                if not line:
                    raise EOFError(f"{self.role} child closed its channel")
                return json.loads(line)

    def call(self, command: str, timeout: float = CHILD_TIMEOUT_SECONDS, **arguments) -> dict:
        self._counter += 1
        ident = self._counter
        self.send({"cmd": command, "id": ident, **arguments})
        while True:
            message = self.read(timeout)
            if message.get("id") == ident:
                return message
            self._events.append(message)

    def event(self, name: str, timeout: float = CHILD_TIMEOUT_SECONDS) -> dict:
        for index, message in enumerate(self._events):
            if message.get("event") == name:
                return self._events.pop(index)
        while True:
            message = self.read(timeout)
            if message.get("event") == name:
                return message
            self._events.append(message)


def process_identity(pid: int) -> str:
    """A start-time identity for an owned child (Linux /proc stat field 22), never a name pattern."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return f"{pid}:{stat.rsplit(')', 1)[1].split()[19]}"
    except (OSError, IndexError):
        return f"{pid}:unknown"


class Topology:
    """Where each role runs and how a process is placed there."""

    is_linux_namespaces = False

    def addresses(self) -> dict[str, tuple[str, str]]:
        raise NotImplementedError

    def ports(self) -> dict[str, int]:
        return {"backend": BACKEND_PORT, "management": MANAGEMENT_PORT, "runner": RUNNER_PORT, "ops": OPS_PORT}

    def slot_port(self, slot: str) -> int:
        return self.ports()["runner"]

    def uid(self, role: str) -> int:
        raise NotImplementedError

    def spawn(self, role: str, argv: list[str], *, env: dict[str, str], cwd: str,
              pass_fds: tuple[int, ...] = (), stdin=subprocess.PIPE, stdout=subprocess.PIPE) -> subprocess.Popen:
        raise NotImplementedError

    def chown(self, path: Path, uid: int) -> None:
        raise NotImplementedError

    def close(self) -> dict:
        return {}


_CLONE_NEWNET = 0x40000000
_CLONE_NEWNS = 0x00020000
_MS_BIND, _MS_REC, _MS_PRIVATE, _MS_RDONLY, _MS_REMOUNT = 4096, 16384, 1 << 18, 1, 32
_PR_SET_NO_NEW_PRIVS = 38


class LinuxNamespaceTopology(Topology):
    """Inner namespaces inside the launcher's outer net+mount+PID namespace.

    Each role owns one network namespace held open by an owned holder process; links are owned
    veth pairs on fixed private /30s with no default route and no forwarding. A spawned role
    process enters its namespace, gets a private mount namespace with its own /etc/hosts
    (H -> its own gateway) and an empty resolver, then drops to its own UID with no capabilities
    and no_new_privs before exec.
    """

    is_linux_namespaces = True

    def __init__(self, work: Path, python: str):
        self.work = work
        self.python = python
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.holders: dict[str, subprocess.Popen] = {}
        self.namespace_fds: dict[str, int] = {}
        self.links: list[str] = []
        self.files = work / "netns"
        self.files.mkdir(parents=True, exist_ok=True)
        for role in ("cp", "ingress", "management", "slot-a", "slot-b"):
            self._hold(role)
        self._wire()

    def _hold(self, role: str) -> None:
        holder = subprocess.Popen(
            [self.python, "-I", str(Path(__file__).resolve()), "holder"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, text=True, preexec_fn=lambda: os.unshare(_CLONE_NEWNET),  # noqa: PLW1509
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, close_fds=True,
        )
        holder.stdin.write(json.dumps({}) + "\n")
        holder.stdin.flush()
        ready = json.loads(holder.stdout.readline())
        assert ready["event"] == "ready"
        self.holders[role] = holder
        self.namespace_fds[role] = os.open(f"/proc/{holder.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)

    def _ip(self, role: str | None, *arguments: str) -> None:
        fd = None if role is None else self.namespace_fds[role]
        subprocess.run(["ip", *arguments], check=True, capture_output=True, timeout=10,
                       preexec_fn=None if fd is None else (lambda: os.setns(fd, _CLONE_NEWNET)),  # noqa: PLW1509
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})

    def _sysctl(self, role: str, name: str, value: str) -> None:
        fd = self.namespace_fds[role]
        path = "/proc/sys/" + name.replace(".", "/")
        subprocess.run(["sh", "-c", 'printf %s "$1" > "$2"', "sysctl", value, path], check=True, timeout=10,
                       preexec_fn=lambda: os.setns(fd, _CLONE_NEWNET),  # noqa: PLW1509
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})

    def _wire(self) -> None:
        for role in self.namespace_fds:
            self._ip(role, "link", "set", "lo", "up")
        for index, role in enumerate(("cp", "management", "slot-a", "slot-b")):
            client, gateway = ADDRESS_PLAN[role]
            outer, inner = f"hi{index}g", f"hi{index}c"
            self._ip(None, "link", "add", outer, "type", "veth", "peer", "name", inner)
            self.links.append(outer)
            self._ip(None, "link", "set", outer, "netns", str(self.holders["ingress"].pid))
            self._ip(None, "link", "set", inner, "netns", str(self.holders[role].pid))
            self._ip("ingress", "addr", "add", f"{gateway}/30", "dev", outer)
            self._ip("ingress", "link", "set", outer, "up")
            self._ip(role, "addr", "add", f"{client}/30", "dev", inner)
            self._ip(role, "link", "set", inner, "up")
        for role in self.namespace_fds:
            self._sysctl(role, "net.ipv4.ip_forward", "0")
            self._sysctl(role, "net.ipv6.conf.all.disable_ipv6", "1")
        self._sysctl("ingress", "net.ipv4.ip_unprivileged_port_start", str(RUNNER_PORT))
        for role in ("cp", "management", "slot-a", "slot-b", "ingress"):
            hosts = self.files / f"{role}.hosts"
            gateway = ADDRESS_PLAN[role][1] if role in ADDRESS_PLAN and role != "cp" else "127.0.0.1"
            hosts.write_text(f"127.0.0.1 localhost\n{gateway} {HOST}\n")
            hosts.chmod(0o644)
        resolver = self.files / "resolv.conf"
        resolver.write_text("# no resolver inside the H0B fixture\n")
        resolver.chmod(0o644)

    def addresses(self) -> dict[str, tuple[str, str]]:
        return dict(ADDRESS_PLAN)

    def uid(self, role: str) -> int:
        return UIDS[role]

    def chown(self, path: Path, uid: int) -> None:
        os.chown(path, uid, uid)

    def spawn(self, role: str, argv: list[str], *, env: dict[str, str], cwd: str,
              pass_fds: tuple[int, ...] = (), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
              namespace: str | None = None, uid: int | None = None) -> subprocess.Popen:
        namespace = namespace or role
        fd = self.namespace_fds[namespace]
        uid = UIDS[role] if uid is None else uid
        hosts = str(self.files / f"{namespace}.hosts")
        resolver = str(self.files / "resolv.conf")
        libc = self.libc

        def mount(source: str | None, target: str, flags: int) -> None:
            if libc.mount(None if source is None else source.encode(), target.encode(), None, flags, None) != 0:
                raise OSError(ctypes.get_errno(), "mount failed")

        def enter() -> None:
            os.setns(fd, _CLONE_NEWNET)
            os.unshare(_CLONE_NEWNS)
            mount(None, "/", _MS_REC | _MS_PRIVATE)
            mount(hosts, "/etc/hosts", _MS_BIND)
            mount(resolver, "/etc/resolv.conf", _MS_BIND)
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "no_new_privs failed")
            os.umask(0o077)

        return subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=subprocess.DEVNULL, env=env, cwd=cwd,
                                pass_fds=pass_fds, close_fds=True, text=True, preexec_fn=enter)  # noqa: PLW1509

    def probe_route_table(self, role: str) -> str:
        fd = self.namespace_fds[role]
        completed = subprocess.run(["ip", "-4", "route", "show"], capture_output=True, text=True, timeout=10,
                                   preexec_fn=lambda: os.setns(fd, _CLONE_NEWNET),  # noqa: PLW1509
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return completed.stdout

    def close(self) -> dict:
        report = {"holders": 0, "links": 0}
        for holder in self.holders.values():
            with contextlib.suppress(OSError):
                holder.stdin.close()
            with contextlib.suppress(subprocess.TimeoutExpired):
                holder.wait(5)
            if holder.poll() is None:
                holder.kill()
                holder.wait(5)
            report["holders"] += 1
        for fd in self.namespace_fds.values():
            with contextlib.suppress(OSError):
                os.close(fd)
        report["links"] = len(self.links)  # veths vanish with their namespaces
        self.holders.clear()
        self.namespace_fds.clear()
        return report


# ---------------------------------------------------------------------------------------------
# The composed environment.

@dataclass
class Installation:
    """Paths the launcher staged (private copies readable by the role UIDs)."""

    root: Path
    python: str
    nginx: str
    node: str
    worker_dist: Path
    openapi_fixture: Path


def load_installation() -> Installation:
    path = os.environ.get(ENVIRONMENT_FILE_ENV, "")
    if not path:
        raise RuntimeError("the fixed host-ingress launcher environment is absent")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Installation(root=Path(data["root"]), python=data["python"], nginx=data["nginx"], node=data["node"],
                        worker_dist=Path(data["worker_dist"]), openapi_fixture=Path(data["openapi_fixture"]))


def runtime_unavailable_reason() -> str | None:
    """Why the dynamic profile cannot run here, or None inside the fixed launcher's namespaces."""
    if not sys.platform.startswith("linux"):
        return "requires the fixed host-ingress launcher on Linux"
    if sys.version_info < (3, 12) or not hasattr(os, "setns"):
        return "requires the launcher's pinned Python with namespace support"
    if os.geteuid() != 0:
        return "requires the launcher's isolated namespace driver"
    if not os.environ.get(ENVIRONMENT_FILE_ENV):
        return "requires the fixed host-ingress launcher environment"
    return None


def make_topology(installation: Installation) -> Topology:
    return LinuxNamespaceTopology(installation.root / "netns", installation.python)


def require_linux_topology(topology: Topology, what: str) -> None:
    """In the required profile a non-namespace topology is a failure; only a scratch developer
    topology (never reachable with HEEL_REQUIRE_HOST_INGRESS=1) may skip what it cannot model."""
    import pytest

    if topology.is_linux_namespaces:
        return
    if os.environ.get(REQUIRED_ENV) == "1":
        pytest.fail(f"{what} requires the launcher's Linux namespace topology")
    pytest.skip(f"developer loopback topology cannot model {what}")


class IngressEnvironment:
    """One composed fixture: CP, nginx, the Worker client, runner slots and the registry."""

    def __init__(self, installation: Installation, topology: Topology):
        self.installation = installation
        self.topology = topology
        self.root = installation.root / "state"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o755)
        self.children: list[ChildProcess] = []
        self.edge_secret = secrets.token_urlsafe(32)
        self.boot_epoch = "boot-" + secrets.token_hex(8)
        self.canaries: list[str] = [self.edge_secret]
        addresses = topology.addresses()
        ports = topology.ports()
        self.backend = (addresses["cp"][0], ports["backend"])
        self.management = (addresses["management"][1], ports["management"])
        self.management_peer = addresses["management"][0]
        self.ops = ("127.0.0.1", ports["ops"])
        self.slots = {slot: (addresses[slot][1], topology.slot_port(slot), addresses[slot][0])
                      for slot in SLOT_IDS if slot in addresses}
        self._dirs()
        self.ca = IngressCA(self.tls / "ca")
        self.cert_path, self.key_path = self.ingress / "tls" / "server.pem", self.ingress / "tls" / "server-key.pem"
        self.leaves = {
            "primary": self.ca.issue("primary", (HOST,)),
            "second": self.ca.issue("second", (HOST,)),
            "alias": self.ca.issue("alias", (HOST, ALIAS_HOST)),
            "wrong-name": self.ca.issue("wrong-name", ("other.example",)),
            "expired": self.ca.issue("expired", (HOST,), expired=True),
        }
        self.public_ca = self.ingress / "tls" / "ca.pem"
        self.public_ca.write_bytes(self.ca.ca_path.read_bytes())
        self.public_ca.chmod(0o644)
        self._install_leaf("primary")
        self.registry = RegistryController(
            self.ingress / "registry" / "registry.json", owner_uid=os.getuid(), boot_epoch=self.boot_epoch,
            backend=self.backend, management=self.management, management_peer=self.management_peer,
            slots=[SlotState(slot_id=slot, address=address, port=port, peer=peer, namespace_id=f"ns-{slot}")
                   for slot, (address, port, peer) in self.slots.items()],
        )
        self.registry.publish()
        self.cp: ChildProcess | None = None
        self.cp_info: dict = {}
        self.nginx: subprocess.Popen | None = None
        self.worker: ChildProcess | None = None
        self.runners: dict[str, ChildProcess] = {}
        self.rendered_digest: str | None = None

    # Filesystem ---------------------------------------------------------------------------
    def _dirs(self) -> None:
        self.ingress = self.root / "ingress"
        self.tls = self.root / "tls-private"
        for path, mode in ((self.ingress, 0o755), (self.ingress / "tls", 0o755), (self.ingress / "registry", 0o755),
                           (self.ingress / "nginx", 0o700), (self.ingress / "nginx" / "tmp", 0o700),
                           (self.tls, 0o700), (self.root / "cp", 0o700), (self.root / "management", 0o700),
                           (self.root / "slot-a", 0o700), (self.root / "slot-b", 0o700),
                           (self.root / "probe", 0o755)):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, mode)
        if self.topology.is_linux_namespaces:
            for role in ("cp", "management", "slot-a", "slot-b"):
                self.topology.chown(self.root / role, self.topology.uid(role))
            for path in (self.ingress / "nginx", self.ingress / "nginx" / "tmp"):
                self.topology.chown(path, self.topology.uid("ingress"))

    def _install_leaf(self, name: str) -> str:
        cert, key = self.leaves[name]
        for source, target, mode in ((cert, self.cert_path, 0o644), (key, self.key_path, 0o600)):
            temporary = target.with_name(target.name + ".new")
            temporary.write_bytes(source.read_bytes())
            os.chmod(temporary, mode)
            if self.topology.is_linux_namespaces:
                self.topology.chown(temporary, self.topology.uid("ingress"))
            os.replace(temporary, target)
        return IngressCA.fingerprint(cert)

    def _env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        # Allowlisted child environment: no ambient credentials, proxies, CA overrides or tokens.
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
               "HOME": str(self.root / "probe"), "TMPDIR": str(self.root / "probe")}
        env.update(extra or {})
        return env

    # Children -----------------------------------------------------------------------------
    def _python_child(self, role: str, kind: str, config: dict, *, namespace: str | None = None,
                      home: Path | None = None) -> ChildProcess:
        argv = [self.installation.python, "-I", str(Path(__file__).resolve()), kind]
        kwargs = {}
        if namespace is not None:
            kwargs["namespace"] = namespace
        env = self._env({"HOME": str(home), "TMPDIR": str(home)} if home is not None else None)
        process = self.topology.spawn(role, argv, env=env, cwd=str(home or self.root / "probe"), **kwargs)
        child = ChildProcess(role=role, process=process, identity=process_identity(process.pid),
                             rpc_in=process.stdin, rpc_out=process.stdout)
        child.send(config)
        self.children.append(child)
        return child

    def start_cp(self, database: str = "memory", *, port: int | None = None, reuse: bool = False) -> dict:
        """Start the real CP. ``sqlite`` with ``reuse`` reopens the same task-local database."""
        if self.cp is not None:
            self.stop_cp()
        if not reuse or not hasattr(self, "cp_secrets"):
            self.cp_secrets = {"device_pepper": secrets.token_hex(32), "runner_pepper": secrets.token_hex(32),
                               "grant_seed": secrets.token_hex(32)}
            self.cp_path = ":memory:" if database == "memory" else str(
                self.root / "cp" / f"control-plane-{secrets.token_hex(4)}.sqlite3")
        config = {"address": self.backend[0], "port": self.backend[1] if port is None else port,
                  "database": self.cp_path, "edge_secret": self.edge_secret, **self.cp_secrets}
        self.cp = self._python_child("cp", "cp", config, home=self.root / "cp")
        self.cp_info = self.cp.event("ready")
        self.cp_database = database
        return self.cp_info

    def start_scripted(self, rules: list[dict], *, upstream_port: int | None = None) -> ChildProcess:
        child = self._python_child("cp", "scripted", {
            "address": self.backend[0], "port": self.backend[1], "rules": rules,
            "upstream": [self.backend[0], upstream_port or 0]}, home=self.root / "cp")
        child.event("ready")
        self.scripted = child
        return child

    def stop_scripted(self) -> list[str]:
        child = getattr(self, "scripted", None)
        if child is None:
            return []
        observed = child.call("seen")
        seen = observed.get("seen", [])
        self.scripted_events = observed.get("events", [])
        with contextlib.suppress(Exception):
            child.call("stop", timeout=10)
        self._reap(child)
        self.scripted = None
        return seen

    def stop_cp(self) -> None:
        if self.cp is None:
            return
        with contextlib.suppress(Exception):
            self.cp.call("stop", timeout=10)
        self._reap(self.cp)
        self.cp = None

    def cp_call(self, command: str, **arguments) -> dict:
        assert self.cp is not None
        reply = self.cp.call(command, **arguments)
        if not reply.get("ok"):
            raise AssertionError(f"control-plane fixture query failed: {reply.get('error')}")
        return reply

    def snapshot(self) -> dict:
        return self.cp_call("snapshot")

    def render(self) -> str:
        values = {
            "STATE_DIR": str(self.ingress / "nginx"), "POLICY_DIR": str(self.installation.root / "src" / "deploy" / "host" / "ingress"),
            "REGISTRY_PATH": str(self.registry.path), "CERT_PATH": str(self.cert_path), "KEY_PATH": str(self.key_path),
            "REGISTRY_OWNER_UID": str(self.registry.owner_uid), "BOOT_EPOCH": self.boot_epoch, "PUBLIC_HOST": HOST,
            "BACKEND_ADDRESS": self.backend[0], "BACKEND_PORT": str(self.backend[1]),
            "MANAGEMENT_ADDRESS": self.management[0], "MANAGEMENT_PORT": str(self.management[1]),
            "MANAGEMENT_PEER": self.management_peer, "EDGE_SECRET": self.edge_secret, "OPS_PORT": str(self.ops[1]),
        }
        slots = [{"SLOT_ID": slot, "SLOT_ADDRESS": address, "SLOT_PORT": str(port), "SLOT_PEER": peer}
                 for slot, (address, port, peer) in self.slots.items()]
        template = (self.installation.root / "src" / "deploy" / "host" / "ingress" / "nginx.conf").read_text(encoding="utf-8")
        rendered = render_nginx_config(template, values, slots)
        self.config_path = self.ingress / "nginx" / "nginx.conf"
        descriptor = os.open(self.config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        if self.topology.is_linux_namespaces:
            self.topology.chown(self.config_path, self.topology.uid("ingress"))
        self.rendered_digest = config_digest(rendered, self.edge_secret)
        return self.rendered_digest

    def nginx_test(self) -> int:
        process = self.topology.spawn("ingress", [self.installation.nginx, "-t", "-q", "-p", str(self.ingress / "nginx"),
                                                  "-c", str(self.config_path), "-e", "/dev/null"],
                                      env=self._env(), cwd=str(self.ingress / "nginx"),
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # Diagnostics may contain configuration text, so they are discarded (stderr is DEVNULL).
        return process.wait(30)

    def start_nginx(self) -> None:
        self.render()
        self.nginx = self.topology.spawn("ingress", [self.installation.nginx, "-p", str(self.ingress / "nginx"),
                                                     "-c", str(self.config_path), "-e", "/dev/null"],
                                         env=self._env(), cwd=str(self.ingress / "nginx"),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.nginx_identity = process_identity(self.nginx.pid)
        self.wait_for_listener()
        # Worker sentinel: only a deliberate reload below may replace these workers.
        self.expected_workers = self.worker_pids()

    def wait_for_listener(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.probe("ingress", mode="tcp", address=self.ops[0], port=self.ops[1],
                                chunks=[[0, base64.b64encode(b"GET /__heel_counters HTTP/1.1\r\nHost: ops\r\n\r\n").decode()]],
                                read_timeout=2)
            if result["received"].startswith(b"HTTP/1.1 200"):
                return
            time.sleep(0.2)
        raise AssertionError("ingress did not start")

    def reload_nginx(self, leaf: str) -> str:
        fingerprint = self._install_leaf(leaf)
        assert self.nginx is not None
        os.kill(self.nginx.pid, signal.SIGHUP)
        deadline = time.monotonic() + 15
        address, port, _peer = self.slots["slot-a"]
        previous = set(self.expected_workers)
        while time.monotonic() < deadline:
            result = self.probe("slot-a", mode="tls", address=address, port=port, server_name=HOST, ca=None)
            workers = self.worker_pids()
            if (result.get("tls") or {}).get("certificate_sha256") == fingerprint and workers and not previous & set(workers):
                self.expected_workers = workers
                return fingerprint
            time.sleep(0.2)
        raise AssertionError("ingress did not reload the certificate")

    def counters(self) -> dict[str, int]:
        result = self.probe("ingress", mode="tcp", address=self.ops[0], port=self.ops[1],
                            chunks=[[0, base64.b64encode(b"GET /__heel_counters HTTP/1.1\r\nHost: ops\r\n\r\n").decode()]],
                            read_timeout=3)
        _head, _, body = result["received"].partition(b"\r\n\r\n")
        return json.loads(body or b"{}")

    def worker_pids(self) -> list[int]:
        """The ingress master's worker processes (children of the owned master), read from /proc
        inside the launcher's PID namespace. A changed list means a worker died and was replaced;
        nginx never releases a dead worker's limit_conn slots, so a change is always a failure."""
        assert self.nginx is not None
        master = self.nginx.pid
        if Path("/proc/self/stat").exists():
            children = []
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                except (OSError, IndexError):
                    continue
                if int(fields[1]) == master:
                    children.append(int(entry.name))
            return sorted(children)
        listing = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, check=True,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout
        return sorted(int(pid) for pid, ppid in (line.split() for line in listing.splitlines() if line.strip())
                      if int(ppid) == master)

    def write_canaries(self) -> None:
        """Hand the run's synthetic secrets to the launcher's artifact scan (private, 0600)."""
        path = os.environ.get("HEEL_HOST_INGRESS_CANARIES")
        if not path:
            return
        known = set(self.canaries) | set(getattr(self, "cp_secrets", {}).values())
        with contextlib.suppress(OSError, ValueError):
            known |= set(json.loads(Path(path).read_text(encoding="utf-8")))
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(sorted(canary for canary in known if isinstance(canary, str) and canary), handle)

    def start_policy_selftest(self) -> None:
        """The reviewed policy module inside the actual nginx/njs/qjs runtime (test-only config)."""
        directory = self.ingress / "selftest"
        directory.mkdir(mode=0o755, exist_ok=True)
        (directory / "body").mkdir(mode=0o700, exist_ok=True)
        module = directory / "selftest.js"
        module.write_text(POLICY_SELFTEST_JS, encoding="utf-8")
        os.chmod(module, 0o644)
        self.selftest_port = self.ops[1] + 1
        conf = (POLICY_SELFTEST_CONF.replace("@STATE@", str(directory))
                .replace("@POLICY_DIR@", str(self.installation.root / "src" / "deploy" / "host" / "ingress"))
                .replace("@SELFTEST_DIR@", str(directory)).replace("@PORT@", str(self.selftest_port)))
        conf_path = directory / "selftest.conf"
        conf_path.write_text(conf, encoding="utf-8")
        os.chmod(conf_path, 0o644)
        if self.topology.is_linux_namespaces:
            for path in (directory, directory / "body"):
                self.topology.chown(path, self.topology.uid("ingress"))
        self.selftest_nginx = self.topology.spawn(
            "ingress", [self.installation.nginx, "-p", str(directory), "-c", str(conf_path), "-e", "/dev/null"],
            env=self._env(), cwd=str(directory), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.selftest_identity = process_identity(self.selftest_nginx.pid)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, _ = self.selftest("/runtime", b"")
            if status == 200:
                return
            time.sleep(0.2)
        raise AssertionError("policy selftest runtime did not start")

    def selftest(self, path: str, body: bytes) -> tuple[int | None, bytes]:
        head = (f"POST {path} HTTP/1.1\r\nHost: selftest\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii")
        result = self.probe("ingress", mode="tcp", address="127.0.0.1", port=self.selftest_port,
                            chunks=[[0, base64.b64encode(head + body).decode()]], read_timeout=60,
                            max_bytes=16 * 1024 * 1024)
        raw = result["received"]
        head_bytes, _, payload = raw.partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.1 ([0-9]{3}) ", head_bytes)
        return (int(match.group(1)) if match else None), payload

    def stop_policy_selftest(self) -> None:
        process = getattr(self, "selftest_nginx", None)
        if process is not None and process.poll() is None and process_identity(process.pid) == self.selftest_identity:
            process.send_signal(signal.SIGQUIT)
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
        self.selftest_nginx = None

    def start_worker(self) -> None:
        directory = self.root / "management"
        adapter = directory / "fake-vpc-adapter.mjs"
        driver = directory / "worker-driver.mjs"
        adapter.write_text(adapter_block(), encoding="utf-8")
        driver.write_text(WORKER_DRIVER_JS, encoding="utf-8")
        for path in (adapter, driver):
            os.chmod(path, 0o644)
        process = self.topology.spawn(
            "management", [self.installation.node, "--disable-warning=ExperimentalWarning", str(driver)],
            env=self._env({"HOME": str(directory), "TMPDIR": str(directory)}), cwd=str(directory),
        )
        child = ChildProcess(role="management", process=process, identity=process_identity(process.pid),
                             rpc_in=process.stdin, rpc_out=process.stdout)
        child.send({
            "host": HOST, "address": self.management[0], "port": self.management[1], "ca": str(self.public_ca),
            "server_index": str(self.installation.worker_dist / "server" / "index.js"), "public_origin": ORIGIN,
            "edge_secret": self.edge_secret,
        })
        self.children.append(child)
        child.event("ready", timeout=60)
        self.worker = child

    def browser(self, method: str, path: str, body: object | None = None, *, cookie: str | None = None,
                origin: str | None = ORIGIN, fetch_site: str | None = "same-origin", raw: bytes | None = None,
                headers: dict[str, str] | None = None) -> dict:
        """A browser request to the compiled Worker (management client), exactly as Cloudflare would deliver it."""
        assert self.worker is not None
        request_headers = {"CF-Connecting-IP": "198.51.100.7"}
        if origin is not None:
            request_headers["Origin"] = origin
        if fetch_site is not None:
            request_headers["Sec-Fetch-Site"] = fetch_site
        if cookie is not None:
            request_headers["Cookie"] = cookie
        payload = raw if raw is not None else (None if body is None else json.dumps(body, separators=(",", ":")).encode())
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
            request_headers["Content-Length"] = str(len(payload))
        request_headers.update(headers or {})
        reply = self.worker.call("fetch", method=method, path="/api/control-plane" + path, headers=request_headers,
                                 body_b64=None if payload is None else base64.b64encode(payload).decode(), timeout=40)
        body_bytes = base64.b64decode(reply.get("body_b64") or "")
        reply["body"] = json.loads(body_bytes) if body_bytes[:1] in (b"{", b"[") else None
        return reply

    def start_runner(self, slot: str) -> ChildProcess:
        home = self.root / slot / f"home-{secrets.token_hex(3)}"
        home.mkdir(mode=0o700)
        if self.topology.is_linux_namespaces:
            self.topology.chown(home, self.topology.uid(slot))
        child = self._python_child(slot, "runner", {
            "home": str(home), "ca": str(self.public_ca), "openapi": str(self.installation.openapi_fixture),
        }, home=self.root / slot)
        child.event("ready")
        self.runners[slot] = child
        return child

    def stop_runner(self, slot: str) -> None:
        child = self.runners.pop(slot, None)
        if child is not None:
            with contextlib.suppress(Exception):
                child.call("stop", timeout=10)
            self._reap(child)

    def wire(self, namespace: str, raw: bytes, *, server_name: str | None = HOST, ca: str | None = "public",
             address: str | None = None, port: int | None = None, chunks: list | None = None, **config) -> dict:
        """Send exact bytes over real TLS from a namespace to its own gateway listener (or management)."""
        if address is None:
            address, port = (self.management if namespace == "management" else self.slots[namespace][:2])
        return self.probe(namespace, mode="tls", address=address, port=port, server_name=server_name,
                          ca=str(self.public_ca) if ca == "public" else ca,
                          chunks=chunks if chunks is not None else [[0, base64.b64encode(raw).decode()]], **config)

    def probe(self, namespace: str, **config) -> dict:
        process = self.topology.spawn(namespace if namespace != "ingress" else "ingress",
                                      [self.installation.python, "-I", str(Path(__file__).resolve()), "probe"],
                                      env=self._env(), cwd=str(self.root / "probe"))
        try:
            schedule = sum(delay for delay, _chunk in config.get("chunks", [])) / 1000
            out, _ = process.communicate(json.dumps(config) + "\n", timeout=config.get("read_timeout", 10) + schedule + 30)
        except subprocess.TimeoutExpired:
            process.kill()
            out, _ = process.communicate()
        result = json.loads(out.strip().splitlines()[-1]) if out.strip() else {"error": "no_result"}
        result["received"] = base64.b64decode(result.get("received_b64") or "")
        return result

    # Cleanup ------------------------------------------------------------------------------
    def _reap(self, child: ChildProcess, timeout: float = 5.0) -> None:
        process = child.process
        for closer in (child.rpc_in,):
            with contextlib.suppress(Exception):
                closer.close()
        if process.poll() is None and process_identity(process.pid) == child.identity:
            process.terminate()
            try:
                process.wait(timeout)
            except subprocess.TimeoutExpired:
                if process_identity(process.pid) == child.identity:
                    process.kill()
                process.wait(timeout)
        with contextlib.suppress(Exception):
            child.rpc_out.close()

    def close(self) -> dict:
        self.write_canaries()
        report = {"children": 0, "nginx": False}
        self.stop_policy_selftest()
        for child in list(self.children):
            self._reap(child)
            report["children"] += 1
        self.children.clear()
        if self.nginx is not None:
            if self.nginx.poll() is None and process_identity(self.nginx.pid) == self.nginx_identity:
                self.nginx.send_signal(signal.SIGQUIT)
                try:
                    self.nginx.wait(10)
                except subprocess.TimeoutExpired:
                    self.nginx.kill()
                    self.nginx.wait(5)
            report["nginx"] = True
        report["topology"] = self.topology.close()
        return report


# ---------------------------------------------------------------------------------------------
# Wire helpers: exact request bytes in, parsed status/headers/body out, from inside a namespace.

def http_request(method: str, target: str, headers: list[tuple[str, str]], body: bytes = b"",
                 version: str = "HTTP/1.1") -> bytes:
    head = f"{method} {target} {version}\r\n" + "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n"
    return head.encode("latin-1") + body


def parse_http_exchange(raw: bytes) -> tuple[list[int], int | None, list[tuple[str, str]], bytes]:
    """Split ``raw`` into interim 1xx statuses and the one final response (exact bytes, no repair)."""
    interim: list[int] = []
    while True:
        match = re.match(rb"HTTP/1\.[01] (1[0-9]{2})[^\r\n]*\r\n(?:[^\r\n]*\r\n)*?\r\n", raw)
        if match is None:
            break
        interim.append(int(match.group(1)))
        raw = raw[match.end():]
    status, headers, body = parse_http(raw)
    return interim, status, headers, body


def parse_http(raw: bytes) -> tuple[int | None, list[tuple[str, str]], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return None, [], b""
    lines = head.decode("latin-1").split("\r\n")
    match = re.match(r"HTTP/1\.[01] ([0-9]{3})", lines[0])
    headers = [(line.split(":", 1)[0].strip(), line.split(":", 1)[1].strip()) for line in lines[1:] if ":" in line]
    return (int(match.group(1)) if match else None), headers, body


@dataclass
class Observation:
    """What one action did: response, CP contact, changed runner tables and policy reasons."""

    status: int | None
    headers: list
    body: bytes
    cp_contacted: bool
    changed_tables: list
    reasons: list
    result: dict
    interim: list = field(default_factory=list)

    def header(self, name: str) -> list[str]:
        return [value for key, value in self.headers if key.lower() == name.lower()]


def observe(env: "IngressEnvironment", action: Callable[[], dict]) -> Observation:
    before = env.snapshot()
    counters_before = env.counters()
    result = action()
    after = env.snapshot()
    counters_after = env.counters()
    reasons = sorted(key for key, value in counters_after.items() if value != counters_before.get(key))
    interim: list[int] = []
    if "received" in result:
        interim, status, headers, body = parse_http_exchange(result["received"])
    else:
        status, headers, body = result.get("status"), [], b""
    changed = sorted(table for table, digest in after["state"].items() if before["state"].get(table) != digest)
    return Observation(status=status, headers=headers, body=body, cp_contacted=after["requests"] > before["requests"],
                       changed_tables=changed, reasons=reasons, result=result, interim=interim)


# Fixed, value-free case evidence (launcher-collected; never request/response material).
_CASE_FIELDS = {"case", "gate", "status", "reasons", "cp_contacted", "changed_tables", "seam"}


def record_case(case: str, gate: str, observation: "Observation | None" = None, *, seam: str | None = None) -> None:
    path = os.environ.get("HEEL_HOST_INGRESS_CASES")
    if not path:
        return
    entry = {"case": case, "gate": gate, "seam": seam}
    if observation is not None:
        entry.update(status=observation.status, reasons=[reason for reason in observation.reasons
                                                         if re.fullmatch(r"[a-z_]+:[a-z_:0-9-]+", reason)],
                     cp_contacted=observation.cp_contacted, changed_tables=observation.changed_tables)
    assert set(entry) <= _CASE_FIELDS and re.fullmatch(r"[a-z0-9_.-]{1,160}", case)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------------------------
# NFC tables for policy.js. njs builds its QuickJS context without String.prototype.normalize,
# and QuickJS carries Unicode 17 while the control plane's comparator (canonical_bytes on the
# pinned Python 3.13.5) uses unicodedata 15.1.0. The policy therefore embeds tables generated
# here from that exact unicodedata; tests regenerate them and require byte equality.

NFC_UNICODE_VERSION = "15.1.0"
NFC_BEGIN = "// BEGIN HEEL_NFC_TABLES"
NFC_END = "// END HEEL_NFC_TABLES"


def _base36(number: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    text = ""
    while True:
        number, remainder = divmod(number, 36)
        text = digits[remainder] + text
        if number == 0:
            return text


def nfc_table_block() -> str:
    """The exact generated block (markers included) for the pinned unicodedata version."""
    import unicodedata

    if unicodedata.unidata_version != NFC_UNICODE_VERSION:
        raise RuntimeError("NFC tables are generated only from unicodedata " + NFC_UNICODE_VERSION)
    decompositions, excluded = [], []
    for code in range(0x110000):
        if 0xD800 <= code <= 0xDFFF or 0xAC00 <= code <= 0xD7A3:
            continue  # surrogates never occur; Hangul syllables are algorithmic
        mapping = unicodedata.decomposition(chr(code))
        if mapping and not mapping.startswith("<"):
            parts = [int(item, 16) for item in mapping.split()]
            decompositions.append(_base36(code) + "=" + ".".join(_base36(item) for item in parts))
            if len(parts) == 2 and unicodedata.normalize("NFC", chr(parts[0]) + chr(parts[1])) != chr(code):
                excluded.append(_base36(code))
    classes, current = [], None
    for code in range(0x110000):
        value = 0 if 0xD800 <= code <= 0xDFFF else unicodedata.combining(chr(code))
        if current is not None and current[2] == value and current[1] == code - 1:
            current[1] = code
            continue
        if current is not None and current[2]:
            classes.append(current)
        current = [code, code, value]
    if current is not None and current[2]:
        classes.append(current)
    ranges = [f"{_base36(a)}{'-' + _base36(b) if b != a else ''}:{_base36(c)}" for a, b, c in classes]

    def literal(name: str, items: list[str]) -> str:
        text = ";".join(items)
        lines = [text[index:index + 96] for index in range(0, len(text), 96)]
        return f"const {name} =\n" + "\n".join(f"    '{line}'" + (" +" if i < len(lines) - 1 else ";")
                                                for i, line in enumerate(lines))

    return "\n".join([
        NFC_BEGIN + " (generated by tests/support/host_ingress_harness.py nfc_table_block from Python",
        f"// unicodedata {NFC_UNICODE_VERSION}; base36 code points. Do not edit by hand.)",
        f"const NFC_UNICODE_VERSION = '{NFC_UNICODE_VERSION}';",
        literal("NFC_DECOMPOSITIONS", decompositions),
        literal("NFC_COMBINING_CLASSES", ranges),
        literal("NFC_EXCLUDED_COMPOSITES", excluded),
        NFC_END,
    ]) + "\n"


def embedded_nfc_block(policy_text: str) -> str:
    begin = policy_text.index(NFC_BEGIN)
    end = policy_text.index(NFC_END) + len(NFC_END) + 1
    return policy_text[begin:end]


# A test-only njs module run by the real nginx/njs/qjs runtime: it calls the reviewed policy's own
# exported helpers on supplied bytes. It is never part of the ingress configuration.
POLICY_SELFTEST_JS = r"""
import policy from 'policy.js';

const internal = policy._internal;

async function body(r) {
    const buffer = await r.readRequestArrayBuffer();
    return new Uint8Array(buffer);
}

// NUL-separated UTF-8 strings in; NUL-separated NFC strings out.
async function nfc(r) {
    try {
        const text = internal.decodeUtf8(await body(r));
        const out = text.split('\0').map((item) => internal.nfc(item)).join('\0');
        r.headersOut['Content-Type'] = 'text/plain; charset=utf-8';
        r.return(200, out);
    } catch (e) {
        r.return(500, 'error:' + (e && e.reason ? e.reason : 'exception'));
    }
}

// One request body in; "accepted" or the fixed refusal reason of the request scanner out.
async function canonical(r) {
    let verdict;
    try {
        const bytes = await body(r);
        const text = internal.decodeUtf8(bytes);
        const doc = internal.parseJson(text);
        verdict = internal.canonicalText(doc) === text ? 'accepted' : 'refused:canonical';
    } catch (e) {
        verdict = e && e.reason ? 'refused:' + e.reason : 'refused:exception';
    }
    r.return(200, verdict);
}

function runtime(r) {
    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify({
        native_normalize: typeof ''.normalize,
        eval: typeof globalThis.eval,
        function_constructor: typeof globalThis.Function,
        nfc_unicode_version: internal.NFC_UNICODE_VERSION || null,
    }));
}

export default { nfc, canonical, runtime };
"""

POLICY_SELFTEST_CONF = """
worker_processes 1;
daemon off;
master_process on;
pid @STATE@/selftest.pid;
error_log /dev/null crit;
events { worker_connections 32; }
http {
    access_log off;
    js_engine qjs;
    js_context_reuse 0;
    js_path @POLICY_DIR@;
    js_path @SELFTEST_DIR@;
    js_import selftest from selftest.js;
    client_max_body_size 16m;
    client_body_buffer_size 16m;
    client_body_in_single_buffer on;
    client_body_temp_path @STATE@/body;
    server {
        listen 127.0.0.1:@PORT@;
        location = /nfc { js_content selftest.nfc; }
        location = /canonical { js_content selftest.canonical; }
        location = /runtime { js_content selftest.runtime; }
    }
}
"""


# ---------------------------------------------------------------------------------------------
# Real flows over the composed fixture. Browser steps go through the compiled Worker and the
# management listener; runner steps go through the slot's runner listener; every registry
# transition uses only CP state the controller has just confirmed.

def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class PairedSlot:
    slot: str
    runner: ChildProcess
    workspace_id: str
    cookie: str
    runner_id: str
    runner_key_id: str
    pairing_id: str
    pairing_phrase: str
    fingerprint: str


class IngressFlows:
    STAGING = "staging.example.com"

    def __init__(self, env: IngressEnvironment):
        self.env = env

    def signup(self, email: str) -> tuple[str, str]:
        reply = self.env.browser("POST", "/v1/signup", {"email": email, "password": "correct-horse-battery"},
                                 origin=None, fetch_site=None)
        assert reply.get("status") == 201, (reply.get("status"), reply.get("error"))
        cookie = reply["set_cookie"][0].split(";", 1)[0]
        assert cookie.startswith("__Host-heel_session=")
        self.env.canaries.append(cookie.split("=", 1)[1])
        return reply["body"]["workspace_id"], cookie

    def invite(self, workspace_id: str, cookie: str) -> str:
        reply = self.env.browser("POST", f"/v1/workspaces/{workspace_id}/runner-pairings",
                                 {"schema_version": "heel.runner-pairing-invite.v1"}, cookie=cookie)
        assert reply.get("status") == 201, reply.get("status")
        token = reply["body"]["invitation_token"]
        self.env.canaries.append(token)
        return token

    def pair(self, slot: str, workspace_id: str, cookie: str, *, register: bool = True,
             approve: bool = True) -> PairedSlot:
        env = self.env
        token = self.invite(workspace_id, cookie)
        (invited,) = env.cp_call("pairing_for_token", token=token)["rows"]
        runner = env.start_runner(slot)
        assert runner.call("pair", token=token, display_name=f"Runner {slot}")["ok"]
        key = runner.event("key")
        if register:
            env.registry.invite(slot, workspace_id=workspace_id, token=token, pairing_id=invited["pairing_id"],
                                public_key_b64=key["public_key_b64"], expires_at_ms=int(invited["expires_at"] * 1000))
        runner.call("continue", gate="key", value=True)
        pending = runner.event("pairing_pending", timeout=60)
        (row,) = env.cp_call("pairing", pairing_id=pending["pairing_id"])["rows"]
        assert row["pairing_id"] == invited["pairing_id"] and row["status"] == "pending"
        assert row["fingerprint"] == key["fingerprint"] == pending["fingerprint"]
        assert row["workspace_id"] == workspace_id and row["exchange_digest"]
        env.registry.pending(slot, {"pairing_id": row["pairing_id"], "runner_id": row["runner_id"], "key_id": row["key_id"],
                                    "fingerprint": row["fingerprint"], "exchange_digest": row["exchange_digest"],
                                    "expires_at_ms": int(row["expires_at"] * 1000)})
        runner.call("continue", gate="pending", value=True)
        base = f"/v1/workspaces/{workspace_id}/runner-pairings/{row['pairing_id']}"
        view = env.browser("GET", base, cookie=cookie)
        assert view["status"] == 200 and view["body"]["pairing_phrase"] == pending["pairing_phrase"]
        assert view["body"]["fingerprint"] == pending["fingerprint"]
        if approve:
            approved = env.browser("POST", base + "/approve", {
                "schema_version": "heel.runner-pairing-approve.v1", "pairing_phrase": view["body"]["pairing_phrase"],
                "fingerprint": view["body"]["fingerprint"],
            }, cookie=cookie)
            assert approved["status"] == 200, approved["status"]
        done = runner.event("pair_done", timeout=90)
        paired = PairedSlot(slot=slot, runner=runner, workspace_id=workspace_id, cookie=cookie,
                            runner_id=row["runner_id"], runner_key_id=row["key_id"], pairing_id=row["pairing_id"],
                            pairing_phrase=pending["pairing_phrase"], fingerprint=row["fingerprint"])
        if not done.get("ok"):
            raise AssertionError(f"pairing failed: {done.get('error')}")
        self.confirm_active(paired)
        return paired

    def confirm_active(self, paired: PairedSlot) -> dict:
        (key,) = self.env.cp_call("identity", workspace_id=paired.workspace_id, runner_id=paired.runner_id)["rows"]
        identity = {"runner_id": paired.runner_id, "key_id": key["key_id"],
                    "public_key_digest": hashlib.sha256(base64.b64decode(key["public_key"])).hexdigest()}
        self.env.registry.activate(paired.slot, identity)
        return identity

    def owner(self, method: str, path: str, body: object | None, cookie: str, **kwargs) -> dict:
        raw = None if body is None else canonical_json(body)
        return self.env.browser(method, path, raw=raw, cookie=cookie, **kwargs)

    def authorize_binding(self, paired: PairedSlot, *, name: str = "Staging") -> tuple[str, dict]:
        env = self.env
        workspace = paired.workspace_id
        project = self.owner("POST", f"/v1/workspaces/{workspace}/projects", {"name": name}, paired.cookie)
        assert project["status"] == 201, project["status"]
        base = f"/v1/workspaces/{workspace}/projects/{project['body']['project_ref']}"
        challenge = self.owner("POST", f"{base}/environments", {
            "schema_version": "heel.verified-environment-start.v1", "origin": f"https://{self.STAGING}",
            "environment_class": "staging", "proof_method": "dns-txt",
            "attestation_text": "ownership verified; environment classification supplied by you",
            "attestation_version": "v1", "attestation_acknowledgement": "accepted",
        }, paired.cookie)
        assert challenge["status"] == 201, challenge["status"]
        env.cp_call("zone", name=f"_heel.{self.STAGING}", values=["heel-verify=" + challenge["body"]["token"]])
        checked = self.owner("POST", f"{base}/environments/{challenge['body']['environment_id']}/check",
                             {"schema_version": "heel.verified-environment-check.v1"}, paired.cookie)
        assert checked["status"] == 200 and checked["body"]["verified"] is True
        listed = self.owner("GET", f"{base}/environments", None, paired.cookie)
        (environment,) = [item for item in listed["body"]["environments"]
                          if item["environment_id"] == challenge["body"]["environment_id"]]
        env.registry.add_project(paired.slot, {"project_id": project["body"]["project_ref"],
                                               "environment_id": environment["environment_id"],
                                               "verification_record_digest": environment["verification_record_digest"]})
        created = self.owner("POST", f"{base}/runner-context-bindings", {
            "schema_version": "heel.runner-context-binding-create.v1",
            "environment_id": environment["environment_id"],
            "verification_record_digest": environment["verification_record_digest"],
            "runner_id": paired.runner_id, "runner_key_id": paired.runner_key_id,
        }, paired.cookie)
        assert created["status"] == 201, created["status"]
        binding = created["body"]["context_binding"]
        (row,) = env.cp_call("binding", binding_id=binding["binding_id"])["rows"]
        assert row["binding_digest"] == binding["binding_digest"] and row["runner_id"] == paired.runner_id
        env.registry.add_context(paired.slot, {"binding_id": row["rcb_id"], "binding_digest": row["binding_digest"],
                                               "project_id": row["project_ref"], "environment_id": row["environment_id"]})
        return base, binding

    def approve_run(self, paired: PairedSlot, base: str, submitted: dict) -> dict:
        env = self.env
        run_path = f"{base}/canary-runs/{submitted['run_id']}"
        dashboard = self.owner("GET", run_path, None, paired.cookie)
        assert dashboard["status"] == 200, dashboard["status"]
        approved = self.owner("POST", run_path + "/approve", {
            "schema_version": "heel.canary-execution-approval.v1", "projection_digest": submitted["projection_digest"],
            "hostname_retype": self.STAGING, "reason": "Run the exact bounded staging rehearsal",
        }, paired.cookie, headers={"Idempotency-Key": "ca1-" + secrets.token_hex(32),
                                   "If-Heel-Control-Generation": str(dashboard["body"]["approval_control_generation"])})
        assert approved["status"] == 201, approved["status"]
        grant = approved["body"]["grant"]
        (row,) = env.cp_call("run", run_id=submitted["run_id"])["rows"]
        assert row["grant_id"] == grant["grant_id"] and row["projection_digest"] == submitted["projection_digest"]
        env.registry.add_run(paired.slot, {
            "run_id": submitted["run_id"], "project_id": row["project_ref"], "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"], "projection_id": submitted["projection_id"],
            "approval_projection_digest": submitted["projection_digest"], "manifest_digest": submitted["manifest_digest"],
        })
        return grant


if __name__ == "__main__":
    raise SystemExit(child_main(sys.argv[1:]))
