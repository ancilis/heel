"""
Heel hosted — control-plane HTTP API (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

A require()-guarded JSON API over the tenancy/entitlement/billing/auth stores. Every workspace
route resolves the caller's role server-side through `tenancy.require`; client-supplied roles and
workspace claims are never trusted. Binds loopback by default — production exposure goes through
the deployment's TLS-terminating edge, never by widening this default.

Safety boundary (unchanged from the engine): scope material is never constructed in this layer.
The only hosted minting path is `POST /workspaces/{id}/scopes` — session principals with
`create_scope` (owner/admin), step-up confirmation, audited, delegating to an engine-injected
minter and answering 501 when none is configured. API-key principals can never exercise
`create_scope` by construction. Verified real-target runs additionally require a currently
verified target plus a scope valid for that exact target, enforced fail-closed by the job plane.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.findings_sync import (
    MAX_FINDINGS_SYNC_BYTES,
    parse_findings_sync_request,
    stable_json,
)
from heel.canary_contracts import (
    canonical_bytes,
    parse_json,
    validate_approval_projection,
    validate_operational_run,
    validate_runner_claim_request,
    validate_runner_heartbeat_request,
    validate_runner_progress_request,
    validate_runner_result_request,
    validate_runner_stop_ack_request,
    validate_runner_context_create,
    validate_runner_context_revoke,
    validate_runner_context_list,
    validate_runner_context_claim,
    validate_runner_approval_projection_submit,
)
from heel.crypto import load_public_key_base64, verify_envelope

from .auth import AuthStore, ThrottledError
from .billing import (
    Billing,
    BillingStore,
    BillingUnavailable,
    DisabledBilling,
    StubBilling,
    SubscriptionManager,
)
from .canary_store import CanaryStore
from .canary_disclosure import (
    CANARY_FINDINGS_SCHEMA,
    MAX_UPLOAD_BYTES,
    CanaryDisclosureError,
    CanaryDisclosureService,
)
from .canary_runs import CanaryRunError, CanaryRunService
from .runner_contexts import RunnerContextBindingService, RunnerContextError
from .runner_auth import (
    RunnerActivationAbortConflict,
    RunnerAuthError,
    RunnerHttpAction,
    RunnerAuthRateLimited,
    RunnerAuthStore,
    RunnerProtocolUpgradeRequired,
    initialize_runner_auth_schema,
)
from .catalog import CATALOG_VERSION, Feature, Meter, get_plan, self_serve_plans
from .device_auth import (
    DEVICE_CAPABILITIES,
    DeviceAuthStore,
    DeviceDenied,
    DeviceExpired,
    DevicePending,
    DeviceRateLimited,
    DeviceTokens,
    RefreshReuseDetected,
    SlowDown,
)
from .entitlement import EntitlementService, Subscription
from .jobs import JobPlane
from .ledger import GlobalCapExceeded, IdempotencyConflict, QuotaExceeded, UsageLedger
from .findings_sync import (
    ApprovalExpired,
    ApprovalRequired,
    FindingsSyncConflict,
    FindingsSyncService,
    SyncPrincipal,
)
from .ops import KillSwitchTripped, Metrics, OpsStore
from .projects import ProjectNotFound, ProjectStore
from .tenancy import (
    ControlPlaneStore, IntegrationLimitExceeded, Role, SeatLimitExceeded, hash_api_key, require,
)
from .verification import (
    ATTESTATION_ACKNOWLEDGEMENT, ATTESTATION_VERSION, EnvironmentCooldown, EnvironmentNotFound,
    HostnameReuseExceeded, OWNERSHIP_ATTESTATION, TargetLimitExceeded, TargetVerifier,
    VerifiedEnvironmentService,
)

MAX_BODY = 64 * 1024
MAX_DEVICE_BODY = 8 * 1024
REQUEST_IO_TIMEOUT_SECONDS = 10
REQUEST_BODY_TOTAL_DEADLINE_SECONDS = 10
MAX_CONCURRENT_REQUESTS = 64
REQUEST_DRAIN_TIMEOUT_SECONDS = 30

_LOGGER = logging.getLogger("heel.saas.control_plane")
_SYNC_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CANARY_IDEMPOTENCY = re.compile(r"ca1-[0-9a-f]{64}\Z")
_CONTROL_GENERATION = re.compile(r"0|[1-9][0-9]*\Z")


class _NullLock:
    def __enter__(self): return self
    def __exit__(self, *_): return False


class _DuplicateJsonKey(ValueError):
    pass


def _duplicate_free_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("non-finite JSON numbers are forbidden")


def current_period() -> str:
    return time.strftime("%Y-%m", time.gmtime())


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.body = {"error": message, **extra}


class _RunnerContextUnavailable(Exception):
    pass


class DeviceApiError(ApiError):
    """Closed device-flow error: stable code only, never a reflected detail string."""

    def __init__(self, status: int, code: str, *, interval: int | None = None):
        Exception.__init__(self, code)
        self.status = status
        self.body = {"schema_version": "heel.device-error.v1", "code": code}
        if interval is not None:
            self.body["interval"] = interval


class ControlPlane:
    """All stores on one SQLite connection; the unit the HTTP layer serves."""

    def __init__(self, path: str = ":memory:", *, dns_txt=None, http_get=None,
                 scope_validator=None, scope_minter=None,
                 device_token_pepper: bytes | None = None,
                 enable_device_auth: bool | None = None,
                 public_origin: str | None = None,
                 billing: Billing | None = None,
                 trust_edge_client_key: bool = False,
                 edge_auth_secret: str | None = None,
                 grant_authority=None,
                 grant_trusted_keys: dict[str, object] | None = None,
                 environment_https_verifier=None,
                 environment_dns_txt=None,
                 runner_auth_pepper: bytes | None = None,
                 runner_connection_factory=None,
                 runner_connections_are_shared: bool | None = None):
        configured_pepper = bool(os.environ.get("HEEL_DEVICE_TOKEN_PEPPER_B64"))
        device_enabled = (
            enable_device_auth
            if enable_device_auth is not None
            else device_token_pepper is not None or configured_pepper
        )
        selected_origin = public_origin or os.environ.get("HEEL_PUBLIC_ORIGIN", "")
        if device_enabled:
            if device_token_pepper is None and not configured_pepper:
                raise RuntimeError(
                    "device authorization requires HEEL_DEVICE_TOKEN_PEPPER_B64"
                )
            parsed_origin = urlsplit(selected_origin)
            if (
                not selected_origin
                or selected_origin != f"{parsed_origin.scheme}://{parsed_origin.netloc}"
                or parsed_origin.scheme not in {"http", "https"}
                or parsed_origin.hostname is None
                or (
                    parsed_origin.scheme == "http"
                    and parsed_origin.hostname not in {"127.0.0.1", "localhost", "::1"}
                )
            ):
                raise RuntimeError(
                    "device authorization requires a canonical HEEL_PUBLIC_ORIGIN"
                )
        # All callers touching this shared SQLite connection use this one re-entrant lock. The
        # environment proof deliberately releases it only for DNS/TLS I/O.
        self.request_lock = threading.RLock()
        self.store = ControlPlaneStore(path)
        self._runner_auth_pepper = runner_auth_pepper
        if runner_connection_factory is None:
            self._runner_connection_factory = (
                (lambda: sqlite3.connect(path, check_same_thread=False)) if path != ":memory:"
                else (lambda: self.store.conn)
            )
            self.runner_connections_are_shared = path == ":memory:"
        else:
            self._runner_connection_factory = runner_connection_factory
            # An injected test factory is safe only when the test explicitly declares that it
            # returns independent durable connections. Defaulting to shared protects fixtures.
            self.runner_connections_are_shared = True if runner_connections_are_shared is None else bool(runner_connections_are_shared)
        conn = self.store.conn
        self.canary_store = CanaryStore(conn)
        # Runtime construction (including unit/demo instances) stays schema-parity with the
        # migration, while authentication itself remains disabled absent a distinct pepper.
        initialize_runner_auth_schema(conn)
        # Runner PoP is optional in local/demo construction but production supplies a distinct
        # pepper before starting its listener. It never shares device or API-key hash domains.
        self.runner_auth = (
            RunnerAuthStore(conn, pepper=runner_auth_pepper)
            if runner_auth_pepper is not None else None
        )
        self.grant_authority = grant_authority
        self.grant_trusted_keys = dict(grant_trusted_keys or {})
        self.auth = AuthStore(conn)
        self.device_auth = (
            DeviceAuthStore(conn, pepper=device_token_pepper) if device_enabled else None
        )
        self.public_origin = selected_origin if device_enabled else None
        self.device_verification_uri = (
            selected_origin + "/device" if device_enabled else None
        )
        self.ledger = UsageLedger(conn)
        self.billing_store = BillingStore(conn)
        self.subs = SubscriptionManager(self.billing_store)
        self.billing = billing if billing is not None else StubBilling()
        self.trust_edge_client_key = bool(trust_edge_client_key)
        self.edge_auth_secret = edge_auth_secret
        self.entitlements = EntitlementService(self.ledger)
        self.verifier = TargetVerifier(conn, dns_txt=dns_txt, http_get=http_get)
        self.environments = VerifiedEnvironmentService(
            conn, https_verifier=environment_https_verifier, dns_txt=environment_dns_txt,
            lock=self.request_lock,
        )
        self.jobs = JobPlane(conn, scope_validator=scope_validator,
                             concurrency_limit=lambda wid: self.entitlements.quota(
                                 self.subscription(wid), Meter.CONCURRENCY))
        # scope_minter(workspace_id, target, requested_by) -> scope_ref. Injected from the
        # engine's human-only signed-scope path; this layer never constructs scope material
        # itself. Absent → the mint route answers 501 and verified runs need an out-of-band
        # engine-minted scope reference.
        self.scope_minter = scope_minter
        self.ops = OpsStore(conn)
        self.projects = ProjectStore(conn)
        self.findings = FindingsSyncService(
            conn,
            projects=self.projects,
            ledger=self.ledger,
            ops=self.ops,
            plan_for_workspace=lambda workspace_id: self.entitlements.effective_plan(
                self.subscription(workspace_id)
            ),
        )
        self.metrics = Metrics()
        if grant_authority is None:
            self.canary_runs = None
            self.canary_disclosure = None
            self.runner_contexts = None
        else:
            self.canary_runs = CanaryRunService(conn, signing=grant_authority)
            self.canary_disclosure = CanaryDisclosureService(conn, signing=grant_authority)
            self.runner_contexts = RunnerContextBindingService(conn, signing=grant_authority)
        self.draining = False
        self.required_schema_version: int | None = None
        # Every store shares one SQLite connection. Serialize complete HTTP request units so
        # transaction boundaries and authentication touches cannot interleave across handler
        # threads. A Postgres deployment replaces this with a per-request pooled connection.

    def close(self) -> None:
        """Release the shared database connection. Safe to call more than once."""
        self.store.conn.close()

    @contextmanager
    def runner_request_store(self):
        """A short independent SQLite unit for a public runner request.

        Browser ceremony calls remain on the human connection under ``request_lock``.  A normal
        deployment gives control requests their own connection, with a deliberately short busy
        wait; in-memory fixtures are marked shared and remain locked by the handler.
        """
        if self._runner_auth_pepper is None:
            raise RunnerAuthError("invalid runner authentication")
        conn = self._runner_connection_factory()
        shared = conn is self.store.conn
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=250")
            yield RunnerAuthStore(conn, pepper=self._runner_auth_pepper)
        finally:
            if not shared:
                conn.close()

    @staticmethod
    def runner_active_limit(store: RunnerAuthStore, pairing_id: str) -> int | None:
        """Read the plan pin through the runner's own connection during activation."""
        row = store.conn.execute(
            "SELECT p.workspace_id,w.plan_id AS workspace_plan,w.catalog_version AS workspace_catalog,"
            "s.plan_id AS subscription_plan,s.catalog_version AS subscription_catalog "
            "FROM canary_runner_pairings p JOIN workspaces w ON w.workspace_id=p.workspace_id "
            "LEFT JOIN subscriptions s ON s.workspace_id=p.workspace_id WHERE p.pairing_id=?",
            (pairing_id,),
        ).fetchone()
        if row is None:
            raise RunnerAuthError("invalid pairing")
        plan_id = row["subscription_plan"] or row["workspace_plan"]
        catalog_version = row["subscription_catalog"] or row["workspace_catalog"]
        limit = get_plan(plan_id, catalog_version).quota(Meter.ACTIVE_RUNNERS)
        return None if limit < 0 else limit

    def subscription(self, workspace_id: str) -> Subscription:
        ws = self.store.get_workspace(workspace_id)
        if ws is None:
            raise ApiError(404, "workspace not found")
        sub = self.billing_store.get(workspace_id)
        if sub is not None and sub.state:
            # The subscription's own pinned catalog version wins — grandfathering resolves
            # against the catalog the subscription was created on, not the workspace default.
            return Subscription(workspace_id, sub.plan_id, sub.state, sub.catalog_version)
        return Subscription(workspace_id, ws["plan_id"], "active", ws["catalog_version"])

    def target_quota_blocked(self, workspace_id: str, hostname: str | None = None) -> bool:
        """True when verifying (another) target would exceed the plan's verified-target quota.
        Checked at challenge start AND at check time, on every surface — starting several
        challenges in parallel must not verify past the limit. Re-verifying an already
        verified hostname is always allowed."""
        sub = self.subscription(workspace_id)
        limit = self.entitlements.quota(sub, Meter.VERIFIED_TARGETS)
        if limit < 0:
            return False
        if hostname and self.verifier.is_verified(workspace_id, hostname):
            return False
        return self.verifier.verified_count(workspace_id) >= limit

    def user_by_email(self, email: str) -> sqlite3.Row | None:
        return self.store.conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()


class _Handler(BaseHTTPRequestHandler):
    server_version = "HeelControlPlane/1"
    cp: ControlPlane  # set by serve()
    webhook_secret: str | None = None

    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_IO_TIMEOUT_SECONDS)

    # --- plumbing ---
    def log_message(self, *a):  # quiet; the deployment edge does access logging
        pass

    def _json(self, status: int, obj: dict, headers: dict | None = None) -> None:
        body = json.dumps(obj).encode()
        response_headers = dict(headers or {})
        if getattr(self, "_defer_json_response", False):
            self._pending_json_response = (status, body, response_headers)
            return
        self._write_json(status, body, response_headers)

    def _write_json(self, status: int, body: bytes, headers: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        request_id = getattr(self, "_request_id", None)
        if request_id is not None:
            self.send_header("X-Heel-Request-Id", request_id)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _write_empty(self, status: int, headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        request_id = getattr(self, "_request_id", None)
        if request_id is not None:
            self.send_header("X-Heel-Request-Id", request_id)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _body(self) -> dict:
        raw = getattr(self, "_buffered_body", b"")
        if not raw:
            return {}
        try:
            obj = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_duplicate_free_object,
                parse_constant=_reject_json_constant,
            )
        except (
            _DuplicateJsonKey,
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
        ):
            raise ApiError(400, "invalid JSON body")
        if not isinstance(obj, dict):
            raise ApiError(400, "body must be a JSON object")
        return obj

    def _device_body(self) -> dict:
        """Decode one closed device-flow request without echoing any supplied value."""
        content_types = self._header_values("Content-Type")
        encodings = self._header_values("Content-Encoding")
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
            or len(encodings) > 1
            or (encodings and encodings[0].strip().lower() not in ("", "identity"))
        ):
            raise DeviceApiError(400, "invalid_request")
        try:
            return self._body()
        except ApiError:
            raise DeviceApiError(400, "invalid_request") from None

    def _raw_body(self) -> bytes:
        return getattr(self, "_buffered_body", b"")

    def _header_values(self, name: str) -> list[str]:
        return list(self.headers.get_all(name) or [])

    @staticmethod
    def _is_findings_sync_path(parts: list[str]) -> bool:
        return (
            len(parts) == 6
            and parts[0] == "v1"
            and parts[1] == "workspaces"
            and parts[3] == "projects"
            and parts[5] == "findings-sync"
        )

    def _buffer_request_body(self, method: str, parts: list[str]) -> None:
        """Validate framing and read request bytes before entering the shared DB lock."""
        sync_path = self._is_findings_sync_path(parts)
        transfer_encodings = self._header_values("Transfer-Encoding")
        if transfer_encodings:
            raise ApiError(
                415 if sync_path else 400,
                "transfer-encoded request bodies are not accepted",
                code=(
                    "unsupported_transfer_encoding"
                    if sync_path
                    else "ambiguous_request_framing"
                ),
            )
        lengths = self._header_values("Content-Length")
        if method != "POST":
            if len(lengths) > 1:
                raise ApiError(400, "ambiguous request framing", code="ambiguous_request_framing")
            if lengths:
                if re.fullmatch(r"[0-9]+", lengths[0], flags=re.ASCII) is None:
                    raise ApiError(
                        400, "invalid request content length", code="ambiguous_request_framing"
                    )
                if len(lengths[0]) > 20:
                    raise ApiError(400, "request body is not allowed", code="ambiguous_request_framing")
                length = int(lengths[0])
                if length != 0:
                    raise ApiError(400, "request body is not allowed", code="ambiguous_request_framing")
            self._buffered_body = b""
            return
        if len(lengths) != 1:
            raise ApiError(400, "one Content-Length is required", code="ambiguous_request_framing")
        if re.fullmatch(r"[0-9]+", lengths[0], flags=re.ASCII) is None:
            raise ApiError(
                400, "invalid request content length", code="ambiguous_request_framing"
            )
        if len(lengths[0]) > 20:
            raise ApiError(
                413,
                "findings sync request is too large" if sync_path else "request body too large",
                **({"code": "findings_sync_request_too_large"} if sync_path else {}),
            )
        length = int(lengths[0])
        device_path = len(parts) == 3 and parts[:2] == ["v1", "device"]
        canary_findings_upload = bool(
            len(parts) == 8
            and parts[:2] == ["v1", "workspaces"]
            and parts[3] == "runners"
            and parts[5] == "runs"
            and parts[7] == "result-projection"
        )
        maximum = (
            MAX_FINDINGS_SYNC_BYTES
            if sync_path
            else MAX_UPLOAD_BYTES if canary_findings_upload
            else MAX_DEVICE_BODY if device_path else MAX_BODY
        )
        if length > maximum:
            raise ApiError(
                413,
                "findings sync request is too large" if sync_path else "request body too large",
                **({"code": "findings_sync_request_too_large"} if sync_path else {}),
            )
        deadline = time.monotonic() + REQUEST_BODY_TOTAL_DEADLINE_SECONDS
        remaining = length
        chunks = []
        try:
            while remaining:
                seconds_left = deadline - time.monotonic()
                if seconds_left <= 0:
                    raise socket.timeout
                self.connection.settimeout(seconds_left)
                chunk = self.rfile.read1(min(remaining, 64 * 1024))
                if not chunk:
                    raise ApiError(400, "incomplete request body", code="incomplete_request_body")
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            self.connection.settimeout(REQUEST_IO_TIMEOUT_SECONDS)
        self._buffered_body = b"".join(chunks)

    def _canonical_parts(self) -> list[str]:
        raw_path = self.path.split("?", 1)[0]
        if not raw_path.startswith("/") or "\\" in raw_path:
            raise ApiError(400, "noncanonical request path", code="noncanonical_path")
        if raw_path == "/":
            return []
        if raw_path.endswith("/") or "//" in raw_path:
            raise ApiError(400, "noncanonical request path", code="noncanonical_path")
        parts = raw_path[1:].split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ApiError(400, "noncanonical request path", code="noncanonical_path")
        if parts and parts[0] in ("v1", "app") and "%" in raw_path:
            raise ApiError(400, "noncanonical request path", code="noncanonical_path")
        return parts

    def _findings_sync_body(self, namespace_key: bytes) -> dict:
        """Read one closed findings payload without decoding or echoing untrusted fields."""
        content_types = self._header_values("Content-Type")
        if len(content_types) != 1:
            raise ApiError(
                400,
                "findings sync request headers are ambiguous",
                code="ambiguous_request_headers",
            )
        content_type = content_types[0].split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(
                415,
                "findings sync requires application/json",
                code="unsupported_media_type",
            )
        content_encodings = self._header_values("Content-Encoding")
        if len(content_encodings) > 1:
            raise ApiError(
                400,
                "findings sync request headers are ambiguous",
                code="ambiguous_request_headers",
            )
        content_encoding = (
            content_encodings[0].strip().lower() if content_encodings else "identity"
        )
        if content_encoding not in ("", "identity"):
            raise ApiError(
                415,
                "compressed findings sync bodies are not accepted",
                code="unsupported_content_encoding",
            )
        raw = self._raw_body()
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ApiError(
                400,
                "invalid findings sync request",
                code="invalid_findings_sync_request",
            ) from None
        try:
            request = parse_findings_sync_request(source, namespace_key)
        except ValueError as error:
            code = (
                "duplicate_json_key"
                if "duplicate fields" in str(error)
                else "invalid_findings_sync_request"
            )
            raise ApiError(400, "invalid findings sync request", code=code) from None
        if len(stable_json(request).encode("utf-8")) > MAX_FINDINGS_SYNC_BYTES:
            raise ApiError(
                413,
                "findings sync request is too large",
                code="findings_sync_request_too_large",
            )
        return request

    def _principal(self):
        """Resolve one session, device token, API key, or anonymous principal."""
        authorization_values = self._header_values("Authorization")
        cookie_values = self._header_values("Cookie")
        if len(authorization_values) > 1 or len(cookie_values) > 1:
            raise ApiError(400, "ambiguous authentication headers", code="ambiguous_request_headers")
        authz = authorization_values[0] if authorization_values else ""
        cookie = cookie_values[0] if cookie_values else ""
        session_tokens = []
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "heel_session" and value:
                session_tokens.append(value)
        if len(session_tokens) > 1 or (authz and session_tokens):
            raise ApiError(400, "ambiguous authentication headers", code="ambiguous_request_headers")
        if authz.startswith("Bearer heel_sk_"):
            got = self.cp.store.authenticate_api_key_principal(authz[len("Bearer "):])
            if not got:
                raise ApiError(401, "invalid API key")
            return "api_key", None, got
        if authz.startswith("Bearer heel_at_"):
            got = self._device_store().resolve_access(authz[len("Bearer "):])
            if not got:
                raise ApiError(401, "invalid device token", code="invalid_grant")
            return "device_session", got.user_id, got
        if session_tokens:
            uid = self.cp.auth.resolve_session(session_tokens[0])
            if uid:
                return "session", uid, None
        return "anon", None, None

    def _device_store(self) -> DeviceAuthStore:
        store = self.cp.device_auth
        if store is None:
            raise DeviceApiError(503, "temporarily_unavailable")
        return store

    def _authorized_identity(
        self, workspace_id: str, capability: str
    ) -> tuple[str, str, Role]:
        """The single choke point for workspace routes. API keys are workspace-bound and can
        NEVER exercise create_scope (human-only, session principals only)."""
        kind, user_id, key = self._principal()
        if kind == "session":
            role = require(self.cp.store, workspace_id, user_id, capability)
            return kind, user_id, role
        if kind == "api_key":
            key_id, ws, role = key
            if ws != workspace_id:
                raise ApiError(403, "API key is scoped to a different workspace")
            if capability == "create_scope":
                raise ApiError(403, "authorization scopes are human-only; use a signed-in session")
            # Live entitlement: keys minted on a paid plan stop working the moment the
            # workspace no longer has API access (downgrade, cancellation, dunning fall-back).
            sub = self.cp.subscription(workspace_id)
            if not self.cp.entitlements.has_feature(sub, Feature.API):
                raise ApiError(402, "API access is not included in this plan",
                               upgrade_to=self.cp.entitlements.upgrade_target(sub))
            from .tenancy import role_can
            if not role_can(role, capability):
                raise ApiError(403, f"API key role {role.value} lacks {capability!r}")
            return kind, key_id, role
        if kind == "device_session":
            device = key
            if device.workspace_id != workspace_id:
                raise ApiError(403, "device is scoped to a different workspace")
            if capability not in DEVICE_CAPABILITIES:
                raise ApiError(403, "device lacks the requested capability")
            role = require(self.cp.store, workspace_id, user_id, capability)
            return kind, device.device_id, role
        raise ApiError(401, "authentication required")

    def _authorize(self, workspace_id: str, capability: str) -> Role:
        return self._authorized_identity(workspace_id, capability)[2]

    def _sync_principal(
        self,
        workspace_id: str,
        capability: str,
        *,
        human_only: bool = False,
    ) -> SyncPrincipal:
        kind, actor_ref, role = self._authorized_identity(workspace_id, capability)
        if human_only and kind not in {"session", "device_session"}:
            raise ApiError(
                403,
                "a signed-in human session is required",
                code="human_session_required",
            )
        return SyncPrincipal(
            actor_ref,
            role,
            (
                "human_session"
                if kind == "session"
                else "device_session" if kind == "device_session" else "api_key"
            ),
        )

    # --- routing ---
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, method: str) -> None:
        self._request_id = secrets.token_hex(16)
        try:
            self._route_parts = self._canonical_parts()
            self._buffer_request_body(method, self._route_parts)
        except ApiError as error:
            self._json(error.status, error.body)
            return
        except (TimeoutError, socket.timeout):
            self._json(408, {"error": "request body timed out", "code": "request_timeout"})
            return
        operational_paths = {
            ("v1", "health"),
            ("v1", "healthz"),
            ("v1", "readyz"),
            ("v1", "metrics"),
        }
        if self.cp.edge_auth_secret is not None and tuple(self._route_parts) not in operational_paths:
            supplied = self._header_values("X-Heel-Edge-Auth")
            if (
                len(supplied) != 1
                or not hmac.compare_digest(supplied[0], self.cp.edge_auth_secret)
            ):
                self._json(401, {"error": "private edge authorization required"})
                return
        # Health and metrics are deliberately independent of the SQLite request unit so an
        # operational probe remains available while another request waits on the database.
        if method == "GET" and tuple(self._route_parts) in {
            ("v1", "health"),
            ("v1", "healthz"),
            ("v1", "metrics"),
        }:
            self._route_serial(method)
            return
        self._pending_json_response = None
        self._defer_json_response = bool(self._route_parts and self._route_parts[0] == "v1")
        try:
            # The environment check owns only short DB snapshots/finalization; its DNS/TLS read
            # must not monopolize the process-wide SQLite request lock.
            if self._is_environment_check_route(method):
                self._route_serial(method)
            elif not self._is_runner_control_route(method):
                with self.cp.request_lock:
                    self._route_serial(method)
            else:
                # Only the exact public exchange/activation and fixed PoP routes bypass the
                # global human lock. They own a fresh short SQLite connection per request.
                # In-memory tests explicitly use a shared connection and therefore stay locked.
                guard = self.cp.request_lock if self.cp.runner_connections_are_shared else _NullLock()
                with guard:
                    with self.cp.runner_request_store() as store:
                        self._runner_request_store = store
                        try:
                            self._route_serial(method)
                        finally:
                            self._runner_request_store = None
        finally:
            self._defer_json_response = False
        pending = self._pending_json_response
        self._pending_json_response = None
        if pending is not None:
            self._write_json(*pending)

    def _is_environment_check_route(self, method: str) -> bool:
        p = self._route_parts
        return bool(method == "POST" and len(p) == 8 and p[0] == "v1" and p[1] == "workspaces"
                    and p[3] == "projects" and p[5] == "environments" and p[7] == "check")

    def _is_runner_control_route(self, method: str) -> bool:
        p = self._route_parts
        if method != "POST" or not p or p[0] != "v1":
            return False
        if len(p) == 3 and p[1] in {"runner-pairings", "runner-rotations"} and p[2] == "exchange":
            return True
        if len(p) == 4 and p[1] == "runner-pairings" and p[3] in {"activate", "activation-abort"}:
            return True
        if len(p) == 4 and p[1] == "runner-rotations" and p[3] in {"activate", "poll", "activation-abort"}:
            return True
        return bool(len(p) >= 6 and p[1] == "workspaces" and p[3] == "runners" and (
            (len(p) == 6 and p[5] == "claim") or
            (len(p) == 7 and p[5] == "contexts" and p[6] == "list") or
            (len(p) == 8 and p[5] == "contexts" and p[7] in {"claim", "approval-projections"}) or
            (len(p) == 7 and p[5] == "resync" and p[6] in {"start", "complete"}) or
            (len(p) == 8 and p[5] == "runs" and p[7] in {
                "heartbeat", "progress", "result", "stop-ack", "result-projection",
            })
        ))

    def _route_serial(self, method: str) -> None:
        try:
            parts = self._route_parts
            if parts and parts[0] == "app":
                from . import dashboard
                if dashboard.handle(self, method, parts):
                    return
                raise ApiError(404, "not found")
            handler = self._match(method, parts)
            if handler is None:
                raise ApiError(404, "not found")
            handler()
        except ApiError as e:
            self._json(e.status, e.body)
        except KillSwitchTripped as e:
            self._json(503, {"error": str(e)})
        except IdempotencyConflict as e:
            self._json(409, {"error": str(e)})
        except GlobalCapExceeded as e:
            # Automatic platform circuit breaker: a temporary service condition, never a
            # per-tenant upgrade prompt.
            self.cp.metrics.inc("circuit_breaker_total")
            self._json(503, {"error": str(e)})
        except HostnameReuseExceeded as e:
            self._json(403, {"error": str(e)})
        except RunnerAuthRateLimited as e:
            self._json(429, {"schema_version": "heel.runner-error.v1", "code": "runner_resync_rate_limited", "retry_after_ms": 60_000}, {"Retry-After": "60"})
        except RunnerProtocolUpgradeRequired:
            self._json(403, {"schema_version": "heel.runner-error.v1", "code": "runner_protocol_upgrade_required"})
        except RunnerAuthError:
            self._json(401, {"schema_version": "heel.runner-error.v1", "code": "invalid_runner_auth"})
        except (CanaryRunError, CanaryDisclosureError) as error:
            self._canary_error(error.code)
        except RunnerContextError as error:
            status = {"same_origin_required": 403, "recent_auth_required": 403,
                      "runner_context_binding_not_found": 404, "conflict": 409,
                      "expired": 410, "canary_authority_unavailable": 503}.get(error.code, 400)
            self._json(status, {"schema_version": "heel.runner-context-error.v1", "code": error.code})
        except PermissionError as e:
            self._json(403, {"error": str(e)})
        except ThrottledError as e:
            self._json(429, {"error": str(e)})
        except Exception as error:
            _LOGGER.error(json.dumps({
                "event": "control_plane_internal_error",
                "exception_type": type(error).__name__,
                "method": getattr(self, "command", "UNKNOWN"),
                "request_id": getattr(self, "_request_id", "unavailable"),
            }, sort_keys=True, separators=(",", ":")))
            self._json(500, {"error": "internal error"})

    def _match(self, method: str, p: list[str]):
        if not p or p[0] != "v1":
            return None
        rest = p[1:]
        flat = {
            ("GET", ("health",)): self._health,
            ("GET", ("healthz",)): self._health,
            ("GET", ("readyz",)): self._readyz,
            ("GET", ("metrics",)): self._metrics,
            ("GET", ("plans",)): self._plans,
            ("POST", ("signup",)): self._signup,
            ("POST", ("login",)): self._login,
            ("POST", ("logout",)): self._logout,
            ("GET", ("me",)): self._me,
            ("POST", ("device", "start")): self._device_start,
            ("POST", ("device", "verify")): self._device_verify,
            ("POST", ("device", "poll")): self._device_poll,
            ("POST", ("device", "token")): self._device_token,
            ("POST", ("device", "refresh")): self._device_refresh,
            ("POST", ("device", "revoke")): self._device_revoke,
            ("POST", ("billing", "webhook")): self._webhook,
        }
        if (method, tuple(rest)) in flat:
            return flat[(method, tuple(rest))]
        if method == "POST" and tuple(rest) == ("runner-pairings", "exchange"):
            return self._runner_pairing_exchange
        if method == "POST" and len(rest) == 3 and rest[0] == "runner-pairings" and rest[2] == "activate":
            return lambda: self._runner_pairing_activate(rest[1])
        if method == "POST" and len(rest) == 3 and rest[0] == "runner-pairings" and rest[2] == "activation-abort":
            return lambda: self._runner_pairing_activation_abort(rest[1])
        if method == "POST" and len(rest) == 3 and rest[0] == "runner-rotations" and rest[2] == "activate":
            return lambda: self._runner_rotation_activate(rest[1])
        if method == "POST" and len(rest) == 3 and rest[0] == "runner-rotations" and rest[2] == "activation-abort":
            return lambda: self._runner_rotation_activation_abort(rest[1])
        if method == "POST" and len(rest) == 3 and rest[0] == "runner-rotations" and rest[2] == "poll":
            return lambda: self._runner_rotation_poll(rest[1])
        if len(rest) >= 3 and rest[0] == "workspaces":
            wid, tail = rest[1], tuple(rest[2:])
            ws_routes = {
                ("GET", ("summary",)): lambda: self._ws_summary(wid),
                ("GET", ("entitlements",)): lambda: self._ws_entitlements(wid),
                ("GET", ("usage",)): lambda: self._ws_usage(wid),
                ("POST", ("invites",)): lambda: self._ws_invite(wid),
                ("POST", ("invites", "accept")): lambda: self._ws_invite_accept(wid),
                ("POST", ("api-keys",)): lambda: self._ws_key_create(wid),
                ("POST", ("runs",)): lambda: self._ws_run(wid),
                ("POST", ("scopes",)): lambda: self._ws_scope_mint(wid),
                ("POST", ("targets",)): lambda: self._ws_target_start(wid),
                ("POST", ("targets", "check")): lambda: self._ws_target_check(wid),
                ("POST", ("billing", "checkout")): lambda: self._ws_checkout(wid),
                ("POST", ("runner-pairings",)): lambda: self._runner_pairing_invite(wid),
            }
            if (method, tail) in ws_routes:
                return ws_routes[(method, tail)]
            if method == "DELETE" and len(tail) == 2 and tail[0] == "api-keys":
                return lambda: self._ws_key_revoke(wid, tail[1])
            if method == "GET" and len(tail) == 2 and tail[0] == "runner-pairings":
                return lambda: self._runner_pairing_inspect(wid, tail[1])
            if method == "POST" and len(tail) == 3 and tail[0] == "runner-pairings" and tail[2] == "approve":
                return lambda: self._runner_pairing_approve(wid, tail[1])
            if method == "POST" and len(tail) == 3 and tail[0] == "runners" and tail[2] == "rotate":
                return lambda: self._runner_rotation_start(wid, tail[1])
            if method == "POST" and len(tail) == 5 and tail[0] == "runners" and tail[2] == "rotations" and tail[4] == "approve":
                return lambda: self._runner_rotation_approve(wid, tail[3])
            if method == "DELETE" and len(tail) == 2 and tail[0] == "runners":
                return lambda: self._runner_revoke(wid, tail[1])
            if method == "POST" and len(tail) == 3 and tail[0] == "runners" and tail[2] == "claim":
                return lambda: self._runner_request(wid, tail[1], "runner_claim", None, "claim")
            if method == "POST" and len(tail) == 4 and tail[0] == "runners" and tail[2:] == ("contexts", "list"):
                return lambda: self._runner_request(wid, tail[1], "runner_claim", None, "context-list")
            if method == "POST" and len(tail) == 5 and tail[0] == "runners" and tail[2] == "contexts" and tail[4] in {"claim", "approval-projections"}:
                return lambda: self._runner_request(wid, tail[1], "runner_claim", tail[3], "context-" + tail[4])
            if method == "POST" and len(tail) == 4 and tail[0] == "runners" and tail[2] == "resync" and tail[3] in {"start", "complete"}:
                return lambda: self._runner_resync(wid, tail[1], tail[3])
            if method == "POST" and len(tail) == 5 and tail[0] == "runners" and tail[2] == "runs" and tail[4] in {"heartbeat", "progress", "result", "stop-ack"}:
                capability = "runner_heartbeat" if tail[4] in {"heartbeat", "stop-ack"} else "runner_" + tail[4]
                return lambda: self._runner_request(wid, tail[1], capability, tail[3], tail[4])
            if (method == "POST" and len(tail) == 5 and tail[0] == "runners"
                    and tail[2] == "runs" and tail[4] == "result-projection"):
                return lambda: self._runner_request(
                    wid, tail[1], "runner_result", tail[3], "result-projection",
                )
            if method == "GET" and len(tail) == 2 and tail[0] == "jobs":
                return lambda: self._ws_job_get(wid, tail[1])
            if tail == ("projects",):
                if method == "POST":
                    return lambda: self._ws_project_create(wid)
                if method == "GET":
                    return lambda: self._ws_projects_list(wid)
            if len(tail) == 3 and tail[0] == "projects" and tail[2] == "namespace-key":
                if method == "GET":
                    return lambda: self._ws_project_namespace_key(wid, tail[1])
            if len(tail) == 4 and tail[0] == "projects" and tail[2:] == (
                "findings-sync", "approve"
            ):
                if method == "POST":
                    return lambda: self._ws_findings_approve(wid, tail[1])
            if len(tail) == 3 and tail[0] == "projects" and tail[2] == "findings-sync":
                if method == "POST":
                    return lambda: self._ws_findings_sync(wid, tail[1])
            if len(tail) == 3 and tail[0] == "projects" and tail[2] == "reviews":
                if method == "GET":
                    return lambda: self._ws_findings_reviews(wid, tail[1])
            if len(tail) == 4 and tail[0] == "projects" and tail[2] == "reviews":
                if method == "GET":
                    return lambda: self._ws_findings_review(wid, tail[1], tail[3])
            if len(tail) >= 3 and tail[0] == "projects" and tail[2] == "environments":
                project_ref = tail[1]
                if len(tail) == 3:
                    if method == "GET":
                        return lambda: self._ws_environments_list(wid, project_ref)
                    if method == "POST":
                        return lambda: self._ws_environment_start(wid, project_ref)
                if len(tail) == 5 and method == "POST" and tail[4] == "check":
                    return lambda: self._ws_environment_check(wid, project_ref, tail[3])
                if len(tail) == 5 and method == "POST" and tail[4] == "revoke":
                    return lambda: self._ws_environment_revoke(wid, project_ref, tail[3])
            if len(tail) >= 3 and tail[0] == "projects":
                project_ref = tail[1]
                if len(tail) == 3 and tail[2] == "runner-context-bindings":
                    if method == "GET":
                        return lambda: self._ws_runner_context_list(wid, project_ref)
                    if method == "POST":
                        return lambda: self._ws_runner_context_create(wid, project_ref)
                if (method == "POST" and len(tail) == 5 and tail[2] == "runner-context-bindings"
                        and tail[4] == "revoke"):
                    return lambda: self._ws_runner_context_revoke(wid, project_ref, tail[3])
                if len(tail) == 3 and tail[2] == "canary-approval-projections" and method == "POST":
                    return lambda: self._ws_canary_projection_submit(wid, project_ref)
                if len(tail) == 3 and tail[2] == "canary-approval-requests" and method == "GET":
                    return lambda: self._ws_canary_approval_requests(wid, project_ref)
                if len(tail) >= 4 and tail[2] == "canary-runs":
                    run_id = tail[3]
                    if len(tail) == 4 and method == "GET":
                        return lambda: self._ws_canary_status(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "approve" and method == "POST":
                        return lambda: self._ws_canary_approve(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "events" and method == "GET":
                        return lambda: self._ws_canary_events(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "stop" and method == "POST":
                        return lambda: self._ws_canary_stop(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "disclosure-permits" and method == "POST":
                        return lambda: self._ws_canary_disclosure_permit(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "disclosure-local-only" and method == "POST":
                        return lambda: self._ws_canary_disclosure_local_only(wid, project_ref, run_id)
                    if len(tail) == 5 and tail[4] == "findings" and method == "GET":
                        return lambda: self._ws_canary_findings(wid, project_ref, run_id)
        return None

    # --- isolated runner pairing and proof routes ---
    def _runner_store(self) -> RunnerAuthStore:
        request_store = getattr(self, "_runner_request_store", None)
        if request_store is not None:
            return request_store
        if self.cp.runner_auth is None:
            raise RunnerAuthError("invalid runner authentication")
        return self.cp.runner_auth

    def _runner_pairing_invite(self, wid: str) -> None:
        actor = self._recent_owner_admin(wid)
        try:
            if set(self._body()) != {"schema_version"} or self._body()["schema_version"] != "heel.runner-pairing-invite.v1":
                raise ValueError
            invitation = self._runner_store().invite(wid)
        except (ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner pairing request", code="invalid_runner_pairing") from None
        self._json(201, {"schema_version": "heel.runner-pairing-invitation.v1", "invitation_token": invitation.token, "expires_at": invitation.expires_at})

    def _runner_pairing_exchange(self) -> None:
        try:
            body = self._body()
            v2_fields = {"schema_version", "invitation_token", "public_key_b64", "pairing_phrase", "display_name", "runner_version", "adapters"}
            v3_fields = v2_fields | {"control_protocol"}
            if (set(body) != v2_fields and set(body) != v3_fields) or body["schema_version"] not in {"heel.runner-pairing-exchange.v2", "heel.runner-pairing-exchange.v3"}:
                raise ValueError
            executable = body["schema_version"] == "heel.runner-pairing-exchange.v3"
            if executable and (set(body) != v3_fields or body["control_protocol"] != "heel.runner-control.v2"):
                raise ValueError
            if not executable and set(body) != v2_fields:
                raise ValueError
            pairing = self._runner_store().exchange(
                body["invitation_token"], body["public_key_b64"], body["pairing_phrase"],
                display_name=body["display_name"], runner_version=body["runner_version"], adapters=body["adapters"],
                control_protocol="heel.runner-control.v2" if executable else None,
                exchange_digest=hashlib.sha256(canonical_bytes(body)).hexdigest() if executable else None,
            )
        except (KeyError, TypeError, ValueError, RunnerAuthError):
            # Exchange must not reveal whether a one-time invitation was known.
            raise ApiError(400, "invalid runner pairing request", code="invalid_runner_pairing") from None
        if pairing.control_protocol is not None:
            self._json(201, {
                "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": pairing.pairing_id,
                "runner_id": pairing.runner_id, "fingerprint": pairing.fingerprint, "status": pairing.status,
                "activation_challenge": pairing.activation_challenge,
                "control_protocol": pairing.control_protocol,
                "pairing_exchange_digest": pairing.pairing_exchange_digest,
            })
            return
        self._json(201, {"schema_version": "heel.runner-pairing-pending.v1", "pairing_id": pairing.pairing_id, "runner_id": pairing.runner_id, "fingerprint": pairing.fingerprint, "status": pairing.status, "activation_challenge": pairing.activation_challenge})

    def _runner_pairing_inspect(self, wid: str, pairing_id: str) -> None:
        self._recent_owner_admin(wid)
        try:
            pairing = self._runner_store().inspect(wid, pairing_id)
        except RunnerAuthError:
            raise ApiError(404, "runner pairing not found", code="runner_pairing_not_found") from None
        self._json(200, {"schema_version": "heel.runner-pairing-view.v1", "pairing_id": pairing.pairing_id, "runner_id": pairing.runner_id, "pairing_phrase": pairing.phrase, "fingerprint": pairing.fingerprint, "status": pairing.status, "expires_at": pairing.expires_at})

    def _runner_pairing_approve(self, wid: str, pairing_id: str) -> None:
        actor = self._recent_owner_admin(wid)
        try:
            body = self._body()
            if set(body) != {"schema_version", "pairing_phrase", "fingerprint"} or body["schema_version"] != "heel.runner-pairing-approve.v1":
                raise ValueError
            self._runner_store().approve(wid, pairing_id, phrase=body["pairing_phrase"], fingerprint=body["fingerprint"], actor=actor)
        except (KeyError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner pairing request", code="invalid_runner_pairing") from None
        self._json(200, {"schema_version": "heel.runner-pairing-approved.v1", "status": "approved"})

    def _runner_pairing_activate(self, pairing_id: str) -> None:
        try:
            body = self._body()
            store = self._runner_store()
            if set(body) == {"schema_version", "client_activation_nonce_b64", "signature_b64"} and body["schema_version"] == "heel.runner-pairing-activate.v3":
                response = store.activate_executable(
                    pairing_id, body, max_active=self.cp.runner_active_limit(store, pairing_id),
                )
                self._json(200, response)
                return
            if set(body) != {"schema_version", "signature_b64"} or body["schema_version"] != "heel.runner-pairing-activate.v1":
                raise ValueError
            # The plan read is intentionally on the same short runner connection, never on
            # cp.store.conn; activation and its active-runner count then share one transaction.
            wid, runner_id, nonce = store.activate(pairing_id, body["signature_b64"], max_active=self.cp.runner_active_limit(store, pairing_id))
        except (KeyError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner pairing request", code="invalid_runner_pairing") from None
        self._json(200, {"schema_version": "heel.runner-pairing-activated.v1", "workspace_id": wid, "runner_id": runner_id, "initial_claim_nonce": nonce, "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]})

    def _runner_pairing_activation_abort(self, pairing_id: str) -> None:
        """Runner-key-only recovery for a challenge that reached Cloud expiry."""
        try:
            if self._header_values("Authorization") or self._header_values("Cookie") or len(self._raw_body()) > 4096:
                raise ValueError
            body = self._body()
            if canonical_bytes(body) != self._raw_body():
                raise ValueError
            response = self._runner_store().abort_executable_pairing_activation(pairing_id, body)
        except RunnerActivationAbortConflict as error:
            payload = {"schema_version": "heel.runner-error.v1", "code": error.code}
            if error.retry_after_ms is not None:
                payload["retry_after_ms"] = error.retry_after_ms
            self._json(409, payload)
            return
        except (KeyError, TypeError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner pairing request", code="invalid_runner_pairing") from None
        self._json(200, response)

    def _runner_rotation_poll(self, pairing_id: str) -> None:
        try:
            challenge = self._runner_store().rotation_activation_challenge(pairing_id)
        except RunnerAuthError:
            raise ApiError(400, "invalid runner rotation", code="invalid_runner_rotation") from None
        self._json(200, {"schema_version": "heel.runner-rotation-activation-challenge.v1", "pairing_id": pairing_id, "activation_challenge": challenge})

    def _runner_rotation_activate(self, pairing_id: str) -> None:
        try:
            body = self._body()
            if set(body) != {"schema_version", "signature_b64"} or body["schema_version"] != "heel.runner-rotation-activate.v2":
                raise ValueError
            wid, runner_id, nonce, sequence, generation = self._runner_store().activate_rotation(pairing_id, body["signature_b64"])
        except (KeyError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner rotation", code="invalid_runner_rotation") from None
        self._json(200, {
            "schema_version": "heel.runner-rotation-activated.v2",
            "workspace_id": wid,
            "runner_id": runner_id,
            "initial_claim_nonce": nonce,
            "initial_claim_sequence": sequence,
            "initial_claim_generation": generation,
        })

    def _runner_rotation_activation_abort(self, pairing_id: str) -> None:
        try:
            if self._header_values("Authorization") or self._header_values("Cookie") or len(self._raw_body()) > 4096:
                raise ValueError
            body = self._body()
            if canonical_bytes(body) != self._raw_body():
                raise ValueError
            response = self._runner_store().abort_rotation_activation(pairing_id, body)
        except RunnerActivationAbortConflict as error:
            payload = {"schema_version": "heel.runner-error.v1", "code": error.code}
            if error.retry_after_ms is not None:
                payload["retry_after_ms"] = error.retry_after_ms
            self._json(409, payload)
            return
        except (KeyError, TypeError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner rotation", code="invalid_runner_rotation") from None
        self._json(200, response)

    def _runner_rotation_start(self, wid: str, runner_id: str) -> None:
        self._recent_owner_admin(wid)
        try:
            body = self._body()
            required = {"schema_version", "previous_fingerprint", "public_key_b64", "pairing_phrase", "runner_version", "adapters"}
            if set(body) != required or body["schema_version"] != "heel.runner-rotation-start.v1": raise ValueError
            view = self._runner_store().start_rotation(wid, runner_id, previous_fingerprint=body["previous_fingerprint"], public_key_b64=body["public_key_b64"], phrase=body["pairing_phrase"], runner_version=body["runner_version"], adapters=body["adapters"])
        except (KeyError, TypeError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner rotation", code="invalid_runner_rotation") from None
        self._json(201, {"schema_version": "heel.runner-rotation-pending.v1", "pairing_id": view.pairing_id, "fingerprint": view.fingerprint, "pairing_phrase": view.phrase})

    def _runner_rotation_approve(self, wid: str, pairing_id: str) -> None:
        actor = self._recent_owner_admin(wid)
        try:
            body = self._body()
            if set(body) != {"schema_version", "pairing_phrase", "fingerprint"} or body["schema_version"] != "heel.runner-rotation-approve.v1": raise ValueError
            self._runner_store().approve_rotation(wid, pairing_id, phrase=body["pairing_phrase"], fingerprint=body["fingerprint"], actor=actor)
        except (KeyError, ValueError, RunnerAuthError):
            raise ApiError(400, "invalid runner rotation", code="invalid_runner_rotation") from None
        self._json(200, {"schema_version": "heel.runner-rotation-approved.v1", "status": "approved"})

    def _runner_revoke(self, wid: str, runner_id: str) -> None:
        actor = self._recent_owner_admin(wid)
        body = self._body()
        if (set(body) != {"schema_version", "reason_code"}
                or body.get("schema_version") != "heel.runner-revoke.v1"
                or type(body.get("reason_code")) is not str):
            raise ApiError(400, "invalid runner revocation", code="invalid_runner_revocation")
        try:
            revoked = self._runner_store().revoke(wid, runner_id, actor=actor, reason_code=body["reason_code"])
        except (ValueError, RunnerAuthError):
            revoked = False
        if not revoked:
            raise ApiError(400, "invalid runner revocation", code="invalid_runner_revocation")
        self._json(200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})

    def _canary_error(self, code: str) -> None:
        status = {
            "invalid_canary_projection": 400,
            "invalid_canary_approval": 400,
            "hostname_confirmation_mismatch": 400,
            "environment_not_executable": 403,
            "canary_quota_exceeded": 402,
            "canary_state_conflict": 409,
            "event_sequence_conflict": 409,
            "disclosure_permit_required": 403,
            "disclosure_permit_expired": 410,
            "permit_consumed": 409,
            "canary_run_not_found": 404,
            "canary_authority_unavailable": 503,
        }.get(code, 409)
        self._json(
            status,
            {"schema_version": "heel.canary-error.v1", "code": code},
        )

    def _human_canary_services(
        self,
    ) -> tuple[CanaryRunService, CanaryDisclosureService]:
        runs = self.cp.canary_runs
        disclosure = self.cp.canary_disclosure
        if runs is None or disclosure is None:
            raise CanaryRunError("canary_authority_unavailable")
        return runs, disclosure

    def _expected_control_generation(self) -> int:
        values = self._header_values("If-Heel-Control-Generation")
        if (len(values) != 1 or _CONTROL_GENERATION.fullmatch(values[0]) is None
                or len(values[0]) > 20):
            raise ApiError(
                400, "invalid canary control generation",
                code="invalid_canary_approval",
            )
        return int(values[0])

    @staticmethod
    def _operational_context_matches(conn: sqlite3.Connection, *, workspace_id: str,
                                     runner_id: str, projection: dict) -> bool:
        """Bind a closed runner receipt to the immutable run/grant graph, not its labels."""
        row = conn.execute(
            "SELECT r.workspace_id,r.project_ref,r.grant_id,g.grant_digest,a.projection_digest,a.projection_json,k.key_id,k.public_key "
            "FROM canary_runs r JOIN canary_execution_grants g ON "
            "g.workspace_id=r.workspace_id AND g.project_ref=r.project_ref AND g.grant_id=r.grant_id "
            "JOIN canary_approval_projections a ON a.workspace_id=g.workspace_id AND a.project_ref=g.project_ref AND a.approval_id=g.approval_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id AND k.status='active' AND k.revoked_at IS NULL "
            "WHERE r.workspace_id=? AND r.runner_id=? AND r.run_id=? AND g.runner_id=? AND a.runner_id=?",
            (workspace_id, runner_id, projection["run_id"], runner_id, runner_id),
        ).fetchone()
        if row is None:
            return False
        try:
            approval = json.loads(row["projection_json"])
        except (TypeError, ValueError):
            return False
        if not all((
            projection["workspace_id"] == row["workspace_id"],
            projection["project_id"] == row["project_ref"],
            projection["grant_id"] == row["grant_id"],
            projection["grant_digest"] == row["grant_digest"],
            projection["approval_projection_digest"] == row["projection_digest"],
            projection["manifest_digest"] == approval.get("manifest_digest"),
            projection["signing_key_id"] == row["key_id"],
        )):
            return False
        try:
            payload = {key: value for key, value in projection.items()
                       if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
            verify_envelope(
                {row["key_id"]: load_public_key_base64(row["public_key"])},
                {"signing_key_id": projection["signing_key_id"], "signature_b64": projection["signature_b64"]},
                canonical_bytes(payload),
            )
        except (TypeError, ValueError):
            return False
        return True

    def _runner_request(self, wid: str, runner_id: str, capability: str, run_id: str | None, operation: str) -> None:
        # Runner paths are fixed and strict: no URI aliases, bearer headers, URL parameters,
        # or payload/path disagreement can enter the PoP verifier.
        if "?" in self.path or "#" in self.path or "%" in self.path or self.command != "POST":
            raise RunnerAuthError("invalid runner authentication")
        try:
            maximum = (
                128 if operation == "context-list"
                else 256 if operation in {"claim", "context-claim"}
                else 69632 if operation == "context-approval-projections"
                else MAX_UPLOAD_BYTES if operation == "result-projection"
                else 36 * 1024
            )
            parsed = parse_json(self._raw_body(), max_bytes=maximum)
            validators = {"claim": validate_runner_claim_request, "heartbeat": validate_runner_heartbeat_request,
                          "progress": validate_runner_progress_request, "result": validate_runner_result_request,
                          "stop-ack": validate_runner_stop_ack_request, "context-list": validate_runner_context_list,
                          "context-claim": validate_runner_context_claim, "context-approval-projections": validate_runner_approval_projection_submit}
            if operation != "result-projection":
                parsed = validators[operation](parsed)
            if (canonical_bytes(parsed) != self._raw_body()
                    or (run_id is not None and (parsed.get("run_id", parsed.get("binding_id", parsed.get("context_binding_id"))) != run_id))):
                raise RunnerAuthError("invalid runner authentication")
            if operation not in {"claim", "result-projection", "context-list", "context-claim", "context-approval-projections"} and not self._operational_context_matches(
                    self._runner_store().conn, workspace_id=wid, runner_id=runner_id,
                    projection=parsed["operational_projection"]):
                raise RunnerAuthError("invalid runner authentication")
            all_headers = {name: self._header_values(name) for name in ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence", "X-Heel-Runner-Signature", "Authorization", "Cookie")}
            store = self._runner_store()
            def action() -> RunnerHttpAction:
                # This setup intentionally happens only after RunnerAuthStore's v3 protocol
                # gate and PoP checks. A legacy pairing must not receive an authority error in
                # place of the non-executable protocol response, and none of these services
                # may be reached before its nonce is protected by the same transaction.
                if not operation.startswith("context-"):
                    runs, disclosure = self._runner_canary_services(store)
                if operation == "claim":
                    claimed = runs.claim(
                        wid, runner_id, all_headers["X-Heel-Runner-Key-Id"][0],
                    )
                    return RunnerHttpAction(200, claimed) if claimed is not None else RunnerHttpAction(204, None)
                key_id = all_headers["X-Heel-Runner-Key-Id"][0]
                if operation.startswith("context-"):
                    if self.cp.grant_authority is None:
                        raise _RunnerContextUnavailable
                    context_runs, _ = self._runner_canary_services(store)
                    context_service = RunnerContextBindingService(store.conn, signing=self.cp.grant_authority)
                if operation == "context-list":
                    return RunnerHttpAction(200, context_service.list_for_runner_in_transaction(wid, runner_id, key_id))
                if operation == "context-claim":
                    return RunnerHttpAction(200, context_service.claim_in_transaction(wid, runner_id, key_id, run_id, parsed))
                if operation == "context-approval-projections":
                    binding = context_service.active_binding_for_projection_in_transaction(
                        wid, runner_id, key_id, run_id, parsed["context_binding_digest"],
                    )
                    response = context_runs.submit_projection_from_runner_in_transaction(
                        parsed["approval_projection"], binding, uploaded_by_runner_id=runner_id,
                    )
                    if getattr(response, "created", False):
                        context_service._event(binding, "projection_submitted", "runner", runner_id)
                    return RunnerHttpAction(201, response)
                if operation == "result-projection":
                    project_ref = self._runner_run_project(
                        store.conn, wid, runner_id, run_id,
                    )
                    return RunnerHttpAction(200, disclosure.upload(
                        wid, project_ref, run_id, runner_id, parsed,
                    ))
                projection = parsed["operational_projection"]
                project_ref = projection["project_id"]
                if operation == "heartbeat":
                    return RunnerHttpAction(200, runs.heartbeat(wid, project_ref, run_id, runner_id, projection))
                if operation == "progress":
                    return RunnerHttpAction(200, runs.progress(wid, project_ref, run_id, runner_id, projection))
                if operation == "result":
                    return RunnerHttpAction(200, runs.result(wid, project_ref, run_id, runner_id, projection))
                acknowledged = runs.ack_stop(
                    wid, project_ref, run_id, runner_id, projection,
                )
                return RunnerHttpAction(200, acknowledged)

            response_status, response, nonce = self._runner_store().authenticate_and_consume(
                workspace_id=wid, runner_id=runner_id, capability=capability, path=self.path,
                raw_body=self._raw_body(), headers=all_headers,
                action=action,
                chain_name=(
                    "claim" if operation in {"claim", "context-list", "context-claim", "context-approval-projections"}
                    else f"result:{run_id}" if operation == "result-projection"
                    else f"{operation}:{run_id}"
                ),
                max_body_bytes=maximum,
            )
        except _RunnerContextUnavailable:
            self._json(503, {"schema_version": "heel.runner-context-error.v1", "code": "runner_context_unavailable"})
            return
        except RunnerContextError:
            raise RunnerAuthError("invalid runner authentication") from None
        except (CanaryRunError, CanaryDisclosureError):
            if operation.startswith("context-"):
                raise RunnerAuthError("invalid runner authentication") from None
            raise
        except RunnerProtocolUpgradeRequired:
            raise
        except (ValueError, RunnerAuthError, LookupError):
            raise RunnerAuthError("invalid runner authentication") from None
        response_headers = {"X-Heel-Runner-Next-Nonce": nonce}
        if response_status == 204:
            self._write_empty(204, response_headers)
        else:
            if response is None:
                raise RunnerAuthError("invalid runner authentication")
            body = RunnerAuthStore.response_wire_body(response)
            if getattr(self, "_defer_json_response", False):
                self._pending_json_response = (response_status, body, response_headers)
            else:
                self._write_json(response_status, body, response_headers)

    def _runner_canary_services(
        self, store: RunnerAuthStore,
    ) -> tuple[CanaryRunService, CanaryDisclosureService]:
        authority = self.cp.grant_authority
        if authority is None:
            raise CanaryRunError("canary_authority_unavailable")
        return (
            CanaryRunService(
                store.conn, signing=authority, runner_auth=store,
                initialize_schema=False,
            ),
            CanaryDisclosureService(
                store.conn, signing=authority, initialize_schema=False,
            ),
        )

    @staticmethod
    def _runner_run_project(
        conn: sqlite3.Connection,
        workspace_id: str,
        runner_id: str,
        run_id: str | None,
    ) -> str:
        row = conn.execute(
            "SELECT project_ref FROM canary_runs WHERE workspace_id=? AND runner_id=? "
            "AND run_id=?",
            (workspace_id, runner_id, run_id),
        ).fetchone()
        if row is None:
            raise LookupError("canary run not found")
        return row["project_ref"]

    def _runner_resync(self, wid: str, runner_id: str, phase: str) -> None:
        if "?" in self.path or "#" in self.path or "%" in self.path or self.command != "POST":
            raise RunnerAuthError("invalid runner authentication")
        headers = {name: self._header_values(name) for name in (
            "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms",
            "X-Heel-Runner-Signature", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence",
            "Authorization", "Cookie")}
        try:
            store = self._runner_store()
            response = (store.start_resync if phase == "start" else store.complete_resync)(
                workspace_id=wid, runner_id=runner_id, path=self.path,
                raw_body=self._raw_body(), headers=headers,
            )
        except (RunnerAuthRateLimited, RunnerProtocolUpgradeRequired):
            raise
        except (ValueError, RunnerAuthError):
            raise RunnerAuthError("invalid runner authentication") from None
        self._json(200, response)

    # --- open endpoints ---
    def _health(self):
        self._json(200, {"ok": True, "catalog_version": CATALOG_VERSION})

    def _readyz(self):
        if self.cp.draining:
            raise ApiError(503, "control plane draining")
        try:
            self.cp.store.conn.execute("SELECT 1")
            if self.cp.required_schema_version is not None:
                current = self.cp.store.conn.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                if current != self.cp.required_schema_version:
                    raise ApiError(503, "database schema unavailable")
        except ApiError:
            raise
        except Exception:
            raise ApiError(503, "database unavailable")
        self._json(200, {
            "ready": True,
            "schema_version": self.cp.required_schema_version,
        })

    def _metrics(self):
        body = self.cp.metrics.render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _plans(self):
        paid_checkout_available = not isinstance(self.cp.billing, DisabledBilling)
        self._json(200, {"catalog_version": CATALOG_VERSION, "plans": [
            {
                "id": pl.id,
                "name": pl.name,
                "price_month_cents": pl.price_month_cents,
                "availability": (
                    "available" if pl.id == "free" or paid_checkout_available else "coming_soon"
                ),
            }
            for pl in self_serve_plans()]})

    @staticmethod
    def _device_token_payload(tokens: DeviceTokens) -> dict:
        return {
            "schema_version": "heel.device-token-response.v1",
            "token_type": "Bearer",
            "access_token": tokens.access_token,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "refresh_expires_in": tokens.refresh_expires_in,
            "device_id": tokens.device_id,
            "workspace_id": tokens.workspace_id,
            "capabilities": list(tokens.capabilities),
        }

    def _device_start(self):
        body = self._device_body()
        if (
            set(body) != {"schema_version", "client_id", "device_name", "device_challenge"}
            or body.get("schema_version") != "heel.device-start.v1"
            or body.get("client_id") != "heel-agent"
            or type(body.get("device_name")) is not str
            or type(body.get("device_challenge")) is not str
        ):
            raise DeviceApiError(400, "invalid_request")
        try:
            supplied_client_key = self.headers.get("X-Heel-Client-Key", "")
            client_key = (
                supplied_client_key
                if re.fullmatch(r"[0-9a-f]{64}", supplied_client_key)
                else hashlib.sha256(
                    ("direct-device-start\0" + self.client_address[0]).encode("utf-8")
                ).hexdigest()
            )
            started = self._device_store().start(
                body["device_name"], body["device_challenge"], client_key=client_key,
            )
        except DeviceRateLimited:
            raise DeviceApiError(429, "rate_limited") from None
        except ValueError:
            raise DeviceApiError(400, "invalid_request") from None
        self._json(201, {
            "schema_version": "heel.device-start-response.v1",
            "device_code": started.device_code,
            "user_code": started.user_code,
            "verification_uri": self.cp.device_verification_uri,
            "expires_in": started.expires_in,
            "interval": started.interval,
        })

    def _require_device_verify_session(self) -> str:
        kind, user_id, _ = self._principal()
        if kind != "session":
            raise DeviceApiError(401, "auth_required")
        internal_same_origin = self.headers.get("X-Heel-Internal-Origin") == "same-origin"
        preserved_origin = self.headers.get("Origin") == self.cp.public_origin
        if not (internal_same_origin and preserved_origin):
            raise DeviceApiError(403, "not_authorized")

        # Device authorization is a sensitive account action. Refuse a browser authentication
        # older than fifteen minutes so an unattended long-lived session cannot add a device.
        cookie = self.headers.get("Cookie", "")
        token = next(
            (
                value
                for part in cookie.split(";")
                for key, _, value in [part.strip().partition("=")]
                if key == "heel_session"
            ),
            "",
        )
        session = self.cp.store.conn.execute(
            "SELECT created_at FROM sessions WHERE token_hash=? AND revoked_at IS NULL",
            (hash_api_key(token),),
        ).fetchone()
        if session is None or time.time() - session["created_at"] > 15 * 60:
            raise DeviceApiError(403, "recent_auth_required")
        return user_id

    def _device_verify(self):
        user_id = self._require_device_verify_session()
        body = self._device_body()
        action = body.get("action")
        user_code = body.get("user_code")
        if body.get("schema_version") != "heel.device-verify.v1" or type(user_code) is not str:
            raise DeviceApiError(400, "invalid_request")
        if action == "inspect":
            if set(body) != {"schema_version", "user_code", "action"}:
                raise DeviceApiError(400, "invalid_request")
            try:
                claim = self._device_store().inspect(user_code, user_id)
            except DeviceExpired:
                raise DeviceApiError(410, "expired_token") from None
            except PermissionError:
                raise DeviceApiError(400, "invalid_request") from None
            self._json(200, {
                "schema_version": "heel.device-verify-view.v1",
                "status": "pending",
                "user_code": user_code,
                "client_id": "heel-agent",
                "device_name": claim.device_name,
                "device_fingerprint": claim.device_fingerprint,
                "capabilities": list(DEVICE_CAPABILITIES),
                "expires_in": claim.expires_in,
                "confirmation_nonce": claim.confirmation_nonce,
            })
            return
        if action == "approve":
            if set(body) != {
                "schema_version", "user_code", "action", "workspace_id",
                "confirmation_nonce",
            }:
                raise DeviceApiError(400, "invalid_request")
            workspace_id = body.get("workspace_id")
            nonce = body.get("confirmation_nonce")
            if type(workspace_id) is not str or type(nonce) is not str:
                raise DeviceApiError(400, "invalid_request")
            try:
                require(self.cp.store, workspace_id, user_id, "sync_findings")
            except PermissionError:
                raise DeviceApiError(403, "not_authorized") from None
        elif action == "deny":
            if set(body) != {"schema_version", "user_code", "action", "confirmation_nonce"}:
                raise DeviceApiError(400, "invalid_request")
            workspace_id = None
            nonce = body.get("confirmation_nonce")
            if type(nonce) is not str:
                raise DeviceApiError(400, "invalid_request")
        else:
            raise DeviceApiError(400, "invalid_request")
        try:
            self._device_store().decide(
                user_code,
                nonce,
                user_id,
                action=action,
                workspace_id=workspace_id,
            )
        except PermissionError:
            raise DeviceApiError(400, "invalid_request") from None
        self._json(200, {
            "schema_version": "heel.device-verify-response.v1",
            "status": "approved" if action == "approve" else "denied",
        })

    def _device_poll(self):
        body = self._device_body()
        if (
            set(body) != {"schema_version", "device_code", "device_verifier"}
            or body.get("schema_version") != "heel.device-poll.v1"
            or type(body.get("device_code")) is not str
            or type(body.get("device_verifier")) is not str
        ):
            raise DeviceApiError(400, "invalid_request")
        try:
            result = self._device_store().poll(body["device_code"], body["device_verifier"])
        except SlowDown as error:
            raise DeviceApiError(429, "slow_down", interval=error.interval) from None
        except PermissionError:
            raise DeviceApiError(401, "invalid_grant") from None
        payload = {
            "schema_version": "heel.device-poll-response.v1",
            "status": result.status,
        }
        if result.status == "pending":
            payload.update({"expires_in": result.expires_in, "interval": result.interval})
        self._json(200, payload)

    def _device_token(self):
        body = self._device_body()
        if (
            set(body) != {"schema_version", "grant_type", "device_code", "device_verifier"}
            or body.get("schema_version") != "heel.device-token.v1"
            or body.get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code"
            or type(body.get("device_code")) is not str
            or type(body.get("device_verifier")) is not str
        ):
            raise DeviceApiError(400, "invalid_request")
        try:
            tokens = self._device_store().exchange(body["device_code"], body["device_verifier"])
        except DevicePending:
            raise DeviceApiError(409, "authorization_pending") from None
        except DeviceDenied:
            raise DeviceApiError(403, "access_denied") from None
        except DeviceExpired:
            raise DeviceApiError(410, "expired_token") from None
        except PermissionError:
            raise DeviceApiError(401, "invalid_grant") from None
        try:
            require(self.cp.store, tokens.workspace_id,
                    self._device_store().resolve_access(tokens.access_token).user_id,
                    "sync_findings")
        except (PermissionError, AttributeError):
            self._device_store().revoke(tokens.refresh_token)
            raise DeviceApiError(403, "access_denied")
        self._json(200, self._device_token_payload(tokens))

    def _device_refresh(self):
        body = self._device_body()
        if (
            set(body) != {"schema_version", "grant_type", "refresh_token"}
            or body.get("schema_version") != "heel.device-refresh.v1"
            or body.get("grant_type") != "refresh_token"
            or type(body.get("refresh_token")) is not str
        ):
            raise DeviceApiError(400, "invalid_request")
        try:
            tokens = self._device_store().refresh(body["refresh_token"])
        except RefreshReuseDetected:
            raise DeviceApiError(401, "refresh_reuse_detected") from None
        except PermissionError:
            raise DeviceApiError(401, "invalid_grant") from None
        principal = self._device_store().resolve_access(tokens.access_token)
        try:
            if principal is None:
                raise PermissionError
            require(self.cp.store, tokens.workspace_id, principal.user_id, "sync_findings")
        except PermissionError:
            self._device_store().revoke(tokens.refresh_token)
            raise DeviceApiError(403, "access_denied")
        self._json(200, self._device_token_payload(tokens))

    def _device_revoke(self):
        body = self._device_body()
        if (
            set(body) != {"schema_version", "refresh_token"}
            or body.get("schema_version") != "heel.device-revoke.v1"
            or type(body.get("refresh_token")) is not str
        ):
            raise DeviceApiError(400, "invalid_request")
        self._device_store().revoke(body["refresh_token"])
        self._json(200, {"schema_version": "heel.device-revoke-response.v1", "ok": True})

    def _signup(self):
        b = self._body()
        email, password = str(b.get("email", "")).strip(), str(b.get("password", ""))
        if "@" not in email:
            raise ApiError(400, "valid email required")
        if len(password) < 10:
            raise ApiError(400, "password must be at least 10 characters")
        # The production edge derives a one-way per-client key from its trusted transport
        # metadata. Direct/local servers continue to use the socket address and never honor
        # caller-supplied forwarding headers.
        client_key = self.client_address[0]
        if self.cp.trust_edge_client_key:
            supplied = self.headers.get("X-Heel-Client-Key", "")
            if re.fullmatch(r"[0-9a-f]{64}", supplied) is None:
                raise ApiError(400, "trusted client key required")
            client_key = supplied
        self.cp.auth.throttle_signup(client_key, email)
        connection = self.cp.store.conn
        connection.execute("BEGIN IMMEDIATE")
        try:
            if self.cp.user_by_email(email):
                raise ApiError(409, "account already exists")
            uid = self.cp.store.create_user(email, commit=False)
            self.cp.auth.set_password(uid, password, commit=False)
            org = self.cp.store.create_org(email, commit=False)
            wid = self.cp.store.create_workspace(
                org, "default", "free", CATALOG_VERSION, commit=False
            )
            self.cp.store.add_member(wid, uid, Role.OWNER, commit=False)
            ses = self.cp.auth.create_session(uid, commit=False)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        self._json(201, {"user_id": uid, "workspace_id": wid},
                   {"Set-Cookie": _session_cookie(ses.token)})

    def _login(self):
        b = self._body()
        email, password = str(b.get("email", "")).strip(), str(b.get("password", ""))
        row = self.cp.user_by_email(email)
        ses = self.cp.auth.login(email, row["user_id"] if row else None, password)
        self._json(200, {"user_id": ses.user_id},
                   {"Set-Cookie": _session_cookie(ses.token)})

    def _logout(self):
        kind, _, _ = self._principal()
        if kind == "session":
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "heel_session":
                    self.cp.auth.revoke_session(v)
        self._json(200, {"ok": True}, {"Set-Cookie": "heel_session=; Max-Age=0; Path=/"})

    def _me(self):
        kind, uid, key = self._principal()
        if kind == "session":
            rows = self.cp.store.conn.execute(
                "SELECT workspace_id, role FROM memberships WHERE user_id=?", (uid,)).fetchall()
            self._json(200, {"user_id": uid, "workspaces": [
                {"workspace_id": r["workspace_id"], "role": r["role"]} for r in rows]})
        elif kind == "api_key":
            # Same live entitlement rule as _authorize: no Feature.API, no hosted API — even
            # for self-introspection, so "paid hosted API access" holds literally everywhere.
            _key_id, workspace_id, role = key
            sub = self.cp.subscription(workspace_id)
            if not self.cp.entitlements.has_feature(sub, Feature.API):
                raise ApiError(402, "API access is not included in this plan",
                               upgrade_to=self.cp.entitlements.upgrade_target(sub))
            self._json(200, {"workspace_id": workspace_id, "role": role.value})
        elif kind == "device_session":
            device = key
            role = self.cp.store.get_role(device.workspace_id, uid)
            if role is None:
                raise ApiError(401, "device access is no longer authorized",
                               code="invalid_grant")
            self._json(200, {
                "principal": "device_session",
                "device_id": device.device_id,
                "workspace_id": device.workspace_id,
                "role": role.value,
                "capabilities": list(DEVICE_CAPABILITIES),
            })
        else:
            raise ApiError(401, "authentication required")

    # --- workspace endpoints (all require()-guarded) ---
    def _ws_summary(self, wid: str):
        self._authorize(wid, "view")
        sub = self.cp.subscription(wid)
        plan = self.cp.entitlements.effective_plan(sub)
        self._json(200, {"workspace_id": wid, "plan": plan.id, "state": sub.state,
                         "catalog_version": sub.catalog_version})

    def _ws_entitlements(self, wid: str):
        self._authorize(wid, "view")
        sub = self.cp.subscription(wid)
        svc = self.cp.entitlements
        plan = svc.effective_plan(sub)
        from .catalog import Feature
        self._json(200, {
            "plan": plan.id,
            "features": {f.value: svc.feature_status(sub, f) for f in Feature},
            "quotas": {m.value: svc.quota(sub, m) for m in Meter}})

    def _ws_usage(self, wid: str):
        self._authorize(wid, "view")
        sub = self.cp.subscription(wid)
        period = current_period()
        svc = self.cp.entitlements
        self._json(200, {"period": period, "remaining": {
            m.value: svc.remaining(sub, m, period) for m in Meter}})

    @staticmethod
    def _project_payload(project) -> dict:
        return {
            "workspace_id": project.workspace_id,
            "project_ref": project.project_ref,
            "name": project.name,
            "created_by": project.created_by,
            "created_at": project.created_at,
        }

    def _ws_project_create(self, wid: str):
        principal = self._sync_principal(wid, "sync_findings")
        body = self._body()
        if set(body) != {"name"} or type(body.get("name")) is not str:
            raise ApiError(400, "a project name is required", code="invalid_project_request")
        try:
            project = self.cp.projects.create(
                wid,
                body["name"],
                created_by=principal.actor_ref,
            )
        except (ValueError, ProjectNotFound):
            raise ApiError(400, "invalid project request", code="invalid_project_request") from None
        self._json(201, self._project_payload(project))

    def _ws_projects_list(self, wid: str):
        self._authorize(wid, "view_synced_reviews")
        self._json(200, {
            "projects": [
                self._project_payload(project) for project in self.cp.projects.list(wid)
            ]
        })

    def _ws_project_namespace_key(self, wid: str, project_ref: str):
        self._sync_principal(wid, "sync_findings")
        try:
            namespace_key = self.cp.projects.namespace_key(wid, project_ref)
        except ProjectNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        self._json(200, {
            "project_ref": project_ref,
            "namespace_key_hex": namespace_key.hex(),
        })

    def _ws_findings_approve(self, wid: str, project_ref: str):
        principal = self._sync_principal(
            wid, "sync_findings", human_only=True,
        )
        content_types = self._header_values("Content-Type")
        content_encodings = self._header_values("Content-Encoding")
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
            or len(content_encodings) > 1
            or (
                content_encodings
                and content_encodings[0].strip().lower() not in ("", "identity")
            )
        ):
            raise ApiError(
                400,
                "invalid findings approval request",
                code="invalid_approval_request",
            )
        try:
            body = self._body()
        except ApiError:
            raise ApiError(
                400,
                "invalid findings approval request",
                code="invalid_approval_request",
            ) from None
        digest = body.get("request_digest")
        if (
            set(body) != {"request_digest"}
            or type(digest) is not str
            or _SYNC_DIGEST.fullmatch(digest) is None
        ):
            raise ApiError(
                400,
                "invalid findings approval request",
                code="invalid_approval_request",
            )
        now = time.time()
        try:
            approval = self.cp.findings.approve(
                wid,
                project_ref,
                digest,
                principal=principal,
                now=now,
                expires_at=now + 600,
            )
        except ProjectNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        self._json(201, {
            "workspace_id": approval.workspace_id,
            "project_ref": approval.project_ref,
            "approval_id": approval.approval_id,
            "request_digest": approval.request_digest,
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at,
            "expires_at": approval.expires_at,
        })

    def _ws_findings_sync(self, wid: str, project_ref: str):
        principal = self._sync_principal(wid, "sync_findings")
        try:
            namespace_key = self.cp.projects.namespace_key(wid, project_ref)
        except ProjectNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        request = self._findings_sync_body(namespace_key)
        idempotency_keys = self._header_values("Idempotency-Key")
        if not idempotency_keys or not idempotency_keys[0]:
            raise ApiError(
                400,
                "an Idempotency-Key is required",
                code="idempotency_key_required",
            )
        if len(idempotency_keys) != 1:
            raise ApiError(
                400,
                "Idempotency-Key is ambiguous",
                code="ambiguous_request_headers",
            )
        idempotency_key = idempotency_keys[0]
        try:
            receipt = self.cp.findings.accept(
                wid,
                project_ref,
                request,
                principal=principal,
                idempotency_key=idempotency_key,
            )
        except ApprovalRequired:
            raise ApiError(
                403,
                "explicit findings sync approval is required",
                code="approval_required",
            ) from None
        except ApprovalExpired:
            raise ApiError(
                403,
                "findings sync approval expired",
                code="approval_expired",
            ) from None
        except FindingsSyncConflict as error:
            message = str(error)
            if "request project does not match" in message:
                code = "project_ref_mismatch"
            elif "idempotency key does not match" in message:
                code = "idempotency_key_mismatch"
            else:
                code = "findings_sync_conflict"
            raise ApiError(409, "findings sync conflict", code=code) from None
        except QuotaExceeded as error:
            sub = self.cp.subscription(wid)
            raise ApiError(
                402,
                "synced review quota exceeded",
                code="quota_exceeded",
                meter=error.meter.value,
                upgrade_to=self.cp.entitlements.upgrade_target(sub),
            ) from None
        self._json(201, receipt)

    def _ws_findings_reviews(self, wid: str, project_ref: str):
        self._authorize(wid, "view_synced_reviews")
        try:
            reviews = self.cp.findings.list_reviews(wid, project_ref)
        except ProjectNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        self._json(200, {"reviews": reviews})

    def _ws_findings_review(self, wid: str, project_ref: str, synced_review_id: str):
        self._authorize(wid, "view_synced_reviews")
        try:
            review = self.cp.findings.get_review(wid, project_ref, synced_review_id)
        except ProjectNotFound:
            raise ApiError(404, "review not found", code="review_not_found") from None
        self._json(200, review)

    def _seat_limit_reached(self, wid: str) -> bool:
        sub = self.cp.subscription(wid)
        limit = self.cp.entitlements.quota(sub, Meter.SEATS)
        return limit >= 0 and len(self.cp.store.members(wid)) >= limit

    def _ws_invite(self, wid: str):
        self._authorize(wid, "manage_members")
        if self._seat_limit_reached(wid):
            self._json(402, {"error": "seat limit reached", "upgrade_to":
                             self.cp.entitlements.upgrade_target(self.cp.subscription(wid))})
            return
        b = self._body()
        try:
            role = Role(str(b.get("role", "")))
        except ValueError:
            raise ApiError(400, "invalid role")
        if role is Role.OWNER:
            raise ApiError(400, "cannot invite as owner")
        email = str(b.get("email", "")).strip()
        if "@" not in email:
            raise ApiError(400, "valid email required")
        token = self.cp.store.create_invite(wid, email, role)
        # v1: token returned to the inviter to deliver; lifecycle email lands in Phase 6.
        self._json(201, {"invite_token": token})

    def _ws_invite_accept(self, wid: str):
        kind, uid, _ = self._principal()
        if kind != "session":
            raise ApiError(401, "sign in to accept an invite")
        token = str(self._body().get("token", ""))
        # Seat quota is enforced atomically inside accept_invite (count + insert in one write
        # transaction), so concurrent accepts cannot race past the limit. The token is checked
        # first inside the same transaction, so invalid tokens learn nothing about quota state.
        sub = self.cp.subscription(wid)
        limit = self.cp.entitlements.quota(sub, Meter.SEATS)
        try:
            role = self.cp.store.accept_invite(
                wid, token, uid, max_seats=None if limit < 0 else limit)
        except SeatLimitExceeded:
            raise ApiError(402, "seat limit reached; ask an admin to upgrade the plan",
                           upgrade_to=self.cp.entitlements.upgrade_target(sub))
        self._json(200, {"workspace_id": wid, "role": role.value})

    def _ws_key_create(self, wid: str):
        self._authorize(wid, "manage_api_keys")
        sub = self.cp.subscription(wid)
        if not self.cp.entitlements.has_feature(sub, Feature.API):
            self._json(402, {"error": "API access is not included in this plan",
                             "upgrade_to": self.cp.entitlements.upgrade_target(sub)})
            return
        b = self._body()
        try:
            role = Role(str(b.get("role", "viewer")))
        except ValueError:
            raise ApiError(400, "invalid role")
        if role in (Role.OWNER, Role.ADMIN):
            raise ApiError(400, "API keys may not carry owner/admin roles")
        # The INTEGRATIONS meter's enforcement consumer: active API keys count against it,
        # enforced atomically inside issue_api_key (count + insert in one write transaction).
        limit = self.cp.entitlements.quota(sub, Meter.INTEGRATIONS)
        try:
            issued = self.cp.store.issue_api_key(
                wid, role, str(b.get("name", "")), max_active=None if limit < 0 else limit)
        except IntegrationLimitExceeded:
            self._json(402, {"error": "integration (API key) limit reached",
                             "upgrade_to": self.cp.entitlements.upgrade_target(sub)})
            return
        self._json(201, {"key_id": issued.key_id, "secret": issued.secret,
                         "note": "store this secret now; it is not retrievable again"})

    def _ws_key_revoke(self, wid: str, key_id: str):
        self._authorize(wid, "manage_api_keys")
        row = self.cp.store.conn.execute(
            "SELECT workspace_id FROM api_keys WHERE key_id=?", (key_id,)).fetchone()
        if not row or row["workspace_id"] != wid:
            raise ApiError(404, "key not found")
        self.cp.store.revoke_api_key(key_id)
        self._json(200, {"ok": True})

    def _ws_scope_mint(self, wid: str):
        """The human-only hosted scope path. Session principals with `create_scope`
        (owner/admin) only — API keys are rejected in _authorize by construction. Requires a
        currently verified target, a step-up confirmation (retype the exact target), and a
        reason that lands in the append-only admin audit. Delegates the actual scope material
        to the engine's injected minter; fails closed (501) when none is configured."""
        self._authorize(wid, "create_scope")
        b = self._body()
        target = str(b.get("target", "")).strip().lower()
        confirm = str(b.get("confirm_target", "")).strip().lower()
        reason = str(b.get("reason", "")).strip()
        if not target or confirm != target:
            raise ApiError(400, "confirm_target must repeat the exact target (step-up confirmation)")
        if not reason:
            raise ApiError(400, "a reason is required; it is recorded in the admin audit log")
        if not self.cp.verifier.is_verified(wid, target):
            raise ApiError(403, "target is not verified for this workspace")
        if self.cp.scope_minter is None:
            raise ApiError(501, "scope minting is not configured in this deployment; mint via "
                                "the engine's human-only path and pass scope_ref to /runs")
        _, user_id, _ = self._principal()
        scope_ref = self.cp.scope_minter(wid, target, user_id)
        self.cp.ops.record(user_id or "unknown", "scope_mint", f"{wid}:{target}", reason)
        self._json(201, {"scope_ref": scope_ref, "target": target})

    def _ws_run(self, wid: str):
        self._authorize(wid, "run_rehearsal")
        b = self._body()
        verified = bool(b.get("verified", False))
        target = str(b.get("target", "")).strip().lower() or None
        sub = self.cp.subscription(wid)
        period = current_period()
        idem = str(b.get("idempotency_key")) if b.get("idempotency_key") else None
        self.cp.ops.check(wid)   # kill switch: deny new spend at enqueue
        if verified and (not target or not self.cp.verifier.is_verified(wid, target)):
            raise ApiError(403, "target is not verified for this workspace")
        try:
            resv = self.cp.entitlements.reserve_run(sub, period, verified=verified,
                                                    idempotency_key=idem)
        except QuotaExceeded as e:
            self.cp.metrics.inc("quota_exceeded_total")
            self._json(402, {"error": "quota exceeded", "meter": e.meter.value,
                             "upgrade_to": self.cp.entitlements.upgrade_target(sub)})
            return
        rids = [r.reservation_id for r in resv]
        try:
            job = self.cp.jobs.enqueue(
                wid, kind="verified" if verified else "synthetic", reservation_ids=rids,
                target=target if verified else None, target_is_verified=verified,
                scope_ref=str(b.get("scope_ref", "")) or None,
                idempotency_key=idem)
        except PermissionError as e:
            for rid in rids:
                self.cp.ledger.refund(rid)
            raise ApiError(403, str(e))
        if job.state != "queued":
            # Idempotent replay of an already-processed request: report the existing job.
            self._json(202, {"status": job.state, "job_id": job.job_id, "period": period})
            return
        self.cp.metrics.inc("runs_enqueued_total")
        self._json(202, {"status": "queued", "job_id": job.job_id, "period": period})

    def _ws_job_get(self, wid: str, job_id: str):
        self._authorize(wid, "view")
        job = self.cp.jobs.get(wid, job_id)
        if job is None:
            raise ApiError(404, "job not found")
        self._json(200, {"job_id": job.job_id, "kind": job.kind, "state": job.state,
                         "target": job.target})

    def _ws_target_start(self, wid: str):
        self._authorize(wid, "manage_targets")
        hostname = str(self._body().get("hostname", ""))
        if self.cp.target_quota_blocked(wid):
            self._json(402, {"error": "verified target limit reached", "upgrade_to":
                             self.cp.entitlements.upgrade_target(self.cp.subscription(wid))})
            return
        try:
            ch = self.cp.verifier.start(wid, hostname)
        except ValueError as e:
            raise ApiError(400, str(e))
        self._json(201, {"target_id": ch.target_id, "hostname": ch.hostname,
                         "token": ch.token, "dns_record": ch.dns_record,
                         "http_url": ch.http_url})

    def _ws_target_check(self, wid: str):
        self._authorize(wid, "manage_targets")
        hostname = str(self._body().get("hostname", ""))
        # Quota is enforced atomically inside the verifier (count + verify in one write
        # transaction), so concurrent checks cannot race past the plan limit.
        sub = self.cp.subscription(wid)
        limit = self.cp.entitlements.quota(sub, Meter.VERIFIED_TARGETS)
        try:
            ok = self.cp.verifier.check(wid, hostname,
                                        max_verified=None if limit < 0 else limit)
        except TargetLimitExceeded:
            raise ApiError(402, "verified target limit reached",
                           upgrade_to=self.cp.entitlements.upgrade_target(sub))
        self._json(200, {"verified": ok})

    def _recent_owner_admin_context(self, wid: str) -> tuple[str, str, int]:
        """Resolve one fresh same-origin browser owner/admin ceremony."""
        if (self.cp.public_origin is None
                or self.headers.get("Origin") != self.cp.public_origin
                or self.headers.get("X-Heel-Internal-Origin") != "same-origin"):
            raise ApiError(403, "same-origin browser ceremony is required", code="same_origin_required")
        kind, user_id, _ = self._principal()
        if kind != "session" or user_id is None:
            raise ApiError(403, "a recent owner or admin browser session is required", code="recent_auth_required")
        cookie = self._header_values("Cookie")[0] if self._header_values("Cookie") else ""
        token = next((value for part in cookie.split(";") for key, _, value in [part.strip().partition("=")]
                      if key == "heel_session"), "")
        session = self.cp.store.conn.execute(
            "SELECT created_at FROM sessions WHERE token_hash=? AND revoked_at IS NULL", (hash_api_key(token),)
        ).fetchone()
        role = self.cp.store.get_role(wid, user_id)
        if (session is None or time.time() - session["created_at"] > 15 * 60
                or role not in {Role.OWNER, Role.ADMIN}):
            raise ApiError(403, "a recent owner or admin browser session is required", code="recent_auth_required")
        return user_id, role.value, int(float(session["created_at"]) * 1000)

    def _recent_owner_admin(self, wid: str) -> str:
        """Sensitive proof actions require a fresh browser session, never a key/device token."""
        return self._recent_owner_admin_context(wid)[0]

    def _ws_canary_projection_submit(self, wid: str, project_ref: str) -> None:
        actor, _, _ = self._recent_owner_admin_context(wid)
        runs, _ = self._human_canary_services()
        projection = self._body()
        if (
            projection.get("workspace_id") != wid
            or projection.get("project_id") != project_ref
        ):
            raise CanaryRunError("invalid_canary_projection")
        try:
            result = runs.submit_projection(projection, uploaded_by=actor)
        except LookupError:
            raise CanaryRunError("canary_authority_unavailable") from None
        self._json(201, result)

    def _ws_canary_approval_requests(self, wid: str, project_ref: str) -> None:
        if ("?" in self.path or "#" in self.path or "%" in self.path
                or self._header_values("Content-Length") or self._header_values("Transfer-Encoding")
                or self._header_values("Content-Encoding")):
            raise ApiError(404, "project not found", code="project_not_found")
        kind, actor, _ = self._principal()
        if kind == "anon" or actor is None:
            raise ApiError(401, "authentication required")
        if kind != "session":
            raise ApiError(404, "project not found", code="project_not_found")
        runs, _ = self._human_canary_services()
        try:
            result = runs.list_pending_approval_requests(wid, project_ref, actor)
        except LookupError:
            raise ApiError(404, "project not found", code="project_not_found") from None
        self._json(200, result)

    def _runner_context_service(self) -> RunnerContextBindingService:
        if self.cp.runner_contexts is None:
            raise RunnerContextError("canary_authority_unavailable")
        return self.cp.runner_contexts

    def _ws_runner_context_create(self, wid: str, project_ref: str) -> None:
        try:
            self._runner_context_human_path_exact()
            self._runner_context_human_scope(wid, project_ref)
            actor, role, _ = self._recent_owner_admin_context(wid)
            body = parse_json(self._raw_body(), max_bytes=2048)
            if canonical_bytes(body) != self._raw_body():
                raise ValueError
            binding = self._runner_context_service().create(wid, project_ref, body, actor=actor, role=role)
        except RunnerContextError:
            raise
        except ApiError as error:
            if error.body.get("code") in {"same_origin_required", "recent_auth_required"}:
                raise RunnerContextError(error.body["code"]) from None
            raise
        except (TypeError, ValueError):
            raise RunnerContextError("invalid_runner_context_binding") from None
        self._json(201, {"schema_version": "heel.runner-context-binding-created.v1", "context_binding": binding})

    def _ws_runner_context_revoke(self, wid: str, project_ref: str, binding_id: str) -> None:
        try:
            self._runner_context_human_path_exact()
            self._runner_context_human_scope(wid, project_ref)
            actor, role, _ = self._recent_owner_admin_context(wid)
            body = parse_json(self._raw_body(), max_bytes=256)
            if canonical_bytes(body) != self._raw_body():
                raise ValueError
            result = self._runner_context_service().revoke(wid, project_ref, binding_id, actor=actor, role=role, request=body)
        except RunnerContextError:
            raise
        except ApiError as error:
            if error.body.get("code") in {"same_origin_required", "recent_auth_required"}:
                raise RunnerContextError(error.body["code"]) from None
            raise
        except (TypeError, ValueError):
            raise RunnerContextError("invalid_runner_context_binding") from None
        self._json(200, result)

    def _ws_runner_context_list(self, wid: str, project_ref: str) -> None:
        self._runner_context_human_path_exact()
        kind, user_id, _ = self._principal()
        if kind != "session" or user_id is None:
            raise RunnerContextError("runner_context_binding_not_found")
        self._json(200, self._runner_context_service().list_for_human(wid, project_ref, actor=user_id))

    def _runner_context_human_path_exact(self) -> None:
        if "?" in self.path or "#" in self.path or "%" in self.path:
            raise RunnerContextError("runner_context_binding_not_found")

    def _runner_context_human_scope(self, wid: str, project_ref: str) -> None:
        """Hide foreign/missing project identifiers before sensitive session ceremonies."""
        kind, user_id, _ = self._principal()
        if kind == "session" and user_id is not None:
            if (self.cp.store.get_role(wid, user_id) is None or self.cp.store.conn.execute(
                "SELECT 1 FROM projects WHERE workspace_id=? AND project_ref=?", (wid, project_ref),
            ).fetchone() is None):
                raise RunnerContextError("runner_context_binding_not_found")

    def _ws_canary_approve(self, wid: str, project_ref: str, run_id: str) -> None:
        actor, role, recent_auth_at_ms = self._recent_owner_admin_context(wid)
        runs, _ = self._human_canary_services()
        body = self._body()
        if (
            set(body) != {
                "schema_version", "projection_digest", "hostname_retype", "reason",
            }
            or body.get("schema_version") != "heel.canary-execution-approval.v1"
            or not all(type(body.get(name)) is str for name in (
                "projection_digest", "hostname_retype", "reason",
            ))
        ):
            raise CanaryRunError("invalid_canary_approval")
        idempotency = self._header_values("Idempotency-Key")
        if len(idempotency) != 1 or _CANARY_IDEMPOTENCY.fullmatch(idempotency[0]) is None:
            raise CanaryRunError("invalid_canary_approval")
        result = runs.approve(
            wid,
            project_ref,
            run_id,
            projection_digest=body["projection_digest"],
            actor=actor,
            role=role,
            reason=body["reason"],
            exact_hostname=body["hostname_retype"],
            recent_auth_at_ms=recent_auth_at_ms,
            idempotency_key=idempotency[0],
            expected_kill_switch_generation=self._expected_control_generation(),
        )
        self._json(201, result)

    def _ws_canary_status(self, wid: str, project_ref: str, run_id: str) -> None:
        self._authorize(wid, "view")
        runs, _ = self._human_canary_services()
        try:
            result = runs.get_status(wid, project_ref, run_id)
        except LookupError:
            raise CanaryDisclosureError("canary_run_not_found") from None
        approval_generation = (
            runs._control_generation()
            if result["status"] == "awaiting_execution_approval"
            else int(result["kill_switch_generation"])
        )
        self._json(200, {
            "schema_version": "heel.canary-run-dashboard.v1",
            "approval_control_generation": approval_generation,
            "run": result,
            "progress": self._canary_dashboard_progress(wid, project_ref, run_id),
        })

    @staticmethod
    def _unavailable_canary_progress() -> dict[str, object]:
        return {
            "schema_version": "heel.canary-run-progress.v1",
            "available": False,
            "current_scenario_id": None,
            "scenarios_completed": None,
            "scenarios_total": None,
            "requests_started": None,
            "requests_completed": None,
            "remaining_requests": None,
            "remaining_wall_ms": None,
            "retries_used": None,
            "redaction_count": None,
            "local_result_ready": False,
        }

    @staticmethod
    def _verified_stored_canary_contract(serialized: object, validator) -> dict:
        if type(serialized) is not str:
            raise ValueError("invalid stored canary contract")
        parsed = parse_json(serialized.encode("utf-8"), max_bytes=64 * 1024)
        value = validator(parsed)
        if canonical_bytes(value).decode("utf-8") != serialized:
            raise ValueError("noncanonical stored canary contract")
        return value

    @staticmethod
    def _verify_stored_runner_signature(value: dict, public_key: str) -> None:
        payload = {
            key: item for key, item in value.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        verify_envelope(
            {value["signing_key_id"]: load_public_key_base64(public_key)},
            {
                "signing_key_id": value["signing_key_id"],
                "signature_b64": value["signature_b64"],
            },
            canonical_bytes(payload),
        )

    def _canary_dashboard_progress(
        self, wid: str, project_ref: str, run_id: str,
    ) -> dict[str, object]:
        unavailable = self._unavailable_canary_progress()
        row = self.cp.store.conn.execute(
            "SELECT r.status,r.grant_id,r.runner_id,r.runner_key_id,"
            "a.projection_json,a.projection_digest AS approval_digest,a.manifest_digest,"
            "g.grant_digest,o.receipt_json,o.receipt_digest,k.public_key "
            "FROM canary_runs r JOIN canary_approval_projections a ON "
            "a.workspace_id=r.workspace_id AND a.project_ref=r.project_ref "
            "AND a.approval_id=r.approval_id JOIN canary_execution_grants g ON "
            "g.workspace_id=r.workspace_id AND g.project_ref=r.project_ref "
            "AND g.grant_id=r.grant_id JOIN canary_runner_keys k ON "
            "k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id "
            "AND k.key_id=r.runner_key_id LEFT JOIN canary_operational_receipts o ON "
            "o.workspace_id=r.workspace_id AND o.project_ref=r.project_ref "
            "AND o.run_id=r.run_id WHERE r.workspace_id=? AND r.project_ref=? AND r.run_id=?",
            (wid, project_ref, run_id),
        ).fetchone()
        if row is None:
            return unavailable
        try:
            approval = self._verified_stored_canary_contract(
                row["projection_json"], validate_approval_projection,
            )
            self._verify_stored_runner_signature(approval, row["public_key"])
            if (
                approval["workspace_id"] != wid
                or approval["project_id"] != project_ref
                or approval["runner"]["runner_id"] != row["runner_id"]
                or approval["runner"]["runner_key_id"] != row["runner_key_id"]
                or approval["projection_digest"] != row["approval_digest"]
                or approval["manifest_digest"] != row["manifest_digest"]
            ):
                raise ValueError("stored canary approval binding mismatch")
            scenarios = approval["scenarios"]
            maximum_requests = approval["budgets"]["maximum_requests"]
            maximum_wall_ms = approval["budgets"]["wall_timeout_ms"]
            progress = {
                "schema_version": "heel.canary-run-progress.v1",
                "available": True,
                "current_scenario_id": None,
                "scenarios_completed": 0,
                "scenarios_total": len(scenarios),
                "requests_started": 0,
                "requests_completed": 0,
                "remaining_requests": maximum_requests,
                "remaining_wall_ms": maximum_wall_ms,
                "retries_used": 0,
                "redaction_count": 0,
                "local_result_ready": False,
            }
            if row["receipt_json"] is None:
                return progress
            receipt = self._verified_stored_canary_contract(
                row["receipt_json"], validate_operational_run,
            )
            self._verify_stored_runner_signature(receipt, row["public_key"])
            if (
                receipt["workspace_id"] != wid
                or receipt["project_id"] != project_ref
                or receipt["run_id"] != run_id
                or receipt["grant_id"] != row["grant_id"]
                or receipt["signing_key_id"] != row["runner_key_id"]
                or receipt["approval_projection_digest"] != row["approval_digest"]
                or receipt["manifest_digest"] != row["manifest_digest"]
                or receipt["grant_digest"] != row["grant_digest"]
                or receipt["projection_digest"] != row["receipt_digest"]
            ):
                raise ValueError("stored canary receipt binding mismatch")
            counters = receipt["counters"]
            completed = min(len(scenarios), counters["actions_contained"] // 2)
            current = None
            if receipt["lifecycle_phase"] != "terminal" and completed < len(scenarios):
                current = scenarios[completed]["scenario_id"]
            progress.update({
                "current_scenario_id": current,
                "scenarios_completed": completed,
                "requests_started": counters["requests_started"],
                "requests_completed": counters["requests_completed"],
                "remaining_requests": counters["remaining_requests"],
                "remaining_wall_ms": counters["remaining_wall_ms"],
                "retries_used": counters["retries_used"],
                "redaction_count": receipt["redaction_count"],
                "local_result_ready": bool(
                    row["status"] == "terminal"
                    and receipt["lifecycle_phase"] == "terminal"
                ),
            })
            return progress
        except (KeyError, TypeError, ValueError):
            return unavailable

    def _ws_canary_events(self, wid: str, project_ref: str, run_id: str) -> None:
        self._authorize(wid, "view")
        runs, _ = self._human_canary_services()
        try:
            events = runs.list_events(wid, project_ref, run_id)
        except LookupError:
            raise CanaryDisclosureError("canary_run_not_found") from None
        self._json(200, {
            "schema_version": "heel.canary-run-events.v1",
            "run_id": run_id,
            "events": events,
        })

    def _ws_canary_stop(self, wid: str, project_ref: str, run_id: str) -> None:
        actor, _, _ = self._recent_owner_admin_context(wid)
        runs, _ = self._human_canary_services()
        body = self._body()
        if set(body) != {"schema_version", "reason_code"} or body != {
            "schema_version": "heel.canary-stop-request.v1",
            "reason_code": "operator_requested",
        }:
            raise CanaryRunError("canary_state_conflict")
        try:
            result = runs.request_stop(
                wid,
                project_ref,
                run_id,
                actor=actor,
                reason="cloud_stop",
                expected_kill_switch_generation=self._expected_control_generation(),
            )
        except LookupError:
            raise CanaryDisclosureError("canary_run_not_found") from None
        self._json(200, result)

    @staticmethod
    def _disclosure_metadata(body: dict, schema: str) -> tuple[str, int, int, int]:
        if (
            set(body) != {
                "schema_version", "projection_digest", "projection_bytes",
                "scenario_count", "finding_count",
            }
            or body.get("schema_version") != schema
            or type(body.get("projection_digest")) is not str
            or type(body.get("projection_bytes")) is not int
            or isinstance(body.get("projection_bytes"), bool)
            or type(body.get("scenario_count")) is not int
            or isinstance(body.get("scenario_count"), bool)
            or type(body.get("finding_count")) is not int
            or isinstance(body.get("finding_count"), bool)
        ):
            raise CanaryDisclosureError("invalid_canary_projection")
        return (
            body["projection_digest"], body["projection_bytes"],
            body["scenario_count"], body["finding_count"],
        )

    def _canary_run_binding(self, wid: str, project_ref: str, run_id: str) -> sqlite3.Row:
        row = self.cp.store.conn.execute(
            "SELECT runner_id,runner_key_id FROM canary_runs WHERE workspace_id=? "
            "AND project_ref=? AND run_id=?",
            (wid, project_ref, run_id),
        ).fetchone()
        if row is None:
            raise CanaryDisclosureError("canary_run_not_found")
        return row

    def _ws_canary_disclosure_permit(
        self, wid: str, project_ref: str, run_id: str,
    ) -> None:
        actor, role, recent_auth_at_ms = self._recent_owner_admin_context(wid)
        _, disclosure = self._human_canary_services()
        digest, byte_count, scenario_count, finding_count = self._disclosure_metadata(
            self._body(), "heel.canary-disclosure-request.v1",
        )
        binding = self._canary_run_binding(wid, project_ref, run_id)
        preview = disclosure.preview(
            wid,
            project_ref,
            run_id,
            runner_id=binding["runner_id"],
            runner_key_id=binding["runner_key_id"],
            projection_schema_version=CANARY_FINDINGS_SCHEMA,
            projection_digest=digest,
            byte_count=byte_count,
            scenario_count=scenario_count,
            finding_count=finding_count,
        )
        result = disclosure.permit(
            wid,
            project_ref,
            run_id,
            request_id=preview["request_id"],
            projection_schema_version=CANARY_FINDINGS_SCHEMA,
            projection_digest=digest,
            byte_count=byte_count,
            scenario_count=scenario_count,
            finding_count=finding_count,
            actor=actor,
            role=role,
            recent_auth_at_ms=recent_auth_at_ms,
        )
        self._json(201, result)

    def _ws_canary_disclosure_local_only(
        self, wid: str, project_ref: str, run_id: str,
    ) -> None:
        actor, _, _ = self._recent_owner_admin_context(wid)
        _, disclosure = self._human_canary_services()
        digest, byte_count, scenario_count, finding_count = self._disclosure_metadata(
            self._body(), "heel.canary-disclosure-local-only.v1",
        )
        binding = self._canary_run_binding(wid, project_ref, run_id)
        preview = disclosure.preview(
            wid,
            project_ref,
            run_id,
            runner_id=binding["runner_id"],
            runner_key_id=binding["runner_key_id"],
            projection_schema_version=CANARY_FINDINGS_SCHEMA,
            projection_digest=digest,
            byte_count=byte_count,
            scenario_count=scenario_count,
            finding_count=finding_count,
        )
        result = disclosure.local_only(
            wid, project_ref, run_id, request_id=preview["request_id"], actor=actor,
        )
        self._json(200, result)

    def _ws_canary_findings(self, wid: str, project_ref: str, run_id: str) -> None:
        self._authorize(wid, "view")
        _, disclosure = self._human_canary_services()
        self._json(200, disclosure.get(wid, project_ref, run_id))

    def _ws_environments_list(self, wid: str, project_ref: str):
        self._authorize(wid, "view")
        try:
            self.cp.projects.get(wid, project_ref)
        except ProjectNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        records = self.cp.environments.list(wid, project_ref)
        for record in records:
            record["is_executable"] = self.cp.environments.is_executable(wid, project_ref, record["environment_id"])
        self._json(200, {"schema_version": "heel.verified-environment-list.v1", "environments": records})

    def _ws_environment_start(self, wid: str, project_ref: str):
        actor = self._recent_owner_admin(wid)
        body = self._body()
        if set(body) != {"schema_version", "origin", "environment_class", "proof_method", "attestation_text", "attestation_version", "attestation_acknowledgement"}:
            raise ApiError(400, "invalid verified environment request", code="invalid_environment_request")
        if body.get("schema_version") != "heel.verified-environment-start.v1":
            raise ApiError(400, "invalid verified environment request", code="invalid_environment_request")
        if not all(type(body.get(key)) is str for key in ("origin", "environment_class", "proof_method", "attestation_text", "attestation_version", "attestation_acknowledgement")):
            raise ApiError(400, "invalid verified environment request", code="invalid_environment_request")
        try:
            challenge = self.cp.environments.start(
                wid, project_ref, body["origin"], body["environment_class"], actor=actor,
                proof_method=body["proof_method"], attestation_text=body["attestation_text"],
                attestation_version=body["attestation_version"],
                attestation_acknowledgement=body["attestation_acknowledgement"],
            )
        except EnvironmentNotFound:
            raise ApiError(404, "project not found", code="project_not_found") from None
        except ValueError:
            raise ApiError(400, "invalid verified environment request", code="invalid_environment_request") from None
        self._json(201, {
            "schema_version": "heel.verified-environment-challenge.v1",
            "environment_id": challenge.environment_id, "origin": challenge.origin,
            "environment_class": challenge.environment_class, "proof_method": body["proof_method"],
            "token": challenge.token, "http_url": challenge.http_url,
            "dns_record": "_heel." + challenge.origin[len("https://"):] + " TXT heel-verify=" + challenge.token,
            "challenge_generation": challenge.generation, "expires_at": challenge.expires_at,
            "attestation": challenge.attestation,
        })

    def _ws_environment_check(self, wid: str, project_ref: str, environment_id: str):
        # Dispatch releases the global lock for this endpoint; retain it for all auth and
        # SQLite reads, while the service releases it only during bounded proof I/O.
        with self.cp.request_lock:
            self._recent_owner_admin(wid)
            body = self._body()
            if set(body) != {"schema_version"} or body.get("schema_version") != "heel.verified-environment-check.v1":
                raise ApiError(400, "invalid verified environment check", code="invalid_environment_check")
            try:
                self.cp.projects.get(wid, project_ref)
                sub = self.cp.subscription(wid)
                limit = self.cp.entitlements.quota(sub, Meter.VERIFIED_TARGETS)
            except ProjectNotFound:
                raise ApiError(404, "project not found", code="project_not_found") from None
        try:
            verified = self.cp.environments.check(wid, project_ref, environment_id,
                                                   max_verified=None if limit < 0 else limit)
        except EnvironmentNotFound:
            raise ApiError(404, "environment not found", code="environment_not_found") from None
        except EnvironmentCooldown:
            raise ApiError(429, "environment check is cooling down", code="environment_check_cooldown") from None
        except TargetLimitExceeded:
            raise ApiError(402, "verified environment limit reached", code="quota_exceeded",
                           upgrade_to=self.cp.entitlements.upgrade_target(sub)) from None
        self._json(200, {"schema_version": "heel.verified-environment-check-result.v1", "verified": verified})

    def _ws_environment_revoke(self, wid: str, project_ref: str, environment_id: str):
        actor = self._recent_owner_admin(wid)
        body = self._body()
        reason = body.get("reason")
        if (set(body) != {"schema_version", "reason"} or body.get("schema_version") != "heel.verified-environment-revoke.v1"
                or type(reason) is not str or not reason.strip() or len(reason) > 512):
            raise ApiError(400, "invalid verified environment revocation", code="invalid_environment_revoke")
        try:
            revoked = self.cp.environments.revoke(wid, project_ref, environment_id, actor=actor, reason=reason.strip())
        except EnvironmentNotFound:
            raise ApiError(404, "environment not found", code="environment_not_found") from None
        if not revoked:
            raise ApiError(404, "environment not found", code="environment_not_found")
        self._json(200, {"schema_version": "heel.verified-environment-revoke-result.v1", "revoked": True})

    def _ws_checkout(self, wid: str):
        self._authorize(wid, "manage_billing")
        b = self._body()
        plan_id = str(b.get("plan", ""))
        try:
            plan = get_plan(plan_id)
        except KeyError:
            raise ApiError(400, "unknown plan")
        if plan.id not in {pl.id for pl in self_serve_plans()} or plan.id == "free":
            raise ApiError(400, "plan is not self-serve purchasable")
        interval = str(b.get("interval", "month"))
        if interval not in ("month", "year"):
            raise ApiError(400, "interval must be month or year")
        try:
            checkout = self.cp.billing.create_checkout(wid, plan, interval)
        except BillingUnavailable:
            raise ApiError(503, "paid checkout is not configured") from None
        self._json(200, checkout)

    # --- billing webhook (signature-verified, no auth principal) ---
    def _webhook(self):
        from .billing import WebhookVerificationError, verify_webhook_signature
        payload = self._raw_body()
        # Fail CLOSED: a deployment without a webhook secret has no billing webhook at all.
        # Unsigned events must never be able to change a workspace's plan or entitlements.
        if not self.webhook_secret:
            raise ApiError(503, "billing webhook not configured (no signing secret)")
        header = self.headers.get("X-Heel-Billing-Signature", "")
        try:
            verify_webhook_signature(payload, header, self.webhook_secret)
        except WebhookVerificationError as e:
            raise ApiError(400, f"webhook signature invalid: {e}")
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise ApiError(400, "invalid JSON body")
        disposition = self.cp.subs.apply_event(event)
        # Keep the workspace's pinned plan in sync when the subscription changes it.
        sub = self.cp.billing_store.get(event.get("workspace_id", ""))
        if sub is not None and disposition == "applied":
            ws = self.cp.store.get_workspace(sub.workspace_id)
            if ws is not None and (ws["plan_id"] != sub.plan_id
                                   or ws["catalog_version"] != sub.catalog_version):
                # Sync plan AND the subscription's pinned catalog version, so the workspace
                # record never points grandfathering at the wrong catalog.
                self.cp.store.set_workspace_plan(sub.workspace_id, sub.plan_id,
                                                 sub.catalog_version)
        self._json(200, {"disposition": disposition})


def _session_cookie(token: str) -> str:
    # Secure is added by the TLS edge in production; HttpOnly+SameSite always.
    return f"heel_session={token}; HttpOnly; SameSite=Lax; Path=/"


class _ControlPlaneHTTPServer(ThreadingHTTPServer):
    """HTTP listener that owns the bound control plane after successful construction."""

    request_queue_size = 128

    def __init__(self, server_address, handler, cp: ControlPlane):
        self.control_plane = cp
        self._owns_control_plane = False
        self._close_callbacks = []
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._drain_condition = threading.Condition()
        self._active_requests = 0
        super().__init__(server_address, handler)
        self._owns_control_plane = True

    def add_close_callback(self, callback) -> None:
        self._close_callbacks.append(callback)

    def process_request(self, request, client_address) -> None:
        if self.control_plane.draining:
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 34\r\n\r\n"
                    b'{"error":"control plane draining"}'
                )
            finally:
                self.shutdown_request(request)
            return
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 32\r\n\r\n"
                    b'{"error":"server request limit"}'
                )
            finally:
                self.shutdown_request(request)
            return
        with self._drain_condition:
            self._active_requests += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._drain_condition:
                self._active_requests -= 1
                self._drain_condition.notify_all()
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._drain_condition:
                self._active_requests -= 1
                self._drain_condition.notify_all()
            self._request_slots.release()

    def wait_for_request_drain(self, timeout: float = REQUEST_DRAIN_TIMEOUT_SECONDS) -> bool:
        """Wait for already-accepted requests without admitting new work."""
        deadline = time.monotonic() + timeout
        with self._drain_condition:
            while self._active_requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drain_condition.wait(remaining)
            return True

    def server_close(self) -> None:
        self.control_plane.draining = True
        try:
            super().server_close()
            drained = self.wait_for_request_drain()
            if not drained:
                _LOGGER.error(json.dumps({
                    "active_requests": self._active_requests,
                    "event": "control_plane_drain_timeout",
                    "timeout_seconds": REQUEST_DRAIN_TIMEOUT_SECONDS,
                }, sort_keys=True, separators=(",", ":")))
        finally:
            if self._owns_control_plane:
                try:
                    try:
                        self.control_plane.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    except Exception:
                        pass
                    self.control_plane.close()
                finally:
                    self._owns_control_plane = False
            callbacks, self._close_callbacks = self._close_callbacks, []
            for callback in reversed(callbacks):
                callback()


def serve(cp: ControlPlane, host: str = "127.0.0.1", port: int = 0,
          *, webhook_secret: str | None = None) -> _ControlPlaneHTTPServer:
    """Create the server and transfer ``cp`` ownership to it.

    The caller drives ``serve_forever``/``shutdown``. ``server_close`` releases both the
    loopback listener and the control plane's shared database connection.
    """
    handler = type("Handler", (_Handler,), {"cp": cp, "webhook_secret": webhook_secret})
    return _ControlPlaneHTTPServer((host, port), handler, cp)
