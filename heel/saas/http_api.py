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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from heel.findings_sync import (
    MAX_FINDINGS_SYNC_BYTES,
    parse_findings_sync_request,
    stable_json,
)

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
from .verification import HostnameReuseExceeded, TargetLimitExceeded, TargetVerifier

MAX_BODY = 64 * 1024
MAX_DEVICE_BODY = 8 * 1024
REQUEST_IO_TIMEOUT_SECONDS = 10
REQUEST_BODY_TOTAL_DEADLINE_SECONDS = 10
MAX_CONCURRENT_REQUESTS = 64
REQUEST_DRAIN_TIMEOUT_SECONDS = 30

_LOGGER = logging.getLogger("heel.saas.control_plane")
_SYNC_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


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
                 grant_trusted_keys: dict[str, object] | None = None):
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
        self.store = ControlPlaneStore(path)
        conn = self.store.conn
        self.canary_store = CanaryStore(conn)
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
        self.draining = False
        self.required_schema_version: int | None = None
        # Every store shares one SQLite connection. Serialize complete HTTP request units so
        # transaction boundaries and authentication touches cannot interleave across handler
        # threads. A Postgres deployment replaces this with a per-request pooled connection.
        self.request_lock = threading.RLock()

    def close(self) -> None:
        """Release the shared database connection. Safe to call more than once."""
        self.store.conn.close()

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
        maximum = (
            MAX_FINDINGS_SYNC_BYTES
            if sync_path
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
            with self.cp.request_lock:
                self._route_serial(method)
        finally:
            self._defer_json_response = False
        pending = self._pending_json_response
        self._pending_json_response = None
        if pending is not None:
            self._write_json(*pending)

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
            }
            if (method, tail) in ws_routes:
                return ws_routes[(method, tail)]
            if method == "DELETE" and len(tail) == 2 and tail[0] == "api-keys":
                return lambda: self._ws_key_revoke(wid, tail[1])
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
        return None

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
