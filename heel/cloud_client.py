"""Strict, fixed-route client for Heel's findings-only cloud continuity surface."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .cloud_auth import DeviceCredentials
from .findings_sync import parse_findings_sync_receipt, parse_findings_sync_request, stable_json


MAX_CLOUD_RESPONSE_BYTES = 256 * 1024
DEVICE_CAPABILITIES = ("sync_findings", "view_synced_reviews")
_WORKSPACE = re.compile(r"ws_[0-9a-f]{16}\Z", flags=re.ASCII)
_PROJECT = re.compile(r"prj_[0-9a-f]{32}\Z", flags=re.ASCII)
_REVIEW = re.compile(r"synrev_[0-9a-f]{32}\Z", flags=re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", flags=re.ASCII)
_DEVICE_CODE = re.compile(r"heel_dev_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_USER_CODE = re.compile(r"[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\Z", flags=re.ASCII)
_DEVICE_ID = re.compile(r"dev_[0-9a-f]{32}\Z", flags=re.ASCII)
_ACCESS = re.compile(r"heel_at_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_REFRESH = re.compile(r"heel_rt_[A-Za-z0-9_-]{64}\Z", flags=re.ASCII)


class CloudClientError(RuntimeError):
    """Bounded public failure that never includes response or credential material."""

    def __init__(self, code: str, status: int = 0, *, interval: int | None = None):
        safe = code if code in {
            "auth_required", "invalid_request", "invalid_response", "invalid_grant",
            "authorization_pending", "access_denied", "expired_token", "slow_down",
            "approval_required", "approval_expired", "quota_exceeded", "conflict",
            "refresh_reuse_detected", "rate_limited", "temporarily_unavailable", "unavailable",
            "project_not_found", "review_not_found", "human_session_required",
        } else "unavailable"
        super().__init__(safe.replace("_", " "))
        self.code = safe
        self.status = status
        self.interval = interval


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class DeviceLogin:
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int
    device_verifier: str


@dataclass(frozen=True)
class DeviceLoginPoll:
    status: str
    expires_in: int | None = None
    interval: int | None = None


@dataclass(frozen=True)
class DeviceExchange:
    credentials: DeviceCredentials
    workspace_id: str
    capabilities: tuple[str, ...] = DEVICE_CAPABILITIES


@dataclass(frozen=True)
class CloudProject:
    workspace_ref: str
    project_ref: str
    name: str
    created_by: str
    created_at: float


@dataclass(frozen=True)
class CloudAccount:
    device_id: str
    workspace_ref: str
    role: str
    capabilities: tuple[str, ...] = DEVICE_CAPABILITIES


@dataclass(frozen=True)
class TransportApproval:
    workspace_ref: str
    project_ref: str
    approval_id: str
    request_digest: str
    approved_by: str
    approved_at: float
    expires_at: float


def _duplicate_free(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _reject_constant(_value):
    raise ValueError("non-finite JSON")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _exact(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CloudClientError("invalid_response", 502)
    return value


def _origin(value: str) -> str:
    if type(value) is not str or value != value.strip() or len(value) > 2048:
        raise ValueError("invalid cloud origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid cloud origin")
    hostname = parsed.hostname.lower()
    if parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("cloud origin must use HTTPS")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid cloud origin") from None
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (
        (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    ):
        host += f":{port}"
    return f"{parsed.scheme}://{host}"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class _UrllibTransport:
    def __init__(self):
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    def __call__(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None):
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=15)
        except HTTPError as error:
            response = error
        except (OSError, URLError):
            raise CloudClientError("unavailable") from None
        try:
            payload = response.read(MAX_CLOUD_RESPONSE_BYTES + 1)
            if len(payload) > MAX_CLOUD_RESPONSE_BYTES:
                raise CloudClientError("invalid_response", 502)
            return HttpResponse(response.status, dict(response.headers.items()), payload)
        finally:
            response.close()


class CloudClient:
    """No generic request escape hatch: every public method maps to one fixed route."""

    def __init__(
        self,
        cloud_base_url: str,
        credential_store,
        *,
        transport: Callable | None = None,
        now: Callable[[], float] = time.time,
    ):
        self.cloud_base_url = _origin(cloud_base_url)
        self.credential_store = credential_store
        if getattr(credential_store, "cloud_base_url", None) != self.cloud_base_url:
            raise ValueError("credential store is bound to a different cloud origin")
        self._transport = transport or _UrllibTransport()
        self._now = now
        self._access: DeviceCredentials | None = None

    def _url(self, path: str) -> str:
        if not self._route_allowed("GET", path) and not self._route_allowed("POST", path):
            raise CloudClientError("invalid_request")
        return self.cloud_base_url + "/api/control-plane" + path

    @staticmethod
    def _route_allowed(method: str, path: str) -> bool:
        if any(marker in path for marker in ("..", "%", "\\", "//", "?", "#")):
            return False
        fixed = {
            ("GET", "/v1/me"),
            ("POST", "/v1/device/start"),
            ("POST", "/v1/device/poll"),
            ("POST", "/v1/device/token"),
            ("POST", "/v1/device/refresh"),
            ("POST", "/v1/device/revoke"),
        }
        if (method, path) in fixed:
            return True
        workspace = r"ws_[0-9a-f]{16}"
        project = r"prj_[0-9a-f]{32}"
        review = r"synrev_[0-9a-f]{32}"
        patterns = {
            ("GET", rf"/v1/workspaces/{workspace}/projects"),
            ("GET", rf"/v1/workspaces/{workspace}/projects/{project}/namespace-key"),
            ("POST", rf"/v1/workspaces/{workspace}/projects/{project}/findings-sync/approve"),
            ("POST", rf"/v1/workspaces/{workspace}/projects/{project}/findings-sync"),
            ("GET", rf"/v1/workspaces/{workspace}/projects/{project}/reviews"),
            ("GET", rf"/v1/workspaces/{workspace}/projects/{project}/reviews/{review}"),
        }
        return any(candidate_method == method and re.fullmatch(pattern, path)
                   for candidate_method, pattern in patterns)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        *,
        access_token: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        if not self._route_allowed(method, path):
            raise CloudClientError("invalid_request")
        if extra_headers is not None:
            if set(extra_headers) != {"Idempotency-Key"} or not re.fullmatch(
                r"fs1-[0-9a-f]{64}", extra_headers["Idempotency-Key"]
            ) or not path.endswith("/findings-sync"):
                raise CloudClientError("invalid_request")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers.update({
                "Content-Type": "application/json",
                "Content-Encoding": "identity",
                "Content-Length": str(len(body)),
            })
        if access_token is not None:
            headers["Authorization"] = f"Bearer {access_token}"
        if extra_headers:
            headers.update(extra_headers)
        try:
            result = self._transport(method, self._url(path), headers, body)
        except CloudClientError:
            raise
        except Exception:
            raise CloudClientError("unavailable") from None
        if 300 <= result.status <= 399:
            raise CloudClientError("invalid_response", 502)
        if len(result.body) > MAX_CLOUD_RESPONSE_BYTES:
            raise CloudClientError("invalid_response", 502)
        return result

    @staticmethod
    def _json(result: HttpResponse) -> dict[str, Any]:
        content_type = next(
            (value for key, value in result.headers.items() if key.lower() == "content-type"), ""
        ).split(";", 1)[0].strip().lower()
        if content_type != "application/json" or len(result.body) > MAX_CLOUD_RESPONSE_BYTES:
            raise CloudClientError("invalid_response", 502)
        try:
            value = json.loads(
                result.body.decode("utf-8"),
                object_pairs_hook=_duplicate_free,
                parse_constant=_reject_constant,
            )
        except (ValueError, UnicodeError, json.JSONDecodeError):
            raise CloudClientError("invalid_response", 502) from None
        if type(value) is not dict:
            raise CloudClientError("invalid_response", 502)
        return value

    def _failure(self, result: HttpResponse) -> CloudClientError:
        try:
            value = self._json(result)
            code = value.get("code")
            if code == "slow_down":
                _exact(value, {"schema_version", "code", "interval"})
                interval = value.get("interval")
                if (
                    value.get("schema_version") != "heel.device-error.v1"
                    or type(interval) is not int
                    or not 5 <= interval <= 30
                ):
                    raise CloudClientError("invalid_response", 502)
                return CloudClientError("slow_down", result.status, interval=interval)
            if value.get("schema_version") == "heel.device-error.v1":
                _exact(value, {"schema_version", "code"})
            elif "error" in value:
                # Workspace endpoints have a separate, frozen public error union. The
                # human-readable server string is validated but never exposed by this client.
                standard = {
                    "invalid_grant", "project_not_found", "review_not_found",
                    "human_session_required", "approval_required", "approval_expired",
                    "idempotency_key_required", "idempotency_key_mismatch",
                    "project_ref_mismatch", "findings_sync_conflict",
                }
                if code in standard:
                    _exact(value, {"error", "code"})
                elif code == "quota_exceeded":
                    _exact(value, {"error", "code", "meter", "upgrade_to"})
                    if type(value["meter"]) is not str or type(value["upgrade_to"]) is not str:
                        raise CloudClientError("invalid_response", 502)
                else:
                    raise CloudClientError("invalid_response", 502)
                if type(value["error"]) is not str or not value["error"]:
                    raise CloudClientError("invalid_response", 502)
            else:
                raise CloudClientError("invalid_response", 502)
            if code not in {
                "auth_required", "invalid_grant", "authorization_pending", "access_denied",
                "expired_token", "refresh_reuse_detected", "rate_limited",
                "temporarily_unavailable", "approval_required", "approval_expired",
                "quota_exceeded", "project_not_found", "review_not_found",
                "human_session_required", "idempotency_key_required",
                "idempotency_key_mismatch", "project_ref_mismatch",
                "findings_sync_conflict", "invalid_request",
            }:
                raise CloudClientError("invalid_response", 502)
            return CloudClientError(code, result.status)
        except CloudClientError:
            raise
        except Exception:
            raise CloudClientError("invalid_response", 502) from None

    def start_device_login(self, device_name: str) -> DeviceLogin:
        if (
            type(device_name) is not str
            or not 1 <= len(device_name) <= 64
            or device_name != device_name.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in device_name)
        ):
            raise CloudClientError("invalid_request")
        verifier = "heel_dv_" + base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode().rstrip("=")
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")
        result = self._request("POST", "/v1/device/start", _canonical_json({
            "schema_version": "heel.device-start.v1",
            "client_id": "heel-agent",
            "device_name": device_name,
            "device_challenge": challenge,
        }))
        if result.status != 201:
            raise self._failure(result)
        value = _exact(self._json(result), {
            "schema_version", "device_code", "user_code", "verification_uri",
            "expires_in", "interval",
        })
        if (
            value["schema_version"] != "heel.device-start-response.v1"
            or type(value["device_code"]) is not str
            or _DEVICE_CODE.fullmatch(value["device_code"]) is None
            or type(value["user_code"]) is not str
            or _USER_CODE.fullmatch(value["user_code"]) is None
            or type(value["verification_uri"]) is not str
            or _origin(value["verification_uri"].removesuffix("/device")) != self.cloud_base_url
            or value["verification_uri"] != self.cloud_base_url + "/device"
            or type(value["expires_in"]) is not int or value["expires_in"] != 600
            or type(value["interval"]) is not int or value["interval"] != 5
        ):
            raise CloudClientError("invalid_response", 502)
        return DeviceLogin(
            value["device_code"], value["user_code"], value["verification_uri"],
            value["expires_in"], value["interval"], verifier,
        )

    def poll_device_login(self, login: DeviceLogin) -> DeviceLoginPoll:
        if type(login) is not DeviceLogin:
            raise CloudClientError("invalid_request")
        result = self._request("POST", "/v1/device/poll", _canonical_json({
            "schema_version": "heel.device-poll.v1",
            "device_code": login.device_code,
            "device_verifier": login.device_verifier,
        }))
        if result.status == 429:
            raise self._failure(result)
        if result.status != 200:
            raise self._failure(result)
        value = self._json(result)
        status = value.get("status")
        if status == "pending":
            _exact(value, {"schema_version", "status", "expires_in", "interval"})
            if (
                value["schema_version"] != "heel.device-poll-response.v1"
                or type(value["expires_in"]) is not int or not 0 <= value["expires_in"] <= 600
                or type(value["interval"]) is not int or not 5 <= value["interval"] <= 30
            ):
                raise CloudClientError("invalid_response", 502)
            return DeviceLoginPoll(status, value["expires_in"], value["interval"])
        _exact(value, {"schema_version", "status"})
        if value["schema_version"] != "heel.device-poll-response.v1" or status not in {
            "approved", "denied", "expired",
        }:
            raise CloudClientError("invalid_response", 502)
        return DeviceLoginPoll(status)

    def _parse_tokens(self, result: HttpResponse) -> DeviceExchange:
        value = _exact(self._json(result), {
            "schema_version", "token_type", "access_token", "expires_in", "refresh_token",
            "refresh_expires_in", "device_id", "workspace_id", "capabilities",
        })
        if (
            value["schema_version"] != "heel.device-token-response.v1"
            or value["token_type"] != "Bearer"
            or type(value["access_token"]) is not str or _ACCESS.fullmatch(value["access_token"]) is None
            or type(value["refresh_token"]) is not str or _REFRESH.fullmatch(value["refresh_token"]) is None
            or type(value["device_id"]) is not str or _DEVICE_ID.fullmatch(value["device_id"]) is None
            or type(value["workspace_id"]) is not str or _WORKSPACE.fullmatch(value["workspace_id"]) is None
            or value["capabilities"] != list(DEVICE_CAPABILITIES)
            or type(value["expires_in"]) is not int or value["expires_in"] != 900
            or type(value["refresh_expires_in"]) is not int
            or not 0 < value["refresh_expires_in"] <= 2_592_000
        ):
            raise CloudClientError("invalid_response", 502)
        instant = int(self._now())
        stored = DeviceCredentials(
            schema_version="heel.device-credentials.v1",
            cloud_base_url=self.cloud_base_url,
            device_id=value["device_id"],
            access_token=value["access_token"],
            access_expires_at=instant + value["expires_in"],
            refresh_token=value["refresh_token"],
            refresh_expires_at=instant + value["refresh_expires_in"],
        )
        return DeviceExchange(stored, value["workspace_id"])

    def exchange_device_login(self, login: DeviceLogin) -> DeviceExchange:
        result = self._request("POST", "/v1/device/token", _canonical_json({
            "schema_version": "heel.device-token.v1",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": login.device_code,
            "device_verifier": login.device_verifier,
        }))
        if result.status != 200:
            raise self._failure(result)
        exchange = self._parse_tokens(result)
        self.credential_store.save(exchange.credentials)
        self._access = exchange.credentials
        return exchange

    def refresh(self) -> DeviceExchange:
        # Rotation must be one cross-process load -> network -> save transaction. Reading the
        # durable value again after acquiring the per-origin lock avoids replaying a token that
        # another CLI/MCP process has just consumed.
        with self.credential_store.refresh_lock():
            current = self.credential_store.load()
            if current is None or getattr(current, "refresh_expires_at", 0) <= int(self._now()):
                raise CloudClientError("auth_required", 401)
            if getattr(current, "cloud_base_url", None) != self.cloud_base_url:
                raise CloudClientError("auth_required", 401)
            try:
                # There is deliberately no retry after this point. A response can be lost
                # after the server consumes a rotating token, so every uncertain outcome
                # invalidates the durable grant and requires a fresh device login.
                result = self._request("POST", "/v1/device/refresh", _canonical_json({
                    "schema_version": "heel.device-refresh.v1",
                    "grant_type": "refresh_token",
                    "refresh_token": current.refresh_token,
                }))
                if result.status != 200:
                    raise self._failure(result)
                exchange = self._parse_tokens(result)
                if exchange.credentials.device_id != current.device_id:
                    raise CloudClientError("invalid_response", 502)
                self.credential_store.save(exchange.credentials)
            except Exception as error:
                self._access = None
                try:
                    self.credential_store.delete()
                except Exception:
                    raise CloudClientError("unavailable") from None
                if isinstance(error, CloudClientError):
                    raise error
                raise CloudClientError("unavailable") from None
            self._access = exchange.credentials
            return exchange

    def _credentials(self) -> DeviceCredentials:
        current = self._access or self.credential_store.load()
        if current is None:
            raise CloudClientError("auth_required", 401)
        if getattr(current, "cloud_base_url", None) != self.cloud_base_url:
            raise CloudClientError("auth_required", 401)
        if not hasattr(current, "access_token") or current.access_expires_at <= int(self._now()):
            return self.refresh().credentials
        self._access = current
        return current

    def _authenticated(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
        expected_status: int = 200,
        transmission_expires_at: float | None = None,
    ) -> HttpResponse:
        def require_live_transmission() -> None:
            if (
                transmission_expires_at is not None
                and self._now() >= transmission_expires_at
            ):
                raise CloudClientError("approval_expired")

        current = self._credentials()
        # Credentials may refresh over the network. Sample the clock only after that work and
        # immediately before opening the authority-bearing request.
        require_live_transmission()
        result = self._request(
            method, path, body, access_token=current.access_token, extra_headers=extra_headers,
        )
        if result.status == 401:
            current = self.refresh().credentials
            require_live_transmission()
            result = self._request(
                method, path, body, access_token=current.access_token, extra_headers=extra_headers,
            )
        if result.status != expected_status:
            error = self._failure(result)
            if result.status == 401:
                self._access = None
                try:
                    self.credential_store.delete()
                except Exception:
                    raise CloudClientError("unavailable") from None
                error = CloudClientError("auth_required", 401)
            raise error
        return result

    def logout(self) -> None:
        with self.credential_store.refresh_lock():
            current = self.credential_store.load()
            if current is None:
                self.credential_store.delete()
                self._access = None
                return
            result = self._request("POST", "/v1/device/revoke", _canonical_json({
                "schema_version": "heel.device-revoke.v1",
                "refresh_token": current.refresh_token,
            }))
            if result.status != 200:
                raise self._failure(result)
            value = _exact(self._json(result), {"schema_version", "ok"})
            if value != {"schema_version": "heel.device-revoke-response.v1", "ok": True}:
                raise CloudClientError("invalid_response", 502)
            self.credential_store.delete()
            self._access = None

    @staticmethod
    def _refs(workspace_ref: str, project_ref: str | None = None) -> None:
        if type(workspace_ref) is not str or _WORKSPACE.fullmatch(workspace_ref) is None:
            raise CloudClientError("invalid_request")
        if project_ref is not None and (
            type(project_ref) is not str or _PROJECT.fullmatch(project_ref) is None
        ):
            raise CloudClientError("invalid_request")

    def list_projects(self, workspace_ref: str) -> tuple[CloudProject, ...]:
        self._refs(workspace_ref)
        result = self._authenticated("GET", f"/v1/workspaces/{workspace_ref}/projects")
        value = _exact(self._json(result), {"projects"})
        if type(value["projects"]) is not list or len(value["projects"]) > 500:
            raise CloudClientError("invalid_response", 502)
        projects = []
        for item in value["projects"]:
            item = _exact(item, {"workspace_id", "project_ref", "name", "created_by", "created_at"})
            if (
                item["workspace_id"] != workspace_ref
                or type(item["project_ref"]) is not str or _PROJECT.fullmatch(item["project_ref"]) is None
                or type(item["name"]) is not str or not 1 <= len(item["name"]) <= 120
                or type(item["created_by"]) is not str or not item["created_by"]
                or type(item["created_at"]) not in {int, float} or item["created_at"] < 0
                or not math.isfinite(item["created_at"])
            ):
                raise CloudClientError("invalid_response", 502)
            projects.append(CloudProject(
                workspace_ref, item["project_ref"], item["name"],
                item["created_by"], float(item["created_at"]),
            ))
        return tuple(projects)

    def account_status(self) -> CloudAccount:
        result = self._authenticated("GET", "/v1/me")
        value = _exact(self._json(result), {
            "principal", "device_id", "workspace_id", "role", "capabilities",
        })
        if (
            value["principal"] != "device_session"
            or type(value["device_id"]) is not str
            or _DEVICE_ID.fullmatch(value["device_id"]) is None
            or type(value["workspace_id"]) is not str
            or _WORKSPACE.fullmatch(value["workspace_id"]) is None
            or value["role"] not in {"owner", "admin", "member", "viewer"}
            or value["capabilities"] != list(DEVICE_CAPABILITIES)
        ):
            raise CloudClientError("invalid_response", 502)
        return CloudAccount(
            value["device_id"], value["workspace_id"], value["role"]
        )

    def namespace_key(self, workspace_ref: str, project_ref: str) -> bytes:
        self._refs(workspace_ref, project_ref)
        result = self._authenticated(
            "GET", f"/v1/workspaces/{workspace_ref}/projects/{project_ref}/namespace-key"
        )
        value = _exact(self._json(result), {"project_ref", "namespace_key_hex"})
        if (
            value["project_ref"] != project_ref
            or type(value["namespace_key_hex"]) is not str
            or _DIGEST.fullmatch(value["namespace_key_hex"]) is None
        ):
            raise CloudClientError("invalid_response", 502)
        return bytes.fromhex(value["namespace_key_hex"])

    def approve_findings(
        self, workspace_ref: str, project_ref: str, request_digest: str
    ) -> TransportApproval:
        self._refs(workspace_ref, project_ref)
        if type(request_digest) is not str or _DIGEST.fullmatch(request_digest) is None:
            raise CloudClientError("invalid_request")
        result = self._authenticated(
            "POST",
            f"/v1/workspaces/{workspace_ref}/projects/{project_ref}/findings-sync/approve",
            _canonical_json({"request_digest": request_digest}),
            expected_status=201,
        )
        value = _exact(self._json(result), {
            "workspace_id", "project_ref", "approval_id", "request_digest", "approved_by",
            "approved_at", "expires_at",
        })
        if (
            value["workspace_id"] != workspace_ref or value["project_ref"] != project_ref
            or value["request_digest"] != request_digest
            or type(value["approval_id"]) is not str
            or re.fullmatch(r"fsauth_[0-9a-f]{32}", value["approval_id"]) is None
            or type(value["approved_by"]) is not str or not value["approved_by"]
            or type(value["approved_at"]) not in {int, float}
            or type(value["expires_at"]) not in {int, float}
            or not math.isfinite(value["approved_at"])
            or not math.isfinite(value["expires_at"])
            or not 0 < value["expires_at"] - value["approved_at"] <= 600
        ):
            raise CloudClientError("invalid_response", 502)
        return TransportApproval(
            workspace_ref, project_ref, value["approval_id"], request_digest,
            value["approved_by"], float(value["approved_at"]), float(value["expires_at"]),
        )

    def sync_findings(
        self,
        permit,
        namespace_key: bytes,
    ) -> dict[str, Any]:
        # Import locally to preserve the cloud-client/queue module boundary. There is no public
        # raw-request overload: the queue's begun transmission is the only send authority.
        from .sync_queue import SyncRecord, SyncTransmissionPermit

        if type(permit) is not SyncTransmissionPermit or type(permit.record) is not SyncRecord:
            raise CloudClientError("invalid_request")
        record = permit.record
        transmission = record.transmission
        human = record.human_approval
        transport = record.transport_approval
        if (
            transmission is None
            or human is None
            or transport is None
            or record.receipt is not None
            or permit.permit_token != transmission.permit_token
            or permit.begun_at != transmission.begun_at
            or permit.effective_expires_at != transmission.effective_expires_at
            or transmission.request_digest != record.request_digest
            or transport.request_digest != record.request_digest
            or transmission.lease_token != record.retry.lease_token
            or record.retry.lease_expires_at is None
            or permit.effective_expires_at != min(
                human.expires_at,
                transport.expires_at,
                record.retry.lease_expires_at,
            )
            or not math.isfinite(permit.begun_at)
            or not math.isfinite(permit.effective_expires_at)
            or permit.effective_expires_at <= permit.begun_at
        ):
            raise CloudClientError("invalid_request")
        workspace_ref = record.workspace_ref
        project_ref = record.project_ref
        request_json = record.request_json
        request_digest = record.request_digest
        self._refs(workspace_ref, project_ref)
        if type(request_json) is not str or type(request_digest) is not str:
            raise CloudClientError("invalid_request")
        raw = request_json.encode("utf-8")
        if (
            len(raw) > MAX_CLOUD_RESPONSE_BYTES
            or _DIGEST.fullmatch(request_digest) is None
            or not hashlib.sha256(raw).hexdigest() == request_digest
        ):
            raise CloudClientError("invalid_request")
        try:
            request = parse_findings_sync_request(request_json, namespace_key)
        except ValueError:
            raise CloudClientError("invalid_request") from None
        if (
            request["project_ref"] != project_ref
            or stable_json(request) != request_json
            or hashlib.sha256(stable_json(request).encode("utf-8")).hexdigest()
            != request_digest
        ):
            raise CloudClientError("invalid_request")
        result = self._authenticated(
            "POST",
            f"/v1/workspaces/{workspace_ref}/projects/{project_ref}/findings-sync",
            raw,
            extra_headers={"Idempotency-Key": f"fs1-{request_digest}"},
            expected_status=201,
            transmission_expires_at=permit.effective_expires_at,
        )
        # The receipt parser is strict, but first enforce the HTTP media type so a
        # mislabeled or intermediary-generated document can never be accepted.
        content_type = next(
            (value for key, value in result.headers.items() if key.lower() == "content-type"), ""
        ).split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise CloudClientError("invalid_response", 502)
        try:
            receipt = parse_findings_sync_receipt(result.body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise CloudClientError("invalid_response", 502) from None
        if (
            receipt["project_ref"] != project_ref
            or receipt["request_digest"] != request_digest
            or receipt["projection_hash"] != request.get("projection_hash")
        ):
            raise CloudClientError("invalid_response", 502)
        return receipt

    def list_history(self, workspace_ref: str, project_ref: str) -> tuple[dict[str, Any], ...]:
        self._refs(workspace_ref, project_ref)
        result = self._authenticated(
            "GET", f"/v1/workspaces/{workspace_ref}/projects/{project_ref}/reviews"
        )
        value = _exact(self._json(result), {"reviews"})
        if type(value["reviews"]) is not list or len(value["reviews"]) > 2_000:
            raise CloudClientError("invalid_response", 502)
        expected = {
            "synced_review_id", "projection_hash", "gate_status", "findings_count",
            "blockers_count", "created_at",
        }
        reviews = []
        for item in value["reviews"]:
            item = _exact(item, expected)
            if (
                type(item["synced_review_id"]) is not str
                or _REVIEW.fullmatch(item["synced_review_id"]) is None
                or type(item["projection_hash"]) is not str
                or _DIGEST.fullmatch(item["projection_hash"]) is None
                or item["gate_status"] not in {"pass", "warn", "block"}
                or type(item["findings_count"]) is not int or item["findings_count"] < 0
                or type(item["blockers_count"]) is not int
                or not 0 <= item["blockers_count"] <= item["findings_count"]
                or type(item["created_at"]) not in {int, float} or item["created_at"] < 0
                or not math.isfinite(item["created_at"])
            ):
                raise CloudClientError("invalid_response", 502)
            reviews.append(dict(item))
        return tuple(reviews)
