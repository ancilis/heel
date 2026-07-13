"""
Arceo hosted — control-plane HTTP API (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

A require()-guarded JSON API over the tenancy/entitlement/billing/auth stores. Every workspace
route resolves the caller's role server-side through `tenancy.require`; client-supplied roles and
workspace claims are never trusted. Binds loopback by default — production exposure goes through
the deployment's TLS-terminating edge, never by widening this default.

Safety boundary (unchanged from the engine): the human-only, HMAC-signed AuthorizationScope is not
creatable here at all in this phase, and API-key principals will never be able to create one —
`create_scope` is session-principal-only by construction. Verified real-target runs return 501
until the Phase 3 job plane lands target verification.
"""
from __future__ import annotations

import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .auth import AuthStore, ThrottledError
from .billing import BillingStore, StubBilling, SubscriptionManager
from .catalog import CATALOG_VERSION, Meter, get_plan, self_serve_plans
from .entitlement import EntitlementService, Subscription
from .ledger import QuotaExceeded, UsageLedger
from .tenancy import ControlPlaneStore, Role, require

MAX_BODY = 64 * 1024


def current_period() -> str:
    return time.strftime("%Y-%m", time.gmtime())


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.body = {"error": message, **extra}


class ControlPlane:
    """All stores on one SQLite connection; the unit the HTTP layer serves."""

    def __init__(self, path: str = ":memory:"):
        self.store = ControlPlaneStore(path)
        conn = self.store.conn
        self.auth = AuthStore(conn)
        self.ledger = UsageLedger(conn)
        self.billing_store = BillingStore(conn)
        self.subs = SubscriptionManager(self.billing_store)
        self.billing = StubBilling()
        self.entitlements = EntitlementService(self.ledger)

    def subscription(self, workspace_id: str) -> Subscription:
        ws = self.store.get_workspace(workspace_id)
        if ws is None:
            raise ApiError(404, "workspace not found")
        sub = self.billing_store.get(workspace_id)
        if sub is not None and sub.state:
            return Subscription(workspace_id, sub.plan_id, sub.state, ws["catalog_version"])
        return Subscription(workspace_id, ws["plan_id"], "active", ws["catalog_version"])

    def user_by_email(self, email: str) -> sqlite3.Row | None:
        return self.store.conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArceoControlPlane/1"
    cp: ControlPlane  # set by serve()
    webhook_secret: str | None = None

    # --- plumbing ---
    def log_message(self, *a):  # quiet; the deployment edge does access logging
        pass

    def _json(self, status: int, obj: dict, headers: dict | None = None) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(413, "request body too large")
        if n == 0:
            return {}
        try:
            obj = json.loads(self.rfile.read(n))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "invalid JSON body")
        if not isinstance(obj, dict):
            raise ApiError(400, "body must be a JSON object")
        return obj

    def _raw_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(413, "request body too large")
        return self.rfile.read(n)

    def _principal(self) -> tuple[str, str | None, tuple[str, Role] | None]:
        """Return (kind, user_id, api_key_scope). kind: 'session' | 'api_key' | 'anon'."""
        authz = self.headers.get("Authorization", "")
        if authz.startswith("Bearer arceo_sk_"):
            got = self.cp.store.authenticate_api_key(authz[len("Bearer "):])
            if not got:
                raise ApiError(401, "invalid API key")
            return "api_key", None, got
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "arceo_session" and v:
                uid = self.cp.auth.resolve_session(v)
                if uid:
                    return "session", uid, None
        return "anon", None, None

    def _authorize(self, workspace_id: str, capability: str) -> Role:
        """The single choke point for workspace routes. API keys are workspace-bound and can
        NEVER exercise create_scope (human-only, session principals only)."""
        kind, user_id, key = self._principal()
        if kind == "session":
            return require(self.cp.store, workspace_id, user_id, capability)
        if kind == "api_key":
            ws, role = key
            if ws != workspace_id:
                raise ApiError(403, "API key is scoped to a different workspace")
            if capability == "create_scope":
                raise ApiError(403, "authorization scopes are human-only; use a signed-in session")
            from .tenancy import role_can
            if not role_can(role, capability):
                raise ApiError(403, f"API key role {role.value} lacks {capability!r}")
            return role
        raise ApiError(401, "authentication required")

    # --- routing ---
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, method: str) -> None:
        try:
            parts = [p for p in self.path.split("?")[0].split("/") if p]
            handler = self._match(method, parts)
            if handler is None:
                raise ApiError(404, "not found")
            handler()
        except ApiError as e:
            self._json(e.status, e.body)
        except PermissionError as e:
            self._json(403, {"error": str(e)})
        except ThrottledError as e:
            self._json(429, {"error": str(e)})
        except Exception:
            self._json(500, {"error": "internal error"})

    def _match(self, method: str, p: list[str]):
        if not p or p[0] != "v1":
            return None
        rest = p[1:]
        flat = {
            ("GET", ("health",)): self._health,
            ("GET", ("plans",)): self._plans,
            ("POST", ("signup",)): self._signup,
            ("POST", ("login",)): self._login,
            ("POST", ("logout",)): self._logout,
            ("GET", ("me",)): self._me,
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
                ("POST", ("billing", "checkout")): lambda: self._ws_checkout(wid),
            }
            if (method, tail) in ws_routes:
                return ws_routes[(method, tail)]
            if method == "DELETE" and len(tail) == 2 and tail[0] == "api-keys":
                return lambda: self._ws_key_revoke(wid, tail[1])
        return None

    # --- open endpoints ---
    def _health(self):
        self._json(200, {"ok": True, "catalog_version": CATALOG_VERSION})

    def _plans(self):
        self._json(200, {"catalog_version": CATALOG_VERSION, "plans": [
            {"id": pl.id, "name": pl.name, "price_month_cents": pl.price_month_cents}
            for pl in self_serve_plans()]})

    def _signup(self):
        b = self._body()
        email, password = str(b.get("email", "")).strip(), str(b.get("password", ""))
        if "@" not in email:
            raise ApiError(400, "valid email required")
        if self.cp.user_by_email(email):
            raise ApiError(409, "account already exists")
        uid = self.cp.store.create_user(email)
        self.cp.auth.set_password(uid, password)   # raises ValueError if weak
        org = self.cp.store.create_org(email)
        wid = self.cp.store.create_workspace(org, "default", "free", CATALOG_VERSION)
        self.cp.store.add_member(wid, uid, Role.OWNER)
        ses = self.cp.auth.create_session(uid)
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
                if k == "arceo_session":
                    self.cp.auth.revoke_session(v)
        self._json(200, {"ok": True}, {"Set-Cookie": "arceo_session=; Max-Age=0; Path=/"})

    def _me(self):
        kind, uid, key = self._principal()
        if kind == "session":
            rows = self.cp.store.conn.execute(
                "SELECT workspace_id, role FROM memberships WHERE user_id=?", (uid,)).fetchall()
            self._json(200, {"user_id": uid, "workspaces": [
                {"workspace_id": r["workspace_id"], "role": r["role"]} for r in rows]})
        elif kind == "api_key":
            self._json(200, {"workspace_id": key[0], "role": key[1].value})
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

    def _ws_invite(self, wid: str):
        self._authorize(wid, "manage_members")
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
        role = self.cp.store.accept_invite(wid, token, uid)
        self._json(200, {"workspace_id": wid, "role": role.value})

    def _ws_key_create(self, wid: str):
        self._authorize(wid, "manage_api_keys")
        b = self._body()
        try:
            role = Role(str(b.get("role", "viewer")))
        except ValueError:
            raise ApiError(400, "invalid role")
        if role in (Role.OWNER, Role.ADMIN):
            raise ApiError(400, "API keys may not carry owner/admin roles")
        issued = self.cp.store.issue_api_key(wid, role, str(b.get("name", "")))
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

    def _ws_run(self, wid: str):
        self._authorize(wid, "run_rehearsal")
        b = self._body()
        if bool(b.get("verified", False)):
            raise ApiError(501, "verified real-target runs arrive with the Phase 3 job plane; "
                                "synthetic rehearsals are available now")
        sub = self.cp.subscription(wid)
        period = current_period()
        idem = str(b.get("idempotency_key")) if b.get("idempotency_key") else None
        try:
            resv = self.cp.entitlements.reserve_run(sub, period, verified=False,
                                                    idempotency_key=idem)
        except QuotaExceeded as e:
            self._json(402, {"error": "quota exceeded", "meter": e.meter.value,
                             "upgrade_to": self.cp.entitlements.upgrade_target(sub)})
            return
        self._json(202, {"status": "queued", "reservation_id": resv[0].reservation_id,
                         "period": period})

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
        self._json(200, self.cp.billing.create_checkout(wid, plan, interval))

    # --- billing webhook (signature-verified, no auth principal) ---
    def _webhook(self):
        from .billing import WebhookVerificationError, verify_webhook_signature
        payload = self._raw_body()
        if self.webhook_secret:
            header = self.headers.get("X-Arceo-Billing-Signature", "")
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
            if ws is not None and ws["plan_id"] != sub.plan_id:
                self.cp.store.set_workspace_plan(sub.workspace_id, sub.plan_id,
                                                 ws["catalog_version"])
        self._json(200, {"disposition": disposition})


def _session_cookie(token: str) -> str:
    # Secure is added by the TLS edge in production; HttpOnly+SameSite always.
    return f"arceo_session={token}; HttpOnly; SameSite=Lax; Path=/"


def serve(cp: ControlPlane, host: str = "127.0.0.1", port: int = 0,
          *, webhook_secret: str | None = None) -> ThreadingHTTPServer:
    """Create (not run) the server; caller drives serve_forever/shutdown. Loopback default."""
    handler = type("Handler", (_Handler,), {"cp": cp, "webhook_secret": webhook_secret})
    return ThreadingHTTPServer((host, port), handler)
