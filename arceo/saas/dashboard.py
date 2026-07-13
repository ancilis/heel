"""
Arceo hosted — server-rendered onboarding + dashboard (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Minimal HTML app on the same control plane and the same session auth as the JSON API — no client
framework, no external assets, every value escaped. Forms are urlencoded POSTs; all authorization
goes through the same `tenancy.require` choke point via the shared handler helpers. The onboarding
checklist mirrors PRODUCT.md: sign up → synthetic run → verify a target → upgrade when quota hits.
"""
from __future__ import annotations

import html
import urllib.parse

from .catalog import Meter
from .ledger import QuotaExceeded

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Arceo</title><style>
body{{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#182026}}
h1{{font-size:1.3rem}} table{{border-collapse:collapse;width:100%}}
td,th{{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #e0e4e8}}
form.inline{{display:inline}} .bar{{background:#e8ecef;height:.5rem;border-radius:.25rem}}
.bar>div{{background:#2b6cb0;height:100%;border-radius:.25rem}}
.note{{color:#5c6770;font-size:.9rem}} .err{{color:#b3261e}}
input,select,button{{font:inherit;padding:.35rem .5rem;margin:.15rem 0}}
</style></head><body><h1>{title}</h1>{body}
<p class="note">Arceo · <a href="/app">dashboard</a> · <a href="/app/logout-form">sign out</a></p>
</body></html>"""


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _page(title: str, body: str) -> str:
    return _PAGE.format(title=_e(title), body=body)


def _form_body(handler) -> dict:
    n = int(handler.headers.get("Content-Length") or 0)
    if n > 64 * 1024:
        return {}
    data = urllib.parse.parse_qs(handler.rfile.read(n).decode(errors="replace"))
    return {k: v[0] for k, v in data.items()}


def _html(handler, status: int, body: str, headers: dict | None = None) -> None:
    raw = body.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(raw)


def _redirect(handler, to: str, headers: dict | None = None) -> None:
    handler.send_response(303)
    handler.send_header("Location", to)
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


_AUTH_FORM = """
<form method="post" action="/app/{action}">
<label>Email <input name="email" type="email" required></label><br>
<label>Password <input name="password" type="password" minlength="10" required></label><br>
<button>{label}</button></form>
<p class="note">{alt}</p>{err}"""


def handle(handler, method: str, parts: list) -> bool:
    """Route /app paths on the shared handler. Returns False if not an /app path."""
    if not parts or parts[0] != "app":
        return False
    tail = tuple(parts[1:])
    kind, uid, _key = handler._principal()

    if tail == ("signup-form",) or tail == ("login-form",):
        action = "signup" if tail[0] == "signup-form" else "login"
        err = handler.path.split("err=")[-1] if "err=" in handler.path else ""
        alt = ('Have an account? <a href="/app/login-form">Sign in</a>' if action == "signup"
               else 'New here? <a href="/app/signup-form">Create an account</a>')
        _html(handler, 200, _page(
            "Create your workspace" if action == "signup" else "Sign in",
            _AUTH_FORM.format(action=action, label=action.title(), alt=alt,
                              err=f'<p class="err">{_e(urllib.parse.unquote(err))}</p>' if err else "")))
        return True

    if method == "POST" and tail in (("signup",), ("login",)):
        f = _form_body(handler)
        email, password = f.get("email", "").strip(), f.get("password", "")
        cp = handler.cp
        try:
            if tail == ("signup",):
                if "@" not in email:
                    raise ValueError("valid email required")
                if cp.user_by_email(email):
                    raise ValueError("account already exists")
                from .catalog import CATALOG_VERSION
                from .tenancy import Role
                new_uid = cp.store.create_user(email)
                cp.auth.set_password(new_uid, password)
                org = cp.store.create_org(email)
                wid = cp.store.create_workspace(org, "default", "free", CATALOG_VERSION)
                cp.store.add_member(wid, new_uid, Role.OWNER)
                ses = cp.auth.create_session(new_uid)
            else:
                row = cp.user_by_email(email)
                ses = cp.auth.login(email, row["user_id"] if row else None, password)
        except Exception as e:
            msg = urllib.parse.quote(str(e) if not isinstance(e, PermissionError)
                                     else "invalid email or password")
            _redirect(handler, f"/app/{tail[0]}-form?err={msg}")
            return True
        from .http_api import _session_cookie
        _redirect(handler, "/app", {"Set-Cookie": _session_cookie(ses.token)})
        return True

    if tail == ("logout-form",):
        cookie = handler.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "arceo_session":
                handler.cp.auth.revoke_session(v)
        _redirect(handler, "/app/login-form",
                  {"Set-Cookie": "arceo_session=; Max-Age=0; Path=/"})
        return True

    # Everything below needs a signed-in session (dashboard is human-facing; API keys use /v1).
    if kind != "session":
        _redirect(handler, "/app/login-form")
        return True

    cp = handler.cp
    rows = cp.store.conn.execute(
        "SELECT workspace_id, role FROM memberships WHERE user_id=?", (uid,)).fetchall()
    if not rows:
        _html(handler, 200, _page("No workspace", "<p>You have no workspace yet.</p>"))
        return True
    wid = rows[0]["workspace_id"]

    if method == "POST" and tail == ("run",):
        sub = cp.subscription(wid)
        from .http_api import current_period
        try:
            resv = cp.entitlements.reserve_run(sub, current_period(), verified=False)
            cp.jobs.enqueue(wid, kind="synthetic",
                            reservation_ids=[r.reservation_id for r in resv])
        except QuotaExceeded:
            _redirect(handler, "/app?quota=1")
            return True
        _redirect(handler, "/app")
        return True

    if method == "POST" and tail == ("target",):
        hostname = _form_body(handler).get("hostname", "")
        try:
            cp.verifier.start(wid, hostname)
        except ValueError as e:
            _redirect(handler, f"/app?err={urllib.parse.quote(str(e))}")
            return True
        _redirect(handler, "/app")
        return True

    if method == "POST" and tail == ("target-check",):
        cp.verifier.check(wid, _form_body(handler).get("hostname", ""))
        _redirect(handler, "/app")
        return True

    if tail == ():
        _html(handler, 200, _page("Dashboard", _render_dashboard(handler, cp, wid)))
        return True
    return False


def _render_dashboard(handler, cp, wid: str) -> str:
    from .http_api import current_period
    sub = cp.subscription(wid)
    plan = cp.entitlements.effective_plan(sub)
    period = current_period()
    out = []
    if "quota=1" in handler.path:
        up = cp.entitlements.upgrade_target(sub)
        out.append(f'<p class="err">Run quota reached for {_e(period)}.'
                   + (f' Consider upgrading to {_e(up)}.' if up else "") + "</p>")
    if "err=" in handler.path:
        out.append(f'<p class="err">{_e(urllib.parse.unquote(handler.path.split("err=")[-1]))}</p>')
    out.append(f"<p>Plan: <strong>{_e(plan.name)}</strong> · state {_e(sub.state)}</p>")

    out.append("<h2>Usage this period</h2><table>")
    for m in (Meter.RUNS, Meter.VERIFIED_RUNS):
        q = cp.entitlements.quota(sub, m)
        rem = cp.entitlements.remaining(sub, m, period)
        used = (q - rem) if (rem is not None and q >= 0) else 0
        pct = int(100 * used / q) if q > 0 else 0
        out.append(f"<tr><td>{_e(m.value)}</td><td>{used} / {'∞' if q < 0 else q}</td>"
                   f'<td style="width:40%"><div class="bar"><div style="width:{pct}%"></div></div></td></tr>')
    out.append("</table>")

    out.append('<h2>Rehearsals</h2><form class="inline" method="post" action="/app/run">'
               "<button>Run synthetic rehearsal</button></form>")
    jobs = cp.store.conn.execute(
        "SELECT job_id, kind, state, created_at FROM jobs WHERE workspace_id=? "
        "ORDER BY created_at DESC LIMIT 10", (wid,)).fetchall()
    if jobs:
        out.append("<table><tr><th>job</th><th>kind</th><th>state</th></tr>")
        out.extend(f"<tr><td>{_e(j['job_id'])}</td><td>{_e(j['kind'])}</td>"
                   f"<td>{_e(j['state'])}</td></tr>" for j in jobs)
        out.append("</table>")

    out.append('<h2>Verified targets</h2>')
    tgts = cp.store.conn.execute(
        "SELECT hostname, token, verified_at, revoked_at FROM verified_targets "
        "WHERE workspace_id=?", (wid,)).fetchall()
    if tgts:
        out.append("<table><tr><th>hostname</th><th>status</th><th></th></tr>")
        for t in tgts:
            if t["revoked_at"]:
                status = "revoked"
            elif t["verified_at"]:
                status = "verified"
            else:
                status = (f'pending — publish TXT <code>arceo-verify={_e(t["token"])}</code> '
                          f'on <code>_arceo.{_e(t["hostname"])}</code>')
            check = ("" if t["revoked_at"] or t["verified_at"] else
                     f'<form class="inline" method="post" action="/app/target-check">'
                     f'<input type="hidden" name="hostname" value="{_e(t["hostname"])}">'
                     f"<button>Check</button></form>")
            out.append(f"<tr><td>{_e(t['hostname'])}</td><td>{status}</td><td>{check}</td></tr>")
        out.append("</table>")
    out.append('<form method="post" action="/app/target">'
               '<input name="hostname" placeholder="app.example.com" required>'
               "<button>Add target</button></form>")

    out.append("<h2>Getting started</h2><ol>"
               "<li>Run a synthetic rehearsal (safe, no network) ✓ above</li>"
               "<li>Verify a real target you control (DNS TXT or HTTP file)</li>"
               "<li>Verified runs stay budget-capped and egress-limited to your target</li>"
               "<li>Hit a quota? Upgrade self-serve from the plan page</li></ol>")
    return "".join(out)
