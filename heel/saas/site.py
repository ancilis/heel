"""
Heel hosted — public website + docs generator (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Static output only; runs from the catalog and doc templates, never against tenant or production
data. Pricing and quotas are read from `catalog.py` so the website can never disagree with what
the entitlement service enforces. Legal pages are explicit templates: they render with a visible
"template — requires counsel review" banner until the owner replaces them (OWNER_ACTIONS).
"""
from __future__ import annotations

import html
import os

from .catalog import CATALOG_VERSION, CUSTOM, Meter, all_plans

_SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Heel</title><style>
body{{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#182026}}
nav a{{margin-right:1rem}} table{{border-collapse:collapse;width:100%}}
td,th{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e0e4e8}}
.banner{{background:#fdf3d7;border:1px solid #e5c65f;padding:.6rem;border-radius:.3rem}}
footer{{margin-top:3rem;color:#5c6770;font-size:.9rem}}
</style></head><body>
<nav><a href="index.html">Heel</a><a href="pricing.html">Pricing</a>
<a href="docs.html">Docs</a><a href="security.html">Security</a></nav>
<h1>{title}</h1>{body}
<footer>Heel · catalog {catalog} · <a href="terms.html">Terms</a> ·
<a href="privacy.html">Privacy</a></footer></body></html>"""

_LEGAL_BANNER = ('<p class="banner">Template — requires counsel review before publication '
                 "(see OWNER_ACTIONS). Not yet legally operative.</p>")

# Claims policy: every statement here must be enforced by shipped code. Do not add claims
# without pointing at the enforcing module in the parenthetical.
_INDEX = """
<p>Heel rehearses your incident response against synthetic and verified real targets, with
guardrails as the product: runs are budget-capped, and real-target runs require proof of target
ownership plus an explicit human authorization scope (jobs.py, verification.py, scope signing).</p>
<ul>
<li>No unverified real-target execution at any tier, ever (job plane fails closed).</li>
<li>Egress during a verified run is limited to your verified target (egress.py, default deny).</li>
<li>Quotas are enforced transactionally at enqueue — no surprise overage bills on Free/Pro
(usage ledger, reserve-at-enqueue).</li>
<li>API keys are workspace-scoped and can never mint authorization scopes — scopes are
human-only (http_api.py).</li>
</ul>
<p><a href="pricing.html">See plans</a> or start free — no card required.</p>"""

_SECURITY = """
<ul>
<li><strong>Proof of control:</strong> real targets are verified via DNS TXT or an HTTPS
well-known file, re-proven periodically, revocable at any time.</li>
<li><strong>Human-only authorization:</strong> the signed scope that permits a real-target run is
minted only through an interactive session; API keys and agents cannot create one.</li>
<li><strong>Budgeted runs:</strong> every run carries immutable wall-clock, token, and egress
ceilings; workers enforce them and expired leases are reaped and refunded.</li>
<li><strong>Egress guard:</strong> default-deny; only the verified target on ports 80/443, with
post-resolution rejection of private and loopback addresses.</li>
<li><strong>Tenant isolation:</strong> every record carries a workspace id; all workspace routes
resolve the caller's role server-side.</li>
<li><strong>Credentials:</strong> passwords are PBKDF2-hashed; API keys, sessions, and invite
tokens are stored only as hashes.</li>
</ul>
<p>Report vulnerabilities to security@ (see docs). Do not test against targets you have not
verified ownership of.</p>"""

_DOCS = """
<h2>Quickstart</h2>
<ol>
<li>Sign up — you get a Free workspace, no card.</li>
<li>Run a synthetic rehearsal from the dashboard (no network, planted ground truth).</li>
<li>Verify a target you control: publish the DNS TXT record or the well-known file the dashboard
gives you, then click Check.</li>
<li>Mint a human authorization scope, then start a verified run against that target.</li>
</ol>
<h2>API</h2>
<p>Base path <code>/v1</code>; authenticate with a session cookie or
<code>Authorization: Bearer &lt;api key&gt;</code>. Keys are workspace-scoped.</p>
<table><tr><th>Endpoint</th><th>Notes</th></tr>
<tr><td>POST /v1/signup, /v1/login, /v1/logout</td><td>account + session</td></tr>
<tr><td>GET /v1/me</td><td>principal + workspaces</td></tr>
<tr><td>GET /v1/workspaces/{id}/summary · /entitlements · /usage</td><td>view role</td></tr>
<tr><td>POST /v1/workspaces/{id}/targets · /targets/check</td><td>ownership verification</td></tr>
<tr><td>POST /v1/workspaces/{id}/runs</td><td>402 with upgrade hint at quota; verified runs need
target + scope_ref</td></tr>
<tr><td>GET /v1/workspaces/{id}/jobs/{job}</td><td>run status</td></tr>
<tr><td>POST /v1/workspaces/{id}/api-keys · DELETE .../api-keys/{key}</td><td>member/viewer/billing
roles only</td></tr>
<tr><td>POST /v1/workspaces/{id}/billing/checkout</td><td>self-serve upgrade</td></tr></table>"""


def _price(cents: int) -> str:
    if cents == CUSTOM:
        return "Contact sales"
    if cents == 0:
        return "$0"
    return f"${cents // 100}/mo"


def _quota(v: int) -> str:
    return "Custom" if v == CUSTOM else str(v)


def render_pricing() -> str:
    plans = all_plans()
    head = "".join(f"<th>{html.escape(p.name)}</th>" for p in plans)
    price = "".join(f"<td>{_price(p.price_month_cents)}</td>" for p in plans)
    rows = [f"<tr><th></th>{head}</tr>", f"<tr><td>Price</td>{price}</tr>"]
    labels = {Meter.RUNS: "Rehearsal runs / mo", Meter.VERIFIED_RUNS: "Verified runs / mo",
              Meter.VERIFIED_TARGETS: "Verified targets", Meter.SEATS: "Seats",
              Meter.CONCURRENCY: "Concurrent runs", Meter.RETENTION_DAYS: "Retention (days)"}
    for m, label in labels.items():
        cells = "".join(f"<td>{_quota(p.quota(m))}</td>" for p in plans)
        rows.append(f"<tr><td>{label}</td>{cells}</tr>")
    return ("<table>" + "".join(rows) + "</table>"
            "<p>Free and Pro have hard ceilings — usage stops at the quota; there is no metered "
            "overage. Enterprise features (SSO, SCIM, data region, private runners) are enabled "
            "per deployment; nothing is a dead checkbox.</p>")


def build(out_dir: str) -> list:
    """Write the static site; returns the file list."""
    pages = {
        "index.html": ("Rehearse incidents with guardrails", _INDEX),
        "pricing.html": (f"Pricing (catalog {CATALOG_VERSION})", render_pricing()),
        "docs.html": ("Documentation", _DOCS),
        "security.html": ("Security model", _SECURITY),
        "terms.html": ("Terms of Service", _LEGAL_BANNER +
                       "<p>Placeholder terms: service provided as-is during beta; acceptable use "
                       "prohibits testing targets you have not verified ownership of.</p>"),
        "privacy.html": ("Privacy Policy", _LEGAL_BANNER +
                         "<p>Placeholder policy: account email, billing state, and run metadata "
                         "are stored to operate the service; no tenant data is sold.</p>"),
    }
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, (title, body) in pages.items():
        path = os.path.join(out_dir, name)
        with open(path, "w") as f:
            f.write(_SHELL.format(title=html.escape(title), body=body,
                                  catalog=html.escape(CATALOG_VERSION)))
        written.append(path)
    return written
