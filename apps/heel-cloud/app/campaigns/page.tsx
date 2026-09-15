// SPDX-License-Identifier: LicenseRef-Heel-Commercial
"use client";

import { useMemo, useState, type MouseEvent } from "react";
import Link from "next/link";
import template from "../../data/campaign-template.json";
import { parseCampaignReport, type CampaignReport } from "../../lib/campaign-report";

const labels: Record<string, string> = {
  tenant_isolation: "Tenant isolation", role_boundary: "Role boundaries", entitlement: "Paid entitlements",
  trial_eligibility: "Trial eligibility", promotion_limits: "Promotion limits", usage_accounting: "Usage accounting",
  quota: "Quotas", lifecycle: "Entitlement changes", idempotency: "Repeated requests", workflow_order: "Workflow order",
  integration_scope: "Integration scope", agent_actions: "Agent permissions",
};
const maxBytes = 256 * 1024;

export default function Campaigns() {
  const [origin, setOrigin] = useState(template.origin);
  const [environment, setEnvironment] = useState("loopback");
  const [selected, setSelected] = useState(new Set(template.scenarios.map((s) => s.family)));
  const [draft, setDraft] = useState(JSON.stringify(template, null, 2));
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [report, setReport] = useState<CampaignReport | null>(null);
  const [filter, setFilter] = useState("all");
  const shown = useMemo(() => report?.results.filter((r) => filter === "all" || r.outcome === filter) ?? [], [report, filter]);

  function generate() {
    setError("");
    if (!selected.size) { setError("Choose at least one test family."); return; }
    const scenarios = template.scenarios.filter((s) => selected.has(s.family));
    setDraft(JSON.stringify({ ...template, origin, environment, scenarios,
      limits: { ...template.limits, max_requests: scenarios.reduce((n, s) => n + s.steps.length + s.cleanup.length, 0) } }, null, 2));
    setNotice("Editable campaign created. Map its paths, actors and response fields to your application's canary fixtures.");
  }
  function download(event: MouseEvent<HTMLAnchorElement>) {
    setError("");
    try {
      if (new TextEncoder().encode(draft).length > maxBytes) throw new Error();
      const plan = JSON.parse(draft);
      if (plan?.schema_version !== "heel.campaign.v1" || !Array.isArray(plan.scenarios) || plan.scenarios.length === 0) throw new Error();
      const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2) + "\n"], { type: "application/json" }));
      event.currentTarget.href = url;
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice("Campaign downloaded. Run prepare locally to validate every operation before authorizing it.");
    } catch { event.preventDefault(); setError("Use valid campaign JSON under 256 KiB."); }
  }
  async function readFile(file: File | undefined, kind: "plan" | "report") {
    setError("");
    if (!file) return;
    try {
      if (file.size > maxBytes) throw new Error("Choose a JSON file under 256 KiB.");
      const source = await file.text();
      if (new TextEncoder().encode(source).length > maxBytes) throw new Error("Choose a JSON file under 256 KiB.");
      const value: unknown = JSON.parse(source);
      if (kind === "report") { setReport(parseCampaignReport(value)); setFilter("all"); }
      else { setDraft(JSON.stringify(value, null, 2)); setNotice("Plan loaded in memory. Review its exact operations before authorizing."); }
    } catch { setError("Choose a valid Heel campaign JSON file under 256 KiB."); }
  }

  return <main className="campaign-page">
    <header className="site-header"><Link className="brand" href="/">Heel</Link><nav aria-label="Workspace"><Link href="/">Static review</Link><Link href="/agent">Agent setup</Link></nav><span className="local-status">Local execution · explicit business rules</span></header>
    <section className="campaign-heading">
      <p className="eyebrow">Abuse campaigns</p><h1>Test what a user<br />can get away with.</h1>
      <p>Follow value across accounts, permissions and state changes. Save the rules, observe the behavior, and repeat after a fix.</p>
      <div className="campaign-flow" aria-label="Campaign workflow"><span>01 Define</span><span>02 Map</span><span>03 Run locally</span><span>04 Inspect evidence</span></div>
    </section>
    {error && <p className="campaign-error" role="alert">{error}</p>}
    {notice && <p className="campaign-notice" role="status">{notice}</p>}
    <div className="campaign-columns">
      <section className="campaign-card"><p className="eyebrow">01 / Define the campaign</p><h2>Choose the rules to exercise.</h2>
        <p>These templates run against the bundled local SaaS. Edit their operations and observations to test your own sandbox.</p>
        <label>Application origin<input value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="https://staging.your-app.com" /></label>
        <label>Environment<select value={environment} onChange={(e) => setEnvironment(e.target.value)}><option value="loopback">Local canary sandbox</option><option value="sandbox">Owned HTTPS sandbox</option><option value="staging">Owned HTTPS staging</option></select></label>
        <fieldset className="campaign-families"><legend>Test families</legend>{template.scenarios.map((scenario) => <label key={scenario.id} className={selected.has(scenario.family) ? "selected" : ""}>
          <input type="checkbox" checked={selected.has(scenario.family)} onChange={() => setSelected((current) => { const next = new Set(current); if (next.has(scenario.family)) next.delete(scenario.family); else next.add(scenario.family); return next; })} />
          <span>{labels[scenario.family]}<small>{scenario.rule}</small></span>
        </label>)}</fieldset>
        <button className="button button-primary" onClick={generate}>Create editable campaign</button>
      </section>
      <div className="campaign-stack">
        <section className="campaign-card"><p className="eyebrow">02 / Map your application</p><h2>Exact actions. Observable outcomes.</h2>
          <p>Map paths and methods, named actors, synthetic fixtures, prerequisites, assertions and cleanup. Credential fields contain environment-variable names only.</p>
          <label className="campaign-file">Load an existing campaign<input type="file" accept=".json,application/json" onChange={(e) => void readFile(e.target.files?.[0], "plan")} /></label>
          <label>Campaign JSON<textarea spellCheck={false} value={draft} onChange={(e) => setDraft(e.target.value)} /></label>
          <a className="button button-secondary" href="#" download="heel-campaign.json" onClick={download}>Download campaign</a>
        </section>
        <section className="campaign-card campaign-terminal"><p className="eyebrow">03 / Authorize and run locally</p><h2>Your application, your runner.</h2>
          <p>Install the current <a href="/agent">Heel Agent</a>, set the canary credential variables in your terminal, then inspect and approve the plan.</p>
          <p>Updating an existing 1.2.0 preview? Reinstall the downloaded wheel with <code>python -m pip install --force-reinstall --no-deps ./heel_sim-1.2.0-py3-none-any.whl</code> to get the campaign commands.</p>
          <pre><code>{`heel campaign prepare heel-campaign.json
heel campaign authorize heel-campaign.json --operator "me" --runs 10 --confirm
heel campaign run heel-campaign.json --scope SCOPE_ID
heel campaign report RUN_ID --format markdown
heel campaign compare BEFORE_RUN_ID AFTER_RUN_ID`}</code></pre>
          <details><summary>Try all families against the local demo</summary><p>Start the synthetic product with <code>heel campaign demo</code>. Set <code>HEEL_CANARY_OWNER=heel-canary-owner</code> and <code>HEEL_CANARY_OUTSIDER=heel-canary-outsider</code> in the runner terminal. Run the default campaign. Restart the demo with <code>--hardened</code> on the same port and repeat to compare the fix.</p></details>
          <p>Authorization binds this exact plan. Editing it requires fresh authorization. Ctrl+C stops requests; inspect cleanup status after interruption.</p>
        </section>
      </div>
    </div>
    <section className="campaign-card campaign-results"><p className="eyebrow">04 / Inspect evidence</p><h2>What did the campaign establish?</h2>
      <label className="campaign-file">Campaign report JSON<input type="file" accept=".json,application/json" onChange={(e) => void readFile(e.target.files?.[0], "report")} /></label>
      <p>The browser does not authenticate imported report signatures. Use <code>heel campaign report</code> locally to verify them. Files stay in memory and are never uploaded.</p>
      <p>Unconfigured families are untested. A held rule applies only to its declared actors, actions and observed responses.</p>
      {report ? <>
        <h3>{report.name}</h3><p>{report.origin} · {report.requests_attempted} attempted requests</p>
        <div className="campaign-filters" aria-label="Filter results">{["all", "violation", "held", "inconclusive", "not_applicable"].map((outcome) => <button key={outcome} aria-pressed={filter === outcome} onClick={() => setFilter(outcome)}>{outcome.replaceAll("_", " ")} <strong>{outcome === "all" ? report.results.length : report.results.filter((r) => r.outcome === outcome).length}</strong></button>)}</div>
        <div className="campaign-coverage">{Object.entries(labels).map(([family, label]) => { const configured = report.results.filter((r) => r.family === family); return <span key={family} className={configured.length ? "configured" : "untested"}>{label}: {configured.length ? `${configured.length} configured` : "untested"}</span>; })}</div>
        {shown.length ? shown.map((row) => <article className={`campaign-result outcome-${row.outcome}`} key={row.scenario_id}>
          <div><span className="eyebrow">{labels[row.family] ?? row.family}</span><strong className="campaign-outcome">Reported {row.outcome.replaceAll("_", " ")}</strong></div>
          <h3>{row.rule}</h3><p>{row.reason.replaceAll("_", " ")} · Cleanup: {row.cleanup.replaceAll("_", " ")}</p>
          <details><summary>{row.checks.length} checks · {row.evidence.length} response observations</summary><ul>{row.checks.map((check) => <li key={check.id}>{check.id}: {check.outcome}</li>)}</ul>{row.evidence.map((evidence) => <p key={evidence.step_id}><strong>{evidence.step_id}</strong> · HTTP {evidence.status} · {evidence.bytes} bytes · {evidence.duration_ms} ms<br /><code>{evidence.sha256}</code></p>)}</details>
        </article>) : <p>No results match this filter.</p>}
      </> : <div className="campaign-empty">Load a local run report to see violations, held rules, inconclusive evidence and coverage.</div>}
    </section>
  </main>;
}
