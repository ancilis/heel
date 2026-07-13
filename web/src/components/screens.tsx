/* SPDX-License-Identifier: Apache-2.0 */
/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";
import { useState } from "react";
import { Panel, Stat, Tag, SevBadge, CatBadge, ReachBar, Verdict, Donut, HBars, CAT_COLOR, fmt, cx, catShort } from "@/lib/ui";

export function TargetToggle({ target, set }: { target: string; set: (t: string) => void }) {
  return (
    <div className="inline-flex rounded-lg border border-border overflow-hidden text-[12px]">
      {[["synthetic-saas", "non-AI SaaS"], ["synthetic-ai", "AI / agent"]].map(([k, label]) => (
        <button key={k} onClick={() => set(k)}
          className={cx("px-3 py-1.5", target === k ? "bg-accent/15 text-accent font-medium" : "text-dim hover:bg-panel2")}>{label}</button>
      ))}
    </div>
  );
}

function usdRange(range: number[] | undefined) {
  if (!range || range.length < 2) return "$--";
  return `$${range[0].toLocaleString()}-$${range[1].toLocaleString()}/mo`;
}

function uniqueValues(rows: any[], key: string) {
  return Array.from(new Set(rows.map(r => r[key]).filter(Boolean))).sort();
}

function FilterSelect({ label, value, options, set }: { label: string; value: string; options: string[]; set: (v: string) => void }) {
  return (
    <label className="text-[10px] uppercase tracking-wider text-muted">
      <span className="block mb-1">{label}</span>
      <select value={value} onChange={e => set(e.target.value)}
        className="bg-panel2 border border-border rounded-md px-2 py-1.5 text-[11px] text-text normal-case tracking-normal w-full">
        <option value="">all</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}

/* ============================== OVERVIEW ============================== */
export function Overview({ s, go }: { s: any; go: (k: string) => void }) {
  const ai = s.targets["synthetic-ai"].coverage, saas = s.targets["synthetic-saas"].coverage;
  const econ = s.economics || {};
  const tiles = [
    { k: "abuse-count", screen: "abuse", label: "What can customers game?", value: s.abuse_board?.ranked_findings?.length ?? s.targets["synthetic-ai"].findings.length, tone: "accent", sub: "ranked by reachability, severity, and dollars" },
    { k: "abuse-cost", screen: "abuse", label: "How much can it cost us?", value: usdRange(econ.total_estimated_monthly_exposure_usd), tone: "bad", sub: "directional monthly exposure" },
    { k: "controls", screen: "controls", label: "Which control stops most abuse?", value: s.controls?.recommended_bundle?.estimated_abuse_reduction ? `${Math.round(s.controls.recommended_bundle.estimated_abuse_reduction * 100)}%` : "—", tone: "ok", sub: s.controls?.recommended_bundle?.friction_cost },
    { k: "regressions", screen: "regressions", label: "Is this covered by regression?", value: `${s.regressions?.with_regression?.length ?? 0}/${(s.regressions?.with_regression?.length ?? 0) + (s.regressions?.without_regression?.length ?? 0)}`, tone: "warn", sub: s.regressions?.last_run_status },
    { k: "launch", screen: "launch", label: "Launch gate", value: (s.launch_review?.gate_status || "warn").toUpperCase(), tone: s.launch_review?.gate_status === "block" ? "bad" : "warn", sub: "changed surfaces + suggested regressions" },
    { k: "safety", screen: "safety", label: "Safety & Authorization", value: s.safety_authorization?.canary_only ? "CANARY" : "CHECK", tone: s.safety_authorization?.scope_mutation_path ? "bad" : "ok", sub: "No production probing; scopes read-only" },
  ];
  return (
    <div className="space-y-4">
      <Panel title="Arceo Abuse War Room" sub="Operator control room for safe SaaS abuse rehearsal: economics first, controls second, regression coverage always visible."
        right={<div className="flex gap-1"><Tag color="#34d399">synthetic</Tag><Tag color="#60a5fa">imported</Tag><Tag color="#fbbf24">staging</Tag></div>}>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5">
          {tiles.map(t => <button key={t.k} onClick={() => go(t.screen)} className="text-left"><Stat label={t.label} value={t.value} sub={t.sub} tone={(t as any).tone} /></button>)}
        </div>
      </Panel>
      <div className="grid md:grid-cols-2 gap-4">
        <Panel title="Safety spine (§10, non-negotiable)">
          <ul className="text-[12px] text-dim space-y-1.5 leading-relaxed">
            <li>• Scopes are <span className="text-text">human-only, out-of-band, signed, immutable</span>; the calling agent can run within one but never mint or widen it.</li>
            <li>• A prompt-injected caller is the <span className="text-text">confused deputy</span>: injected args are data, never instructions; every escalation is rejected + logged.</li>
            <li>• Findings are <span className="text-ok">contained, canary-only</span> PoCs — no real exfil/exhaustion; prohibited content is never generated (guardrails verified with benign canaries).</li>
            <li>• Plausibility-weighted · severity-honest · immutable hash-chained self-audit · lane discipline (<Tag color="#fb7185">appsec</Tag>/<Tag color="#a78bfa">model-redteam</Tag> handoffs).</li>
          </ul>
        </Panel>
        <Panel title="Operator framing">
          <div className="space-y-2 text-[12px] text-dim">
            <div><span className="text-text">Synthetic</span> mode is active in this snapshot. Imported and staging modes are visible operator states, not permission to run against production.</div>
            <div><span className="text-text">No production probing.</span> Real or imported target execution remains signed-scope gated, read-only from this UI, and canary-only.</div>
            <div>Benchmark evidence stays available below: synthetic wiring, blind eval, held-out eval, and containment history.</div>
            <div className="text-[11px] text-muted">Reference coverage still shows: AI self-consistency {Math.round(ai.coverage * 100)}%, non-AI category-10 findings {saas.category10_findings}.</div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

/* ============================== ABUSE BOARD ============================== */
export function AbuseBoard({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const [category, setCategory] = useState("");
  const [persona, setPersona] = useState("");
  const [pack, setPack] = useState("");
  const [productArea, setProductArea] = useState("");
  const allRows = s.abuse_board?.ranked_findings || [];
  const rows = allRows.filter((f: any) =>
    (!category || f.category === category) &&
    (!persona || f.persona === persona) &&
    (!pack || f.pack === pack) &&
    (!productArea || f.product_area === productArea)
  );
  return (
    <div className="space-y-4">
      <Panel title="Abuse Board" sub="Ranked by reachability, severity, and optional economic impact. Filter by category, persona, pack, and product area."
        right={<div className="flex items-center gap-2"><Tag color="#fb7185">{usdRange(s.economics?.top_estimated_monthly_range_usd)}</Tag><TargetToggle target={target} set={setTarget} /></div>}>
        <div className="grid sm:grid-cols-4 gap-2">
          <FilterSelect label="category" value={category} set={setCategory} options={s.abuse_board?.filters?.category || uniqueValues(allRows, "category")} />
          <FilterSelect label="persona" value={persona} set={setPersona} options={s.abuse_board?.filters?.persona || uniqueValues(allRows, "persona")} />
          <FilterSelect label="pack" value={pack} set={setPack} options={s.abuse_board?.filters?.pack || uniqueValues(allRows, "pack")} />
          <FilterSelect label="product area" value={productArea} set={setProductArea} options={s.abuse_board?.filters?.product_area || uniqueValues(allRows, "product_area")} />
        </div>
      </Panel>
      <Panel title="Ranked abuse queue" sub={`${rows.length} visible of ${allRows.length} finding(s). Dollar severity leads the row; CVSS is intentionally absent.`}>
        <div className="space-y-1.5">
          {rows.map((f: any) => (
            <div key={`${f.target_id}:${f.id}`} className="rounded-lg border border-border bg-panel2/40">
              <button onClick={() => setOpen(open === f.id ? null : f.id)} className="w-full flex items-center gap-2 px-3 py-2 text-left">
                <Tag color="#fb7185" solid>{usdRange(f.economic_impact?.estimated_monthly_range_usd)}</Tag>
                <SevBadge s={f.severity.label} />
                <span className="tabnum text-[12px] text-text flex-1 truncate">{f.affordance_id}</span>
                <CatBadge c={f.category} />
                <Tag color="#34d399">{f.persona}</Tag>
                <ReachBar r={f.reachability_score} plausible={f.plausible} />
                <span className="tabnum text-[11px] text-muted w-10 text-right">{f.rank_score}</span>
              </button>
              {open === f.id && (
                <div className="px-3 pb-3 pt-1 border-t border-border/60 text-[12px] space-y-2">
                  <div className="text-dim">{(s.scenarios.find((x: any) => x.id === f.scenario_id) || {}).objective || f.scenario_id}</div>
                  <div className="grid sm:grid-cols-3 gap-2">
                    <div className="rounded-md bg-panel border border-border p-2">
                      <div className="text-[10px] uppercase text-muted mb-1">economic assumption</div>
                      <div className="text-[12px] text-text">{f.economic_impact?.assumption}</div>
                      <div className="tabnum text-[11px] text-muted mt-1">{f.economic_impact?.confidence}</div>
                    </div>
                    <div className="rounded-md bg-panel border border-border p-2">
                      <div className="text-[10px] uppercase text-muted mb-1">surface</div>
                      <div className="tabnum text-[11px] text-dim">target: {f.target_id}</div>
                      <div className="tabnum text-[11px] text-dim">pack: {f.pack}</div>
                      <div className="text-[11px] text-dim">area: {f.product_area}</div>
                    </div>
                    <div className="rounded-md bg-panel border border-border p-2">
                      <div className="text-[10px] uppercase text-muted mb-1">recommended control</div>
                      <div className="text-[12px] text-text">{f.recommended_control}</div>
                      <div className="text-[11px] text-muted mt-1">reduction: <span className="text-ok tabnum">{fmt(f.estimated_exploitability_reduction, 2)}</span></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ============================== LAUNCH REVIEW ============================== */
export function LaunchReview({ s }: { s: any }) {
  const lr = s.launch_review;
  return (
    <div className="space-y-4">
      <Panel title="Launch Review" sub="Changed surfaces, pass/warn/block gate, and the regressions operators should add before launch."
        right={<Tag color={lr.gate_status === "block" ? "#fb7185" : "#fbbf24"} solid>{lr.gate_status.toUpperCase()}</Tag>}>
        <div className="grid md:grid-cols-3 gap-2">
          {lr.changed_surfaces.map((surface: any) => (
            <div key={surface.surface} className="rounded-lg border border-border bg-panel2/50 p-3">
              <div className="text-[12px] text-text font-medium">{surface.surface}</div>
              <div className="text-[11px] text-muted mt-1">{surface.product_area}</div>
              <div className="text-[11px] text-warn mt-2">{surface.risk}</div>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Suggested regressions" sub="Drafts only; they become active after operator review.">
        <div className="space-y-1.5">
          {lr.suggested_regressions.map((r: any) => (
            <div key={r.finding_id} className="flex items-center gap-2 rounded-md border border-border bg-panel2/40 px-3 py-2">
              <Tag color="#34d399">candidate</Tag>
              <span className="tabnum text-[12px] text-text">{r.scenario_id}</span>
              <span className="tabnum text-[11px] text-muted ml-auto">{r.finding_id}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ============================== EXISTING PRODUCT REVIEW ============================== */
export function ExistingProductReview({ s }: { s: any }) {
  const ep = s.existing_product;
  return (
    <div className="space-y-4">
      <Panel title="Existing Product Review" sub="Imported model summary, entitlement graph risks, and explicit mode state."
        right={<div className="flex gap-1">{ep.mode_indicator.available_modes.map((m: string) => <Tag key={m} color={m === ep.mode_indicator.active_mode ? "#34d399" : "#60a5fa"}>{m}</Tag>)}</div>}>
        <div className="grid md:grid-cols-3 gap-2">
          <Stat label="active mode" value={ep.mode_indicator.active_mode} tone="ok" sub={ep.mode_indicator.note} />
          <Stat label="surfaces" value={ep.imported_model_summary.surfaces.length} sub={ep.imported_model_summary.name} />
          <Stat label="data mode" value={ep.imported_model_summary.data_mode} sub="canary-only rehearsal" />
        </div>
      </Panel>
      <Panel title="Entitlement graph risks">
        <div className="space-y-1.5">
          {ep.entitlement_graph_risks.map((risk: any) => (
            <div key={risk.node} className="grid md:grid-cols-[220px_1fr_140px] gap-2 rounded-md border border-border bg-panel2/40 px-3 py-2 text-[12px]">
              <span className="tabnum text-accent">{risk.node}</span>
              <span className="text-dim">{risk.risk}</span>
              <CatBadge c={risk.category} />
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ============================== CONTROL SIMULATOR ============================== */
export function ControlSimulator({ s }: { s: any }) {
  const controls = s.controls;
  return (
    <div className="space-y-4">
      <Panel title="Control Simulator" sub="Candidate controls ranked by abuse reduction and friction cost."
        right={<Tag color="#34d399" solid>{Math.round(controls.recommended_bundle.estimated_abuse_reduction * 100)}% bundle</Tag>}>
        <div className="grid md:grid-cols-3 gap-2 mb-3">
          <Stat label="recommended bundle" value={controls.recommended_bundle.name} tone="ok" sub={controls.recommended_bundle.friction_cost} />
          <Stat label="controls" value={controls.recommended_bundle.controls.length} />
          <Stat label="friction" value={controls.recommended_bundle.friction_cost} tone="warn" />
        </div>
        <div className="space-y-1.5">
          {controls.candidate_controls.map((c: any, i: number) => (
            <div key={`${c.control}-${i}`} className="rounded-md border border-border bg-panel2/40 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="text-[12px] text-text flex-1">{c.control}</span>
                <Tag color="#34d399">{Math.round(c.estimated_abuse_reduction * 100)}% reduction</Tag>
                <Tag color={c.friction_cost === "low" ? "#34d399" : "#fbbf24"}>{c.friction_cost} friction</Tag>
              </div>
              <div className="text-[10px] text-muted mt-1">{c.notes}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ============================== REGRESSION COVERAGE ============================== */
export function RegressionCoverage({ s }: { s: any }) {
  const regs = s.regressions;
  return (
    <div className="space-y-4">
      <Panel title="Regression Coverage" sub="Which findings are now permanent canary-only abuse regressions."
        right={<Tag color="#34d399">{regs.last_run_status}</Tag>}>
        <div className="grid md:grid-cols-2 gap-3">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">findings with regression</div>
            {regs.with_regression.map((f: any) => <CoverageRow key={f.id} f={f} covered />)}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">findings without regression</div>
            {regs.without_regression.map((f: any) => <CoverageRow key={f.id} f={f} />)}
          </div>
        </div>
        <div className="text-[11px] text-muted mt-3">{regs.coverage_note}</div>
      </Panel>
    </div>
  );
}

function CoverageRow({ f, covered }: { f: any; covered?: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-border bg-panel2/40 px-3 py-2 mb-1">
      <Tag color={covered ? "#34d399" : "#fbbf24"}>{covered ? "covered" : "gap"}</Tag>
      <span className="tabnum text-[11px] text-text truncate">{f.scenario_id}</span>
      <span className="ml-auto"><CatBadge c={f.category} /></span>
    </div>
  );
}

/* ============================== INCIDENT LIBRARY ============================== */
export function IncidentLibrary({ s }: { s: any }) {
  const incidents = s.incidents;
  return (
    <div className="space-y-4">
      <Panel title="Incident Library" sub="Sanitized incidents, generated scenarios, and generated canary-only regressions. Nothing auto-enables.">
        <div className="grid md:grid-cols-3 gap-3">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">sanitized incidents</div>
            {incidents.sanitized_incidents.map((i: any) => (
              <div key={i.incident_id} className="rounded-md border border-border bg-panel2/40 p-2 mb-1">
                <div className="tabnum text-[12px] text-text">{i.incident_id}</div>
                <div className="text-[11px] text-dim mt-1">{i.summary}</div>
                <Tag color={i.prohibited_fields_removed_confirmed ? "#34d399" : "#fb7185"}>sanitized</Tag>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">generated scenarios</div>
            {incidents.generated_scenarios.map((sc: any) => (
              <div key={sc.scenario_id} className="rounded-md border border-border bg-panel2/40 p-2 mb-1">
                <div className="tabnum text-[12px] text-text">{sc.scenario_id}</div>
                <CatBadge c={sc.category} /> <Tag color="#fbbf24">draft</Tag>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">generated regressions</div>
            {incidents.generated_regressions.map((r: any) => (
              <div key={r.regression_id} className="rounded-md border border-border bg-panel2/40 p-2 mb-1">
                <div className="tabnum text-[12px] text-text">{r.regression_id}</div>
                <Tag color="#34d399">{r.evidence_mode}</Tag>
              </div>
            ))}
          </div>
        </div>
      </Panel>
    </div>
  );
}

/* ============================== SAFETY & AUTHORIZATION ============================== */
export function SafetyAuthorization({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const safety = s.safety_authorization;
  return (
    <div className="space-y-4">
      <Panel title="Safety & Authorization" sub="Signed scope status, read-only scope panel, containment chain, canary-only status, and no scope mutation path."
        right={<div className="flex gap-1"><Verdict pass={!safety.scope_mutation_path} labels={["no mutation path", "mutation path"]} /><TargetToggle target={target} set={setTarget} /></div>}>
        <div className="grid md:grid-cols-4 gap-2">
          <Stat label="signed scope" value={safety.signed_scope_status} tone="ok" />
          <Stat label="scope panel" value={safety.scope_panel.read_only ? "read-only" : "mutable"} tone={safety.scope_panel.read_only ? "ok" : "bad"} />
          <Stat label="containment" value={safety.containment_log.chain_valid ? "valid" : "broken"} tone={safety.containment_log.chain_valid ? "ok" : "bad"} sub={safety.containment_log.chain_status} />
          <Stat label="evidence mode" value={safety.canary_only ? "canary-only" : "check"} tone={safety.canary_only ? "ok" : "bad"} />
        </div>
        <div className="rounded-md border border-ok/30 bg-ok/5 p-2 mt-3 text-[11px] text-dim">{safety.mode_note}</div>
      </Panel>
      <AuthGate s={s} />
    </div>
  );
}

/* ============================== BACKTEST ============================== */
function BacktestRow({ c }: { c: any }) {
  return (
    <Panel title={c.target} sub={`${c.kind} · ${c.true_positives} TP / ${c.false_negatives} FN / ${c.false_positives} FP`}>
      <div className="flex items-center gap-4">
        <Donut value={c.coverage} color={c.coverage >= 0.9 ? "#34d399" : "#fbbf24"} label="coverage" />
        <div className="flex-1 grid grid-cols-2 gap-2">
          <Stat label="false-positive rate" value={fmt(c.false_positive_rate, 2)} tone={c.false_positive_rate <= 0.1 ? "ok" : "warn"} />
          <Stat label="severity calibration" value={fmt(c.severity_calibration, 2)} />
          <Stat label="category-10 findings" value={c.category10_findings} tone={c.has_agent_surface ? "text" : (c.category10_findings === 0 ? "ok" : "bad")} sub={c.has_agent_surface ? "AI target" : "must be 0 (optional)"} />
          <Stat label="implausible demoted" value={c.implausible_flagged} sub="plausibility-weighting" />
        </div>
      </div>
      <div className="mt-2 text-[11px] text-muted">missed (honest FN): {c.missed.map((m: any) => m.affordance).join(", ") || "—"} · discovered: {c.discovered_scenarios.join(", ")}</div>
    </Panel>
  );
}

export function Backtest({ s }: { s: any }) {
  const saas = s.targets["synthetic-saas"].coverage, ai = s.targets["synthetic-ai"].coverage;
  return (
    <div className="space-y-4">
      <Panel title="Planted-vector self-consistency backtest" sub="Coverage / FP / severity-calibration on the two synthetic targets. Category 10 cleanly yields nothing on the non-AI target — proving it is optional.">
        <div className="rounded-md border border-warn/30 bg-warn/5 p-2 text-[11px] text-dim">{saas.caveat}</div>
      </Panel>
      <div className="grid md:grid-cols-2 gap-4"><BacktestRow c={saas} /><BacktestRow c={ai} /></div>
    </div>
  );
}

/* ============================== BLIND EVAL ============================== */
export function BlindEval({ s }: { s: any }) {
  const b = s.blind_eval, ai = s.targets["synthetic-ai"].coverage.coverage;
  return (
    <div className="space-y-4">
      <Panel title="Blind-target evaluation — the honest real-detection metric"
        sub="Planted weaknesses use encodings authored independently of the seed probes (arceo/blind.py). Parallel fan-out over many blind targets. This is real detection accuracy — NOT the self-consistency coverage.">
        <div className="flex items-center gap-6 flex-wrap">
          <div className="text-center">
            <Donut value={b.real_recall_pooled} color="#fb7185" label="real recall" />
            <div className="text-[10px] text-muted tabnum mt-1">95% CI [{b.real_recall_wilson_ci95.join(", ")}]</div>
          </div>
          <div className="text-center">
            <Donut value={ai} color="#34d399" label="self-consist." />
            <div className="text-[10px] text-muted tabnum mt-1">wiring metric</div>
          </div>
          <div className="flex-1 grid grid-cols-2 gap-2 min-w-[280px]">
            <Stat label="real precision" value={fmt(b.real_precision_pooled, 2)} tone="accent" />
            <Stat label="false-positive rate" value={fmt(b.false_positive_rate_mean, 2)} />
            <Stat label="found / planted" value={`${b.total_found}/${b.total_planted}`} tone="bad" sub={`${b.total_missed} missed (unanticipated encodings)`} />
            <Stat label="cat-10 clean (blind non-AI)" value={b.category10_clean_on_non_ai} tone="ok" sub="verified, not structural" />
          </div>
        </div>
        <div className="mt-3 rounded-md border border-bad/30 bg-bad/5 p-2 text-[11px] text-dim">measured encoding-overlap {b.encoding_overlap.overlap} · {b.real_recall_is}</div>
        <div className="mt-2 text-[11px] text-muted">fan-out: {b.fan_out} ({b.workers} workers, {b.n_targets} targets). Real recall rises as the library&apos;s encoding breadth grows — that is the honest improvement axis.</div>
      </Panel>
    </div>
  );
}

/* ============================== HELD-OUT (independent authorship) ============================== */
export function HeldOut({ s }: { s: any }) {
  const h = s.heldout_eval, dev = h.dev || h, test = h.test || h;
  const tsem = test.with_semantic, tex = test.exact_match;
  return (
    <div className="space-y-4">
      <Panel title="Held-out evaluation — independently-authored targets (the strongest honesty test)"
        sub="Targets authored by a separate LLM swarm given only the abuse taxonomy — blind to Arceo's probe vocabulary (docs/HELDOUT_PROVENANCE.md). Proper dev/test discipline: the semantic catalog was tuned on DEV; the TEST split was frozen and never inspected — its number is the unbiased one.">
        <div className="flex items-center gap-6 flex-wrap">
          <div className="text-center"><Donut value={tex.recall} color="#6b7280" label="exact (test)" />
            <div className="text-[10px] text-muted tabnum mt-1">{tex.found}/{tex.planted}</div></div>
          <div className="text-2xl text-muted">→</div>
          <div className="text-center"><Donut value={tsem.recall} color="#34d399" label="semantic (test)" />
            <div className="text-[10px] text-muted tabnum mt-1">CI [{tsem.wilson_ci95.join(", ")}]</div></div>
          <div className="flex-1 grid grid-cols-2 gap-2 min-w-[260px]">
            <Stat label="localization recall" value={fmt(tsem.recall, 2)} tone="ok" sub={`right affordance · cluster-CI [${tsem.recall_cluster_ci95.join(", ")}]`} />
            <Stat label="attribution recall" value={fmt(tsem.attribution_recall, 2)} tone="warn" sub={`+ right category · CI [${tsem.attribution_cluster_ci95.join(", ")}]`} />
            <Stat label="TEST precision" value={fmt(tsem.precision, 2)} tone="accent" sub={`CI [${tsem.precision_cluster_ci95.join(", ")}]`} />
            <Stat label="overfitting gap" value={`${Math.round((dev.with_semantic.recall - tsem.recall) * 100)}pp`} tone="warn" sub={`dev ${fmt(dev.with_semantic.recall, 2)} − test, shown`} />
          </div>
        </div>
        <div className="mt-3 text-[11px] text-dim">Two honest gaps shown, not hidden: <span className="text-text">dev→test</span> (overfitting) and <span className="text-text">localization→attribution</span> (~{Math.round((1 - tsem.attribution_recall / Math.max(tsem.recall, 0.01)) * 100)}% of flagged affordances get the wrong category). Exact matching barely generalizes (test {fmt(tex.recall, 2)}); semantic families recover ~{Math.round(tsem.recall / Math.max(tex.recall, 0.01))}× — only by widening real-vocabulary coverage, never by writing probes against known plants. CIs are target-level cluster bootstraps. Not near 1.0 — the honest ceiling.</div>
      </Panel>
      <Panel title="TEST recall by category (unbiased)" sub="Where Arceo generalizes vs where it has gaps, on targets it never saw.">
        <HBars items={Object.entries(tsem.recall_by_category).map(([c, v]) => {
          const [f, t] = (v as string).split("/").map(Number);
          return { label: catShort(c), value: t ? Math.round((f / t) * 100) : 0, color: CAT_COLOR[c], tag: <span className="tabnum text-[10px] text-muted w-10">{v as string}</span> };
        })} max={100} />
      </Panel>
    </div>
  );
}

/* ============================== LIVE SWARM ============================== */
export function LiveSwarm({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const sw = s.targets[target].swarm;
  return (
    <Panel title="Live swarm monitor" sub={`${sw.length} probe actions — adversarial + opportunistic agents and where each is probing.`}
      right={<div className="flex items-center gap-2"><span className="flex items-center gap-1.5 text-[11px] text-ok"><span className="live-dot w-1.5 h-1.5 rounded-full bg-ok inline-block" />running</span><TargetToggle target={target} set={setTarget} /></div>}>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {sw.map((a: any, i: number) => (
          <div key={i} className="rounded-lg border border-border bg-panel2/40 p-2.5">
            <div className="flex items-center justify-between">
              <Tag color={a.klass === "opportunistic" ? "#34d399" : "#f59e0b"}>{a.klass}</Tag>
              <span className="inline-block w-1.5 h-1.5 rounded-full live-dot" style={{ background: a.fired ? "#fb7185" : "#6b7280" }} />
            </div>
            <div className="tabnum text-[11px] text-text mt-1.5 truncate">{a.affordance || "—"}</div>
            <div className="tabnum text-[10px] text-muted truncate">{a.scenario}</div>
            <div className="text-[10px] mt-1" style={{ color: a.fired ? "#fb7185" : "#6b7280" }}>{a.action}{a.fired ? " · HIT" : ""}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ============================== SCOPES ============================== */
export function Scopes({ s }: { s: any }) {
  return (
    <Panel title="Authorization scopes" sub="Read-only. Scope creation/widening is human-only, out-of-band (CLI + --confirm) — the UI and every API cannot mint or widen a scope.">
      {s.scopes.map((sc: any, i: number) => (
        <div key={i} className="rounded-lg border border-border bg-panel2/40 p-3 mb-2">
          <div className="flex items-center justify-between">
            <span className="tabnum text-[13px] text-text">{sc.scope_id}</span>
            <Tag color="#34d399">signature {sc.signature}</Tag>
          </div>
          <div className="grid sm:grid-cols-2 gap-x-4 gap-y-0.5 mt-2 text-[11px] text-dim tabnum">
            <div>allowlist: <span className="text-text">{sc.target_allowlist.join(", ")}</span></div>
            <div>approver: <span className="text-text">{sc.operator_confirmation}</span></div>
            <div>limits: {JSON.stringify(sc.rate_and_resource_limits)}</div>
            <div>data mode: {sc.data_handling_mode}</div>
          </div>
        </div>
      ))}
      <div className="text-[11px] text-muted mt-1">To create a scope: <code className="text-accent">arceo scope create --target … --operator you --confirm</code></div>
    </Panel>
  );
}

/* ============================== CONTAINMENT ============================== */
export function Containment({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const t = s.targets[target];
  const color: Record<string, string> = { probe: "#6b7280", finding: "#fb7185", run_start: "#60a5fa", run_complete: "#34d399",
    handoff: "#a78bfa", opportunistic_probe: "#34d399", discovered_scenario: "#f59e0b", reject_run: "#ef4444", reject_unknown_tool: "#ef4444" };
  return (
    <Panel title="Containment log" sub="Immutable, hash-chained (HMAC) record of exactly what Arceo did — with the invoking caller. Tamper-evident."
      right={<div className="flex items-center gap-2"><Verdict pass={t.containment_valid} labels={["chain valid", "broken"]} /><TargetToggle target={target} set={setTarget} /></div>}>
      <div className="space-y-0.5 max-h-[60vh] overflow-y-auto">
        {t.containment.map((e: any, i: number) => (
          <div key={i} className="flex items-center gap-2 text-[11px] tabnum border-b border-border/30 py-1">
            <span className="text-muted w-8">#{e.seq}</span>
            <Tag color={color[e.action] || "#6b7280"}>{e.action}</Tag>
            <span className="text-dim flex-1 truncate">{typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}</span>
            <span className="text-muted">{e.caller}</span>
            <span className="text-muted/60 w-16 truncate" title={e.entry_hash}>{(e.entry_hash || "").slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ============================== INTEGRATION ============================== */
export function Integration({ s }: { s: any }) {
  return (
    <div className="space-y-4">
      <div className="grid md:grid-cols-3 gap-3">
        <Stat label="MCP server" value={`${s.meta.server} v${s.meta.version}`} tone="accent" />
        <Stat label="tools exposed" value={s.meta.tools.length} sub="consumption/execution only" />
        <Stat label="discovery model" value={s.meta.model} sub="swappable: ARCEO_MODEL=anthropic" />
      </div>
      <Panel title="Registered MCP tool schema" sub="No scope-creation/widening tool exists — by construction (§10.1).">
        <div className="space-y-1.5">
          {s.meta.tool_schemas.map((tl: any) => (
            <div key={tl.name} className="rounded-md border border-border bg-panel2/40 px-3 py-2">
              <div className="flex items-center gap-2"><span className="tabnum text-[12px] text-accent">{tl.name}</span></div>
              <div className="text-[11px] text-muted mt-0.5">{tl.description}</div>
            </div>
          ))}
          {["arceo_create_scope", "arceo_widen_scope"].map(n => (
            <div key={n} className="rounded-md border border-bad/30 bg-bad/5 px-3 py-1.5 text-[11px] text-bad tabnum">
              ✗ {n} — absent by construction (human-only, out-of-band)
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ============================== AUTH GATE ============================== */
export function AuthGate({ s }: { s: any }) {
  return (
    <Panel title="Authorization gate" sub="The calling agent is an untrusted, possibly prompt-injected channel. Every escalation attempt over the MCP/REST surface is rejected and logged."
      right={<Verdict pass={s.auth_gate.all_rejected} />}>
      <div className="space-y-1.5">
        {s.auth_gate.attempts.map((a: any, i: number) => (
          <div key={i} className="flex items-start gap-2 rounded-md border border-border bg-panel2/40 px-3 py-2">
            <Tag color={a.rejected ? "#34d399" : "#fb7185"}>{a.rejected ? "REJECTED + logged" : "NOT REJECTED"}</Tag>
            <div className="flex-1">
              <div className="text-[12px] text-text">{a.label}</div>
              {a.message && <div className="text-[10px] text-muted tabnum mt-0.5 truncate">{a.message}</div>}
            </div>
          </div>
        ))}
      </div>
      <div className="text-[11px] text-muted mt-2">containment hash-chain: {s.auth_gate.chain_status}</div>
    </Panel>
  );
}

/* ============================== SCENARIOS ============================== */
export function Scenarios({ s }: { s: any }) {
  const byCat: Record<string, any[]> = {};
  for (const sc of s.scenarios) (byCat[sc.category] ||= []).push(sc);
  return (
    <Panel title="Scenario library" sub={`${s.meta.n_scenarios} scenarios across ${s.meta.categories.length} categories (${s.meta.n_json_scenarios} from JSON — addable without code). §4.10 agent pack applies only to agent targets.`}>
      <div className="grid md:grid-cols-2 gap-3">
        {Object.keys(byCat).sort().map(cat => (
          <div key={cat} className="rounded-lg border border-border bg-panel2/30 p-3">
            <div className="flex items-center gap-2 mb-1.5"><span className="w-2 h-2 rounded-full" style={{ background: CAT_COLOR[cat] }} /><CatBadge c={cat} /><span className="text-[10px] text-muted">{byCat[cat].length}</span></div>
            <ul className="space-y-1">
              {byCat[cat].map((sc: any) => (
                <li key={sc.id} className="text-[11px] text-dim flex items-center gap-1.5">
                  <span className="flex-1">{sc.objective}</span>
                  {sc.applies_when === "has_agent_surface" && <Tag color="#ef4444">agent</Tag>}
                  {sc.handoff && <Tag color="#a78bfa">→{sc.handoff}</Tag>}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Panel>
  );
}
