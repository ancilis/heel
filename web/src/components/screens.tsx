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

/* ============================== OVERVIEW ============================== */
export function Overview({ s, go }: { s: any; go: (k: string) => void }) {
  const ai = s.targets["synthetic-ai"].coverage, saas = s.targets["synthetic-saas"].coverage;
  const tiles = [
    { k: "abuse", label: "Abuse vectors (AI target)", value: s.targets["synthetic-ai"].findings.length, tone: "accent", sub: "ranked, reachability-weighted" },
    { k: "backtest", label: "Self-consistency coverage", value: `${Math.round(ai.coverage * 100)}%`, tone: "ok", sub: `FP ${ai.false_positive_rate} · cat-10 cleanly ${saas.category10_findings} on non-AI` },
    { k: "auth", label: "Authorization gate", value: s.auth_gate.all_rejected ? "PASS" : "FAIL", tone: s.auth_gate.all_rejected ? "ok" : "bad", sub: "every escalation rejected + logged" },
    { k: "integration", label: "MCP tools exposed", value: s.meta.tools.length, sub: "no scope-mutation tool, by design" },
    { k: "scenarios", label: "Scenario library", value: s.meta.n_scenarios, sub: `${s.meta.categories.length} categories · model: ${s.meta.model}` },
    { k: "swarm", label: "Agent classes", value: "2", tone: "accent", sub: "adversarial + opportunistic-human" },
  ];
  return (
    <div className="space-y-4">
      <Panel title="HEEL" sub="Rehearse how a customer or third party could abuse your product — before it ships.">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5">
          {tiles.map(t => <button key={t.k} onClick={() => go(t.k)} className="text-left"><Stat label={t.label} value={t.value} sub={t.sub} tone={(t as any).tone} /></button>)}
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
        <Panel title="Honest framing">
          <div className="space-y-2 text-[12px] text-dim">
            <div>The coverage number is a <span className="text-warn">self-consistency / wiring</span> metric on synthetic targets (seed probes + planted weaknesses authored together) — <span className="text-text">not</span> real-target accuracy.</div>
            <div>Honest signals: a genuine miss (<span className="tabnum">ato_chain</span>, found by neither class), a decoy false positive, a plausibility-demoted degenerate, a swarm-discovered scenario, and lane handoffs.</div>
            <div>Both agent classes matter: coupon-stacking is a blind spot for the programmatic class, <span className="text-text">closed by the opportunistic-human class</span>.</div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

/* ============================== ABUSE BOARD ============================== */
export function AbuseBoard({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const t = s.targets[target];
  const byCat: Record<string, any[]> = {};
  for (const f of t.findings) (byCat[f.category] ||= []).push(f);
  const cats = Object.keys(byCat).sort((a, b) => Math.max(...byCat[b].map(f => f.severity.score)) - Math.max(...byCat[a].map(f => f.severity.score)));
  return (
    <div className="space-y-4">
      <Panel title="Abuse board" sub="Vectors ranked by severity, grouped by category. Reachability-weighted — implausible findings demoted, not hidden."
        right={<TargetToggle target={target} set={setTarget} />}>
        <div className="flex flex-wrap gap-2 text-[11px] text-muted mb-1">
          <span>{t.findings.length} vectors</span><span>·</span>
          <span>{t.coverage.opportunistic_findings} from the opportunistic-human class</span><span>·</span>
          <span>handoffs: {JSON.stringify(t.coverage.handoffs.map((h: any) => h.handoff))}</span>
        </div>
      </Panel>
      {cats.map(cat => (
        <Panel key={cat} title={catShort(cat)} sub={`${byCat[cat].length} vector(s)`}
          right={<span className="w-2.5 h-2.5 rounded-full" style={{ background: CAT_COLOR[cat] }} />}>
          <div className="space-y-1.5">
            {byCat[cat].sort((a, b) => b.severity.score - a.severity.score).map((f: any) => (
              <div key={f.id} className="rounded-lg border border-border bg-panel2/40">
                <button onClick={() => setOpen(open === f.id ? null : f.id)} className="w-full flex items-center gap-2 px-3 py-2 text-left">
                  <SevBadge s={f.severity.label} />
                  <span className="tabnum text-[12px] text-text flex-1 truncate">{f.affordance_id}</span>
                  {f.klass === "opportunistic_human" && <Tag color="#34d399">human</Tag>}
                  {f.handoff_to_appsec && <Tag color="#fb7185">→ appsec</Tag>}
                  <ReachBar r={f.reachability_score} plausible={f.plausible} />
                  <span className="tabnum text-[11px] text-muted w-10 text-right">{f.severity.score}</span>
                </button>
                {open === f.id && (
                  <div className="px-3 pb-3 pt-1 border-t border-border/60 text-[12px] space-y-2">
                    <div className="text-dim">{(s.scenarios.find((x: any) => x.id === f.scenario_id) || {}).objective || f.scenario_id}</div>
                    <div className="grid sm:grid-cols-2 gap-2">
                      <div className="rounded-md bg-panel border border-border p-2">
                        <div className="text-[10px] uppercase text-muted mb-1">contained PoC</div>
                        <div className="tabnum text-[11px] text-dim">strategy: {f.reproduction.strategy}</div>
                        <div className="tabnum text-[11px] text-dim">sample: <span className="text-ok">{f.reproduction.sample}</span> · contained: {String(f.reproduction.contained)}</div>
                        {f.reproduction.profiles && <div className="tabnum text-[11px] text-dim">profiles: {f.reproduction.profiles.join(", ")}</div>}
                      </div>
                      <div className="rounded-md bg-panel border border-border p-2">
                        <div className="text-[10px] uppercase text-muted mb-1">recommended control</div>
                        <div className="text-[12px] text-text">{f.recommended_control}</div>
                        <div className="text-[11px] text-muted mt-1">est. exploitability reduction: <span className="text-ok tabnum">{fmt(f.estimated_exploitability_reduction, 2)}</span></div>
                      </div>
                    </div>
                    {f.classification_impact && (
                      <div className="rounded-md border border-info/30 bg-info/5 p-2">
                        <div className="text-[10px] uppercase text-info mb-1">classification annotation (optional, ON)</div>
                        <div className="text-[11px] text-dim">data classes: {(f.classification_impact.data_classes || []).join(", ")}</div>
                        <div className="text-[11px] text-dim">obligations: {(f.obligation_impact?.obligations || []).join(", ")}</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      ))}
    </div>
  );
}

/* ============================== BACKTEST ============================== */
export function Backtest({ s }: { s: any }) {
  const saas = s.targets["synthetic-saas"].coverage, ai = s.targets["synthetic-ai"].coverage;
  const Row = ({ c }: { c: any }) => (
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
  return (
    <div className="space-y-4">
      <Panel title="Planted-vector self-consistency backtest" sub="Coverage / FP / severity-calibration on the two synthetic targets. Category 10 cleanly yields nothing on the non-AI target — proving it is optional.">
        <div className="rounded-md border border-warn/30 bg-warn/5 p-2 text-[11px] text-dim">{saas.caveat}</div>
      </Panel>
      <div className="grid md:grid-cols-2 gap-4"><Row c={saas} /><Row c={ai} /></div>
    </div>
  );
}

/* ============================== BLIND EVAL ============================== */
export function BlindEval({ s }: { s: any }) {
  const b = s.blind_eval, ai = s.targets["synthetic-ai"].coverage.coverage;
  return (
    <div className="space-y-4">
      <Panel title="Blind-target evaluation — the honest real-detection metric"
        sub="Planted weaknesses use encodings authored independently of the seed probes (heel/blind.py). Parallel fan-out over many blind targets. This is real detection accuracy — NOT the self-consistency coverage.">
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
        <div className="mt-2 text-[11px] text-muted">fan-out: {b.fan_out} ({b.workers} workers, {b.n_targets} targets). Real recall rises as the library's encoding breadth grows — that is the honest improvement axis.</div>
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
        sub="Targets authored by a separate LLM swarm given only the abuse taxonomy — blind to HEEL's probe vocabulary (docs/HELDOUT_PROVENANCE.md). Proper dev/test discipline: the semantic catalog was tuned on DEV; the TEST split was frozen and never inspected — its number is the unbiased one.">
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
      <Panel title="TEST recall by category (unbiased)" sub="Where HEEL generalizes vs where it has gaps, on targets it never saw.">
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
      <div className="text-[11px] text-muted mt-1">To create a scope: <code className="text-accent">heel scope create --target … --operator you --confirm</code></div>
    </Panel>
  );
}

/* ============================== CONTAINMENT ============================== */
export function Containment({ s, target, setTarget }: { s: any; target: string; setTarget: (t: string) => void }) {
  const t = s.targets[target];
  const color: Record<string, string> = { probe: "#6b7280", finding: "#fb7185", run_start: "#60a5fa", run_complete: "#34d399",
    handoff: "#a78bfa", opportunistic_probe: "#34d399", discovered_scenario: "#f59e0b", reject_run: "#ef4444", reject_unknown_tool: "#ef4444" };
  return (
    <Panel title="Containment log" sub="Immutable, hash-chained (HMAC) record of exactly what HEEL did — with the invoking caller. Tamper-evident."
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
        <Stat label="discovery model" value={s.meta.model} sub="swappable: HEEL_MODEL=anthropic" />
      </div>
      <Panel title="Registered MCP tool schema" sub="No scope-creation/widening tool exists — by construction (§10.1).">
        <div className="space-y-1.5">
          {s.meta.tool_schemas.map((tl: any) => (
            <div key={tl.name} className="rounded-md border border-border bg-panel2/40 px-3 py-2">
              <div className="flex items-center gap-2"><span className="tabnum text-[12px] text-accent">{tl.name}</span></div>
              <div className="text-[11px] text-muted mt-0.5">{tl.description}</div>
            </div>
          ))}
          {["heel_create_scope", "heel_widen_scope"].map(n => (
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
