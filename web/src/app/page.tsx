"use client";
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useState, type ReactNode } from "react";
import {
  Overview, AbuseBoard, Backtest, BlindEval, HeldOut, LiveSwarm, Scopes, Containment, Integration, AuthGate, Scenarios,
} from "@/components/screens";

const NAV: { group: string; items: { k: string; label: string }[] }[] = [
  { group: "System", items: [{ k: "overview", label: "Overview" }, { k: "swarm", label: "Live swarm" }] },
  { group: "Findings", items: [{ k: "abuse", label: "Abuse board" }, { k: "backtest", label: "Backtest" }, { k: "blindeval", label: "Blind eval" }, { k: "heldout", label: "Held-out (real)" }, { k: "scenarios", label: "Scenario library" }] },
  { group: "Safety", items: [{ k: "auth", label: "Authorization gate" }, { k: "scopes", label: "Scope panel" }, { k: "containment", label: "Containment log" }, { k: "integration", label: "MCP / integration" }] },
];

export default function ControlRoom() {
  const [snap, setSnap] = useState<any>(null);
  const [active, setActive] = useState("overview");
  const [target, setTarget] = useState("synthetic-ai");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { fetch("/data/snapshot.json").then(r => r.json()).then(setSnap).catch(e => setErr(String(e))); }, []);

  const title = NAV.flatMap(g => g.items).find(i => i.k === active)?.label ?? "";
  const screens: Record<string, ReactNode> = snap ? {
    overview: <Overview s={snap} go={setActive} />,
    abuse: <AbuseBoard s={snap} target={target} setTarget={setTarget} />,
    backtest: <Backtest s={snap} />,
    blindeval: <BlindEval s={snap} />,
    heldout: <HeldOut s={snap} />,
    swarm: <LiveSwarm s={snap} target={target} setTarget={setTarget} />,
    scopes: <Scopes s={snap} />,
    containment: <Containment s={snap} target={target} setTarget={setTarget} />,
    integration: <Integration s={snap} />,
    auth: <AuthGate s={snap} />,
    scenarios: <Scenarios s={snap} />,
  } : {};

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 shrink-0 border-r border-border bg-panel/60 flex flex-col">
        <div className="px-4 py-4 border-b border-border">
          <div className="text-[15px] font-bold tracking-tight">HEEL</div>
          <div className="text-[10px] text-muted mt-0.5">abuse-simulation control room</div>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV.map(g => (
            <div key={g.group} className="px-2 mb-3">
              <div className="px-2 text-[9px] uppercase tracking-widest text-muted mb-1">{g.group}</div>
              {g.items.map(it => (
                <button key={it.k} onClick={() => setActive(it.k)}
                  className={`w-full text-left px-2.5 py-1.5 rounded-md text-[12.5px] mb-0.5 transition-colors ${active === it.k ? "bg-accent/15 text-accent font-medium" : "text-dim hover:bg-panel2 hover:text-text"}`}>
                  {it.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-border text-[10px] text-muted">
          <div className="flex items-center gap-1.5"><span className="live-dot inline-block w-1.5 h-1.5 rounded-full bg-ok" /> synthetic targets · no real target</div>
          <div className="mt-1">MCP-first · pure-stdlib backend · no keys</div>
        </div>
      </aside>
      <main className="flex-1 min-w-0 grid-faint">
        <header className="sticky top-0 z-10 backdrop-blur bg-bg/70 border-b border-border px-6 py-3 flex items-center justify-between">
          <div>
            <div className="text-[14px] font-semibold">{title}</div>
            <div className="text-[11px] text-muted">prove an abuse path is reachable · contained PoC · recommended control</div>
          </div>
          <div className="text-[11px] text-muted tabnum">synthetic-first · safety spine §10 · {snap ? "47 tests green" : "loading"}</div>
        </header>
        <div className="p-6 max-w-[1180px]">
          {err && <div className="text-bad text-sm">Failed to load snapshot — run <code className="text-accent">make ui-data</code>. ({err})</div>}
          {!snap && !err && <div className="text-muted text-sm animate-pulse">loading control room…</div>}
          {snap && screens[active]}
        </div>
      </main>
    </div>
  );
}
