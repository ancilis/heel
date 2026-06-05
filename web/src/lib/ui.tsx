import React from "react";

export const cx = (...c: (string | false | undefined)[]) => c.filter(Boolean).join(" ");
export const fmt = (n: number | null | undefined, d = 2) => (n === null || n === undefined ? "—" : n.toFixed(d));

export const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#fb7185", medium: "#fbbf24", low: "#60a5fa",
};
export const CAT_COLOR: Record<string, string> = {
  license_entitlement: "#f59e0b", data_harvesting: "#fb7185", unintended_endpoints: "#a78bfa",
  function_abuse: "#f472b6", content_policy: "#fb923c", identity_account: "#22d3ee",
  trust_economy: "#34d399", integration_extensibility: "#818cf8", compliance_boundary: "#facc15",
  agent_mcp_surface: "#ef4444",
};
export const catShort = (c: string) => c.replace(/_/g, " ").replace("entitlement", "ent.").replace("extensibility", "ext.");

export function Panel({ title, sub, right, className, children }: {
  title?: string; sub?: string; right?: React.ReactNode; className?: string; children: React.ReactNode;
}) {
  return (
    <div className={cx("rounded-xl border border-border bg-panel/80", className)}>
      {(title || right) && (
        <div className="flex items-start justify-between gap-3 px-4 pt-3 pb-2 border-b border-border/70">
          <div>
            {title && <div className="text-[13px] font-semibold tracking-wide">{title}</div>}
            {sub && <div className="text-[11px] text-muted mt-0.5">{sub}</div>}
          </div>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function Stat({ label, value, sub, tone = "text" }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string }) {
  const t: Record<string, string> = { text: "text-text", ok: "text-ok", bad: "text-bad", warn: "text-warn", accent: "text-accent", crit: "text-crit" };
  return (
    <div className="rounded-lg border border-border bg-panel2/60 px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-muted">{label}</div>
      <div className={cx("tabnum text-2xl font-semibold mt-1", t[tone] || "text-text")}>{value}</div>
      {sub && <div className="text-[11px] text-dim mt-0.5">{sub}</div>}
    </div>
  );
}

export function Tag({ children, color = "#98a1b2", solid }: { children: React.ReactNode; color?: string; solid?: boolean }) {
  return (
    <span className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium tabnum whitespace-nowrap"
      style={solid ? { background: color, color: "#07080b" } : { color, border: `1px solid ${color}40`, background: `${color}14` }}>
      {children}
    </span>
  );
}

export const SevBadge = ({ s }: { s: string }) => <Tag color={SEV_COLOR[s] || "#98a1b2"} solid>{s}</Tag>;
export const CatBadge = ({ c }: { c: string }) => <Tag color={CAT_COLOR[c] || "#98a1b2"}>{catShort(c)}</Tag>;

export function ReachBar({ r, plausible }: { r: number; plausible: boolean }) {
  return (
    <div className="flex items-center gap-1.5" title={`reachability ${r}`}>
      <div className="h-1.5 w-12 rounded-full bg-border overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${Math.round(r * 100)}%`, background: plausible ? "#34d399" : "#6b7280" }} />
      </div>
      <span className="tabnum text-[10px]" style={{ color: plausible ? "#98a1b2" : "#6b7280" }}>
        {plausible ? `${Math.round(r * 100)}%` : "demoted"}
      </span>
    </div>
  );
}

export function Verdict({ pass, labels = ["PASS", "FAIL"] }: { pass: boolean; labels?: [string, string] }) {
  return <Tag color={pass ? "#34d399" : "#fb7185"} solid>{pass ? labels[0] : labels[1]}</Tag>;
}

export function Donut({ value, size = 92, color = "#34d399", label }: { value: number; size?: number; color?: string; label?: string }) {
  const r = size / 2 - 8, c = 2 * Math.PI * r;
  return (
    <svg viewBox={`0 0 ${size} ${size}`} style={{ width: size, height: size }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#21252e" strokeWidth="8" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
        strokeDasharray={`${value * c} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x="50%" y="48%" textAnchor="middle" className="tabnum" fontSize="17" fontWeight="600" fill="#e8eaef">{Math.round(value * 100)}%</text>
      {label && <text x="50%" y="64%" textAnchor="middle" fontSize="8" fill="#6b7280">{label}</text>}
    </svg>
  );
}

export function HBars({ items, max }: { items: { label: string; value: number; color?: string; tag?: React.ReactNode }[]; max?: number }) {
  const m = max ?? Math.max(...items.map(i => i.value), 0.001);
  return (
    <div className="space-y-1.5">
      {items.map((it, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="w-36 shrink-0 text-[11px] text-dim truncate">{it.label}</div>
          <div className="flex-1 h-3 rounded bg-panel2 overflow-hidden">
            <div className="h-full rounded" style={{ width: `${(it.value / m) * 100}%`, background: it.color || "#f59e0b" }} />
          </div>
          <div className="w-9 text-right tabnum text-[11px]">{it.value}</div>
          {it.tag}
        </div>
      ))}
    </div>
  );
}
