// SPDX-License-Identifier: LicenseRef-Heel-Commercial
export type CampaignOutcome = "held" | "violation" | "inconclusive" | "not_applicable";
export interface CampaignResult {
  scenario_id: string; family: string; rule: string; outcome: CampaignOutcome;
  reason: string; cleanup: string;
  checks: { id: string; outcome: string }[];
  evidence: { step_id: string; status: number; sha256: string; bytes: number; duration_ms: number }[];
}
export interface CampaignReport {
  name: string; run_id: string; campaign_digest: string; origin: string;
  requests_attempted: number; results: CampaignResult[];
}
const outcomes = new Set(["held", "violation", "inconclusive", "not_applicable"]);
const hex = /^[0-9a-f]{64}$/;
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Expected a report object.");
  return value as Record<string, unknown>;
}
function text(value: unknown, max = 400): string {
  if (typeof value !== "string" || !value || value.length > max || /[\u0000-\u001f]/.test(value)) throw new Error("Invalid report text.");
  return value;
}
function integer(value: unknown, max = 1000000): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) throw new Error("Invalid report count.");
  return value;
}
export function parseCampaignReport(value: unknown): CampaignReport {
  const root = object(value);
  if (root.schema_version !== "heel.campaign.report.v1" || root.uploaded !== false || !hex.test(text(root.signature))) throw new Error("Choose a Heel campaign report.");
  if (!/^[0-9a-f]{32}$/.test(text(root.run_id)) || !hex.test(text(root.campaign_digest))) throw new Error("Invalid report identity.");
  if (!Array.isArray(root.results) || root.results.length < 1 || root.results.length > 40) throw new Error("Invalid report results.");
  const ids = new Set<string>();
  const results = root.results.map((value): CampaignResult => {
    const row = object(value);
    const id = text(row.scenario_id, 64);
    if (ids.has(id) || !outcomes.has(text(row.outcome))) throw new Error("Invalid scenario result.");
    ids.add(id);
    if (!Array.isArray(row.checks) || row.checks.length > 20 || !Array.isArray(row.evidence) || row.evidence.length > 25) throw new Error("Invalid evidence list.");
    return {
      scenario_id: id, family: text(row.family, 64), rule: text(row.rule), outcome: row.outcome as CampaignOutcome,
      reason: text(row.reason), cleanup: text(row.cleanup, 32),
      checks: row.checks.map((item) => { const check = object(item); return { id: text(check.id, 64), outcome: text(check.outcome, 32) }; }),
      evidence: row.evidence.map((item) => {
        const evidence = object(item);
        if (!hex.test(text(evidence.sha256))) throw new Error("Invalid evidence digest.");
        return { step_id: text(evidence.step_id, 64), status: integer(evidence.status, 599), sha256: String(evidence.sha256),
          bytes: integer(evidence.bytes, 65536), duration_ms: integer(evidence.duration_ms, 300000) };
      }),
    };
  });
  return { name: text(root.name, 120), run_id: String(root.run_id), campaign_digest: String(root.campaign_digest),
    origin: text(root.origin), requests_attempted: integer(root.requests_attempted, 200), results };
}
