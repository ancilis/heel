// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type {
  ConfiguredReadinessRequirement,
  LivePathSegment,
  LiveReadAssertion,
  PlanLabel,
  ScenarioBindableCatalogId,
} from "./canary-api";

/** Plain-language names for the two supported comparisons (restricted role first, then control). */
export const COMPARISON_LABELS: Readonly<Record<ScenarioBindableCatalogId, string>> = Object.freeze({
  anonymous_authenticated_read: "Anonymous vs signed-in read",
  plan_entitlement_read: "Lower plan vs higher plan read",
});

/** A path as typed segments: a key is quoted exactly ("0" stays a key), an index is shown as [n]. */
export function pathText(path: readonly LivePathSegment[]): string {
  return path.map((segment) => typeof segment === "number" ? `[${segment}]` : JSON.stringify(segment)).join(" › ");
}

export function successCheckText(assertion: LiveReadAssertion): string {
  return `${pathText(assertion.success_witness.path)} equals your local value “${assertion.success_witness.expected_fixture}”`;
}

export function conditionText(assertion: LiveReadAssertion): string {
  const condition = assertion.condition;
  return condition.kind === "json_field_present"
    ? `${pathText(condition.path)} is present (null, false and 0 count as present)`
    : `${pathText(condition.path)} equals your local value “${condition.expected_fixture}”`;
}

export function roleText(role: string, labels: readonly PlanLabel[]): string {
  const label = labels.find((item) => item.role === role)?.plan_label;
  const base = role.replace("_", " ");
  return label ? `${base} (“${label}”, operator-supplied)` : base;
}

/** The next safe LOCAL command for one missing requirement; never a value, never a browser action. */
export function readinessAdvice(item: ConfiguredReadinessRequirement, route: string): string | null {
  if (item.state === "ready") return null;
  if (item.kind === "route") {
    return item.state === "unsupported"
      ? "Parameterized routes are not supported for configured tests yet. Choose a literal route."
      : `Import the OpenAPI document that contains ${route}: heel runner import-openapi <openapi.json>`;
  }
  if (item.kind === "role_credential") {
    return `Store the ${item.subject?.replace("_", " ")} credential on the runner (hidden prompt): heel runner credential add --profile bearer --role ${item.subject} --label "${item.subject?.replace("_", " ")}" --backend keychain`;
  }
  if (item.kind === "local_input") {
    return item.state === "revoked"
      ? `The value for “${item.subject}” was revoked. Add a new one: heel runner input add --name ${item.subject} --type text --backend keychain`
      : `Enter the expected value on the runner (hidden prompt, never in the browser): heel runner input add --name ${item.subject} --type text --backend keychain`;
  }
  return "The original run is not on this runner. Replay it from the runner that executed it.";
}

export const STATE_WORDS: Readonly<Record<ConfiguredReadinessRequirement["state"], string>> = Object.freeze({
  ready: "ready", missing: "missing", revoked: "revoked", unsupported: "unsupported",
});

export function requirementLabel(item: ConfiguredReadinessRequirement): string {
  if (item.kind === "route") return "Imported route";
  if (item.kind === "role_credential") return `Credential: ${item.subject?.replace("_", " ")}`;
  if (item.kind === "local_input") return `Local value: ${item.subject}`;
  return "Original run on this runner";
}

/** Closed result reasons in plain language. An inconclusive reason never implies pass or failure. */
export function reasonText(reason: string): string {
  const known: Record<string, string> = {
    restricted_condition_true: "The condition held for the restricted role after a successful control read.",
    restricted_condition_false: "The control read succeeded and the condition did not hold for the restricted role.",
    restricted_empty_denial: "The restricted role received an empty denial (401/402/403/404) after a successful control read.",
    local_input_unavailable: "A frozen local value was missing or revoked on the runner, so no request was sent for this test.",
    run_incomplete: "The run did not complete both reads, so no verdict was reached.",
  };
  if (reason in known) return known[reason];
  if (reason.startsWith("restricted_")) {
    return `The control read succeeded, but the restricted read could not be evaluated (${reason.slice(11).replaceAll("_", " ")}).`;
  }
  return `The control read could not establish a baseline (${reason.replaceAll("_", " ")}), so the restricted read was not judged.`;
}

/** Plain-language recovery for containment codes the runner signed. */
export const CONTAINMENT_ADVICE: Readonly<Record<string, string>> = Object.freeze({
  admitted: "The run was admitted under the approved scope.",
  action_started: "Requests were started within the approved budget.",
  action_completed: "Requests completed within the approved budget.",
  action_rejected: "The runner refused at least one request before sending it (for example a missing local value). Check the runner setup, then request a new dry run.",
  budget_exhausted: "The approved request or time budget ran out. Request a new dry run; nothing beyond the budget was sent.",
  dns_changed: "The target's address changed during the run, so the runner stopped. Re-check the target, then request a new dry run.",
  stop_observed: "A stop was observed and the run ended early.",
  response_truncated: "A response exceeded the read limit and was truncated; its condition could not be fully evaluated.",
  redacted: "Sensitive values were redacted before anything was recorded.",
});
