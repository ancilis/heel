// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type {
  ConfiguredReadinessRequirement,
  LivePathSegment,
  LiveReadAssertion,
  PlanLabel,
  ScenarioBindableCatalogId,
} from "./canary-api";
import { RUNNER_RC6_CLI } from "../components/canary/RunnerPairingCard";

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

/** One local step: plain-language text, exact commands to run on the runner machine, and an optional note. */
export interface LocalAdvice { text: string; commands: readonly string[]; note?: string }

/** Non-secret choices the browser may make for a generated local command. */
export type LocalValueType = "text" | "number" | "boolean" | "null";
export type LocalBackend = "keychain" | "secret-service";
export const VALUE_TYPE_LABELS: Readonly<Record<LocalValueType, string>> = Object.freeze({
  text: "Text (for example abc, typed without quotes)", number: "Number (for example 42 or 1.5)",
  boolean: "Boolean (true or false)", null: "Null (stores JSON null; nothing is asked)",
});
export const BACKEND_LABELS: Readonly<Record<LocalBackend, string>> = Object.freeze({
  keychain: "macOS Keychain", "secret-service": "Linux Secret Service",
});
/** Why the type matters: equality is strict, so the text "42" never equals the number 42. */
export const TYPE_NOTE = "Choose the type of the JSON value in the response; equality is strict, so text \"42\" never equals the number 42. "
  + "Any type except null asks for the value in a hidden prompt on the runner; it never reaches this browser or Heel Cloud.";

const SAFE_ARGUMENT = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
function quoted(value: string): string {
  if (!SAFE_ARGUMENT.test(value)) throw new Error("unsafe command argument");
  return value.includes(" ") ? `"${value}"` : value;
}

/** One runnable command storing a named expected value locally; the value is typed only at the hidden prompt. */
export function inputCommand(ref: string, type: LocalValueType, backend: LocalBackend): string {
  return `${RUNNER_RC6_CLI} runner input add --name ${quoted(ref)} --type ${type} --backend ${backend}`;
}

/** One runnable bearer-credential command; the token is typed only at the hidden prompt. */
export function credentialCommand(role: string, planLabel: string | null, backend: LocalBackend): string {
  const words = role.replace("_", " ");
  const plan = planLabel !== null && role.endsWith("_plan") ? ` --plan-label ${quoted(planLabel)}` : "";
  return `${RUNNER_RC6_CLI} runner credential add --role ${quoted(role)} --label ${quoted(words)}${plan} --profile bearer --backend ${backend}`;
}

/** Placeholder path: the customer's own OpenAPI file, which the browser never sees. */
export const OPENAPI_PATH = "./openapi.json";
export const IMPORT_COMMAND = `${RUNNER_RC6_CLI} runner import-openapi ${OPENAPI_PATH}`;

export interface AdviceChoices {
  backend: LocalBackend;
  typeFor: (ref: string) => LocalValueType;
  planLabelFor: (role: string) => string | null;
}

/**
 * The next safe LOCAL step for one unmet requirement; never a value, never a browser action. A replay
 * (configured_regression) must reuse the ORIGINAL frozen input handles, so it never advises re-adding a value.
 */
export function readinessAdvice(
  item: ConfiguredReadinessRequirement, route: string,
  planKind: "configured_live_read" | "configured_regression" = "configured_live_read",
  choices: AdviceChoices = { backend: "keychain", typeFor: () => "text", planLabelFor: () => null },
): LocalAdvice | null {
  if (item.state === "ready") return null;
  if (item.kind === "route") {
    return item.state === "unsupported"
      ? { text: "Parameterized routes are not supported for configured tests yet. Choose a literal route.", commands: [] }
      : { text: `Import the OpenAPI document that contains ${route} on the runner:`, commands: [IMPORT_COMMAND],
        note: `${OPENAPI_PATH} stands for the path of your own OpenAPI file on the runner machine.` };
  }
  if (item.kind === "role_credential") {
    const role = item.subject ?? "";
    return {
      text: `Store the ${role.replace("_", " ")} bearer token on the runner (hidden prompt):`,
      commands: [credentialCommand(role, choices.planLabelFor(role), choices.backend)],
    };
  }
  if (item.kind === "local_input") {
    if (planKind === "configured_regression") {
      return {
        text: `This replay must use the original value it saved for “${item.subject}”, and that value is ${item.state === "revoked" ? "revoked" : "missing"} on this runner. `
          + "Adding a new value under the same name cannot repair this replay. Cancel this request, then request a new dry run of the test "
          + "(it freezes the new value) and approve that instead.",
        commands: [],
      };
    }
    const ref = item.subject ?? "";
    return {
      text: item.state === "revoked"
        ? `The current value for “${ref}” was revoked. Store a new one on the runner:`
        : "Enter the expected value on the runner (never in the browser):",
      commands: [inputCommand(ref, choices.typeFor(ref), choices.backend)],
      note: TYPE_NOTE,
    };
  }
  return { text: "The original run is not on this runner. Replay it from the runner that executed it, or request a new dry run of the test.", commands: [] };
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
