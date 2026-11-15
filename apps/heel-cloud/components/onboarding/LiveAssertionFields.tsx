// SPDX-License-Identifier: LicenseRef-Heel-Commercial
"use client";

import { useEffect, useId, useRef, type ReactNode } from "react";


/**
 * Guided, controlled fields for one canonical `heel.live-read-assertion.v1` definition.
 *
 * This is a pure editor: it sends nothing, stores nothing and never collects an expected value or a credential. It
 * only names local references that the runner resolves on the user's machine. The helpers mirror the closed E1 schema
 * (`heel/runner/content_assertion.py`) so the editor can explain problems inline; the server's canonical validation
 * stays authoritative and this module does not evaluate responses.
 *
 * Integration contract:
 * - Start from `emptyLiveAssertionDraft()` or `hydrateLiveAssertion(saved)` (null when `saved` is not valid canonical).
 * - Render `<LiveAssertionFields draft onChange disabled />`; `onChange` receives the next draft and its validation.
 * - Save only when `validateLiveAssertionDraft(draft).ok`; otherwise `errors` lists, in display order, what to fix.
 *   The result is a pure function of the draft, so an invalid edit can never keep an earlier valid definition.
 */

export const LIVE_READ_ASSERTION_SCHEMA = "heel.live-read-assertion.v1";
export const LIVE_PATH_MAX_SEGMENTS = 8;
export const LIVE_KEY_MAX_CHARS = 128;
export const LIVE_KEY_MAX_BYTES = 256;
export const LIVE_INDEX_MAX = 1023;
export const LIVE_DEFINITION_MAX_BYTES = 4096;

const RESERVED_KEYS: ReadonlySet<string> = new Set(["*", "**", ".", "..", "$", "@"]);
const REFERENCE_SHAPE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const INDEX_SHAPE = /^(?:0|[1-9][0-9]*)$/;
const CONTROL_OR_SURROGATE = /[\p{Cc}\p{Cs}]/u;
const ENCODER = new TextEncoder();

export type LivePathSegmentKind = "key" | "index";
export type LiveConditionKind = "json_field_present" | "json_scalar_equals_fixture";

/**
 * One ordered path row. `text` is exactly what was typed; `id` only keeps controls stable and is never serialized.
 * Ids must be unique within one draft. Drafts from `emptyLiveAssertionDraft` and `hydrateLiveAssertion` use
 * deterministic ids (`witness-1`, `condition-1`, ...), so server-rendered and hydrated labels and controls match.
 */
export interface LivePathRowDraft {
  readonly id: string;
  readonly kind: LivePathSegmentKind;
  readonly text: string;
}

/**
 * The editable state. References are names of local inputs, never values. `conditionReference` is kept while the
 * condition is "Field is present" so switching back does not lose typing, but it is serialized only for equality.
 */
export interface LiveAssertionDraft {
  readonly witnessPath: readonly LivePathRowDraft[];
  readonly witnessReference: string;
  readonly conditionKind: LiveConditionKind;
  readonly conditionPath: readonly LivePathRowDraft[];
  readonly conditionReference: string;
}

/** A path segment: a string is one exact object key (dots included); a number is an array index. */
export type LivePathSegment = string | number;

/** The exact closed E1 definition shape. */
export interface LiveReadAssertionV1 {
  readonly schema_version: typeof LIVE_READ_ASSERTION_SCHEMA;
  readonly success_witness: { readonly path: readonly LivePathSegment[]; readonly expected_fixture: string };
  readonly condition:
    | { readonly kind: "json_field_present"; readonly path: readonly LivePathSegment[] }
    | { readonly kind: "json_scalar_equals_fixture"; readonly path: readonly LivePathSegment[]; readonly expected_fixture: string };
}

/**
 * Field identifiers for errors: path-level (`witness.path`, `condition.path`), one per row
 * (`witness.segment.<row id>`, `condition.segment.<row id>`), the two references, and `definition` for total size.
 */
export type LiveAssertionField =
  | "witness.path" | "witness.reference" | "condition.path" | "condition.reference" | "definition"
  | `witness.segment.${string}` | `condition.segment.${string}`;

export type LiveAssertionValidation =
  | {
    readonly ok: true;
    readonly assertion: LiveReadAssertionV1;
    /** Sorted-key, whitespace-free UTF-8 JSON as the server canonicalizes it; for size display only, not a digest. */
    readonly canonical: string;
  }
  | { readonly ok: false; readonly errors: Readonly<Partial<Record<LiveAssertionField, string>>> };

let rowSequence = 0;

/**
 * A new path row with a fresh process-unique id, for rows built outside a draft builder. Do not use it while building
 * the initial draft of server-rendered markup: the counter differs between server and client processes.
 */
export function newLivePathRow(kind: LivePathSegmentKind, text = ""): LivePathRowDraft {
  rowSequence += 1;
  return { id: `live-path-row-${rowSequence}`, kind, text };
}

type Side = "witness" | "condition";

/** Deterministic row ids scoped to one path of one draft: `<side>-1`, `<side>-2`, ... */
function pathRows(side: Side, segments: readonly (readonly [LivePathSegmentKind, string])[]): LivePathRowDraft[] {
  return segments.map(([kind, text], index) => ({ id: `${side}-${index + 1}`, kind, text }));
}

/** A row id for `side` that no row already in `rows` uses: one past the highest `<side>-<n>` present. */
function nextRowId(side: Side, rows: readonly LivePathRowDraft[]): string {
  const prefix = `${side}-`;
  let highest = 0;
  for (const row of rows) {
    const suffix = row.id.startsWith(prefix) ? row.id.slice(prefix.length) : "";
    if (INDEX_SHAPE.test(suffix)) highest = Math.max(highest, Number(suffix));
  }
  return `${prefix}${highest + 1}`;
}

/** One empty key row per path, presence condition, no references. It is not yet valid. */
export function emptyLiveAssertionDraft(): LiveAssertionDraft {
  return {
    witnessPath: pathRows("witness", [["key", ""]]), witnessReference: "",
    conditionKind: "json_field_present", conditionPath: pathRows("condition", [["key", ""]]), conditionReference: "",
  };
}

function segmentError(row: LivePathRowDraft): string | null {
  if (row.kind === "index") {
    if (row.text === "") return "Enter an array index from 0 to 1023.";
    if (!INDEX_SHAPE.test(row.text)) return "Enter the index as digits only: no spaces, signs, decimals or leading zeros.";
    return Number(row.text) > LIVE_INDEX_MAX ? "Use an array index from 0 to 1023." : null;
  }
  if (row.text === "") return "Enter the exact object key.";
  if (CONTROL_OR_SURROGATE.test(row.text)) return "Remove control characters or unpaired surrogates from the key.";
  // Saved checks are canonicalized as NFC and must never rename a real JSON key, so only keys already in NFC are
  // supported here. The typed text is kept exactly as entered; it is not normalized for the customer.
  if (row.text !== row.text.normalize("NFC")) {
    return "This key uses decomposed Unicode (for example e followed by a combining accent). Saved checks support keys in composed (NFC) form only; type the key with composed characters, matching the response exactly.";
  }
  if ([...row.text].length > LIVE_KEY_MAX_CHARS) return "Use at most 128 characters in one key.";
  if (ENCODER.encode(row.text).length > LIVE_KEY_MAX_BYTES) return "Use at most 256 bytes (UTF-8) in one key.";
  if (RESERVED_KEYS.has(row.text)) return `“${row.text}” is reserved: Heel paths have no wildcards or JSONPath syntax. Use the real key.`;
  return null;
}

function referenceError(text: string): string | null {
  if (text === "") return "Enter a local reference name.";
  return REFERENCE_SHAPE.test(text) ? null : "Use 1 to 64 ASCII letters, digits, _ or -, starting with a letter.";
}

function serializePath(rows: readonly LivePathRowDraft[]): LivePathSegment[] {
  return rows.map((row) => (row.kind === "index" ? Number(row.text) : row.text));
}

/** Validate every field and serialize exactly the closed E1 schema, or return all field errors in display order. */
export function validateLiveAssertionDraft(draft: LiveAssertionDraft): LiveAssertionValidation {
  const errors: Partial<Record<LiveAssertionField, string>> = {};
  const checkPath = (side: "witness" | "condition", rows: readonly LivePathRowDraft[]) => {
    if (rows.length === 0) errors[`${side}.path`] = "Add at least one path segment.";
    if (rows.length > LIVE_PATH_MAX_SEGMENTS) errors[`${side}.path`] = "Use at most 8 path segments.";
    for (const row of rows) {
      const message = segmentError(row);
      if (message !== null) errors[`${side}.segment.${row.id}`] = message;
    }
  };
  checkPath("witness", draft.witnessPath);
  const witnessReference = referenceError(draft.witnessReference);
  if (witnessReference !== null) errors["witness.reference"] = witnessReference;
  checkPath("condition", draft.conditionPath);
  const equality = draft.conditionKind === "json_scalar_equals_fixture";
  if (equality) {
    const conditionReference = referenceError(draft.conditionReference);
    if (conditionReference !== null) errors["condition.reference"] = conditionReference;
  }
  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const witnessPath = serializePath(draft.witnessPath);
  const conditionPath = serializePath(draft.conditionPath);
  const assertion: LiveReadAssertionV1 = {
    schema_version: LIVE_READ_ASSERTION_SCHEMA,
    success_witness: { path: witnessPath, expected_fixture: draft.witnessReference },
    condition: equality
      ? { kind: "json_scalar_equals_fixture", path: conditionPath, expected_fixture: draft.conditionReference }
      : { kind: "json_field_present", path: conditionPath },
  };
  // Keys in sorted order at every level, matching the server's sort_keys canonical form.
  const canonical = JSON.stringify({
    condition: equality
      ? { expected_fixture: draft.conditionReference, kind: assertion.condition.kind, path: conditionPath }
      : { kind: assertion.condition.kind, path: conditionPath },
    schema_version: LIVE_READ_ASSERTION_SCHEMA,
    success_witness: { expected_fixture: draft.witnessReference, path: witnessPath },
  });
  if (ENCODER.encode(canonical).length > LIVE_DEFINITION_MAX_BYTES) {
    return { ok: false, errors: { definition: "This check is longer than 4,096 bytes when saved. Shorten keys or remove path segments." } };
  }
  return { ok: true, assertion, canonical };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isPlainObject(value)) return false;
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function hydratePath(side: Side, value: unknown): LivePathRowDraft[] | null {
  if (!Array.isArray(value)) return null;
  const segments: [LivePathSegmentKind, string][] = [];
  for (const segment of value) {
    if (typeof segment === "string") segments.push(["key", segment]);
    else if (typeof segment === "number" && Number.isSafeInteger(segment) && !Object.is(segment, -0)) segments.push(["index", String(segment)]);
    else return null;
  }
  return pathRows(side, segments);
}

/**
 * Hydrate a saved canonical definition (parsed JSON) into a draft, keeping every key a key and every index an index.
 * Returns null unless the value is exactly a valid `heel.live-read-assertion.v1` definition.
 */
export function hydrateLiveAssertion(value: unknown): LiveAssertionDraft | null {
  if (!hasExactKeys(value, ["schema_version", "success_witness", "condition"])) return null;
  if (value.schema_version !== LIVE_READ_ASSERTION_SCHEMA) return null;
  const witness = value.success_witness;
  if (!hasExactKeys(witness, ["path", "expected_fixture"]) || typeof witness.expected_fixture !== "string") return null;
  const condition = value.condition;
  if (!isPlainObject(condition)) return null;
  let conditionKind: LiveConditionKind;
  let conditionReference = "";
  if (condition.kind === "json_field_present" && hasExactKeys(condition, ["kind", "path"])) {
    conditionKind = "json_field_present";
  } else if (condition.kind === "json_scalar_equals_fixture" && hasExactKeys(condition, ["kind", "path", "expected_fixture"])
    && typeof condition.expected_fixture === "string") {
    conditionKind = "json_scalar_equals_fixture";
    conditionReference = condition.expected_fixture;
  } else {
    return null;
  }
  const witnessPath = hydratePath("witness", witness.path);
  const conditionPath = hydratePath("condition", condition.path);
  if (witnessPath === null || conditionPath === null) return null;
  const draft: LiveAssertionDraft = {
    witnessPath, witnessReference: witness.expected_fixture, conditionKind, conditionPath, conditionReference,
  };
  return validateLiveAssertionDraft(draft).ok ? draft : null;
}


export interface LiveAssertionFieldsProps {
  draft: LiveAssertionDraft;
  /** Receives every edit with its fresh validation; a partial or invalid edit always arrives with `ok: false`. */
  onChange: (draft: LiveAssertionDraft, validation: LiveAssertionValidation) => void;
  disabled?: boolean;
  /** Show inline field errors (default true). The owner may hide them until the first save attempt. */
  showErrors?: boolean;
}

const REFERENCE_HINT = "Enter the reference name, not the expected value; values stay on your runner.";

export function LiveAssertionFields({ draft, onChange, disabled = false, showErrors = true }: LiveAssertionFieldsProps) {
  const base = useId();
  const pendingFocus = useRef<string | null>(null);
  const validation = validateLiveAssertionDraft(draft);
  const errors: Readonly<Partial<Record<LiveAssertionField, string>>> = showErrors && !validation.ok ? validation.errors : {};

  useEffect(() => {
    if (pendingFocus.current === null) return;
    document.getElementById(pendingFocus.current)?.focus();
    pendingFocus.current = null;
  });

  const update = (next: LiveAssertionDraft) => onChange(next, validateLiveAssertionDraft(next));
  const fieldId = (name: string) => `${base}-${name}`;

  function referenceInput(side: Side, label: string, value: string, set: (text: string) => LiveAssertionDraft) {
    const id = fieldId(`${side}-reference`);
    const error = errors[`${side}.reference`];
    return (
      <>
        <label htmlFor={id}>{label}</label>
        <input aria-describedby={[`${id}-hint`, error ? `${id}-error` : null].filter(Boolean).join(" ")}
          aria-invalid={error ? true : undefined} autoCapitalize="off" autoComplete="off" disabled={disabled} id={id}
          onChange={(event) => update(set(event.target.value))} spellCheck={false} type="text" value={value} />
        <p id={`${id}-hint`}>{REFERENCE_HINT}</p>
        {error ? <p id={`${id}-error`}>{error}</p> : null}
      </>
    );
  }

  function pathEditor(side: Side, legend: string, rows: readonly LivePathRowDraft[]): ReactNode {
    // DOM ids carry the editor's useId prefix and the side, so two editors or two paths never share an id.
    const rowFieldId = (row: LivePathRowDraft, part: "kind" | "text") => fieldId(`${side}-row-${row.id}-${part}`);
    const setRows = (next: readonly LivePathRowDraft[]) =>
      update(side === "witness" ? { ...draft, witnessPath: next } : { ...draft, conditionPath: next });
    const pathError = errors[`${side}.path`];
    const hintId = fieldId(`${side}-path-hint`);
    const full = rows.length >= LIVE_PATH_MAX_SEGMENTS;
    const add = (kind: LivePathSegmentKind) => {
      const row: LivePathRowDraft = { id: nextRowId(side, rows), kind, text: "" };
      pendingFocus.current = rowFieldId(row, "text");
      setRows([...rows, row]);
    };
    const remove = (index: number) => {
      const neighbour = rows[index + 1] ?? rows[index - 1];
      pendingFocus.current = neighbour ? rowFieldId(neighbour, "kind") : fieldId(`${side}-add-key`);
      setRows(rows.filter((_, position) => position !== index));
    };
    return (
      <fieldset aria-describedby={[hintId, pathError ? `${hintId}-error` : null].filter(Boolean).join(" ")}>
        <legend>{legend}</legend>
        <p id={hintId}>1 to 8 segments, read in order. Choose Object key or Array index for each: a key with dots stays one key, and key “0” is not index 0.</p>
        <ol>
          {rows.map((row, index) => {
            const number = index + 1;
            const kindId = rowFieldId(row, "kind");
            const textId = rowFieldId(row, "text");
            const error = errors[`${side}.segment.${row.id}`];
            const errorId = `${textId}-error`;
            return (
              <li key={row.id}>
                <div className="account-field">
                  <label htmlFor={kindId}>Segment {number} type</label>
                  <select disabled={disabled} id={kindId} value={row.kind}
                    onChange={(event) => setRows(rows.map((item) => item.id === row.id ? { ...item, kind: event.target.value as LivePathSegmentKind } : item))}>
                    <option value="key">Object key</option>
                    <option value="index">Array index</option>
                  </select>
                </div>
                <label htmlFor={textId}>Segment {number} {row.kind === "index" ? "array index" : "object key"}</label>
                <input aria-describedby={error ? errorId : undefined} aria-invalid={error ? true : undefined} autoCapitalize="off"
                  autoComplete="off" disabled={disabled} id={textId} inputMode={row.kind === "index" ? "numeric" : "text"}
                  onChange={(event) => setRows(rows.map((item) => item.id === row.id ? { ...item, text: event.target.value } : item))}
                  spellCheck={false} type="text" value={row.text} />
                {error ? <p id={errorId}>{error}</p> : null}
                <button className="button button-secondary" disabled={disabled || rows.length <= 1} onClick={() => remove(index)} type="button">
                  Remove segment {number}
                </button>
              </li>
            );
          })}
        </ol>
        {pathError ? <p id={`${hintId}-error`}>{pathError}</p> : null}
        <div className="run-actions">
          <button aria-label={`Add object key to ${legend.toLowerCase()}`} className="button button-secondary" disabled={disabled || full}
            id={fieldId(`${side}-add-key`)} onClick={() => add("key")} type="button">Add object key</button>
          <button aria-label={`Add array index to ${legend.toLowerCase()}`} className="button button-secondary" disabled={disabled || full}
            onClick={() => add("index")} type="button">Add array index</button>
        </div>
        {full ? <p>Paths have at most 8 segments.</p> : null}
      </fieldset>
    );
  }

  const conditionKindId = fieldId("condition-kind");
  const equality = draft.conditionKind === "json_scalar_equals_fixture";
  return (
    <div className="account-form live-assertion-fields">
      <fieldset>
        <legend>Successful response check</legend>
        <p>Heel first confirms the response is the successful read you expect: the field at this path must equal a value kept on your runner. If that field is missing or does not match, the outcome is inconclusive.</p>
        {pathEditor("witness", "Success field path", draft.witnessPath)}
        {referenceInput("witness", "Expected value reference", draft.witnessReference, (text) => ({ ...draft, witnessReference: text }))}
      </fieldset>
      <fieldset>
        <legend>Condition to test</legend>
        <div className="account-field">
          <label htmlFor={conditionKindId}>Condition</label>
          <select aria-describedby={`${conditionKindId}-hint`} disabled={disabled} id={conditionKindId} value={draft.conditionKind}
            onChange={(event) => update({ ...draft, conditionKind: event.target.value as LiveConditionKind })}>
            <option value="json_field_present">Field is present</option>
            <option value="json_scalar_equals_fixture">Scalar equals local input</option>
          </select>
        </div>
        <p id={`${conditionKindId}-hint`}>{equality
          ? "The field must hold a scalar equal to a local input on your runner."
          : "The field counts as present whatever its value, including null, false or 0."}</p>
        {pathEditor("condition", "Condition field path", draft.conditionPath)}
        {equality
          ? referenceInput("condition", "Local input reference", draft.conditionReference, (text) => ({ ...draft, conditionReference: text }))
          : null}
      </fieldset>
      {errors.definition ? <p className="error-message" role="alert">{errors.definition}</p> : null}
    </div>
  );
}
