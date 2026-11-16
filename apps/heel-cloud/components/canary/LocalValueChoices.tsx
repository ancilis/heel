// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useId } from "react";

import {
  BACKEND_LABELS,
  TYPE_NOTE,
  VALUE_TYPE_LABELS,
  inputCommand,
  type LocalBackend,
  type LocalValueType,
} from "../../lib/live-test-text";

/** The runner machine's OS secret store; a non-secret choice that only shapes the generated command. */
export function BackendChoice({ value, onChange, disabled = false }: {
  value: LocalBackend; onChange: (value: LocalBackend) => void; disabled?: boolean;
}) {
  const id = useId();
  return (
    <label htmlFor={id}>
      Runner machine secret store
      <select disabled={disabled} id={id} onChange={(event) => onChange(event.target.value as LocalBackend)} value={value}>
        {(Object.keys(BACKEND_LABELS) as LocalBackend[]).map((key) => <option key={key} value={key}>{BACKEND_LABELS[key]}</option>)}
      </select>
    </label>
  );
}

/** The JSON type of one named expected value; the value itself is only ever typed at the runner's hidden prompt. */
export function ValueTypeChoice({ reference, value, onChange, disabled = false }: {
  reference: string; value: LocalValueType; onChange: (value: LocalValueType) => void; disabled?: boolean;
}) {
  const id = useId();
  return (
    <label htmlFor={id}>
      Value type for {reference}
      <select disabled={disabled} id={id} onChange={(event) => onChange(event.target.value as LocalValueType)} value={value}>
        {(Object.keys(VALUE_TYPE_LABELS) as LocalValueType[]).map((key) => <option key={key} value={key}>{VALUE_TYPE_LABELS[key]}</option>)}
      </select>
    </label>
  );
}

/** Runnable `input add` commands for named references, built only from non-secret choices. */
export function LocalValueCommands({ references, backend, onBackend, types, onType }: {
  references: readonly string[]; backend: LocalBackend; onBackend: (value: LocalBackend) => void;
  types: Readonly<Record<string, LocalValueType>>; onType: (reference: string, value: LocalValueType) => void;
}) {
  return (
    <div className="approval-fields local-value-commands">
      <BackendChoice onChange={onBackend} value={backend} />
      <ul aria-label="Local values to enter on the runner">
        {references.map((reference) => (
          <li key={reference}>
            <ValueTypeChoice onChange={(value) => onType(reference, value)} reference={reference} value={types[reference] ?? "text"} />
            <code>{inputCommand(reference, types[reference] ?? "text", backend)}</code>
          </li>
        ))}
      </ul>
      <p>{TYPE_NOTE}</p>
    </div>
  );
}
