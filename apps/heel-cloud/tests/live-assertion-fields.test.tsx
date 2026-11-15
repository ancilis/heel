// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Guided live-read assertion fields.
 *
 * SEAM: the editor is rendered alone inside a controlled harness; no client, route, runner or target is involved.
 * Canonical server validation (`heel/runner/content_assertion.py`) stays authoritative; these tests only pin the
 * editor's mirror of the closed E1 schema and its DOM behaviour.
 */

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { act, useState } from "react";
import { hydrateRoot } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, test, vi } from "vitest";

import {
  LiveAssertionFields, emptyLiveAssertionDraft, hydrateLiveAssertion, newLivePathRow, validateLiveAssertionDraft,
  type LiveAssertionDraft, type LiveAssertionValidation,
} from "../components/onboarding/LiveAssertionFields";


afterEach(cleanup);

const HINT = "Enter the reference name, not the expected value; values stay on your runner.";

const PRESENCE = {
  schema_version: "heel.live-read-assertion.v1",
  success_witness: { path: ["data", 0, "account.id"], expected_fixture: "own_account" },
  condition: { kind: "json_field_present", path: ["data", 0, "0"] },
};
const EQUALITY = {
  schema_version: "heel.live-read-assertion.v1",
  success_witness: { path: ["profile", "id"], expected_fixture: "own_id" },
  condition: { kind: "json_scalar_equals_fixture", path: ["plan"], expected_fixture: "free_plan" },
};

function Harness({ initial, disabled, showErrors, spy }: {
  initial: LiveAssertionDraft; disabled?: boolean; showErrors?: boolean;
  spy?: (draft: LiveAssertionDraft, validation: LiveAssertionValidation) => void;
}) {
  const [draft, setDraft] = useState(initial);
  return <LiveAssertionFields disabled={disabled} draft={draft} showErrors={showErrors}
    onChange={(next, validation) => { setDraft(next); spy?.(next, validation); }} />;
}

function mount(initial: LiveAssertionDraft = emptyLiveAssertionDraft(), options: { disabled?: boolean; showErrors?: boolean } = {}) {
  const spy = vi.fn<(draft: LiveAssertionDraft, validation: LiveAssertionValidation) => void>();
  render(<Harness initial={initial} spy={spy} {...options} />);
  const last = () => spy.mock.calls.at(-1)!;
  return { spy, lastDraft: () => last()[0], lastValidation: () => last()[1] };
}

function group(name: string): HTMLElement {
  return screen.getByRole("group", { name });
}

function type(element: HTMLElement, value: string) {
  fireEvent.change(element, { target: { value } });
}

function textField(path: HTMLElement, segment: number): HTMLInputElement {
  return within(path).getByLabelText(new RegExp(`^Segment ${segment} (object key|array index)$`)) as HTMLInputElement;
}

function describedText(element: HTMLElement): string {
  return (element.getAttribute("aria-describedby") ?? "").split(" ").filter(Boolean)
    .map((id) => document.getElementById(id)?.textContent ?? "").join(" | ");
}

function fill(witnessPath: HTMLElement, conditionPath: HTMLElement) {
  type(textField(witnessPath, 1), "id");
  type(screen.getByLabelText("Expected value reference"), "own_id");
  type(textField(conditionPath, 1), "plan");
}


describe("helpers mirror the closed E1 schema", () => {
  test("hydration round-trips presence and equality definitions exactly, keeping key and index types", () => {
    for (const saved of [PRESENCE, EQUALITY]) {
      const draft = hydrateLiveAssertion(saved);
      expect(draft).not.toBeNull();
      const result = validateLiveAssertionDraft(draft!);
      expect(result.ok && result.assertion).toEqual(saved);
    }
    const draft = hydrateLiveAssertion(PRESENCE)!;
    expect(draft.witnessPath.map(({ kind, text }) => [kind, text])).toEqual([["key", "data"], ["index", "0"], ["key", "account.id"]]);
    expect(draft.conditionPath.map(({ kind, text }) => [kind, text])).toEqual([["key", "data"], ["index", "0"], ["key", "0"]]);
  });

  test("canonical form sorts keys at every level, matches the server shape and omits expected_fixture for presence", () => {
    const presence = validateLiveAssertionDraft(hydrateLiveAssertion(PRESENCE)!);
    expect(presence.ok && presence.canonical).toBe(
      '{"condition":{"kind":"json_field_present","path":["data",0,"0"]},"schema_version":"heel.live-read-assertion.v1",'
      + '"success_witness":{"expected_fixture":"own_account","path":["data",0,"account.id"]}}');
    const equality = validateLiveAssertionDraft(hydrateLiveAssertion(EQUALITY)!);
    expect(equality.ok && equality.canonical).toBe(
      '{"condition":{"expected_fixture":"free_plan","kind":"json_scalar_equals_fixture","path":["plan"]},'
      + '"schema_version":"heel.live-read-assertion.v1","success_witness":{"expected_fixture":"own_id","path":["profile","id"]}}');
  });

  test.each([
    ["an unknown top-level field", { ...PRESENCE, extra: true }],
    ["a missing field", { schema_version: PRESENCE.schema_version, success_witness: PRESENCE.success_witness }],
    ["another schema version", { ...PRESENCE, schema_version: "heel.live-read-assertion.v2" }],
    ["an unsupported kind", { ...PRESENCE, condition: { kind: "json_value_matches", path: ["a"] } }],
    ["expected_fixture on a presence condition", { ...PRESENCE, condition: { ...PRESENCE.condition, expected_fixture: "x" } }],
    ["equality without expected_fixture", { ...EQUALITY, condition: { kind: "json_scalar_equals_fixture", path: ["plan"] } }],
    ["an expected value instead of a reference", { ...EQUALITY, condition: { ...EQUALITY.condition, expected_fixture: 42 } }],
    ["an invalid reference", { ...EQUALITY, success_witness: { path: ["id"], expected_fixture: "1st" } }],
    ["an empty path", { ...PRESENCE, condition: { kind: "json_field_present", path: [] } }],
    ["nine segments", { ...PRESENCE, condition: { kind: "json_field_present", path: ["a", "b", "c", "d", "e", "f", "g", "h", "i"] } }],
    ["a negative index", { ...PRESENCE, condition: { kind: "json_field_present", path: [-1] } }],
    ["index 1024", { ...PRESENCE, condition: { kind: "json_field_present", path: [1024] } }],
    ["a fractional index", { ...PRESENCE, condition: { kind: "json_field_present", path: [1.5] } }],
    ["a boolean segment", { ...PRESENCE, condition: { kind: "json_field_present", path: [true] } }],
    ["a reserved key", { ...PRESENCE, condition: { kind: "json_field_present", path: ["**"] } }],
    ["a path that is not an array", { ...PRESENCE, condition: { kind: "json_field_present", path: "a.b" } }],
    ["a non-object", "{}"],
  ])("hydration refuses %s", (_, value) => {
    expect(hydrateLiveAssertion(value)).toBeNull();
  });

  test.each([
    ["key", "a", true],
    ["key", "a.b", true],
    ["key", " padded ", true],
    ["key", "ключ", true],
    ["key", "x".repeat(128), true],
    ["key", "x".repeat(129), false],
    ["key", "😀".repeat(64), true],
    ["key", "😀".repeat(60) + "x".repeat(10), true],
    ["key", "é".repeat(128), true],
    ["key", "\u00e9", true],
    ["key", "e\u0301", false],
    ["key", "\u1100\u1161", false],
    ["key", "\u212b", false],
    ["key", "👩\u200d💻", true],
    ["key", "😀".repeat(65), false],
    ["key", "ab\u0000", false],
    ["key", "tab\there", false],
    ["key", "\u007f", false],
    ["key", "\ud800", false],
    ["key", "", false],
    ...["*", "**", ".", "..", "$", "@"].map((reserved) => ["key", reserved, false] as const),
    ["key", "$.a", true],
    ["key", "***", true],
    ["index", "0", true],
    ["index", "1023", true],
    ["index", "1024", false],
    ["index", "00", false],
    ["index", "01", false],
    ["index", " 1", false],
    ["index", "1 ", false],
    ["index", "+1", false],
    ["index", "-1", false],
    ["index", "1.0", false],
    ["index", "1e2", false],
    ["index", "0x1", false],
    ["index", "١", false],
    ["index", "", false],
  ] as const)("a %s segment %j is accepted: %s", (kind, text, accepted) => {
    const draft: LiveAssertionDraft = { ...emptyLiveAssertionDraft(), witnessPath: [newLivePathRow("key", "id")], witnessReference: "own",
      conditionPath: [newLivePathRow(kind, text)] };
    const result = validateLiveAssertionDraft(draft);
    expect(result.ok).toBe(accepted);
    if (result.ok) expect(result.assertion.condition.path).toEqual([kind === "index" ? Number(text) : text]);
    else expect(Object.keys(result.errors)).toEqual([`condition.segment.${draft.conditionPath[0]!.id}`]);
  });

  test.each([["a", true], ["A-b_9", true], ["a".repeat(64), true], ["a".repeat(65), false], ["9a", false], ["_a", false], ["a b", false], ["ä", false], ["", false]])(
    "reference name %j is accepted: %s", (reference, accepted) => {
      const draft = { ...hydrateLiveAssertion(EQUALITY)!, conditionReference: reference };
      const result = validateLiveAssertionDraft(draft);
      expect(result.ok).toBe(accepted);
      if (!result.ok) expect(Object.keys(result.errors)).toEqual(["condition.reference"]);
    });

  test("the canonical definition is bounded at 4096 UTF-8 bytes", () => {
    const wide = (count: number) => Array.from({ length: count }, () => newLivePathRow("key", "😀".repeat(64)));
    const fits = validateLiveAssertionDraft({ ...hydrateLiveAssertion(PRESENCE)!, witnessPath: wide(8), conditionPath: wide(7) });
    expect(fits.ok).toBe(true);
    expect(new TextEncoder().encode(fits.ok ? fits.canonical : "").length).toBeLessThanOrEqual(4096);
    const over = validateLiveAssertionDraft({ ...hydrateLiveAssertion(PRESENCE)!, witnessPath: wide(8), conditionPath: wide(8) });
    expect(over).toEqual({ ok: false, errors: { definition: expect.stringMatching(/4,096 bytes/) } });
  });

  test("presence ignores a leftover equality reference; equality requires its own", () => {
    const draft = { ...hydrateLiveAssertion(PRESENCE)!, conditionReference: "not valid!" };
    const presence = validateLiveAssertionDraft(draft);
    expect(presence.ok && presence.assertion.condition).toEqual({ kind: "json_field_present", path: ["data", 0, "0"] });
    const equality = validateLiveAssertionDraft({ ...draft, conditionKind: "json_scalar_equals_fixture" });
    expect(equality.ok).toBe(false);
  });
});


describe("guided assertion editor", () => {
  test("shows two labelled sections, the inconclusive explanation and the value boundary, with no JSON editor", () => {
    mount();
    const witness = group("Successful response check");
    const condition = group("Condition to test");
    expect(witness.textContent).toMatch(/missing or does not match, the outcome is inconclusive/);
    expect(within(witness).getByText(HINT)).toBeTruthy();
    expect(describedText(screen.getByLabelText("Expected value reference"))).toContain(HINT);
    const kind = within(condition).getByLabelText("Condition") as HTMLSelectElement;
    expect(Array.from(kind.options, (option) => [option.value, option.textContent]))
      .toEqual([["json_field_present", "Field is present"], ["json_scalar_equals_fixture", "Scalar equals local input"]]);
    expect(describedText(kind)).toMatch(/null, false or 0/);
    expect(document.querySelector("textarea")).toBeNull();
    expect(document.querySelectorAll('input[type="password"], input[type="number"]').length).toBe(0);
    expect(screen.queryByLabelText(/expected value$/i)).toBeNull();
    for (const button of screen.getAllByRole("button")) expect(button.getAttribute("type")).toBe("button");
  });

  test("controlled creation emits a valid presence definition only once every field is valid", () => {
    const { spy, lastValidation } = mount();
    const witnessPath = group("Success field path");
    const conditionPath = group("Condition field path");
    type(textField(witnessPath, 1), "id");
    expect(lastValidation().ok).toBe(false);
    type(screen.getByLabelText("Expected value reference"), "own_id");
    expect(lastValidation().ok).toBe(false);
    type(textField(conditionPath, 1), "plan");
    expect(lastValidation()).toEqual({ ok: true, canonical: expect.any(String), assertion: {
      schema_version: "heel.live-read-assertion.v1",
      success_witness: { path: ["id"], expected_fixture: "own_id" },
      condition: { kind: "json_field_present", path: ["plan"] },
    } });
    expect(spy).toHaveBeenCalledTimes(3);
  });

  test("mixed key and index rows serialize in order; a dotted key is one key and key 0 differs from index 0", () => {
    const { lastValidation } = mount();
    const witnessPath = group("Success field path");
    const conditionPath = group("Condition field path");
    fill(witnessPath, conditionPath);
    type(textField(conditionPath, 1), "a.b");
    fireEvent.click(within(conditionPath).getByRole("button", { name: "Add array index to condition field path" }));
    type(textField(conditionPath, 2), "0");
    fireEvent.click(within(conditionPath).getByRole("button", { name: "Add object key to condition field path" }));
    type(textField(conditionPath, 3), "0");
    const result = lastValidation();
    expect(result.ok && result.assertion.condition.path).toEqual(["a.b", 0, "0"]);

    fireEvent.change(within(conditionPath).getByLabelText("Segment 2 type"), { target: { value: "key" } });
    const switched = lastValidation();
    expect(switched.ok && switched.assertion.condition.path).toEqual(["a.b", "0", "0"]);
    expect(textField(conditionPath, 2).value).toBe("0");
  });

  test("an invalid edit shows a field-associated error and never keeps the earlier valid output; correction restores it", () => {
    const { lastValidation, lastDraft } = mount(hydrateLiveAssertion(PRESENCE)!);
    const conditionPath = group("Condition field path");
    const index = textField(conditionPath, 2);
    expect(index.getAttribute("aria-invalid")).toBeNull();

    type(index, "01");
    expect(lastValidation().ok).toBe(false);
    expect(index.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(index)).toMatch(/digits only/);
    expect(lastDraft().conditionPath[1]).toMatchObject({ kind: "index", text: "01" });

    for (const [text, message] of [["1024", /0 to 1023/], [" 1", /digits only/], ["", /from 0 to 1023/]] as const) {
      type(index, text);
      expect(lastValidation().ok).toBe(false);
      expect(describedText(index)).toMatch(message);
    }
    type(index, "1");
    expect(index.getAttribute("aria-invalid")).toBeNull();
    expect(index.getAttribute("aria-describedby")).toBeNull();
    const result = lastValidation();
    expect(result.ok && result.assertion.condition.path).toEqual(["data", 1, "0"]);

    const key = textField(conditionPath, 3);
    type(key, "**");
    expect(describedText(key)).toMatch(/reserved/);
    type(key, "x\u0007");
    expect(describedText(key)).toMatch(/control characters/);
    type(key, "x".repeat(129));
    expect(describedText(key)).toMatch(/128 characters/);
    type(key, "x".repeat(128));
    expect(key.value).toBe("x".repeat(128));
    expect(lastValidation().ok).toBe(true);

    const reference = screen.getByLabelText("Expected value reference");
    type(reference, "own account");
    expect(reference.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(reference)).toMatch(/ASCII letters/);
    expect(lastValidation()).toEqual({ ok: false, errors: { "witness.reference": expect.any(String) } });
  });

  test("a decomposed (non-NFC) key keeps its exact text and gets a clear field error; the composed key is accepted", () => {
    const { lastValidation, lastDraft } = mount(hydrateLiveAssertion(PRESENCE)!);
    const key = textField(group("Condition field path"), 3);
    type(key, "caf" + "e\u0301");
    expect(key.value).toBe("cafe\u0301");
    expect(lastDraft().conditionPath[2]!.text).toBe("cafe\u0301");
    expect(key.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(key)).toMatch(/composed \(NFC\) form/);
    const rejected = lastValidation();
    expect(rejected.ok).toBe(false);
    expect(Object.keys(rejected.ok ? {} : rejected.errors)).toEqual([`condition.segment.${lastDraft().conditionPath[2]!.id}`]);
    expect(hydrateLiveAssertion({ ...PRESENCE, condition: { kind: "json_field_present", path: ["cafe\u0301"] } })).toBeNull();

    type(key, "caf\u00e9");
    expect(key.getAttribute("aria-invalid")).toBeNull();
    const accepted = lastValidation();
    expect(accepted.ok && accepted.assertion.condition.path).toEqual(["data", 0, "caf\u00e9"]);
  });

  test("key text is kept exactly: no trimming, truncation or coercion", () => {
    const { lastValidation } = mount(hydrateLiveAssertion(PRESENCE)!);
    const key = textField(group("Condition field path"), 3);
    type(key, "  spaced  ");
    expect(key.value).toBe("  spaced  ");
    const result = lastValidation();
    expect(result.ok && result.assertion.condition.path).toEqual(["data", 0, "  spaced  "]);
  });

  test("switching to equality asks for its own reference; switching back to presence drops it from output", () => {
    const { lastValidation } = mount(hydrateLiveAssertion(PRESENCE)!);
    expect(screen.queryByLabelText("Local input reference")).toBeNull();
    const kind = screen.getByLabelText("Condition");
    fireEvent.change(kind, { target: { value: "json_scalar_equals_fixture" } });
    expect(lastValidation()).toEqual({ ok: false, errors: { "condition.reference": "Enter a local reference name." } });
    const reference = screen.getByLabelText("Local input reference");
    expect(describedText(reference)).toContain(HINT);
    type(reference, "free_plan");
    const equality = lastValidation();
    expect(equality.ok && equality.assertion.condition).toEqual({ kind: "json_scalar_equals_fixture", path: ["data", 0, "0"], expected_fixture: "free_plan" });

    fireEvent.change(kind, { target: { value: "json_field_present" } });
    const presence = lastValidation();
    expect(presence.ok && presence.assertion.condition).toEqual({ kind: "json_field_present", path: ["data", 0, "0"] });
    expect(presence.ok && presence.canonical).not.toContain("free_plan");
    expect(screen.queryByLabelText("Local input reference")).toBeNull();
  });

  test("hydrated equality definitions show their stored references and types", () => {
    mount(hydrateLiveAssertion(EQUALITY)!);
    expect((screen.getByLabelText("Condition") as HTMLSelectElement).value).toBe("json_scalar_equals_fixture");
    expect((screen.getByLabelText("Local input reference") as HTMLInputElement).value).toBe("free_plan");
    expect((screen.getByLabelText("Expected value reference") as HTMLInputElement).value).toBe("own_id");
    const witnessPath = group("Success field path");
    expect((within(witnessPath).getByLabelText("Segment 2 type") as HTMLSelectElement).value).toBe("key");
  });

  test("add and remove are keyboard-operable buttons, bounded at 8 segments, with focus kept sensibly", () => {
    const { lastDraft } = mount(hydrateLiveAssertion(PRESENCE)!);
    const witnessPath = group("Success field path");
    const addKey = within(witnessPath).getByRole("button", { name: "Add object key to success field path" }) as HTMLButtonElement;
    const addIndex = within(witnessPath).getByRole("button", { name: "Add array index to success field path" }) as HTMLButtonElement;

    fireEvent.click(addIndex);
    expect(document.activeElement).toBe(textField(witnessPath, 4));
    expect(within(witnessPath).getByLabelText("Segment 4 type")).toHaveProperty("value", "index");
    for (let count = 5; count <= 8; count += 1) fireEvent.click(addKey);
    expect(lastDraft().witnessPath).toHaveLength(8);
    expect(addKey.disabled).toBe(true);
    expect(addIndex.disabled).toBe(true);
    expect(witnessPath.textContent).toMatch(/at most 8 segments/);

    const secondId = lastDraft().witnessPath[1]!.id;
    const thirdId = lastDraft().witnessPath[2]!.id;
    fireEvent.click(within(witnessPath).getByRole("button", { name: "Remove segment 2" }));
    expect(lastDraft().witnessPath.map((row) => row.id)).not.toContain(secondId);
    expect(lastDraft().witnessPath[1]!.id).toBe(thirdId);
    expect(document.activeElement).toBe(within(witnessPath).getByLabelText("Segment 2 type"));
    expect(addKey.disabled).toBe(false);

    fireEvent.click(within(witnessPath).getByRole("button", { name: "Remove segment 7" }));
    expect(document.activeElement).toBe(within(witnessPath).getByLabelText("Segment 6 type"));
    while (lastDraft().witnessPath.length > 1) fireEvent.click(within(witnessPath).getByRole("button", { name: "Remove segment 1" }));
    expect(within(witnessPath).getByRole("button", { name: "Remove segment 1" })).toHaveProperty("disabled", true);
  });

  test("controls are stable across edits: the same input element keeps focus while typing", () => {
    mount(hydrateLiveAssertion(PRESENCE)!);
    const key = textField(group("Success field path"), 3);
    key.focus();
    type(key, "account.ids");
    expect(textField(group("Success field path"), 3)).toBe(key);
    expect(document.activeElement).toBe(key);
  });

  test("disabled state disables every control and emits nothing", () => {
    const { spy } = mount(hydrateLiveAssertion(EQUALITY)!, { disabled: true });
    const controls = document.querySelectorAll("input, select, button");
    expect(controls.length).toBeGreaterThan(8);
    for (const control of controls) expect((control as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(screen.getAllByRole("button")[0]!);
    expect(spy).not.toHaveBeenCalled();
  });

  test("errors can be hidden until the owner asks for them, while validation still blocks", () => {
    const { lastValidation } = mount(emptyLiveAssertionDraft(), { showErrors: false });
    expect(document.querySelectorAll('[aria-invalid="true"]').length).toBe(0);
    type(screen.getByLabelText("Expected value reference"), "x y");
    expect(lastValidation().ok).toBe(false);
    expect(document.querySelectorAll('[aria-invalid="true"]').length).toBe(0);
  });

  test("an empty draft marks each missing field invalid with its own message", () => {
    mount();
    expect(textField(group("Success field path"), 1).getAttribute("aria-invalid")).toBe("true");
    expect(describedText(textField(group("Condition field path"), 1))).toMatch(/exact object key/);
    expect(describedText(screen.getByLabelText("Expected value reference"))).toMatch(/Enter a local reference name/);
  });
});


describe("stable DOM identity", () => {
  function ids(root: ParentNode): string[] {
    return Array.from(root.querySelectorAll("[id]"), (element) => element.id);
  }

  function expectLabelsResolve(root: ParentNode) {
    const all = ids(document);
    expect(new Set(all).size).toBe(all.length);
    const labels = root.querySelectorAll("label[for]");
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      const target = document.getElementById(label.getAttribute("for")!);
      expect(target).not.toBeNull();
      expect(root.contains(target)).toBe(true);
    }
  }

  test("initial and hydrated drafts get deterministic row ids, whatever was built before", () => {
    const first = emptyLiveAssertionDraft();
    for (let count = 0; count < 5; count += 1) { emptyLiveAssertionDraft(); hydrateLiveAssertion(PRESENCE); newLivePathRow("key"); }
    expect(emptyLiveAssertionDraft()).toEqual(first);
    expect(hydrateLiveAssertion(PRESENCE)).toEqual(hydrateLiveAssertion(PRESENCE));
    const hydrated = hydrateLiveAssertion(PRESENCE)!;
    const rowIds = [...hydrated.witnessPath, ...hydrated.conditionPath].map((row) => row.id);
    expect(new Set(rowIds).size).toBe(rowIds.length);
  });

  test.each([["an empty draft", () => emptyLiveAssertionDraft()], ["a hydrated draft", () => hydrateLiveAssertion(EQUALITY)!]])(
    "%s renders identical server HTML repeatedly and hydrates on the client with the same ids and labels", async (_, build) => {
      const noop = () => undefined;
      // A warmed server process: builders have already run for earlier requests.
      for (let count = 0; count < 3; count += 1) renderToString(<LiveAssertionFields draft={build()} onChange={noop} />);
      const serverHtml = renderToString(<LiveAssertionFields draft={build()} onChange={noop} />);
      expect(renderToString(<LiveAssertionFields draft={build()} onChange={noop} />)).toBe(serverHtml);

      const container = document.createElement("div");
      container.innerHTML = serverHtml;
      document.body.appendChild(container);
      const serverIds = ids(container);
      const serverLabels = Array.from(container.querySelectorAll("label[for]"), (label) => [label.textContent, label.getAttribute("for")]);
      const serverFirstInput = container.querySelector("input");
      const recoverable: unknown[] = [];
      const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
      const root = await act(async () => hydrateRoot(container, <Harness initial={build()} />, {
        onRecoverableError: (error) => { recoverable.push(error); },
      }));
      try {
        expect(recoverable).toEqual([]);
        expect(consoleError).not.toHaveBeenCalled();
        expect(ids(container)).toEqual(serverIds);
        expect(Array.from(container.querySelectorAll("label[for]"), (label) => [label.textContent, label.getAttribute("for")])).toEqual(serverLabels);
        expect(container.querySelector("input")).toBe(serverFirstInput);
        expectLabelsResolve(container);
      } finally {
        consoleError.mockRestore();
        act(() => root.unmount());
        container.remove();
      }
    });

  test("two editors on one page keep distinct ids and labels resolve inside their own editor", () => {
    render(<>
      <section aria-label="first editor"><Harness initial={emptyLiveAssertionDraft()} /></section>
      <section aria-label="second editor"><Harness initial={hydrateLiveAssertion(PRESENCE)!} /></section>
    </>);
    const first = screen.getByRole("region", { name: "first editor" });
    const second = screen.getByRole("region", { name: "second editor" });
    expectLabelsResolve(first);
    expectLabelsResolve(second);
    fireEvent.click(within(second).getByRole("button", { name: "Add array index to success field path" }));
    expect(document.activeElement).toBe(textField(within(second).getByRole("group", { name: "Success field path" }), 4));
    expectLabelsResolve(first);
    expectLabelsResolve(second);
  });

  test("user-added rows never collide with existing or removed-then-readded rows", () => {
    const { lastDraft } = mount(hydrateLiveAssertion(PRESENCE)!);
    const witnessPath = group("Success field path");
    const addKey = within(witnessPath).getByRole("button", { name: "Add object key to success field path" });
    fireEvent.click(within(witnessPath).getByRole("button", { name: "Remove segment 1" }));
    fireEvent.click(addKey);
    fireEvent.click(addKey);
    fireEvent.click(within(witnessPath).getByRole("button", { name: "Remove segment 2" }));
    fireEvent.click(addKey);
    const rowIds = [...lastDraft().witnessPath, ...lastDraft().conditionPath].map((row) => row.id);
    expect(new Set(rowIds).size).toBe(rowIds.length);
    expect(document.activeElement).toBe(textField(witnessPath, lastDraft().witnessPath.length));
    expectLabelsResolve(document);
  });

  test("path type selects reuse the existing account-field styling with explicit labels", () => {
    mount();
    const selects = document.querySelectorAll("select");
    expect(selects.length).toBe(3);
    for (const select of selects) {
      expect(select.parentElement?.classList.contains("account-field")).toBe(true);
      expect(select.parentElement?.querySelector(`label[for="${select.id}"]`)).not.toBeNull();
    }
  });
});
