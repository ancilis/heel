// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import sampleOpenApi from "../data/sample-openapi.json";
import sampleReview from "../data/sample-review.v1.json";
import type { ReviewEnvelopeV1 } from "../lib/review-v1";


const review = vi.fn();
const rerun = vi.fn();
const cancel = vi.fn();
const restart = vi.fn();
const dispose = vi.fn();
const save = vi.fn();
const list = vi.fn();
const remove = vi.fn();
const clear = vi.fn();

vi.mock("../lib/browser-review-client", async (importOriginal) => {
  const original = await importOriginal<typeof import("../lib/browser-review-client")>();
  return {
    ...original,
    BrowserReviewClient: class {
      status = "ready" as const;
      review = review;
      rerun = rerun;
      cancel = cancel;
      restart = restart;
      dispose = dispose;
      whenReady = vi.fn().mockResolvedValue(undefined);
      subscribe(listener: (status: string) => void) {
        listener("ready");
        return vi.fn();
      }
    },
  };
});

vi.mock("../lib/local-reviews", async (importOriginal) => {
  const original = await importOriginal<typeof import("../lib/local-reviews")>();
  return {
    ...original,
    LocalReviewStore: class {
      save = save;
      list = list;
      delete = remove;
      clear = clear;
    },
  };
});

import Home from "../app/page";
import McpQuickstart from "../app/mcp/page";
import { OpenApiInput } from "../components/review/OpenApiInput";
import { ReviewWorkspace } from "../components/review/ReviewWorkspace";


const sampleSource = `${JSON.stringify(sampleOpenApi, null, 2)}\n`;


function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}


function rehashEnvelope<T extends { review_id: string; result_hash: string }>(value: T): T {
  const body = structuredClone(value) as T;
  delete (body as Partial<T>).review_id;
  delete (body as Partial<T>).result_hash;
  const resultHash = createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  return { ...body, review_id: `review_${resultHash.slice(0, 20)}`, result_hash: resultHash } as T;
}


function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}


function namedReview(productId: string): ReviewEnvelopeV1 {
  return rehashEnvelope({
    ...structuredClone(sampleReview),
    product_id: productId,
  }) as ReviewEnvelopeV1;
}


afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

beforeEach(() => {
  vi.clearAllMocks();
  review.mockResolvedValue({ envelope: sampleReview, receipt: null });
  rerun.mockResolvedValue({
    envelope: sampleReview,
    receipt: {
      schema_version: "heel.review-presentation.v1",
      assumption: "not declared in this OpenAPI; not proof the control is absent",
      confidence: "confirmed_gaps",
      items: [{
        surface: "runagenttool",
        field: "tenant_filter",
        value: "not_enforced",
        receipt: "confirmed_gap",
      }],
    },
  });
  save.mockResolvedValue(true);
  list.mockResolvedValue([]);
  remove.mockResolvedValue(true);
  clear.mockResolvedValue(true);
});


describe("Heel anonymous launch review", () => {
  test("renders exact executable blocker evidence and immediate actions without a wall", () => {
    const { container } = render(<Home />);
    const hero = container.querySelector(".hero");
    expect(hero).toBeTruthy();

    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/launch blocker/i);
    expect(container.textContent).toMatch(/global beyond intended tenant/i);
    expect(container.textContent).toContain("tool scope minimization");
    expect(container.textContent).toMatch(/launch_review_runagenttool_agent_surface_overscope/i);
    expect(within(hero as HTMLElement).getByRole("button", { name: /run the sample/i })).toBeTruthy();
    expect(within(hero as HTMLElement).getByRole("button", { name: /analyze mine/i })).toBeTruthy();
    expect(screen.getByRole("link", { name: /use heel with an agent/i }).getAttribute("href")).toBe("/mcp");
    expect(within(hero as HTMLElement).getByText(/launch_review_runagenttool_agent_surface_overscope/i)).toBeTruthy();

    expect(container.textContent).toMatch(/runs here, not on our server/i);
    expect(container.textContent).not.toMatch(/sign up to review|customer count|accuracy rate|testimonial/i);
  });

  test("runs the committed sample through the background browser client", async () => {
    render(<Home />);

    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(review).toHaveBeenCalledWith(sampleSource));
    expect(screen.getByRole("status").textContent).toMatch(/review complete/i);
  });

  test("labels example, customer, and saved evidence with truthful provenance", async () => {
    list.mockResolvedValueOnce([{
      schema_version: "heel.local-review.v1",
      envelope: sampleReview,
      saved_at: 1_700_000_000_000,
      sync_state: "local_only",
    }]);
    render(<Home />);
    expect(screen.getByText("Completed example review")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    fireEvent.change(screen.getByLabelText(/paste openapi json/i), { target: { value: sampleSource } });
    fireEvent.click(screen.getByLabelText(/not credentials or customer data/i));
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    expect(await screen.findByText("Your completed review")).toBeTruthy();

    const candidates = await screen.findAllByRole("button", { name: /northstar-workspace-api/i });
    fireEvent.click(candidates.find((button) => button.classList.contains("history-open"))!);
    expect(screen.getByText("Saved local review")).toBeTruthy();
  });

  test("links the truthful first-party MCP download and executable", () => {
    render(<Home />);
    const setup = screen.getByRole("link", { name: /open local mcp setup/i });
    expect(setup.getAttribute("href")).toBe("/mcp");
    const section = screen.getByRole("heading", { name: /same review from your local ai surface/i }).closest("section");
    expect(section?.textContent).toContain("heel-sim");
    expect(section?.textContent).toContain("heel-mcp");
    expect(section?.textContent).toMatch(/first-party apache-2\.0/i);
    expect(section?.textContent).toMatch(/no account or package registry is required/i);
  });

  test("offers the verified Agent artifacts and exact local install command", () => {
    render(<McpQuickstart />);

    const wheel = screen.getByRole("link", { name: "Download Heel Agent 1.1.0" });
    expect(wheel.getAttribute("href")).toBe("/downloads/heel_sim-1.1.0-py3-none-any.whl");
    expect(wheel.hasAttribute("download")).toBe(true);
    const source = screen.getByRole("link", { name: /download source archive/i });
    expect(source.getAttribute("href")).toBe("/downloads/heel_sim-1.1.0.tar.gz");
    expect(source.hasAttribute("download")).toBe(true);

    const manifest = JSON.parse(readFileSync(
      resolve(process.cwd(), "public/downloads/heel-open-core-manifest.json"),
      "utf8",
    )) as { artifacts: Array<{ name: string; sha256: string }> };
    const wheelArtifact = manifest.artifacts.find((artifact) => artifact.name.endsWith(".whl"));
    expect(wheelArtifact).toBeTruthy();
    expect(document.body.textContent).toContain(wheelArtifact?.sha256);
    expect(document.body.textContent).toContain("python3 -m venv .venv");
    expect(document.body.textContent).toContain(
      ".venv/bin/python -m pip install ./heel_sim-1.1.0-py3-none-any.whl",
    );
    expect(document.body.textContent).not.toMatch(
      /not yet available as a public download|licensed source checkout|public main branch/i,
    );
  });

  test("states the MCP release, platform, privacy, and execution boundaries", () => {
    render(<McpQuickstart />);

    expect(screen.getByText(/base mcp core is apache-2\.0 licensed and free/i)).toBeTruthy();
    expect(screen.getByText(/pypi publication is not yet available/i)).toBeTruthy();
    expect(screen.getByText(/python 3\.11 or newer/i)).toBeTruthy();
    expect(screen.getByText(/posix filesystem/i)).toBeTruthy();
    expect(screen.getByText(/windows is not currently supported/i)).toBeTruthy();
    expect(screen.getByText(/client or model provider may receive or upload/i)).toBeTruthy();
    expect(screen.getByText(/heel cannot enforce that client-provider boundary/i)).toBeTruthy();
    expect(screen.getByText(/all exposed mcp tools remain constrained/i)).toBeTruthy();
    expect(screen.getByText(/pre-existing, human-created signed scope/i)).toBeTruthy();
    expect(screen.getByText(/heel mcp exposes no tool to create, widen, or relax a scope/i)).toBeTruthy();
    expect(screen.getByText(
      /scope creation is an out-of-band cli action; do not grant agent-controlled shells access to that cli, heel_home, or the signing key/i,
    )).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/an agent cannot create, widen, or relax one/i);
  });

  test("shows source bytes and rejects oversize input before worker messaging", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const input = screen.getByLabelText(/paste openapi json/i);
    const oversized = "a".repeat(2 * 1024 * 1024 + 1);
    fireEvent.change(input, { target: { value: oversized } });

    expect(screen.getByText(`${oversized.length.toLocaleString("en-US")} bytes / 2 MiB`)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/2 MiB limit/i);
    expect(review).not.toHaveBeenCalled();
  });

  test("requires an in-memory API-description acknowledgement before reviewing customer input", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    fireEvent.change(screen.getByLabelText(/paste openapi json/i), { target: { value: sampleSource } });
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/confirm this is an api description/i);
    expect(review).not.toHaveBeenCalled();

    fireEvent.click(screen.getByLabelText(/not credentials or customer data/i));
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    await waitFor(() => expect(review).toHaveBeenCalledWith(sampleSource));
  });

  test("fatally decodes selected files before review", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const picker = screen.getByLabelText(/choose openapi json file/i);
    const invalid = new File([new Uint8Array([0xc3, 0x28])], "broken.json", { type: "application/json" });
    fireEvent.change(picker, { target: { files: [invalid] } });

    expect((await screen.findByRole("alert")).textContent).toMatch(/UTF-8/i);
    expect(review).not.toHaveBeenCalled();
  });

  test("accepts a dropped JSON file and keeps it in component memory", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const dropZone = screen.getByRole("button", { name: /drop openapi json/i });
    const file = new File([sampleSource], "openapi.json", { type: "application/json" });
    fireEvent.drop(dropZone, { dataTransfer: { files: [file] } });

    await waitFor(() => expect((screen.getByLabelText(/paste openapi json/i) as HTMLTextAreaElement).value).toBe(sampleSource));
    expect(screen.getByRole("status", { name: /selected file/i }).textContent).toMatch(/openapi\.json/i);
    expect(save).not.toHaveBeenCalled();
  });

  test("commits only the latest asynchronous file selection", async () => {
    const firstRead = deferred<ArrayBuffer>();
    const secondRead = deferred<ArrayBuffer>();
    const onSourceChange = vi.fn();
    const onError = vi.fn();
    render(
      <OpenApiInput
        source=""
        disabled={false}
        onSourceChange={onSourceChange}
        onError={onError}
        onSubmit={vi.fn()}
      />,
    );
    const dropZone = screen.getByRole("button", { name: /drop openapi json/i });
    const first = {
      name: "first.json",
      size: 5,
      arrayBuffer: () => firstRead.promise,
    } as File;
    const second = {
      name: "second.json",
      size: 6,
      arrayBuffer: () => secondRead.promise,
    } as File;
    fireEvent.drop(dropZone, { dataTransfer: { files: [first] } });
    fireEvent.drop(dropZone, { dataTransfer: { files: [second] } });

    await act(async () => secondRead.resolve(new TextEncoder().encode("second").buffer));
    expect(onSourceChange).toHaveBeenCalledTimes(1);
    expect(onSourceChange).toHaveBeenLastCalledWith("second");
    await act(async () => firstRead.resolve(new TextEncoder().encode("first").buffer));
    expect(onSourceChange).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status", { name: /selected file/i }).textContent).toMatch(/second\.json/i);
  });

  test("does not commit an asynchronous file read after input unmount", async () => {
    const read = deferred<ArrayBuffer>();
    const onSourceChange = vi.fn();
    const onError = vi.fn();
    const { unmount } = render(
      <OpenApiInput
        source=""
        disabled={false}
        onSourceChange={onSourceChange}
        onError={onError}
        onSubmit={vi.fn()}
      />,
    );
    const file = { name: "late.json", size: 4, arrayBuffer: () => read.promise } as File;
    fireEvent.drop(screen.getByRole("button", { name: /drop openapi json/i }), {
      dataTransfer: { files: [file] },
    });
    unmount();
    await act(async () => read.resolve(new TextEncoder().encode("late").buffer));
    expect(onSourceChange).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  test("typing invalidates an older asynchronous file read", async () => {
    const read = deferred<ArrayBuffer>();
    const onSourceChange = vi.fn();
    render(
      <OpenApiInput
        source=""
        disabled={false}
        onSourceChange={onSourceChange}
        onError={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );
    const file = { name: "older.json", size: 5, arrayBuffer: () => read.promise } as File;
    fireEvent.drop(screen.getByRole("button", { name: /drop openapi json/i }), {
      dataTransfer: { files: [file] },
    });
    fireEvent.change(screen.getByLabelText(/paste openapi json/i), { target: { value: "newer typed source" } });
    expect(onSourceChange).toHaveBeenCalledTimes(1);
    expect(onSourceChange).toHaveBeenLastCalledWith("newer typed source");

    await act(async () => read.resolve(new TextEncoder().encode("older").buffer));
    expect(onSourceChange).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("status", { name: /selected file/i })).toBeNull();
  });

  test("a same-mount source reset invalidates an older asynchronous file read", async () => {
    const read = deferred<ArrayBuffer>();
    const onSourceChange = vi.fn();
    const props = {
      disabled: false,
      onSourceChange,
      onError: vi.fn(),
      onSubmit: vi.fn(),
    };
    const view = render(<OpenApiInput {...props} source="before reset" />);
    const file = { name: "older.json", size: 5, arrayBuffer: () => read.promise } as File;
    fireEvent.drop(screen.getByRole("button", { name: /drop openapi json/i }), {
      dataTransfer: { files: [file] },
    });
    view.rerender(<OpenApiInput {...props} source="reset by parent" />);

    await act(async () => read.resolve(new TextEncoder().encode("older").buffer));
    expect(onSourceChange).not.toHaveBeenCalled();
    expect(screen.queryByRole("status", { name: /selected file/i })).toBeNull();
  });

  test("restarting custom input invalidates a pending empty-source file read", async () => {
    const read = deferred<ArrayBuffer>();
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const file = { name: "stale.json", size: 5, arrayBuffer: () => read.promise } as File;
    fireEvent.drop(screen.getByRole("button", { name: /drop openapi json/i }), {
      dataTransfer: { files: [file] },
    });

    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    await act(async () => read.resolve(new TextEncoder().encode("stale").buffer));
    expect((screen.getByLabelText(/paste openapi json/i) as HTMLTextAreaElement).value).toBe("");
    expect(screen.queryByRole("status", { name: /selected file/i })).toBeNull();
  });

  test("restarting custom input returns focus to the reset input region", async () => {
    const { container } = render(<Home />);
    const analyzeMine = screen.getByRole("button", { name: /analyze mine/i });
    fireEvent.click(analyzeMine);
    const inputRegion = container.querySelector<HTMLElement>(".input-focus-target");
    await waitFor(() => expect(document.activeElement).toBe(inputRegion));

    analyzeMine.focus();
    expect(document.activeElement).toBe(analyzeMine);
    fireEvent.click(analyzeMine);
    await waitFor(() => expect(document.activeElement).toBe(inputRegion));
  });

  test("rejects non-JSON names and reports exact oversized file identity before decoding", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const dropZone = screen.getByRole("button", { name: /drop openapi json/i });
    fireEvent.drop(dropZone, {
      dataTransfer: { files: [new File([sampleSource], "credentials.txt", { type: "application/json" })] },
    });
    expect((await screen.findByRole("alert")).textContent).toMatch(/credentials\.txt.*\.json/i);

    const oversized = new File(["a".repeat(2 * 1024 * 1024 + 1)], "huge-api.json", { type: "text/plain" });
    fireEvent.drop(dropZone, { dataTransfer: { files: [oversized] } });
    expect((await screen.findByRole("alert")).textContent).toContain("huge-api.json");
    expect(screen.getByRole("alert").textContent).toContain("2,097,153 bytes");
    expect(review).not.toHaveBeenCalled();
  });

  test("only answers supported operation questions and reruns locally with a receipt", async () => {
    render(<Home />);
    expect(screen.getAllByText(/not answerable from this OpenAPI/i).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getAllByLabelText(/^not enforced:/i)[0]);
    fireEvent.click(screen.getByRole("button", { name: /rerun with answers/i }));

    await waitFor(() => expect(rerun).toHaveBeenCalledTimes(1));
    const submitted = rerun.mock.calls[0][2];
    expect(submitted).toEqual(expect.arrayContaining([
      expect.objectContaining({ value: "not_enforced" }),
    ]));
    expect(await screen.findByText("confirmed_gaps")).toBeTruthy();
    expect(screen.getByText(/not declared in this OpenAPI/i)).toBeTruthy();
    expect(screen.getByText(/findings changed by 0/i)).toBeTruthy();
  });

  test("binds guided answers to the source that produced the visible review", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    fireEvent.change(screen.getByLabelText(/paste openapi json/i), {
      target: { value: '{"openapi":"3.1.0","info":{"title":"Different","version":"1"},"paths":{}}' },
    });
    fireEvent.click(screen.getAllByLabelText(/^not enforced:/i)[0]);
    fireEvent.click(screen.getByRole("button", { name: /rerun with answers/i }));

    await waitFor(() => expect(rerun).toHaveBeenCalledTimes(1));
    expect(rerun.mock.calls[0][0]).toBe(sampleSource);
    expect(rerun.mock.calls[0][1]).toEqual(sampleReview);
  });

  test("keeps cumulative answers bound to the original successful baseline", async () => {
    const afterFirst = structuredClone(sampleReview);
    afterFirst.questions = afterFirst.questions.slice(1);
    afterFirst.summary.questions = afterFirst.questions.length;
    afterFirst.source_hash = "a".repeat(64);
    const validAfterFirst = rehashEnvelope(afterFirst);
    rerun.mockResolvedValueOnce({
      envelope: validAfterFirst,
      receipt: {
        schema_version: "heel.review-presentation.v1",
        assumption: "not declared in this OpenAPI; not proof the control is absent",
        confidence: "improved",
        items: [{
          surface: "runagenttool",
          field: "entitlement_check",
          value: "enforced",
          receipt: "applied",
        }],
      },
    });

    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getAllByLabelText(/^enforced:/i)[0]);
    fireEvent.click(screen.getByRole("button", { name: /rerun with answers/i }));
    await waitFor(() => expect(rerun).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getAllByLabelText(/^unknown:/i)[0]);
    fireEvent.click(screen.getByRole("button", { name: /rerun with answers/i }));

    await waitFor(() => expect(rerun).toHaveBeenCalledTimes(2));
    expect(rerun.mock.calls[1][1]).toEqual(sampleReview);
    expect(rerun.mock.calls[1][2]).toHaveLength(2);
  });

  test("requires one real local run before attaching answers to server-rendered example evidence", () => {
    render(<Home />);
    expect((screen.getAllByLabelText(/^not enforced:/i)[0] as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText(/run the sample or review your own openapi once/i)).toBeTruthy();
    expect(rerun).not.toHaveBeenCalled();
  });

  test("does not offer a false rerun for result-only local history", async () => {
    list.mockResolvedValueOnce([{
      schema_version: "heel.local-review.v1",
      envelope: sampleReview,
      saved_at: 1_700_000_000_000,
      sync_state: "local_only",
    }]);
    render(<Home />);
    const candidates = await screen.findAllByRole("button", { name: /northstar-workspace-api/i });
    const saved = candidates.find((button) => button.classList.contains("history-open"));
    expect(saved).toBeTruthy();
    fireEvent.click(saved!);

    expect(screen.getByText(/saved results do not retain the source/i)).toBeTruthy();
    expect((screen.getAllByLabelText(/^not enforced:/i)[0] as HTMLInputElement).disabled).toBe(true);
  });

  test("retries a failed rerun with the retained source, baseline, and answers", async () => {
    rerun.mockRejectedValueOnce(new Error("private worker failure"));
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    fireEvent.change(screen.getByLabelText(/paste openapi json/i), { target: { value: sampleSource } });
    fireEvent.click(screen.getByLabelText(/not credentials or customer data/i));
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(1));
    const answer = screen.getAllByLabelText(/^not enforced:/i)[0] as HTMLInputElement;
    fireEvent.click(answer);
    fireEvent.click(screen.getByRole("button", { name: /rerun with answers/i }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/could not be completed safely/i);
    expect((screen.getByLabelText(/paste openapi json/i) as HTMLTextAreaElement).value).toBe(sampleSource);
    expect(answer.checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: /retry locally/i }));

    await waitFor(() => expect(rerun).toHaveBeenCalledTimes(2));
    expect(restart).toHaveBeenCalledTimes(1);
    expect(rerun.mock.calls[1]).toEqual([
      sampleSource,
      sampleReview,
      [expect.objectContaining({ value: "not_enforced" })],
    ]);
    expect(review).toHaveBeenCalledTimes(1);
  });

  test("retries the immutable failed submission and still requires acknowledgement for edited input", async () => {
    const submitted = '{"openapi":"3.1.0","info":{"title":"Submitted","version":"1"},"paths":{}}';
    const edited = '{"openapi":"3.1.0","info":{"title":"Edited","version":"1"},"paths":{}}';
    review.mockRejectedValueOnce(new Error("private initial failure"));
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    const input = screen.getByLabelText(/paste openapi json/i);
    fireEvent.change(input, { target: { value: submitted } });
    fireEvent.click(screen.getByLabelText(/not credentials or customer data/i));
    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    await screen.findByRole("alert");

    fireEvent.change(input, { target: { value: edited } });
    fireEvent.click(screen.getByRole("button", { name: /retry locally/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(2));
    expect(review.mock.calls[1]).toEqual([submitted]);

    fireEvent.click(screen.getByRole("button", { name: /review this openapi/i }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/confirm this is an api description/i);
    expect(review).toHaveBeenCalledTimes(2);
  });

  test("starting a new custom review clears a stale retry action", async () => {
    review.mockRejectedValueOnce(new Error("private initial failure"));
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await screen.findByRole("alert");
    expect(screen.getByRole("button", { name: /retry locally/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /analyze mine/i }));
    expect(screen.queryByRole("button", { name: /retry locally/i })).toBeNull();
  });

  test("locks local result controls while busy and ignores completion after a newer visible result", async () => {
    const pending = deferred<{ envelope: ReviewEnvelopeV1; receipt: null }>();
    const late = namedReview("Late worker result");
    const saved = namedReview("Saved visible result");
    review.mockReturnValueOnce(pending.promise);
    list.mockResolvedValueOnce([{
      schema_version: "heel.local-review.v1",
      envelope: saved,
      saved_at: 1_700_000_000_000,
      sync_state: "local_only",
    }]);
    render(<Home />);
    const openSaved = (await screen.findAllByRole("button", { name: /saved visible result/i }))
      .find((button) => button.classList.contains("history-open"))!;
    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(review).toHaveBeenCalledTimes(1));

    const saveButton = screen.getByRole("button", { name: /save result on this device/i }) as HTMLButtonElement;
    const deleteButton = screen.getByRole("button", { name: /delete saved visible result/i }) as HTMLButtonElement;
    const clearButton = screen.getByRole("button", { name: /clear local history/i }) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);
    expect((openSaved as HTMLButtonElement).disabled).toBe(true);
    expect(deleteButton.disabled).toBe(true);
    expect(clearButton.disabled).toBe(true);
    fireEvent.click(saveButton);
    fireEvent.click(openSaved);
    fireEvent.click(deleteButton);
    fireEvent.click(clearButton);
    expect(save).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /cancel review/i }));
    fireEvent.click(openSaved);
    expect(screen.getByText("Saved local review")).toBeTruthy();
    await act(async () => pending.resolve({ envelope: late, receipt: null }));
    expect(screen.getAllByText("Saved visible result").length).toBeGreaterThan(0);
    expect(screen.queryByText("Late worker result")).toBeNull();
  });

  test("saves only on explicit request and keeps local history deletable", async () => {
    render(<Home />);
    await waitFor(() => expect(list).toHaveBeenCalledTimes(1));
    expect(save).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /save result on this device/i }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(sampleReview));
    expect(save.mock.calls[0][0]).not.toHaveProperty("source");
    expect(save.mock.calls[0][0]).not.toHaveProperty("answers");
    expect(screen.getByRole("button", { name: /clear local history/i })).toBeTruthy();
  });

  test("scopes save confirmation to its review and contains storage exceptions", async () => {
    const next = namedReview("New unsaved result");
    review.mockResolvedValueOnce({ envelope: next, receipt: null });
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /save result on this device/i }));
    expect(await screen.findByText(/validated result saved on this device only/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /run the sample/i }));
    await waitFor(() => expect(
      screen.getByRole("link", { name: /download json/i }).getAttribute("download"),
    ).toMatch(/new-unsaved-result/i));
    expect(screen.queryByText(/validated result saved on this device only/i)).toBeNull();

    save.mockRejectedValueOnce(new Error("quota wrapper failure"));
    fireEvent.click(screen.getByRole("button", { name: /save result on this device/i }));
    expect(await screen.findByText(/local storage is unavailable/i)).toBeTruthy();
  });

  test("clears the visible review save confirmation after deleting that saved review", async () => {
    list.mockResolvedValue([{
      schema_version: "heel.local-review.v1",
      envelope: sampleReview,
      saved_at: 1_700_000_000_000,
      sync_state: "local_only",
    }]);
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /save result on this device/i }));
    expect(await screen.findByText(/validated result saved on this device only/i)).toBeTruthy();

    fireEvent.click(await screen.findByRole("button", { name: /delete northstar-workspace-api/i }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith(sampleReview.review_id));
    expect(screen.queryByText(/validated result saved on this device only/i)).toBeNull();
  });

  test("clears the visible review save confirmation after clearing local history", async () => {
    render(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /save result on this device/i }));
    expect(await screen.findByText(/validated result saved on this device only/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /clear local history/i }));
    await waitFor(() => expect(clear).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/validated result saved on this device only/i)).toBeNull();
  });

  test("bounds large review collections and progressively reveals each collection", () => {
    const large = structuredClone(sampleReview);
    const count = 75;
    large.findings = Array.from({ length: count }, () => ({ ...sampleReview.findings[0] }));
    large.recommended_controls = Array.from({ length: count }, () => ({ ...sampleReview.findings[0] }));
    const matchingRegression = sampleReview.suggested_regressions.find(
      (item) => item.surface_id === sampleReview.findings[0].surface_id
        && item.scenario_hint === sampleReview.findings[0].risk,
    )!;
    large.suggested_regressions = Array.from({ length: count }, () => ({ ...matchingRegression }));
    large.questions = Array.from({ length: count }, () => ({ ...sampleReview.questions[0] }));
    large.summary = { findings: count, blockers: count, questions: count };
    const validLarge = rehashEnvelope(large) as ReviewEnvelopeV1;
    const { container } = render(<ReviewWorkspace initialReview={validLarge} />);

    const controls = screen.getByRole("heading", { name: /recommended controls/i }).closest("section")!;
    const regressions = screen.getByRole("heading", { name: /suggested regressions/i }).closest("section")!;
    const additional = screen.getByRole("heading", { name: /additional findings/i }).closest("section")!;
    expect(within(controls).getAllByRole("listitem")).toHaveLength(20);
    expect(within(regressions).getAllByRole("listitem")).toHaveLength(20);
    expect(within(additional).getAllByRole("listitem")).toHaveLength(20);
    expect(container.querySelectorAll(".question")).toHaveLength(20);

    fireEvent.click(within(controls).getByRole("button", { name: /load more recommended controls/i }));
    fireEvent.click(within(regressions).getByRole("button", { name: /load more suggested regressions/i }));
    fireEvent.click(within(additional).getByRole("button", { name: /load more additional findings/i }));
    fireEvent.click(screen.getByRole("button", { name: /load more confidence questions/i }));
    expect(within(controls).getAllByRole("listitem")).toHaveLength(40);
    expect(within(regressions).getAllByRole("listitem")).toHaveLength(40);
    expect(within(additional).getAllByRole("listitem")).toHaveLength(40);
    expect(container.querySelectorAll(".question")).toHaveLength(40);
  });

  test("creates bounded Blob downloads on demand and revokes them without an API", async () => {
    const outbound = vi.fn();
    const createObjectURL = vi.fn((blob: Blob) => {
      void blob;
      return "blob:heel-local-review";
    });
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("fetch", outbound);
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });
    vi.useFakeTimers();
    render(<Home />);

    const json = screen.getByRole("link", { name: /download json/i });
    const markdown = screen.getByRole("link", { name: /download markdown/i });
    expect(json.getAttribute("download")).toMatch(/\.json$/);
    expect(markdown.getAttribute("download")).toMatch(/\.md$/);
    expect(json.getAttribute("href")).toBe("#");
    json.addEventListener("click", (event) => event.preventDefault());
    markdown.addEventListener("click", (event) => event.preventDefault());
    fireEvent.click(json);
    fireEvent.click(markdown);
    expect(createObjectURL).toHaveBeenCalledTimes(2);
    const jsonBlob = createObjectURL.mock.calls[0][0] as Blob;
    const markdownBlob = createObjectURL.mock.calls[1][0] as Blob;
    expect(JSON.parse(await jsonBlob.text())).toEqual(sampleReview);
    expect(await markdownBlob.text()).toContain("launch\\_review\\_runagenttool");
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledTimes(2);
    expect(outbound).not.toHaveBeenCalled();
  });

  test("states the exact browser-local privacy receipt", () => {
    const { container } = render(<Home />);
    expect(container.textContent).toContain("This OpenAPI document was not sent to Heel");
    expect(container.textContent).toContain("dedicated browser worker");
    expect(container.textContent).toContain("0 analyzer network calls after same-origin runtime assets load");
    expect(container.textContent).toContain("Only validated results may be explicitly saved on this device");
    expect(container.textContent).toContain("No sync intent");
  });
});
