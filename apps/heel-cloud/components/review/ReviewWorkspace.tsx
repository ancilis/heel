// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import {
  BrowserReviewClient,
  BrowserReviewClientError,
  MAX_BROWSER_INPUT_BYTES,
  type BrowserReviewStatus,
} from "../../lib/browser-review-client";
import { LocalReviewStore, type StoredLocalReviewV1 } from "../../lib/local-reviews";
import {
  reviewDownloadName,
  reviewToJson,
  reviewToMarkdown,
} from "../../lib/review-export";
import type { ReviewAnswer, ReviewAnswerReceiptV1 } from "../../lib/review-presentation";
import type { ReviewEnvelopeV1 } from "../../lib/review-v1";
import { SAMPLE_OPENAPI_SOURCE } from "../../lib/sample-openapi";
import { FindingView } from "./FindingView";
import { OpenApiInput } from "./OpenApiInput";
import { PrivacyReceipt } from "./PrivacyReceipt";
import { QuestionList, questionAnswerKey } from "./QuestionList";


type ReviewPhase = "example" | "loading_engine" | "reviewing" | "complete" | "failed" | "cancelled";
type ReviewProvenance = "example" | "custom" | "history";
type ReviewRequestSnapshot = Readonly<{
  kind: "initial";
  source: string;
  provenance: Exclude<ReviewProvenance, "history">;
}> | Readonly<{
  kind: "rerun";
  source: string;
  baseline: ReviewEnvelopeV1;
  answers: ReviewAnswer[];
  before: ReviewEnvelopeV1;
  provenance: Exclude<ReviewProvenance, "history">;
}>;

const COLLECTION_PAGE_SIZE = 20;


function ProgressiveList<T>({
  items,
  label,
  renderItem,
}: {
  items: T[];
  label: string;
  renderItem(item: T, index: number): ReactNode;
}) {
  const [visible, setVisible] = useState(COLLECTION_PAGE_SIZE);
  const shown = items.slice(0, visible);
  return (
    <>
      <ul>{shown.map(renderItem)}</ul>
      {visible < items.length ? (
        <button
          className="text-button load-more"
          type="button"
          onClick={() => setVisible((current) => Math.min(current + COLLECTION_PAGE_SIZE, items.length))}
        >
          Load more {label} ({items.length - visible} remaining)
        </button>
      ) : null}
    </>
  );
}


function topFinding(review: ReviewEnvelopeV1) {
  const reachableOnly = review.findings.some((finding) => finding.reachable);
  let bestIndex = -1;
  review.findings.forEach((finding, index) => {
    if (reachableOnly && !finding.reachable) return;
    if (bestIndex < 0) {
      bestIndex = index;
      return;
    }
    const current = review.findings[bestIndex];
    const severity = Number(current.severity === "block") - Number(finding.severity === "block");
    if (severity < 0 || (severity === 0 && finding.surface_id.localeCompare(current.surface_id, "en-US") < 0)) {
      bestIndex = index;
    }
  });
  return {
    finding: bestIndex < 0 ? null : review.findings[bestIndex],
    index: bestIndex,
  };
}


function publicFailure(error: unknown): string {
  return error instanceof BrowserReviewClientError
    ? error.publicMessage
    : "The browser-local review could not be completed safely.";
}


function statusMessage(phase: ReviewPhase, review: ReviewEnvelopeV1): string {
  if (phase === "example") return `Example review complete · ${review.summary.findings} findings · ${review.summary.blockers} blocker`;
  if (phase === "loading_engine") return "Loading the browser-local Python engine · your input remains in memory";
  if (phase === "reviewing") return "Reviewing locally · no analyzer network calls";
  if (phase === "failed") return "Review failed · your input and answers remain in memory";
  if (phase === "cancelled") return "Review cancelled · your input and answers remain in memory";
  return `Review complete · ${review.summary.findings} findings · ${review.summary.blockers} blocker`;
}


export function ReviewWorkspace({ initialReview }: { initialReview: ReviewEnvelopeV1 }) {
  const [result, setResult] = useState(initialReview);
  const [provenance, setProvenance] = useState<ReviewProvenance>("example");
  const [source, setSource] = useState(SAMPLE_OPENAPI_SOURCE);
  const [reviewSource, setReviewSource] = useState<string | null>(SAMPLE_OPENAPI_SOURCE);
  const [reviewBaseline, setReviewBaseline] = useState<ReviewEnvelopeV1 | null>(initialReview);
  const [canRerun, setCanRerun] = useState(false);
  const [inputOpen, setInputOpen] = useState(false);
  const [phase, setPhase] = useState<ReviewPhase>("example");
  const [engineStatus, setEngineStatus] = useState<BrowserReviewStatus>("loading_engine");
  const [error, setError] = useState("");
  const [answers, setAnswers] = useState<Map<string, ReviewAnswer>>(new Map());
  const [receipt, setReceipt] = useState<ReviewAnswerReceiptV1 | null>(null);
  const [changes, setChanges] = useState<{ findings: number; questions: number } | null>(null);
  const [history, setHistory] = useState<StoredLocalReviewV1[]>([]);
  const [storageNotice, setStorageNotice] = useState<{ reviewId: string; message: string } | null>(null);
  const [retryAvailable, setRetryAvailable] = useState(false);
  const clientRef = useRef<BrowserReviewClient | null>(null);
  const storeRef = useRef<LocalReviewStore | null>(null);
  const inputHeadingRef = useRef<HTMLDivElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const requestGenerationRef = useRef(0);
  const requestActiveRef = useRef(false);
  const retryRequestRef = useRef<ReviewRequestSnapshot | null>(null);

  useEffect(() => {
    const client = new BrowserReviewClient();
    const store = new LocalReviewStore();
    clientRef.current = client;
    storeRef.current = store;
    const unsubscribe = client.subscribe((status) => {
      setEngineStatus(status);
      if (status === "reviewing" && requestActiveRef.current) setPhase("reviewing");
    });
    void client.whenReady().then(
      () => setEngineStatus("ready"),
      () => setEngineStatus("failed"),
    );
    void store.list().then(setHistory, () => {
      setStorageNotice({
        reviewId: initialReview.review_id,
        message: "Local storage is unavailable. Your current result remains in memory.",
      });
    });
    return () => {
      requestGenerationRef.current += 1;
      requestActiveRef.current = false;
      unsubscribe();
      client.dispose();
      clientRef.current = null;
      storeRef.current = null;
    };
  }, [initialReview.review_id]);

  useEffect(() => {
    if (inputOpen) inputHeadingRef.current?.focus();
  }, [inputOpen]);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  const primary = useMemo(() => topFinding(result), [result]);
  const finding = primary.finding;
  const additionalFindings = useMemo(
    () => result.findings.filter((_item, index) => index !== primary.index),
    [result, primary.index],
  );
  const regression = finding === null ? null : result.suggested_regressions.find((item) => (
    item.surface_id === finding.surface_id && item.scenario_hint === finding.risk
  )) ?? null;
  const disabled = phase === "loading_engine" || phase === "reviewing";
  const jsonExport = useMemo(() => reviewToJson(result), [result]);
  const markdownExport = useMemo(() => reviewToMarkdown(result, receipt), [result, receipt]);
  const provenanceLabel = provenance === "custom"
    ? "Your completed review"
    : provenance === "history"
      ? "Saved local review"
      : "Completed example review";

  async function refreshHistory(reviewId: string): Promise<void> {
    const store = storeRef.current;
    try {
      if (store === null) throw new Error("local store is unavailable");
      setHistory(await store.list());
    } catch {
      setStorageNotice({
        reviewId,
        message: "Local storage is unavailable. Your current result remains in memory.",
      });
    }
  }

  async function runRequest(request: ReviewRequestSnapshot): Promise<void> {
    const client = clientRef.current;
    if (client === null) {
      setError("The browser-local review engine is still starting. Try again in a moment.");
      return;
    }
    if (request.kind === "initial") {
      const bytes = new TextEncoder().encode(request.source).byteLength;
      if (bytes > MAX_BROWSER_INPUT_BYTES) {
        setError("That document exceeds Heel's 2 MiB limit for browser review.");
        return;
      }
      if (request.source.trim().length === 0) {
        setError("Paste or choose an OpenAPI JSON document first.");
        return;
      }
    }
    const generation = ++requestGenerationRef.current;
    requestActiveRef.current = true;
    retryRequestRef.current = request;
    setRetryAvailable(true);
    setError("");
    if (request.kind === "initial") {
      setReceipt(null);
      setChanges(null);
    }
    setPhase(client.status === "loading_engine" ? "loading_engine" : "reviewing");
    try {
      const completed = request.kind === "initial"
        ? await client.review(request.source)
        : await client.rerun(request.source, request.baseline, request.answers);
      if (generation !== requestGenerationRef.current) return;
      requestActiveRef.current = false;
      retryRequestRef.current = null;
      setRetryAvailable(false);
      setResult(completed.envelope);
      setProvenance(request.provenance);
      if (request.kind === "initial") {
        setReviewSource(request.source);
        setReviewBaseline(completed.envelope);
        setCanRerun(true);
        setAnswers(new Map());
      } else {
        setChanges({
          findings: completed.envelope.summary.findings - request.before.summary.findings,
          questions: completed.envelope.summary.questions - request.before.summary.questions,
        });
      }
      setReceipt(completed.receipt);
      setPhase("complete");
    } catch (caught) {
      if (generation !== requestGenerationRef.current) return;
      requestActiveRef.current = false;
      if (caught instanceof BrowserReviewClientError && caught.code === "review_cancelled") {
        setPhase("cancelled");
      } else {
        setError(publicFailure(caught));
        setPhase("failed");
      }
    }
  }

  function runSample(): void {
    setInputOpen(false);
    setSource(SAMPLE_OPENAPI_SOURCE);
    setAnswers(new Map());
    void runRequest({ kind: "initial", source: SAMPLE_OPENAPI_SOURCE, provenance: "example" });
  }

  function analyzeMine(): void {
    requestGenerationRef.current += 1;
    requestActiveRef.current = false;
    retryRequestRef.current = null;
    setRetryAvailable(false);
    setInputOpen(true);
    setSource("");
    setAnswers(new Map());
    setReceipt(null);
    setChanges(null);
    setError("");
    setPhase(provenance === "example" ? "example" : "complete");
  }

  function rerunWithAnswers(): void {
    const submitted = [...answers.values()];
    if (
      reviewSource === null
      || reviewBaseline === null
      || !canRerun
      || submitted.length === 0
    ) return;
    void runRequest({
      kind: "rerun",
      source: reviewSource,
      baseline: reviewBaseline,
      answers: submitted.map((answer) => ({ ...answer })),
      before: result,
      provenance: provenance === "custom" ? "custom" : "example",
    });
  }

  function answerQuestion(answer: ReviewAnswer): void {
    setAnswers((current) => {
      const next = new Map(current);
      next.set(questionAnswerKey(answer), answer);
      return next;
    });
  }

  function cancelReview(): void {
    requestGenerationRef.current += 1;
    requestActiveRef.current = false;
    clientRef.current?.cancel();
    setPhase("cancelled");
  }

  function retryReview(): void {
    const request = retryRequestRef.current;
    if (request === null) return;
    clientRef.current?.restart();
    void runRequest(request);
  }

  function prepareDownload(
    event: ReactMouseEvent<HTMLAnchorElement>,
    content: string,
    mimeType: string,
  ): void {
    try {
      const url = URL.createObjectURL(new Blob([content], { type: `${mimeType};charset=utf-8` }));
      event.currentTarget.href = url;
      setTimeout(() => URL.revokeObjectURL(url), 1_000);
    } catch {
      event.preventDefault();
      setError("This browser could not prepare the local download.");
    }
  }

  async function saveResult(): Promise<void> {
    if (disabled) return;
    const reviewId = result.review_id;
    try {
      const store = storeRef.current;
      if (store === null) throw new Error("local store is unavailable");
      const stored = await store.save(result);
      if (!stored) throw new Error("local save was unavailable");
      setStorageNotice({ reviewId, message: "Validated result saved on this device only." });
      await refreshHistory(reviewId);
    } catch {
      setStorageNotice({
        reviewId,
        message: "Local storage is unavailable. Your current result remains in memory.",
      });
    }
  }

  async function deleteResult(reviewId: string): Promise<void> {
    if (disabled) return;
    const visibleReviewId = result.review_id;
    try {
      const store = storeRef.current;
      if (store === null || !await store.delete(reviewId)) throw new Error("local delete was unavailable");
      setStorageNotice((current) => current?.reviewId === reviewId ? null : current);
      await refreshHistory(visibleReviewId);
    } catch {
      setStorageNotice({
        reviewId: visibleReviewId,
        message: "Local storage is unavailable. No in-memory result was lost.",
      });
    }
  }

  async function clearHistory(): Promise<void> {
    if (disabled) return;
    const reviewId = result.review_id;
    try {
      const store = storeRef.current;
      if (store === null || !await store.clear()) throw new Error("local clear was unavailable");
      setStorageNotice(null);
      await refreshHistory(reviewId);
    } catch {
      setStorageNotice({
        reviewId,
        message: "Local storage is unavailable. No in-memory result was lost.",
      });
    }
  }

  function openHistory(item: StoredLocalReviewV1): void {
    if (disabled) return;
    requestGenerationRef.current += 1;
    requestActiveRef.current = false;
    retryRequestRef.current = null;
    setRetryAvailable(false);
    setResult(item.envelope);
    setProvenance("history");
    setReviewSource(null);
    setReviewBaseline(null);
    setCanRerun(false);
    setAnswers(new Map());
    setReceipt(null);
    setChanges(null);
    setError("");
    setStorageNotice(null);
    setPhase("complete");
  }

  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Launch abuse review · browser local</p>
          <h1>Find the launch blocker hidden in your API.</h1>
          <p className="hero-lede">
            Heel turns an OpenAPI document into reachable abuse evidence,
            recommended controls, and regression tests without uploading the document.
          </p>
          <div className="hero-actions">
            <button className="button button-primary" type="button" onClick={runSample} disabled={disabled}>
              Run the sample
            </button>
            <button className="button button-secondary" type="button" onClick={analyzeMine} disabled={disabled}>
              Analyze mine
            </button>
            <a className="text-link" href="#mcp">Use Heel with an agent</a>
          </div>
          <ul className="boundary-list" aria-label="Product boundaries">
            <li>Static review only</li>
            <li>No live probing</li>
            <li>No account required</li>
          </ul>
        </div>
        <aside className="hero-proof" aria-label="Current result summary">
          <p className="proof-label">Generated by Heel 1.1.0</p>
          <div className="gate-row">
            <span className={`gate gate-${result.gate_status}`}>{result.gate_status}</span>
            <span>{result.summary.blockers} reachable launch blocker</span>
          </div>
          {finding ? <p>{finding.reason}</p> : <p>No launch findings in this review.</p>}
          {finding ? (
            <div className="proof-control">
              <span>Control</span>
              <strong>{finding.control}</strong>
            </div>
          ) : null}
          {regression ? (
            <div className="proof-regression">
              <span>Regression</span>
              <code>{regression.name}</code>
            </div>
          ) : null}
        </aside>
      </section>

      <section className="review-workspace" id="review" aria-labelledby="workspace-title">
      <div className="workspace-bar">
        <div>
          <p className="eyebrow">{provenanceLabel}</p>
          <h2 id="workspace-title">See the evidence before you install anything.</h2>
        </div>
      </div>

      {inputOpen ? (
        <div ref={inputHeadingRef} tabIndex={-1} className="input-focus-target">
          <OpenApiInput
            source={source}
            disabled={disabled}
            onSourceChange={setSource}
            onError={setError}
            onSubmit={() => void runRequest({ kind: "initial", source, provenance: "custom" })}
          />
        </div>
      ) : null}

      {error ? <div className="error-message" role="alert" tabIndex={-1} ref={errorRef}>{error}</div> : null}

      <div className="review-status" role="status" aria-live="polite" aria-atomic="true">
        <span className="status-dot" aria-hidden="true" />
        {statusMessage(phase, result)}
        <span className="engine-state">Engine: {engineStatus.replaceAll("_", " ")}</span>
      </div>
      {disabled ? (
        <button className="text-button" type="button" onClick={cancelReview}>Cancel review</button>
      ) : null}
      {(phase === "failed" || phase === "cancelled") && retryAvailable ? (
        <button className="button button-secondary" type="button" onClick={retryReview}>Retry locally</button>
      ) : null}

      {finding ? <FindingView finding={finding} regression={regression} /> : (
        <p className="empty-result">No launch findings in this review.</p>
      )}

      <div className="evidence-grid">
        <section className="evidence-panel" aria-labelledby="controls-title">
          <p className="eyebrow">Controls</p>
          <h3 id="controls-title">Recommended controls</h3>
          <ProgressiveList
            key={`${result.review_id}:controls`}
            items={result.recommended_controls}
            label="recommended controls"
            renderItem={(control, index) => (
              <li key={`${control.surface_type}:${control.surface_id}:${control.risk}:${index}`}>
                <strong>{control.control}</strong>
                <span>{control.surface_id} · {control.reason}</span>
              </li>
            )}
          />
        </section>
        <section className="evidence-panel" aria-labelledby="regressions-title">
          <p className="eyebrow">Keep the fix</p>
          <h3 id="regressions-title">Suggested regressions</h3>
          <ProgressiveList
            key={`${result.review_id}:regressions`}
            items={result.suggested_regressions}
            label="suggested regressions"
            renderItem={(item, index) => (
              <li key={`${item.surface_type}:${item.surface_id}:${item.name}:${index}`}>
                <code>{item.name}</code>
                <span>{item.scenario_hint} · {item.safety}</span>
              </li>
            )}
          />
        </section>
        {additionalFindings.length > 0 ? (
          <section className="evidence-panel evidence-panel-wide" aria-labelledby="additional-findings-title">
            <p className="eyebrow">Complete evidence</p>
            <h3 id="additional-findings-title">Additional findings</h3>
            <ProgressiveList
              key={`${result.review_id}:findings`}
              items={additionalFindings}
              label="additional findings"
              renderItem={(item, index) => (
                <li key={`${item.surface_type}:${item.surface_id}:${item.risk}:${index}`}>
                  <strong>{item.risk.replaceAll("_", " ")}</strong>
                  <span>{item.surface_id} · {item.reason} · Control: {item.control}</span>
                </li>
              )}
            />
          </section>
        ) : null}
      </div>

      <QuestionList
        key={result.review_id}
        questions={result.questions}
        answers={answers}
        disabled={disabled || !canRerun}
        onAnswer={answerQuestion}
        onRerun={rerunWithAnswers}
      />
      {reviewSource === null ? (
        <p className="history-source-note">
          Saved results do not retain the source. Review the OpenAPI again to rerun its questions.
        </p>
      ) : !canRerun ? (
        <p className="history-source-note">
          Run the sample or review your own OpenAPI once to enable guided reruns.
        </p>
      ) : null}

      {receipt ? (
        <section className="answer-receipt" aria-labelledby="receipt-title">
          <p className="eyebrow">Current session answer receipt</p>
          <h3 id="receipt-title">{receipt.confidence}</h3>
          <p>{receipt.assumption}</p>
          {changes ? (
            <p>Findings changed by {changes.findings}; questions changed by {changes.questions}.</p>
          ) : null}
          <ul>
            {receipt.items.map((item) => (
              <li key={`${item.surface}:${item.field}`}>
                {item.surface} · {item.field} · {item.receipt}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="local-tools">
        <PrivacyReceipt />
        <section className="export-card" aria-labelledby="export-title">
          <p className="eyebrow">Take the evidence</p>
          <h3 id="export-title">Local exports</h3>
          <p>Generated in this browser. The JSON envelope is not augmented.</p>
          <div className="export-actions">
            <a
              className="button button-secondary"
              download={reviewDownloadName(result, "json")}
              href="#"
              onClick={(event) => prepareDownload(event, jsonExport, "application/json")}
            >
              Download JSON
            </a>
            <a
              className="button button-secondary"
              download={reviewDownloadName(result, "md")}
              href="#"
              onClick={(event) => prepareDownload(event, markdownExport, "text/markdown")}
            >
              Download Markdown
            </a>
          </div>
          <button className="button button-primary" type="button" onClick={() => void saveResult()} disabled={disabled}>
            Save result on this device
          </button>
          {storageNotice?.reviewId === result.review_id ? (
            <p className="storage-message" aria-live="polite">{storageNotice.message}</p>
          ) : null}
        </section>
      </div>

      <section className="history-card" aria-labelledby="history-title">
        <div className="history-heading">
          <div>
            <p className="eyebrow">Optional, device local</p>
            <h3 id="history-title">Local result history</h3>
          </div>
          <button className="text-button" type="button" onClick={() => void clearHistory()} disabled={disabled}>
            Clear local history
          </button>
        </div>
        {history.length === 0 ? <p>No results explicitly saved on this device.</p> : (
          <ul>
            {history.map((item) => (
              <li key={item.envelope.review_id}>
                <button
                  className="history-open"
                  type="button"
                  disabled={disabled}
                  onClick={() => openHistory(item)}
                >
                  <strong>{item.envelope.product_id}</strong>
                  <span>{item.envelope.gate_status} · {item.envelope.summary.findings} findings</span>
                </button>
                <button
                  className="text-button"
                  type="button"
                  disabled={disabled}
                  onClick={() => void deleteResult(item.envelope.review_id)}
                >
                  Delete {item.envelope.product_id}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
      </section>
    </>
  );
}
