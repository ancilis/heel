// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
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


function topFinding(review: ReviewEnvelopeV1) {
  const reachable = review.findings.filter((finding) => finding.reachable);
  const candidates = reachable.length > 0 ? reachable : review.findings;
  return [...candidates].sort((left, right) => {
    const severity = Number(right.severity === "block") - Number(left.severity === "block");
    if (severity !== 0) return severity;
    return left.surface_id.localeCompare(right.surface_id, "en-US");
  })[0] ?? null;
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
  const [storageMessage, setStorageMessage] = useState("");
  const clientRef = useRef<BrowserReviewClient | null>(null);
  const storeRef = useRef<LocalReviewStore | null>(null);
  const inputHeadingRef = useRef<HTMLDivElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const lastRequestKindRef = useRef<"initial" | "rerun">("initial");

  useEffect(() => {
    const client = new BrowserReviewClient();
    const store = new LocalReviewStore();
    clientRef.current = client;
    storeRef.current = store;
    const unsubscribe = client.subscribe((status) => {
      setEngineStatus(status);
      if (status === "reviewing") setPhase("reviewing");
    });
    void client.whenReady().then(
      () => setEngineStatus("ready"),
      () => setEngineStatus("failed"),
    );
    void store.list().then(setHistory);
    return () => {
      unsubscribe();
      client.dispose();
      clientRef.current = null;
      storeRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (inputOpen) inputHeadingRef.current?.focus();
  }, [inputOpen]);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  const finding = useMemo(() => topFinding(result), [result]);
  const regression = finding === null ? null : result.suggested_regressions.find((item) => (
    item.surface_id === finding.surface_id && item.scenario_hint === finding.risk
  )) ?? null;
  const disabled = phase === "loading_engine" || phase === "reviewing";
  const jsonExport = reviewToJson(result);
  const markdownExport = reviewToMarkdown(result, receipt);

  async function refreshHistory(): Promise<void> {
    const store = storeRef.current;
    if (store !== null) setHistory(await store.list());
  }

  async function execute(nextSource: string): Promise<void> {
    const client = clientRef.current;
    if (client === null) {
      setError("The browser-local review engine is still starting. Try again in a moment.");
      return;
    }
    const bytes = new TextEncoder().encode(nextSource).byteLength;
    if (bytes > MAX_BROWSER_INPUT_BYTES) {
      setError("That document exceeds Heel's 2 MiB limit for browser review.");
      return;
    }
    if (nextSource.trim().length === 0) {
      setError("Paste or choose an OpenAPI JSON document first.");
      return;
    }
    setError("");
    setReceipt(null);
    setChanges(null);
    setPhase(client.status === "loading_engine" ? "loading_engine" : "reviewing");
    lastRequestKindRef.current = "initial";
    try {
      const completed = await client.review(nextSource);
      setResult(completed.envelope);
      setReviewSource(nextSource);
      setReviewBaseline(completed.envelope);
      setCanRerun(true);
      setAnswers(new Map());
      setReceipt(completed.receipt);
      setPhase("complete");
    } catch (caught) {
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
    void execute(SAMPLE_OPENAPI_SOURCE);
  }

  function analyzeMine(): void {
    setInputOpen(true);
    setSource("");
    setAnswers(new Map());
    setReceipt(null);
    setChanges(null);
    setError("");
  }

  async function rerunWithAnswers(): Promise<void> {
    const client = clientRef.current;
    const submitted = [...answers.values()];
    if (
      client === null
      || reviewSource === null
      || reviewBaseline === null
      || !canRerun
      || submitted.length === 0
    ) return;
    setError("");
    setPhase(client.status === "loading_engine" ? "loading_engine" : "reviewing");
    const before = result;
    lastRequestKindRef.current = "rerun";
    try {
      const completed = await client.rerun(reviewSource, reviewBaseline, submitted);
      setResult(completed.envelope);
      setReceipt(completed.receipt);
      setChanges({
        findings: completed.envelope.summary.findings - before.summary.findings,
        questions: completed.envelope.summary.questions - before.summary.questions,
      });
      setPhase("complete");
    } catch (caught) {
      if (caught instanceof BrowserReviewClientError && caught.code === "review_cancelled") {
        setPhase("cancelled");
      } else {
        setError(publicFailure(caught));
        setPhase("failed");
      }
    }
  }

  function answerQuestion(answer: ReviewAnswer): void {
    setAnswers((current) => {
      const next = new Map(current);
      next.set(questionAnswerKey(answer), answer);
      return next;
    });
  }

  function cancelReview(): void {
    clientRef.current?.cancel();
    setPhase("cancelled");
  }

  function retryReview(): void {
    clientRef.current?.restart();
    if (lastRequestKindRef.current === "rerun") {
      void rerunWithAnswers();
    } else {
      void execute(source);
    }
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
    const stored = await storeRef.current?.save(result);
    if (stored) {
      setStorageMessage("Validated result saved on this device only.");
      await refreshHistory();
    } else {
      setStorageMessage("Local storage is unavailable. Your current result remains in memory.");
    }
  }

  async function deleteResult(reviewId: string): Promise<void> {
    const removed = await storeRef.current?.delete(reviewId);
    if (!removed) setStorageMessage("Local storage is unavailable. No in-memory result was lost.");
    await refreshHistory();
  }

  async function clearHistory(): Promise<void> {
    const cleared = await storeRef.current?.clear();
    if (!cleared) setStorageMessage("Local storage is unavailable. No in-memory result was lost.");
    await refreshHistory();
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
          <p className="eyebrow">Completed example review</p>
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
            onSubmit={() => void execute(source)}
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
      {phase === "failed" || phase === "cancelled" ? (
        <button className="button button-secondary" type="button" onClick={retryReview}>Retry locally</button>
      ) : null}

      {finding ? <FindingView finding={finding} regression={regression} /> : (
        <p className="empty-result">No launch findings in this review.</p>
      )}

      <div className="evidence-grid">
        <section className="evidence-panel" aria-labelledby="controls-title">
          <p className="eyebrow">Controls</p>
          <h3 id="controls-title">Recommended controls</h3>
          <ul>
            {result.recommended_controls.map((control) => (
              <li key={`${control.surface_type}:${control.surface_id}:${control.risk}`}>
                <strong>{control.control}</strong>
                <span>{control.surface_id} · {control.reason}</span>
              </li>
            ))}
          </ul>
        </section>
        <section className="evidence-panel" aria-labelledby="regressions-title">
          <p className="eyebrow">Keep the fix</p>
          <h3 id="regressions-title">Suggested regressions</h3>
          <ul>
            {result.suggested_regressions.map((item) => (
              <li key={`${item.surface_type}:${item.surface_id}:${item.name}`}>
                <code>{item.name}</code>
                <span>{item.scenario_hint} · {item.safety}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <QuestionList
        questions={result.questions}
        answers={answers}
        disabled={disabled || !canRerun}
        onAnswer={answerQuestion}
        onRerun={() => void rerunWithAnswers()}
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
          <button className="button button-primary" type="button" onClick={() => void saveResult()}>
            Save result on this device
          </button>
          {storageMessage ? <p className="storage-message" aria-live="polite">{storageMessage}</p> : null}
        </section>
      </div>

      <section className="history-card" aria-labelledby="history-title">
        <div className="history-heading">
          <div>
            <p className="eyebrow">Optional, device local</p>
            <h3 id="history-title">Local result history</h3>
          </div>
          <button className="text-button" type="button" onClick={() => void clearHistory()}>
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
                  onClick={() => {
                    setResult(item.envelope);
                    setReviewSource(null);
                    setReviewBaseline(null);
                    setCanRerun(false);
                    setAnswers(new Map());
                    setReceipt(null);
                    setChanges(null);
                    setError("");
                    setPhase("complete");
                  }}
                >
                  <strong>{item.envelope.product_id}</strong>
                  <span>{item.envelope.gate_status} · {item.envelope.summary.findings} findings</span>
                </button>
                <button className="text-button" type="button" onClick={() => void deleteResult(item.envelope.review_id)}>
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
