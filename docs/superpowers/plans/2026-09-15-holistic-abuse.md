# Holistic Abuse Implementation Plan

**Goal:** Turn the reviewed foundation into an extensible product-abuse testing workflow for owned applications.

**Architecture:** Preserve static review and existing runner contracts. Add digest-authorized local campaigns, bounded network execution, stateful assertions, coverage, regression comparison and a browser authoring/results surface.

**Tech Stack:** Python standard library, existing Heel scope/storage, React/TypeScript frontend, pytest and Vitest.

## Work

- [x] Fix the five review defects in `review_answers.py`, `openapi_model.py`, `static_review.py` and guided-answer UI. Test negative answers, mixed permissions, removed controls, intent/enforcement and realistic answer counts.
- [x] Add `campaign_contract.py` and `campaign_templates.py`: strict bounded schema, explicit rule families, deterministic campaign digest, declarative selectors/comparisons, complete manifest validation and reusable examples.
- [x] Add `campaign_transport.py`: fixed-origin HTTPS, pinned public DNS, explicit literal-loopback sandbox, credential references, bounded JSON, no redirects/retries, exact approved operations.
- [x] Add `campaign_runner.py`: scope/digest validation, atomic budget and attempt reservation, evidence hashes, assertions/preconditions, cleanup, cancellation, report storage/signature and regression comparison.
- [x] Add `campaign_cli.py` and wire CLI/MCP: prepare, authorize, run, report, compare and templates; no MCP authorization tool.
- [x] Add an independent local HTTP demo and integration tests for stateful abuse families and defended counterexamples.
- [x] Add browser campaign authoring/report UI and navigation with explicit coverage and no target traffic in the browser.
- [x] Update capability docs and downloadable artifacts; run focused tests, full Python/frontend/security/build gates and installed CLI/MCP acceptance. Final verification and private publication are recorded in the implementation report.

Implementation uses failing behavioral tests before each feature. Security boundaries are reviewed as part of each step. Progress is recorded here rather than treating a plan as completed work.
