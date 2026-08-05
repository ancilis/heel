# Heel Local Agent Alpha Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the complete product to the Heel brand and ship a genuinely useful, local-first MCP flow that turns an OpenAPI JSON document into a deterministic launch review without an account, upload, or network call.

**Architecture:** Preserve the existing Apache core and commercial SaaS work, but rename the entire product atomically so package, CLI, MCP, state directories, protocol identifiers, documentation, and tests agree. Add one browser-compatible review service that wraps the existing OpenAPI importer and `review_product_models()` kernel in a versioned `ReviewEnvelope`; both the CLI and MCP call that service. Store projects and reviews only under `HEEL_HOME` in this milestone, and keep every cloud/sync action absent until an explicit sync contract is implemented later.

**Tech Stack:** Python 3.11+ standard library, MCP JSON-RPC over stdio, `unittest`, setuptools, deterministic JSON and SHA-256.

---

## File map

- Rename `arceo/` to `heel/`: the complete engine and commercial SaaS package.
- Rename `tests/test_arceo.py` and `tests/test_arceo_branding.py`: core and brand contract tests.
- Create `heel/review_contract.py`: versioned result, privacy, question, and sync-intent schema.
- Create `heel/review_service.py`: pure in-memory OpenAPI-to-review orchestration shared by all interfaces.
- Create `heel/local_projects.py`: local JSON persistence under `HEEL_HOME`; no remote transport.
- Create `heel/review_export.py`: deterministic Markdown export from `heel.review.v1`.
- Modify `heel/openapi_import.py`: emit Heel vendor-extension names and structured missing-rule questions.
- Modify `heel/mcp_server.py`: add working project/review/explain/export tools to the canonical MCP surface.
- Modify `heel/cli.py`: add `heel review openapi` using the exact same service as MCP.
- Modify `heel/scope.py`: expose `heel_home()` and `HEEL_*` environment names.
- Modify `pyproject.toml`, `MANIFEST.in`, `server.json`, `README.md`, and product docs: coherent Heel packaging and configuration.
- Create `tests/fixtures/reviews/sample_review_v1.json`: golden deterministic review used by native and future browser parity tests.
- Create `tests/test_review_contract.py`, `tests/test_review_service.py`, `tests/test_local_projects.py`, and `tests/test_mcp_review.py`: contract and customer-journey tests.

### Task 1: Atomically restore the Heel identity and package the full product

**Files:**
- Rename: `arceo/` → `heel/`
- Rename: `tests/test_arceo.py` → `tests/test_heel.py`
- Rename: `tests/test_arceo_branding.py` → `tests/test_heel_branding.py`
- Rename: `docs/ARCEOBENCH.md` → `docs/HEELBENCH.md`
- Rename: `.github/codex/prompts/10_arceobench.md` → `.github/codex/prompts/10_heelbench.md`
- Modify: `pyproject.toml`
- Modify: `MANIFEST.in`
- Modify: every tracked text file containing `Arceo`, `arceo`, or `ARCEO`
- Test: `tests/test_heel_branding.py`

- [ ] **Step 1: Replace the branding test with the failing Heel contract**

After renaming the test file, replace its body with:

```python
import importlib
from pathlib import Path
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HeelBrandingTests(unittest.TestCase):
    def test_python_package_imports_as_heel(self):
        module = importlib.import_module("heel")
        self.assertTrue(hasattr(module, "__version__"))

    def test_distribution_and_console_scripts_use_heel(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)
        self.assertEqual(project["project"]["name"], "heel-sim")
        self.assertEqual(
            project["project"]["scripts"],
            {
                "heel": "heel.cli:main",
                "heel-mcp": "heel.mcp_server:main",
                "heel-rest": "heel.rest:serve",
            },
        )
        self.assertEqual(project["tool"]["setuptools"]["packages"]["find"]["include"], ["heel*"])

    def test_no_retired_brand_remains_in_product_files(self):
        result = subprocess.run(
            [
                "rg", "-n", "-i", "arceo", ".",
                "--glob", "!.git/**", "--glob", "!docs/superpowers/specs/**",
                "--glob", "!docs/superpowers/plans/**", "--glob", "!*.pyc",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
```

- [ ] **Step 2: Run the brand test and verify it fails before the package move**

Run: `python3 -m unittest tests.test_heel_branding -v`

Expected: FAIL because `heel` cannot yet be imported and `pyproject.toml` still names the retired package.

- [ ] **Step 3: Move named files and perform the controlled text migration**

Run exactly:

```bash
git mv arceo heel
git mv tests/test_arceo.py tests/test_heel.py
git mv tests/test_arceo_branding.py tests/test_heel_branding.py
git mv docs/ARCEOBENCH.md docs/HEELBENCH.md
git mv .github/codex/prompts/10_arceobench.md .github/codex/prompts/10_heelbench.md
rg -l -0 'Arceo|arceo|ARCEO' --glob '!docs/superpowers/specs/**' --glob '!docs/superpowers/plans/**' | xargs -0 perl -pi -e 's/ARCEO/HEEL/g; s/Arceo/Heel/g; s/arceo/heel/g'
```

Then set the packaging blocks in `pyproject.toml` to:

```toml
[project]
name = "heel-sim"
version = "1.1.0"
description = "Heel reviews SaaS product models locally and shows the abuse paths and controls to address before launch."

[project.scripts]
heel = "heel.cli:main"
heel-mcp = "heel.mcp_server:main"
heel-rest = "heel.rest:serve"

[tool.setuptools.packages.find]
include = ["heel*"]

[tool.setuptools.package-data]
heel = ["scenarios_lib/*.json", "heldout/*.json"]

[tool.setuptools.exclude-package-data]
heel = ["**/__pycache__/*"]
```

Delete the obsolete `packages = ["heel"]` assignment rather than leaving both setuptools package modes configured. Preserve the existing classifiers, dependencies, optional dependencies, authors, URLs, and license while changing their brand paths to Heel.

- [ ] **Step 4: Run focused packaging and import tests**

Run: `python3 -m unittest tests.test_heel_branding tests.test_heel -v`

Expected: PASS, and the SaaS subpackage imports through `heel.saas`.

- [ ] **Step 5: Prove setuptools discovers the commercial subpackage**

Run:

```bash
python3 -c 'from setuptools import find_packages; p=find_packages(include=["heel*"]); assert "heel" in p and "heel.saas" in p, p; print(p)'
```

Expected: output includes both `heel` and `heel.saas`.

- [ ] **Step 6: Commit the atomic restoration**

```bash
git add -A
git commit -m "refactor: restore Heel identity atomically"
```

### Task 2: Freeze `heel.review.v1` and deterministic privacy contracts

**Files:**
- Create: `heel/review_contract.py`
- Create: `tests/test_review_contract.py`

- [ ] **Step 1: Write failing contract tests**

```python
import json
import unittest

from heel.review_contract import (
    EXECUTION_MODES,
    REVIEW_SCHEMA_VERSION,
    build_review_envelope,
    stable_json_hash,
)


class ReviewContractTests(unittest.TestCase):
    def test_envelope_is_deterministic_local_and_unsynced(self):
        review = {
            "product_id": "sample-saas",
            "launch_gate_status": "block",
            "changed_surfaces": [],
            "new_abuse_affordances": [{
                "surface_type": "exports",
                "surface_id": "export_users",
                "risk": "export_without_tenant_quota",
                "severity": "block",
                "control": "tenant quota",
                "reason": "export is reachable without a tenant quota",
                "reachable": True,
            }],
            "high_risk_missing_controls": [],
            "recommended_controls": [],
            "suggested_regression_tests": [],
            "safety": {"network_calls": False, "live_probing": False},
        }
        one = build_review_envelope(
            review, source_hash="source", model_hash="model", baseline_hash="baseline",
            execution_mode="machine_local", questions=[],
        )
        two = build_review_envelope(
            review, source_hash="source", model_hash="model", baseline_hash="baseline",
            execution_mode="machine_local", questions=[],
        )
        self.assertEqual(one, two)
        self.assertEqual(one["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(EXECUTION_MODES, {"browser_local", "machine_local", "cloud_isolated"})
        self.assertEqual(one["execution_mode"], "machine_local")
        self.assertEqual(one["review_id"], "review_" + one["result_hash"][:20])
        self.assertEqual(one["privacy"], {
            "execution": "machine_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })
        self.assertEqual(one["summary"]["blockers"], 1)

    def test_stable_hash_ignores_mapping_order(self):
        self.assertEqual(stable_json_hash({"a": 1, "b": 2}), stable_json_hash({"b": 2, "a": 1}))

    def test_contract_is_json_serializable(self):
        envelope = build_review_envelope({
            "product_id": "empty", "launch_gate_status": "pass",
            "changed_surfaces": [], "new_abuse_affordances": [],
            "high_risk_missing_controls": [], "recommended_controls": [],
            "suggested_regression_tests": [], "safety": {},
        }, source_hash="source", model_hash="model", baseline_hash="baseline",
           execution_mode="browser_local", questions=[])
        self.assertEqual(json.loads(json.dumps(envelope)), envelope)

    def test_unknown_execution_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "execution_mode"):
            build_review_envelope({}, source_hash="source", model_hash="model",
                                  baseline_hash=None, execution_mode="remote_magic", questions=[])
```

- [ ] **Step 2: Run the tests and verify the missing module failure**

Run: `python3 -m unittest tests.test_review_contract -v`

Expected: ERROR with `ModuleNotFoundError: No module named 'heel.review_contract'`.

- [ ] **Step 3: Implement the complete versioned envelope builder**

Create `heel/review_contract.py`:

```python
"""Versioned, JSON-only review contract shared by native, browser, MCP, and cloud clients."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


REVIEW_SCHEMA_VERSION = "heel.review.v1"
ENGINE_VERSION = "1.1.0"
EXECUTION_MODES = {"browser_local", "machine_local", "cloud_isolated"}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_json_hash(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def build_review_envelope(
    review: Mapping[str, Any], *, source_hash: str, model_hash: str,
    baseline_hash: str | None, execution_mode: str,
    questions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if execution_mode not in EXECUTION_MODES:
        raise ValueError(f"unsupported execution_mode: {execution_mode}")
    findings = [dict(item) for item in review.get("new_abuse_affordances", [])]
    findings.sort(key=lambda item: (
        0 if item.get("severity") == "block" else 1,
        str(item.get("surface_type", "")),
        str(item.get("surface_id", "")),
        str(item.get("risk", "")),
    ))
    envelope = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "product_id": str(review.get("product_id", "")),
        "source_hash": source_hash,
        "model_hash": model_hash,
        "baseline_hash": baseline_hash,
        "execution_mode": execution_mode,
        "gate_status": str(review.get("launch_gate_status", "pass")),
        "summary": {
            "findings": len(findings),
            "blockers": sum(item.get("severity") == "block" for item in findings),
            "questions": len(questions),
        },
        "findings": findings,
        "recommended_controls": [dict(item) for item in review.get("recommended_controls", [])],
        "suggested_regressions": [dict(item) for item in review.get("suggested_regression_tests", [])],
        "questions": [dict(item) for item in questions],
        "safety": dict(review.get("safety", {})),
        "privacy": {
            "execution": execution_mode,
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        },
    }
    result_hash = stable_json_hash(envelope)
    return {"review_id": "review_" + result_hash[:20], "result_hash": result_hash, **envelope}
```

- [ ] **Step 4: Run the contract tests**

Run: `python3 -m unittest tests.test_review_contract -v`

Expected: 4 tests PASS.

- [ ] **Step 5: Commit the contract**

```bash
git add heel/review_contract.py tests/test_review_contract.py
git commit -m "feat: freeze Heel review envelope v1"
```

### Task 3: Build the pure OpenAPI review service and missing-rule questions

**Files:**
- Create: `heel/review_service.py`
- Modify: `heel/openapi_import.py`
- Create: `tests/test_review_service.py`
- Create: `tests/fixtures/reviews/sample_review_v1.json`

- [ ] **Step 1: Write failing one-document review tests**

```python
import json
from pathlib import Path
import unittest

from heel.review_service import review_openapi


ROOT = Path(__file__).resolve().parents[1]


class ReviewServiceTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads((ROOT / "tests/fixtures/openapi/saas_api.json").read_text())

    def test_valid_openapi_returns_a_useful_local_review(self):
        result = review_openapi(self.spec)
        self.assertEqual(result["schema_version"], "heel.review.v1")
        self.assertFalse(result["privacy"]["network_calls"])
        self.assertFalse(result["privacy"]["uploaded"])
        self.assertGreater(result["summary"]["findings"], 0)
        self.assertIn(result["gate_status"], {"warn", "block"})
        self.assertTrue(result["findings"][0]["reason"])
        self.assertTrue(result["findings"][0]["control"])

    def test_same_input_produces_identical_envelope(self):
        self.assertEqual(review_openapi(self.spec), review_openapi(self.spec))

    def test_missing_metadata_becomes_structured_questions(self):
        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Question App", "version": "1"},
            "paths": {"/exports": {"get": {"operationId": "exportUsers"}}},
        })
        fields = {question["field"] for question in result["questions"]}
        self.assertIn("tenant_filter", fields)
        self.assertIn("entitlement_check", fields)

    def test_secret_examples_fail_without_echoing_the_secret(self):
        secret = "sk-live-1234567890abcdef"
        with self.assertRaisesRegex(ValueError, "secret-like value") as caught:
            review_openapi({
                "openapi": "3.1.0", "info": {"title": "Bad", "version": "1"},
                "paths": {}, "components": {"examples": {"bad": {"value": secret}}},
            })
        self.assertNotIn(secret, str(caught.exception))
```

- [ ] **Step 2: Run the service tests and verify the missing module failure**

Run: `python3 -m unittest tests.test_review_service -v`

Expected: ERROR with `ModuleNotFoundError: No module named 'heel.review_service'`.

- [ ] **Step 3: Implement one-document review orchestration**

Create `heel/review_service.py`:

```python
"""Pure in-memory review orchestration; safe to package for Pyodide later."""
from __future__ import annotations

import re
from typing import Any, Mapping

from .importers import LIST_FIELDS, PRODUCT_MODEL_VERSION
from .launch_review import review_product_models
from .openapi_import import product_model_from_openapi
from .review_contract import build_review_envelope, stable_json_hash


_WARNING_ROUTE = re.compile(r"for (?P<route>/\S+)$")


def empty_product_model(product_id: str) -> dict[str, Any]:
    model = {field: [] for field in LIST_FIELDS}
    model.update({
        "schema_version": PRODUCT_MODEL_VERSION,
        "product_id": product_id,
        "source": "heel:empty-baseline",
        "generated_at": "1970-01-01T00:00:00Z",
        "environments": ["synthetic"],
    })
    return model


def questions_from_warnings(warnings: list[str]) -> list[dict[str, Any]]:
    questions = []
    for warning in sorted(set(warnings)):
        route_match = _WARNING_ROUTE.search(warning)
        route = route_match.group("route") if route_match else "product"
        if warning.startswith("missing tenant metadata"):
            field = "tenant_filter"
            prompt = f"How is tenant access enforced for {route}?"
        elif warning.startswith("missing entitlement metadata"):
            field = "entitlement_check"
            prompt = f"Which plan or entitlement protects {route}?"
        else:
            field = "product_rule"
            prompt = warning
        questions.append({
            "id": f"{field}:{stable_json_hash([route, warning])[:12]}",
            "field": field,
            "surface": route,
            "prompt": prompt,
            "required": False,
        })
    return questions


def review_openapi(spec: Mapping[str, Any]) -> dict[str, Any]:
    model = product_model_from_openapi(spec, source="openapi:inline-local")
    baseline = empty_product_model(model["product_id"])
    review = review_product_models(baseline, model).to_dict()
    questions = questions_from_warnings(list(model.get("import_warnings", [])))
    return build_review_envelope(
        review,
        source_hash=stable_json_hash(spec),
        model_hash=stable_json_hash(model),
        baseline_hash=stable_json_hash(baseline),
        execution_mode="machine_local",
        questions=questions,
    )
```

In `heel/openapi_import.py`, change accepted vendor extensions from `x-arceo-*` to `x-heel-*`; do not add URL fetching or any network dependency.

- [ ] **Step 4: Run review, importer, and launch-review tests**

Run: `python3 -m unittest tests.test_review_service tests.test_openapi_import tests.test_final_integration -v`

Expected: PASS.

- [ ] **Step 5: Write and lock the golden fixture from the deterministic sample**

Run:

```bash
python3 -c 'import json; from pathlib import Path; from heel.review_service import review_openapi; p=Path("tests/fixtures/openapi/saas_api.json"); out=Path("tests/fixtures/reviews/sample_review_v1.json"); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(review_openapi(json.loads(p.read_text())), indent=2, sort_keys=True)+"\n")'
python3 -c 'import json; from pathlib import Path; d=json.loads(Path("tests/fixtures/reviews/sample_review_v1.json").read_text()); assert d["summary"]["findings"] > 0 and d["privacy"]["uploaded"] is False'
```

Expected: both commands exit 0 and the fixture contains at least one real finding.

- [ ] **Step 6: Commit the shared review service**

```bash
git add heel/openapi_import.py heel/review_service.py tests/test_review_service.py tests/fixtures/reviews/sample_review_v1.json tests/test_openapi_import.py
git commit -m "feat: review OpenAPI locally with Heel"
```

### Task 4: Add local projects and deterministic Markdown reports

**Files:**
- Create: `heel/local_projects.py`
- Create: `heel/review_export.py`
- Create: `tests/test_local_projects.py`

- [ ] **Step 1: Write failing persistence and export tests**

```python
import json
from pathlib import Path
import tempfile
import unittest

from heel.local_projects import LocalProjectStore
from heel.review_export import review_to_markdown


class LocalProjectTests(unittest.TestCase):
    def test_review_round_trip_stays_inside_selected_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(Path(tmp))
            envelope = {"review_id": "review_abc", "product_id": "sample", "gate_status": "block", "summary": {"findings": 1, "blockers": 1, "questions": 0}, "findings": []}
            store.save_review(envelope)
            self.assertEqual(store.get_review("review_abc"), envelope)
            self.assertEqual(store.list_reviews(), [{"review_id": "review_abc", "product_id": "sample", "gate_status": "block"}])
            self.assertEqual(list(Path(tmp).rglob("*.json")), [Path(tmp) / "reviews" / "review_abc.json"])

    def test_markdown_contains_gate_reason_and_control(self):
        markdown = review_to_markdown({
            "review_id": "review_abc", "product_id": "sample", "gate_status": "block",
            "summary": {"findings": 1, "blockers": 1, "questions": 0},
            "findings": [{"severity": "block", "reason": "Export crosses tenants", "control": "Enforce tenant filtering", "surface_id": "exportUsers"}],
            "privacy": {"execution": "local", "uploaded": False},
        })
        self.assertIn("# Heel launch review: sample", markdown)
        self.assertIn("Export crosses tenants", markdown)
        self.assertIn("Enforce tenant filtering", markdown)
        self.assertIn("not uploaded", markdown)
```

- [ ] **Step 2: Run the tests and verify the missing module failure**

Run: `python3 -m unittest tests.test_local_projects -v`

Expected: ERROR because `heel.local_projects` does not exist.

- [ ] **Step 3: Implement local-only persistence**

Create `heel/local_projects.py`:

```python
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


def default_home() -> Path:
    return Path(os.environ.get("HEEL_HOME", Path.cwd() / ".heel")).expanduser().resolve()


class LocalProjectStore:
    def __init__(self, root: Path | None = None):
        self.root = (root or default_home()).resolve()
        self.reviews = self.root / "reviews"

    def save_review(self, envelope: Mapping[str, Any]) -> Path:
        review_id = str(envelope["review_id"])
        if not review_id.startswith("review_") or not review_id.replace("_", "").isalnum():
            raise ValueError("invalid review_id")
        self.reviews.mkdir(parents=True, exist_ok=True)
        path = self.reviews / f"{review_id}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(dict(envelope), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
        return path

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        path = self.reviews / f"{review_id}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_reviews(self) -> list[dict[str, str]]:
        if not self.reviews.exists():
            return []
        items = []
        for path in sorted(self.reviews.glob("review_*.json")):
            review = json.loads(path.read_text(encoding="utf-8"))
            items.append({key: str(review[key]) for key in ("review_id", "product_id", "gate_status")})
        return items
```

Create `heel/review_export.py`:

```python
from __future__ import annotations

from typing import Any, Mapping


def review_to_markdown(envelope: Mapping[str, Any]) -> str:
    summary = envelope.get("summary", {})
    lines = [
        f"# Heel launch review: {envelope.get('product_id', '')}",
        "",
        f"Gate: **{str(envelope.get('gate_status', 'pass')).upper()}**",
        f"Findings: {summary.get('findings', 0)} · Blockers: {summary.get('blockers', 0)}",
        "Privacy: analyzed locally; source document was not uploaded.",
        "",
    ]
    for index, finding in enumerate(envelope.get("findings", []), 1):
        lines.extend([
            f"## {index}. [{str(finding.get('severity', 'warn')).upper()}] {finding.get('surface_id', 'surface')}",
            "",
            str(finding.get("reason", "")),
            "",
            f"Recommended control: {finding.get('control', '')}",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"
```

- [ ] **Step 4: Run the local store tests**

Run: `python3 -m unittest tests.test_local_projects -v`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit local persistence and export**

```bash
git add heel/local_projects.py heel/review_export.py tests/test_local_projects.py
git commit -m "feat: save and export local Heel reviews"
```

### Task 5: Make the useful review flow canonical over MCP

**Files:**
- Modify: `heel/mcp_server.py`
- Create: `tests/test_mcp_review.py`

- [ ] **Step 1: Write failing MCP behavior tests**

```python
import tempfile
from pathlib import Path
import unittest

from heel.local_projects import LocalProjectStore
from heel.mcp_server import HeelServer, REVIEW_TOOL_NAMES


class MCPReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = HeelServer(projects=LocalProjectStore(Path(self.tmp.name)))

    def tearDown(self):
        self.tmp.cleanup()

    def test_agent_can_get_value_from_one_tool_call(self):
        result = self.server.call_tool("heel_review_openapi", {
            "openapi": {
                "openapi": "3.1.0", "info": {"title": "Agent App", "version": "1"},
                "paths": {"/exports": {"get": {"operationId": "exportUsers"}}},
            }
        }, "mcp:test")
        self.assertGreater(result["summary"]["findings"], 0)
        self.assertFalse(result["privacy"]["uploaded"])
        self.assertIsNotNone(self.server.projects.get_review(result["review_id"]))

    def test_agent_can_list_read_and_export_review(self):
        review = self.server.call_tool("heel_review_openapi", {
            "openapi": {"openapi": "3.1.0", "info": {"title": "Agent App", "version": "1"}, "paths": {"/exports": {"get": {"operationId": "exportUsers"}}}}
        }, "mcp:test")
        listed = self.server.call_tool("heel_list_reviews", {}, "mcp:test")
        loaded = self.server.call_tool("heel_get_review", {"review_id": review["review_id"]}, "mcp:test")
        exported = self.server.call_tool("heel_export_review", {"review_id": review["review_id"], "format": "markdown"}, "mcp:test")
        self.assertEqual(listed["reviews"][0]["review_id"], review["review_id"])
        self.assertEqual(loaded, review)
        self.assertIn("# Heel launch review", exported["content"])

    def test_review_tools_are_in_the_public_registry(self):
        self.assertEqual(REVIEW_TOOL_NAMES, {"heel_review_openapi", "heel_list_reviews", "heel_get_review", "heel_export_review"})
```

- [ ] **Step 2: Run the MCP tests and verify the symbol failure**

Run: `python3 -m unittest tests.test_mcp_review -v`

Expected: ERROR because `HeelServer` and `REVIEW_TOOL_NAMES` are not defined yet.

- [ ] **Step 3: Add four exact tool schemas and handlers**

In `heel/mcp_server.py`, rename `ArceoServer` to `HeelServer`, set `SERVER_INFO = {"name": "heel", "version": "1.1.0"}`, keep all existing safe tools under `heel_*`, and add:

```python
from .local_projects import LocalProjectStore
from .review_export import review_to_markdown
from .review_service import review_openapi

EXISTING_TOOL_SCHEMAS = TOOL_SCHEMAS
REVIEW_TOOL_SCHEMAS = [
    {
        "name": "heel_review_openapi",
        "description": "Analyze an OpenAPI JSON object locally and return a launch review. No network calls or upload.",
        "inputSchema": {
            "type": "object", "required": ["openapi"], "additionalProperties": False,
            "properties": {"openapi": {"type": "object"}},
        },
    },
    {"name": "heel_list_reviews", "description": "List locally saved Heel reviews.", "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}}},
    {
        "name": "heel_get_review", "description": "Read one locally saved review.",
        "inputSchema": {"type": "object", "required": ["review_id"], "additionalProperties": False, "properties": {"review_id": {"type": "string"}}},
    },
    {
        "name": "heel_export_review", "description": "Export a locally saved review as Markdown or JSON.",
        "inputSchema": {"type": "object", "required": ["review_id", "format"], "additionalProperties": False, "properties": {"review_id": {"type": "string"}, "format": {"enum": ["markdown", "json"]}}},
    },
]
REVIEW_TOOL_NAMES = {tool["name"] for tool in REVIEW_TOOL_SCHEMAS}
TOOL_SCHEMAS = EXISTING_TOOL_SCHEMAS + REVIEW_TOOL_SCHEMAS
TOOL_NAMES = {tool["name"] for tool in TOOL_SCHEMAS}
```

Use this constructor and handlers inside `HeelServer`:

```python
def __init__(self, store: Store | None = None, classify_enabled: bool = False, projects: LocalProjectStore | None = None):
    self.store = store or Store()
    self.runs: dict[str, object] = {}
    self.classify_enabled = classify_enabled
    self.projects = projects or LocalProjectStore()

def heel_review_openapi(self, args, caller):
    envelope = review_openapi(args["openapi"])
    self.projects.save_review(envelope)
    return envelope

def heel_list_reviews(self, args, caller):
    return {"reviews": self.projects.list_reviews()}

def heel_get_review(self, args, caller):
    review = self.projects.get_review(str(args.get("review_id", "")))
    if review is None:
        raise ToolError("unknown review_id")
    return review

def heel_export_review(self, args, caller):
    review = self.heel_get_review(args, caller)
    if args.get("format") == "markdown":
        return {"format": "markdown", "content": review_to_markdown(review)}
    return {"format": "json", "content": json.dumps(review, indent=2, sort_keys=True)}
```

Keep scope mutation absent. Reject unknown tools exactly as before. `main()` must construct `HeelServer` with the same `HEEL_HOME` for the SQLite audit store and `LocalProjectStore` so data cannot drift into two roots.

- [ ] **Step 4: Run MCP review and existing MCP safety tests**

Run: `python3 -m unittest tests.test_mcp_review tests.test_heel tests.test_saas_adversarial -v`

Expected: PASS; forged scope mutation tools remain rejected.

- [ ] **Step 5: Exercise the actual stdio transport**

Run:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"launch-smoke","version":"1"}}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | HEEL_HOME="$(mktemp -d)" python3 -m heel.mcp_server
```

Expected: two JSON-RPC responses; `serverInfo.name` is `heel`, and `tools/list` includes `heel_review_openapi`.

- [ ] **Step 6: Commit the MCP vertical slice**

```bash
git add heel/mcp_server.py tests/test_mcp_review.py
git commit -m "feat: deliver local launch reviews over MCP"
```

### Task 6: Add the matching CLI, install manifest, and launch-alpha gate

**Files:**
- Modify: `heel/cli.py`
- Modify: `server.json`
- Modify: `README.md`
- Create: `docs/MCP_QUICKSTART.md`
- Create: `tests/test_local_agent_journey.py`

- [ ] **Step 1: Write the failing CLI/MCP customer-journey test**

```python
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LocalAgentJourneyTests(unittest.TestCase):
    def test_cli_reviews_openapi_without_account_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-m", "heel.cli", "review", "openapi", "tests/fixtures/openapi/saas_api.json", "--json"],
                cwd=ROOT,
                env={"PATH": str(Path(sys.executable).parent), "HEEL_HOME": tmp},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            review = json.loads(result.stdout)
            self.assertGreater(review["summary"]["findings"], 0)
            self.assertFalse(review["privacy"]["uploaded"])
            self.assertTrue((Path(tmp) / "reviews" / f"{review['review_id']}.json").is_file())

    def test_mcp_manifest_names_the_real_distribution_and_command(self):
        manifest = json.loads((ROOT / "server.json").read_text())
        package = manifest["packages"][0]
        self.assertEqual(manifest["name"], "io.github.ancilis/heel")
        self.assertEqual(package["identifier"], "heel-sim")
        self.assertEqual(package["package_arguments"][-1]["value"], "heel-mcp")
```

- [ ] **Step 2: Run the journey test and verify the missing command failure**

Run: `python3 -m unittest tests.test_local_agent_journey -v`

Expected: FAIL because `heel review openapi` is not registered.

- [ ] **Step 3: Route the CLI through the shared service**

Add this handler to `heel/cli.py`:

```python
def _review_openapi(path: str, *, as_json: bool) -> int:
    from .local_projects import LocalProjectStore
    from .openapi_import import load_openapi
    from .review_export import review_to_markdown
    from .review_service import review_openapi

    envelope = review_openapi(load_openapi(path))
    LocalProjectStore().save_review(envelope)
    print(json.dumps(envelope, indent=2, sort_keys=True) if as_json else review_to_markdown(envelope), end="\n" if as_json else "")
    return 0
```

Register nested argparse commands so the customer command is exactly:

```text
heel review openapi PATH [--json]
```

The command must not require a scope because it is a static model review and performs no probing.

- [ ] **Step 4: Replace `server.json` with the real Heel MCP install metadata**

Use `name: io.github.ancilis/heel`, package identifier `heel-sim`, executable `heel-mcp`, and environment variables `HEEL_HOME`, `HEEL_SIGNING_KEY`, and `HEEL_MODEL`. The manifest description must lead with: “Heel reviews a SaaS product model before launch and returns ranked abuse paths, missing controls, and regression tests.”

- [ ] **Step 5: Write the no-account five-minute quickstart**

`docs/MCP_QUICKSTART.md` must contain these runnable commands and the matching AI-client config:

```bash
python3 -m pip install heel-sim
heel review openapi openapi.json
```

```json
{
  "mcpServers": {
    "heel": {
      "command": "heel-mcp",
      "env": {"HEEL_HOME": "/absolute/path/to/private/heel-data"}
    }
  }
}
```

State plainly: review data stays on the machine, the review path makes no network calls, the OpenAPI must not contain credentials or customer data, and no Heel Cloud account is required.

- [ ] **Step 6: Run the local-agent launch gate**

Run:

```bash
python3 -m unittest tests.test_local_agent_journey tests.test_mcp_review tests.test_review_service tests.test_review_contract tests.test_local_projects -v
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m pip wheel . --no-deps -w dist
python3 -c 'import zipfile, pathlib; w=next(pathlib.Path("dist").glob("heel_security-*.whl")); names=zipfile.ZipFile(w).namelist(); assert any(n.startswith("heel/saas/") for n in names), names'
git diff --check
```

Expected: the focused journey passes, the full suite passes, the wheel contains `heel/saas/`, and `git diff --check` exits 0.

- [ ] **Step 7: Commit the Local Agent Alpha**

```bash
git add heel/cli.py server.json README.md docs/MCP_QUICKSTART.md tests/test_local_agent_journey.py pyproject.toml
git commit -m "feat: ship Heel local agent alpha"
```

## Milestone acceptance

The Local Agent Alpha is complete only when a clean environment can install the built wheel, connect `heel-mcp`, submit the sample OpenAPI through `heel_review_openapi`, and receive a saved `heel.review.v1` envelope containing at least one finding plus a recommended control. No queued status, fake URL, cloud account, external API call, or manual database edit counts as completion.
