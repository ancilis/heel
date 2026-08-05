"""Pure in-memory OpenAPI review orchestration for local execution."""
from __future__ import annotations

import re
from typing import Any

from .importers import LIST_FIELDS, PRODUCT_MODEL_VERSION
from .launch_review import review_product_models
from .openapi_import import product_model_from_openapi
from .review_contract import build_review_envelope, stable_json_hash


_WARNING_ROUTE = re.compile(r"for (?P<route>/\S+)$")
_BASELINE_SAFETY_NOTE = (
    "Synthetic empty baseline for local OpenAPI review; no live probing."
)


def empty_product_model(product_id: str) -> dict[str, Any]:
    """Build the canonical valid baseline used by one-document reviews."""
    model = {field: [] for field in LIST_FIELDS}
    model.update({
        "schema_version": PRODUCT_MODEL_VERSION,
        "product_id": product_id,
        "source": "heel:empty-baseline",
        "generated_at": "1970-01-01T00:00:00Z",
        "environments": ["synthetic"],
        "safety_notes": [_BASELINE_SAFETY_NOTE],
    })
    return model


def questions_from_warnings(warnings: list[str]) -> list[dict[str, Any]]:
    """Convert importer warnings to deterministic strict-v1 question records."""
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


def review_openapi(
    spec: dict, *, execution_mode: str = "machine_local"
) -> dict:
    """Import and review an OpenAPI document without I/O or active execution."""
    model = product_model_from_openapi(spec, source="openapi:inline-local")
    baseline = empty_product_model(model["product_id"])
    review = review_product_models(baseline, model).to_dict()
    questions = questions_from_warnings(list(model.get("import_warnings", [])))
    return build_review_envelope(
        review,
        source_hash=stable_json_hash(spec),
        model_hash=stable_json_hash(model),
        baseline_hash=stable_json_hash(baseline),
        execution_mode=execution_mode,
        questions=questions,
    )
