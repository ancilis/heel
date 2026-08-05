"""Pure in-memory OpenAPI review orchestration for local execution."""
from __future__ import annotations

from typing import Any

from .importers import LIST_FIELDS, PRODUCT_MODEL_VERSION
from .launch_review import review_product_models
from .openapi_import import product_model_from_openapi
from .review_contract import build_review_envelope, stable_json_hash


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


def questions_from_hints(hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert structured importer hints to deterministic strict-v1 questions."""
    questions = []
    for hint in sorted(hints, key=stable_json_hash):
        code = str(hint["code"])
        field = str(hint["field"])
        method = str(hint["method"])
        route = str(hint["route"])
        operation_id = str(hint["operation_id"])
        message = str(hint["message"])
        semantic_context = [code, field, method, route, operation_id, message]
        operation_context = f"{method} {route} (operation {operation_id})"
        if field == "tenant_filter":
            prompt = f"How is tenant access enforced for {operation_context}?"
        elif field == "entitlement_check":
            prompt = f"Which plan or entitlement protects {operation_context}?"
        elif method == route == operation_id == "product":
            prompt = message
        else:
            prompt = f"{message} [{method} {route}; operation {operation_id}]"
        questions.append({
            "id": f"{field}:{stable_json_hash(semantic_context)[:12]}",
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
    questions = questions_from_hints(list(model.get("import_question_hints", [])))
    return build_review_envelope(
        review,
        source_hash=stable_json_hash(spec),
        model_hash=stable_json_hash(model),
        baseline_hash=stable_json_hash(baseline),
        execution_mode=execution_mode,
        questions=questions,
    )
