"""Offline file operations for the pure OpenAPI ProductModel mapper."""
from __future__ import annotations

import json
import os
import re
from typing import Any, Mapping

from .openapi_model import (
    LIST_FIELDS,
    PRODUCT_MODEL_VERSION,
    OpenAPIImportError,
    is_broad_scope,
    product_model_from_openapi,
    validate_product_model,
)


_HTTP_RE = re.compile(r"(?i)^https?://")


def import_openapi_file(path: str) -> dict:
    spec = load_openapi(path)
    return product_model_from_openapi(spec, source=f"openapi:{os.path.basename(path)}")


def load_openapi(path: str) -> dict:
    if _HTTP_RE.match(path):
        raise OpenAPIImportError(
            "OpenAPI import reads local files only; no network calls or URL fetching"
        )
    suffix = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            text = file_handle.read()
    except OSError as exc:
        raise OpenAPIImportError(f"cannot read OpenAPI file: {exc}") from exc
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise OpenAPIImportError(
                "YAML OpenAPI import requires PyYAML; export the spec as JSON export instead"
            ) from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise OpenAPIImportError(f"invalid OpenAPI JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise OpenAPIImportError("OpenAPI document must be an object")
    return data


def write_product_model(model: Mapping[str, Any], out_path: str) -> None:
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as file_handle:
        json.dump(dict(model), file_handle, indent=2, sort_keys=True)
        file_handle.write("\n")
