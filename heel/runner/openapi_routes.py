"""Privacy-minimized read route inventory derived through Heel's OpenAPI model."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any

from heel.canary_contracts import canonical_bytes
from heel.openapi_model import product_model_from_openapi


_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ROUTE = re.compile(r"^/[^\x00-\x1f\x7f?#]*$")


class RouteInventory:
    """Derive a closed GET/HEAD inventory; never retain the source document."""

    def __init__(self, specification: Mapping[str, Any]):
        if not isinstance(specification, Mapping):
            raise ValueError("OpenAPI document must be an object")
        try:
            source_bytes = json.dumps(
                specification,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("OpenAPI document is not finite JSON") from None
        self._source_digest = hashlib.sha256(source_bytes).hexdigest()
        # Use the existing hardened importer as the single OpenAPI interpretation
        # boundary. Only the minimized endpoint records survive this constructor.
        product = product_model_from_openapi(specification, source="openapi:runner-local")
        routes: list[dict[str, Any]] = []
        for endpoint in product["endpoints_routes"]:
            method = endpoint["method"]
            if method not in {"GET", "HEAD"}:
                continue
            route = endpoint["route"]
            if type(route) is not str or _ROUTE.fullmatch(route) is None or "//" in route:
                raise ValueError("unsafe OpenAPI route")
            placeholders = _PLACEHOLDER.findall(route)
            if (
                any(_PLACEHOLDER_NAME.fullmatch(name) is None for name in placeholders)
                or len(placeholders) != len(set(placeholders))
                or route.count("{") != len(placeholders)
                or route.count("}") != len(placeholders)
            ):
                raise ValueError("unsafe OpenAPI route placeholder")
            routes.append({
                "method": method,
                "route_template": route,
                "operation_id": endpoint["operation_id"],
                "placeholders": sorted(placeholders),
            })
        routes.sort(key=lambda item: (
            item["route_template"], item["method"], item["operation_id"]
        ))
        if len(routes) > 2000 or len(canonical_bytes(routes)) > 256 * 1024:
            raise ValueError("read route inventory exceeds local limit")
        if len({(item["method"], item["route_template"]) for item in routes}) != len(routes):
            raise ValueError("duplicate read route")
        self._routes = tuple(routes)

    @property
    def source_digest(self) -> str:
        return self._source_digest

    def read_routes(self) -> list[dict[str, Any]]:
        return [
            {**entry, "placeholders": list(entry["placeholders"])}
            for entry in self._routes
        ]
