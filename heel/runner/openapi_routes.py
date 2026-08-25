"""Privacy-minimized GET/HEAD inventory derived through Heel's OpenAPI model."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
import unicodedata
from typing import Any

from heel.canary_contracts import canonical_bytes
from heel.openapi_model import product_model_from_openapi


_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}", flags=re.ASCII)


def normalize_route_template(value: object) -> tuple[str, list[str]]:
    """Return one NFC route and exact unique placeholders or fail closed."""
    if type(value) is not str:
        raise ValueError("route template must be text")
    route = unicodedata.normalize("NFC", value)
    if (
        not route.startswith("/")
        or len(route.encode("utf-8")) > 1024
        or any(
            unicodedata.category(character) == "Cc"
            or 0xD800 <= ord(character) <= 0xDFFF
            for character in route
        )
        or any(character in route for character in ("%", "\\", "?", "#"))
        or "//" in route
    ):
        raise ValueError("unsafe route template")
    segments = route.split("/")[1:]
    if any(segment in {".", ".."} for segment in segments):
        raise ValueError("unsafe route template")
    placeholders = _PLACEHOLDER.findall(route)
    if (
        route.count("{") != len(placeholders)
        or route.count("}") != len(placeholders)
        or len(placeholders) != len(set(placeholders))
    ):
        raise ValueError("unsafe route placeholder")
    return route, sorted(placeholders)


class RouteInventory:
    """Interpret OpenAPI once, then retain only a closed read-route projection."""

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
        product = product_model_from_openapi(specification, source="openapi:runner-local")
        routes: list[dict[str, Any]] = []
        for endpoint in product["endpoints_routes"]:
            method = endpoint["method"]
            if method not in {"GET", "HEAD"}:
                continue
            route, placeholders = normalize_route_template(endpoint["route"])
            routes.append({
                "method": method,
                "route_template": route,
                "operation_id": endpoint["operation_id"],
                "placeholders": placeholders,
            })
        routes.sort(key=lambda item: (
            item["route_template"], item["method"], item["operation_id"]
        ))
        if len(routes) > 2000 or len(canonical_bytes(routes)) > 256 * 1024:
            raise ValueError("read route inventory exceeds local limit")
        coordinates = [(item["method"], item["route_template"]) for item in routes]
        if len(coordinates) != len(set(coordinates)):
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
