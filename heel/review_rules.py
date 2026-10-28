"""Shared pure predicates for ProductModel import and launch review."""
from __future__ import annotations

from typing import Any


BROAD_SCOPE_VALUES = frozenset({
    "*",
    "all",
    "admin",
    "full",
    "full_access",
    "read_write_all",
    "global",
    "all_tenants",
    "read:all",
    "write:all",
})


def is_broad_scope(value: Any) -> bool:
    """Return whether a string is one of Heel's exact broad-scope identifiers."""
    return isinstance(value, str) and value.strip().lower() in BROAD_SCOPE_VALUES
