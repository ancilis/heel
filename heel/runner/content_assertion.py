"""Closed local protected-content predicate. No raw content enters shared projections."""
from __future__ import annotations

import json


def protected_content(body: bytes, *, marker: str | None, status: int, method: str = 'GET') -> bool | None:
    """Check the exact synthetic protected field, never a reflected id or status alone.

    The fixture marker is bound in the approved route manifest. Products must place it
    in `protected_canary` only within protected output, never in public/error metadata.
    Unknown bodies remain inconclusive. False means absence for this complete read,
    not that every field, route, lifecycle, or aggregate limit is safe.
    """
    if method != 'GET' or not marker or not marker.startswith('heel-canary-') or len(body) > 256 * 1024:
        return None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        data = json.loads(body, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        return False if not body and status in {401, 402, 403, 404} else None
    if type(data) is not dict:
        return None
    # Check disclosure even in an error envelope: protected data is still disclosed.
    if data.get('protected_canary') == marker:
        return True
    if status in {401, 402, 403, 404} or data.get('error') or data.get('errors'):
        return False
    if status == 200 and (data.get('visibility') in {'public', 'redacted'} or data.get('protected_canary') is None and data.get('records') == []):
        return False
    return None
