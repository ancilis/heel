"""Session-wide test configuration.

The TLS test edge (``tests/support/edge_tls_harness.py``) mirrors the product Worker's control-plane
allowlist. Its bytes are a hash-pinned accepted H2 input, so they are not edited; the one runner route
the Worker added for E3 configured delivery (``contexts/{rcb}/configured-plan-requests/sync``, 8 KiB,
runner-proof family) is mirrored here instead, exactly as ``worker/index.ts`` allows it.
"""
from __future__ import annotations

import re


def _mirror_worker_configured_sync_route() -> None:
    import tests.support.edge_tls_harness as edge

    if getattr(edge, "_E3_CONFIGURED_SYNC_MIRRORED", False):
        return
    sync = re.compile(
        rf"^/v1/workspaces/{edge._WS}/runners/{edge._RUNNER}/contexts/rcb_[0-9a-f]{{32}}/configured-plan-requests/sync$"
    )
    original, original_cap = edge._RUNNER_CONTEXT_CONTROL, edge._body_cap

    class _ContextControl:
        pattern = original.pattern

        @staticmethod
        def match(path):
            return original.match(path) or sync.match(path)

    edge._RUNNER_CONTEXT_CONTROL = _ContextControl()
    edge._body_cap = lambda path: 8 * 1024 if sync.match(path) else original_cap(path)
    edge._E3_CONFIGURED_SYNC_MIRRORED = True


def pytest_configure(config):  # noqa: ARG001 - pytest hook signature
    _mirror_worker_configured_sync_route()
