"""
Heel hosted control-plane (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

This subpackage is the proprietary hosted-SaaS layer. It is a SEPARATE licensing unit from the
Apache-2.0 open-source engine in the parent `heel` package (see docs/saas/decisions/
ADR-0001-brand-and-open-core.md and LICENSE-COMMERCIAL.md). Do not copy this code under the
Apache grant.

Local-first: every module here runs offline with zero external accounts (SQLite, stub billing,
stub auth). Production vendor adapters swap in behind interfaces once the owner supplies credentials.
"""
from __future__ import annotations

SPDX_LICENSE = "LicenseRef-Heel-Commercial"
