#!/usr/bin/env python3
"""
Control-plane backup / restore-verify (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Uses SQLite's online backup API (safe while the server runs) and verifies every restore:
migrations must report nothing pending and the reconciliation report must be clean before a
restored copy may be promoted (RUNBOOKS.md, restore drill).

Usage:
  python3 scripts/saas_backup.py backup  <live_db> <backup_path>
  python3 scripts/saas_backup.py verify  <backup_path>
"""
from __future__ import annotations

import sqlite3
import sys

sys.path.insert(0, ".")


def backup(live: str, dest: str) -> int:
    src = sqlite3.connect(live)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()
    print(f"backup written: {dest}")
    return 0


def verify(path: str) -> int:
    from arceo.saas.ledger import UsageLedger
    from arceo.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator
    from arceo.saas.reconcile import reconcile

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        print("FAIL: integrity_check")
        return 1
    # A restored copy is a scratch instance (runbook): bring schema current, then require clean.
    applied = Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    if applied:
        print(f"note: applied migrations {applied} on the restored copy")
    rep = reconcile(conn, UsageLedger(conn))
    if not rep.clean:
        print(f"FAIL: reconcile not clean: mismatches={rep.plan_mismatches} "
              f"unknown={rep.unknown_subscription_workspaces} "
              f"dangling={rep.dangling_reservations}")
        return 1
    print("VERIFY PASS: integrity ok, schema current, reconcile clean")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "backup" and len(sys.argv) == 4:
        sys.exit(backup(sys.argv[2], sys.argv[3]))
    if cmd == "verify":
        sys.exit(verify(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
