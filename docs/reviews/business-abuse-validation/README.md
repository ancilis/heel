# Validation evidence

See [the implementation report](../2026-09-04-business-abuse-implementation.md) for commands, environment qualifications and limitations. These are local test logs, not customer evidence or deployment records.

The full Python run used `HEEL_REQUIRE_STANDARD_BUILD=1` and private non-symlinked `TMPDIR`. The final focused run covers the later completed-observation wording correction. Frontend build/Node logs use an isolated app copy with real dependency directories; the initial environment failures are retained separately. No transport safeguard was relaxed.

Trailing whitespace in captured logs is normalized for source control.

Local checkout paths are replaced with `<WORKTREE>` to avoid publishing machine-specific paths.
