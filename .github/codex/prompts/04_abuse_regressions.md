# Prompt 4 — Add abuse regression tests

Task: Turn Heel findings into permanent abuse regression tests.

Create:

- heel/regressions.py
- CLI commands:
  - heel regress add --run <run_id> --vector <vector_id> --name <name>
  - heel regress list
  - heel regress run --target <target_id_or_imported_model> --scope <scope_id>
  - heel regress export --format json
- storage support in heel/store.py
- tests in tests/test_heel.py or tests/test_regressions.py
- docs/REGRESSIONS.md

Behavior:
A regression stores:

- name
- original vector id
- scenario id
- target affordance pattern
- success criterion
- recommended control
- expected status: blocked | still_reachable
- created_at
- source run id
- safety flags

Re-running a regression must use the same safety spine:

- signed scope required
- canary-only
- no scope widening
- containment log entries

A regression result should say:

- previously reachable
- currently reachable / blocked / inconclusive
- control likely present or absent
- evidence summary

Do not create weaponized repro steps.

CLI UX example:

```bash
heel regress add --run run-abc --vector av:run-abc:7 --name free_trial_serial_signup
heel regress run --scope scope-123 --target staging-saas
```

Tests:

- add regression from finding
- list regression
- re-run regression against same synthetic target still finds it
- re-run against a hardened synthetic fixture reports blocked
- regression run is logged
- no regression command can create/widen scope

Docs:

- Explain “abuse regression testing” as unit tests for product abuse controls.
- Show how to use this in CI/staging.

Acceptance criteria:

- Findings are not just reports; they become reusable tests.
