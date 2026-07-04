# HEEL War Room Dashboard

This Next.js app renders the deterministic HEEL snapshot at `public/data/snapshot.json`. It is a
thin UI over the pure-stdlib Python exporter; it does not call live targets, mint scopes, widen
scopes, or run probes.

The dashboard is organized around the operator questions:

- What can customers game?
- How much can it cost us?
- Which control stops the most abuse with the least friction?
- Is this now covered by a regression?

## Data Flow

Regenerate the snapshot from the repository root:

```bash
make ui-data
```

Run the dashboard locally:

```bash
cd web
npm install
npm run dev
```

Build check:

```bash
npm run build
```

## Safety Posture

The snapshot labels synthetic, imported, and staging modes, with synthetic active in the checked-in
sample. Imported and staging modes remain scope-gated and canary-only. No production probing is
performed or implied by this UI. The Safety & Authorization section shows signed scope status,
read-only scope details, containment-chain status, canary-only status, and the absence of any scope
mutation path.
