// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export default function Home() {
  return (
    <main className="loading-shell">
      <section
        className="loading-card"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        <span className="loading-mark" aria-hidden="true">
          H
        </span>
        <p className="loading-kicker">Browser-local review</p>
        <h1>Preparing Heel</h1>
        <p className="loading-copy">
          Your document stays in this browser. The private review workspace is
          getting ready.
        </p>
        <span className="loading-pulse" aria-hidden="true" />
      </section>
    </main>
  );
}
