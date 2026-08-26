// SPDX-License-Identifier: LicenseRef-Heel-Commercial


export function PrivacyReceipt() {
  return (
    <section className="privacy-receipt" aria-labelledby="privacy-title">
      <div>
        <p className="eyebrow">Local privacy receipt</p>
        <h3 id="privacy-title">This OpenAPI document was not sent to Heel.</h3>
      </div>
      <ul>
        <li>Analyzed inside a dedicated browser worker.</li>
        <li>0 analyzer network calls after same-origin runtime assets load.</li>
        <li>Only validated results may be explicitly saved on this device.</li>
        <li>No sync intent.</li>
      </ul>
    </section>
  );
}
