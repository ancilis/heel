# Arceo Commercial License (hosted layer)

DRAFT — NOT LEGAL ADVICE. Flagged for owner counsel review (see docs/saas/OWNER_ACTIONS.md).

The open-source **engine** in the `arceo/` package (excluding `arceo/saas/`) is licensed under the
**Apache License 2.0** (see `LICENSE` and `NOTICE`). Nothing here changes that grant.

Files carrying `SPDX-License-Identifier: LicenseRef-Arceo-Commercial` — currently everything under
`arceo/saas/` and the hosted portions of `web/` — are the **proprietary hosted layer**. They are:

- NOT covered by the Apache-2.0 grant;
- provided for evaluation and internal use in connection with an Arceo hosted subscription;
- not to be redistributed, sublicensed, or offered as a competing hosted service without a written
  commercial agreement with the copyright holder (Ancilis).

This dual arrangement (Apache core + proprietary hosted layer in one repository) is a permitted
"aggregate"/"separate work" configuration under Apache-2.0 §5; the boundary is machine-checkable via
the per-file SPDX headers. Final terms are subject to owner counsel review before any public offering.

© 2026 Ancilis. All rights reserved for the commercial layer.
