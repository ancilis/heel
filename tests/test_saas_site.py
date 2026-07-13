"""Phase 6 tests: static site generation stays truthful to the catalog and the safety claims."""
from __future__ import annotations

import os
import tempfile
import unittest

from arceo.saas.catalog import CATALOG_VERSION, get_plan
from arceo.saas.site import build, render_pricing


class SiteTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.files = build(self.dir)

    def read(self, name):
        with open(os.path.join(self.dir, name)) as f:
            return f.read()

    def test_all_pages_written(self):
        names = {os.path.basename(p) for p in self.files}
        self.assertEqual(names, {"index.html", "pricing.html", "docs.html",
                                 "security.html", "terms.html", "privacy.html"})

    def test_pricing_matches_catalog(self):
        page = render_pricing()
        pro = get_plan("pro")
        self.assertIn(f"${pro.price_month_cents // 100}/mo", page)
        from arceo.saas.catalog import Meter
        self.assertIn(str(pro.quota(Meter.RUNS)), page)
        self.assertIn("Contact sales", page)          # enterprise
        self.assertIn(CATALOG_VERSION, self.read("pricing.html"))

    def test_no_overage_claim_matches_catalog_shape(self):
        self.assertIn("no metered overage", self.read("pricing.html"))

    def test_safety_claims_present(self):
        idx = self.read("index.html")
        self.assertIn("No unverified real-target execution", idx)
        sec = self.read("security.html")
        self.assertIn("human-only", sec.lower())
        self.assertIn("default-deny", sec)

    def test_legal_pages_carry_template_banner(self):
        for name in ("terms.html", "privacy.html"):
            self.assertIn("requires counsel review", self.read(name))

    def test_no_tenant_or_secret_material(self):
        for p in self.files:
            with open(p) as f:
                content = f.read()
            for needle in ("arceo_sk_", "arceo_ses_", "workspace_id=ws_", "ARCEO_API_KEY_PEPPER"):
                self.assertNotIn(needle, content, p)


if __name__ == "__main__":
    unittest.main()
