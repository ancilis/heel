"""Static contract for the private single-node production deployment bundle."""
from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentBundleTests(unittest.TestCase):
    def test_control_plane_image_is_non_root_health_checked_and_runs_real_entrypoint(self):
        source = (ROOT / "deploy/Dockerfile.control-plane").read_text(encoding="utf-8")
        self.assertIn("USER heel", source)
        self.assertIn("python", source)
        self.assertIn("-m", source)
        self.assertIn("heel.saas.server", source)
        self.assertIn("HEALTHCHECK", source)
        self.assertIn("/v1/readyz", source)
        self.assertNotIn("pip install heel-sim", source)
        self.assertIn("cryptography==45.0.7", source)
        self.assertIn("--only-binary=:all:", source)

    def test_compose_keeps_origin_private_single_node_and_on_a_durable_volume(self):
        source = (ROOT / "deploy/compose.yaml").read_text(encoding="utf-8")
        self.assertIn("heel-control-plane-data:/var/lib/heel", source)
        self.assertIn("HEEL_PRIVATE_NETWORK_ACK: private-vpc-only", source)
        self.assertIn("cloudflared", source)
        self.assertIn("TUNNEL_TOKEN:", source)
        self.assertIn("condition: service_healthy", source)
        self.assertIn("stop_grace_period: 35s", source)
        self.assertNotRegex(source, r"(?m)^\s*ports:")
        self.assertNotIn("replicas:", source)

    def test_example_environment_names_every_owner_secret_without_values(self):
        source = (ROOT / "deploy/.env.production.example").read_text(encoding="utf-8")
        for name in (
            "HEEL_PUBLIC_ORIGIN",
            "HEEL_DEVICE_TOKEN_PEPPER_B64",
            "HEEL_API_KEY_PEPPER",
            "HEEL_EDGE_AUTH_SECRET_B64",
            "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64",
            "HEEL_GRANT_SIGNING_KEY_ID",
            "HEEL_GRANT_TRUSTED_PUBLIC_KEYS",
            "HEEL_CLOUDFLARE_TUNNEL_TOKEN",
            "HEEL_CLOUDFLARED_IMAGE",
        ):
            self.assertIn(f"{name}=", source)
        self.assertNotIn("stub.local", source)
        self.assertNotRegex(source, r"heel_(?:at|rt|ses|sk)_[A-Za-z0-9_-]+")


if __name__ == "__main__":
    unittest.main()
