// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import vinext from "vinext";
import { defineConfig } from "vite";
import { sites } from "./build/sites-vite-plugin";

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

const VPC_SERVICE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export default defineConfig(async ({ command }) => {
  // Keep Wrangler and Miniflare state project-local. These are non-secret tool
  // settings; application environment belongs in ignored `.env*` files.
  process.env.WRANGLER_WRITE_LOGS ??= "false";
  process.env.WRANGLER_LOG_PATH ??= ".wrangler/logs";
  process.env.MINIFLARE_REGISTRY_PATH ??= ".wrangler/registry";

  // Wrangler snapshots its log path while the Cloudflare plugin is imported.
  const { cloudflare } = await import("@cloudflare/vite-plugin");
  const controlPlaneServiceId = process.env.HEEL_CONTROL_PLANE_VPC_SERVICE_ID?.trim();
  const publicOrigin = process.env.HEEL_PUBLIC_ORIGIN?.trim();
  if (command === "build" && !VPC_SERVICE_ID.test(controlPlaneServiceId ?? "")) {
    throw new Error(
      "HEEL_CONTROL_PLANE_VPC_SERVICE_ID must be a Cloudflare VPC service UUID for production builds",
    );
  }
  if (command === "build") {
    let validPublicOrigin = false;
    try {
      const parsed = new URL(publicOrigin ?? "");
      validPublicOrigin = parsed.protocol === "https:" && parsed.origin === publicOrigin;
    } catch {
      validPublicOrigin = false;
    }
    if (!validPublicOrigin) {
      throw new Error("HEEL_PUBLIC_ORIGIN must be one canonical HTTPS origin for production builds");
    }
  }
  const publicVars: Record<string, string> = {};
  if (publicOrigin !== undefined) publicVars.PUBLIC_ORIGIN = publicOrigin;
  const localBindingConfig = {
    main: "./worker/index.ts",
    compatibility_flags: ["nodejs_compat"],
    observability: { enabled: false },
    vars: publicVars,
    vpc_services: controlPlaneServiceId === undefined
      ? []
      : [{ binding: "CONTROL_PLANE", service_id: controlPlaneServiceId }],
  };

  return {
    server: isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : undefined,
    plugins: [
      vinext(),
      sites(),
      cloudflare({
        viteEnvironment: { name: "rsc", childEnvironments: ["ssr"] },
        config: localBindingConfig,
      }),
    ],
  };
});
