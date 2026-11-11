// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { NextConfig } from "next";

import { canonicalPublicOrigin } from "./build/deployment-config";

const nextConfig: NextConfig = {
  // The runner pair command's --origin: the validated canonical public origin, or empty (no command shown).
  env: { HEEL_PUBLIC_ORIGIN: canonicalPublicOrigin(process.env.HEEL_PUBLIC_ORIGIN) ?? "" },
};

export default nextConfig;
