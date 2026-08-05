// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Keep true generated outputs ignored while linting tracked application source.
  globalIgnores([
    ".next/**",
    "out/**",
    "next-env.d.ts",
    "!build/",
    "!build/**",
  ]),
]);

export default eslintConfig;
