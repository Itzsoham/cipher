import globals from "globals"

import { nextJsConfig } from "@cipher/eslint-config/next-js"

/** @type {import("eslint").Linter.Config} */
export default [
  ...nextJsConfig,
  { ignores: ["playwright-report/**", "test-results/**"] },
  { files: ["scripts/**/*.mjs"], languageOptions: { globals: globals.node } },
]
