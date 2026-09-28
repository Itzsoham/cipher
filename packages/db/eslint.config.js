import { config } from "@cipher/eslint-config/base"

/** @type {import("eslint").Linter.Config} */
export default [...config, { ignores: ["src/generated/**"] }]
