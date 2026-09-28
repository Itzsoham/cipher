import path from "node:path"

import { config } from "dotenv"
import { defineConfig } from "prisma/config"

// The repo keeps a single .env at the root. Variables already set in the
// environment (CI, Vercel) take precedence.
config({ path: path.resolve(import.meta.dirname, "../../.env"), quiet: true })

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  // Migrations use the direct (non-pooled) connection.
  datasource: { url: process.env.DIRECT_URL ?? "" },
})
