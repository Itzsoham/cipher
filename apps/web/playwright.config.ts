import path from "node:path"

import { defineConfig, devices } from "@playwright/test"
import { config } from "dotenv"

import { E2E_ALLOWLIST, MAIL_DIR } from "./e2e/constants"

// Local runs read the root .env; CI sets the variables directly.
config({ path: path.resolve(import.meta.dirname, "../../.env"), quiet: true })

const PORT = 3100
const baseURL = `http://localhost:${PORT}`

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Runs the production build, so `turbo test:e2e` builds first.
    command: `pnpm start --port ${PORT}`,
    url: `${baseURL}/sign-in`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      BETTER_AUTH_URL: baseURL,
      MAIL_TRANSPORT: "file",
      MAIL_DIR,
      SIGNUP_ALLOWLIST: E2E_ALLOWLIST.join(","),
    },
  },
})
