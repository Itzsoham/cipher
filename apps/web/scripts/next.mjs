// Runs the Next.js CLI with the repo's root .env loaded, if there is one.
// Variables already set (CI, Vercel, Playwright) take precedence.
import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"

import { config } from "dotenv"

const envFile = path.resolve(import.meta.dirname, "../../../.env")
if (existsSync(envFile)) config({ path: envFile, quiet: true })

const require = createRequire(import.meta.url)
const nextBin = require.resolve("next/dist/bin/next")

const child = spawn(process.execPath, [nextBin, ...process.argv.slice(2)], {
  stdio: "inherit",
})
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  else process.exit(code ?? 1)
})
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal))
}
