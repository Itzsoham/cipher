import { rm } from "node:fs/promises"

import { MAIL_DIR } from "./constants"
import { clearRateLimits, deleteE2eUsers } from "./db"

export default async function globalSetup() {
  await rm(MAIL_DIR, { recursive: true, force: true })
  await deleteE2eUsers()
  await clearRateLimits()
}
