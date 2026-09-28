import path from "node:path"

export const MAIL_DIR = path.resolve(import.meta.dirname, "../.mail/e2e")

// Every e2e account uses this domain so global setup can delete them.
export const E2E_DOMAIN = "e2e.test"

export const users = {
  verify: `verify@${E2E_DOMAIN}`,
  unverified: `unverified@${E2E_DOMAIN}`,
  signOut: `sign-out@${E2E_DOMAIN}`,
  reset: `reset@${E2E_DOMAIN}`,
  twoFactor: `two-factor@${E2E_DOMAIN}`,
  stranger: `stranger@${E2E_DOMAIN}`,
}

export const E2E_ALLOWLIST = [
  users.verify,
  users.unverified,
  users.signOut,
  users.reset,
  users.twoFactor,
]

export const PASSWORD = "correct-horse-battery-1"
export const NEW_PASSWORD = "another-long-password-2"
