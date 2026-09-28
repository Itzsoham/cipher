import { z } from "zod"

export const email = z.email("Enter a valid email address.")

// Mirrors Better Auth's minPasswordLength on the server.
export const newPassword = z
  .string()
  .min(12, "Use at least 12 characters.")
  .max(128, "Use at most 128 characters.")

export const totpCode = z
  .string()
  .regex(/^\d{6}$/, "Enter the 6-digit code from your authenticator app.")

/** Only allow same-origin relative redirects. */
export function safeNext(next: string | null | undefined) {
  // Rejects "//host" and "/\host", which browsers treat as other origins.
  if (!next || !/^\/(?![/\\])/.test(next)) return "/vault"
  return next
}
