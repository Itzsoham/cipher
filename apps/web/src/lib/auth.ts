import { prisma } from "@cipher/db"
import { betterAuth } from "better-auth"
import { prismaAdapter } from "better-auth/adapters/prisma"
import { APIError } from "better-auth/api"
import { nextCookies } from "better-auth/next-js"
import { twoFactor } from "better-auth/plugins"

import { sendMail } from "@/lib/mailer"

function signupAllowlist() {
  return new Set(
    (process.env.SIGNUP_ALLOWLIST ?? "")
      .split(",")
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean)
  )
}

export const auth = betterAuth({
  appName: "Cipher",
  database: prismaAdapter(prisma, { provider: "postgresql" }),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
    requireEmailVerification: true,
    revokeSessionsOnPasswordReset: true,
    sendResetPassword: async ({ user, url }) => {
      await sendMail({
        to: user.email,
        subject: "Reset your Cipher password",
        text: `Reset your account password: ${url}\n\nThis does not change your master password or your vault.`,
        url,
      })
    },
  },
  emailVerification: {
    sendOnSignUp: true,
    autoSignInAfterVerification: false,
    sendVerificationEmail: async ({ user, url }) => {
      await sendMail({
        to: user.email,
        subject: "Verify your Cipher email",
        text: `Verify your email address: ${url}`,
        url,
      })
    },
  },
  databaseHooks: {
    user: {
      create: {
        // S1: sign-up is limited to SIGNUP_ALLOWLIST, enforced on the server.
        before: async (user) => {
          if (!signupAllowlist().has(user.email.toLowerCase())) {
            throw new APIError("FORBIDDEN", {
              message: "Sign-up is not open for this email.",
            })
          }
          return { data: user }
        },
      },
    },
  },
  rateLimit: {
    enabled: true,
    // In-memory storage does not survive serverless cold starts.
    storage: "database",
    customRules: {
      "/sign-in/*": { window: 60, max: 5 },
      "/two-factor/*": { window: 60, max: 5 },
      "/request-password-reset": { window: 300, max: 3 },
      "/send-verification-email": { window: 300, max: 3 },
    },
  },
  plugins: [twoFactor({ issuer: "Cipher" }), nextCookies()],
})
