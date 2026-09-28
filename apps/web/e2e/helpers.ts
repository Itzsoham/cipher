import { readdir, readFile } from "node:fs/promises"
import path from "node:path"

import { expect, test as base, type Page } from "@playwright/test"

import { MAIL_DIR, PASSWORD } from "./constants"
import { clearRateLimits } from "./db"

export const test = base.extend<{ resetRateLimits: void }>({
  resetRateLimits: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      await clearRateLimits()
      await use()
    },
    { auto: true },
  ],
})

export { expect }

type Mail = { to: string; subject: string; url?: string; createdAt: string }

async function readMail(): Promise<Mail[]> {
  const files = await readdir(MAIL_DIR).catch(() => [] as string[])
  const mail = await Promise.all(
    files
      .filter((f) => f.endsWith(".json"))
      .map(async (f) =>
        JSON.parse(await readFile(path.join(MAIL_DIR, f), "utf8"))
      )
  )
  return mail.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
}

/** Waits for the newest message to `to` whose subject contains `subject`. */
export async function waitForMailLink(to: string, subject: string) {
  let link: string | undefined
  await expect
    .poll(
      async () => {
        const matches = (await readMail()).filter(
          (m) => m.to === to && m.subject.includes(subject)
        )
        link = matches.at(-1)?.url
        return link
      },
      { message: `mail "${subject}" to ${to}`, timeout: 10_000 }
    )
    .toBeTruthy()
  return link!
}

export async function countMail(to: string) {
  return (await readMail()).filter((m) => m.to === to).length
}

export async function signUp(page: Page, email: string, password = PASSWORD) {
  await page.goto("/sign-up")
  await page.getByLabel("Email").fill(email)
  await page.getByLabel("Account password").fill(password)
  await page.getByLabel("Confirm password").fill(password)
  await page.getByRole("button", { name: "Create account" }).click()
}

export async function signIn(page: Page, email: string, password = PASSWORD) {
  await page.goto("/sign-in")
  await page.getByLabel("Email").fill(email)
  await page.getByLabel("Password").fill(password)
  await page.getByRole("button", { name: "Sign in" }).click()
}

/** Signs up through the UI and follows the verification link. */
export async function createVerifiedUser(page: Page, email: string) {
  await signUp(page, email)
  await expect(page).toHaveURL(/\/verify-email/)
  await page.goto(await waitForMailLink(email, "Verify"))
  await expect(page).toHaveURL(/\/sign-in\?verified=1/)
}
