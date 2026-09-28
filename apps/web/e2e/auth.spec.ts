import { NEW_PASSWORD, PASSWORD, users } from "./constants"
import {
  countMail,
  createVerifiedUser,
  expect,
  signIn,
  signUp,
  test,
  waitForMailLink,
} from "./helpers"
import { userExists } from "./db"

test("rejects sign-up for an email that is not allowlisted", async ({
  page,
}) => {
  // Better Auth answers a refused sign-up exactly like a successful one
  // (no session, synthetic user), so the response does not reveal which
  // emails are allowlisted. The rejection shows up as no account and no mail.
  await signUp(page, users.stranger)
  await expect(page).toHaveURL(/\/verify-email/)

  const response = await page.request.post("/api/auth/sign-up/email", {
    data: { email: users.stranger, password: PASSWORD, name: "stranger" },
  })
  expect(response.status()).toBe(200)
  expect((await response.json()).token).toBeNull()

  expect(await userExists(users.stranger)).toBe(false)
  expect(await countMail(users.stranger)).toBe(0)
})

test("allowlisted sign-up verifies by email and can sign in", async ({
  page,
}) => {
  await createVerifiedUser(page, users.verify)
  await expect(page.getByText("Email verified")).toBeVisible()

  await signIn(page, users.verify)
  await expect(page).toHaveURL(/\/vault$/)
  await expect(page.getByTestId("account-email")).toHaveText(users.verify)
})

test("blocks sign-in until the email is verified", async ({ page }) => {
  await signUp(page, users.unverified)
  await expect(page).toHaveURL(/\/verify-email/)

  await signIn(page, users.unverified)
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Verify your email before signing in" })
  ).toBeVisible()
  await expect(page).toHaveURL(/\/sign-in/)
})

test("sign-out ends the session and /vault redirects to sign-in", async ({
  page,
}) => {
  await createVerifiedUser(page, users.signOut)
  await signIn(page, users.signOut)
  await expect(page).toHaveURL(/\/vault$/)

  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(/\/sign-in/)

  await page.goto("/vault")
  await expect(page).toHaveURL(/\/sign-in\?next=%2Fvault/)
})

test("password reset link sets a new password", async ({ page }) => {
  await createVerifiedUser(page, users.reset)

  await page.goto("/forgot-password")
  await page.getByLabel("Email").fill(users.reset)
  await page.getByRole("button", { name: "Send reset link" }).click()
  await expect(page.getByText("a reset link is on its way")).toBeVisible()

  await page.goto(await waitForMailLink(users.reset, "Reset"))
  await expect(page).toHaveURL(/\/reset-password\?token=/)
  await page.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD)
  await page.getByLabel("Confirm new password").fill(NEW_PASSWORD)
  await page.getByRole("button", { name: "Update password" }).click()
  await expect(page).toHaveURL(/\/sign-in\?reset=1/)

  await signIn(page, users.reset, PASSWORD)
  await expect(
    page.getByRole("alert").filter({ hasText: /invalid/i })
  ).toBeVisible()

  await signIn(page, users.reset, NEW_PASSWORD)
  await expect(page).toHaveURL(/\/vault$/)
})

test("responses carry a nonce CSP and security headers", async ({ page }) => {
  const response = await page.goto("/sign-in")
  const headers = response!.headers()
  const csp = headers["content-security-policy"] ?? ""

  const nonce = csp.match(/'nonce-([^']+)'/)?.[1]
  expect(nonce).toBeTruthy()
  expect(csp).toContain("'strict-dynamic'")
  expect(csp).toContain("frame-ancestors 'none'")
  expect(csp).toContain("base-uri 'none'")
  expect(headers["referrer-policy"]).toBe("no-referrer")

  // Next.js applies the nonce to its own scripts.
  const scriptNonces = await page
    .locator("script[src]")
    .evaluateAll((els) => els.map((el) => (el as HTMLScriptElement).nonce))
  expect(scriptNonces.length).toBeGreaterThan(0)
  expect(scriptNonces.every((n) => n === nonce)).toBe(true)

  // A fresh nonce per request.
  const again = await page.request.get("/sign-in")
  expect(again.headers()["content-security-policy"]).not.toContain(nonce!)
})
