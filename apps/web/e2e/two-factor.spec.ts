import { PASSWORD, users } from "./constants"
import { createVerifiedUser, expect, signIn, test } from "./helpers"
import { totp } from "./totp"

test("enable two-factor login, then sign in with a TOTP code", async ({
  page,
}) => {
  await createVerifiedUser(page, users.twoFactor)
  await signIn(page, users.twoFactor)
  await expect(page).toHaveURL(/\/vault$/)

  await page.goto("/settings/security")
  await page.getByLabel("Account password").fill(PASSWORD)
  await page.getByRole("button", { name: "Set up two-factor login" }).click()

  const secret = await page.locator("code").textContent()
  expect(secret).toMatch(/^[A-Z2-7]+=*$/)
  await page.getByLabel("Enter the 6-digit code").fill(totp(secret!))
  await page.getByRole("button", { name: "Turn on two-factor login" }).click()
  await expect(page.getByText("On. Sign-in asks for a code")).toBeVisible()

  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(/\/sign-in/)

  await signIn(page, users.twoFactor)
  await expect(page).toHaveURL(/\/2fa$/)
  // /vault stays closed until the second factor is verified.
  await page.goto("/vault")
  await expect(page).toHaveURL(/\/sign-in/)

  await signIn(page, users.twoFactor)
  await expect(page).toHaveURL(/\/2fa$/)
  await page.getByLabel("Authentication code").fill("000000")
  await page.getByRole("button", { name: "Verify" }).click()
  await expect(
    page.getByRole("alert").filter({ hasText: /invalid/i })
  ).toBeVisible()

  await page.getByLabel("Authentication code").fill(totp(secret!))
  await page.getByRole("button", { name: "Verify" }).click()
  await expect(page).toHaveURL(/\/vault$/)
})
