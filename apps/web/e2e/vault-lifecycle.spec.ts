import {
  MASTER_PASSWORD,
  NEW_MASTER_PASSWORD,
  users,
} from "./constants"
import { deleteE2eUsers } from "./db"
import {
  createVerifiedUser,
  expect,
  signIn,
  test,
} from "./helpers"

test.describe("Vault Lifecycle (Phase 3)", () => {
  test.beforeEach(async () => {
    test.setTimeout(90_000)
    await deleteE2eUsers()
  })

  test("setup, lock, unlock, cross-tab lock sync, and change master password", async ({
    page,
    context,
  }) => {
    // 1. Create and verify user
    await createVerifiedUser(page, users.vault)
    await signIn(page, users.vault)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    // 2. Fresh setup wizard
    await expect(page.getByText("Set Up Master Password")).toBeVisible()

    // Weak password rejected
    await page.locator("#master-password").fill("short")
    await page.locator("#confirm-password").fill("short")
    await expect(
      page.getByRole("button", { name: "Continue to Recovery Key" })
    ).toBeDisabled()

    // Strong password accepted
    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await expect(
      page.getByRole("button", { name: "Continue to Recovery Key" })
    ).toBeEnabled()

    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    // 3. Recovery key display & confirmation
    await expect(page.getByText("Save Your Recovery Key")).toBeVisible({ timeout: 15_000 })
    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    await expect(recoveryKeyEl).toBeVisible()
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    expect(recoveryKeyText).toMatch(/^([0-9A-HJKMNP-Z]{4}-){13}[0-9A-HJKMNP-Z]{4}$/)

    const lastGroup = recoveryKeyText.split("-").pop()!
    expect(lastGroup).toHaveLength(4)

    // Wrong confirmation fails
    await page.locator("#confirm-recovery").fill("0000")
    await expect(
      page.getByRole("button", { name: "Complete Vault Setup" })
    ).toBeDisabled()

    // Correct confirmation succeeds
    await page.locator("#confirm-recovery").fill(lastGroup)
    await expect(
      page.getByRole("button", { name: "Complete Vault Setup" })
    ).toBeEnabled()

    await page.getByRole("button", { name: "Complete Vault Setup" }).click()

    // 4. Vault is now unlocked
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText("Vault Entries")).toBeVisible()

    // 5. Cross-tab lock sync
    const page2 = await context.newPage()
    await page2.goto("/vault")
    // Tab 2 starts locked (VK is in-memory only); unlock Tab 2
    await page2.locator("#unlock-password").fill(MASTER_PASSWORD)
    await page2.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(page2.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })

    // Locking in tab 1 immediately locks tab 2 via BroadcastChannel
    await page.getByRole("button", { name: "Lock Vault" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()
    await expect(page2.getByText("Unlock Your Vault")).toBeVisible()
    await page2.close()

    // 6. Unlock with wrong password fails
    await page.locator("#unlock-password").fill("wrong-password-here-123!")
    await page.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(
      page.getByText(/incorrect master password/i).first()
    ).toBeVisible({ timeout: 15_000 })

    // Unlock with correct password succeeds
    await page.locator("#unlock-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })

    // 7. Change master password in settings via client navigation (preserves in-memory VK)
    await page.getByRole("link", { name: "Settings" }).click()
    await expect(page.getByText("Vault Settings")).toBeVisible()

    await page.getByRole("button", { name: "Change Master Password" }).click()
    await page.locator("#current-master-password").fill(MASTER_PASSWORD)
    await page.locator("#new-modal-password").fill(NEW_MASTER_PASSWORD)
    await page.locator("#confirm-modal-password").fill(NEW_MASTER_PASSWORD)
    await page.getByRole("button", { name: "Save New Password" }).click()

    await expect(page.getByText("Master password updated successfully")).toBeVisible({ timeout: 15_000 })

    // Return to vault via client navigation, lock, and test new password
    await page.getByRole("link", { name: "Vault" }).first().click()
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible()
    await page.getByRole("button", { name: "Lock Vault" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()

    // Old password fails
    await page.locator("#unlock-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(
      page.getByText(/incorrect master password/i).first()
    ).toBeVisible({ timeout: 15_000 })

    // New password succeeds
    await page.locator("#unlock-password").fill(NEW_MASTER_PASSWORD)
    await page.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })
  })

  test("recovery flow: restore vault with recovery key and issue new key", async ({
    page,
  }) => {
    // 1. Create and verify user
    await createVerifiedUser(page, users.vaultRecover)
    await signIn(page, users.vaultRecover)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    // 2. Setup vault
    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    await expect(recoveryKeyEl).toBeVisible({ timeout: 15_000 })
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    const lastGroup = recoveryKeyText.split("-").pop()!

    await page.locator("#confirm-recovery").fill(lastGroup)
    await page.getByRole("button", { name: "Complete Vault Setup" }).click()
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })

    // 3. Lock vault
    await page.getByRole("button", { name: "Lock Vault" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()

    // 4. Switch to recovery
    await page.getByRole("button", { name: "Forgot master password? Use recovery key" }).click()
    await expect(page.getByText("Recover Vault")).toBeVisible()

    // Wrong recovery key fails
    await page.locator("#recovery-key-input").fill("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-MMMM-NNNN-PPPP-QQQQ")
    await page.getByRole("button", { name: "Verify Recovery Key" }).click()
    await expect(
      page.getByText(/Checksum validation failed|Failed to verify recovery key/i)
    ).toBeVisible({ timeout: 15_000 })

    // Correct recovery key proceeds
    await page.locator("#recovery-key-input").fill(recoveryKeyText)
    await page.getByRole("button", { name: "Verify Recovery Key" }).click()

    // 5. Set new password
    await expect(page.getByText("Set New Master Password")).toBeVisible({ timeout: 15_000 })
    await page.locator("#new-master-password").fill(NEW_MASTER_PASSWORD)
    await page.locator("#confirm-new-master-password").fill(NEW_MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to New Recovery Key" }).click()

    // 6. Confirm new recovery key
    await expect(page.getByText("Save Your NEW Recovery Key")).toBeVisible({ timeout: 15_000 })
    const newRecoveryKeyEl = page.locator("div.font-mono.select-all")
    const newRecoveryKeyText = (await newRecoveryKeyEl.textContent())?.trim() ?? ""
    expect(newRecoveryKeyText).not.toBe(recoveryKeyText)

    const newLastGroup = newRecoveryKeyText.split("-").pop()!
    await page.locator("#confirm-new-recovery").fill(newLastGroup)
    await page.getByRole("button", { name: "Complete Vault Recovery" }).click()

    // 7. Vault is recovered and unlocked
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })

    // Lock and verify new password works
    await page.getByRole("button", { name: "Lock Vault" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()

    await page.locator("#unlock-password").fill(NEW_MASTER_PASSWORD)
    await page.getByRole("button", { name: "Unlock Vault" }).click()
    await expect(page.getByTestId("vault-unlocked-status")).toBeVisible({ timeout: 15_000 })
  })
})
