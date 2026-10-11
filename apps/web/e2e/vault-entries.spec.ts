import {
  MASTER_PASSWORD,
  users,
} from "./constants"
import { clearRateLimits, deleteE2eUsers } from "./db"
import {
  createVerifiedUser,
  expect,
  signIn,
  test,
} from "./helpers"

test.describe("Vault Entries & Zero-Knowledge (Phase 4)", () => {
  test.beforeEach(async () => {
    test.setTimeout(90_000)
    await deleteE2eUsers()
    await clearRateLimits()
  })

  test.afterAll(async () => {
    await deleteE2eUsers()
    await clearRateLimits()
  })

  test("full entry lifecycle: wire check, password/note CRUD, URL safety, search, reveal, and lock purge", async ({
    page,
  }) => {
    // 1. Setup user & unlock vault
    await createVerifiedUser(page, users.vaultEntries)
    await signIn(page, users.vaultEntries)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    await expect(page.getByText("Set Up Master Password")).toBeVisible()
    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    await expect(page.getByText("Save Your Recovery Key")).toBeVisible({ timeout: 15_000 })
    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    const lastGroup = recoveryKeyText.split("-").pop()!

    await page.locator("#confirm-recovery").fill(lastGroup)
    await expect(
      page.getByRole("button", { name: "Complete Vault Setup" })
    ).toBeEnabled()
    await page.getByRole("button", { name: "Complete Vault Setup" }).click()

    // Vault should be unlocked
    await expect(page.locator('[data-testid="vault-unlocked-status"]')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText("Vault Entries")).toBeVisible()

    // 2. Wire Check: Intercept POST /api/vault/entries and assert zero-knowledge on the wire
    let interceptedPostData: Record<string, unknown> | null = null
    await page.route("**/api/vault/entries", async (route) => {
      if (route.request().method() === "POST") {
        interceptedPostData = route.request().postDataJSON()
      }
      await route.continue()
    })

    // 3. URL Scheme Guard Check
    await page.getByRole("button", { name: "New Entry" }).click()
    await expect(page.getByText("New Vault Entry")).toBeVisible()

    await page.locator("#entry-title").fill("XSS Attack Test")
    await page.locator("#entry-url").fill("javascript:alert(1)")
    await page.getByRole("button", { name: "Create Entry" }).click()

    // Must show validation error and prevent submit
    await expect(page.getByText("URL must begin with http:// or https://")).toBeVisible()
    expect(interceptedPostData).toBeNull()

    // 4. Create valid Password Entry
    await page.locator("#entry-title").fill("GitHub Production")
    await page.locator("#entry-username").fill("octocat@github.com")
    await page.locator("#entry-password").fill("SuperSecretKey#999")
    await page.locator("#entry-url").fill("https://github.com/login")
    await page.locator("#entry-notes").fill("Secondary organization credentials")
    await page.getByRole("button", { name: "Create Entry" }).click()

    await expect(page.getByText("Entry created successfully")).toBeVisible()

    // Verify wire interception: server NEVER received plaintext title, username, password, or notes
    expect(interceptedPostData).not.toBeNull()
    expect(interceptedPostData).toHaveProperty("encryptedData")
    expect(interceptedPostData).toHaveProperty("iv")
    expect(interceptedPostData).toHaveProperty("type", "password")
    expect(JSON.stringify(interceptedPostData)).not.toContain("GitHub Production")
    expect(JSON.stringify(interceptedPostData)).not.toContain("octocat@github.com")
    expect(JSON.stringify(interceptedPostData)).not.toContain("SuperSecretKey#999")
    expect(JSON.stringify(interceptedPostData)).not.toContain("Secondary organization credentials")

    // Verify decrypted entry rendered in UI
    await expect(page.getByRole("heading", { name: "GitHub Production" })).toBeVisible()
    await expect(page.getByText("octocat@github.com").first()).toBeVisible()
    await expect(page.getByText("https://github.com/login").first()).toBeVisible()

    // 5. Create Secure Note Entry
    await page.getByRole("button", { name: "New Entry" }).click()
    await page.getByRole("button", { name: /Secure Note|Note/ }).click()
    await page.locator("#entry-title").fill("Recovery Seeds Backup")
    await page.locator("#entry-text").fill("apple banana cherry dog elephant fox grape")
    await page.getByRole("button", { name: "Create Entry" }).click()

    await expect(page.getByText("Secure note created successfully")).toBeVisible()
    await expect(page.getByRole("heading", { name: "Recovery Seeds Backup" })).toBeVisible()

    // 6. In-Memory Search
    const searchInput = page.getByPlaceholder("Search titles, usernames, notes...")
    await searchInput.fill("GitHub")
    await expect(page.getByRole("button", { name: /GitHub Production/ })).toBeVisible()
    await expect(page.getByRole("button", { name: /Recovery Seeds Backup/ })).not.toBeVisible()

    await searchInput.fill("Recovery")
    await expect(page.getByRole("button", { name: /Recovery Seeds Backup/ })).toBeVisible()
    await expect(page.getByRole("button", { name: /GitHub Production/ })).not.toBeVisible()

    await searchInput.fill("")
    await expect(page.getByRole("button", { name: /GitHub Production/ })).toBeVisible()
    await expect(page.getByRole("button", { name: /Recovery Seeds Backup/ })).toBeVisible()

    // 7. Password Reveal & Detail View
    await page.getByRole("button", { name: /GitHub Production/ }).click()
    await expect(page.getByText("••••••••••••••••")).toBeVisible()

    // Click show password button
    await page.getByTitle("Show password (auto-hides after 10s)").click()
    await expect(page.getByText("SuperSecretKey#999")).toBeVisible()
    await expect(page.getByText("Auto-hiding in 10s")).toBeVisible()

    // 8. Edit Entry (CAS version check)
    await page.getByRole("button", { name: "Edit" }).first().click()
    await expect(page.getByText("Edit Vault Entry")).toBeVisible()
    await page.locator("#entry-title").fill("GitHub Production Updated")
    await page.getByRole("button", { name: "Save Changes" }).click()

    await expect(page.getByText("Entry updated successfully")).toBeVisible()
    await expect(page.getByRole("heading", { name: "GitHub Production Updated" })).toBeVisible()

    // 9. Delete Entry
    await page.getByRole("button", { name: /Recovery Seeds Backup/ }).click()
    await page.getByRole("button", { name: "Delete" }).first().click()
    await expect(page.getByRole("heading", { name: "Delete Entry" })).toBeVisible()
    await page.getByRole("button", { name: "Delete Entry" }).click()

    await expect(page.getByText("Entry deleted")).toBeVisible()
    await expect(page.getByRole("button", { name: /Recovery Seeds Backup/ })).not.toBeVisible()

    // 10. Lock Clears Decrypted State from DOM
    await page.getByRole("button", { name: "Lock" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()
    await expect(page.getByText("GitHub Production Updated")).not.toBeVisible()
    await expect(page.getByText("SuperSecretKey#999")).not.toBeVisible()
  })

  test("handles tampered ciphertext with a non-blocking Decrypt Failure row", async ({
    page,
  }) => {
    await createVerifiedUser(page, users.vaultEntries)
    await signIn(page, users.vaultEntries)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    const lastGroup = recoveryKeyText.split("-").pop()!
    await page.locator("#confirm-recovery").fill(lastGroup)
    await page.getByRole("button", { name: "Complete Vault Setup" }).click()

    // Create one valid entry
    await page.getByRole("button", { name: "New Entry" }).click()
    await page.locator("#entry-title").fill("Healthy Entry")
    await page.locator("#entry-password").fill("HealthyPassword123")
    await page.getByRole("button", { name: "Create Entry" }).click()
    await expect(page.getByRole("heading", { name: "Healthy Entry" })).toBeVisible()

    // Intercept GET /api/vault/entries and inject a tampered entry alongside the healthy one
    await page.route("**/api/vault/entries", async (route) => {
      if (route.request().method() === "GET") {
        const response = await route.fetch()
        const json = await response.json()
        if (Array.isArray(json) && json.length > 0) {
          json.push({
            id: "00000000-0000-0000-0000-000000000001",
            type: "password",
            cryptoVersion: 1,
            vaultKeyVersion: 1,
            entryVersion: 1,
            encryptedData: "BAD_CIPHERTEXT_BASE64_DATA==",
            iv: "00112233445566778899aabb",
            r2Key: null,
            blobIv: null,
            blobSize: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          })
        }
        await route.fulfill({ json })
        return
      }
      await route.continue()
    })

    // Reload vault page to trigger fetch with tampered entry
    await page.reload()
    await page.locator("#unlock-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Unlock Vault" }).click()

    // The healthy entry MUST still be decrypted and visible
    await expect(page.getByText("Healthy Entry")).toBeVisible()

    // The tampered entry MUST display a Could Not Decrypt row, not crash or hide
    await expect(page.getByText("Could Not Decrypt")).toBeVisible()
    await page.getByText("Could Not Decrypt").click()
    await expect(page.getByText("Could Not Decrypt Entry")).toBeVisible()
    await expect(
      page.getByText("This record failed authentication tag or AAD verification")
    ).toBeVisible()
  })

  test("bulk delete removes multiple selected entries atomically", async ({
    page,
  }) => {
    await createVerifiedUser(page, users.vaultEntries)
    await signIn(page, users.vaultEntries)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    const lastGroup = recoveryKeyText.split("-").pop()!
    await page.locator("#confirm-recovery").fill(lastGroup)
    await page.getByRole("button", { name: "Complete Vault Setup" }).click()

    // Create entry 1
    await page.getByRole("button", { name: "New Entry" }).click()
    await page.locator("#entry-title").fill("Item to Delete 1")
    await page.getByRole("button", { name: "Create Entry" }).click()
    await expect(page.getByText("Entry created successfully")).toBeVisible({ timeout: 15_000 })
    await expect(page.getByRole("heading", { name: "Item to Delete 1" })).toBeVisible({ timeout: 15_000 })

    // Create entry 2
    await page.getByRole("button", { name: "New Entry" }).click()
    await page.locator("#entry-title").fill("Item to Delete 2")
    await page.getByRole("button", { name: "Create Entry" }).click()
    await expect(page.getByText("Entry created successfully")).toBeVisible({ timeout: 15_000 })
    await expect(page.getByRole("heading", { name: "Item to Delete 2" })).toBeVisible({ timeout: 15_000 })

    // Enter bulk select mode
    await page.getByRole("button", { name: "Select" }).click()
    await page.getByRole("button", { name: "Select All" }).click()

    // Click Delete Selected
    await page.getByRole("button", { name: /Delete \(2\)/ }).click()

    await expect(page.getByText("Deleted 2 entries")).toBeVisible()
    await expect(page.getByText("Item to Delete 1")).not.toBeVisible()
    await expect(page.getByText("Item to Delete 2")).not.toBeVisible()
  })
})

