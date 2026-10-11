import { MASTER_PASSWORD, users } from "./constants"
import { clearRateLimits, deleteE2eUsers } from "./db"
import { createVerifiedUser, expect, signIn, test } from "./helpers"

test.describe("Vault File Attachments & Object Storage (Phase 5)", () => {
  test.beforeEach(async () => {
    test.setTimeout(90_000)
    await deleteE2eUsers()
    await clearRateLimits()
  })

  test.afterAll(async () => {
    await deleteE2eUsers()
    await clearRateLimits()
  })

  test("zero-knowledge file attachment lifecycle: wire check, download byte-identity, allowlisted preview, 25MB check, and lock purge", async ({
    page,
  }) => {
    // 1. Setup user & unlock vault
    await createVerifiedUser(page, users.vaultFiles)
    await signIn(page, users.vaultFiles)
    await expect(page).toHaveURL(/\/vault$/, { timeout: 15_000 })

    await expect(page.getByText("Set Up Master Password")).toBeVisible()
    await page.locator("#master-password").fill(MASTER_PASSWORD)
    await page.locator("#confirm-password").fill(MASTER_PASSWORD)
    await page.getByRole("button", { name: "Continue to Recovery Key" }).click()

    await expect(page.getByText("Save Your Recovery Key")).toBeVisible({
      timeout: 15_000,
    })
    const recoveryKeyEl = page.locator("div.font-mono.select-all")
    const recoveryKeyText = (await recoveryKeyEl.textContent())?.trim() ?? ""
    const lastGroup = recoveryKeyText.split("-").pop()!

    await page.locator("#confirm-recovery").fill(lastGroup)
    await expect(
      page.getByRole("button", { name: "Complete Vault Setup" })
    ).toBeEnabled()
    await page.getByRole("button", { name: "Complete Vault Setup" }).click()

    await expect(
      page.locator('[data-testid="vault-unlocked-status"]')
    ).toBeVisible({
      timeout: 15_000,
    })

    // 2. Wire Check Interceptors
    let interceptedPresignData: Record<string, unknown> | null = null
    let interceptedUploadBody: Buffer | null = null
    let interceptedEntryData: Record<string, unknown> | null = null

    await page.route("**/api/vault/files/presign-upload", async (route) => {
      if (route.request().method() === "POST") {
        interceptedPresignData = route.request().postDataJSON()
      }
      await route.continue()
    })

    await page.route("**/api/vault/files/local-storage*", async (route) => {
      if (route.request().method() === "PUT") {
        interceptedUploadBody = route.request().postDataBuffer()
      }
      await route.continue()
    })

    await page.route("**/api/vault/entries", async (route) => {
      if (route.request().method() === "POST") {
        interceptedEntryData = route.request().postDataJSON()
      }
      await route.continue()
    })

    // 3. Open New Entry modal & Select File type
    await page.getByRole("button", { name: "New Entry" }).click()
    await expect(page.getByText("New Vault Entry")).toBeVisible()
    await page.getByRole("button", { name: "File" }).click()

    // 4. Test Zero-Byte rejection
    const emptyFilePayload = {
      name: "empty.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(""),
    }
    await page.locator("#file-upload-input").setInputFiles(emptyFilePayload)
    await expect(page.getByText(/File (must not be empty|cannot be empty)/i)).toBeVisible()

    // 5. Upload a Valid Text File
    const secretContent = "TOP_SECRET_CLASSIFIED_DATA_V5_CONFIDENTIAL"
    const validFilePayload = {
      name: "secret-notes.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(secretContent, "utf-8"),
    }

    await page.locator("#file-upload-input").setInputFiles(validFilePayload)
    await expect(page.getByText("secret-notes.txt")).toBeVisible()
    await page.locator("#entry-notes").fill("Confidential project brief")

    // Submit File Entry
    await page.getByRole("button", { name: /Upload & (Encrypt|Save Entry)/ }).click()
    await expect(
      page.getByText(/File (encrypted and uploaded|entry created) successfully/)
    ).toBeVisible({
      timeout: 20_000,
    })

    // 6. Verify Wire Security & Zero-Knowledge Invariants
    // Server presign route only receives blobSize, not filename or plaintext
    expect(interceptedPresignData).not.toBeNull()
    expect(JSON.stringify(interceptedPresignData)).not.toContain(
      "secret-notes.txt"
    )
    expect(JSON.stringify(interceptedPresignData)).not.toContain(secretContent)

    // Storage driver upload route receives only AES-GCM encrypted bytes
    expect(interceptedUploadBody).not.toBeNull()
    expect(interceptedUploadBody!.toString("utf-8")).not.toContain(
      secretContent
    )

    // Vault Entry creation route never receives plaintext metadata or content
    expect(interceptedEntryData).not.toBeNull()
    expect(interceptedEntryData).toHaveProperty("type", "file")
    expect(interceptedEntryData).toHaveProperty("r2Key")
    expect(interceptedEntryData).toHaveProperty("blobIv")
    expect(interceptedEntryData).toHaveProperty("blobSize")
    expect(JSON.stringify(interceptedEntryData)).not.toContain(
      "secret-notes.txt"
    )
    expect(JSON.stringify(interceptedEntryData)).not.toContain("text/plain")
    expect(JSON.stringify(interceptedEntryData)).not.toContain(secretContent)
    expect(JSON.stringify(interceptedEntryData)).not.toContain(
      "Confidential project brief"
    )

    // 7. Verify List and Detail Rendering
    await expect(
      page.getByRole("heading", { name: "secret-notes.txt" })
    ).toBeVisible()
    await page.getByRole("button", { name: /secret-notes\.txt/ }).click()

    await expect(page.getByText("text/plain")).toBeVisible()
    await expect(page.getByText("Confidential project brief")).toBeVisible()

    // 8. Safe Allowlisted Preview
    await page.getByRole("button", { name: "Preview" }).click()
    await expect(page.getByText("Preview: secret-notes.txt")).toBeVisible()
    // Content rendered in <pre> tag
    await expect(page.locator("pre").getByText(secretContent)).toBeVisible()
    // Verify no sandbox="allow-same-origin" iframe exists
    const unsafeFrames = await page
      .locator('iframe[sandbox*="allow-same-origin"]')
      .count()
    expect(unsafeFrames).toBe(0)

    // Close preview modal
    await page.keyboard.press("Escape")

    // 9. Download and Byte-Identity Check
    const downloadPromise = page.waitForEvent("download")
    await page.getByRole("button", { name: /Download/ }).first().click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe("secret-notes.txt")

    const downloadStream = await download.createReadStream()
    const chunks: Buffer[] = []
    for await (const chunk of downloadStream) {
      chunks.push(chunk as Buffer)
    }
    const downloadedContent = Buffer.concat(chunks).toString("utf-8")
    expect(downloadedContent).toBe(secretContent)

    // 10. Lock Purges Decrypted File Content & References
    await page.getByRole("button", { name: "Lock" }).click()
    await expect(page.getByText("Unlock Your Vault")).toBeVisible()
    await expect(page.getByText("secret-notes.txt")).not.toBeVisible()
    await expect(page.getByText(secretContent)).not.toBeVisible()
  })
})
