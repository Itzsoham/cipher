import { describe, expect, it, beforeEach, afterEach } from "vitest"
import { LocalStorageDriver } from "../src/lib/storage"
import fs from "node:fs/promises"
import path from "node:path"
import os from "node:os"

describe("Storage Driver & Overflow Backstop Tests", () => {
  let tmpDir: string
  let driver: LocalStorageDriver

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "cipher-storage-test-"))
    driver = new LocalStorageDriver(
      tmpDir,
      "test-secret-key-at-least-32-chars-long!"
    )
  })

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it("HeadObject correctly reports object existence and exact contentLength", async () => {
    const key = "u/user123/file-1.bin"
    const data = Buffer.from("Hello, zero-knowledge encrypted file!")

    const beforeHead = await driver.headObject(key)
    expect(beforeHead.exists).toBe(false)
    expect(beforeHead.contentLength).toBe(0)

    await driver.saveFile(key, data)

    const afterHead = await driver.headObject(key)
    expect(afterHead.exists).toBe(true)
    expect(afterHead.contentLength).toBe(data.length)
  })

  it("detects size mismatch when actual upload exceeds or differs from declared size (HeadObject backstop)", async () => {
    const key = "u/user123/oversized.bin"
    const declaredSize = 100 // Client declared 100 bytes
    const actualUploadedData = Buffer.alloc(200, 0xaa) // Actually uploaded 200 bytes

    await driver.saveFile(key, actualUploadedData)

    const head = await driver.headObject(key)
    expect(head.exists).toBe(true)
    // Server validation check: head.contentLength !== declaredSize
    const isSizeMatched = head.contentLength === declaredSize
    expect(isSizeMatched).toBe(false)
    expect(head.contentLength).toBe(200)
  })

  it("rejects path traversal keys in storage driver", async () => {
    await expect(
      driver.saveFile("../evil.bin", Buffer.from("bad"))
    ).rejects.toThrow("Path traversal attempted")
    await expect(driver.readFile("../evil.bin")).rejects.toThrow(
      "Path traversal attempted"
    )
    await expect(driver.deleteObject("../evil.bin")).rejects.toThrow(
      "Path traversal attempted"
    )
    await expect(driver.headObject("../evil.bin")).rejects.toThrow(
      "Path traversal attempted"
    )
  })

  it("verifies and rejects tampered upload signatures", async () => {
    const key = "u/user123/signed-file.bin"
    const contentLength = 1024
    const { uploadUrl } = await driver.getPresignedUploadUrl({
      key,
      contentLength,
      expiresInSeconds: 300,
    })

    const url = new URL(uploadUrl)
    const expires = parseInt(url.searchParams.get("exp") ?? "0", 10)
    const sig = url.searchParams.get("sig") ?? ""

    // Valid signature
    expect(driver.verifySignature(key, expires, contentLength, sig)).toBe(true)

    // Tampered key
    expect(
      driver.verifySignature(
        "u/user123/other-file.bin",
        expires,
        contentLength,
        sig
      )
    ).toBe(false)

    // Tampered contentLength
    expect(driver.verifySignature(key, expires, contentLength + 1, sig)).toBe(
      false
    )

    // Tampered signature
    expect(
      driver.verifySignature(
        key,
        expires,
        contentLength,
        sig.slice(0, -2) + "00"
      )
    ).toBe(false)
  })

  it("correctly lists all objects with async iterator", async () => {
    await driver.saveFile("u/user1/a.bin", Buffer.from("a"))
    await driver.saveFile("u/user1/b.bin", Buffer.from("b"))
    await driver.saveFile("u/user2/c.bin", Buffer.from("c"))

    const user1Keys: string[] = []
    for await (const obj of driver.listAllObjects("u/user1")) {
      user1Keys.push(obj.key)
    }

    expect(user1Keys.length).toBe(2)
    // Keys normalized with forward slashes or path separators
    expect(user1Keys.some((k) => k.includes("a.bin"))).toBe(true)
    expect(user1Keys.some((k) => k.includes("b.bin"))).toBe(true)
    expect(user1Keys.some((k) => k.includes("c.bin"))).toBe(false)
  })
})
