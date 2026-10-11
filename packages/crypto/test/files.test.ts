import { describe, expect, it } from "vitest"
import {
  generateVaultKey,
  encryptFileBlob,
  decryptFileBlob,
  fileBlobAad,
  type FileBlobAadFields,
  AES_GCM_TAG_BYTES,
} from "../src"

describe("File Blob Encryption & Decryption (Phase 5)", () => {
  const fields: FileBlobAadFields = {
    entryId: "550e8400-e29b-41d4-a716-446655440000",
    userId: "user_test_123",
    r2Key: "u/user_test_123/550e8400-e29b-41d4-a716-446655440000",
    vaultKeyVersion: 1,
  }

  it("successfully encrypts and decrypts a file blob round-trip", async () => {
    const vk = await generateVaultKey()
    const originalText = "Sensitive financial report and customer identities"
    const originalBytes = new TextEncoder().encode(originalText)

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    // Ciphertext size must equal original size + 16-byte AES-GCM tag
    expect(encryptedBlob.byteLength).toBe(
      originalBytes.byteLength + AES_GCM_TAG_BYTES
    )
    expect(blobIv.byteLength).toBe(12)

    // Decrypt
    const decryptedBytes = await decryptFileBlob(
      encryptedBlob,
      blobIv,
      vk,
      fields,
      originalBytes.byteLength
    )

    const decryptedText = new TextDecoder().decode(decryptedBytes)
    expect(decryptedText).toBe(originalText)
  })

  it("fails to decrypt if ciphertext is tampered", async () => {
    const vk = await generateVaultKey()
    const originalBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    const tampered = new Uint8Array(encryptedBlob)
    tampered[0]! ^= 0x01

    await expect(
      decryptFileBlob(tampered, blobIv, vk, fields, originalBytes.byteLength)
    ).rejects.toThrow()
  })

  it("fails to decrypt if blobIv is corrupted or wrong", async () => {
    const vk = await generateVaultKey()
    const originalBytes = new Uint8Array([10, 20, 30, 40])

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    const wrongIv = new Uint8Array(blobIv)
    wrongIv[0]! ^= 0xff

    await expect(
      decryptFileBlob(encryptedBlob, wrongIv, vk, fields, originalBytes.byteLength)
    ).rejects.toThrow()
  })

  it("fails to decrypt if r2Key in AAD is mismatched", async () => {
    const vk = await generateVaultKey()
    const originalBytes = new Uint8Array([11, 22, 33])

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    const swappedFields: FileBlobAadFields = {
      ...fields,
      r2Key: "u/user_attacker/swapped-key",
    }

    await expect(
      decryptFileBlob(encryptedBlob, blobIv, vk, swappedFields, originalBytes.byteLength)
    ).rejects.toThrow()
  })

  it("fails to decrypt if entryId or userId in AAD is mismatched", async () => {
    const vk = await generateVaultKey()
    const originalBytes = new Uint8Array([99, 88, 77])

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    await expect(
      decryptFileBlob(
        encryptedBlob,
        blobIv,
        vk,
        { ...fields, entryId: "00000000-0000-0000-0000-000000000000" },
        originalBytes.byteLength
      )
    ).rejects.toThrow()

    await expect(
      decryptFileBlob(
        encryptedBlob,
        blobIv,
        vk,
        { ...fields, userId: "different_user" },
        originalBytes.byteLength
      )
    ).rejects.toThrow()
  })

  it("fails if expectedPlaintextSize does not match decrypted length", async () => {
    const vk = await generateVaultKey()
    const originalBytes = new Uint8Array([1, 2, 3, 4, 5])

    const { encryptedBlob, blobIv } = await encryptFileBlob(
      originalBytes,
      vk,
      fields
    )

    await expect(
      decryptFileBlob(
        encryptedBlob,
        blobIv,
        vk,
        fields,
        10 // Wrong expected size
      )
    ).rejects.toThrow(RangeError)
  })

  it("deterministic fileBlobAad format", () => {
    const aadBytes = fileBlobAad(fields)
    const jsonStr = new TextDecoder().decode(aadBytes)
    const parsed = JSON.parse(jsonStr)

    expect(parsed).toEqual([
      "cipher-file-blob",
      1,
      fields.entryId,
      fields.userId,
      fields.r2Key,
      fields.vaultKeyVersion,
    ])
  })
})
