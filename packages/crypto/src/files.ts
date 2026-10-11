/**
 * File blob encryption and decryption — Phase 5.
 *
 * Each file attached to a vault entry has its raw bytes encrypted client-side
 * before upload via AES-256-GCM under the session Vault Key (VK).
 *
 * AAD bindings:
 *   ["cipher-file-blob", cryptoVersion, entryId, userId, r2Key, vaultKeyVersion]
 *
 * This binds the blob cryptographically to the entry, user, R2 key, and key version.
 */

import { AES_GCM_IV_BYTES } from "./constants"
import { type FileBlobAadFields, fileBlobAad } from "./aad"
import { ab, randomBytes } from "./utils"

const AES_GCM_ALGO = "AES-GCM" as const

export interface EncryptedFileBlob {
  encryptedBlob: Uint8Array
  blobIv: Uint8Array
}

/**
 * Encrypts a raw file blob using AES-256-GCM under the session Vault Key.
 *
 * @param fileBytes - The raw file bytes (ArrayBuffer or Uint8Array).
 * @param vk        - The session Vault Key (non-extractable CryptoKey).
 * @param fields    - Context fields bound into the AAD.
 */
export async function encryptFileBlob(
  fileBytes: ArrayBuffer | Uint8Array,
  vk: CryptoKey,
  fields: FileBlobAadFields
): Promise<EncryptedFileBlob> {
  const blobIv = randomBytes(AES_GCM_IV_BYTES) // 12 bytes
  const aad = ab(fileBlobAad(fields))

  const u8 = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes)
  const ciphertext = await crypto.subtle.encrypt(
    { name: AES_GCM_ALGO, iv: blobIv, additionalData: aad, tagLength: 128 },
    vk,
    ab(u8)
  )

  return {
    encryptedBlob: new Uint8Array(ciphertext),
    blobIv,
  }
}

/**
 * Decrypts an encrypted file blob and verifies that the decrypted byte length
 * strictly matches the expected plaintext file size declared in metadata.
 *
 * @param encryptedBlob         - The raw ciphertext bytes (including 16-byte GCM tag).
 * @param blobIv                - 12-byte random IV used during encryption.
 * @param vk                    - The session Vault Key.
 * @param fields                - Context fields reconstructed from entry metadata.
 * @param expectedPlaintextSize - Plaintext byte length from FileEntryPayload.fileSize.
 *
 * @throws {DOMException} if GCM tag verification fails or AAD mismatches.
 * @throws {RangeError}   if decrypted length doesn't equal expectedPlaintextSize.
 */
export async function decryptFileBlob(
  encryptedBlob: ArrayBuffer | Uint8Array,
  blobIv: Uint8Array,
  vk: CryptoKey,
  fields: FileBlobAadFields,
  expectedPlaintextSize: number
): Promise<Uint8Array> {
  if (blobIv.byteLength !== AES_GCM_IV_BYTES) {
    throw new RangeError(
      `decryptFileBlob: blobIv must be ${AES_GCM_IV_BYTES} bytes, got ${blobIv.byteLength}.`
    )
  }

  const aad = ab(fileBlobAad(fields))

  const u8 = encryptedBlob instanceof Uint8Array ? encryptedBlob : new Uint8Array(encryptedBlob)
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: AES_GCM_ALGO, iv: ab(blobIv), additionalData: aad, tagLength: 128 },
    vk,
    ab(u8)
  )

  const result = new Uint8Array(plaintextBuffer)

  if (result.byteLength !== expectedPlaintextSize) {
    throw new RangeError(
      `decryptFileBlob: decrypted size ${result.byteLength} bytes does not match expected size ${expectedPlaintextSize} bytes.`
    )
  }

  return result
}
