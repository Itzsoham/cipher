/**
 * Entry encryption and decryption — section 7.
 *
 * Each vault entry is stored as:
 *   encryptedData: Uint8Array  ← AES-GCM ciphertext of the padded JSON
 *   iv:            Uint8Array  ← 12-byte random IV (fresh on every save)
 *
 * The entry's plaintext `type`, `cryptoVersion`, `vaultKeyVersion`, `entryId`,
 * and `userId` are bound via AAD so they cannot be altered or entries cannot be
 * swapped without decryption failing.
 */

import { AES_GCM_IV_BYTES } from "./constants.js"
import { type EntryAadFields, entryAad } from "./aad.js"
import { pad, unpad } from "./padding.js"
import { ab, randomBytes } from "./utils.js"

const AES_GCM_ALGO = "AES-GCM" as const

// ── Types ─────────────────────────────────────────────────────────────────────

/** The raw data that lives in the vault entry JSON before encryption. */
export type EntryPlaintext = Record<string, unknown>

export interface EncryptedEntry {
  /** AES-GCM ciphertext (padded JSON + 128-bit tag). */
  encryptedData: Uint8Array
  /** 12-byte IV; unique per save — store this alongside encryptedData. */
  iv: Uint8Array
}

// ── Encryption ────────────────────────────────────────────────────────────────

/**
 * Encrypts a vault entry.
 *
 * Steps:
 *  1. Serialize `plaintext` to UTF-8 JSON.
 *  2. Pad to the next 256-byte bucket (minimum 512 B), with a 4-byte
 *     big-endian length prefix (M12).
 *  3. Encrypt with AES-256-GCM under `vk`, with a fresh random 12-byte IV.
 *  4. Bind the entry's context (AAD) so the ciphertext is tied to this
 *     specific entry, user, type, and version.
 *
 * @param plaintext - The entry data to encrypt (will be JSON-serialized).
 * @param vk        - The session Vault Key (usages: ["encrypt", "decrypt"]).
 * @param fields    - Fields bound into AAD (entryId, userId, type, vaultKeyVersion).
 */
export async function encryptEntry(
  plaintext: EntryPlaintext,
  vk: CryptoKey,
  fields: EntryAadFields
): Promise<EncryptedEntry> {
  const iv = randomBytes(AES_GCM_IV_BYTES)
  const aad = ab(entryAad(fields))

  const utf8 = ab(new TextEncoder().encode(JSON.stringify(plaintext)))
  const padded = pad(utf8)

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: AES_GCM_ALGO, iv, additionalData: aad, tagLength: 128 },
    vk,
    ab(padded)
  )

  return {
    encryptedData: new Uint8Array(cipherBuffer),
    iv,
  }
}

// ── Decryption ────────────────────────────────────────────────────────────────

/**
 * Decrypts a vault entry.
 *
 * Steps:
 *  1. Reconstruct the AAD from the stored plaintext fields (same values as
 *     at encryption time). AES-GCM verifies the tag automatically.
 *  2. Decrypt.
 *  3. Strip padding: read the 4-byte big-endian length, slice, and parse JSON.
 *
 * @throws {DOMException} if the GCM tag is invalid (tampered ciphertext, wrong
 *   VK, or AAD mismatch).
 * @throws {RangeError}   if the padding metadata is corrupt.
 * @throws {SyntaxError}  if the decrypted bytes are not valid JSON.
 */
export async function decryptEntry(
  encrypted: EncryptedEntry,
  vk: CryptoKey,
  fields: EntryAadFields
): Promise<EntryPlaintext> {
  const { encryptedData, iv } = encrypted

  if (iv.byteLength !== AES_GCM_IV_BYTES) {
    throw new RangeError(
      `decryptEntry: IV must be ${AES_GCM_IV_BYTES} bytes, got ${iv.byteLength}.`
    )
  }

  const aad = ab(entryAad(fields))

  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: AES_GCM_ALGO, iv: ab(iv), additionalData: aad, tagLength: 128 },
    vk,
    ab(encryptedData)
  )

  const padded = new Uint8Array(plaintextBuffer)
  const utf8 = unpad(padded)

  return JSON.parse(new TextDecoder().decode(utf8)) as EntryPlaintext
}
