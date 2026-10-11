/**
 * Deterministic Associated Data (AAD) serialisation.
 *
 * AES-GCM's AAD is passed into the GHASH function; any change to it causes
 * decryption to throw. It is NOT stored alongside the ciphertext — instead,
 * the decryptor reconstructs it from values already stored in the database
 * (entryId, userId, type, versions) and verifies them implicitly.
 *
 * Encoding contract
 * -----------------
 * All AAD values are primitive JSON types (string | number). We serialise them
 * as `JSON.stringify(array)` encoded to UTF-8. An array of primitives is
 * deterministic under JSON.stringify regardless of runtime or platform:
 *   - Array order is fixed by argument position.
 *   - There are no object keys whose ordering could vary.
 *   - Numbers serialise without locale-dependent formatting.
 *   - Strings serialise with standard JSON escaping.
 */

import {
  AAD_LABEL_ENTRY,
  AAD_LABEL_FILE_BLOB,
  AAD_LABEL_VK_WRAP,
  CRYPTO_VERSION,
} from "./constants"

const encoder = new TextEncoder()

// ── Vault-Key wrapping AAD (sections 4 & 5) ──────────────────────────────────

export type VkWrapMode = "master" | "recovery"

/**
 * Builds the AAD bytes for wrapping/unwrapping the Vault Key.
 *
 * Array: `["cipher-vk-wrap", cryptoVersion, mode, userId]`
 *
 * Binding `userId` prevents a wrapped key from being replayed on another
 * account. Binding `mode` prevents swapping the master-wrap with the
 * recovery-wrap.
 */
export function vkWrapAad(mode: VkWrapMode, userId: string): Uint8Array {
  return encoder.encode(
    JSON.stringify([AAD_LABEL_VK_WRAP, CRYPTO_VERSION, mode, userId])
  )
}

// ── Entry encryption AAD (section 7) ─────────────────────────────────────────

export interface EntryAadFields {
  entryId: string
  userId: string
  /** Plaintext entry type as stored in the DB (e.g. "password", "secure_note", "file"). */
  type: string
  /** Matches `VaultConfig.vaultKeyVersion`. */
  vaultKeyVersion: number
}

/**
 * Builds the AAD bytes for encrypting/decrypting a vault entry.
 *
 * Array: `["cipher-entry", cryptoVersion, entryId, userId, type, vaultKeyVersion]`
 *
 * Binding `entryId` prevents ciphertexts from being swapped between entries.
 * Binding `userId` prevents cross-account ciphertext replay.
 * Binding `type` prevents type-confusion attacks (showing a password as a note).
 * Binding `vaultKeyVersion` prevents passing old-VK ciphertexts as current.
 */
export function entryAad(fields: EntryAadFields): Uint8Array {
  return encoder.encode(
    JSON.stringify([
      AAD_LABEL_ENTRY,
      CRYPTO_VERSION,
      fields.entryId,
      fields.userId,
      fields.type,
      fields.vaultKeyVersion,
    ])
  )
}

// ── File blob encryption AAD (Phase 5) ──────────────────────────────────────

export interface FileBlobAadFields {
  entryId: string
  userId: string
  /** Canonical S3/R2 storage key: "u/<userId>/<uuid>". */
  r2Key: string
  /** Matches `VaultConfig.vaultKeyVersion`. */
  vaultKeyVersion: number
}

/**
 * Builds the AAD bytes for encrypting/decrypting a file blob.
 *
 * Array: `["cipher-file-blob", cryptoVersion, entryId, userId, r2Key, vaultKeyVersion]`
 *
 * Binding `entryId`, `userId`, and `r2Key` prevents swapping blobs between entries or users.
 */
export function fileBlobAad(fields: FileBlobAadFields): Uint8Array {
  return encoder.encode(
    JSON.stringify([
      AAD_LABEL_FILE_BLOB,
      CRYPTO_VERSION,
      fields.entryId,
      fields.userId,
      fields.r2Key,
      fields.vaultKeyVersion,
    ])
  )
}

