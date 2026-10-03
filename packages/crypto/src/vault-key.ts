/**
 * Vault Key (VK) lifecycle — sections 2, 4, 5, 6.
 *
 * Key-usage flag contract (enforced by WebCrypto, will throw at runtime if wrong)
 * ────────────────────────────────────────────────────────────────────────────────
 *  Role          | Algorithm | extractable | usages
 *  ─────────────────────────────────────────────────────────────────────────────
 *  KEK_m / KEK_r | AES-GCM   | false       | ["wrapKey", "unwrapKey"]
 *  VK (session)  | AES-GCM   | false       | ["encrypt", "decrypt"]
 *  VK (re-wrap)  | AES-GCM   | true        | ["encrypt", "decrypt"]
 *  ─────────────────────────────────────────────────────────────────────────────
 *
 * WebCrypto's wrapKey/unwrapKey use the *wrapping key's* algorithm (AES-GCM
 * here) to perform the wrap, and the *wrapped key's* algorithm for import.
 * The KEK therefore needs ["wrapKey","unwrapKey"], not ["encrypt","decrypt"].
 *
 * generateVaultKey() returns extractable: true so wrapKey can serialise it.
 * The session non-extractable copy comes from unwrapVaultKey(extractable:false).
 */

import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  KEK_BYTES,
  RECOVERY_HKDF_INFO,
  VK_BYTES,
} from "./constants.js"
import { type VkWrapMode, vkWrapAad } from "./aad.js"
import { ab, randomBytes } from "./utils.js"

// Re-export so callers can build both pieces from one import.
export type { VkWrapMode }

const AES_GCM_ALGO = "AES-GCM" as const

/** AES-GCM algorithm descriptor (explicit tagLength: 128). */
function wrapAlgo(
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): AesGcmParams {
  return { name: AES_GCM_ALGO, iv, additionalData: aad, tagLength: 128 }
}

// ── KEK import ───────────────────────────────────────────────────────────────

/**
 * Imports raw 32-byte key material as a non-extractable AES-GCM key
 * with `["wrapKey", "unwrapKey"]` usages.
 *
 * Used for both KEK_m (from Argon2id output) and KEK_r (from HKDF output).
 *
 * IMPORTANT: the usages MUST be ["wrapKey", "unwrapKey"]. If you use
 * ["encrypt", "decrypt"] instead, all calls to crypto.subtle.wrapKey /
 * unwrapKey will throw InvalidAccessError at runtime.
 */
export async function importKek(rawBytes: Uint8Array): Promise<CryptoKey> {
  if (rawBytes.byteLength !== VK_BYTES) {
    throw new RangeError(
      `importKek: expected 32 bytes, got ${rawBytes.byteLength}.`,
    )
  }
  return crypto.subtle.importKey(
    "raw",
    ab(rawBytes),
    { name: AES_GCM_ALGO },
    false, // non-extractable
    ["wrapKey", "unwrapKey"], // ← MUST be wrapKey/unwrapKey, not encrypt/decrypt
  )
}

// ── Vault Key generation ──────────────────────────────────────────────────────

/**
 * Generates a new random 256-bit Vault Key.
 *
 * Returns an *extractable* CryptoKey so it can immediately be passed to
 * `wrapVaultKey()`. WebCrypto's `wrapKey` requires the key being wrapped to
 * have `extractable: true` (the spec exports it internally before encryption).
 *
 * The *session* non-extractable copy is obtained by calling
 * `unwrapVaultKey({ …, extractable: false })` right after the two wraps are
 * stored — the generated key is then dropped.
 */
export async function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: AES_GCM_ALGO, length: 256 },
    true, // must be extractable so wrapKey can serialise it
    ["encrypt", "decrypt"],
  )
}

// ── Wrapping ──────────────────────────────────────────────────────────────────

export interface WrappedVaultKey {
  /** AES-GCM ciphertext of the VK (raw key bytes + 16-byte GCM tag). */
  wrappedKey: Uint8Array<ArrayBuffer>
  /** Random 12-byte IV used for this wrap operation. */
  iv: Uint8Array<ArrayBuffer>
}

/**
 * Wraps the Vault Key under a KEK (master or recovery).
 *
 * The AAD binds the wrap to a specific mode ("master" | "recovery") and
 * userId, so a wrapped VK copied from another account or swapped between the
 * two wrap slots will fail to unwrap.
 *
 * @param vk     - The Vault Key CryptoKey (must be extractable: true).
 * @param kek    - A KEK imported with `importKek()` (usages: wrapKey/unwrapKey).
 * @param mode   - "master" or "recovery".
 * @param userId - The vault owner's user ID.
 */
export async function wrapVaultKey(
  vk: CryptoKey,
  kek: CryptoKey,
  mode: VkWrapMode,
  userId: string,
): Promise<WrappedVaultKey> {
  const iv = randomBytes(AES_GCM_IV_BYTES)
  const aad = ab(vkWrapAad(mode, userId))

  const wrappedBuffer = await crypto.subtle.wrapKey(
    "raw",          // export format for the VK before wrapping
    vk,             // the key to wrap (must be extractable: true)
    kek,            // the wrapping key (needs "wrapKey" usage)
    wrapAlgo(iv, aad),
  )

  return {
    wrappedKey: new Uint8Array(wrappedBuffer) as Uint8Array<ArrayBuffer>,
    iv,
  }
}

// ── Unwrapping ────────────────────────────────────────────────────────────────

export interface UnwrapVaultKeyOptions {
  wrappedKey: Uint8Array
  iv: Uint8Array
  kek: CryptoKey
  mode: VkWrapMode
  userId: string
  /**
   * When false (default, session use): the unwrapped VK is non-extractable.
   * When true (re-wrap only): extractable, so wrapKey can read it again.
   * Drop every reference to an extractable VK as soon as the new wrap is done.
   */
  extractable?: boolean
}

/**
 * Unwraps the Vault Key from storage.
 *
 * Wrong password → the GCM tag check fails → SubtleCrypto throws
 *   `DOMException: The operation failed for an operation-specific reason`
 * (or `"OperationError"`). No separate password verifier is needed or stored.
 *
 * @throws {DOMException} on authentication failure (wrong KEK or tampered data).
 */
export async function unwrapVaultKey(
  opts: UnwrapVaultKeyOptions,
): Promise<CryptoKey> {
  const { wrappedKey, iv, kek, mode, userId, extractable = false } = opts

  if (iv.byteLength !== AES_GCM_IV_BYTES) {
    throw new RangeError(
      `unwrapVaultKey: IV must be ${AES_GCM_IV_BYTES} bytes, got ${iv.byteLength}.`,
    )
  }
  if (wrappedKey.byteLength !== VK_BYTES + AES_GCM_TAG_BYTES) {
    throw new RangeError(
      `unwrapVaultKey: wrappedKey must be ${VK_BYTES + AES_GCM_TAG_BYTES} bytes, got ${wrappedKey.byteLength}.`,
    )
  }

  const aad = ab(vkWrapAad(mode, userId))

  return crypto.subtle.unwrapKey(
    "raw",                               // import format of the unwrapped key
    ab(wrappedKey),                      // the wrapped key bytes
    kek,                                 // the KEK (needs "unwrapKey" usage)
    wrapAlgo(ab(iv), aad),               // algorithm used to unwrap (AES-GCM + AAD)
    { name: AES_GCM_ALGO, length: 256 }, // algorithm for the resulting VK
    extractable,                         // false for sessions, true for re-wrap only
    ["encrypt", "decrypt"],              // usages for the resulting VK
  )
}

// ── HKDF-SHA-256 for KEK_r ────────────────────────────────────────────────────

/**
 * Derives KEK_r from the recovery key's raw bytes using HKDF-SHA-256.
 *
 * The salt is the 32-byte random value stored in `VaultConfig.recoveryHkdfSalt`.
 * The info string is the constant `RECOVERY_HKDF_INFO` ("cipher/v1/recovery-kek").
 *
 * Returns raw bytes — call `importKek()` to turn them into a CryptoKey.
 */
export async function deriveRecoveryKek(
  recoveryKeyBytes: Uint8Array,
  hkdfSalt: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    ab(recoveryKeyBytes),
    { name: "HKDF" },
    false,
    ["deriveBits"],
  )

  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: ab(hkdfSalt),
      info: ab(new TextEncoder().encode(RECOVERY_HKDF_INFO)),
    },
    hkdfKey,
    KEK_BYTES * 8, // bits
  )

  return new Uint8Array(derived) as Uint8Array<ArrayBuffer>
}
