/**
 * @cipher/crypto — Phase 2 public surface.
 *
 * All cryptographic operations run in the browser against WebCrypto (or in a
 * Vitest environment that polyfills it). No Node.js crypto is used.
 */

// ── Constants ─────────────────────────────────────────────────────────────────
export {
  CRYPTO_VERSION,
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  VK_BYTES,
  KDF_SALT_BYTES,
  KEK_BYTES,
  KDF_FLOOR,
  KDF_CEILING,
  RECOVERY_KEY_BYTES,
  RECOVERY_HKDF_SALT_BYTES,
  RECOVERY_HKDF_INFO,
  PADDING_HEADER_BYTES,
  PADDING_BUCKET_BYTES,
  PADDING_MIN_BYTES,
  AAD_LABEL_VK_WRAP,
  AAD_LABEL_ENTRY,
} from "./constants.js"

// ── KDF parameter validation ──────────────────────────────────────────────────
export { type KdfParams, validateKdfParams } from "./kdf-params.js"

// ── Padding ───────────────────────────────────────────────────────────────────
export { paddedSize, pad, unpad } from "./padding.js"

// ── AAD ───────────────────────────────────────────────────────────────────────
export {
  type VkWrapMode,
  type EntryAadFields,
  vkWrapAad,
  entryAad,
} from "./aad.js"

// ── Vault Key lifecycle ───────────────────────────────────────────────────────
export {
  importKek,
  generateVaultKey,
  type WrappedVaultKey,
  type UnwrapVaultKeyOptions,
  wrapVaultKey,
  unwrapVaultKey,
  deriveRecoveryKek,
} from "./vault-key.js"

// ── Entry encryption ──────────────────────────────────────────────────────────
export {
  type EntryPlaintext,
  type EncryptedEntry,
  encryptEntry,
  decryptEntry,
} from "./entries.js"
