/**
 * Shared constants for @cipher/crypto.
 *
 * All numeric sizes are in bytes unless the name says otherwise.
 */

export const CRYPTO_VERSION = 1

// ── AES-GCM ──────────────────────────────────────────────────────────────────

/** IV length required by AES-GCM (96 bits). */
export const AES_GCM_IV_BYTES = 12

/** Authentication tag length used by AES-GCM (128 bits / 16 bytes). */
export const AES_GCM_TAG_BYTES = 16

// ── Vault Key ─────────────────────────────────────────────────────────────────

/** Raw byte length of the Vault Key (256 bits). */
export const VK_BYTES = 32

// ── Master-password KDF (Argon2id) ────────────────────────────────────────────

/** Salt length fed to Argon2id (128 bits). */
export const KDF_SALT_BYTES = 16

/** Output key length from Argon2id → KEK_m (256 bits). */
export const KEK_BYTES = 32

/**
 * Hard floors and ceilings for server-supplied Argon2id settings (S4).
 * The crypto layer checks these BEFORE deriving anything.
 */
export const KDF_FLOOR = {
  memoryCost: 64 * 1024, // 64 MiB in KiB
  timeCost: 3,
  parallelism: 1,
} as const

export const KDF_CEILING = {
  memoryCost: 1024 * 1024, // 1 GiB in KiB
  timeCost: 10,
  parallelism: 4,
} as const

// ── Recovery key (HKDF) ───────────────────────────────────────────────────────

/** Raw entropy bytes in the recovery key (256 bits). */
export const RECOVERY_KEY_BYTES = 32

/** Salt fed to HKDF-SHA-256 when deriving KEK_r. */
export const RECOVERY_HKDF_SALT_BYTES = 32

/** Canonical HKDF info string for KEK_r derivation. */
export const RECOVERY_HKDF_INFO = "cipher/v1/recovery-kek"

// ── Padding (M12) ─────────────────────────────────────────────────────────────

/** Length prefix stored inside each padded plaintext (4-byte big-endian uint32). */
export const PADDING_HEADER_BYTES = 4

/** Pad to the next multiple of this many bytes. */
export const PADDING_BUCKET_BYTES = 256

/** Minimum padded size (includes the 4-byte header). */
export const PADDING_MIN_BYTES = 512

// ── AAD label strings ─────────────────────────────────────────────────────────

/** Prefix used in the AAD for wrapping the Vault Key. */
export const AAD_LABEL_VK_WRAP = "cipher-vk-wrap"

/** Prefix used in the AAD for encrypting vault entries. */
export const AAD_LABEL_ENTRY = "cipher-entry"
