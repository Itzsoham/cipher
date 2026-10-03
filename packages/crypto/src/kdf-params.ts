/**
 * KDF parameter validation — S4 floor/ceiling guard.
 *
 * Called with whatever the server returns in VaultConfig BEFORE any Argon2id
 * derivation begins. Throws a TypeError if anything is out of range so the
 * caller can surface "server error" rather than silently using weak settings.
 */

import {
  KDF_CEILING,
  KDF_FLOOR,
  KDF_SALT_BYTES,
} from "./constants.js"

export interface KdfParams {
  /** Must be exactly "argon2id". */
  algorithm: string
  /** Memory cost in KiB (e.g. 65536 for 64 MiB). */
  memoryCost: number
  /** Number of passes (time cost). */
  timeCost: number
  /** Degree of parallelism. */
  parallelism: number
  /** Random salt; must be exactly KDF_SALT_BYTES long. */
  salt: Uint8Array
}

/**
 * Validates server-supplied Argon2id settings against the hard-coded
 * floor/ceiling. Throws `TypeError` with a descriptive message on any
 * violation. Returns `void` on success.
 *
 * Call this once the VaultConfig is fetched and before calling the KDF.
 */
export function validateKdfParams(p: KdfParams): void {
  if (p.algorithm !== "argon2id") {
    throw new TypeError(
      `KDF: unsupported algorithm "${p.algorithm}"; only "argon2id" is accepted.`,
    )
  }

  if (!(p.salt instanceof Uint8Array) || p.salt.byteLength !== KDF_SALT_BYTES) {
    throw new TypeError(
      `KDF: salt must be exactly ${KDF_SALT_BYTES} bytes, got ${p.salt?.byteLength ?? "??"}.`,
    )
  }

  // Memory cost
  if (p.memoryCost < KDF_FLOOR.memoryCost) {
    throw new TypeError(
      `KDF: memoryCost ${p.memoryCost} KiB is below the floor of ${KDF_FLOOR.memoryCost} KiB (64 MiB).`,
    )
  }
  if (p.memoryCost > KDF_CEILING.memoryCost) {
    throw new TypeError(
      `KDF: memoryCost ${p.memoryCost} KiB exceeds the ceiling of ${KDF_CEILING.memoryCost} KiB (1 GiB).`,
    )
  }

  // Time cost (passes)
  if (p.timeCost < KDF_FLOOR.timeCost) {
    throw new TypeError(
      `KDF: timeCost ${p.timeCost} is below the floor of ${KDF_FLOOR.timeCost}.`,
    )
  }
  if (p.timeCost > KDF_CEILING.timeCost) {
    throw new TypeError(
      `KDF: timeCost ${p.timeCost} exceeds the ceiling of ${KDF_CEILING.timeCost}.`,
    )
  }

  // Parallelism
  if (p.parallelism < KDF_FLOOR.parallelism) {
    throw new TypeError(
      `KDF: parallelism ${p.parallelism} is below the floor of ${KDF_FLOOR.parallelism}.`,
    )
  }
  if (p.parallelism > KDF_CEILING.parallelism) {
    throw new TypeError(
      `KDF: parallelism ${p.parallelism} exceeds the ceiling of ${KDF_CEILING.parallelism}.`,
    )
  }
}
