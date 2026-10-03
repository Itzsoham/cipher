/**
 * @cipher/crypto — Phase 2 tests.
 *
 * These run under Vitest in the Node.js environment. Node 22 provides a
 * standards-conformant WebCrypto implementation at `globalThis.crypto.subtle`.
 *
 * Test organisation:
 *  1. KDF parameter validation (S4 floor/ceiling guard)
 *  2. Padding round-trips and boundary conditions (M12)
 *  3. AAD serialisation determinism
 *  4. Vault Key — wrap, unwrap, and wrong-key failure
 *  5. Recovery KEK derivation (HKDF-SHA-256)
 *  6. Entry encrypt/decrypt round-trip and tampering
 *  7. Session VK non-extractability
 *  8. Known-answer vector: HKDF-SHA-256 (RFC 5869 §A.2)
 */

import { describe, expect, it } from "vitest"

import {
  // KDF
  KDF_FLOOR,
  KDF_CEILING,
  KDF_SALT_BYTES,
  type KdfParams,
  validateKdfParams,
  // Padding
  PADDING_MIN_BYTES,
  PADDING_BUCKET_BYTES,
  PADDING_HEADER_BYTES,
  pad,
  paddedSize,
  unpad,
  // AAD
  vkWrapAad,
  entryAad,
  // Vault Key
  importKek,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  deriveRecoveryKek,
  // Entries
  type EntryPlaintext,
  encryptEntry,
  decryptEntry,
  // Constants
  AES_GCM_IV_BYTES,
  VK_BYTES,
  RECOVERY_HKDF_SALT_BYTES,
  CRYPTO_VERSION,
} from "../src/index.js"
import { ab } from "../src/utils.js"

// ── Helpers ───────────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(new ArrayBuffer(n))
  crypto.getRandomValues(buf)
  return buf
}

/** Build a throwaway 32-byte KEK for tests. */
async function makeKek(): Promise<{ key: CryptoKey; raw: Uint8Array<ArrayBuffer> }> {
  const raw = randomBytes(VK_BYTES)
  const key = await importKek(raw)
  return { key, raw }
}

const TEST_USER = "user_abc123"
const TEST_ENTRY_ID = "11111111-1111-1111-1111-111111111111"
const TEST_TYPE = "password"
const TEST_VKV = 1

// ─────────────────────────────────────────────────────────────────────────────
// 1. KDF parameter validation
// ─────────────────────────────────────────────────────────────────────────────

describe("validateKdfParams", () => {
  const good: KdfParams = {
    algorithm: "argon2id",
    memoryCost: KDF_FLOOR.memoryCost,
    timeCost: KDF_FLOOR.timeCost,
    parallelism: KDF_FLOOR.parallelism,
    salt: randomBytes(KDF_SALT_BYTES),
  }

  it("accepts valid floor-boundary settings", () => {
    expect(() => validateKdfParams(good)).not.toThrow()
  })

  it("accepts valid ceiling-boundary settings", () => {
    expect(() =>
      validateKdfParams({
        ...good,
        memoryCost: KDF_CEILING.memoryCost,
        timeCost: KDF_CEILING.timeCost,
        parallelism: KDF_CEILING.parallelism,
      }),
    ).not.toThrow()
  })

  it("rejects an unknown algorithm", () => {
    expect(() =>
      validateKdfParams({ ...good, algorithm: "bcrypt" }),
    ).toThrow(TypeError)
  })

  it("rejects memoryCost below floor", () => {
    expect(() =>
      validateKdfParams({ ...good, memoryCost: KDF_FLOOR.memoryCost - 1 }),
    ).toThrow(TypeError)
  })

  it("rejects memoryCost above ceiling", () => {
    expect(() =>
      validateKdfParams({ ...good, memoryCost: KDF_CEILING.memoryCost + 1 }),
    ).toThrow(TypeError)
  })

  it("rejects timeCost below floor", () => {
    expect(() =>
      validateKdfParams({ ...good, timeCost: KDF_FLOOR.timeCost - 1 }),
    ).toThrow(TypeError)
  })

  it("rejects timeCost above ceiling", () => {
    expect(() =>
      validateKdfParams({ ...good, timeCost: KDF_CEILING.timeCost + 1 }),
    ).toThrow(TypeError)
  })

  it("rejects parallelism below floor", () => {
    expect(() =>
      validateKdfParams({ ...good, parallelism: KDF_FLOOR.parallelism - 1 }),
    ).toThrow(TypeError)
  })

  it("rejects parallelism above ceiling", () => {
    expect(() =>
      validateKdfParams({ ...good, parallelism: KDF_CEILING.parallelism + 1 }),
    ).toThrow(TypeError)
  })

  it("rejects a salt that is too short", () => {
    expect(() =>
      validateKdfParams({ ...good, salt: randomBytes(KDF_SALT_BYTES - 1) }),
    ).toThrow(TypeError)
  })

  it("rejects a salt that is too long", () => {
    expect(() =>
      validateKdfParams({ ...good, salt: randomBytes(KDF_SALT_BYTES + 1) }),
    ).toThrow(TypeError)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 2. Padding
// ─────────────────────────────────────────────────────────────────────────────

describe("padding", () => {
  it("paddedSize returns at least PADDING_MIN_BYTES for tiny inputs", () => {
    expect(paddedSize(0)).toBe(PADDING_MIN_BYTES)
    expect(paddedSize(1)).toBe(PADDING_MIN_BYTES)
    expect(paddedSize(PADDING_MIN_BYTES - PADDING_HEADER_BYTES - 1)).toBe(
      PADDING_MIN_BYTES,
    )
  })

  it("paddedSize is always a multiple of PADDING_BUCKET_BYTES", () => {
    for (const len of [0, 1, 10, 100, 255, 256, 257, 509, 510, 511, 512, 1000]) {
      const size = paddedSize(len)
      expect(size % PADDING_BUCKET_BYTES).toBe(0)
      expect(size).toBeGreaterThanOrEqual(PADDING_MIN_BYTES)
    }
  })

  it("pad output length matches paddedSize", () => {
    const data = randomBytes(30)
    expect(pad(data).byteLength).toBe(paddedSize(30))
  })

  it("round-trips small plaintext correctly", () => {
    const original = new TextEncoder().encode("hello world")
    const padded = pad(original)
    const recovered = unpad(padded)
    expect(recovered).toEqual(original)
  })

  it("round-trips plaintext that fills exactly one 256-byte bucket", () => {
    // Header (4 B) + 252 B plaintext = 256 B raw — one bucket of 256 B.
    // BUT PADDING_MIN_BYTES is 512, so the result is clamped up to 512.
    const boundary = randomBytes(PADDING_BUCKET_BYTES - PADDING_HEADER_BYTES) // 252 bytes
    expect(pad(boundary).byteLength).toBe(PADDING_MIN_BYTES) // 512 B (minimum applies)
    expect(unpad(pad(boundary))).toEqual(boundary)
  })

  it("round-trips plaintext large enough to escape the minimum (768 bytes output)", () => {
    // Header (4 B) + 764 B plaintext = 768 B → exactly 3 buckets; above PADDING_MIN_BYTES.
    const large = randomBytes(3 * PADDING_BUCKET_BYTES - PADDING_HEADER_BYTES) // 764 bytes
    expect(pad(large).byteLength).toBe(3 * PADDING_BUCKET_BYTES) // 768 B
    expect(unpad(pad(large))).toEqual(large)
  })

  it("padding bytes after plaintext are all zero", () => {
    const original = randomBytes(10)
    const padded = pad(original)
    for (let i = PADDING_HEADER_BYTES + 10; i < padded.byteLength; i++) {
      expect(padded[i]).toBe(0)
    }
  })

  it("unpad throws RangeError if stored length exceeds buffer", () => {
    const buf = new Uint8Array(PADDING_MIN_BYTES)
    // Write a length that overflows.
    new DataView(buf.buffer).setUint32(0, buf.byteLength, false)
    expect(() => unpad(buf)).toThrow(RangeError)
  })

  it("unpad throws RangeError if buffer is below minimum size", () => {
    expect(() => unpad(new Uint8Array(PADDING_MIN_BYTES - 1))).toThrow(RangeError)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 3. AAD serialisation
// ─────────────────────────────────────────────────────────────────────────────

describe("AAD", () => {
  it("vkWrapAad is deterministic for the same inputs", () => {
    const a = vkWrapAad("master", TEST_USER)
    const b = vkWrapAad("master", TEST_USER)
    expect(a).toEqual(b)
  })

  it("vkWrapAad differs between master and recovery modes", () => {
    const m = vkWrapAad("master", TEST_USER)
    const r = vkWrapAad("recovery", TEST_USER)
    expect(m).not.toEqual(r)
  })

  it("vkWrapAad differs for different users", () => {
    const a = vkWrapAad("master", "user_A")
    const b = vkWrapAad("master", "user_B")
    expect(a).not.toEqual(b)
  })

  it("entryAad is deterministic for the same inputs", () => {
    const fields = { entryId: TEST_ENTRY_ID, userId: TEST_USER, type: TEST_TYPE, vaultKeyVersion: TEST_VKV }
    expect(entryAad(fields)).toEqual(entryAad(fields))
  })

  it("entryAad encodes the cryptoVersion constant", () => {
    const raw = new TextDecoder().decode(
      entryAad({ entryId: TEST_ENTRY_ID, userId: TEST_USER, type: TEST_TYPE, vaultKeyVersion: 1 }),
    )
    expect(raw).toContain(String(CRYPTO_VERSION))
  })

  it("entryAad differs when any field changes", () => {
    const base = { entryId: TEST_ENTRY_ID, userId: TEST_USER, type: TEST_TYPE, vaultKeyVersion: 1 }
    const aBase = entryAad(base)

    expect(entryAad({ ...base, entryId: "22222222-2222-2222-2222-222222222222" })).not.toEqual(aBase)
    expect(entryAad({ ...base, userId: "user_other" })).not.toEqual(aBase)
    expect(entryAad({ ...base, type: "secure_note" })).not.toEqual(aBase)
    expect(entryAad({ ...base, vaultKeyVersion: 2 })).not.toEqual(aBase)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 4. Vault Key wrap/unwrap
// ─────────────────────────────────────────────────────────────────────────────

describe("Vault Key wrapping", () => {
  it("wraps and unwraps the VK under master mode", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)
    const unwrapped = await unwrapVaultKey({ wrappedKey, iv, kek, mode: "master", userId: TEST_USER })

    // Smoke-test: the unwrapped key can encrypt and the original can decrypt the same data.
    const data = randomBytes(64)
    const iv2 = randomBytes(AES_GCM_IV_BYTES)
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, vk, data)
    const recovered = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv2 }, unwrapped, ciphertext)
    expect(new Uint8Array(recovered)).toEqual(data)
  })

  it("wraps and unwraps the VK under recovery mode", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "recovery", TEST_USER)
    const unwrapped = await unwrapVaultKey({ wrappedKey, iv, kek, mode: "recovery", userId: TEST_USER })

    const data = randomBytes(32)
    const iv2 = randomBytes(AES_GCM_IV_BYTES)
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, vk, data)
    expect(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv2 }, unwrapped, ct))).toEqual(data)
  })

  it("unwrap fails with a wrong KEK (wrong master password)", async () => {
    const { key: correctKek } = await makeKek()
    const { key: wrongKek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, correctKek, "master", TEST_USER)

    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek: wrongKek, mode: "master", userId: TEST_USER }),
    ).rejects.toThrow()
  })

  it("unwrap fails when mode is swapped (master wrap cannot be opened as recovery)", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)

    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek, mode: "recovery", userId: TEST_USER }),
    ).rejects.toThrow()
  })

  it("unwrap fails when userId is different (cross-account replay)", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", "user_A")

    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek, mode: "master", userId: "user_B" }),
    ).rejects.toThrow()
  })

  it("unwrap fails when any ciphertext byte is tampered", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)
    wrappedKey[0] = wrappedKey[0]! ^ 0xff // flip first byte

    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek, mode: "master", userId: TEST_USER }),
    ).rejects.toThrow()
  })

  it("unwrap fails when the IV is tampered", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)
    iv[0] = iv[0]! ^ 0xff // flip first IV byte

    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek, mode: "master", userId: TEST_USER }),
    ).rejects.toThrow()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 5. Recovery KEK derivation (HKDF-SHA-256)
// ─────────────────────────────────────────────────────────────────────────────

describe("Recovery KEK (HKDF)", () => {
  it("derives KEK_r deterministically from the same inputs", async () => {
    const recoveryKey = randomBytes(VK_BYTES)
    const salt = randomBytes(RECOVERY_HKDF_SALT_BYTES)

    const kek1 = await deriveRecoveryKek(recoveryKey, salt)
    const kek2 = await deriveRecoveryKek(recoveryKey, salt)
    expect(kek1).toEqual(kek2)
  })

  it("derives different KEK_r for different salts", async () => {
    const recoveryKey = randomBytes(VK_BYTES)
    const kek1 = await deriveRecoveryKek(recoveryKey, randomBytes(RECOVERY_HKDF_SALT_BYTES))
    const kek2 = await deriveRecoveryKek(recoveryKey, randomBytes(RECOVERY_HKDF_SALT_BYTES))
    expect(kek1).not.toEqual(kek2)
  })

  it("derives different KEK_r for different recovery keys", async () => {
    const salt = randomBytes(RECOVERY_HKDF_SALT_BYTES)
    const kek1 = await deriveRecoveryKek(randomBytes(VK_BYTES), salt)
    const kek2 = await deriveRecoveryKek(randomBytes(VK_BYTES), salt)
    expect(kek1).not.toEqual(kek2)
  })

  it("derived KEK_r can be imported and used to wrap/unwrap the VK", async () => {
    const recoveryKey = randomBytes(VK_BYTES)
    const salt = randomBytes(RECOVERY_HKDF_SALT_BYTES)

    const kekRaw = await deriveRecoveryKek(recoveryKey, salt)
    const kek = await importKek(kekRaw)
    const vk = await generateVaultKey()

    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "recovery", TEST_USER)
    await expect(
      unwrapVaultKey({ wrappedKey, iv, kek, mode: "recovery", userId: TEST_USER }),
    ).resolves.toBeDefined()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 6. Entry encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────────

describe("Entry encrypt/decrypt", () => {
  const fields = {
    entryId: TEST_ENTRY_ID,
    userId: TEST_USER,
    type: TEST_TYPE,
    vaultKeyVersion: TEST_VKV,
  }

  const plaintext: EntryPlaintext = {
    title: "Example Site",
    site: "https://example.com",
    username: "alice",
    password: "hunter2",
    notes: "test note",
  }

  it("round-trips a password entry", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)
    const decrypted = await decryptEntry(encrypted, vk, fields)
    expect(decrypted).toEqual(plaintext)
  })

  it("produces a fresh IV on every encryption (never reuses)", async () => {
    const vk = await generateVaultKey()
    const a = await encryptEntry(plaintext, vk, fields)
    const b = await encryptEntry(plaintext, vk, fields)
    expect(a.iv).not.toEqual(b.iv)
  })

  it("decryption fails when the ciphertext is tampered", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)
    encrypted.encryptedData[0] = encrypted.encryptedData[0]! ^ 0xff

    await expect(decryptEntry(encrypted, vk, fields)).rejects.toThrow()
  })

  it("decryption fails when the IV is tampered", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)
    encrypted.iv[0] = encrypted.iv[0]! ^ 0xff

    await expect(decryptEntry(encrypted, vk, fields)).rejects.toThrow()
  })

  it("decryption fails when entryId in AAD is changed", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)

    await expect(
      decryptEntry(encrypted, vk, { ...fields, entryId: "99999999-9999-9999-9999-999999999999" }),
    ).rejects.toThrow()
  })

  it("decryption fails when userId in AAD is changed", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)

    await expect(
      decryptEntry(encrypted, vk, { ...fields, userId: "user_attacker" }),
    ).rejects.toThrow()
  })

  it("decryption fails when type in AAD is changed", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)

    await expect(
      decryptEntry(encrypted, vk, { ...fields, type: "secure_note" }),
    ).rejects.toThrow()
  })

  it("decryption fails when vaultKeyVersion in AAD is changed", async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)

    await expect(
      decryptEntry(encrypted, vk, { ...fields, vaultKeyVersion: 2 }),
    ).rejects.toThrow()
  })

  it("decryption fails with a different VK (wrong vault key)", async () => {
    const vk = await generateVaultKey()
    const wrongVk = await generateVaultKey()
    const encrypted = await encryptEntry(plaintext, vk, fields)

    await expect(decryptEntry(encrypted, wrongVk, fields)).rejects.toThrow()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 7. Session VK non-extractability
// ─────────────────────────────────────────────────────────────────────────────

describe("VK non-extractability", () => {
  it("the session VK (unwrapped with extractable: false) cannot be exported", async () => {
    // generateVaultKey() is extractable (needed for wrapKey to work).
    // The *session* VK is the one produced by unwrapVaultKey(extractable: false).
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()
    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)

    const sessionVk = await unwrapVaultKey({
      wrappedKey,
      iv,
      kek,
      mode: "master",
      userId: TEST_USER,
      extractable: false, // ← this is what makes it non-extractable
    })

    await expect(
      crypto.subtle.exportKey("raw", sessionVk),
    ).rejects.toThrow()
  })

  it("an extractable VK (re-wrap helper) can be exported", async () => {
    const { key: kek } = await makeKek()
    const vk = await generateVaultKey()
    const { wrappedKey, iv } = await wrapVaultKey(vk, kek, "master", TEST_USER)

    const extractableVk = await unwrapVaultKey({
      wrappedKey,
      iv,
      kek,
      mode: "master",
      userId: TEST_USER,
      extractable: true,
    })

    const exported = await crypto.subtle.exportKey("raw", extractableVk)
    expect(new Uint8Array(exported).byteLength).toBe(VK_BYTES)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 8. Known-answer vector: HKDF-SHA-256 (RFC 5869 §A.2)
// ─────────────────────────────────────────────────────────────────────────────

describe("HKDF-SHA-256 known-answer vector (RFC 5869 §A.2, first 32 bytes)", () => {
  /** Decode a compact hex string into a Uint8Array<ArrayBuffer>. */
  function hex(s: string): Uint8Array<ArrayBuffer> {
    const bytes = s.match(/../g)!.map((b) => parseInt(b, 16))
    const out = new Uint8Array(new ArrayBuffer(bytes.length))
    bytes.forEach((v, i) => {
      out[i] = v
    })
    return out
  }

  it("matches RFC 5869 §A.2 OKM first 32 bytes", async () => {
    // IKM: 0x00..0x4f (80 bytes)
    const ikm = new Uint8Array(new ArrayBuffer(80)).map((_, i) => i)
    // Salt: 0x60..0xaf (80 bytes)
    const salt = new Uint8Array(new ArrayBuffer(80)).map((_, i) => 0x60 + i)
    // Info: 0xb0..0xef (80 bytes)
    const info = new Uint8Array(new ArrayBuffer(80)).map((_, i) => 0xb0 + i)

    const hkdfKey = await crypto.subtle.importKey("raw", ab(ikm), { name: "HKDF" }, false, ["deriveBits"])
    const derived = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: ab(salt), info: ab(info) },
      hkdfKey,
      32 * 8, // 256 bits
    )

    // RFC 5869 §A.2 OKM (first 32 bytes):
    const expected = hex(
      "b11e398dc80327a1" +
      "c8e7f78c596a4934" +
      "4f012eda2d4efad8" +
      "a050cc4c19afa97c",
    )

    expect(new Uint8Array(derived)).toEqual(expected)
  })
})
