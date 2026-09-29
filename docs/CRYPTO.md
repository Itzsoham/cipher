# Cipher crypto design (Phase 2 walkthrough)

Status: **draft for approval.** Nothing in `packages/crypto` is written until this is approved.

This explains, in plain language, how the vault is encrypted. Each section says what happens, why, and what exactly is stored. All of it runs in the browser. The server only ever stores the results.

---

## 1. The building blocks

| Tool | What it does here | Where it comes from |
|---|---|---|
| **AES-256-GCM** | Encrypts data and detects any tampering (a 128-bit tag). | The browser's built-in WebCrypto. |
| **Argon2id** | Turns the master password into a key, deliberately slowly and with a lot of memory, so guessing passwords is expensive. | A library (chosen by benchmark, section 9). |
| **HKDF-SHA256** | Turns the recovery key (already random) into an encryption key. No slowness is needed because the recovery key cannot be guessed. | WebCrypto. |
| **`crypto.getRandomValues`** | All randomness: keys, salts, IVs, the recovery key. | WebCrypto. |

No custom cryptography. Everything else is how these pieces are combined.

---

## 2. The Vault Key (VK)

- When you set up the vault, the browser creates one random 256-bit **Vault Key**.
- The VK encrypts every entry and every file. It never changes when you change your password.
- The VK is **never stored as-is**. The server only stores it *wrapped* (encrypted) twice: once under your master password, once under your recovery key.

Why: changing your password or using the recovery key only re-wraps this one small key. None of your data has to be re-encrypted.

---

## 3. Master password → key (Argon2id)

1. Your master password is normalised (Unicode NFC, so the same password typed on different devices gives the same bytes) and encoded as UTF-8.
2. Argon2id runs with a random 16-byte **salt** and these settings:
   - memory **64 MiB**, **3** passes, parallelism **1**, output 32 bytes.
3. The output is **KEK_m** (key-encryption key from the master password). It is imported as a non-extractable AES-GCM key.

Stored on the server (`VaultConfig`): the salt and the three settings. **Not** stored: the password, KEK_m, or any password hash.

Argon2id runs in a **Web Worker**, so the page stays responsive while it works.

### Floor and ceiling on the settings (S4)

The settings come back from the server when you unlock. A malicious or buggy server could send weak settings (to make guessing cheap) or absurd ones (to freeze your browser). So `packages/crypto` checks them **before deriving anything** and refuses anything outside:

| | Floor | Ceiling |
|---|---|---|
| Memory | 64 MiB | 1 GiB |
| Passes | 3 | 10 |
| Parallelism | 1 | 4 |
| Salt | exactly 16 bytes | |
| Algorithm | must be `argon2id` | |

---

## 4. Wrapping the VK under the master password

- The VK is encrypted with AES-256-GCM under KEK_m, with a fresh random 12-byte IV.
- The encryption also binds a label (the *associated data*, see section 7): `["cipher-vk-wrap", 1, "master", userId]`. A wrapped key copied from another account, or swapped with the recovery wrap, fails to open.
- Result: `masterWrappedKey` and `masterWrapIv`.

**Wrong password:** a wrong password gives a different KEK_m, so the GCM tag check fails and unwrapping throws. That failure *is* the password check. No separate verifier is stored, so the server holds nothing to test guesses against except the wrapped key itself (which costs one Argon2id run per guess).

---

## 5. The recovery key

### What it looks like

- 32 random bytes (256 bits), plus a 3-byte checksum (the first 3 bytes of SHA-256 of the 32 bytes). 35 bytes in total.
- Written in **Crockford base32**: digits and capital letters without I, L, O and U, so it is hard to misread. When you type it, case and dashes are ignored, and `O`→`0`, `I`/`L`→`1` are corrected.
- 56 characters in 14 groups of 4, for example:
  `7K3M-Q9TD-2HXA-...` (14 groups)
- The checksum catches typos immediately ("that recovery key is not valid") instead of a confusing decryption failure. A random typo slips past it about once in 16 million tries.

### How it protects the VK

1. **KEK_r** = HKDF-SHA256(recovery key bytes, salt = random 32 bytes, info = `"cipher/v1/recovery-kek"`).
2. The VK is wrapped under KEK_r exactly as in section 4, with the label `["cipher-vk-wrap", 1, "recovery", userId]`.

Stored: `recoveryHkdfSalt`, `recoveryWrappedKey`, `recoveryWrapIv`. **Not** stored: the recovery key.

You see the recovery key **once**, at setup. You confirm it by typing its last group and can download it as a `.txt` file.

---

## 6. How the browser holds the VK (S3)

The raw 32 VK bytes are **never visible to app code**, not even for a moment:

| Situation | How the VK is held |
|---|---|
| **Setup** | WebCrypto generates the VK as a key object, wraps it twice (`wrapKey`), then unwraps a *non-extractable* copy for the session. The generated key is dropped. |
| **Unlocked session** | A *non-extractable* `CryptoKey`: it can encrypt and decrypt, but JavaScript cannot read its bytes. |
| **Change password / recovery** | Unwrap an *extractable* copy inside one function, `wrapKey` it under the new KEK, and drop it before the function returns. |
| **Lock** | The reference is dropped, and decrypted data is cleared (see SECURITY.md for what JavaScript can and cannot promise). |

This goes one step further than the plan: WebCrypto's `wrapKey`/`unwrapKey` do the wrapping inside the browser's crypto engine, so the raw bytes do not pass through JavaScript at all.

---

## 7. Encrypting an entry

An entry is JSON, for example `{ "title": "…", "site": "…", "username": "…", "password": "…", "notes": "…" }`. For a file entry it is the file's name, type and size (the file content is encrypted separately in Phase 5).

1. **Pad** (M12). The JSON is encoded as UTF-8, prefixed with its length (4 bytes), then zero-filled to the next multiple of 256 bytes, with a minimum of 512. So a 30-byte note and a 400-byte note both become 512 bytes, and the server sees only a rough size.
2. **Encrypt** with AES-256-GCM under the VK, with a **fresh random 12-byte IV on every save** (never reused, including edits).
3. **Bind the context** (the associated data, AAD). The AAD is the UTF-8 of this JSON array:
   `["cipher-entry", cryptoVersion, entryId, userId, type, vaultKeyVersion]`
   It is not stored inside the ciphertext, but decryption fails unless the exact same values are supplied. So the server cannot:
   - move a ciphertext to another entry or another account,
   - change an entry's plaintext `type` (e.g. show a password as a note),
   - pass off old-format data as a newer version.
4. Stored: `encryptedData`, `iv`, plus the plaintext `type`, `cryptoVersion`, `vaultKeyVersion` and timestamps. Entry IDs are UUIDs made in the browser, so they are known before encryption and can go into the AAD.

Decryption reverses this: check the AAD, decrypt, read the length prefix, strip the padding, parse the JSON.

**IV safety:** random 96-bit IVs are safe up to about 4 billion encryptions under one key. The vault's limit is 5,000 entries, so this is nowhere near.

---

## 8. The flows

**Setup:** pick master password → derive KEK_m → generate VK → make recovery key → wrap VK twice → upload `VaultConfig` → show recovery key once.

**Unlock:** fetch `VaultConfig` → check KDF settings against floor/ceiling → derive KEK_m in the worker → unwrap VK (non-extractable). A failed tag means "wrong master password".

**Change master password:** unlock with the current password → new salt, derive new KEK_m → re-wrap VK. The recovery wrap is unchanged.

**Forgot master password (recovery):** type the recovery key → checksum check → derive KEK_r → unwrap VK → choose a new master password → re-wrap under it → **issue a new recovery key** (new bytes, new salt) and re-wrap under that → save both in one request. The old recovery key stops working, and the new one is shown once.

---

## 9. Choosing the Argon2id library (benchmark rule)

Per the plan: benchmark in a Web Worker at 64 MiB / 3 passes on desktop Chrome and with Chrome DevTools CPU throttling at 4–6x (plus a real phone if you have one). If a library takes over about 1–1.5 s on desktop or about 3 s on mobile, use **hash-wasm** and add `'wasm-unsafe-eval'` to the CSP. I will report the actual numbers either way.

What I expect going in, to be confirmed by measurement:

| Library | Notes |
|---|---|
| `@noble/hashes` 2.4 | Pure JavaScript, audited, actively maintained (updated Aug 2026). No CSP change. Likely **too slow** at 64 MiB, because pure-JS Argon2 is several times slower than WebAssembly. |
| `argon2-browser` 1.18 | WebAssembly, fast, but **unmaintained since April 2022**. I suggest not shipping an unmaintained crypto dependency even if it benchmarks well. I will still measure it, as the plan says. |
| `hash-wasm` 4.12 | WebAssembly, fast, maintained (last release Nov 2024). The planned fallback. Needs `'wasm-unsafe-eval'`, which permits compiling WebAssembly only, not `eval` of JavaScript. |

Whatever wins, the tests cross-check it against the official Argon2id test vector (RFC 9106) and against a second library.

---

## 10. Tests (Vitest)

- Round trips: entries, both key wraps, padding (including sizes at the 256-byte boundaries).
- Tampering fails: changing any byte of the ciphertext, the IV, or any AAD field (`entryId`, `userId`, `type`, versions).
- Wrong master password and wrong recovery key both fail cleanly.
- KDF settings below the floor or above the ceiling are refused *before* any derivation starts.
- Recovery re-wrap: after recovery, the new password and the new recovery key open the vault, and the old recovery key does not.
- Recovery key encoding: round trip, typo detection, `O`/`I`/`L` correction, case and dash tolerance.
- Known-answer vectors: Argon2id (RFC 9106), HKDF-SHA256 (RFC 5869).
- The session VK is non-extractable (`exportKey` throws).

---

## 11. What this does not protect against

- **The server shipping bad code.** Whoever controls the deployment could serve JavaScript that captures the master password. The same holds for a server that swaps in a wrapped key it knows. Both are the web-delivery limit described in SECURITY.md; the CSP and the no-third-party rule narrow it but cannot remove it.
- **Metadata:** number of entries per type, timestamps, and rough sizes, as the plan states.
- **A weak master password.** Argon2id makes each guess cost about a second of work, but a short common password is still guessable. That is why Phase 3 adds a strength meter with a minimum score.
- **A compromised device** (malware, a malicious browser extension) can read what you see and type.

---

## Decisions for you

1. Approve this design as written, or mark changes.
2. **Recovery key format:** Crockford base32, 14 groups of 4, 24-bit checksum (section 5). OK?
3. **`argon2-browser`:** measure it but rule it out for being unmaintained (section 9)? My recommendation is yes.
