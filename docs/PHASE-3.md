# Phase 3: Vault Flows (Setup, Unlock, Lock, Change Password, Recovery)

Status: **revised for approval.** Strict zero-knowledge architecture aligned with `docs/PLAN.md` and `docs/CRYPTO.md`.

---

## 1. Scope & Principles

### 1.1 Strictly in Phase 3
1. **Master password setup wizard:** Strength check (zxcvbn-ts), VK generation, wrapping under KEK_m and KEK_r, one-time recovery key display & confirmation, upload `VaultConfig`.
2. **Unlock flow:** Fetch `VaultConfig`, validate KDF params against floors/ceilings, derive KEK_m in a Web Worker, unwrap session VK (`extractable: false`). The GCM tag check *is* the password verification.
3. **Lock & auto-lock:** Memory teardown (drop VK, clear caches), idle detection with timestamp-based sleep/wake recovery, cross-tab synchronization via `BroadcastChannel("cipher-vault")`.
4. **Change master password:** While unlocked, unwrap short-lived extractable VK, generate new salt, derive new KEK_m, re-wrap VK, submit with re-auth & optimistic concurrency check.
5. **Recovery flow:** Input Crockford base32 recovery key, checksum verification, derive KEK_r, unwrap VK, set new master password, generate & confirm **new** recovery key, submit both wraps atomically with re-auth.
6. **Settings:** Auto-lock timeout adjustment, Change Master Password, Regenerate Recovery Key (while unlocked only).

### 1.2 Cut back to Phase 4 & Phase 5 (Anti-Scope Creep)
- **Phase 4:** Entry CRUD (create, read, update, delete entries), in-memory search & filtering, password generator, clipboard auto-clear for copied secrets.
- **Phase 5:** File uploads/downloads, R2 storage integration, streaming encryption.

---

## 2. Zero-Knowledge API Contract

The server **never** verifies passwords, never holds master password hashes, never decrypts data, and never counts "wrong password attempts."

| Route | Method | Purpose & Zero-Knowledge Behavior |
|---|---|---|
| `/api/vault/config` | GET | Returns the user's `VaultConfig` (KDF salt, KDF parameters, `masterWrappedKey`, `masterWrapIv`, `recoveryHkdfSalt`, `recoveryWrappedKey`, `recoveryWrapIv`, `autoLockMinutes`, `updatedAt`). Rate-limited to prevent scraping. |
| `/api/vault/setup` | POST | Initial creation of `VaultConfig`. Rejects if config already exists for user. Validates KDF settings against floor/ceiling and payload sizes. |
| `/api/vault/change-password` | POST | Updates `masterWrappedKey`, `masterWrapIv`, and KDF settings. Requires **fresh account session re-auth** and **optimistic concurrency check** (`expectedUpdatedAt`). Recovery wrap is preserved. |
| `/api/vault/recover` | POST | Atomically updates **both** wraps (`masterWrappedKey`, `masterWrapIv`, KDF params, `recoveryWrappedKey`, `recoveryWrapIv`, `recoveryHkdfSalt`). Requires fresh session re-auth and `expectedUpdatedAt`. Old recovery key is invalidated immediately. |
| `/api/vault/regenerate-recovery` | POST | Updates `recoveryWrappedKey`, `recoveryWrapIv`, `recoveryHkdfSalt`. Requires fresh session re-auth and `expectedUpdatedAt`. Master wrap is preserved. |
| `/api/vault/settings` | PATCH | Updates non-cryptographic vault preferences (e.g. `autoLockMinutes`: 1–30 min). |

### 2.1 Concurrency & Overwrite Protection (Compare-and-Swap)
Whenever wraps are updated (`/change-password`, `/recover`, `/regenerate-recovery`), the client sends:
- `expectedUpdatedAt`: The ISO timestamp of `VaultConfig.updatedAt` fetched at start of the flow.
- The server performs an atomic update:
  ```ts
  const result = await prisma.vaultConfig.updateMany({
    where: { userId: session.user.id, updatedAt: new Date(expectedUpdatedAt) },
    data: { ...newWraps, updatedAt: new Date() },
  })
  if (result.count === 0) throw new APIError("CONFLICT", "Vault configuration has changed in another session.")
  ```
This prevents stale tabs or hijacked sessions from bricking the vault with junk wraps.

### 2.2 Rate Limiting
- Rate limiting is applied to **API requests** (e.g. `/api/vault/config` GET 10/min per IP/user, `/api/vault/change-password` and `/api/vault/recover` 3/5min).
- The server **does not** and **cannot** rate-limit offline master password guesses. Protection against offline brute-forcing comes entirely from the computational and memory cost of Argon2id (64 MiB, 3 passes) enforced by the S4 parameter floor.

---

## 3. Client-Side Vault Flows

### 3.1 Master Password Setup Wizard (`setup-flow.tsx`)
1. **Password entry & validation:**
   - Evaluated using `zxcvbn-ts`. Minimum required score: **3 of 4** (0–4 scale).
   - `userInputs` passed to zxcvbn include user's email, name, and username to prevent personal information in the master password.
   - Prominent UI warning: *"Your master password must differ from your account login password. Cipher cannot reset your master password."*
2. **Key generation & derivation (in memory):**
   - Client generates a random 16-byte KDF salt via `crypto.getRandomValues`.
   - Web Worker derives KEK_m using Argon2id (64 MiB, 3 passes, 1 thread).
   - Client generates extractable Vault Key (256-bit AES-GCM).
   - Wraps VK under KEK_m (`wrapVaultKey`) with AAD `["cipher-vk-wrap", 1, "master", userId]`.
   - Generates 32 random bytes for recovery key + 3-byte SHA-256 checksum (Crockford base32, 14 groups of 4).
   - Derives KEK_r via HKDF-SHA256 with fresh 32-byte `recoveryHkdfSalt`.
   - Wraps VK under KEK_r (`wrapVaultKey`) with AAD `["cipher-vk-wrap", 1, "recovery", userId]`.
3. **Show & confirm recovery key BEFORE committing:**
   - **Crucial ordering:** The wraps are held in component memory. The recovery key is displayed to the user with a "Download .txt" button and copy button.
   - User must confirm they saved the key by typing the **last group** (4 characters) of the recovery key.
   - Only **after** successful confirmation does the client POST to `/api/vault/setup`.
   - If the network request fails, user can retry without losing the generated key. If the tab closes before confirmation, the vault remains uninitialized.
4. **Session initialization:**
   - Client unwraps session VK as non-extractable (`extractable: false`), drops extractable VK references, publishes `UNLOCK` to `BroadcastChannel`, and enters `/vault`.

### 3.2 Unlock Flow (`unlock-modal.tsx` or `/vault/unlock`)
1. Client fetches `VaultConfig` from `/api/vault/config`.
2. Validates KDF settings against hardcoded floor and ceiling (`validateKdfParams`).
3. Master password input is passed to Web Worker with salt and parameters.
4. Worker returns KEK_m bytes (transferred via `postMessage(buf, [buf])`).
5. Client imports KEK_m with usages `["unwrapKey"]`.
6. Client attempts `unwrapVaultKey`:
   - SubtleCrypto verifies the 128-bit AES-GCM tag against `masterWrappedKey`, `masterWrapIv`, and AAD `["cipher-vk-wrap", 1, "master", userId]`.
   - **Wrong password:** GCM authentication tag check fails, throwing `OperationError`. Client displays *"Incorrect master password"*.
   - **Correct password:** Produces non-extractable session `CryptoKey` (`extractable: false`).
7. Stores session VK in client memory (`VaultSession`).
8. Publishes `UNLOCK` event with current timestamp across `BroadcastChannel("cipher-vault")`.
9. Starts auto-lock monitor.

### 3.3 Auto-Lock & Cross-Tab Synchronization

#### Cross-Tab Coordination (`BroadcastChannel("cipher-vault")`)
- `type SyncMessage = { type: 'LOCK' | 'UNLOCK' | 'ACTIVITY', timestamp: number }`
- **Lock propagation:** Any tab sending `LOCK` causes all tabs to drop the session VK and reset UI to locked state.
- **Activity propagation:** Any user interaction (click, keypress, scroll) in any tab throttles an `ACTIVITY` message every 15s to reset idle timers across tabs.
- **Unlock synchronization:** When Tab A unlocks, it broadcasts `UNLOCK`. Tab B notes that the vault is unlocked in the session; each tab maintains its own in-memory non-extractable `CryptoKey` (or Tab B prompts password on demand if keys cannot cross worker boundaries).

#### Sleep-Safe Idle Detection
Timers (`setTimeout` / `setInterval`) pause when laptops sleep or mobile browsers background tabs. Relying purely on timers causes stale vaults to remain open after wake-up.
- `VaultSession` records `lastActivityTimestamp = Date.now()`.
- On window `focus`, `visibilitychange`, and a periodic 5s heartbeat check:
  ```ts
  const idleMs = Date.now() - lastActivityTimestamp
  if (idleMs >= autoLockMinutes * 60 * 1000) {
    vaultSession.lock() // Lock immediately
  }
  ```

#### Teardown on Lock (S5)
When locking (explicit button, timeout, or cross-tab message):
1. Session VK reference is set to `null`.
2. Decrypted state stores and React Query caches are invalidated/wiped.
3. Component tree re-renders to locked placeholder / unlock modal.
4. Broadcasts `LOCK` to other tabs.

### 3.4 Change Master Password Flow
1. Vault must already be unlocked (user holds active session VK).
2. Prompts user for current master password (to ensure session freshness and extractability) or derives from active session.
3. Generates fresh 16-byte KDF salt, derives new KEK_m in worker.
4. Unwraps extractable VK inside an isolated function scope, wraps under new KEK_m.
5. Immediately drops extractable VK references.
6. Submits new wrap + KDF params + `expectedUpdatedAt` to `/api/vault/change-password`.
7. Recovery wrap remains untouched.

### 3.5 Recovery Flow (`recovery-flow.tsx`)
1. User enters 56-character recovery key (Crockford base32).
2. Client parses, normalizes (`O`→`0`, `I`/`L`→`1`), and verifies 24-bit SHA-256 checksum. Invalid checksum halts immediately with typo notification.
3. Client derives KEK_r via HKDF-SHA256 (`deriveRecoveryKek`) using `VaultConfig.recoveryHkdfSalt`.
4. Unwraps VK (`extractable: true`) in single-function scope.
5. Prompts user for **new master password** (validated with zxcvbn >= 3/4).
6. Derives new KEK_m, re-wraps VK under new master password.
7. **Issues NEW recovery key:**
   - Generates 32 random bytes + 3-byte checksum.
   - Derives new KEK_r with fresh 32-byte salt, wraps VK under new KEK_r.
8. **Show & confirm NEW recovery key BEFORE committing:**
   - Displays new recovery key, offers `.txt` download.
   - Requires user to confirm typing the last group (4 characters).
9. Submits both wraps + `expectedUpdatedAt` to `/api/vault/recover`.
10. Old recovery key is permanently dead. New master password and new recovery key are now active.

### 3.6 Settings & Recovery Key Management
- **View existing recovery key:** **Impossible by design.** The recovery key is never stored in the database or client storage. Settings displays a plain explanation: *"Your recovery key is not stored anywhere. If you lost your copy, regenerate a new one below."*
- **Regenerate recovery key (while unlocked):**
  - Requires vault to be unlocked.
  - Client generates new recovery key, derives new KEK_r, re-wraps active VK.
  - Displays & confirms new recovery key before submitting to `/api/vault/regenerate-recovery`.

---

## 4. Architecture & Component Tree

```
apps/web/src/
├── app/(app)/
│   └── vault/
│       ├── page.tsx                  ── Unlocked dashboard placeholder / status
│       └── settings/
│           └── page.tsx              ── Vault settings (auto-lock, change password, regenerate recovery)
├── components/vault/
│   ├── setup-wizard.tsx              ── Master password setup + one-time recovery key display & confirmation
│   ├── unlock-modal.tsx              ── Password input, Web Worker KDF, unwrap VK
│   ├── recovery-wizard.tsx           ── Recovery key input, typo check, new password + new recovery key
│   ├── change-password-modal.tsx     ── Change master password dialog
│   ├── regenerate-recovery-modal.tsx ── Regenerate recovery key dialog
│   └── vault-status-bar.tsx          ── Lock button, auto-lock countdown, sync indicator
├── lib/vault/
│   ├── worker-client.ts              ── Web Worker Argon2id bridge with transferable ArrayBuffers
│   ├── vault-session.ts              ── In-memory CryptoKey holder, lock/unlock state
│   ├── vault-sync.ts                 ── BroadcastChannel coordinator with sleep-safe timestamping
│   ├── recovery-key.ts               ── Crockford base32 encode/decode, 24-bit SHA-256 checksum
│   └── password-strength.ts          ── zxcvbn-ts wrapper with userInputs & 0-4 scoring
└── workers/
    └── kdf.worker.ts                 ── Argon2id derivation worker (transfers ArrayBuffer back)
```

---

## 5. Phase 3 Milestones

- **M1: Recovery Key & Strength Modules**
  - Implement Crockford base32 encoder/decoder with 24-bit SHA-256 checksum and typo correction.
  - Implement zxcvbn-ts wrapper (0–4 scoring, userInputs binding).
  - Web Worker Argon2id wrapper (`worker-client.ts`).
  - Unit tests in `apps/web` / `packages/crypto`.

- **M2: Vault Setup Wizard & API**
  - `/api/vault/setup` route with schema validation and KDF bounds check.
  - Setup wizard UI: master password + strength indicator + recovery key display & confirmation before POST.
  - Verification: setting up a fresh vault works end-to-end.

- **M3: Unlock, Lock, and Auto-Lock Sync**
  - `/api/vault/config` route (GET) with rate limiting.
  - Unlock modal: Web Worker derivation + SubtleCrypto tag verification.
  - `VaultSync` with `BroadcastChannel("cipher-vault")` and sleep-safe timestamp checks.
  - Teardown on lock: clearing state, wiping cache, dropping keys.

- **M4: Password Change & Recovery Flows**
  - `/api/vault/change-password` with compare-and-swap and re-auth.
  - `/api/vault/recover` with compare-and-swap, atomic dual-wrap replacement, and new recovery key issuance.
  - `/api/vault/regenerate-recovery` for settings.

- **M5: Playwright Integration & E2E Tests**
  - Setup flow: correct validation, recovery key confirmation, vault initialized.
  - Unlock flow: correct password unlocks, wrong password rejected by GCM tag check.
  - Cross-tab lock: locking Tab A locks Tab B.
  - Recovery flow: recovery key unlocks, issues new key, old key fails.
  - Change password: new password works, old password fails.

---

## 6. Testing Strategy

### Unit Tests
- `recovery-key.test.ts`:
  - 32-byte entropy + 3-byte checksum generates exactly 56 Crockford base32 characters.
  - Typo detection: single-character and transposed character mutations fail checksum.
  - Case and dash insensitivity; `O`→`0`, `I`/`L`→`1` corrections.
- `kdf-worker.test.ts`:
  - Web Worker derivation produces deterministic KEK matching known Argon2id test vector.
  - Transferred ArrayBuffer detaches from worker scope.
- `password-strength.test.ts`:
  - Scores 0 through 4 correctly identified.
  - UserInputs (email, name) properly penalize passwords containing personal details.

### Playwright E2E Tests (`apps/web/e2e/vault-lifecycle.spec.ts`)
1. **Fresh user setup:**
   - Navigates to `/vault`, prompted with setup wizard.
   - Weak password rejected (< 3/4).
   - Recovery key shown; setup blocked until last 4 characters confirmed.
   - Redirects to unlocked vault.
2. **Lock & Unlock:**
   - Clicking "Lock" drops session; vault locked UI displayed.
   - Entering incorrect password shows error toast ("Incorrect master password").
   - Entering correct password unlocks vault.
3. **Auto-lock & Cross-Tab:**
   - Opening Tab 1 and Tab 2; locking in Tab 1 immediately locks Tab 2.
4. **Change password:**
   - User changes password; signs out/locks; new password unlocks; old password rejected.
5. **Recovery:**
   - User initiates recovery using recovery key.
   - Enters new password; receives new recovery key; completes flow.
   - Previous recovery key fails; new password unlocks vault.

---

## 7. Confirmation Checklist

- [x] Server never verifies passwords or decrypts data (GCM tag check is the sole proof of key possession).
- [x] Entry CRUD and Password Generator deferred to Phase 4.
- [x] Recovery key shown and confirmed **before** calling `/api/vault/setup` or `/api/vault/recover`.
- [x] Optimistic concurrency (`expectedUpdatedAt`) and fresh re-auth protect wrap-updating routes.
- [x] "View existing recovery key" removed; regeneration allowed only when unlocked.
- [x] zxcvbn score corrected to 0–4 scale with minimum 3.
- [x] Salt generated by client at setup time.
- [x] Cross-tab auto-lock uses sleep-safe timestamp checks.
