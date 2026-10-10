# Phase 4 Plan: Vault Entries & Password Generator

## 1. Overview & Zero-Knowledge Architecture

Phase 4 builds the core functional capabilities of the Cipher vault:
1. **Entry Creation, Editing, and Deletion** for `password` and `secure_note` entry types.
2. **Strict Zero-Knowledge Data Handling**:
   - The server **never** sees plaintext titles, URLs, usernames, passwords, or notes.
   - All entry details live inside `encryptedData` (AES-256-GCM with length-prefixed bucket padding).
   - The database only knows: `id` (UUID), `userId`, `type` (`password` | `secure_note`), `encryptedData` (hex/bytes), `iv` (12 bytes), `createdAt`, and `updatedAt`.
   - AES-GCM Associated Data (AAD) binds: `[entryId, userId, type, cryptoVersion, vaultKeyVersion]`, preventing ciphertext swapping or type tampering.
3. **In-Memory Decrypted Store**:
   - Decrypted entries reside only in client React memory while the vault is unlocked.
   - When the vault locks (manually, via inactivity timer, or cross-tab sync), the decrypted store and search index are instantly zeroed and discarded.
4. **Fast In-Memory Search**:
   - Client-side search matching against decrypted `title`, `username`, `url`, and `notes`.
5. **Cryptographically Secure Password Generator**:
   - Built on `crypto.getRandomValues()` with rejection sampling (no modulo bias).
   - Configurable options: length (8–64), uppercase, lowercase, numbers, symbols, avoid ambiguous characters (`0/O`, `1/l/I`), and passphrase mode (Diceware word list).
6. **Auto-Clearing Clipboard**:
   - 30-second countdown with visual indicator, clearing sensitive values if the window is still focused.

---

## 2. Cryptographic Specs & Data Schema

### 2.1 Entry Payloads (`packages/crypto/src/entries.ts`)
The payload shapes serialized as JSON before padding:

```ts
export interface PasswordEntryPayload {
  title: string
  username?: string
  password?: string
  url?: string
  notes?: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}

export interface SecureNoteEntryPayload {
  title: string
  text: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}
```

### 2.2 Padding & Encryption Workflow
```
Plaintext JSON 
   │
   ▼
UTF-8 Bytes
   │
   ▼
pad(bytes) ──> Header: 4-byte big-endian uint32 byteLength
              Body: plaintext bytes
              Tail: random padding to next 256-byte bucket (min 512 bytes)
   │
   ▼
AES-256-GCM Encrypt with session VK
   - 12-byte random IV
   - AAD: JSON.stringify([entryId, userId, type, cryptoVersion, vaultKeyVersion])
   │
   ▼
Upload to Server: { id, type, encryptedDataHex, ivHex }
```

### 2.3 Server-Side Validation (M14)
Every mutation route (`POST`, `PUT`, `DELETE`) enforces Zod constraints:
- `id`: valid UUID v4
- `type`: enum `["password", "secure_note"]`
- `encryptedData`: hex string $\le 128\text{ KiB}$ (representing $\le 64\text{ KiB}$ bytes)
- `iv`: hex string of exactly 24 characters (12 bytes)
- **Quota Cap**: Maximum 5,000 entries per user.

---

## 3. Milestone Breakdown

### Milestone 1: Server API Routes (`apps/web/src/app/api/vault/entries/`)
- `GET /api/vault/entries`:
  - Returns metadata + ciphertext list: `Array<{ id, type, cryptoVersion, vaultKeyVersion, encryptedData, iv, createdAt, updatedAt }>`
- `POST /api/vault/entries`:
  - Validates payload with Zod.
  - Verifies user entry count $< 5,000$.
  - Inserts new `VaultEntry` in Prisma.
- `PUT /api/vault/entries/[id]`:
  - Validates `id` matches `userId`.
  - Updates `encryptedData`, `iv`, and `updatedAt`.
- `DELETE /api/vault/entries/[id]`:
  - Deletes entry owned by `userId`.
- `DELETE /api/vault/entries`:
  - Bulk deletion endpoint supporting multi-item removal: `{ ids: string[] }`.

### Milestone 2: Client Vault Store & Decryption Service (`apps/web/src/lib/vault/`)
- `entry-store.ts`:
  - Decrypts entry payloads upon fetch using the session `CryptoKey`.
  - Maintains decrypted entries in memory.
  - Handles concurrent entry updates / optimistic UI.
  - Clears all state on `LOCK`.
- `password-generator.ts`:
  - Uses `crypto.getRandomValues()` with uniform rejection sampling to eliminate modulo bias.
  - Generates random strings (charset: lower, upper, digits, symbols, ambiguous filter).
  - Diceware mode: EFF short wordlist passphrase generator.
- `clipboard.ts`:
  - Copies text to clipboard and arms a 30-second cleanup timer with notification.

### Milestone 3: Entry UI Components (`apps/web/src/components/vault/entries/`)
- `entry-list.tsx`:
  - Split view or responsive master-detail.
  - Filter tabs: All, Passwords, Secure Notes.
  - Fast search input with instant matching.
  - Empty state with quick action buttons.
- `entry-detail.tsx`:
  - Displays selected entry.
  - Hidden password field with reveal toggle and one-click copy.
  - URL launcher (`target="_blank" rel="noopener noreferrer"`).
  - Edit and Delete dialogs.
- `entry-dialog.tsx`:
  - Modal form for creating / editing entries.
  - Integrated password generator button.
  - Form validation with react-hook-form and zod.
- `password-generator-dialog.tsx`:
  - Dedicated generator popup / inline popover with strength bar, regenerate button, and copy action.

### Milestone 4: Integration with Main Vault View
- Update `apps/web/src/app/(app)/vault/vault-view.tsx`:
  - When `status === "unlocked"`, render `EntryDashboard` containing search, generator, entry list, and detail views.
  - Floating action button / toolbar button to open the "Add Entry" dialog.

### Milestone 5: Playwright Integration & E2E Tests (`apps/web/e2e/vault-entries.spec.ts`)
- **Add Password Entry**: create entry, verify encryption on wire, verify decrypted appearance in UI.
- **Add Secure Note**: create note, verify formatting and notes view.
- **In-Memory Search**: type query into search box, verify filtering.
- **Copy & Auto-Clear**: click copy, verify clipboard value, trigger cleanup.
- **Edit Entry**: update title and password, verify ciphertext update on server.
- **Delete Entry**: delete entry, verify removal from list and database.
- **Lock Clearing**: lock vault, verify all decrypted entries and search inputs vanish from the DOM.

---

## 4. Security & Compliance Checklist

- [x] Plaintext never transmitted to or received from server (`encryptedData` only).
- [x] AAD includes `entryId`, `userId`, and `type`.
- [x] Length-bucket padding (256-byte intervals, min 512 bytes) prevents plaintext length leakage.
- [x] Session `CryptoKey` remains non-extractable in memory.
- [x] Zod enforces 64 KiB payload ceiling and 5,000 entry quota on server.
- [x] Rejection sampling ensures unbiased password generation.
