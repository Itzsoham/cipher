# Phase 4 Plan: Vault Entries & Password Generator

> [!IMPORTANT]
> **Prerequisites.** Phase 4 depends on Phase 3 being fully approved *and* implemented in its corrected form (server never verifies passwords or decrypts anything; recovery key shown and confirmed before committing wraps). Do not begin Phase 4 implementation until the revised Phase 3 is committed and its full test suite is green.

## 1. Overview & Zero-Knowledge Architecture

Phase 4 builds the core functional capabilities of the Cipher vault:

1. **Entry Creation, Editing, and Deletion** for `password` and `secure_note` entry types.
2. **Strict Zero-Knowledge Data Handling**:
   - The server **never** sees plaintext titles, URLs, usernames, passwords, or notes.
   - All entry details live inside `encryptedData` (AES-256-GCM with zero-padded bucket padding, per CRYPTO.md §7).
   - The database stores: `id` (UUID), `userId`, `type` (`password` | `secure_note`), `encryptedData` (bytes), `iv` (12 bytes), `cryptoVersion`, `vaultKeyVersion`, `entryVersion`, `createdAt`, and `updatedAt`.
   - AES-GCM Associated Data (AAD) is exactly `["cipher-entry", cryptoVersion, entryId, userId, type, vaultKeyVersion]` — matching `entryAad()` in `@cipher/crypto`.
   - On wire (API), `encryptedData` is transmitted as base64 (avoiding hex bloat and staying well within Vercel's ~4.5 MB serverless limit).
3. **In-Memory Decrypted Store**:
   - Decrypted entries reside only in client React memory while the vault is unlocked.
   - When the vault locks (manually, via inactivity timer, or cross-tab sync), all references are dropped, the component tree is unmounted, and the decrypted store is discarded. Decrypted data never enters `localStorage`, the URL, React Query's persisted cache, or logs. See SECURITY.md for JavaScript memory guarantees.
4. **Fast In-Memory Search**:
   - Client-side search matching against decrypted `title`, `username`, `url`, and `notes`. Hidden custom fields and the `text` field of secure notes are excluded from the search index.
5. **Cryptographically Secure Password Generator**:
   - Built on `crypto.getRandomValues()` with rejection sampling (no modulo bias).
   - Configurable: length (8–64), uppercase, lowercase, digits, symbols, avoid ambiguous characters (`0/O/o`, `1/l/I`).
   - Passphrase mode: EFF short wordlist, minimum 6 words (~60 bits of entropy). Wordlist bundled locally — no CDN.
6. **Auto-Clearing Clipboard**:
   - 30-second countdown with visual indicator (configurable for test runs). Warns the user that it will overwrite the clipboard. Skips the clear and displays clear warnings if the tab is unfocused, permissions are blocked, or the content has changed.

---

## 2. Cryptographic Specs & Data Contract

### 2.1 Entry Payloads

The payload shapes, serialised as JSON before padding:

```ts
// packages/crypto/src/entries.ts — already defines these
export interface PasswordEntryPayload {
  title: string
  username?: string
  password?: string
  url?: string          // validated: http: or https: only
  notes?: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}

export interface SecureNoteEntryPayload {
  title: string
  text: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}

export type EntryPlaintext = PasswordEntryPayload | SecureNoteEntryPayload
```

> **No reimplementation.** The agent calls `encryptEntry` and `decryptEntry` from `@cipher/crypto`. No crypto logic goes in `apps/web`.

### 2.2 Padding & Encryption (already in `@cipher/crypto`)

Per CRYPTO.md §7:

```
Plaintext JSON
   │ UTF-8 encode
   ▼
4-byte big-endian uint32 length prefix + plaintext bytes + zero-fill to next 256-byte bucket (min 512 bytes)
   │ pad()
   ▼
AES-256-GCM Encrypt with session VK
   - 12-byte random IV (fresh on every save, including edits)
   - AAD: UTF-8(JSON.stringify(["cipher-entry", cryptoVersion, entryId, userId, type, vaultKeyVersion]))
         ↑ exactly entryAad() from @cipher/crypto/aad.ts
   │
   ▼
Server stores: { id, type, encryptedData, iv, cryptoVersion, vaultKeyVersion, entryVersion }
```

Decryption reverses: re-derive AAD from stored plaintext fields → decrypt → unpad → parse JSON.

### 2.3 URL Safety

Before saving and before rendering any clickable URL:
- Strip leading/trailing whitespace.
- Parse with `new URL(...)` and allow only `http:` and `https:` schemes.
- Any other scheme (`javascript:`, `data:`, `ftp:`, etc.) is rejected at the form level and the link is never rendered as an `<a href>`.

### 2.4 Server-Side Validation (M14)

Every mutation route enforces Zod constraints:

| Field | Constraint |
|---|---|
| `id` | UUID v4 |
| `type` | `"password"` or `"secure_note"` |
| `encryptedData` | base64 string representing ≤ 64 KiB of bytes |
| `iv` | hex string of exactly 24 characters (12 bytes) |
| `cryptoVersion` | positive integer |
| `vaultKeyVersion` | positive integer |
| `entryVersion` (PUT/DELETE) | positive integer — compare-and-swap guard |
| Quota | Maximum 5,000 entries per user, total ciphertext ≤ 20 MiB per user (enforced on POST and PUT) |
| Bulk delete `ids` | Array, max 100 ids per request, all must be owned by the caller |

---

## 3. Schema Change

Add `entryVersion Int @default(1)` to the `VaultEntry` model in [`packages/db/prisma/schema.prisma`](file:///d:/Development/cipher/packages/db/prisma/schema.prisma).

"Hand-edit" means two things:
1. **Edit the `.prisma` file directly** — add the field to the `VaultEntry` model by hand.
2. **Write a new migration SQL file** — create `packages/db/prisma/migrations/<timestamp>_add_entry_version/migration.sql` containing `ALTER TABLE "VaultEntry" ADD COLUMN "entryVersion" INTEGER NOT NULL DEFAULT 1;` and apply it with `prisma migrate deploy` against the Neon dev branch (`DIRECT_URL`).

> **Do not run `auth generate` or `prisma migrate dev --create-only` on this project.** Schema and migration files are maintained by hand per project rules.

`entryVersion` is the compare-and-swap version for concurrent edit protection. The server increments it atomically inside the single-statement `UPDATE … WHERE entryVersion = ?`. A `PUT` or `DELETE` that sends a stale version gets `409 Conflict`.

---

## 4. Milestone Breakdown

### Milestone 1: Server API Routes (`apps/web/src/app/api/vault/entries/`)

Five routes, all session-authenticated via `requireSession()`. No plaintext in, no plaintext out.

| Route | Behaviour |
|---|---|
| `GET /api/vault/entries` | Returns the full ciphertext list: `Array<{ id, type, cryptoVersion, vaultKeyVersion, entryVersion, encryptedData, iv, createdAt, updatedAt }>`. `encryptedData` is serialized as base64 to prevent JSON payload bloat (~33% overhead vs 100% with hex, keeping well below Vercel's serverless limits). |
| `POST /api/vault/entries` | Zod-validates payload. Runs in `prisma.$transaction`: checks entry count < 5,000 and total ciphertext ≤ 20 MiB, then inserts `VaultEntry` with `entryVersion: 1`. Returns `{ id, entryVersion, createdAt }`. |
| `PUT /api/vault/entries/[id]` | Zod-validates. Checks `userId` ownership. Re-checks the 20 MiB per-user total ciphertext quota with size delta; returns `413` if exceeded. Compare-and-swap in a single atomic statement: `UPDATE "VaultEntry" SET "encryptedData"=$1, "iv"=$2, "cryptoVersion"=$3, "vaultKeyVersion"=$4, "entryVersion"="entryVersion"+1, "updatedAt"=NOW() WHERE "id"=$5 AND "userId"=$6 AND "entryVersion"=$7`. If zero rows updated, returns `409 Conflict`. Returns `{ entryVersion, updatedAt }`. |
| `DELETE /api/vault/entries/[id]` | Client always sends `?v=<entryVersion>`. Deletes entry atomically: `DELETE FROM "VaultEntry" WHERE "id"=$1 AND "userId"=$2 AND "entryVersion"=$3`. Returns 404 if not found/not owned, 409 if version is stale. |
| `DELETE /api/vault/entries` | Body: `{ ids: string[], v?: Record<string, number> }` (max 100 ids). `v` is a map of `id → entryVersion`; entries in the map are deleted only if the stored version matches. Returns `{ deleted: number, stale: string[] }`. |

Rate limits on all mutation routes (POST/PUT/DELETE): 60 requests/minute per user, backed by database counter (using Prisma `RateLimit` table).

### Milestone 2: Client Vault Store & Services (`apps/web/src/lib/vault/`)

**`entry-store.ts`**
- Fetches ciphertext list from `GET /api/vault/entries` on unlock.
- Calls `decryptEntry(encrypted, vk, { entryId, userId, type, cryptoVersion, vaultKeyVersion })` from `@cipher/crypto` for each entry.
- Entries that fail to decrypt are kept as `{ id, type, error: "decrypt-failed" }` — they are displayed as a "Could not decrypt" row, not silently hidden (possible tampering indicator).
- Maintains an in-memory array of decrypted entries. Never touches React Query persistent storage, `localStorage`, the URL, or logs.
- On `LOCK`: drop all decrypted entries, drop all references, trigger vault UI unmount.
- Optimistic updates for create/edit/delete with rollback on API error.
- Tracks `entryVersion` per entry for compare-and-swap PUT and DELETE calls.

**`password-generator.ts`**
- Uses `crypto.getRandomValues()` with uniform rejection sampling to eliminate modulo bias.
- Character mode: configurable charset (lower, upper, digits, symbols, ambiguous-filter).
- Passphrase mode: EFF short wordlist (bundled in `src/lib/vault/wordlist.ts`), minimum 6 words. Words joined by `-` or space (user preference).
- No CDN dependency.

**`clipboard.ts`**
- Writes to `navigator.clipboard.writeText`.
- Arms a countdown timer (default 30 seconds; configurable duration for testing).
- Displays a persistent warning toast: "Clipboard will be cleared in N seconds — this will overwrite whatever you copy next."
- On expiry, checks document focus and clipboard content:
  1. Document not focused → skip clear; show **"Clipboard not cleared — tab was not focused"** and dismiss.
  2. Document focused, `readText()` succeeds and value still matches → clear with `writeText("")` and dismiss.
  3. Document focused, `readText()` succeeds but value differs → skip clear; show **"Clipboard not cleared — you copied something else"** and dismiss.
  4. Document focused, `readText()` throws (permission denied or API unavailable) → skip clear; show **"Clipboard not cleared — permission denied"** and dismiss.
- Never silently skips. The user always gets explicit feedback about whether the clear happened.

### Milestone 3: Entry UI Components (`apps/web/src/components/vault/entries/`)

**`entry-list.tsx`**
- Responsive master-detail (side-by-side on desktop, slide-in on mobile).
- Filter tabs: All, Passwords, Secure Notes.
- Search input: instant client-side match against decrypted `title`, `username`, `url`, `notes` (and `text` for secure notes). Hidden custom fields are never indexed.
- Empty state with a "New Entry" call to action.
- "Could not decrypt" rows shown with a warning icon — not hidden.

**`entry-detail.tsx`**
- Displays the selected decrypted entry.
- Password field: hidden by default, reveal toggle, auto-re-hides after 10 seconds.
- Notes and hidden custom fields: `spellCheck={false} autoComplete="off"`.
- URL: rendered as a link **only after** scheme validation (`http:` / `https:`). Opens `target="_blank" rel="noopener noreferrer"`.
- One-click copy with clipboard auto-clear countdown.
- Edit and Delete action buttons.

**`entry-dialog.tsx`**
- Modal for creating / editing entries (type selected at creation, immutable after).
- Password inputs: `spellCheck={false} autoComplete="new-password"`.
- URL field: validated for `http:`/`https:` scheme before form submission.
- Integrated "Generate" button that opens `PasswordGeneratorDialog` and fills the password field.
- Form validation with `react-hook-form` + `zod`. Client-side URL scheme check is the gating validator.

**`password-generator-dialog.tsx`**
- Standalone generator popup with character-set toggles, length slider (8–64), passphrase mode toggle (≥6 words), strength bar (zxcvbn-ts score 0–4), regenerate button, and copy action.

> All inputs that handle sensitive data use `spellCheck={false}`. Password and hidden-field inputs also use `autoComplete="new-password"` or `autoComplete="off"`. This prevents browser spell-check from sending data to vendor servers.

### Milestone 4: Integration with Main Vault View

- Update `apps/web/src/app/(app)/vault/vault-view.tsx`:
  - When `status === "unlocked"`, render `<EntryDashboard>` containing search, entry list, detail pane, generator, and "New Entry" button.
  - On `LOCK`, unmount `<EntryDashboard>` entirely — this drops all decrypted state from React's tree.

### Milestone 5: Playwright Integration Tests (`apps/web/e2e/vault-entries.spec.ts`)

All tests set up the vault in `beforeEach` (unlock with test credentials) and delete test entries in `afterEach`.

| Test | What it verifies |
|---|---|
| **Wire check** | Intercept `POST /api/vault/entries`; assert the request body contains `encryptedData` and `iv`, and no plaintext `title`, `password`, or `notes`. |
| **Add Password Entry** | Create entry, verify it appears decrypted in the list. |
| **Add Secure Note** | Create note, verify `text` field visible in detail. |
| **URL scheme guard** | Attempt to save a `javascript:` URL; assert form error, no server request. |
| **In-Memory Search** | Type a query; verify filtering. Clear query; verify all entries return. |
| **Copy & Auto-Clear** | Click copy, assert clipboard value (via `page.evaluate`), wait countdown, assert clipboard cleared. |
| **Edit Entry** | Update title; assert `entryVersion` incremented in server response. |
| **Stale version 409** | Simulate two concurrent edits; assert second PUT gets 409. |
| **Delete Entry** | Delete one entry; assert removed from list via `GET /api/vault/entries`. |
| **Bulk Delete** | Select and delete 3 entries in one request; assert all removed from list. |
| **Decrypt failure row** | Tamper one ciphertext in DB; assert "Could not decrypt" row is shown, other entries render normally. |
| **Lock clears entries** | Lock vault; assert no entry titles or passwords remain in the DOM. |

---

## 5. Security & Acceptance Criteria

The following must all pass before Phase 4 is considered complete:

- [ ] Plaintext never transmitted to or received from server — only `encryptedData` and `iv` on the wire.
- [ ] AAD exactly matches `entryAad()` output: `["cipher-entry", cryptoVersion, entryId, userId, type, vaultKeyVersion]`.
- [ ] Zero-fill padding (not random) matches CRYPTO.md §7 — `pad()` from `@cipher/crypto` is called, not reimplemented.
- [ ] URL scheme validated as `http:` or `https:` at save and at render.
- [ ] Compare-and-swap `entryVersion` is a single atomic `UPDATE … WHERE entryVersion = ?` — no read-then-write.
- [ ] Client always sends `entryVersion` on delete; stale single DELETE (with `?v=`) returns `409`; stale bulk DELETE ids are skipped and returned in `stale[]`.
- [ ] PUT re-checks the 20 MiB per-user total after accounting for the size delta; returns `413` if exceeded.
- [ ] `cryptoVersion` and `vaultKeyVersion` stored and returned by server on POST and PUT.
- [ ] Per-user total ciphertext ≤ 20 MiB enforced server-side on both POST and PUT.
- [ ] Per-user entry count ≤ 5,000 enforced on POST in transaction.
- [ ] Bulk delete capped at 100 ids; all checked for ownership.
- [ ] Rate limits (60 req/min per user, database-backed via Prisma `RateLimit`) enforced on all POST, PUT, and DELETE routes.
- [ ] Decrypt failures shown as visible "Could not decrypt" rows — not hidden, not crashing the list.
- [ ] Search does not index hidden custom fields.
- [ ] `spellCheck={false}` and `autoComplete="new-password"` / `autoComplete="off"` on all sensitive inputs.
- [ ] Clipboard clear always gives explicit feedback: cleared, "not cleared — copied something else", "not cleared — permission denied", or "not cleared — tab was not focused". Never silently skips.
- [ ] Revealed passwords auto-re-hide after 10 seconds.
- [ ] EFF short wordlist bundled locally; passphrase mode uses ≥ 6 words.
- [ ] Decrypted entries never enter `localStorage`, URL params, React Query persistent cache, or logs.
- [ ] Lock unmounts the vault entry tree and drops all decrypted data references.
- [ ] Phase 3 revised implementation committed and all tests green before Phase 4 implementation starts.

---

## 6. Known Gaps (document in SECURITY.md)

The following limitations are accepted for Phase 4 and must be noted in `SECURITY.md`:

- **Replay of old ciphertexts.** The server could replay an older valid ciphertext for an entry. The AAD binds `entryId`, `userId`, `type`, and `vaultKeyVersion` but not the entry's `entryVersion`. A future improvement would include `entryVersion` in the AAD, making replay detectable. For now, per-entry `updatedAt` timestamps give a heuristic signal.
- **Server hiding entries.** The server can omit entries from `GET /api/vault/entries`. The client has no way to detect this without a signed manifest. Documented as a metadata-level trust assumption.
- **JavaScript memory.** Plaintext strings may linger in the GC heap after references are dropped. The vault UI unmounts and drops references; JavaScript cannot guarantee zeroing. See SECURITY.md.
