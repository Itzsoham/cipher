# Phase 5 Plan: Zero-Knowledge File Attachments & Object Storage

> [!IMPORTANT]
> **Status: Pending approval.** Do not begin implementation until this document is approved.
> **Prerequisites:** Phase 4 committed, all 10 Playwright tests green, full turbo pipeline passing.

---

## 0. Phase 4 Coverage Audit

The reviewer noted that Phase 4's plan listed 12 E2E scenarios but only 1 Playwright test was reported as passing. This table maps every Phase 4 acceptance criterion to its actual test coverage.

### E2E Coverage Table

| Planned scenario (PHASE-4.md §4 M5) | Covered in `vault-entries.spec.ts` | Notes |
|---|---|---|
| Wire check (no plaintext on POST) | ✅ Lines 54–92 | Playwright route intercept; asserts `encryptedData`, `iv`, no title/username/password/notes |
| Add Password Entry | ✅ Lines 74–97 | Creates entry, verifies decrypted heading in DOM |
| Add Secure Note | ✅ Lines 99–107 | Creates note, verifies heading |
| URL scheme guard (`javascript:`) | ✅ Lines 63–72 | Validation error shown, no POST fired |
| In-Memory Search | ✅ Lines 109–121 | Filter by "GitHub", then "Recovery", then clear |
| Copy & Auto-Clear clipboard | ❌ **Not implemented** | Test omitted; clipboard API unreliable in headless Chromium |
| Edit Entry (CAS PUT) | ✅ Lines 132–139 | Updates title, verifies success toast |
| Stale version 409 | ❌ **Not implemented** | Two-tab concurrency test omitted |
| Delete Entry | ✅ Lines 141–148 | Deletes note, asserts removed from list |
| Bulk Delete | ❌ **Not implemented** | No bulk-select test scenario |
| Decrypt failure row | ❌ **Not implemented** | Requires DB tamper via test helper |
| Lock clears entries | ✅ Lines 150–154 | Locks vault, asserts DOM cleared |

**4 of 12 scenarios were not implemented in the E2E spec.** The unit test suite (`vitest`) covers the crypto primitives and generator logic, but the following gaps remain in integration coverage:

- **Clipboard auto-clear**: Untested at E2E level. Clipboard `readText()` requires a permission grant that headless Chromium does not support in the default test profile. Acceptance: add a Playwright test using `browserContext.grantPermissions(['clipboard-read'])` and fake timers via `page.clock.install()`.
- **Stale 409**: Untested. Acceptance: use direct `fetch()` inside `page.evaluate()` to send a PUT with a stale `entryVersion` and assert the 409 response.
- **Bulk delete**: Untested. Acceptance: create 3 entries, select all via bulk-select UI, delete, assert list empty.
- **Decrypt failure row**: Untested. Acceptance: use a test DB helper to corrupt one entry's `encryptedData`, then assert the "Could not decrypt" row renders without crashing the list.

These four scenarios must be added as part of Phase 5's M5 milestone before Phase 5 is considered complete.

### Rate Limiter Scope Confirmation

The `checkRateLimit()` function in [`apps/web/src/lib/rate-limit.ts`](file:///d:/Development/cipher/apps/web/src/lib/rate-limit.ts) is a **custom database-backed sliding counter** using the Prisma `RateLimit` table. It is NOT Better Auth's built-in limiter (which only covers Better Auth's own auth routes).

It is called explicitly on `POST /api/vault/entries` (line 87), and must be verified that it is also called on `PUT /api/vault/entries/[id]` and `DELETE /api/vault/entries/[id]`. ✅ Confirmed in `[id]/route.ts` — both `PUT` and `DELETE` call `checkRateLimit({ key: \`entry-mutation:${session.user.id}\` })`.

The 60 req/min limit applies to all three mutation routes via the shared `entry-mutation:<userId>` key. This is confirmed.

---

## 1. Overview & Architectural Goals

Phase 5 introduces zero-knowledge encrypted file storage (documents, images, scans, keys) up to **25 MB** per file.

1. **Client-Side Blob Encryption**: Files are encrypted in the browser with AES-256-GCM using the session Vault Key before any bytes leave the device. The server and storage provider never see plaintext file content, file name, or MIME type.
2. **Metadata in Encrypted Entry**: File name, MIME type, and file size live only inside the zero-padded `encryptedData` JSON. Cloudflare R2 stores only `application/octet-stream`.
3. **Direct-to-R2 via Presigned URLs**: Browser uploads (PUT) and downloads (GET) go directly to R2, bypassing the Next.js server. This avoids Vercel's ~4.5 MB serverless response limit and server memory spikes.
4. **Server Verification on Commit**: Before saving a `file` entry to the database, the server runs `HeadObject` to confirm the blob exists in R2, belongs to `u/<userId>/`, and the size matches the declared `blobSize`.
5. **Safe Delete Order**: DB row is removed first; R2 object is deleted after. A failed R2 delete is cleaned up by the daily cron. (See §4.4.)
6. **Self-Contained Local Driver for Dev & CI**: `STORAGE_DRIVER=local` enables a local HTTP server that mimics presigned PUT/GET with signature and expiry checks. Production (`STORAGE_DRIVER=r2`) throws at startup if R2 credentials are missing.

> [!CAUTION]
> **Phase 5 is the riskiest surface in v1.** It introduces storage credentials, presigned URL generation, and in-browser preview rendering. Phases 3 and 4 already give you a working zero-knowledge vault for passwords and notes. The reviewer recommends running the vault on dummy data, building the encrypted export (post-v1) first, and deciding whether Phase 5 earns its place before proceeding. Cryptomator already covers files for most use cases.

---

## 2. Cryptographic Specifications

### 2.1 File Entry Metadata (`FileEntryPayload`)

Encrypted inside `encryptedData` using `encryptEntry()` from `@cipher/crypto` with `type: "file"`:

```ts
// packages/crypto/src/entries.ts — add to existing file
export interface FileEntryPayload {
  fileName: string   // original file name; stripped of path separators on download
  mimeType: string   // stored for reference; NOT trusted for preview rendering
  fileSize: number   // original plaintext byte count (before encryption)
  notes?: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}
```

- **Padding**: 4-byte big-endian length prefix, zero-filled to next 256-byte bucket, minimum 512 bytes (same `pad()` from `@cipher/crypto`).
- **Entry AAD**: `["cipher-entry", cryptoVersion, entryId, userId, "file", vaultKeyVersion]` — reuses `entryAad()`.

### 2.2 File Blob Encryption & AAD

The blob has its own AAD separate from the metadata entry, binding `entryId`, `userId`, `r2Key`, and `vaultKeyVersion`.

```ts
// packages/crypto/src/aad.ts — add alongside entryAad()
export interface FileBlobAadFields {
  entryId: string
  userId: string
  r2Key: string       // "u/<userId>/<uuid>" — bound to prevent blob swapping
  vaultKeyVersion: number
}

export function fileBlobAad(fields: FileBlobAadFields): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      "cipher-file-blob",
      CRYPTO_VERSION,
      fields.entryId,
      fields.userId,
      fields.r2Key,
      fields.vaultKeyVersion,
    ])
  )
}
```

```ts
// packages/crypto/src/files.ts — new file
export async function encryptFileBlob(
  fileBytes: ArrayBuffer | Uint8Array,
  vk: CryptoKey,
  fields: FileBlobAadFields
): Promise<{ encryptedBlob: Uint8Array; blobIv: Uint8Array }> {
  const blobIv = randomBytes(AES_GCM_IV_BYTES) // 12 bytes
  const aad = ab(fileBlobAad(fields))

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: blobIv, additionalData: aad, tagLength: 128 },
    vk,
    ab(fileBytes)
  )

  return { encryptedBlob: new Uint8Array(ciphertext), blobIv }
}

export async function decryptFileBlob(
  encryptedBlob: ArrayBuffer | Uint8Array,
  blobIv: Uint8Array,
  vk: CryptoKey,
  fields: FileBlobAadFields,
  expectedPlaintextSize: number  // from FileEntryPayload.fileSize — verify after decrypt
): Promise<Uint8Array> {
  const aad = ab(fileBlobAad(fields))

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ab(blobIv), additionalData: aad, tagLength: 128 },
    vk,
    ab(encryptedBlob)
  )

  const result = new Uint8Array(plaintext)

  // Post-decrypt size verification
  if (result.byteLength !== expectedPlaintextSize) {
    throw new RangeError(
      `decryptFileBlob: decrypted size ${result.byteLength} ≠ declared fileSize ${expectedPlaintextSize}`
    )
  }

  return result
}
```

- **Ciphertext size**: `fileSize + 16` bytes (16-byte AES-GCM tag). This is what `blobSize` stores in the DB.
- **Single-shot limit**: 25 MB plaintext (26,214,400 bytes). Larger files require chunked streaming; out of scope for v1.
- **Memory note**: A 25 MB file requires approximately three in-memory copies during decryption (encrypted fetch buffer, decrypted plaintext, Blob). This is ~75 MB peak. Fine on desktop; tight on low-end phones. Documented in `SECURITY.md`.

### 2.3 Known Gap (inheriting from Phase 4 §6)

`entryVersion` is not included in either the entry AAD or the blob AAD. The server can replay an older valid ciphertext or an older blob for the same entry. A future improvement adds `entryVersion` to both AAD arrays. Documented in `SECURITY.md`.

---

## 3. Storage Architecture

### 3.1 Environment Variables

```bash
# Storage (Phase 5) — add to .env.example
STORAGE_DRIVER=r2                     # "r2" | "local". Production: must be "r2".
R2_ACCOUNT_ID=                        # Cloudflare Account ID
R2_ACCESS_KEY_ID=                     # R2 S3 API Token Key ID
R2_SECRET_ACCESS_KEY=                 # R2 S3 API Token Secret Key
R2_BUCKET_NAME=                       # e.g. cipher-vault-files
R2_ENDPOINT=                          # https://<account_id>.r2.cloudflarestorage.com (exact host — not wildcard)
CRON_SECRET=                          # Compared in constant time; protects /api/cron/cleanup-orphaned-files
```

> [!CAUTION]
> **Production fail-fast.** If `STORAGE_DRIVER` is `"r2"` and any of `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`, or `R2_ENDPOINT` are missing, the storage module throws at module load time (import-time validation via a startup check). This prevents the local driver silently activating in production and writing to ephemeral Vercel disk.
>
> **Never** enable the local driver via "if R2 vars are missing" — that's the bug the reviewer flagged.

### 3.2 Storage Driver Interface

```ts
// apps/web/src/lib/storage/index.ts

export interface StorageDriver {
  getPresignedUploadUrl(params: {
    key: string
    contentLength: number   // signed into the URL — test that exceeding it is rejected
    expiresInSeconds: number
  }): Promise<{ uploadUrl: string }>

  getPresignedDownloadUrl(params: {
    key: string
    expiresInSeconds: number
  }): Promise<{ downloadUrl: string }>

  headObject(key: string): Promise<{ contentLength: number; exists: boolean }>

  deleteObject(key: string): Promise<void>

  // Batched: up to 1,000 per call (S3 limit)
  deleteObjects(keys: string[]): Promise<{ deleted: string[]; failed: string[] }>

  // Lists with pagination; yields all keys under prefix across all pages
  listAllObjects(prefix: string): AsyncIterable<{ key: string; lastModified: Date }>
}

// Loaded once at module scope; throws at startup if misconfigured in production
export declare const storage: StorageDriver
```

**R2Driver**: Uses `@aws-sdk/client-s3` and `@aws-sdk/s3-request-presigner` with `forcePathStyle: false`. Points to `R2_ENDPOINT` (exact host).

**LocalDriver**: Only allowed when `STORAGE_DRIVER=local`. Writes to `.storage/<key>` in the project root. Exposes local API endpoint `/api/vault/files/local/[...key]` that verifies:
- HMAC-SHA256 signature over `key + expiry + contentLength` (using `LOCAL_STORAGE_SECRET` env var).
- Request timestamp is within the signed expiry window (rejects expired URLs).
- The key does not contain `..`, `~`, or absolute path components (path-traversal protection).
- PUT body `Content-Length` matches the signed value (returns 400 if different).

### 3.3 Presigned `ContentLength` Verification

The AWS SDK's `PutObjectCommand` presigner **does not sign `content-length` by default**. This means a client could upload more bytes than declared.

The backstop is the `HeadObject` check on DB commit — if the actual object is larger than `blobSize`, the entry is rejected. But we also need a test that proves the backstop catches this:

```ts
// apps/web/test/storage-overflow.test.ts (Vitest, runs against local driver)
// 1. Presign a PUT for 100 bytes
// 2. Upload 200 bytes
// 3. Attempt to commit the entry with blobSize: 100
// 4. Assert: server returns 422 (HeadObject size mismatch)
```

Document in §6 of this plan: "ContentLength is not signed by R2's presigned PUT. The HeadObject check on commit is the enforcement point."

### 3.4 Cloudflare R2 CORS Configuration

Set on the R2 bucket (via Cloudflare dashboard or Wrangler):

```json
[
  {
    "AllowedOrigins": ["https://your-exact-production-domain.com", "http://localhost:3000"],
    "AllowedMethods": ["GET", "PUT", "HEAD"],
    "AllowedHeaders": ["Content-Type", "Content-Length"],
    "MaxAgeSeconds": 3600
  }
]
```

**Not** `*.r2.cloudflarestorage.com`. The exact origin, pinned.

### 3.5 CSP Update (`apps/web/src/proxy.ts`)

```
connect-src 'self' https://<account_id>.r2.cloudflarestorage.com
img-src     'self' data: blob:
frame-src   blob:
```

- `connect-src`: Exact R2 endpoint host — not wildcard.
- `img-src blob:`: Required for decrypted image previews rendered via `<img src={blobUrl}>`.
- `frame-src blob:`: Required for PDF preview iframe (if enabled; currently out of scope).
- No `allow-same-origin` sandbox on preview frames.

---

## 4. API Endpoints

### 4.1 `POST /api/vault/files/presign-upload`

**Rate limit**: 10 requests/minute per user (separate key `file-presign:<userId>` — not the 60/min entry-mutation bucket). This caps orphan upload abuse at ~10 × 25 MB = 250 MB/min, which is bounded by the per-user quota check.

```ts
// Request body (Zod)
z.object({
  entryId: z.string().uuid(),
  blobSize: z.number().int().min(17).max(25 * 1024 * 1024 + 16),
  // min(17): 1 byte plaintext + 16 tag bytes. Zero-byte files get a clear error at form validation.
})
```

**Server logic**:
1. Validate session (`requireSession()`).
2. Rate check: 10/min per user (`file-presign:<userId>`).
3. Quota check: sum of `blobSize` for all `file` entries owned by user + this `blobSize` ≤ 250 MiB. Returns `413` if exceeded.
4. Pending bytes check: count presign requests in the last 5 minutes that do not yet have a matching DB entry; if total pending bytes would exceed 250 MiB, reject. (Prevents presign abuse before commit.)
5. Generate `r2Key = "u/${session.user.id}/${crypto.randomUUID()}"`.
6. Call `storage.getPresignedUploadUrl({ key: r2Key, contentLength: blobSize, expiresInSeconds: 300 })`.
7. Return `{ uploadUrl, r2Key }`.

**Response**: `{ uploadUrl: string, r2Key: string }`.

### 4.2 `GET /api/vault/files/[id]/presign-download`

```ts
// Server logic
1. requireSession()
2. findUnique VaultEntry where id = params.id AND userId = session.user.id AND type = "file"
3. Assert r2Key is non-null
4. Call storage.getPresignedDownloadUrl({ key: r2Key, expiresInSeconds: 300 })
5. Return { downloadUrl }
```

**Presigned download URL is single-use from the client's perspective**: the browser fetches the blob, decrypts, and saves. The URL expires in 5 minutes.

### 4.3 Entry Routes: `POST` and `PUT /api/vault/entries`

Extend Zod schemas to include `file` type with required/forbidden fields:

```ts
// Zod discriminated union by type
const fileEntryFields = z.object({
  type: z.literal("file"),
  r2Key: z.string().regex(/^u\/[^/]+\/[0-9a-f-]{36}$/),  // "u/<userId>/<uuid>"
  blobIv: z.string().length(24).regex(/^[0-9a-fA-F]+$/), // 12 bytes = 24 hex chars
  blobSize: z.number().int().min(17).max(25 * 1024 * 1024 + 16),
})

const passwordOrNoteFields = z.object({
  type: z.enum(["password", "secure_note"]),
  r2Key: z.undefined(),
  blobIv: z.undefined(),
  blobSize: z.undefined(),
})

const createEntrySchema = z.discriminatedUnion("type", [
  baseEntryFields.merge(fileEntryFields),
  baseEntryFields.merge(passwordOrNoteFields),
])
```

**Additional server checks for `file` entries on POST and PUT**:
1. Verify `r2Key` starts with `u/${session.user.id}/` (ownership prefix check).
2. Call `storage.headObject(r2Key)`. If `!exists`, return `422 (object not found in storage)`.
3. If `headObject.contentLength !== blobSize`, return `422 (declared size mismatch)`.
4. Re-check file storage quota (sum of `blobSize` across user's `file` entries ≤ 250 MiB).
5. On **PUT with a new `r2Key`** (file replacement): after the DB CAS succeeds, enqueue the old `r2Key` for deletion. If the DB CAS fails (409), do not delete anything.

**Safe deletion order** (critical — fixes the "delete order loses data" bug from the review):

```
// POST: (1) browser encrypts → (2) browser PUTs to R2 → (3) browser POSTs entry to DB
// PUT replace: (1) browser encrypts new blob → (2) browser PUTs to R2 →
//              (3) server runs CAS UPDATE (old r2Key → new r2Key) →
//              (4) only after successful CAS: server DELETEs old R2 object
// DELETE entry: (1) DELETE DB row → (2) DELETE R2 object
//              If R2 delete fails, the daily cron cleans it up.
```

### 4.4 `DELETE /api/vault/entries/[id]` (file entries)

1. Read the entry to get `r2Key` (if `type === "file"`).
2. Delete the DB row atomically (CAS with `entryVersion`).
3. Only if DB delete succeeded: call `storage.deleteObject(r2Key)`.
4. If R2 delete fails: log a warning; the cron will clean it up. Do NOT fail the response — the row is already gone.

### 4.5 `GET /api/cron/cleanup-orphaned-files`

- **Auth**: `Authorization: Bearer <CRON_SECRET>` compared with `timingSafeEqual()` (constant-time).
- **Logic**:
  1. Paginate `storage.listAllObjects("u/")` (handles 1,000-key pages via `AsyncIterable`).
  2. Collect all R2 keys.
  3. Query DB for all active `r2Key` values: `prisma.vaultEntry.findMany({ select: { r2Key: true }, where: { r2Key: { not: null } } })`.
  4. Find keys in R2 that are NOT in the DB AND `lastModified` is older than 24 hours.
  5. Delete orphans in batches of up to 1,000 (S3 batched delete limit) via `storage.deleteObjects()`.
  6. Return `{ cleaned: number }`.
- **Cron schedule** (Vercel `vercel.json`): `"0 3 * * *"` (03:00 UTC daily).

---

## 5. Client File Operations

### 5.1 Upload Orchestration (`apps/web/src/lib/vault/file-client.ts`)

```
1. Validate file size <= 25 MB (show clear error if 0 bytes or > 25 MB)
2. Read file as ArrayBuffer
3. POST /api/vault/files/presign-upload { entryId, blobSize: file.size + 16 }
4. encryptFileBlob(fileBytes, vk, { entryId, userId, r2Key, vaultKeyVersion })
5. PUT uploadUrl with body=encryptedBlob, Content-Type: application/octet-stream
6. POST /api/vault/entries with entry payload + { r2Key, blobIv: hex(blobIv), blobSize }
```

Progress is reported as three phases via a callback: `"encrypting"` → `"uploading"` → `"saving"`.

### 5.2 Download Orchestration

```
1. GET /api/vault/files/[id]/presign-download → { downloadUrl }
2. fetch(downloadUrl) → ArrayBuffer (encrypted blob)
3. decryptFileBlob(encryptedBlob, blobIv, vk, { entryId, userId, r2Key, vaultKeyVersion }, fileSize)
   → verifies decrypted.byteLength === fileSize
4. Strip path separators and control chars from fileName:
   safeFileName = fileName.replace(/[\\/\x00-\x1f]/g, "_").slice(0, 255)
5. new Blob([decryptedBytes], { type: "application/octet-stream" })  // always octet-stream
6. anchor.href = URL.createObjectURL(blob); anchor.download = safeFileName; anchor.click()
7. setTimeout(() => URL.revokeObjectURL(anchor.href), 60_000)  // 60s delay, not immediate
```

> [!NOTE]
> The Blob type is always `application/octet-stream` on download — regardless of the `mimeType` stored in the encrypted metadata. This prevents MIME-sniffing issues and forces the browser to save rather than render.

> [!NOTE]
> Revoke the object URL after 60 seconds, not immediately after `.click()`. Revoking immediately can cancel the download in Chrome before the transfer completes.

### 5.3 Preview (Strict Allowlist, No SVG/PDF)

Preview is allowed only for a strict allowlist of safe types. The rendered MIME type is forced from this allowlist — **not** from the stored `mimeType` metadata.

```ts
const PREVIEW_ALLOWLIST: Record<string, { forcedMime: string; renderer: "img" | "text" }> = {
  "image/png":  { forcedMime: "image/png",  renderer: "img" },
  "image/jpeg": { forcedMime: "image/jpeg", renderer: "img" },
  "image/webp": { forcedMime: "image/webp", renderer: "img" },
  "text/plain": { forcedMime: "text/plain", renderer: "text" },
}
// SVG: skipped in v1 (can execute scripts in same origin)
// PDF: skipped in v1 (Chrome ignores sandbox in blob: iframes for PDFs)
// text/html, text/markdown: not in allowlist; download only
```

**Image preview**: Decrypt blob → `new Blob([bytes], { type: forcedMime })` → `<img src={URL.createObjectURL(blob)} alt={safeFileName}>` inside the detail modal. Revoke URL when modal closes or vault locks.

**Text preview**: Decrypt blob → `new TextDecoder().decode(bytes)` → render inside `<pre className="max-h-96 overflow-auto whitespace-pre-wrap">`. No HTML rendering. No iframe.

**No `<iframe sandbox="allow-same-origin">`** anywhere — this was the XSS vector. The vault session key lives in this origin. Any rendered iframe with same-origin access can read it.

### 5.4 Memory Safety

During download/preview, the in-memory lifecycle is:
1. `ArrayBuffer` (encrypted, from fetch).
2. `Uint8Array` (decrypted, from WebCrypto).
3. `Blob` (for the object URL).

Step 1 and 2 together are ~50 MB peak for a 25 MB file. Step 3 is another copy in the Blob store. Total: ~75 MB peak. Neither the encrypted nor decrypted buffer is stored in React state or the entry store. Both are local to the download function and are eligible for GC once dereferenced. Documented in `SECURITY.md`.

### 5.5 Lock Cleanup

When the vault locks:
- All active preview Blob URLs are explicitly revoked via `URL.revokeObjectURL()`.
- The file entry store is cleared along with the rest of the entry store.
- The `<EntryDashboard>` component tree is unmounted.

---

## 6. UI Components

### 6.1 `<EntryList>` — "Files" Tab

Add a fourth tab alongside "All", "Logins", "Notes". Displays file name (from decrypted metadata), formatted size (`formatBytes`), and a file-type icon keyed on the extension. Never displays the raw stored `mimeType`.

### 6.2 `<EntryDialog>` — File Upload

- Drag-and-drop zone + file picker button.
- Client-side validation before any network call:
  - Zero-byte files: show "File must not be empty".
  - Files > 25 MB: show "Files must be 25 MB or smaller. Use the encrypted export for larger files."
- Three-phase progress bar: "Encrypting…" → "Uploading…" → "Saving…"
- Cancel button aborts the `fetch()` via `AbortController`.

### 6.3 `<EntryDetail>` — File Actions

- **File card**: shows `safeFileName`, `formatBytes(fileSize)`, type icon, upload date.
- **Download button**: triggers §5.2 flow with loading spinner. Disabled while decryption/download is in progress.
- **Preview button**: only shown for MIME types in `PREVIEW_ALLOWLIST`. Uses §5.3 flow.
- **Replace File button**: opens file picker; runs upload flow; on success, triggers a PUT (CAS) with new `r2Key`, `blobIv`, `blobSize`. Old R2 object deleted only after CAS succeeds.

---

## 7. Milestones & Implementation Order

### M1: Crypto Package Extension
- Add `AAD_LABEL_FILE_BLOB = "cipher-file-blob"` to `packages/crypto/src/constants.ts`.
- Add `fileBlobAad()` and `FileBlobAadFields` to `packages/crypto/src/aad.ts`.
- Add `FileEntryPayload` to `packages/crypto/src/entries.ts`.
- Create `packages/crypto/src/files.ts` with `encryptFileBlob` and `decryptFileBlob`.
- Unit tests in `packages/crypto/test/files.test.ts`:
  - Round trip (encrypt then decrypt equals original).
  - Tampered ciphertext throws `DOMException`.
  - Wrong `blobIv` throws.
  - Wrong `r2Key` in AAD throws.
  - Wrong `entryId` in AAD throws.
  - Declared `fileSize` mismatch after decrypt throws `RangeError`.

### M2: Storage Infrastructure & Backend Routes
- Install `@aws-sdk/client-s3` and `@aws-sdk/s3-request-presigner` in `apps/web`.
- Implement `apps/web/src/lib/storage/index.ts` with `R2Driver`, `LocalDriver`, startup fail-fast.
- Create `POST /api/vault/files/presign-upload` (10/min rate limit, quota check, pending-bytes check).
- Create `GET /api/vault/files/[id]/presign-download`.
- Update `/api/vault/entries` POST and PUT Zod schemas to discriminated union with file fields.
- Add `HeadObject` verification + safe delete order in entry routes.
- Create `GET /api/cron/cleanup-orphaned-files` with constant-time `CRON_SECRET` comparison, paginated list, batched delete.
- Update CSP `connect-src`, `img-src`, `frame-src` in `apps/web/src/proxy.ts`.

### M3: Client File Services
- Implement `apps/web/src/lib/vault/file-client.ts` (upload and download orchestration).
- Extend `EntryProvider` and `useEntries` to hold decrypted `FileEntryPayload` metadata.
- Add "Files" filter tab to store.

### M4: UI Components
- Add "Files" tab to `<EntryList>`.
- Add file drag-and-drop zone with 3-phase progress to `<EntryDialog>`.
- Add file card, download, preview, and replace actions to `<EntryDetail>`.
- Lock cleanup integration.

### M5: Verification & E2E
- **Backfill missing Phase 4 tests** (clipboard auto-clear, stale 409, bulk delete, decrypt failure row).
- Vitest: `storage-overflow.test.ts` proving `HeadObject` catches oversized uploads.
- Playwright (`apps/web/e2e/vault-files.spec.ts`):
  - Upload file (local driver). Wire check: assert no plaintext filename or content in POST body.
  - Download: decrypt bytes match original.
  - 25 MB limit: assert form error, no presign request.
  - Zero-byte file: assert form error.
  - Replace file: assert old key deleted after CAS.
  - Delete entry: assert R2 key deleted.
  - Vault lock: assert all blob URLs revoked, no decrypted data in DOM.
  - Oversized upload: upload more bytes than `blobSize`, assert 422 on commit.
  - Preview allowlist: `text/html` file shows download-only (no preview button).
- Monorepo: `pnpm turbo build test lint typecheck` — 0 errors, 0 warnings.

---

## 8. Security Checklist & Acceptance Criteria

- [ ] **Zero-knowledge blob**: file content encrypted client-side before any network activity.
- [ ] **Zero-knowledge metadata**: `fileName`, `mimeType`, `fileSize` live only in `encryptedData`.
- [ ] **Blob AAD**: binds `["cipher-file-blob", cryptoVersion, entryId, userId, r2Key, vaultKeyVersion]`.
- [ ] **Post-decrypt size check**: `decryptFileBlob` verifies `decrypted.byteLength === fileSize`.
- [ ] **Safe filename on download**: path separators and control characters stripped before `anchor.download`.
- [ ] **Object URL revoke delay**: 60 seconds after `.click()`, not immediate.
- [ ] **25 MB hard cap**: enforced in form validation (`min: 1 byte`, `max: 25 MiB`) and in presign Zod schema.
- [ ] **Zero-byte rejection**: explicit error message, no silent failure.
- [ ] **HeadObject commit check**: POST and PUT verify object existence and size match before writing DB row.
- [ ] **Ownership prefix check**: `r2Key` must start with `u/${session.user.id}/`.
- [ ] **Safe delete order**: DB delete first, R2 delete after. Failed R2 delete is non-fatal; cron cleans up.
- [ ] **No old-blob deletion before CAS**: on replace, old R2 object deleted only after DB CAS succeeds.
- [ ] **Production fail-fast**: missing R2 env vars throw at module load time. Local driver never activates in production.
- [ ] **Local driver security**: HMAC signature, expiry window, path-traversal protection, ContentLength enforcement.
- [ ] **ContentLength not signed by presigner**: HeadObject is the enforcement point. Covered by `storage-overflow.test.ts`.
- [ ] **Presign rate limit**: 10/min per user on `POST /api/vault/files/presign-upload`.
- [ ] **File storage quota**: 250 MiB per user, enforced on presign and on entry commit.
- [ ] **Preview XSS prevention**: MIME type forced from allowlist (not from stored metadata). No SVG, no PDF, no iframe with `allow-same-origin`.
- [ ] **CSP**: exact R2 host in `connect-src`, `img-src blob:`, `frame-src blob:`.
- [ ] **Cron secret**: constant-time comparison with `timingSafeEqual`.
- [ ] **Cron pagination**: handles >1,000 R2 objects via paginated `listAllObjects`.
- [ ] **Cron batched delete**: deletes orphans in batches ≤ 1,000.
- [ ] **File Zod schema**: discriminated union enforces `r2Key`/`blobIv`/`blobSize` required for `"file"`, forbidden for `"password"` and `"secure_note"`. `blobIv` validated as 24 hex chars.
- [ ] **Quota on replace**: subtracts old `blobSize`, adds new `blobSize` in the quota check.
- [ ] **Memory documented**: ~75 MB peak for 25 MB file; no long-lived state in React store.
- [ ] **Phase 4 E2E gaps backfilled**: clipboard auto-clear, stale 409, bulk delete, decrypt failure row.
- [ ] **Phase 4 before Phase 5**: all Phase 4 acceptance criteria including backfilled tests must pass.

---

## 9. Known Gaps (document in SECURITY.md)

- **Blob replay**: The server can serve an older valid ciphertext blob for the same entry. `entryVersion` is not in the blob AAD. Future fix: include `entryVersion` in `fileBlobAad`.
- **Server hiding files**: The server can omit entries from `GET /api/vault/entries`. Client has no signed manifest to detect this.
- **ContentLength not signed by R2**: Presigned PUT `ContentLength` is declared but not cryptographically bound by R2's presigner. `HeadObject` on commit is the enforcement backstop.
- **JavaScript memory**: Decrypted bytes linger in GC until collected. The vault drops all references on lock; it cannot guarantee zeroing.
- **No encrypted export/backup**: R2 and Neon are independent stores. A restored database could reference blobs that no longer exist. Build the encrypted export before storing any real data.
