# Phase 5 Plan: Zero-Knowledge File Attachments & Object Storage

> [!IMPORTANT]
> **Prerequisites.** Phase 5 depends on Phase 4 being fully approved, implemented, and verified.
> The database schema already contains the necessary columns on `VaultEntry`: `r2Key`, `blobIv`, and `blobSize`.
> Work proceeds milestone by milestone with strict adherence to zero-knowledge guarantees: the server and storage provider **never** see plaintext file contents, file names, or MIME types.

---

## 1. Overview & Architectural Goals

Phase 5 introduces zero-knowledge encrypted file storage (documents, images, scans, keys) up to **25 MB** per file.

1. **Client-Side Blob Encryption**:
   - Files are encrypted in the browser using the session Vault Key (`vk`) before any bytes leave the device.
   - Encryption uses single-shot **AES-256-GCM** with a fresh 12-byte random IV (`blobIv`) per upload.
   - The ciphertext has an authentication tag (128 bits / 16 bytes) appended.
   - **Associated Data (AAD)**: Deterministically binds `["cipher-file-blob", cryptoVersion, entryId, userId, r2Key, vaultKeyVersion]`. Swapping file blobs between entries or accounts causes decryption to fail.

2. **Zero-Knowledge Metadata Encryption**:
   - File metadata (`fileName`, `mimeType`, `fileSize`, `notes`, `customFields`) is JSON-serialized, zero-padded to 256-byte buckets (min 512 bytes), and encrypted using `@cipher/crypto`'s `encryptEntry` under `vk` with `type: "file"`.
   - Neither the Next.js server nor Cloudflare R2 can see the plaintext file name or MIME type.
   - Cloudflare R2 object `ContentType` is always `application/octet-stream`.

3. **Direct-to-Storage Presigned Uploads & Downloads**:
   - Blob uploads and downloads bypass the Next.js server completely: the browser uploads directly to Cloudflare R2 via presigned `PUT` and downloads directly from R2 via presigned `GET`.
   - Avoids Vercel serverless request body limits (~4.5 MB) and server memory spikes.
   - Upload URLs enforce strict `ContentLength` in the S3 signature and expire in 5 minutes (300 seconds).

4. **Server Validation & Security Checks (M13 & M14)**:
   - S3 object key format is strictly `u/<userId>/<uuid>` — completely decoupled from original file names.
   - On entry commit (`POST /api/vault/entries` or `PUT /api/vault/entries/[id]`), the server executes an S3 `HeadObject` check to verify that the object exists in R2, belongs to `u/<userId>/`, and matches the declared `blobSize`.
   - Total file quota check per user (e.g., 250 MiB total file storage limit) enforced on presign request.
   - On entry deletion, the server removes the corresponding R2 object via `DeleteObject`.

5. **Self-Contained Local Storage Driver for Testing & CI**:
   - Like `MAIL_TRANSPORT="file"`, a `STORAGE_DRIVER="r2" | "local"` setting ensures local development and GitHub Actions CI run without external Cloudflare credentials.
   - The local driver implements the exact same presigned HTTP `PUT` and `GET` protocol against a local endpoint (`/api/vault/files/local-storage/...`).

6. **Automated Orphan Cleanup (M13)**:
   - A daily Vercel Cron route (`/api/cron/cleanup-orphaned-files`) protected by `CRON_SECRET` scans objects in R2 older than 24 hours without a matching `VaultEntry.r2Key` in the database and purges them.

---

## 2. Cryptographic Specifications

### 2.1 File Entry Metadata (`FileEntryPayload`)

The entry metadata encrypted inside `encryptedData` using `encryptEntry()` from `@cipher/crypto`:

```ts
export interface FileEntryPayload {
  fileName: string
  mimeType: string
  fileSize: number // original plaintext file size in bytes
  notes?: string
  customFields?: Array<{ name: string; value: string; type: "text" | "hidden" }>
}
```

- **Padding**: Prefixed with 4-byte big-endian length, zero-filled to next 256-byte bucket, minimum 512 bytes.
- **Entry AAD**: `["cipher-entry", cryptoVersion, entryId, userId, "file", vaultKeyVersion]` (reusing `entryAad()` in `@cipher/crypto`).

### 2.2 File Blob Encryption & AAD

To prevent ciphertext substitution attacks, the file blob itself is authenticated with its own AAD.

```ts
// packages/crypto/src/aad.ts
export interface FileBlobAadFields {
  entryId: string
  userId: string
  r2Key: string
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
// packages/crypto/src/files.ts
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

  return {
    encryptedBlob: new Uint8Array(ciphertext),
    blobIv,
  }
}

export async function decryptFileBlob(
  encryptedBlob: ArrayBuffer | Uint8Array,
  blobIv: Uint8Array,
  vk: CryptoKey,
  fields: FileBlobAadFields
): Promise<Uint8Array> {
  const aad = ab(fileBlobAad(fields))

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ab(blobIv), additionalData: aad, tagLength: 128 },
    vk,
    ab(encryptedBlob)
  )

  return new Uint8Array(plaintext)
}
```

- **Size limit**: Single-shot WebCrypto `encrypt`/`decrypt` is limited to **25 MB** (26,214,400 bytes).
- **Blob Ciphertext Size**: Exactly `originalFileSize + 16` bytes (due to the 16-byte AES-GCM tag).

---

## 3. Storage Architecture: Cloudflare R2 & Local Driver

### 3.1 Environment Variables

Added to `.env.example`:

```bash
# Storage (Phase 5)
STORAGE_DRIVER=r2                     # "r2" in production, "local" in dev/test/CI
R2_ACCOUNT_ID=                        # Cloudflare Account ID
R2_ACCESS_KEY_ID=                     # S3 API Token Key ID
R2_SECRET_ACCESS_KEY=                 # S3 API Token Secret Key
R2_BUCKET_NAME=                       # Bucket name (e.g. cipher-vault-files)
R2_PUBLIC_ENDPOINT=                   # https://<account_id>.r2.cloudflarestorage.com
CRON_SECRET=                          # Secret token for Vercel Cron orphan cleanup
```

### 3.2 S3 Client Abstraction (`apps/web/src/lib/storage/index.ts`)

```ts
export interface StorageDriver {
  getPresignedUploadUrl(params: {
    key: string
    contentLength: number
    contentType?: string
    expiresInSeconds?: number
  }): Promise<{ uploadUrl: string }>

  getPresignedDownloadUrl(params: {
    key: string
    expiresInSeconds?: number
  }): Promise<{ downloadUrl: string }>

  headObject(key: string): Promise<{ contentLength: number; exists: boolean }>

  deleteObject(key: string): Promise<void>

  deleteObjects(keys: string[]): Promise<void>

  listObjects(prefix: string): Promise<Array<{ key: string; lastModified: Date }>>
}
```

- **R2Driver**: Uses `@aws-sdk/client-s3` and `@aws-sdk/s3-request-presigner` pointed to `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`.
- **LocalDriver**: Enabled if `STORAGE_DRIVER === "local"` or if R2 variables are not set. Writes files to `.storage/` in the project root and provides local API endpoints that stream uploads and downloads with identical HTTP semantics.

### 3.3 R2 CORS Configuration

Must be configured on the Cloudflare R2 bucket:

```json
[
  {
    "AllowedOrigins": [
      "http://localhost:3000",
      "http://localhost:3100",
      "https://cipher.example.com"
    ],
    "AllowedMethods": ["GET", "PUT", "HEAD"],
    "AllowedHeaders": ["Content-Type", "Content-Length"],
    "MaxAgeSeconds": 3600
  }
]
```

### 3.4 Content Security Policy (`apps/web/src/proxy.ts`)

Update `connect-src` to permit the R2 endpoint:
- In production: `'self' https://*.r2.cloudflarestorage.com`
- In development/test: `'self' http://localhost:3100`

---

## 4. API Endpoints

### 4.1 Presigned Upload Route: `POST /api/vault/files/presign-upload`

- **Auth**: Requires valid session via `requireSession()`.
- **Rate Limit**: 60 requests/minute.
- **Request Body (Zod)**:
  ```ts
  z.object({
    entryId: z.string().uuid(),
    blobSize: z.number().int().min(17).max(25 * 1024 * 1024 + 16), // <= 25 MB + 16 tag bytes
  })
  ```
- **Validation**:
  1. Checks user's active file storage quota (e.g. max 250 MiB sum of `blobSize`). If exceeded, returns `413 (Quota Exceeded)`.
  2. Generates `r2Key`: `u/${session.user.id}/${crypto.randomUUID()}`.
  3. Obtains presigned upload URL with `ContentLength: blobSize` and `ContentType: "application/octet-stream"`.
- **Response**:
  ```json
  {
    "uploadUrl": "https://...",
    "r2Key": "u/user_123/550e8400-e29b-41d4-a716-446655440000"
  }
  ```

### 4.2 Presigned Download Route: `GET /api/vault/files/[id]/presign-download`

- **Auth**: Requires valid session.
- **Validation**:
  1. Finds `VaultEntry` where `id = params.id` and `userId = session.user.id`.
  2. Confirms `type === "file"` and `r2Key` is non-null.
  3. Obtains presigned download URL for `r2Key` (expires in 300s).
- **Response**:
  ```json
  {
    "downloadUrl": "https://..."
  }
  ```

### 4.3 Vault Entry Integration: `POST` and `PUT /api/vault/entries`

- When saving a `file` entry:
  - Client sends `type: "file"`, `r2Key`, `blobIv` (hex, 12 bytes), `blobSize` (number).
  - Server verifies:
    1. `r2Key` begins with `u/${session.user.id}/`.
    2. Server executes `storage.headObject(r2Key)`. Confirms object exists and actual size matches `blobSize`.
    3. Re-checks user file storage quota.
  - On update (`PUT`), if `r2Key` changed (new file uploaded), the old R2 object is queued or immediately deleted via `storage.deleteObject(oldR2Key)`.
  - On single `DELETE` or bulk `DELETE`, all associated R2 objects are deleted via `storage.deleteObjects(keys)`.

### 4.4 Daily Orphan Cleanup: `GET /api/cron/cleanup-orphaned-files`

- **Auth**: Bearer token matching `CRON_SECRET`.
- **Logic**:
  1. Lists all objects in storage under `u/`.
  2. Queries DB for all active `r2Key`s.
  3. Identifies objects in R2 older than 24 hours that do not exist in the database.
  4. Deletes orphaned objects in batches.
- **Response**: `{ cleaned: number }`.

---

## 5. Client Services & UI Components

### 5.1 Decryption & Download Flow

To prevent out-of-memory errors on low-spec devices, decrypted file blobs are **never stored permanently in React state**:
1. In the entry list, only decrypted metadata (`fileName`, `fileSize`, `mimeType`) is held in the in-memory entry store.
2. When the user clicks **"Download File"**:
   - Client requests presigned download URL from `/api/vault/files/[id]/presign-download`.
   - Browser fetches encrypted blob from R2 as `ArrayBuffer`.
   - Client decrypts blob in WebCrypto using `sessionVK`, `blobIv`, and `fileBlobAad`.
   - Creates a temporary object URL (`URL.createObjectURL(new Blob([decryptedBytes], { type: mimeType }))`).
   - Triggers anchor download with `download={fileName}`.
   - Cleans up object URL immediately after click via `URL.revokeObjectURL()`.

### 5.2 Decrypted Safe Preview Flow

For safe document formats (PNG, JPEG, WebP, SVG, text, markdown, PDF):
- Client offers an optional **"Preview"** action in `<EntryDetail>`.
- Client decrypts blob into a Blob URL and renders in an isolated `<iframe sandbox="allow-same-origin">` or `<img>`.
- No HTML or SVG script execution allowed.
- When the preview modal closes, or when the vault locks, the object URL is explicitly revoked.

### 5.3 UI Component Upgrades

1. **`<EntryList>`**:
   - Adds **"Files"** tab alongside "All", "Logins", and "Notes".
   - Shows file badge, formatted size (`formatBytes`), and file icon based on MIME type.
2. **`<EntryDialog>`**:
   - Supports selecting type **"File"**.
   - Drag-and-drop file upload zone.
   - Immediate client-side validation: rejects files $> 25\text{ MB}$.
   - Shows progress bar during:
     1. Local AES-GCM blob encryption.
     2. Direct R2 presigned PUT upload.
     3. Entry metadata save.
3. **`<EntryDetail>`**:
   - Displays file card with file name, formatted size, type, and upload date.
   - Download button with loading spinner.
   - Preview button for supported media types.
   - Replace File button (with atomic old-file cleanup).
4. **Lock Cleanup**:
   - On vault lock, all active preview blob URLs are revoked and garbage-collected.

---

## 6. Milestones & Implementation Order

### Milestone 1: Crypto Package Extension
- Add `AAD_LABEL_FILE_BLOB = "cipher-file-blob"` to `packages/crypto/src/constants.ts`.
- Add `fileBlobAad` to `packages/crypto/src/aad.ts`.
- Add `encryptFileBlob` and `decryptFileBlob` to `packages/crypto/src/files.ts`.
- Add unit tests in `packages/crypto/test/files.test.ts` (round trip, tampering, wrong AAD, wrong IV).

### Milestone 2: Storage Infrastructure & Backend Routes
- Install `@aws-sdk/client-s3` and `@aws-sdk/s3-request-presigner` in `apps/web`.
- Implement `apps/web/src/lib/storage/index.ts` with `R2Driver` and `LocalDriver`.
- Create `/api/vault/files/presign-upload` and `/api/vault/files/[id]/presign-download`.
- Update `/api/vault/entries` POST, PUT, DELETE with `headObject` verification and R2 object cleanup.
- Add `/api/cron/cleanup-orphaned-files` with `CRON_SECRET` protection.
- Update CSP `connect-src` in `apps/web/src/proxy.ts`.

### Milestone 3: Client File Operations & Store
- Implement `apps/web/src/lib/vault/file-client.ts`:
  - Upload orchestration (presign $\to$ encrypt blob $\to$ direct PUT $\to$ save entry).
  - Download orchestration (presign $\to$ fetch blob $\to$ decrypt blob $\to$ download).
- Extend `EntryProvider` and `useEntries` to handle file entries and "Files" filter tab.

### Milestone 4: UI Components
- Update `<EntryList>` with "Files" tab and file icon representations.
- Update `<EntryDialog>` with 25 MB file drag-and-drop zone and multi-step progress bar.
- Update `<EntryDetail>` with file metadata card, secure download action, and sandboxed preview modal.

### Milestone 5: Verification & E2E Testing
- Vitest unit tests for file crypto, storage driver, and size validation.
- Playwright E2E suite (`apps/web/e2e/vault-files.spec.ts`):
  - File upload with direct PUT.
  - Wire check: verify that plaintext file name and contents NEVER appear in server requests.
  - File download and decrypted byte-for-byte identity check.
  - 25 MB limit rejection test.
  - Deletion and storage cleanup check.
  - Vault lock drops preview URLs and decrypted memory.
- Monorepo validation: `pnpm turbo build test lint typecheck`.

---

## 7. Security Checklist & Acceptance Criteria

- [ ] **Zero-knowledge**: File content is encrypted with AES-256-GCM in the browser before leaving the client.
- [ ] **Metadata confidentiality**: File name and MIME type live only in zero-padded `encryptedData`; R2 stores only `application/octet-stream`.
- [ ] **Cryptographic binding**: File blob AAD binds `["cipher-file-blob", cryptoVersion, entryId, userId, r2Key, vaultKeyVersion]`.
- [ ] **Size limits**: Hard 25 MB limit enforced in the browser and in presigned PUT `ContentLength`.
- [ ] **Server verification**: `HeadObject` confirms object existence and exact byte length before DB commit.
- [ ] **Ownership isolation**: `r2Key` strictly prefixed with `u/${userId}/`; server rejects any key not starting with session user ID.
- [ ] **Deletion hygiene**: Deleting a vault entry immediately deletes the corresponding object in storage.
- [ ] **Orphan cleanup**: Daily cron purges abandoned uploads older than 24 hours.
- [ ] **Local/CI compatibility**: Self-contained test driver allows complete test execution without real Cloudflare credentials.
- [ ] **Memory safety**: Decrypted file blobs are not kept in long-lived state; temporary Blob URLs are revoked immediately.
