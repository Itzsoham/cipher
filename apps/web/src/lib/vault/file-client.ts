import {
  encryptFileBlob,
  decryptFileBlob,
  encryptEntry,
} from "@cipher/crypto"
import { bytesToBase64 } from "./base64"
import { bytesToHex, hexToBytes } from "./hex"
import type { DecryptedFileEntry, FileEntryPayload } from "./entry-types"

export type UploadProgressPhase = "encrypting" | "uploading" | "saving"

export interface UploadFileOptions {
  file: File
  notes?: string
  vk: CryptoKey
  userId: string
  vaultKeyVersion?: number
  onProgress?: (phase: UploadProgressPhase) => void
  abortSignal?: AbortSignal
}

export const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024 // 25 MB

/**
 * Strict allowlist for client-side preview rendering.
 * NEVER allow SVG (script execution) or PDF (sandbox bypass / untrusted plugin) in v1.
 */
export const PREVIEW_ALLOWLIST: Record<
  string,
  { forcedMime: string; renderer: "img" | "text" }
> = {
  "image/png": { forcedMime: "image/png", renderer: "img" },
  "image/jpeg": { forcedMime: "image/jpeg", renderer: "img" },
  "image/webp": { forcedMime: "image/webp", renderer: "img" },
  "text/plain": { forcedMime: "text/plain", renderer: "text" },
}

/**
 * Sanitizes file names before downloading to strip path separators and control characters.
 */
export function sanitizeFileName(name: string): string {
  // eslint-disable-next-line no-control-regex
  return name.replace(/[\\/\x00-\x1f]/g, "_").slice(0, 255) || "downloaded-file"
}

/**
 * Formats a byte size into human readable string (KB, MB, GB).
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const k = 1024
  const sizes = ["B", "KB", "MB", "GB"]
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

/**
 * Complete client-side upload orchestration for zero-knowledge file attachments.
 */
export async function uploadVaultFile(
  options: UploadFileOptions
): Promise<DecryptedFileEntry> {
  const { file, notes, vk, userId, onProgress, abortSignal } = options
  const vaultKeyVersion = options.vaultKeyVersion ?? 1
  const cryptoVersion = 1

  if (file.size === 0) {
    throw new Error("File must not be empty.")
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    throw new Error("Files must be 25 MB or smaller. Use the encrypted export for larger files.")
  }

  const entryId = crypto.randomUUID()
  const declaredBlobSize = file.size + 16 // 16 bytes AES-GCM tag

  // Phase 1: Request presigned upload URL
  onProgress?.("uploading")
  const presignRes = await fetch("/api/vault/files/presign-upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      entryId,
      blobSize: declaredBlobSize,
    }),
    signal: abortSignal,
  })

  if (!presignRes.ok) {
    const body = await presignRes.json().catch(() => ({}))
    throw new Error(body.message || body.error || `Presign failed: ${presignRes.status}`)
  }

  const { uploadUrl, r2Key } = (await presignRes.json()) as {
    uploadUrl: string
    r2Key: string
  }

  // Phase 2: Client-side file encryption
  onProgress?.("encrypting")
  const fileBuffer = await file.arrayBuffer()
  const { encryptedBlob, blobIv } = await encryptFileBlob(
    fileBuffer,
    vk,
    {
      entryId,
      userId,
      r2Key,
      vaultKeyVersion,
    }
  )

  // Phase 3: Direct PUT to storage provider
  onProgress?.("uploading")
  const blobBuffer = encryptedBlob.buffer.slice(
    encryptedBlob.byteOffset,
    encryptedBlob.byteOffset + encryptedBlob.byteLength
  ) as ArrayBuffer
  const uploadRes = await fetch(uploadUrl, {
    method: "PUT",
    headers: {
      "Content-Type": "application/octet-stream",
    },
    body: blobBuffer,
    signal: abortSignal,
  })

  if (!uploadRes.ok) {
    throw new Error(`Direct storage upload failed with status ${uploadRes.status}`)
  }

  // Phase 4: Encrypt metadata and commit entry to server DB
  onProgress?.("saving")
  const metadataPayload: FileEntryPayload = {
    fileName: sanitizeFileName(file.name),
    mimeType: file.type || "application/octet-stream",
    fileSize: file.size,
    notes,
  }

  const encryptedMetadata = await encryptEntry(metadataPayload, vk, {
    entryId,
    userId,
    type: "file",
    vaultKeyVersion,
  })

  const saveRes = await fetch("/api/vault/entries", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: entryId,
      type: "file",
      cryptoVersion,
      vaultKeyVersion,
      encryptedData: bytesToBase64(encryptedMetadata.encryptedData),
      iv: bytesToHex(encryptedMetadata.iv),
      r2Key,
      blobIv: bytesToHex(blobIv),
      blobSize: encryptedBlob.byteLength,
    }),
    signal: abortSignal,
  })

  if (!saveRes.ok) {
    const body = await saveRes.json().catch(() => ({}))
    throw new Error(body.error || `Failed to commit file entry: ${saveRes.status}`)
  }

  const saved = await saveRes.json()

  return {
    id: entryId,
    type: "file",
    cryptoVersion,
    vaultKeyVersion,
    entryVersion: saved.entryVersion ?? 1,
    data: metadataPayload,
    r2Key,
    blobIv: bytesToHex(blobIv),
    blobSize: encryptedBlob.byteLength,
    createdAt: saved.createdAt,
    updatedAt: saved.createdAt,
  }
}

/**
 * Downloads, decrypts, and saves the file locally in browser.
 */
export async function downloadVaultFile(
  entry: DecryptedFileEntry,
  vk: CryptoKey,
  userId: string
): Promise<void> {
  if (!entry.r2Key || !entry.blobIv) {
    throw new Error("Missing storage coordinates for this file entry.")
  }

  // 1. Get presigned download URL
  const presignRes = await fetch(`/api/vault/files/${entry.id}/presign-download`)
  if (!presignRes.ok) {
    const body = await presignRes.json().catch(() => ({}))
    throw new Error(body.error || "Failed to retrieve download URL.")
  }

  const { downloadUrl } = await presignRes.json()

  // 2. Fetch encrypted blob from storage
  const blobRes = await fetch(downloadUrl)
  if (!blobRes.ok) {
    throw new Error(`Failed to fetch file blob: ${blobRes.status}`)
  }

  const encryptedBytes = await blobRes.arrayBuffer()

  // 3. Decrypt and verify expected length
  const decryptedBytes = await decryptFileBlob(
    encryptedBytes,
    hexToBytes(entry.blobIv),
    vk,
    {
      entryId: entry.id,
      userId,
      r2Key: entry.r2Key,
      vaultKeyVersion: entry.vaultKeyVersion,
    },
    entry.data.fileSize
  )

  // 4. Trigger download with application/octet-stream and safe filename
  const safeName = sanitizeFileName(entry.data.fileName)
  // Convert Uint8Array to ArrayBuffer for Blob compatibility
  const arrayBuf = decryptedBytes.buffer.slice(
    decryptedBytes.byteOffset,
    decryptedBytes.byteOffset + decryptedBytes.byteLength
  ) as ArrayBuffer
  const blob = new Blob([arrayBuf], { type: "application/octet-stream" })
  const objectUrl = URL.createObjectURL(blob)

  const a = document.createElement("a")
  a.href = objectUrl
  a.download = safeName
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)

  // Retain for 60 seconds before revoking so downloads don't get canceled prematurely in Chrome
  setTimeout(() => {
    URL.revokeObjectURL(objectUrl)
  }, 60_000)
}

/**
 * Decrypts a file blob into a temporary preview object URL or text content.
 * Forces MIME type from strict allowlist; never executes scripts.
 */
export async function previewVaultFile(
  entry: DecryptedFileEntry,
  vk: CryptoKey,
  userId: string
): Promise<{ type: "img" | "text"; content: string; revoke?: () => void }> {
  const allowConfig = PREVIEW_ALLOWLIST[entry.data.mimeType]
  if (!allowConfig) {
    throw new Error(`Preview is not supported for MIME type "${entry.data.mimeType}". Please download to view.`)
  }

  if (!entry.r2Key || !entry.blobIv) {
    throw new Error("Missing storage coordinates for this file entry.")
  }

  const presignRes = await fetch(`/api/vault/files/${entry.id}/presign-download`)
  if (!presignRes.ok) {
    throw new Error("Failed to get presigned download link.")
  }
  const { downloadUrl } = await presignRes.json()

  const blobRes = await fetch(downloadUrl)
  if (!blobRes.ok) throw new Error("Failed to download file blob.")
  const encryptedBytes = await blobRes.arrayBuffer()

  const decryptedBytes = await decryptFileBlob(
    encryptedBytes,
    hexToBytes(entry.blobIv),
    vk,
    {
      entryId: entry.id,
      userId,
      r2Key: entry.r2Key,
      vaultKeyVersion: entry.vaultKeyVersion,
    },
    entry.data.fileSize
  )

  if (allowConfig.renderer === "text") {
    const text = new TextDecoder().decode(decryptedBytes)
    return { type: "text", content: text }
  }

  // Image renderer: force allowlisted MIME type
  const arrayBuf = decryptedBytes.buffer.slice(
    decryptedBytes.byteOffset,
    decryptedBytes.byteOffset + decryptedBytes.byteLength
  ) as ArrayBuffer
  const blob = new Blob([arrayBuf], { type: allowConfig.forcedMime })
  const url = URL.createObjectURL(blob)

  return {
    type: "img",
    content: url,
    revoke: () => URL.revokeObjectURL(url),
  }
}
