import type {
  CustomField,
  PasswordEntryPayload,
  SecureNoteEntryPayload,
  FileEntryPayload,
} from "@cipher/crypto"

export type {
  CustomField,
  PasswordEntryPayload,
  SecureNoteEntryPayload,
  FileEntryPayload,
}

export type EntryType = "password" | "secure_note" | "file"

export interface DecryptedPasswordEntry {
  id: string
  type: "password"
  cryptoVersion: number
  vaultKeyVersion: number
  entryVersion: number
  data: PasswordEntryPayload
  createdAt: string
  updatedAt: string
}

export interface DecryptedSecureNoteEntry {
  id: string
  type: "secure_note"
  cryptoVersion: number
  vaultKeyVersion: number
  entryVersion: number
  data: SecureNoteEntryPayload
  createdAt: string
  updatedAt: string
}

export interface DecryptedFileEntry {
  id: string
  type: "file"
  cryptoVersion: number
  vaultKeyVersion: number
  entryVersion: number
  data: FileEntryPayload
  r2Key?: string
  blobIv?: string
  blobSize?: number
  createdAt: string
  updatedAt: string
}

export interface DecryptFailedEntry {
  id: string
  type: EntryType
  cryptoVersion: number
  vaultKeyVersion: number
  entryVersion: number
  error: "decrypt-failed"
  createdAt: string
  updatedAt: string
}

export type DecryptedVaultEntry =
  | DecryptedPasswordEntry
  | DecryptedSecureNoteEntry
  | DecryptedFileEntry
  | DecryptFailedEntry

export function isDecryptFailed(
  entry: DecryptedVaultEntry
): entry is DecryptFailedEntry {
  return "error" in entry && entry.error === "decrypt-failed"
}

/**
 * Validates that a string is a valid web URL with http: or https: scheme.
 * Prevents javascript: or data: XSS schemes.
 */
export function isValidWebUrl(rawUrl: string | undefined | null): boolean {
  if (!rawUrl || !rawUrl.trim()) return false
  try {
    const parsed = new URL(rawUrl.trim())
    return parsed.protocol === "http:" || parsed.protocol === "https:"
  } catch {
    return false
  }
}

/**
 * Returns trimmed URL if protocol is http: or https:, null otherwise.
 */
export function sanitizeWebUrl(rawUrl: string | undefined | null): string | null {
  if (!rawUrl || !rawUrl.trim()) return null
  const trimmed = rawUrl.trim()
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return trimmed
    }
    return null
  } catch {
    return null
  }
}

