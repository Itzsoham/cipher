import { decryptEntry, encryptEntry } from "@cipher/crypto"
import { base64ToBytes, bytesToBase64 } from "./base64"
import type {
  DecryptedVaultEntry,
  EntryType,
  PasswordEntryPayload,
  SecureNoteEntryPayload,
} from "./entry-types"
import { bytesToHex, hexToBytes } from "./hex"

export interface RawServerEntry {
  id: string
  type: EntryType
  cryptoVersion: number
  vaultKeyVersion: number
  entryVersion: number
  encryptedData: string // base64
  iv: string // hex
  createdAt: string
  updatedAt: string
}

/**
 * Fetches encrypted entries from /api/vault/entries and decrypts them in parallel.
 * Failed entries are preserved as { id, type, error: "decrypt-failed" } so they
 * can be displayed as visible warnings to the user (tampering indicator).
 */
export async function fetchAndDecryptEntries(
  vk: CryptoKey,
  userId: string
): Promise<DecryptedVaultEntry[]> {
  const res = await fetch("/api/vault/entries", {
    method: "GET",
    headers: { Accept: "application/json" },
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `Failed to fetch entries: ${res.status}`)
  }

  const rawEntries: RawServerEntry[] = await res.json()

  const decryptedPromises = rawEntries.map(
    async (entry): Promise<DecryptedVaultEntry> => {
      try {
        const encryptedData = base64ToBytes(entry.encryptedData)
        const iv = hexToBytes(entry.iv)

        const plaintext = await decryptEntry(
          { encryptedData, iv },
          vk,
          {
            entryId: entry.id,
            userId,
            type: entry.type,
            vaultKeyVersion: entry.vaultKeyVersion,
          }
        )

        if (entry.type === "password") {
          return {
            id: entry.id,
            type: "password",
            cryptoVersion: entry.cryptoVersion,
            vaultKeyVersion: entry.vaultKeyVersion,
            entryVersion: entry.entryVersion,
            data: plaintext as PasswordEntryPayload,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
          }
        } else {
          return {
            id: entry.id,
            type: "secure_note",
            cryptoVersion: entry.cryptoVersion,
            vaultKeyVersion: entry.vaultKeyVersion,
            entryVersion: entry.entryVersion,
            data: plaintext as SecureNoteEntryPayload,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
          }
        }
      } catch (err) {
        console.warn(`Failed to decrypt entry ${entry.id}:`, err)
        return {
          id: entry.id,
          type: entry.type,
          cryptoVersion: entry.cryptoVersion,
          vaultKeyVersion: entry.vaultKeyVersion,
          entryVersion: entry.entryVersion,
          error: "decrypt-failed",
          createdAt: entry.createdAt,
          updatedAt: entry.updatedAt,
        }
      }
    }
  )

  return await Promise.all(decryptedPromises)
}

export interface CreateEntryParams {
  type: EntryType
  data: PasswordEntryPayload | SecureNoteEntryPayload
  vk: CryptoKey
  userId: string
  vaultKeyVersion?: number
}

/**
 * Encrypts in the browser and uploads a new vault entry.
 */
export async function createVaultEntry(
  params: CreateEntryParams
): Promise<DecryptedVaultEntry> {
  const id = crypto.randomUUID()
  const vaultKeyVersion = params.vaultKeyVersion ?? 1
  const cryptoVersion = 1

  const encrypted = await encryptEntry(params.data, params.vk, {
    entryId: id,
    userId: params.userId,
    type: params.type,
    vaultKeyVersion,
  })

  const res = await fetch("/api/vault/entries", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id,
      type: params.type,
      cryptoVersion,
      vaultKeyVersion,
      encryptedData: bytesToBase64(encrypted.encryptedData),
      iv: bytesToHex(encrypted.iv),
    }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `Failed to create entry: ${res.status}`)
  }

  const serverResult = await res.json()

  if (params.type === "password") {
    return {
      id,
      type: "password",
      cryptoVersion,
      vaultKeyVersion,
      entryVersion: serverResult.entryVersion ?? 1,
      data: params.data as PasswordEntryPayload,
      createdAt: serverResult.createdAt,
      updatedAt: serverResult.createdAt,
    }
  } else {
    return {
      id,
      type: "secure_note",
      cryptoVersion,
      vaultKeyVersion,
      entryVersion: serverResult.entryVersion ?? 1,
      data: params.data as SecureNoteEntryPayload,
      createdAt: serverResult.createdAt,
      updatedAt: serverResult.createdAt,
    }
  }
}

export interface UpdateEntryParams {
  id: string
  type: EntryType
  data: PasswordEntryPayload | SecureNoteEntryPayload
  entryVersion: number
  vk: CryptoKey
  userId: string
  vaultKeyVersion?: number
}

/**
 * Encrypts in the browser and submits an atomic CAS update for an existing entry.
 */
export async function updateVaultEntry(
  params: UpdateEntryParams
): Promise<{ entryVersion: number; updatedAt: string }> {
  const vaultKeyVersion = params.vaultKeyVersion ?? 1
  const cryptoVersion = 1

  const encrypted = await encryptEntry(params.data, params.vk, {
    entryId: params.id,
    userId: params.userId,
    type: params.type,
    vaultKeyVersion,
  })

  const res = await fetch(`/api/vault/entries/${params.id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      cryptoVersion,
      vaultKeyVersion,
      entryVersion: params.entryVersion,
      encryptedData: bytesToBase64(encrypted.encryptedData),
      iv: bytesToHex(encrypted.iv),
    }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    if (res.status === 409) {
      throw new Error("Conflict: This entry was modified in another session. Please refresh.")
    }
    throw new Error(body.error || `Failed to update entry: ${res.status}`)
  }

  return await res.json()
}

/**
 * Atomically deletes a single entry, verifying the version guard.
 */
export async function deleteVaultEntry(
  id: string,
  entryVersion: number
): Promise<void> {
  const res = await fetch(`/api/vault/entries/${id}?v=${entryVersion}`, {
    method: "DELETE",
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    if (res.status === 409) {
      throw new Error("Conflict: This entry was modified in another session.")
    }
    throw new Error(body.error || `Failed to delete entry: ${res.status}`)
  }
}

/**
 * Bulk deletes entries with version checks.
 */
export async function bulkDeleteVaultEntries(
  entries: Array<{ id: string; entryVersion: number }>
): Promise<{ deleted: number; stale: string[] }> {
  const ids = entries.map((e) => e.id)
  const v: Record<string, number> = {}
  for (const entry of entries) {
    v[entry.id] = entry.entryVersion
  }

  const res = await fetch("/api/vault/entries", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids, v }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `Failed to bulk delete entries: ${res.status}`)
  }

  return await res.json()
}

