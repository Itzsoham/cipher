"use client"

import * as React from "react"
import {
  bulkDeleteVaultEntries,
  createVaultEntry,
  deleteVaultEntry,
  fetchAndDecryptEntries,
  updateVaultEntry,
} from "./entry-client"
import {
  type DecryptedVaultEntry,
  type EntryType,
  isDecryptFailed,
  type PasswordEntryPayload,
  type SecureNoteEntryPayload,
} from "./entry-types"

interface EntryContextValue {
  entries: DecryptedVaultEntry[]
  filteredEntries: DecryptedVaultEntry[]
  selectedId: string | null
  selectedEntry: DecryptedVaultEntry | null
  vk: CryptoKey | null
  userId: string | null
  filterType: "all" | EntryType
  searchQuery: string
  isLoading: boolean
  error: string | null
  setSelectedId: (id: string | null) => void
  setFilterType: (type: "all" | EntryType) => void
  setSearchQuery: (query: string) => void
  refreshEntries: () => Promise<void>
  addEntry: (
    type: "password" | "secure_note",
    data: PasswordEntryPayload | SecureNoteEntryPayload
  ) => Promise<DecryptedVaultEntry>
  addFileEntry: (entry: DecryptedVaultEntry) => void
  editEntry: (
    id: string,
    type: EntryType,
    data: PasswordEntryPayload | SecureNoteEntryPayload
  ) => Promise<void>
  removeEntry: (id: string) => Promise<void>
  bulkRemoveEntries: (ids: string[]) => Promise<void>
  clearEntries: () => void
}

const EntryContext = React.createContext<EntryContextValue | null>(null)

interface EntryProviderProps {
  vk: CryptoKey | null
  userId: string | null
  children: React.ReactNode
}

export function EntryProvider({ vk, userId, children }: EntryProviderProps) {
  const [entries, setEntries] = React.useState<DecryptedVaultEntry[]>([])
  const [selectedId, setSelectedId] = React.useState<string | null>(null)
  const [filterType, setFilterType] = React.useState<"all" | EntryType>("all")
  const [searchQuery, setSearchQuery] = React.useState<string>("")
  const [isLoading, setIsLoading] = React.useState<boolean>(false)
  const [error, setError] = React.useState<string | null>(null)

  const clearEntries = React.useCallback(() => {
    setEntries([])
    setSelectedId(null)
    setSearchQuery("")
    setError(null)
  }, [])

  const refreshEntries = React.useCallback(async () => {
    if (!vk || !userId) {
      clearEntries()
      return
    }

    setIsLoading(true)
    setError(null)
    try {
      const decrypted = await fetchAndDecryptEntries(vk, userId)
      setEntries(decrypted)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load entries"
      setError(msg)
    } finally {
      setIsLoading(false)
    }
  }, [vk, userId, clearEntries])

  // Automatically fetch when VK and userId are present
  React.useEffect(() => {
    let active = true
    if (vk && userId) {
      fetchAndDecryptEntries(vk, userId)
        .then((decrypted) => {
          if (active) {
            setEntries(decrypted)
            setIsLoading(false)
          }
        })
        .catch((err: unknown) => {
          if (active) {
            setError(err instanceof Error ? err.message : "Failed to load entries")
            setIsLoading(false)
          }
        })
    }
    return () => {
      active = false
    }
  }, [vk, userId])

  const addFileEntry = React.useCallback((entry: DecryptedVaultEntry) => {
    setEntries((prev) => [entry, ...prev])
    setSelectedId(entry.id)
  }, [])

  const addEntry = React.useCallback(
    async (
      type: "password" | "secure_note",
      data: PasswordEntryPayload | SecureNoteEntryPayload
    ): Promise<DecryptedVaultEntry> => {
      if (!vk || !userId) throw new Error("Vault is locked")

      const newEntry = await createVaultEntry({
        type,
        data,
        vk,
        userId,
      })

      setEntries((prev) => [newEntry, ...prev])
      setSelectedId(newEntry.id)
      return newEntry
    },
    [vk, userId]
  )

  const editEntry = React.useCallback(
    async (
      id: string,
      type: EntryType,
      data: PasswordEntryPayload | SecureNoteEntryPayload
    ): Promise<void> => {
      if (!vk || !userId) throw new Error("Vault is locked")

      const current = entries.find((e) => e.id === id)
      if (!current) throw new Error("Entry not found in store")

      const result = await updateVaultEntry({
        id,
        type,
        data,
        entryVersion: current.entryVersion,
        vk,
        userId,
      })

      setEntries((prev) =>
        prev.map((e) => {
          if (e.id !== id) return e
          if (type === "password") {
            return {
              ...e,
              type: "password",
              entryVersion: result.entryVersion,
              updatedAt: result.updatedAt,
              data: data as PasswordEntryPayload,
            }
          } else {
            return {
              ...e,
              type: "secure_note",
              entryVersion: result.entryVersion,
              updatedAt: result.updatedAt,
              data: data as SecureNoteEntryPayload,
            }
          }
        })
      )
    },
    [vk, userId, entries]
  )

  const removeEntry = React.useCallback(
    async (id: string): Promise<void> => {
      const current = entries.find((e) => e.id === id)
      if (!current) return

      await deleteVaultEntry(id, current.entryVersion)

      setEntries((prev) => prev.filter((e) => e.id !== id))
      if (selectedId === id) {
        setSelectedId(null)
      }
    },
    [entries, selectedId]
  )

  const bulkRemoveEntries = React.useCallback(
    async (ids: string[]): Promise<void> => {
      const targets = entries
        .filter((e) => ids.includes(e.id))
        .map((e) => ({ id: e.id, entryVersion: e.entryVersion }))

      if (targets.length === 0) return

      await bulkDeleteVaultEntries(targets)

      setEntries((prev) => prev.filter((e) => !ids.includes(e.id)))
      if (selectedId && ids.includes(selectedId)) {
        setSelectedId(null)
      }
    },
    [entries, selectedId]
  )

  // Filtered & searched entries computation
  const filteredEntries = React.useMemo(() => {
    const q = searchQuery.trim().toLowerCase()

    return entries.filter((entry) => {
      // 1. Filter by tab type
      if (filterType !== "all" && entry.type !== filterType) {
        return false
      }

      // 2. If no search query, include all
      if (!q) return true

      // Failed entries only match on their type or error indicator
      if (isDecryptFailed(entry)) {
        return "could not decrypt".includes(q) || entry.type.includes(q)
      }

      // Password entries: search in title, username, url, notes. Never search custom hidden fields.
      if (entry.type === "password") {
        const d = entry.data
        if (d.title.toLowerCase().includes(q)) return true
        if (d.username && d.username.toLowerCase().includes(q)) return true
        if (d.url && d.url.toLowerCase().includes(q)) return true
        if (d.notes && d.notes.toLowerCase().includes(q)) return true
        // Plaintext custom fields only
        if (
          d.customFields?.some(
            (f) =>
              f.type === "text" &&
              (f.name.toLowerCase().includes(q) || f.value.toLowerCase().includes(q))
          )
        ) {
          return true
        }
        return false
      }

      // Secure Note entries: search in title, text. Never search custom hidden fields.
      if (entry.type === "secure_note") {
        const d = entry.data
        if (d.title.toLowerCase().includes(q)) return true
        if (d.text && d.text.toLowerCase().includes(q)) return true
        if (
          d.customFields?.some(
            (f) =>
              f.type === "text" &&
              (f.name.toLowerCase().includes(q) || f.value.toLowerCase().includes(q))
          )
        ) {
          return true
        }
        return false
      }

      // File entries: search in fileName and notes
      if (entry.type === "file") {
        const d = entry.data
        if (d.fileName.toLowerCase().includes(q)) return true
        if (d.notes && d.notes.toLowerCase().includes(q)) return true
        if (
          d.customFields?.some(
            (f) =>
              f.type === "text" &&
              (f.name.toLowerCase().includes(q) || f.value.toLowerCase().includes(q))
          )
        ) {
          return true
        }
        return false
      }

      return false
    })
  }, [entries, filterType, searchQuery])

  const selectedEntry = React.useMemo(() => {
    if (!selectedId) return null
    return entries.find((e) => e.id === selectedId) ?? null
  }, [entries, selectedId])

  const value: EntryContextValue = {
    entries,
    filteredEntries,
    selectedId,
    selectedEntry,
    vk,
    userId,
    filterType,
    searchQuery,
    isLoading,
    error,
    setSelectedId,
    setFilterType,
    setSearchQuery,
    refreshEntries,
    addEntry,
    addFileEntry,
    editEntry,
    removeEntry,
    bulkRemoveEntries,
    clearEntries,
  }

  return <EntryContext.Provider value={value}>{children}</EntryContext.Provider>
}

export function useEntries(): EntryContextValue {
  const ctx = React.useContext(EntryContext)
  if (!ctx) {
    throw new Error("useEntries must be used within an EntryProvider")
  }
  return ctx
}

