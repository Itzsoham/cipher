"use client"

import * as React from "react"
import { copyToClipboard } from "@/lib/vault/clipboard"
import { useEntries } from "@/lib/vault/entry-store"
import {
  type EntryType,
  isDecryptFailed,
} from "@/lib/vault/entry-types"
import { formatBytes } from "@/lib/vault/file-client"
import { Button } from "@cipher/ui/components/button"
import { Input } from "@cipher/ui/components/input"
import {
  AlertTriangle,
  CheckSquare,
  Copy,
  FileText,
  KeyRound,
  Loader2,
  Plus,
  Search,
  Square,
  StickyNote,
  Trash2,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { EntryDialog } from "./entry-dialog"

export function EntryList() {
  const {
    filteredEntries,
    selectedId,
    setSelectedId,
    filterType,
    setFilterType,
    searchQuery,
    setSearchQuery,
    isLoading,
    bulkRemoveEntries,
  } = useEntries()

  const [createDialogOpen, setCreateDialogOpen] = React.useState(false)
  const [isBulkSelecting, setIsBulkSelecting] = React.useState(false)
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set())
  const [isBulkDeleting, setIsBulkDeleting] = React.useState(false)

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleSelectAll = () => {
    if (selectedIds.size === filteredEntries.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(filteredEntries.map((e) => e.id)))
    }
  }

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return
    setIsBulkDeleting(true)
    try {
      await bulkRemoveEntries(Array.from(selectedIds))
      toast.success(`Deleted ${selectedIds.size} entries`)
      setSelectedIds(new Set())
      setIsBulkSelecting(false)
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to delete entries"
      toast.error(msg)
    } finally {
      setIsBulkDeleting(false)
    }
  }

  return (
    <div className="flex h-full flex-col border-r bg-card/50">
      {/* Top Header & Actions */}
      <div className="space-y-3 border-b p-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold">Vault Entries</h2>
            <p className="text-[11px] text-muted-foreground">
              {filteredEntries.length}{" "}
              {filteredEntries.length === 1 ? "entry" : "entries"}
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              className="h-8 text-xs"
              onClick={() => {
                setIsBulkSelecting((prev) => !prev)
                setSelectedIds(new Set())
              }}
            >
              {isBulkSelecting ? "Done" : "Select"}
            </Button>
            <Button
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={() => setCreateDialogOpen(true)}
            >
              <Plus className="size-3.5" />
              New Entry
            </Button>
          </div>
        </div>

        {/* Search Bar */}
        <div className="relative">
          <Search className="absolute top-2.5 left-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search titles, usernames, notes..."
            value={searchQuery}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 bg-background pr-8 pl-8 text-xs"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="absolute top-2.5 right-2.5 text-muted-foreground hover:text-foreground"
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>

        {/* Filter Tabs */}
        <div className="flex rounded-md bg-muted p-0.5 text-xs">
          {(
            [
              { id: "all", label: "All" },
              { id: "password", label: "Passwords" },
              { id: "secure_note", label: "Notes" },
              { id: "file", label: "Files" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`flex-1 rounded py-1 text-center font-medium transition-colors ${
                filterType === tab.id
                  ? "bg-background text-foreground shadow-2xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setFilterType(tab.id as "all" | EntryType)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Bulk Action Bar */}
        {isBulkSelecting && (
          <div className="flex items-center justify-between rounded-md bg-muted/70 p-2 text-xs">
            <button
              type="button"
              onClick={handleSelectAll}
              className="flex items-center gap-1.5 font-medium hover:text-primary"
            >
              {selectedIds.size === filteredEntries.length &&
              filteredEntries.length > 0 ? (
                <CheckSquare className="size-3.5 text-primary" />
              ) : (
                <Square className="size-3.5" />
              )}
              {selectedIds.size === filteredEntries.length
                ? "Deselect All"
                : "Select All"}
            </button>
            <Button
              variant="destructive"
              size="sm"
              className="h-6 gap-1 px-2 text-[11px]"
              disabled={selectedIds.size === 0 || isBulkDeleting}
              onClick={handleBulkDelete}
            >
              {isBulkDeleting ? (
                <Loader2 className="size-3 animate-spin" />
              ) : (
                <Trash2 className="size-3" />
              )}
              Delete ({selectedIds.size})
            </Button>
          </div>
        )}
      </div>

      {/* Entry List Items */}
      <div className="flex-1 divide-y divide-border/50 overflow-y-auto">
        {isLoading ? (
          <div className="flex h-32 items-center justify-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="size-4 animate-spin text-primary" />
            Decrypting vault entries...
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="p-8 text-center text-xs text-muted-foreground">
            {searchQuery
              ? `No entries found matching "${searchQuery}"`
              : 'No entries in this view. Click "New Entry" to get started.'}
          </div>
        ) : (
          filteredEntries.map((entry) => {
            const isSelected = selectedId === entry.id
            const isChecked = selectedIds.has(entry.id)
            const failed = isDecryptFailed(entry)

            let title = "Damaged Entry"
            let subtitle = ""

            if (!failed) {
              if (entry.type === "file") {
                title = entry.data.fileName
                subtitle = formatBytes(entry.data.fileSize)
              } else if (entry.type === "password") {
                title = entry.data.title
                subtitle = entry.data.username || entry.data.url || ""
              } else {
                title = entry.data.title
                subtitle = entry.data.text.slice(0, 40)
              }
            }

            return (
              <div
                key={entry.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelectedId(entry.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault()
                    setSelectedId(entry.id)
                  }
                }}
                className={`group flex cursor-pointer items-center justify-between p-3 text-left transition-colors select-none ${
                  isSelected
                    ? "bg-accent text-accent-foreground"
                    : "hover:bg-muted/50"
                } ${failed ? "border-l-4 border-l-destructive bg-destructive/5" : ""}`}
              >
                <div className="flex min-w-0 items-center gap-3 pr-2">
                  {isBulkSelecting ? (
                    <button
                      type="button"
                      onClick={(e) => toggleSelect(entry.id, e)}
                      className="shrink-0 text-muted-foreground hover:text-foreground"
                    >
                      {isChecked ? (
                        <CheckSquare className="size-4 text-primary" />
                      ) : (
                        <Square className="size-4" />
                      )}
                    </button>
                  ) : (
                    <div
                      className={`flex size-8 shrink-0 items-center justify-center rounded-md ${
                        failed
                          ? "bg-destructive/20 text-destructive"
                          : "bg-muted text-muted-foreground group-hover:text-foreground"
                      }`}
                    >
                      {failed ? (
                        <AlertTriangle className="size-4" />
                      ) : entry.type === "password" ? (
                        <KeyRound className="size-4" />
                      ) : entry.type === "file" ? (
                        <FileText className="size-4" />
                      ) : (
                        <StickyNote className="size-4" />
                      )}
                    </div>
                  )}

                  <div className="min-w-0 flex-1">
                    <p
                      className={`truncate text-sm font-medium ${
                        failed ? "font-semibold text-destructive" : ""
                      }`}
                    >
                      {failed ? "Could Not Decrypt" : title}
                    </p>
                    {subtitle && (
                      <p className="truncate text-xs text-muted-foreground">
                        {subtitle}
                      </p>
                    )}
                  </div>
                </div>

                {!failed &&
                  entry.type === "password" &&
                  entry.data.password && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                      onClick={(e) => {
                        e.stopPropagation()
                        copyToClipboard(entry.data.password!, {
                          label: "Password",
                        })
                      }}
                      title="Quick copy password"
                    >
                      <Copy className="size-3.5" />
                    </Button>
                  )}
              </div>
            )
          })
        )}
      </div>

      <EntryDialog open={createDialogOpen} onOpenChange={setCreateDialogOpen} />
    </div>
  )
}
