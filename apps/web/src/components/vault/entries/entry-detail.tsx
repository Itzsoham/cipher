"use client"

import * as React from "react"
import { copyToClipboard } from "@/lib/vault/clipboard"
import { useEntries } from "@/lib/vault/entry-store"
import {
  type DecryptedVaultEntry,
  isDecryptFailed,
  sanitizeWebUrl,
} from "@/lib/vault/entry-types"
import { Button } from "@cipher/ui/components/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@cipher/ui/components/dialog"
import {
  AlertTriangle,
  Copy,
  Edit3,
  ExternalLink,
  Eye,
  EyeOff,
  Globe,
  KeyRound,
  Lock,
  StickyNote,
  Trash2,
  User,
} from "lucide-react"
import { toast } from "sonner"
import { EntryDialog } from "./entry-dialog"

interface EntryDetailProps {
  entry: DecryptedVaultEntry | null
}

export function EntryDetail({ entry }: EntryDetailProps) {
  const { removeEntry } = useEntries()

  const [passwordRevealed, setPasswordRevealed] = React.useState(false)
  const [revealedCustomFields, setRevealedCustomFields] = React.useState<
    Record<number, boolean>
  >({})
  const [editOpen, setEditOpen] = React.useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false)
  const [isDeleting, setIsDeleting] = React.useState(false)

  // Auto-re-hide revealed password after 10 seconds
  React.useEffect(() => {
    if (!passwordRevealed) return
    const timer = setTimeout(() => {
      setPasswordRevealed(false)
    }, 10_000)

    return () => clearTimeout(timer)
  }, [passwordRevealed])

  if (!entry) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted-foreground">
        <Lock className="mb-3 size-12 stroke-1 text-muted-foreground/50" />
        <h3 className="text-base font-medium text-foreground">
          No entry selected
        </h3>
        <p className="mt-1 max-w-sm text-sm">
          Select an item from the list on the left to view and copy credentials,
          or create a new entry.
        </p>
      </div>
    )
  }

  const handleDelete = async () => {
    setIsDeleting(true)
    try {
      await removeEntry(entry.id)
      toast.success("Entry deleted")
      setDeleteConfirmOpen(false)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete entry"
      toast.error(msg)
    } finally {
      setIsDeleting(false)
    }
  }

  // Render decryption failure view
  if (isDecryptFailed(entry)) {
    return (
      <div className="space-y-6 p-6">
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-destructive" />
            <div>
              <h3 className="text-sm font-semibold text-destructive">
                Could Not Decrypt Entry
              </h3>
              <p className="mt-1 text-xs text-muted-foreground">
                The authentication tag or ciphertext for this entry failed
                verification. It may have been tampered with, modified under a
                different Vault Key, or corrupted in storage.
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-2 text-xs text-muted-foreground">
          <div>
            <span className="font-medium text-foreground">Entry ID:</span>{" "}
            {entry.id}
          </div>
          <div>
            <span className="font-medium text-foreground">Type:</span>{" "}
            {entry.type}
          </div>
          <div>
            <span className="font-medium text-foreground">Version:</span>{" "}
            {entry.entryVersion}
          </div>
          <div>
            <span className="font-medium text-foreground">Updated:</span>{" "}
            {new Date(entry.updatedAt).toLocaleString()}
          </div>
        </div>

        <Button
          variant="destructive"
          size="sm"
          onClick={() => setDeleteConfirmOpen(true)}
          className="gap-1.5"
        >
          <Trash2 className="size-3.5" />
          Delete Damaged Entry
        </Button>

        {/* Delete Confirmation Dialog */}
        <Dialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete Damaged Entry</DialogTitle>
              <DialogDescription>
                This will permanently delete this ciphertext record from the
                server. This action cannot be undone.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setDeleteConfirmOpen(false)}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleDelete}
                disabled={isDeleting}
              >
                Delete
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    )
  }

  const isPassword = entry.type === "password"
  const safeUrl = isPassword ? sanitizeWebUrl(entry.data.url) : null

  return (
    <div className="max-w-2xl space-y-6 p-6">
      {/* Header bar */}
      <div className="flex items-start justify-between gap-4 border-b pb-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-muted text-primary">
            {isPassword ? (
              <KeyRound className="size-5" />
            ) : (
              <StickyNote className="size-5" />
            )}
          </div>
          <div>
            <h2 className="text-xl font-semibold tracking-tight">
              {entry.data.title}
            </h2>
            <p className="text-xs text-muted-foreground">
              {isPassword ? "Password Entry" : "Secure Note"} • Updated{" "}
              {new Date(entry.updatedAt).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEditOpen(true)}
            className="gap-1.5"
          >
            <Edit3 className="size-3.5" />
            Edit
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDeleteConfirmOpen(true)}
            className="gap-1.5 text-muted-foreground hover:text-destructive"
          >
            <Trash2 className="size-3.5" />
            Delete
          </Button>
        </div>
      </div>

      {/* Entry Details */}
      {isPassword ? (
        <div className="space-y-4">
          {/* Username */}
          {entry.data.username && (
            <div className="space-y-1 rounded-lg border bg-card p-3">
              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <User className="size-3.5" /> Username / Email
              </span>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium select-all">
                  {entry.data.username}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={() =>
                    copyToClipboard(entry.data.username!, { label: "Username" })
                  }
                  title="Copy username"
                >
                  <Copy className="size-3.5" />
                </Button>
              </div>
            </div>
          )}

          {/* Password */}
          {entry.data.password && (
            <div className="space-y-1 rounded-lg border bg-card p-3">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Lock className="size-3.5" /> Password
                </span>
                {passwordRevealed && (
                  <span className="text-[11px] font-medium text-amber-500">
                    Auto-hiding in 10s
                  </span>
                )}
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm tracking-wider select-all">
                  {passwordRevealed ? entry.data.password : "••••••••••••••••"}
                </span>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground"
                    onClick={() => setPasswordRevealed((prev) => !prev)}
                    title={
                      passwordRevealed
                        ? "Hide password"
                        : "Show password (auto-hides after 10s)"
                    }
                  >
                    {passwordRevealed ? (
                      <EyeOff className="size-3.5" />
                    ) : (
                      <Eye className="size-3.5" />
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7"
                    onClick={() =>
                      copyToClipboard(entry.data.password!, {
                        label: "Password",
                      })
                    }
                    title="Copy password"
                  >
                    <Copy className="size-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Website URL */}
          {entry.data.url && (
            <div className="space-y-1 rounded-lg border bg-card p-3">
              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Globe className="size-3.5" /> Website
              </span>
              <div className="flex items-center justify-between">
                {safeUrl ? (
                  <a
                    href={safeUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex max-w-md items-center gap-1 truncate text-sm font-medium text-primary hover:underline"
                  >
                    {safeUrl}
                    <ExternalLink className="size-3 shrink-0" />
                  </a>
                ) : (
                  <span className="truncate text-sm text-muted-foreground italic">
                    {entry.data.url} (untrusted scheme)
                  </span>
                )}
                {safeUrl && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7"
                    onClick={() => copyToClipboard(safeUrl, { label: "URL" })}
                    title="Copy URL"
                  >
                    <Copy className="size-3.5" />
                  </Button>
                )}
              </div>
            </div>
          )}

          {/* Notes */}
          {entry.data.notes && (
            <div className="space-y-1 rounded-lg border bg-card p-3">
              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <StickyNote className="size-3.5" /> Notes
              </span>
              <p className="font-mono text-sm whitespace-pre-wrap text-muted-foreground select-all">
                {entry.data.notes}
              </p>
            </div>
          )}
        </div>
      ) : (
        /* Secure Note View */
        <div className="space-y-4">
          <div className="space-y-2 rounded-lg border bg-card p-4">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Secure Content</span>
              <Button
                variant="ghost"
                size="icon"
                className="size-7"
                onClick={() =>
                  copyToClipboard(entry.data.text, { label: "Note Content" })
                }
                title="Copy note"
              >
                <Copy className="size-3.5" />
              </Button>
            </div>
            <pre className="font-mono text-sm leading-relaxed whitespace-pre-wrap select-all">
              {entry.data.text}
            </pre>
          </div>
        </div>
      )}

      {/* Custom Fields */}
      {entry.data.customFields && entry.data.customFields.length > 0 && (
        <div className="space-y-2 border-t pt-2">
          <h4 className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
            Custom Fields
          </h4>
          <div className="grid gap-2">
            {entry.data.customFields.map((field, idx) => {
              const isHidden = field.type === "hidden"
              const isRevealed = Boolean(revealedCustomFields[idx])

              return (
                <div
                  key={idx}
                  className="flex items-center justify-between rounded-lg border bg-card p-2.5"
                >
                  <div className="space-y-0.5">
                    <span className="text-xs text-muted-foreground">
                      {field.name}
                    </span>
                    <div className="font-mono text-sm select-all">
                      {isHidden && !isRevealed ? "••••••••" : field.value}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {isHidden && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7 text-muted-foreground"
                        onClick={() =>
                          setRevealedCustomFields((prev) => ({
                            ...prev,
                            [idx]: !prev[idx],
                          }))
                        }
                      >
                        {isRevealed ? (
                          <EyeOff className="size-3.5" />
                        ) : (
                          <Eye className="size-3.5" />
                        )}
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() =>
                        copyToClipboard(field.value, { label: field.name })
                      }
                    >
                      <Copy className="size-3.5" />
                    </Button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Edit Dialog */}
      <EntryDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        entryToEdit={entry}
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Entry</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{entry.data.title}&quot;?
              This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteConfirmOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              Delete Entry
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
