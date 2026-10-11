"use client"

import * as React from "react"
import { copyToClipboard } from "@/lib/vault/clipboard"
import { useEntries } from "@/lib/vault/entry-store"
import {
  type DecryptedVaultEntry,
  isDecryptFailed,
  sanitizeWebUrl,
} from "@/lib/vault/entry-types"
import {
  downloadVaultFile,
  previewVaultFile,
  formatBytes,
  PREVIEW_ALLOWLIST,
} from "@/lib/vault/file-client"
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
  Download,
  Edit3,
  ExternalLink,
  Eye,
  EyeOff,
  FileText,
  Globe,
  KeyRound,
  Loader2,
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
  const { removeEntry, vk, userId } = useEntries()

  const [passwordRevealed, setPasswordRevealed] = React.useState(false)
  const [revealedCustomFields, setRevealedCustomFields] = React.useState<
    Record<number, boolean>
  >({})
  const [editOpen, setEditOpen] = React.useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false)
  const [isDeleting, setIsDeleting] = React.useState(false)

  // File download and preview states
  const [isDownloading, setIsDownloading] = React.useState(false)
  const [previewOpen, setPreviewOpen] = React.useState(false)
  const [previewLoading, setPreviewLoading] = React.useState(false)
  const [previewData, setPreviewData] = React.useState<{
    type: "img" | "text"
    content: string
    revoke?: () => void
  } | null>(null)

  // Auto-re-hide revealed password after 10 seconds
  React.useEffect(() => {
    if (!passwordRevealed) return
    const timer = setTimeout(() => {
      setPasswordRevealed(false)
    }, 10_000)

    return () => clearTimeout(timer)
  }, [passwordRevealed])

  // Lock and unmount cleanup: revoke preview object URLs
  React.useEffect(() => {
    return () => {
      if (previewData?.revoke) {
        previewData.revoke()
      }
    }
  }, [previewData])

  if (!entry) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted-foreground">
        <Lock className="mb-3 size-10 stroke-[1.25] text-muted-foreground/50" />
        <h3 className="text-sm font-medium text-foreground">
          No Entry Selected
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Select an entry from the list to view its decrypted details.
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
      toast.error(err instanceof Error ? err.message : "Failed to delete entry")
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDownloadFile = async () => {
    if (isDecryptFailed(entry) || entry.type !== "file" || !vk || !userId) return
    setIsDownloading(true)
    try {
      await downloadVaultFile(entry, vk, userId)
      toast.success("File decrypted and downloaded")
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to download file")
    } finally {
      setIsDownloading(false)
    }
  }

  const handlePreviewFile = async () => {
    if (isDecryptFailed(entry) || entry.type !== "file" || !vk || !userId) return
    setPreviewLoading(true)
    try {
      const data = await previewVaultFile(entry, vk, userId)
      setPreviewData(data)
      setPreviewOpen(true)
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Preview failed")
    } finally {
      setPreviewLoading(false)
    }
  }

  // Handle Decryption Failure Row / View
  if (isDecryptFailed(entry)) {
    return (
      <div className="max-w-2xl space-y-6 p-6">
        <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-6">
          <div className="flex items-start gap-4">
            <div className="rounded-lg bg-destructive/10 p-2 text-destructive">
              <AlertTriangle className="size-6" />
            </div>
            <div className="space-y-2">
              <h3 className="text-base font-semibold text-destructive">
                Could Not Decrypt Entry
              </h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                This record failed authentication tag or AAD verification. This
                may indicate data corruption, tampering, or a key mismatch. The
                original ciphertext has not been modified or removed.
              </p>
              <div className="space-y-1 pt-2 font-mono text-[11px] text-muted-foreground">
                <p>Entry ID: {entry.id}</p>
                <p>Type: {entry.type}</p>
                <p>Version: {entry.entryVersion}</p>
              </div>
            </div>
          </div>

          <div className="mt-6 flex justify-end gap-2 border-t pt-4">
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setDeleteConfirmOpen(true)}
              className="gap-1.5"
            >
              <Trash2 className="size-3.5" />
              Delete Damaged Entry
            </Button>
          </div>
        </div>

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
  const isFile = entry.type === "file"
  const safeUrl = isPassword ? sanitizeWebUrl(entry.data.url) : null
  const canPreview =
    isFile && Boolean(PREVIEW_ALLOWLIST[entry.data.mimeType])

  return (
    <div className="max-w-2xl space-y-6 p-6">
      {/* Header bar */}
      <div className="flex items-start justify-between gap-4 border-b pb-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-muted text-primary">
            {isPassword ? (
              <KeyRound className="size-5" />
            ) : isFile ? (
              <FileText className="size-5" />
            ) : (
              <StickyNote className="size-5" />
            )}
          </div>
          <div>
            <h2 className="text-xl font-semibold tracking-tight">
              {isFile ? entry.data.fileName : entry.data.title}
            </h2>
            <p className="text-xs text-muted-foreground">
              {isPassword
                ? "Password Entry"
                : isFile
                ? `File Attachment (${formatBytes(entry.data.fileSize)})`
                : "Secure Note"}{" "}
              • Updated {new Date(entry.updatedAt).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {!isFile && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditOpen(true)}
              className="gap-1.5"
            >
              <Edit3 className="size-3.5" />
              Edit
            </Button>
          )}
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
      {isFile ? (
        /* File Entry View */
        <div className="space-y-4">
          <div className="rounded-lg border bg-card p-4 space-y-4">
            <div className="flex items-center justify-between border-b pb-3">
              <div>
                <span className="text-xs text-muted-foreground">Filename</span>
                <p className="text-sm font-semibold select-all">
                  {entry.data.fileName}
                </p>
              </div>
              <div className="text-center">
                <span className="text-xs text-muted-foreground">Format</span>
                <p className="text-sm font-medium font-mono text-muted-foreground">
                  {entry.data.mimeType}
                </p>
              </div>
              <div className="text-right">
                <span className="text-xs text-muted-foreground">File Size</span>
                <p className="text-sm font-medium">
                  {formatBytes(entry.data.fileSize)}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 pt-1">
              <Button
                size="sm"
                className="gap-2"
                onClick={handleDownloadFile}
                disabled={isDownloading}
              >
                {isDownloading ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Download className="size-4" />
                )}
                Download File
              </Button>

              {canPreview && (
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-2"
                  onClick={handlePreviewFile}
                  disabled={previewLoading}
                >
                  {previewLoading ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Eye className="size-4" />
                  )}
                  Preview
                </Button>
              )}
            </div>
          </div>

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
      ) : isPassword ? (
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
                  <KeyRound className="size-3.5" /> Password
                </span>
                {passwordRevealed && (
                  <span className="text-[11px] text-amber-500 font-medium">
                    Auto-hiding in 10s
                  </span>
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-medium select-all">
                  {passwordRevealed ? entry.data.password : "••••••••••••••••"}
                </span>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7"
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
      {!isFile &&
        entry.data.customFields &&
        entry.data.customFields.length > 0 && (
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
              Are you sure you want to delete &quot;
              {isFile ? entry.data.fileName : entry.data.title}&quot;? This
              cannot be undone.
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

      {/* Safe Allowlisted Preview Dialog */}
      <Dialog
        open={previewOpen}
        onOpenChange={(open) => {
          setPreviewOpen(open)
          if (!open && previewData?.revoke) {
            previewData.revoke()
            setPreviewData(null)
          }
        }}
      >
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              Preview: {isFile ? entry.data.fileName : "Document"}
            </DialogTitle>
            <DialogDescription>
              Decrypted client-side from zero-knowledge object storage.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4 flex justify-center items-center">
            {previewData?.type === "img" ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={previewData.content}
                alt={isFile ? entry.data.fileName : "Preview"}
                className="max-h-[60vh] max-w-full rounded-md object-contain"
              />
            ) : previewData?.type === "text" ? (
              <pre className="max-h-[60vh] w-full overflow-auto rounded-md bg-muted p-4 font-mono text-xs whitespace-pre-wrap select-all">
                {previewData.content}
              </pre>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setPreviewOpen(false)
                if (previewData?.revoke) {
                  previewData.revoke()
                  setPreviewData(null)
                }
              }}
            >
              Close
            </Button>
            <Button onClick={handleDownloadFile} className="gap-2">
              <Download className="size-4" /> Download
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
