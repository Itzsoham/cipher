"use client"

import * as React from "react"
import { useEntries } from "@/lib/vault/entry-store"
import {
  type CustomField,
  type DecryptedVaultEntry,
  type EntryType,
  isValidWebUrl,
  type PasswordEntryPayload,
  type SecureNoteEntryPayload,
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
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
import {
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Plus,
  StickyNote,
  Trash2,
  Wand2,
} from "lucide-react"
import { toast } from "sonner"
import { PasswordGeneratorDialog } from "./password-generator-dialog"

interface EntryDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  entryToEdit?: DecryptedVaultEntry | null
}

function EntryDialogForm({
  entryToEdit,
  onOpenChange,
}: {
  entryToEdit?: DecryptedVaultEntry | null
  onOpenChange: (open: boolean) => void
}) {
  const { addEntry, editEntry } = useEntries()
  const isEditing = Boolean(entryToEdit)

  const [type, setType] = React.useState<EntryType>(() => {
    if (entryToEdit && !("error" in entryToEdit)) {
      return entryToEdit.type
    }
    return "password"
  })

  const [title, setTitle] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit)) {
      return entryToEdit.data.title || ""
    }
    return ""
  })

  const [username, setUsername] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit) && entryToEdit.type === "password") {
      return entryToEdit.data.username || ""
    }
    return ""
  })

  const [password, setPassword] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit) && entryToEdit.type === "password") {
      return entryToEdit.data.password || ""
    }
    return ""
  })

  const [url, setUrl] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit) && entryToEdit.type === "password") {
      return entryToEdit.data.url || ""
    }
    return ""
  })

  const [notes, setNotes] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit) && entryToEdit.type === "password") {
      return entryToEdit.data.notes || ""
    }
    return ""
  })

  const [text, setText] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit) && entryToEdit.type === "secure_note") {
      return entryToEdit.data.text || ""
    }
    return ""
  })

  const [customFields, setCustomFields] = React.useState<CustomField[]>(() => {
    if (entryToEdit && !("error" in entryToEdit)) {
      return entryToEdit.data.customFields ? [...entryToEdit.data.customFields] : []
    }
    return []
  })

  const [showPassword, setShowPassword] = React.useState(false)
  const [isSubmitting, setIsSubmitting] = React.useState(false)
  const [generatorOpen, setGeneratorOpen] = React.useState(false)
  const [urlError, setUrlError] = React.useState<string | null>(null)

  const handleAddCustomField = () => {
    setCustomFields((prev) => [
      ...prev,
      { name: "", value: "", type: "text" },
    ])
  }

  const handleRemoveCustomField = (index: number) => {
    setCustomFields((prev) => prev.filter((_, i) => i !== index))
  }

  const handleCustomFieldChange = (
    index: number,
    field: Partial<CustomField>
  ) => {
    setCustomFields((prev) =>
      prev.map((item, i) => (i === index ? { ...item, ...field } : item))
    )
  }

  const handleUrlChange = (val: string) => {
    setUrl(val)
    if (val.trim() && !isValidWebUrl(val)) {
      setUrlError("URL must begin with http:// or https://")
    } else {
      setUrlError(null)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!title.trim()) {
      toast.error("Title is required")
      return
    }

    if (type === "password" && url.trim() && !isValidWebUrl(url)) {
      setUrlError("URL must begin with http:// or https://")
      toast.error("Invalid URL scheme: only http: and https: are permitted")
      return
    }

    setIsSubmitting(true)
    try {
      const sanitizedCustomFields = customFields.filter(
        (f) => f.name.trim().length > 0
      )

      if (type === "password") {
        const payload: PasswordEntryPayload = {
          title: title.trim(),
          username: username.trim() || undefined,
          password: password || undefined,
          url: url.trim() || undefined,
          notes: notes.trim() || undefined,
          customFields: sanitizedCustomFields.length > 0 ? sanitizedCustomFields : undefined,
        }

        if (isEditing && entryToEdit) {
          await editEntry(entryToEdit.id, "password", payload)
          toast.success("Entry updated successfully")
        } else {
          await addEntry("password", payload)
          toast.success("Entry created successfully")
        }
      } else {
        const payload: SecureNoteEntryPayload = {
          title: title.trim(),
          text: text,
          customFields: sanitizedCustomFields.length > 0 ? sanitizedCustomFields : undefined,
        }

        if (isEditing && entryToEdit) {
          await editEntry(entryToEdit.id, "secure_note", payload)
          toast.success("Secure note updated successfully")
        } else {
          await addEntry("secure_note", payload)
          toast.success("Secure note created successfully")
        }
      }

      onOpenChange(false)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save entry"
      toast.error(msg)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>
              {isEditing ? "Edit Vault Entry" : "New Vault Entry"}
            </DialogTitle>
            <DialogDescription>
              Zero-knowledge encrypted client-side using your Vault Key.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Type Selector (only for new entry) */}
            {!isEditing && (
              <div className="flex rounded-lg bg-muted p-1 text-xs">
                <button
                  type="button"
                  className={`flex-1 flex items-center justify-center gap-2 rounded-md py-1.5 font-medium transition-colors ${
                    type === "password"
                      ? "bg-background text-foreground shadow-xs"
                      : "text-muted-foreground"
                  }`}
                  onClick={() => setType("password")}
                >
                  <KeyRound className="size-3.5" />
                  Login / Password
                </button>
                <button
                  type="button"
                  className={`flex-1 flex items-center justify-center gap-2 rounded-md py-1.5 font-medium transition-colors ${
                    type === "secure_note"
                      ? "bg-background text-foreground shadow-xs"
                      : "text-muted-foreground"
                  }`}
                  onClick={() => setType("secure_note")}
                >
                  <StickyNote className="size-3.5" />
                  Secure Note
                </button>
              </div>
            )}

            {/* Title */}
            <div className="space-y-1.5">
              <Label htmlFor="entry-title">Title *</Label>
              <Input
                id="entry-title"
                required
                placeholder={type === "password" ? "e.g. GitHub, Google" : "e.g. Recovery seed, WiFi codes"}
                value={title}
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>

            {type === "password" ? (
              <>
                {/* Username / Email */}
                <div className="space-y-1.5">
                  <Label htmlFor="entry-username">Username or Email</Label>
                  <Input
                    id="entry-username"
                    placeholder="e.g. user@example.com"
                    value={username}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                {/* Password + Generator Button */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="entry-password">Password</Label>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-xs text-primary gap-1"
                      onClick={() => setGeneratorOpen(true)}
                    >
                      <Wand2 className="size-3" />
                      Generate
                    </Button>
                  </div>
                  <div className="relative">
                    <Input
                      id="entry-password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      spellCheck={false}
                      autoComplete="new-password"
                      className="pr-10 font-mono"
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-1 top-1 size-7 text-muted-foreground"
                      onClick={() => setShowPassword((prev) => !prev)}
                      title={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </Button>
                  </div>
                </div>

                {/* Website URL */}
                <div className="space-y-1.5">
                  <Label htmlFor="entry-url">Website URL</Label>
                  <Input
                    id="entry-url"
                    type="text"
                    placeholder="https://example.com"
                    value={url}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => handleUrlChange(e.target.value)}
                    className={urlError ? "border-destructive focus-visible:ring-destructive" : ""}
                  />
                  {urlError && <p className="text-[11px] text-destructive">{urlError}</p>}
                </div>

                {/* Notes */}
                <div className="space-y-1.5">
                  <Label htmlFor="entry-notes">Notes</Label>
                  <textarea
                    id="entry-notes"
                    rows={3}
                    value={notes}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    placeholder="Additional details..."
                  />
                </div>
              </>
            ) : (
              /* Secure Note Content */
              <div className="space-y-1.5">
                <Label htmlFor="entry-text">Note Content</Label>
                <textarea
                  id="entry-text"
                  rows={8}
                  required
                  value={text}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(e) => setText(e.target.value)}
                  className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  placeholder="Write secret note content here..."
                />
              </div>
            )}

            {/* Custom Fields */}
            <div className="space-y-2 pt-2 border-t">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Custom Fields</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs gap-1"
                  onClick={handleAddCustomField}
                >
                  <Plus className="size-3" />
                  Add Field
                </Button>
              </div>

              {customFields.map((field, idx) => (
                <div key={idx} className="flex items-center gap-2 pt-1">
                  <Input
                    placeholder="Field name"
                    value={field.name}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => handleCustomFieldChange(idx, { name: e.target.value })}
                    className="flex-1 h-8 text-xs"
                  />
                  <select
                    value={field.type}
                    onChange={(e) =>
                      handleCustomFieldChange(idx, {
                        type: e.target.value as "text" | "hidden",
                      })
                    }
                    className="h-8 rounded-md border border-input bg-transparent px-2 text-xs"
                  >
                    <option value="text">Text</option>
                    <option value="hidden">Hidden</option>
                  </select>
                  <Input
                    type={field.type === "hidden" ? "password" : "text"}
                    placeholder="Value"
                    value={field.value}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => handleCustomFieldChange(idx, { value: e.target.value })}
                    className="flex-1 h-8 text-xs font-mono"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-8 text-muted-foreground hover:text-destructive"
                    onClick={() => handleRemoveCustomField(idx)}
                  >
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          </div>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              disabled={isSubmitting}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && (
                <Loader2 className="mr-2 size-4 animate-spin" />
              )}
              {isEditing ? "Save Changes" : "Create Entry"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      {/* Embedded Password Generator Dialog */}
      <PasswordGeneratorDialog
        open={generatorOpen}
        onOpenChange={setGeneratorOpen}
        onSelectPassword={(newPw) => {
          setPassword(newPw)
          setShowPassword(true)
        }}
      />
    </>
  )
}

export function EntryDialog({
  open,
  onOpenChange,
  entryToEdit,
}: EntryDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <EntryDialogForm
          entryToEdit={entryToEdit}
          onOpenChange={onOpenChange}
        />
      )}
    </Dialog>
  )
}
