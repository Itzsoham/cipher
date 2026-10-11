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
import {
  uploadVaultFile,
  formatBytes,
  MAX_FILE_SIZE_BYTES,
  type UploadProgressPhase,
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
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
import {
  Eye,
  EyeOff,
  FileText,
  KeyRound,
  Loader2,
  Plus,
  StickyNote,
  Trash2,
  Upload,
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
  const { addEntry, addFileEntry, editEntry, vk, userId } = useEntries()
  const isEditing = Boolean(entryToEdit)

  const [type, setType] = React.useState<EntryType>(() => {
    if (entryToEdit && !("error" in entryToEdit)) {
      return entryToEdit.type
    }
    return "password"
  })

  const [title, setTitle] = React.useState(() => {
    if (entryToEdit && !("error" in entryToEdit)) {
      if (entryToEdit.type === "file") return entryToEdit.data.fileName
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
    if (entryToEdit && !("error" in entryToEdit)) {
      if ("notes" in entryToEdit.data && typeof entryToEdit.data.notes === "string") {
        return entryToEdit.data.notes
      }
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
      if ("customFields" in entryToEdit.data && Array.isArray(entryToEdit.data.customFields)) {
        return [...entryToEdit.data.customFields]
      }
    }
    return []
  })

  // File upload state
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null)
  const [fileError, setFileError] = React.useState<string | null>(null)
  const [uploadPhase, setUploadPhase] = React.useState<UploadProgressPhase | null>(null)

  const [showPassword, setShowPassword] = React.useState(false)
  const [isSubmitting, setIsSubmitting] = React.useState(false)
  const [generatorOpen, setGeneratorOpen] = React.useState(false)
  const [urlError, setUrlError] = React.useState<string | null>(null)

  const handleFileChange = (file: File | null) => {
    setFileError(null)
    if (!file) {
      setSelectedFile(null)
      return
    }

    if (file.size === 0) {
      setFileError("File must not be empty.")
      setSelectedFile(null)
      return
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setFileError("Files must be 25 MB or smaller. Use the encrypted export for larger files.")
      setSelectedFile(null)
      return
    }

    setSelectedFile(file)
    if (!title) {
      setTitle(file.name)
    }
  }

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

    if (type !== "file" && !title.trim()) {
      toast.error("Title is required")
      return
    }

    if (type === "password" && url.trim() && !isValidWebUrl(url)) {
      setUrlError("URL must begin with http:// or https://")
      toast.error("Invalid URL scheme: only http: and https: are permitted")
      return
    }

    if (type === "file" && !isEditing && !selectedFile) {
      setFileError("Please choose a file to upload")
      toast.error("File is required")
      return
    }

    setIsSubmitting(true)
    try {
      const sanitizedCustomFields = customFields.filter(
        (f) => f.name.trim().length > 0
      )

      if (type === "file") {
        if (!vk || !userId) {
          throw new Error("Vault is locked or session is missing")
        }

        if (selectedFile) {
          const newEntry = await uploadVaultFile({
            file: selectedFile,
            notes: notes.trim() || undefined,
            vk,
            userId,
            onProgress: setUploadPhase,
          })
          addFileEntry(newEntry)
          toast.success("File encrypted and uploaded successfully")
        }
      } else if (type === "password") {
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
      setUploadPhase(null)
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
                  Password
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
                <button
                  type="button"
                  className={`flex-1 flex items-center justify-center gap-2 rounded-md py-1.5 font-medium transition-colors ${
                    type === "file"
                      ? "bg-background text-foreground shadow-xs"
                      : "text-muted-foreground"
                  }`}
                  onClick={() => setType("file")}
                >
                  <FileText className="size-3.5" />
                  File
                </button>
              </div>
            )}

            {/* File Upload Specific Section */}
            {type === "file" ? (
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>File (Up to 25 MB) *</Label>
                  <div
                    className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-muted-foreground/25 p-6 text-center hover:border-primary/50 transition-colors"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault()
                      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                        handleFileChange(e.dataTransfer.files[0])
                      }
                    }}
                  >
                    <Upload className="size-8 text-muted-foreground mb-2" />
                    <p className="text-sm font-medium">
                      Drag and drop your file here, or browse
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Documents, images, or archives up to 25 MB
                    </p>
                    <input
                      id="file-upload-input"
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          handleFileChange(e.target.files[0])
                        }
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="mt-3"
                      onClick={() =>
                        document.getElementById("file-upload-input")?.click()
                      }
                    >
                      Select File
                    </Button>
                  </div>
                  {selectedFile && (
                    <div className="flex items-center justify-between rounded-md bg-muted/50 p-2.5 text-xs">
                      <div className="flex items-center gap-2 truncate">
                        <FileText className="size-4 text-primary shrink-0" />
                        <span className="font-medium truncate">
                          {selectedFile.name}
                        </span>
                        <span className="text-muted-foreground shrink-0">
                          ({formatBytes(selectedFile.size)})
                        </span>
                      </div>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="size-6 text-muted-foreground hover:text-destructive shrink-0"
                        onClick={() => setSelectedFile(null)}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </div>
                  )}
                  {fileError && (
                    <p className="text-xs text-destructive">{fileError}</p>
                  )}
                </div>

                {/* Optional Notes for File */}
                <div className="space-y-1.5">
                  <Label htmlFor="entry-notes">Notes</Label>
                  <textarea
                    id="entry-notes"
                    rows={2}
                    placeholder="Optional notes or description for this document..."
                    value={notes}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  />
                </div>

                {/* Progress bar during upload */}
                {uploadPhase && (
                  <div className="space-y-1 rounded-md bg-primary/10 p-3 text-xs text-primary font-medium flex items-center gap-2">
                    <Loader2 className="size-4 animate-spin shrink-0" />
                    <span>
                      {uploadPhase === "encrypting" && "Encrypting file in browser with AES-GCM..."}
                      {uploadPhase === "uploading" && "Uploading encrypted ciphertext to storage..."}
                      {uploadPhase === "saving" && "Saving encrypted entry to vault..."}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              /* Password and Secure Note Fields */
              <>
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
                    <div className="space-y-1.5">
                      <Label htmlFor="entry-username">Username or Email</Label>
                      <Input
                        id="entry-username"
                        placeholder="user@example.com"
                        value={username}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) => setUsername(e.target.value)}
                      />
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="entry-password">Password</Label>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-6 gap-1 px-1.5 text-xs text-primary hover:text-primary"
                          onClick={() => setGeneratorOpen(true)}
                        >
                          <Wand2 className="size-3" /> Generate
                        </Button>
                      </div>
                      <div className="relative">
                        <Input
                          id="entry-password"
                          type={showPassword ? "text" : "password"}
                          placeholder="Password"
                          value={password}
                          spellCheck={false}
                          autoComplete="new-password"
                          onChange={(e) => setPassword(e.target.value)}
                          className="pr-10 font-mono"
                        />
                        <button
                          type="button"
                          className="absolute top-2.5 right-2.5 text-muted-foreground hover:text-foreground"
                          onClick={() => setShowPassword((prev) => !prev)}
                        >
                          {showPassword ? (
                            <EyeOff className="size-4" />
                          ) : (
                            <Eye className="size-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor="entry-url">Website URL</Label>
                      <Input
                        id="entry-url"
                        type="url"
                        placeholder="https://example.com"
                        value={url}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) => handleUrlChange(e.target.value)}
                      />
                      {urlError && (
                        <p className="text-xs text-destructive">{urlError}</p>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor="entry-notes">Notes</Label>
                      <textarea
                        id="entry-notes"
                        rows={3}
                        placeholder="Additional secret details, security questions..."
                        value={notes}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) => setNotes(e.target.value)}
                        className="w-full rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      />
                    </div>
                  </>
                ) : (
                  <div className="space-y-1.5">
                    <Label htmlFor="entry-text">Secure Content *</Label>
                    <textarea
                      id="entry-text"
                      required
                      rows={6}
                      placeholder="Write your secret notes, tokens, or recovery seeds here..."
                      value={text}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(e) => setText(e.target.value)}
                      className="w-full font-mono rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                  </div>
                )}
              </>
            )}

            {/* Custom Fields (for passwords and notes) */}
            {type !== "file" && (
              <div className="space-y-2 border-t pt-3">
                <div className="flex items-center justify-between">
                  <Label className="text-xs">Custom Fields</Label>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-6 gap-1 px-2 text-xs"
                    onClick={handleAddCustomField}
                  >
                    <Plus className="size-3" /> Add Field
                  </Button>
                </div>

                <div className="space-y-2">
                  {customFields.map((field, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <Input
                        placeholder="Field Name"
                        value={field.name}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) => handleCustomFieldChange(idx, { name: e.target.value })}
                        className="w-1/3 h-8 text-xs"
                      />
                      <select
                        value={field.type}
                        onChange={(e) =>
                          handleCustomFieldChange(idx, {
                            type: e.target.value as "text" | "hidden",
                          })
                        }
                        className="h-8 rounded-md border bg-background px-2 text-xs"
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
            )}
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
              {isEditing ? "Save Changes" : type === "file" ? "Upload & Encrypt" : "Create Entry"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

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
