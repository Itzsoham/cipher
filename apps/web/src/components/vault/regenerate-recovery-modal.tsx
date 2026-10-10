"use client"

import { useState } from "react"
import { toast } from "sonner"
import {
  importKek,
  unwrapVaultKey,
  wrapVaultKey,
  deriveRecoveryKek,
  validateKdfParams,
} from "@cipher/crypto"
import { Button } from "@cipher/ui/components/button"
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
import { Alert, AlertDescription, AlertTitle } from "@cipher/ui/components/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@cipher/ui/components/dialog"
import { useVault } from "@/hooks/use-vault"
import {
  generateRecoveryKey,
  extractLastGroup,
} from "@/lib/vault/recovery-key"
import { deriveKeyWithWorker } from "@/lib/vault/worker-client"
import { hexToBytes, bytesToHex } from "@/lib/vault/hex"
import { Copy, Download, KeyRound, Loader2, RefreshCw } from "lucide-react"

export function RegenerateRecoveryModal() {
  const { config, setSessionUnlocked } = useVault()

  const [open, setOpen] = useState(false)
  const [step, setStep] = useState<"auth" | "confirm">("auth")
  const [masterPassword, setMasterPassword] = useState("")
  const [isGenerating, setIsGenerating] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const [stagedWrap, setStagedWrap] = useState<{
    newRecoveryKeyFormatted: string
    recoveryHkdfSaltHex: string
    recoveryWrappedKeyHex: string
    recoveryWrapIvHex: string
  } | null>(null)

  const [confirmationInput, setConfirmationInput] = useState("")

  const lastGroup = stagedWrap
    ? extractLastGroup(stagedWrap.newRecoveryKeyFormatted)
    : ""
  const isConfirmed =
    confirmationInput.trim().toUpperCase() === lastGroup.toUpperCase()

  // Step 1: Prompt for master password to unwrap extractable VK and generate new recovery wrap
  async function handleProceedToGenerate(e: React.FormEvent) {
    e.preventDefault()
    if (!config || !masterPassword || isGenerating) return

    setIsGenerating(true)
    try {
      const salt = hexToBytes(config.kdfSalt)
      validateKdfParams({
        algorithm: config.kdfAlgorithm,
        memoryCost: config.kdfMemoryKiB,
        timeCost: config.kdfIterations,
        parallelism: config.kdfParallelism,
        salt,
      })

      // Derive KEK_m to unwrap extractable VK
      const kekRaw = await deriveKeyWithWorker({
        password: masterPassword,
        salt,
        iterations: config.kdfIterations,
        memorySize: config.kdfMemoryKiB,
        parallelism: config.kdfParallelism,
        hashLength: 32,
      })
      const kek = await importKek(kekRaw)

      let extractableVk: CryptoKey
      try {
        extractableVk = await unwrapVaultKey({
          wrappedKey: hexToBytes(config.masterWrappedKey),
          iv: hexToBytes(config.masterWrapIv),
          kek,
          mode: "master",
          userId: config.userId,
          extractable: true,
        })
      } catch {
        throw new Error("Master password is incorrect")
      }

      // Generate new recovery key
      const { formatted, entropy } = await generateRecoveryKey()

      const newRecoveryHkdfSalt = crypto.getRandomValues(new Uint8Array(32))
      const kek_r_bytes = await deriveRecoveryKek(entropy, newRecoveryHkdfSalt)
      const kek_r = await importKek(kek_r_bytes)

      const recoveryWrap = await wrapVaultKey(
        extractableVk,
        kek_r,
        "recovery",
        config.userId
      )

      setStagedWrap({
        newRecoveryKeyFormatted: formatted,
        recoveryHkdfSaltHex: bytesToHex(newRecoveryHkdfSalt),
        recoveryWrappedKeyHex: bytesToHex(recoveryWrap.wrappedKey),
        recoveryWrapIvHex: bytesToHex(recoveryWrap.iv),
      })

      setStep("confirm")
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to generate new recovery key"
      toast.error(msg)
    } finally {
      setIsGenerating(false)
    }
  }

  // Step 2: User confirms new recovery key, submits to server
  async function handleCommitRegeneration() {
    if (!config || !stagedWrap || !isConfirmed || isSubmitting) return

    setIsSubmitting(true)
    try {
      const payload = {
        recoveryHkdfSalt: stagedWrap.recoveryHkdfSaltHex,
        recoveryWrappedKey: stagedWrap.recoveryWrappedKeyHex,
        recoveryWrapIv: stagedWrap.recoveryWrapIvHex,
        expectedUpdatedAt: config.updatedAt,
      }

      const res = await fetch("/api/vault/regenerate-recovery", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || "Failed to save new recovery wrap")
      }

      const resData = await res.json()

      // Update config in context
      if (setSessionUnlocked) {
        setSessionUnlocked(null as unknown as CryptoKey, {
          ...config,
          recoveryHkdfSalt: stagedWrap.recoveryHkdfSaltHex,
          recoveryWrappedKey: stagedWrap.recoveryWrappedKeyHex,
          recoveryWrapIv: stagedWrap.recoveryWrapIvHex,
          updatedAt: resData.updatedAt,
        })
      }

      toast.success("New recovery key activated! Old key is now void.")
      setOpen(false)
      setStep("auth")
      setMasterPassword("")
      setConfirmationInput("")
      setStagedWrap(null)
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to regenerate recovery key"
      toast.error(msg)
    } finally {
      setIsSubmitting(false)
    }
  }

  function handleCopy() {
    if (!stagedWrap) return
    navigator.clipboard.writeText(stagedWrap.newRecoveryKeyFormatted)
    toast.success("New recovery key copied")
  }

  function handleDownload() {
    if (!stagedWrap || !config) return
    const text = [
      "CIPHER VAULT RECOVERY KEY (NEW)",
      "===============================",
      "",
      `User ID: ${config.userId}`,
      `Generated: ${new Date().toISOString()}`,
      "",
      `Recovery Key: ${stagedWrap.newRecoveryKeyFormatted}`,
      "",
      "IMPORTANT:",
      "- Any previous recovery key is permanently invalid.",
      "- This is the ONLY copy of your new recovery key.",
      "- Keep this file in a safe, offline location.",
    ].join("\n")

    const blob = new Blob([text], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `cipher-recovery-key-new.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("Recovery key downloaded")
  }

  function handleOpenChange(isOpen: boolean) {
    setOpen(isOpen)
    if (!isOpen) {
      setStep("auth")
      setMasterPassword("")
      setConfirmationInput("")
      setStagedWrap(null)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <RefreshCw className="mr-2 h-4 w-4" /> Regenerate Recovery Key
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Regenerate Recovery Key</DialogTitle>
          <DialogDescription>
            Issue a brand new recovery key. Your existing recovery key will immediately stop working.
          </DialogDescription>
        </DialogHeader>

        {step === "auth" ? (
          <form onSubmit={handleProceedToGenerate} className="space-y-4">
            <Alert variant="destructive">
              <AlertTitle className="text-xs font-semibold">Security Verification</AlertTitle>
              <AlertDescription className="text-xs">
                Enter your master password to authorize re-wrapping your Vault Key under a new recovery secret.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="regen-auth-password">Master Password</Label>
              <Input
                id="regen-auth-password"
                type="password"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                placeholder="Enter master password"
                required
              />
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setOpen(false)}
                disabled={isGenerating}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!masterPassword || isGenerating}>
                {isGenerating ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <KeyRound className="mr-2 h-4 w-4" />
                    Generate New Key
                  </>
                )}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="rounded-lg border bg-muted/40 p-3 font-mono text-center text-xs font-semibold tracking-wider select-all break-all">
              {stagedWrap?.newRecoveryKeyFormatted}
            </div>

            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={handleCopy}
              >
                <Copy className="mr-2 h-4 w-4" /> Copy
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={handleDownload}
              >
                <Download className="mr-2 h-4 w-4" /> Download .txt
              </Button>
            </div>

            <div className="space-y-2 pt-2">
              <Label htmlFor="confirm-regen-key">
                Confirm by typing the last 4 characters ({lastGroup}):
              </Label>
              <Input
                id="confirm-regen-key"
                type="text"
                maxLength={4}
                value={confirmationInput}
                onChange={(e) => setConfirmationInput(e.target.value.toUpperCase())}
                placeholder={lastGroup}
                className="font-mono text-center tracking-widest uppercase"
              />
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setStep("auth")}
                disabled={isSubmitting}
              >
                Back
              </Button>
              <Button
                type="button"
                disabled={!isConfirmed || isSubmitting}
                onClick={handleCommitRegeneration}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Activating...
                  </>
                ) : (
                  "Activate New Key"
                )}
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
