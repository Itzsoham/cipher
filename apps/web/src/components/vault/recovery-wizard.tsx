"use client"

import { useState, useTransition } from "react"
import { toast } from "sonner"
import {
  deriveRecoveryKek,
  importKek,
  unwrapVaultKey,
  wrapVaultKey,
} from "@cipher/crypto"
import { Button } from "@cipher/ui/components/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@cipher/ui/components/card"
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
import { Alert, AlertDescription, AlertTitle } from "@cipher/ui/components/alert"
import { useVault } from "@/hooks/use-vault"
import {
  parseRecoveryKey,
  generateRecoveryKey,
  extractLastGroup,
} from "@/lib/vault/recovery-key"
import {
  evaluatePasswordStrength,
  type PasswordStrengthResult,
} from "@/lib/vault/password-strength"
import { deriveKeyWithWorker } from "@/lib/vault/worker-client"
import { hexToBytes, bytesToHex } from "@/lib/vault/hex"
import {
  AlertTriangle,
  Copy,
  Download,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"

interface RecoveryWizardProps {
  user: {
    id: string
    email: string
    name?: string | null
  }
  onCancel?: () => void
  onComplete?: () => void
}

interface StagedRecoveryData {
  vk: CryptoKey // extractable VK in single-session recovery flow
  oldConfigUpdatedAt: string
}

interface StagedNewWraps {
  kdfSaltHex: string
  kdfMemoryKiB: number
  kdfIterations: number
  kdfParallelism: number
  masterWrappedKeyHex: string
  masterWrapIvHex: string
  recoveryHkdfSaltHex: string
  recoveryWrappedKeyHex: string
  recoveryWrapIvHex: string
  newRecoveryKeyFormatted: string
  newKekRaw: Uint8Array
}

export function RecoveryWizard({
  user,
  onCancel,
  onComplete,
}: RecoveryWizardProps) {
  const { config, refreshConfig, setSessionUnlocked } = useVault()

  const [step, setStep] = useState<"enter-key" | "new-password" | "confirm-new-key">("enter-key")
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("")
  const [isVerifyingKey, setIsVerifyingKey] = useState(false)
  const [stagedRecovery, setStagedRecovery] = useState<StagedRecoveryData | null>(null)

  const [newPassword, setNewPassword] = useState("")
  const [confirmNewPassword, setConfirmNewPassword] = useState("")
  const [isDerivingNewWraps, setIsDerivingNewWraps] = useState(false)
  const [stagedNewWraps, setStagedNewWraps] = useState<StagedNewWraps | null>(null)

  const [confirmationInput, setConfirmationInput] = useState("")
  const [isPending, startTransition] = useTransition()

  // Step 1: Verify recovery key & unwrap VK as extractable
  async function handleVerifyRecoveryKey(e: React.FormEvent) {
    e.preventDefault()
    if (!recoveryKeyInput || isVerifyingKey) return

    setIsVerifyingKey(true)
    try {
      let activeConfig = config
      if (!activeConfig) {
        activeConfig = await refreshConfig()
      }
      if (!activeConfig) {
        throw new Error("Vault configuration not found on server")
      }

      // 1. Parse and verify Crockford base32 + 24-bit SHA-256 checksum
      const entropy = await parseRecoveryKey(recoveryKeyInput)

      // 2. Derive KEK_r using stored recoveryHkdfSalt
      const recoveryHkdfSalt = hexToBytes(activeConfig.recoveryHkdfSalt)
      const kek_r_bytes = await deriveRecoveryKek(entropy, recoveryHkdfSalt)
      const kek_r = await importKek(kek_r_bytes)

      // 3. Unwrap VK as extractable so we can re-wrap it under new password & key
      const recoveryWrappedKey = hexToBytes(activeConfig.recoveryWrappedKey)
      const recoveryWrapIv = hexToBytes(activeConfig.recoveryWrapIv)

      const vk = await unwrapVaultKey({
        wrappedKey: recoveryWrappedKey,
        iv: recoveryWrapIv,
        kek: kek_r,
        mode: "recovery",
        userId: user.id,
        extractable: true,
      })

      setStagedRecovery({
        vk,
        oldConfigUpdatedAt: activeConfig.updatedAt,
      })

      toast.success("Recovery key verified! Please choose a new master password.")
      setStep("new-password")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to verify recovery key"
      toast.error(msg)
    } finally {
      setIsVerifyingKey(false)
    }
  }

  // Step 2: Validate new password, re-wrap VK under new KEK_m and new KEK_r
  const strength: PasswordStrengthResult = evaluatePasswordStrength(newPassword, [
    user.email,
    user.name || "",
  ])
  const passwordsMatch = newPassword.length > 0 && newPassword === confirmNewPassword
  const isNewPasswordValid =
    newPassword.length >= 12 && passwordsMatch && strength.score >= 3

  async function handlePrepareNewWraps() {
    if (!stagedRecovery || !isNewPasswordValid) return

    setIsDerivingNewWraps(true)
    try {
      const kdfSalt = crypto.getRandomValues(new Uint8Array(16))
      const kdfMemoryKiB = 65536
      const kdfIterations = 3
      const kdfParallelism = 1

      // Derive new KEK_m
      const newKekRaw = await deriveKeyWithWorker({
        password: newPassword,
        salt: kdfSalt,
        iterations: kdfIterations,
        memorySize: kdfMemoryKiB,
        parallelism: kdfParallelism,
        hashLength: 32,
      })
      const newKek_m = await importKek(newKekRaw)

      // Wrap VK under new master password
      const newMasterWrap = await wrapVaultKey(
        stagedRecovery.vk,
        newKek_m,
        "master",
        user.id
      )

      // Issue NEW recovery key (old key is retired)
      const { formatted: newRecoveryKeyFormatted, entropy: newRecoveryEntropy } =
        await generateRecoveryKey()

      const newRecoveryHkdfSalt = crypto.getRandomValues(new Uint8Array(32))
      const newKek_r_bytes = await deriveRecoveryKek(
        newRecoveryEntropy,
        newRecoveryHkdfSalt
      )
      const newKek_r = await importKek(newKek_r_bytes)

      const newRecoveryWrap = await wrapVaultKey(
        stagedRecovery.vk,
        newKek_r,
        "recovery",
        user.id
      )

      setStagedNewWraps({
        kdfSaltHex: bytesToHex(kdfSalt),
        kdfMemoryKiB,
        kdfIterations,
        kdfParallelism,
        masterWrappedKeyHex: bytesToHex(newMasterWrap.wrappedKey),
        masterWrapIvHex: bytesToHex(newMasterWrap.iv),
        recoveryHkdfSaltHex: bytesToHex(newRecoveryHkdfSalt),
        recoveryWrappedKeyHex: bytesToHex(newRecoveryWrap.wrappedKey),
        recoveryWrapIvHex: bytesToHex(newRecoveryWrap.iv),
        newRecoveryKeyFormatted,
        newKekRaw,
      })

      setStep("confirm-new-key")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to derive new keys"
      toast.error(msg)
    } finally {
      setIsDerivingNewWraps(false)
    }
  }

  // Step 3: Confirm new recovery key before submitting
  const lastGroup = stagedNewWraps
    ? extractLastGroup(stagedNewWraps.newRecoveryKeyFormatted)
    : ""
  const isConfirmed =
    confirmationInput.trim().toUpperCase() === lastGroup.toUpperCase()

  function handleCompleteRecovery() {
    if (!stagedRecovery || !stagedNewWraps || !isConfirmed) return

    startTransition(async () => {
      try {
        const payload = {
          kdfSalt: stagedNewWraps.kdfSaltHex,
          kdfAlgorithm: "argon2id",
          kdfMemoryKiB: stagedNewWraps.kdfMemoryKiB,
          kdfIterations: stagedNewWraps.kdfIterations,
          kdfParallelism: stagedNewWraps.kdfParallelism,
          masterWrappedKey: stagedNewWraps.masterWrappedKeyHex,
          masterWrapIv: stagedNewWraps.masterWrapIvHex,
          recoveryHkdfSalt: stagedNewWraps.recoveryHkdfSaltHex,
          recoveryWrappedKey: stagedNewWraps.recoveryWrappedKeyHex,
          recoveryWrapIv: stagedNewWraps.recoveryWrapIvHex,
          expectedUpdatedAt: stagedRecovery.oldConfigUpdatedAt,
        }

        const res = await fetch("/api/vault/recover", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })

        if (!res.ok) {
          const err = await res.json()
          throw new Error(err.error || "Failed to commit recovery to server")
        }

        const resData = await res.json()

        // Unwrap session VK as non-extractable
        const kek = await importKek(stagedNewWraps.newKekRaw)
        const sessionVk = await unwrapVaultKey({
          wrappedKey: hexToBytes(stagedNewWraps.masterWrappedKeyHex),
          iv: hexToBytes(stagedNewWraps.masterWrapIvHex),
          kek,
          mode: "master",
          userId: user.id,
          extractable: false,
        })

        toast.success("Vault recovered successfully with new credentials!")

        setSessionUnlocked(sessionVk, {
          ...payload,
          autoLockMinutes: config?.autoLockMinutes ?? 5,
          updatedAt: resData.updatedAt,
          vaultKeyVersion: config?.vaultKeyVersion ?? 1,
          userId: user.id,
        })
        onComplete?.()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Recovery failed"
        toast.error(msg)
      }
    })
  }

  function handleCopyNewRecoveryKey() {
    if (!stagedNewWraps) return
    navigator.clipboard.writeText(stagedNewWraps.newRecoveryKeyFormatted)
    toast.success("New recovery key copied to clipboard")
  }

  function handleDownloadNewRecoveryKey() {
    if (!stagedNewWraps) return
    const text = [
      "CIPHER VAULT RECOVERY KEY (NEW)",
      "===============================",
      "",
      `Account: ${user.email}`,
      `Generated: ${new Date().toISOString()}`,
      "",
      `New Recovery Key: ${stagedNewWraps.newRecoveryKeyFormatted}`,
      "",
      "IMPORTANT:",
      "- Your old recovery key has been permanently invalidated.",
      "- This is the ONLY copy of your new recovery key.",
      "- Cipher does not store this key anywhere on the server.",
      "- Keep this file in a safe, offline location.",
    ].join("\n")

    const blob = new Blob([text], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `cipher-recovery-key-${user.email}.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("New recovery key downloaded")
  }

  if (step === "enter-key") {
    return (
      <Card className="mx-auto max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-amber-600" />
            <CardTitle>Recover Vault</CardTitle>
          </div>
          <CardDescription>
            Enter your 56-character recovery key to regain access to your vault.
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleVerifyRecoveryKey}>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="recovery-key-input">Recovery Key</Label>
              <Input
                id="recovery-key-input"
                type="text"
                placeholder="XXXX-XXXX-XXXX-..."
                value={recoveryKeyInput}
                onChange={(e) => setRecoveryKeyInput(e.target.value)}
                className="font-mono text-xs uppercase"
                disabled={isVerifyingKey}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Hyphens and spacing are optional. Common typos (O/0, I/1, L/1) are automatically corrected.
              </p>
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button
              type="submit"
              className="w-full"
              disabled={!recoveryKeyInput.trim() || isVerifyingKey}
            >
              {isVerifyingKey ? "Verifying..." : "Verify Recovery Key"}
            </Button>
            {onCancel && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={onCancel}
                disabled={isVerifyingKey}
              >
                Back to Master Password
              </Button>
            )}
          </CardFooter>
        </form>
      </Card>
    )
  }

  if (step === "new-password") {
    return (
      <Card className="mx-auto max-w-lg">
        <CardHeader>
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            <CardTitle>Set New Master Password</CardTitle>
          </div>
          <CardDescription>
            Your recovery key was successfully verified. Set a new master password for your vault.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Important</AlertTitle>
            <AlertDescription className="text-xs">
              Your previous master password will be completely replaced. A new recovery key will also be generated.
            </AlertDescription>
          </Alert>

          <div className="space-y-2">
            <Label htmlFor="new-master-password">New Master Password (min. 12 characters)</Label>
            <Input
              id="new-master-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new master password"
            />
          </div>

          {newPassword.length > 0 && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span>Strength:</span>
                <span className="font-medium">
                  {strength.score >= 3 ? "Strong" : "Weak"} (Score {strength.score}/4)
                </span>
              </div>
              <div className="grid grid-cols-4 gap-1 h-1.5">
                {[0, 1, 2, 3].map((level) => (
                  <div
                    key={level}
                    className={`rounded-full ${
                      strength.score > level
                        ? strength.score >= 3
                          ? "bg-emerald-500"
                          : "bg-amber-500"
                        : "bg-muted"
                    }`}
                  />
                ))}
              </div>
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="confirm-new-master-password">Confirm New Password</Label>
            <Input
              id="confirm-new-master-password"
              type="password"
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              placeholder="Confirm new master password"
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-2">
          <Button
            className="w-full"
            disabled={!isNewPasswordValid || isDerivingNewWraps}
            onClick={handlePrepareNewWraps}
          >
            {isDerivingNewWraps ? "Generating New Keys..." : "Continue to New Recovery Key"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setStep("enter-key")}
            disabled={isDerivingNewWraps}
          >
            Back
          </Button>
        </CardFooter>
      </Card>
    )
  }

  // Step 3: Show & confirm new recovery key before submitting to server
  return (
    <Card className="mx-auto max-w-lg">
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-emerald-600" />
          <CardTitle>Save Your NEW Recovery Key</CardTitle>
        </div>
        <CardDescription>
          Your old recovery key has been invalidated. You MUST save this new key now.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-lg border bg-muted/40 p-4 font-mono text-center text-sm font-semibold tracking-wider select-all break-all">
          {stagedNewWraps?.newRecoveryKeyFormatted}
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            className="flex-1"
            size="sm"
            onClick={handleCopyNewRecoveryKey}
          >
            <Copy className="mr-2 h-4 w-4" /> Copy Key
          </Button>
          <Button
            variant="outline"
            className="flex-1"
            size="sm"
            onClick={handleDownloadNewRecoveryKey}
          >
            <Download className="mr-2 h-4 w-4" /> Download .txt
          </Button>
        </div>

        <div className="space-y-2 pt-2">
          <Label htmlFor="confirm-new-recovery">
            Confirm by typing the last 4 characters ({lastGroup}):
          </Label>
          <Input
            id="confirm-new-recovery"
            type="text"
            maxLength={4}
            value={confirmationInput}
            onChange={(e) => setConfirmationInput(e.target.value.toUpperCase())}
            placeholder={lastGroup}
            className="font-mono text-center tracking-widest uppercase"
          />
        </div>
      </CardContent>
      <CardFooter className="flex flex-col gap-2">
        <Button
          className="w-full"
          disabled={!isConfirmed || isPending}
          onClick={handleCompleteRecovery}
        >
          {isPending ? "Restoring Vault..." : "Complete Vault Recovery"}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={isPending}
          onClick={() => setStep("new-password")}
        >
          Back
        </Button>
      </CardFooter>
    </Card>
  )
}
