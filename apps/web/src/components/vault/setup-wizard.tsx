"use client"

import { useState, useTransition } from "react"
import { toast } from "sonner"
import {
  generateVaultKey,
  wrapVaultKey,
  deriveRecoveryKek,
  unwrapVaultKey,
  importKek,
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
  evaluatePasswordStrength,
  type PasswordStrengthResult,
} from "@/lib/vault/password-strength"
import {
  generateRecoveryKey,
  extractLastGroup,
} from "@/lib/vault/recovery-key"
import { deriveKeyWithWorker } from "@/lib/vault/worker-client"
import { bytesToHex } from "@/lib/vault/hex"
import { AlertTriangle, Copy, Download, KeyRound, ShieldCheck } from "lucide-react"

interface SetupWizardProps {
  user: {
    id: string
    email: string
    name?: string | null
  }
}

interface GeneratedVaultData {
  kdfSaltHex: string
  kdfMemoryKiB: number
  kdfIterations: number
  kdfParallelism: number
  masterWrappedKeyHex: string
  masterWrapIvHex: string
  recoveryHkdfSaltHex: string
  recoveryWrappedKeyHex: string
  recoveryWrapIvHex: string
  recoveryKeyFormatted: string
  kekRaw: Uint8Array
}

export function SetupWizard({ user }: SetupWizardProps) {
  const { setSessionUnlocked } = useVault()

  const [step, setStep] = useState<"password" | "recovery">("password")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [confirmationInput, setConfirmationInput] = useState("")
  const [isGenerating, setIsGenerating] = useState(false)
  const [isPending, startTransition] = useTransition()

  const [generatedData, setGeneratedData] = useState<GeneratedVaultData | null>(null)

  const strength: PasswordStrengthResult = evaluatePasswordStrength(password, [
    user.email,
    user.name || "",
  ])

  const passwordsMatch = password.length > 0 && password === confirmPassword
  const isPasswordValid =
    password.length >= 12 && passwordsMatch && strength.score >= 3

  // Step 1 -> Step 2: Generate keys in memory and display recovery key
  async function handleProceedToRecovery() {
    if (!isPasswordValid) return

    setIsGenerating(true)
    try {
      // 1. Generate 16-byte random KDF salt
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const kdfMemoryKiB = 65536 // 64 MiB (S4 floor)
      const kdfIterations = 3
      const kdfParallelism = 1

      // 2. Derive KEK_m in worker
      const kekRaw = await deriveKeyWithWorker({
        password,
        salt,
        iterations: kdfIterations,
        memorySize: kdfMemoryKiB,
        parallelism: kdfParallelism,
        hashLength: 32,
      })
      const kek_m = await importKek(kekRaw)

      // 3. Generate extractable Vault Key
      const vk = await generateVaultKey()

      // 4. Wrap VK under KEK_m
      const masterWrap = await wrapVaultKey(vk, kek_m, "master", user.id)

      // 5. Generate recovery key (32 bytes entropy + 3-byte checksum)
      const { formatted: recoveryKeyFormatted, entropy: recoveryEntropy } =
        await generateRecoveryKey()

      // 6. Derive KEK_r via HKDF-SHA256 with fresh 32-byte salt
      const recoveryHkdfSalt = crypto.getRandomValues(new Uint8Array(32))
      const kek_r_bytes = await deriveRecoveryKek(recoveryEntropy, recoveryHkdfSalt)
      const kek_r = await importKek(kek_r_bytes)

      // 7. Wrap VK under KEK_r
      const recoveryWrap = await wrapVaultKey(vk, kek_r, "recovery", user.id)

      setGeneratedData({
        kdfSaltHex: bytesToHex(salt),
        kdfMemoryKiB,
        kdfIterations,
        kdfParallelism,
        masterWrappedKeyHex: bytesToHex(masterWrap.wrappedKey),
        masterWrapIvHex: bytesToHex(masterWrap.iv),
        recoveryHkdfSaltHex: bytesToHex(recoveryHkdfSalt),
        recoveryWrappedKeyHex: bytesToHex(recoveryWrap.wrappedKey),
        recoveryWrapIvHex: bytesToHex(recoveryWrap.iv),
        recoveryKeyFormatted,
        kekRaw,
      })

      setStep("recovery")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to generate vault keys"
      toast.error(msg)
    } finally {
      setIsGenerating(false)
    }
  }

  // Step 2 -> Commit: User has confirmed last group of recovery key
  const lastGroup = generatedData
    ? extractLastGroup(generatedData.recoveryKeyFormatted)
    : ""
  const isConfirmed =
    confirmationInput.trim().toUpperCase() === lastGroup.toUpperCase()

  function handleCompleteSetup() {
    if (!generatedData || !isConfirmed) return

    startTransition(async () => {
      try {
        const payload = {
          kdfSalt: generatedData.kdfSaltHex,
          kdfAlgorithm: "argon2id",
          kdfMemoryKiB: generatedData.kdfMemoryKiB,
          kdfIterations: generatedData.kdfIterations,
          kdfParallelism: generatedData.kdfParallelism,
          masterWrappedKey: generatedData.masterWrappedKeyHex,
          masterWrapIv: generatedData.masterWrapIvHex,
          recoveryHkdfSalt: generatedData.recoveryHkdfSaltHex,
          recoveryWrappedKey: generatedData.recoveryWrappedKeyHex,
          recoveryWrapIv: generatedData.recoveryWrapIvHex,
          autoLockMinutes: 5,
        }

        const res = await fetch("/api/vault/setup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })

        if (!res.ok) {
          const err = await res.json()
          throw new Error(err.error || "Failed to save vault setup")
        }

        const resData = await res.json()

        // Unwrap session VK as non-extractable
        const kek = await importKek(generatedData.kekRaw)
        const sessionVk = await unwrapVaultKey({
          wrappedKey: new Uint8Array(
            generatedData.masterWrappedKeyHex
              .match(/../g)!
              .map((b) => parseInt(b, 16))
          ),
          iv: new Uint8Array(
            generatedData.masterWrapIvHex
              .match(/../g)!
              .map((b) => parseInt(b, 16))
          ),
          kek,
          mode: "master",
          userId: user.id,
          extractable: false,
        })

        toast.success("Vault created successfully!")

        setSessionUnlocked(sessionVk, {
          ...payload,
          updatedAt: resData.updatedAt,
          vaultKeyVersion: 1,
          userId: user.id,
        })
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to complete setup"
        toast.error(msg)
      }
    })
  }

  function handleCopyRecoveryKey() {
    if (!generatedData) return
    navigator.clipboard.writeText(generatedData.recoveryKeyFormatted)
    toast.success("Recovery key copied to clipboard")
  }

  function handleDownloadRecoveryKey() {
    if (!generatedData) return
    const text = [
      "CIPHER VAULT RECOVERY KEY",
      "=========================",
      "",
      `Account: ${user.email}`,
      `Generated: ${new Date().toISOString()}`,
      "",
      `Recovery Key: ${generatedData.recoveryKeyFormatted}`,
      "",
      "IMPORTANT:",
      "- This is the ONLY copy of your recovery key.",
      "- Cipher does not store this key anywhere on the server.",
      "- If you lose your master password, this key is the only way to recover your vault.",
      "- Keep this file in a safe, offline location.",
    ].join("\n")

    const blob = new Blob([text], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `cipher-recovery-key-${user.email}.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("Recovery key downloaded")
  }

  if (step === "password") {
    return (
      <Card className="mx-auto max-w-lg">
        <CardHeader>
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            <CardTitle>Set Up Master Password</CardTitle>
          </div>
          <CardDescription>
            Your master password protects all secrets in your vault. It is never sent to the server.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Zero-Knowledge Security</AlertTitle>
            <AlertDescription className="text-xs">
              Your master password <strong>must differ</strong> from your account login password.
              Cipher cannot recover or reset your master password.
            </AlertDescription>
          </Alert>

          <div className="space-y-2">
            <Label htmlFor="master-password">Master Password (min. 12 characters)</Label>
            <Input
              id="master-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a strong master password"
              autoComplete="new-password"
            />
          </div>

          {password.length > 0 && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span>Strength:</span>
                <span className="font-medium">
                  {strength.score === 0 && "Very Weak"}
                  {strength.score === 1 && "Weak"}
                  {strength.score === 2 && "Fair"}
                  {strength.score === 3 && "Strong"}
                  {strength.score === 4 && "Very Strong"}
                  {" (Score " + strength.score + "/4)"}
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
              {strength.score < 3 && (
                <p className="text-xs text-muted-foreground">
                  Minimum score of 3 required. {strength.warning || "Use a longer passphrase with varied words."}
                </p>
              )}
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm Master Password</Label>
            <Input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your master password"
              autoComplete="new-password"
            />
            {confirmPassword.length > 0 && !passwordsMatch && (
              <p className="text-xs text-destructive">Passwords do not match</p>
            )}
          </div>
        </CardContent>
        <CardFooter>
          <Button
            className="w-full"
            disabled={!isPasswordValid || isGenerating}
            onClick={handleProceedToRecovery}
          >
            {isGenerating ? "Deriving Keys..." : "Continue to Recovery Key"}
          </Button>
        </CardFooter>
      </Card>
    )
  }

  // Step 2: Show and Confirm Recovery Key BEFORE committing!
  return (
    <Card className="mx-auto max-w-lg">
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-emerald-600" />
          <CardTitle>Save Your Recovery Key</CardTitle>
        </div>
        <CardDescription>
          If you ever forget your master password, this recovery key is the ONLY way to regain access to your vault.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-lg border bg-muted/40 p-4 font-mono text-center text-sm font-semibold tracking-wider select-all break-all">
          {generatedData?.recoveryKeyFormatted}
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            className="flex-1"
            size="sm"
            onClick={handleCopyRecoveryKey}
          >
            <Copy className="mr-2 h-4 w-4" /> Copy Key
          </Button>
          <Button
            variant="outline"
            className="flex-1"
            size="sm"
            onClick={handleDownloadRecoveryKey}
          >
            <Download className="mr-2 h-4 w-4" /> Download .txt
          </Button>
        </div>

        <Alert>
          <AlertTitle className="text-xs font-semibold">One-Time Display</AlertTitle>
          <AlertDescription className="text-xs">
            Cipher does not store this key anywhere. Save it in a secure location now.
          </AlertDescription>
        </Alert>

        <div className="space-y-2 pt-2">
          <Label htmlFor="confirm-recovery">
            Confirm by typing the last 4 characters ({lastGroup}):
          </Label>
          <Input
            id="confirm-recovery"
            type="text"
            maxLength={4}
            value={confirmationInput}
            onChange={(e) => setConfirmationInput(e.target.value.toUpperCase())}
            placeholder={lastGroup}
            className="font-mono text-center tracking-widest uppercase"
            autoComplete="off"
          />
          {confirmationInput.length > 0 && !isConfirmed && (
            <p className="text-xs text-destructive text-center">
              Characters do not match the last group of your recovery key.
            </p>
          )}
        </div>
      </CardContent>
      <CardFooter className="flex flex-col gap-2">
        <Button
          className="w-full"
          disabled={!isConfirmed || isPending}
          onClick={handleCompleteSetup}
        >
          {isPending ? "Creating Vault..." : "Complete Vault Setup"}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={isPending}
          onClick={() => setStep("password")}
        >
          Back
        </Button>
      </CardFooter>
    </Card>
  )
}
