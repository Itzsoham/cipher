"use client"

import { useState } from "react"
import { toast } from "sonner"
import {
  importKek,
  unwrapVaultKey,
  wrapVaultKey,
  validateKdfParams,
} from "@cipher/crypto"
import { Button } from "@cipher/ui/components/button"
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
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
import { evaluatePasswordStrength } from "@/lib/vault/password-strength"
import { deriveKeyWithWorker } from "@/lib/vault/worker-client"
import { hexToBytes, bytesToHex } from "@/lib/vault/hex"
import { KeyRound, Loader2 } from "lucide-react"

export function ChangePasswordModal() {
  const { config, setSessionUnlocked } = useVault()

  const [open, setOpen] = useState(false)
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  const strength = evaluatePasswordStrength(newPassword)
  const passwordsMatch = newPassword.length > 0 && newPassword === confirmPassword
  const isValid =
    currentPassword.length > 0 &&
    newPassword.length >= 12 &&
    passwordsMatch &&
    strength.score >= 3

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!config || !isValid || isSubmitting) return

    setIsSubmitting(true)
    try {
      const oldSalt = hexToBytes(config.kdfSalt)
      validateKdfParams({
        algorithm: config.kdfAlgorithm,
        memoryCost: config.kdfMemoryKiB,
        timeCost: config.kdfIterations,
        parallelism: config.kdfParallelism,
        salt: oldSalt,
      })

      // 1. Derive old KEK_m
      const oldKekRaw = await deriveKeyWithWorker({
        password: currentPassword,
        salt: oldSalt,
        iterations: config.kdfIterations,
        memorySize: config.kdfMemoryKiB,
        parallelism: config.kdfParallelism,
        hashLength: 32,
      })
      const oldKek = await importKek(oldKekRaw)

      // 2. Unwrap extractable VK for re-wrapping
      let extractableVk: CryptoKey
      try {
        extractableVk = await unwrapVaultKey({
          wrappedKey: hexToBytes(config.masterWrappedKey),
          iv: hexToBytes(config.masterWrapIv),
          kek: oldKek,
          mode: "master",
          userId: config.userId,
          extractable: true,
        })
      } catch {
        throw new Error("Current master password is incorrect")
      }

      // 3. Generate fresh 16-byte KDF salt & derive new KEK_m
      const newSalt = crypto.getRandomValues(new Uint8Array(16))
      const kdfMemoryKiB = 65536
      const kdfIterations = 3
      const kdfParallelism = 1

      const newKekRaw = await deriveKeyWithWorker({
        password: newPassword,
        salt: newSalt,
        iterations: kdfIterations,
        memorySize: kdfMemoryKiB,
        parallelism: kdfParallelism,
        hashLength: 32,
      })
      const newKek = await importKek(newKekRaw)

      // 4. Wrap VK under new KEK_m
      const newMasterWrap = await wrapVaultKey(
        extractableVk,
        newKek,
        "master",
        config.userId
      )

      // 5. Commit with atomic compare-and-swap
      const payload = {
        kdfSalt: bytesToHex(newSalt),
        kdfAlgorithm: "argon2id",
        kdfMemoryKiB,
        kdfIterations,
        kdfParallelism,
        masterWrappedKey: bytesToHex(newMasterWrap.wrappedKey),
        masterWrapIv: bytesToHex(newMasterWrap.iv),
        expectedUpdatedAt: config.updatedAt,
      }

      const res = await fetch("/api/vault/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || "Failed to update password on server")
      }

      const resData = await res.json()

      // 6. Unwrap session VK as non-extractable
      const sessionVk = await unwrapVaultKey({
        wrappedKey: newMasterWrap.wrappedKey,
        iv: newMasterWrap.iv,
        kek: newKek,
        mode: "master",
        userId: config.userId,
        extractable: false,
      })

      setSessionUnlocked(sessionVk, {
        ...config,
        ...payload,
        updatedAt: resData.updatedAt,
      })

      toast.success("Master password updated successfully")
      setOpen(false)
      setCurrentPassword("")
      setNewPassword("")
      setConfirmPassword("")
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to change master password"
      toast.error(msg)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <KeyRound className="mr-2 h-4 w-4" /> Change Master Password
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change Master Password</DialogTitle>
          <DialogDescription>
            Update your master password. Your vault entries do not need to be re-encrypted.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="current-master-password">Current Master Password</Label>
            <Input
              id="current-master-password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
              autoComplete="current-password"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="new-modal-password">New Master Password (min. 12 characters)</Label>
            <Input
              id="new-modal-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new master password"
              autoComplete="new-password"
              required
            />
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
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm-modal-password">Confirm New Password</Label>
            <Input
              id="confirm-modal-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new master password"
              autoComplete="new-password"
              required
            />
            {confirmPassword.length > 0 && !passwordsMatch && (
              <p className="text-xs text-destructive">Passwords do not match</p>
            )}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setOpen(false)}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={!isValid || isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Updating...
                </>
              ) : (
                "Save New Password"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
