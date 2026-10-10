"use client"

import { useState } from "react"
import Link from "next/link"
import { toast } from "sonner"
import { useVault } from "@/hooks/use-vault"
import { ChangePasswordModal } from "@/components/vault/change-password-modal"
import { RegenerateRecoveryModal } from "@/components/vault/regenerate-recovery-modal"
import { Button } from "@cipher/ui/components/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@cipher/ui/components/card"
import { Alert, AlertDescription, AlertTitle } from "@cipher/ui/components/alert"
import { Lock, ShieldAlert, Timer } from "lucide-react"

export default function VaultSettingsPage() {
  const { status, autoLockMinutes, updateAutoLockMinutes } = useVault()
  const [selectedMinutes, setSelectedMinutes] = useState<number>(autoLockMinutes)
  const [isUpdatingTimeout, setIsUpdatingTimeout] = useState(false)

  if (status !== "unlocked") {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-semibold">Vault Settings</h1>
          <p className="text-sm text-muted-foreground">
            Manage your master password, recovery key, and auto-lock preferences.
          </p>
        </div>

        <Alert variant="destructive">
          <Lock className="h-4 w-4" />
          <AlertTitle>Vault is Locked</AlertTitle>
          <AlertDescription className="text-xs">
            Your vault must be unlocked to modify vault security settings.
          </AlertDescription>
        </Alert>

        <Button asChild>
          <Link href="/vault">Return to Vault to Unlock</Link>
        </Button>
      </div>
    )
  }

  async function handleSaveTimeout() {
    setIsUpdatingTimeout(true)
    try {
      await updateAutoLockMinutes(selectedMinutes)
      toast.success("Auto-lock timeout updated")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update timeout"
      toast.error(msg)
    } finally {
      setIsUpdatingTimeout(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Vault Settings</h1>
        <p className="text-sm text-muted-foreground">
          Manage your master password, recovery key, and security preferences.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Auto-Lock Settings */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Timer className="h-5 w-5 text-primary" />
              <CardTitle>Auto-Lock Timeout</CardTitle>
            </div>
            <CardDescription>
              Automatically lock your vault after a period of user inactivity across any open tab.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {[1, 5, 10, 15, 30].map((mins) => (
                <Button
                  key={mins}
                  type="button"
                  size="sm"
                  variant={selectedMinutes === mins ? "default" : "outline"}
                  onClick={() => setSelectedMinutes(mins)}
                >
                  {mins} {mins === 1 ? "Minute" : "Minutes"}
                </Button>
              ))}
            </div>

            {selectedMinutes !== autoLockMinutes && (
              <Button
                size="sm"
                onClick={handleSaveTimeout}
                disabled={isUpdatingTimeout}
              >
                {isUpdatingTimeout ? "Saving..." : "Save Timeout Preference"}
              </Button>
            )}
          </CardContent>
        </Card>

        {/* Master Password Management */}
        <Card>
          <CardHeader>
            <CardTitle>Master Password</CardTitle>
            <CardDescription>
              Change your vault master password. This re-wraps your Vault Key without re-encrypting any stored data.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ChangePasswordModal />
          </CardContent>
        </Card>

        {/* Recovery Key Management */}
        <Card>
          <CardHeader>
            <CardTitle>Recovery Key</CardTitle>
            <CardDescription>
              Your 56-character recovery key is the only fallback if you forget your master password.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle className="text-xs font-semibold">Zero-Knowledge Architecture</AlertTitle>
              <AlertDescription className="text-xs">
                Cipher <strong>never stores your recovery key</strong>. It is held only in your offline records.
                If you lost your copy, regenerate a new one below while your vault is unlocked.
              </AlertDescription>
            </Alert>

            <RegenerateRecoveryModal />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
