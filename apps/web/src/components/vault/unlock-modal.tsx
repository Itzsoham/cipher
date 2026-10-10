"use client"

import { useState } from "react"
import { toast } from "sonner"
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
import { useVault } from "@/hooks/use-vault"
import { KeyRound, Lock, Loader2 } from "lucide-react"

interface UnlockModalProps {
  onSwitchToRecovery?: () => void
}

export function UnlockModal({ onSwitchToRecovery }: UnlockModalProps) {
  const { unlockWithPassword } = useVault()
  const [password, setPassword] = useState("")
  const [isUnlocking, setIsUnlocking] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault()
    if (!password || isUnlocking) return

    setIsUnlocking(true)
    setError(null)
    try {
      await unlockWithPassword(password)
      toast.success("Vault unlocked")
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to unlock vault"
      setError(msg)
      toast.error(msg)
    } finally {
      setIsUnlocking(false)
    }
  }

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-primary" />
          <CardTitle>Unlock Your Vault</CardTitle>
        </div>
        <CardDescription>
          Enter your master password to decrypt your session Vault Key.
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleUnlock}>
        <CardContent className="space-y-4">
          {error && (
            <div className="rounded-md bg-destructive/15 p-3 text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="unlock-password">Master Password</Label>
            <Input
              id="unlock-password"
              type="password"
              placeholder="Enter master password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isUnlocking}
              autoFocus
              autoComplete="current-password"
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-3">
          <Button
            type="submit"
            className="w-full"
            disabled={!password || isUnlocking}
          >
            {isUnlocking ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Unlocking Vault...
              </>
            ) : (
              <>
                <KeyRound className="mr-2 h-4 w-4" />
                Unlock Vault
              </>
            )}
          </Button>

          {onSwitchToRecovery && (
            <Button
              type="button"
              variant="link"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={onSwitchToRecovery}
              disabled={isUnlocking}
            >
              Forgot master password? Use recovery key
            </Button>
          )}
        </CardFooter>
      </form>
    </Card>
  )
}
