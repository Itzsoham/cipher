"use client"

import { useState } from "react"
import { useVault } from "@/hooks/use-vault"
import { SetupWizard } from "@/components/vault/setup-wizard"
import { UnlockModal } from "@/components/vault/unlock-modal"
import { RecoveryWizard } from "@/components/vault/recovery-wizard"
import { VaultStatusBar } from "@/components/vault/vault-status-bar"
import { Loader2, Shield } from "lucide-react"

interface VaultViewProps {
  user: {
    id: string
    email: string
    name?: string | null
  }
}

export function VaultView({ user }: VaultViewProps) {
  const { status } = useVault()
  const [showRecovery, setShowRecovery] = useState(false)

  if (status === "loading") {
    return (
      <div className="flex min-h-[40vh] flex-col items-center justify-center gap-3 text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
        <p className="text-sm">Connecting to secure vault...</p>
      </div>
    )
  }

  if (status === "uninitialized") {
    return <SetupWizard user={user} />
  }

  if (status === "locked") {
    if (showRecovery) {
      return (
        <RecoveryWizard user={user} onCancel={() => setShowRecovery(false)} />
      )
    }
    return <UnlockModal onSwitchToRecovery={() => setShowRecovery(true)} />
  }

  // Unlocked state (Phase 3 Dashboard)
  return (
    <div className="space-y-6">
      <VaultStatusBar />

      <div className="rounded-2xl border border-dashed p-8 text-center sm:p-12">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Shield className="h-6 w-6" />
        </div>
        <h2 className="mt-4 text-lg font-semibold">
          Your Zero-Knowledge Vault is Ready
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">
          Your Vault Key is decrypted in client memory with AES-256-GCM. Entry
          encryption and management arrive in Phase 4.
        </p>
        <p className="mt-4 text-xs text-muted-foreground">
          Test auto-lock by leaving this tab idle, or use the Settings page to
          test password change and recovery key rotation.
        </p>
      </div>
    </div>
  )
}
