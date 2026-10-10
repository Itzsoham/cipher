"use client"

import Link from "next/link"
import { useVault } from "@/hooks/use-vault"
import { Button } from "@cipher/ui/components/button"
import { Lock, Settings, ShieldCheck } from "lucide-react"

export function VaultStatusBar() {
  const { status, autoLockMinutes, lockVault } = useVault()

  if (status !== "unlocked") return null

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border bg-card/60 px-4 py-3 shadow-sm backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span
              data-testid="vault-unlocked-status"
              className="text-xs font-semibold tracking-wide uppercase text-emerald-600 dark:text-emerald-400"
            >
              Vault Unlocked
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Auto-locks after {autoLockMinutes} min of inactivity
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" asChild>
          <Link href="/vault/settings">
            <Settings className="mr-1.5 h-3.5 w-3.5" />
            Settings
          </Link>
        </Button>
        <Button
          variant="destructive"
          size="sm"
          onClick={lockVault}
          className="gap-1.5"
        >
          <Lock className="h-3.5 w-3.5" />
          Lock Vault
        </Button>
      </div>
    </div>
  )
}
