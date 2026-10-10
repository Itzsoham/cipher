"use client"

import React, {
  createContext,
  useEffect,
  useState,
  useCallback,
  useRef,
} from "react"
import { importKek, unwrapVaultKey, validateKdfParams } from "@cipher/crypto"
import { VaultSession } from "@/lib/vault/vault-session"
import { VaultSync } from "@/lib/vault/vault-sync"
import { deriveKeyWithWorker } from "@/lib/vault/worker-client"
import { hexToBytes } from "@/lib/vault/hex"

export type VaultStatus = "loading" | "uninitialized" | "locked" | "unlocked"

export interface SerializedVaultConfig {
  kdfSalt: string
  kdfAlgorithm: string
  kdfMemoryKiB: number
  kdfIterations: number
  kdfParallelism: number
  masterWrappedKey: string
  masterWrapIv: string
  recoveryHkdfSalt: string
  recoveryWrappedKey: string
  recoveryWrapIv: string
  autoLockMinutes: number
  updatedAt: string
  vaultKeyVersion: number
  userId: string
}

export interface VaultContextType {
  status: VaultStatus
  config: SerializedVaultConfig | null
  sessionVK: CryptoKey | null
  autoLockMinutes: number
  refreshConfig: () => Promise<SerializedVaultConfig | null>
  unlockWithPassword: (password: string) => Promise<void>
  lockVault: () => void
  setSessionUnlocked: (
    vk: CryptoKey,
    updatedConfig?: SerializedVaultConfig
  ) => void
  updateAutoLockMinutes: (minutes: number) => Promise<void>
}

export const VaultContext = createContext<VaultContextType | undefined>(undefined)

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<VaultStatus>("loading")
  const [config, setConfig] = useState<SerializedVaultConfig | null>(null)
  const [sessionVK, setSessionVK] = useState<CryptoKey | null>(null)
  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(5)

  const vaultSessionRef = useRef<VaultSession>(new VaultSession())
  const vaultSyncRef = useRef<VaultSync | null>(null)
  const lastBroadcastActivityRef = useRef<number>(0)

  // Initialize VaultSync
  useEffect(() => {
    const sync = new VaultSync()
    vaultSyncRef.current = sync

    sync.onLock(() => {
      vaultSessionRef.current.lock()
      setSessionVK(null)
      setStatus((prev) => (prev === "unlocked" ? "locked" : prev))
    })

    sync.onActivity(() => {
      vaultSessionRef.current.refreshActivity()
    })

    return () => {
      sync.close()
      vaultSyncRef.current = null
    }
  }, [])

  // Fetch initial VaultConfig
  const refreshConfig = useCallback(async (): Promise<SerializedVaultConfig | null> => {
    try {
      const res = await fetch("/api/vault/config")
      if (res.status === 404) {
        setConfig(null)
        setStatus("uninitialized")
        return null
      }
      if (!res.ok) {
        throw new Error("Failed to fetch vault config")
      }
      const data: SerializedVaultConfig = await res.json()
      setConfig(data)
      setAutoLockMinutes(data.autoLockMinutes || 5)
      setStatus((prev) => (prev === "unlocked" ? "unlocked" : "locked"))
      return data
    } catch {
      setStatus("uninitialized")
      return null
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refreshConfig()
  }, [refreshConfig])

  // Lock helper
  const lockVault = useCallback(() => {
    vaultSessionRef.current.lock()
    setSessionVK(null)
    setStatus("locked")
    vaultSyncRef.current?.broadcastLock()
  }, [])

  // Unlock with password flow
  const unlockWithPassword = useCallback(
    async (password: string) => {
      let activeConfig = config
      if (!activeConfig) {
        activeConfig = await refreshConfig()
      }
      if (!activeConfig) {
        throw new Error("Vault is not initialized")
      }

      const salt = hexToBytes(activeConfig.kdfSalt)

      // S4 bounds check before derivation
      validateKdfParams({
        algorithm: activeConfig.kdfAlgorithm,
        memoryCost: activeConfig.kdfMemoryKiB,
        timeCost: activeConfig.kdfIterations,
        parallelism: activeConfig.kdfParallelism,
        salt,
      })

      // Derive KEK_m in worker
      const kekBytes = await deriveKeyWithWorker({
        password,
        salt,
        iterations: activeConfig.kdfIterations,
        memorySize: activeConfig.kdfMemoryKiB,
        parallelism: activeConfig.kdfParallelism,
        hashLength: 32,
      })

      const kek = await importKek(kekBytes)

      try {
        const vk = await unwrapVaultKey({
          wrappedKey: hexToBytes(activeConfig.masterWrappedKey),
          iv: hexToBytes(activeConfig.masterWrapIv),
          kek,
          mode: "master",
          userId: activeConfig.userId,
          extractable: false, // Session VK is strictly non-extractable
        })

        vaultSessionRef.current.unlock(vk, activeConfig.autoLockMinutes)
        setSessionVK(vk)
        setStatus("unlocked")
        vaultSyncRef.current?.broadcastUnlock()
      } catch {
        throw new Error("Incorrect master password")
      }
    },
    [config, refreshConfig]
  )

  // Direct unlock setter (e.g. after setup wizard or recovery wizard)
  const setSessionUnlocked = useCallback(
    (vk: CryptoKey, updatedConfig?: SerializedVaultConfig) => {
      if (updatedConfig) {
        setConfig(updatedConfig)
        setAutoLockMinutes(updatedConfig.autoLockMinutes)
      }
      const minutes = updatedConfig?.autoLockMinutes ?? autoLockMinutes
      vaultSessionRef.current.unlock(vk, minutes)
      setSessionVK(vk)
      setStatus("unlocked")
      vaultSyncRef.current?.broadcastUnlock()
    },
    [autoLockMinutes]
  )

  // Update auto-lock settings
  const updateAutoLockMinutes = useCallback(async (minutes: number) => {
    const res = await fetch("/api/vault/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ autoLockMinutes: minutes }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.error || "Failed to update settings")
    }
    const data = await res.json()
    setAutoLockMinutes(data.autoLockMinutes)
    setConfig((prev) =>
      prev ? { ...prev, autoLockMinutes: data.autoLockMinutes } : null
    )
    vaultSessionRef.current.autoLockMinutes = data.autoLockMinutes
  }, [])

  // User activity listeners (throttled)
  useEffect(() => {
    const handleActivity = () => {
      vaultSessionRef.current.refreshActivity()
      const now = Date.now()
      if (now - lastBroadcastActivityRef.current > 15000) {
        lastBroadcastActivityRef.current = now
        vaultSyncRef.current?.broadcastActivity()
      }
    }

    window.addEventListener("keydown", handleActivity, { passive: true })
    window.addEventListener("mousedown", handleActivity, { passive: true })
    window.addEventListener("touchstart", handleActivity, { passive: true })
    window.addEventListener("scroll", handleActivity, { passive: true })

    return () => {
      window.removeEventListener("keydown", handleActivity)
      window.removeEventListener("mousedown", handleActivity)
      window.removeEventListener("touchstart", handleActivity)
      window.removeEventListener("scroll", handleActivity)
    }
  }, [])

  // Sleep-safe idle checking interval & visibility listener
  useEffect(() => {
    const checkLockState = () => {
      if (status === "unlocked" && vaultSessionRef.current.isLocked()) {
        lockVault()
      }
    }

    const interval = setInterval(checkLockState, 5000)

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        checkLockState()
      }
    }

    window.addEventListener("focus", checkLockState)
    document.addEventListener("visibilitychange", handleVisibilityChange)

    return () => {
      clearInterval(interval)
      window.removeEventListener("focus", checkLockState)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [status, lockVault])

  return (
    <VaultContext.Provider
      value={{
        status,
        config,
        sessionVK,
        autoLockMinutes,
        refreshConfig,
        unlockWithPassword,
        lockVault,
        setSessionUnlocked,
        updateAutoLockMinutes,
      }}
    >
      {children}
    </VaultContext.Provider>
  )
}
