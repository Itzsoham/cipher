export type VaultSyncMessage = {
  type: "LOCK" | "UNLOCK" | "ACTIVITY"
  timestamp: number
}

/**
 * Cross-tab synchronization via BroadcastChannel("cipher-vault").
 * Coordinates lock/unlock states and throttled activity notifications.
 */
export class VaultSync {
  private channel: BroadcastChannel | null = null
  private onLockCallback?: () => void
  private onUnlockCallback?: () => void
  private onActivityCallback?: () => void

  constructor() {
    if (
      typeof window !== "undefined" &&
      typeof BroadcastChannel !== "undefined"
    ) {
      this.channel = new BroadcastChannel("cipher-vault")
      this.channel.onmessage = this.handleMessage.bind(this)
    }
  }

  private handleMessage(event: MessageEvent<VaultSyncMessage>) {
    const data = event.data
    if (!data || typeof data !== "object") return

    switch (data.type) {
      case "LOCK":
        this.onLockCallback?.()
        break
      case "UNLOCK":
        this.onUnlockCallback?.()
        break
      case "ACTIVITY":
        this.onActivityCallback?.()
        break
    }
  }

  broadcastLock() {
    this.channel?.postMessage({ type: "LOCK", timestamp: Date.now() })
  }

  broadcastUnlock() {
    this.channel?.postMessage({ type: "UNLOCK", timestamp: Date.now() })
  }

  broadcastActivity() {
    this.channel?.postMessage({ type: "ACTIVITY", timestamp: Date.now() })
  }

  onLock(callback: () => void) {
    this.onLockCallback = callback
  }

  onUnlock(callback: () => void) {
    this.onUnlockCallback = callback
  }

  onActivity(callback: () => void) {
    this.onActivityCallback = callback
  }

  close() {
    this.channel?.close()
    this.channel = null
  }
}
