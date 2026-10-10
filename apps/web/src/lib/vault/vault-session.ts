/**
 * In-memory non-extractable CryptoKey holder for the active vault session.
 * The raw key bytes are NEVER stored in localStorage, sessionStorage, or cookies.
 */
export class VaultSession {
  private vk: CryptoKey | null = null
  public lastActivityTimestamp: number = 0
  public autoLockMinutes: number = 5

  unlock(vk: CryptoKey, autoLockMinutes: number): void {
    this.vk = vk
    this.autoLockMinutes = autoLockMinutes > 0 ? autoLockMinutes : 5
    this.refreshActivity()
  }

  lock(): void {
    this.vk = null
    this.lastActivityTimestamp = 0
  }

  getVk(): CryptoKey | null {
    if (this.isLocked()) {
      this.lock()
      return null
    }
    return this.vk
  }

  refreshActivity(): void {
    this.lastActivityTimestamp = Date.now()
  }

  isLocked(): boolean {
    if (!this.vk) return true
    if (this.autoLockMinutes <= 0) return false

    const now = Date.now()
    const autoLockMs = this.autoLockMinutes * 60 * 1000
    // Sleep-safe idle check: locks if idle timeout expired or system time drifted
    if (
      now < this.lastActivityTimestamp ||
      now - this.lastActivityTimestamp >= autoLockMs
    ) {
      return true
    }
    return false
  }
}
