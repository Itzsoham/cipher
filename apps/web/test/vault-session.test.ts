import { describe, expect, it } from "vitest"
import { VaultSession } from "@/lib/vault/vault-session"

describe("VaultSession in-memory management", () => {
  it("starts locked with null key", () => {
    const session = new VaultSession()
    expect(session.isLocked()).toBe(true)
    expect(session.getVk()).toBeNull()
  })

  it("stores unlocked key and updates activity timestamp", async () => {
    const session = new VaultSession()
    const mockKey = {} as CryptoKey

    session.unlock(mockKey, 5)
    expect(session.isLocked()).toBe(false)
    expect(session.getVk()).toBe(mockKey)
    expect(session.lastActivityTimestamp).toBeGreaterThan(0)
  })

  it("drops key and resets timestamp on lock()", () => {
    const session = new VaultSession()
    session.unlock({} as CryptoKey, 5)

    session.lock()
    expect(session.isLocked()).toBe(true)
    expect(session.getVk()).toBeNull()
    expect(session.lastActivityTimestamp).toBe(0)
  })

  it("detects idle timeout", () => {
    const session = new VaultSession()
    session.unlock({} as CryptoKey, 5)

    // Simulate idle time beyond 5 minutes
    session.lastActivityTimestamp = Date.now() - 6 * 60 * 1000

    expect(session.isLocked()).toBe(true)
    // getVk() should auto-lock when expired
    expect(session.getVk()).toBeNull()
  })
})
