import { describe, expect, it } from "vitest"
import { hexToBytes, bytesToHex } from "@/lib/vault/hex"

describe("Hex utilities", () => {
  it("round-trips random bytes to hex and back", () => {
    const orig = crypto.getRandomValues(new Uint8Array(32))
    const hex = bytesToHex(orig)
    expect(hex).toHaveLength(64)
    expect(hex).toMatch(/^[0-9a-f]{64}$/)

    const decoded = hexToBytes(hex)
    expect(decoded).toEqual(orig)
  })

  it("handles empty arrays", () => {
    expect(bytesToHex(new Uint8Array(0))).toBe("")
    expect(hexToBytes("")).toEqual(new Uint8Array(0))
  })

  it("throws on invalid hex lengths or characters", () => {
    expect(() => hexToBytes("abc")).toThrow(/odd number of characters/)
    expect(() => hexToBytes("zz")).toThrow(/Invalid hex character/)
  })
})
