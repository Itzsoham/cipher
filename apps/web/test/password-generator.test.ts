import { describe, expect, it } from "vitest"
import {
  generatePassword,
  generatePassphrase,
} from "../src/lib/vault/password-generator"

describe("Password Generator", () => {
  it("generates a password of the requested length", () => {
    const pw16 = generatePassword({ length: 16 })
    expect(pw16).toHaveLength(16)

    const pw32 = generatePassword({ length: 32 })
    expect(pw32).toHaveLength(32)
  })

  it("clamps password length between 8 and 64", () => {
    const tooShort = generatePassword({ length: 4 })
    expect(tooShort).toHaveLength(8)

    const tooLong = generatePassword({ length: 128 })
    expect(tooLong).toHaveLength(64)
  })

  it("filters ambiguous characters when requested", () => {
    const ambiguous = ["0", "O", "o", "1", "l", "I", "|"]
    for (let i = 0; i < 20; i++) {
      const pw = generatePassword({ length: 64, avoidAmbiguous: true })
      for (const char of ambiguous) {
        expect(pw).not.toContain(char)
      }
    }
  })

  it("generates Diceware passphrase with at least 6 words", () => {
    const passphrase = generatePassphrase({ wordCount: 6, separator: "-" })
    const words = passphrase.split("-")
    expect(words).toHaveLength(6)
    for (const w of words) {
      expect(w.length).toBeGreaterThan(0)
      expect(w).toMatch(/^[a-z]+$/)
    }
  })

  it("enforces minimum 6 words even if fewer requested", () => {
    const passphrase = generatePassphrase({ wordCount: 3, separator: " " })
    const words = passphrase.split(" ")
    expect(words).toHaveLength(6)
  })

  it("can capitalize words in passphrase", () => {
    const passphrase = generatePassphrase({ wordCount: 6, separator: "-", capitalize: true })
    const words = passphrase.split("-")
    for (const w of words) {
      expect(w[0]).toBe(w[0]?.toUpperCase())
    }
  })
})

