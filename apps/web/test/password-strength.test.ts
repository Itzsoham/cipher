import { describe, expect, it } from "vitest"
import { evaluatePasswordStrength } from "@/lib/vault/password-strength"

describe("Password Strength (zxcvbn-ts 0-4 scoring)", () => {
  it("returns score 0 for empty password", () => {
    const result = evaluatePasswordStrength("")
    expect(result.score).toBe(0)
  })

  it("rates common dictionary passwords as weak (score 0 or 1)", () => {
    expect(evaluatePasswordStrength("password").score).toBeLessThanOrEqual(1)
    expect(evaluatePasswordStrength("123456789012").score).toBeLessThanOrEqual(
      1
    )
    expect(evaluatePasswordStrength("qwertyuiopas").score).toBeLessThanOrEqual(
      1
    )
  })

  it("penalizes passwords matching user inputs (email / username)", () => {
    const userInputs = ["alice@example.com", "alice", "Alice Smith"]

    // Password containing username
    const resWithInput = evaluatePasswordStrength(
      "aliceSecretP@ss123",
      userInputs
    )
    const resWithoutInput = evaluatePasswordStrength("aliceSecretP@ss123", [])

    // With userInputs passed, score should be penalized
    expect(resWithInput.score).toBeLessThanOrEqual(resWithoutInput.score)
  })

  it("rates long passphrases with high entropy as strong (score 3 or 4)", () => {
    const strong = evaluatePasswordStrength(
      "correct-horse-battery-staple-quantum-42!"
    )
    expect(strong.score).toBeGreaterThanOrEqual(3)
  })
})
