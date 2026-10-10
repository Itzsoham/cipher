import { describe, expect, it } from "vitest"
import {
  generateRecoveryKey,
  parseRecoveryKey,
  formatRecoveryKey,
  extractLastGroup,
} from "@/lib/vault/recovery-key"

describe("Recovery Key (Crockford Base32 with 24-bit SHA-256 Checksum)", () => {
  it("generates a 56-character formatted recovery key in 14 groups of 4", async () => {
    const { formatted, entropy } = await generateRecoveryKey()

    expect(entropy.byteLength).toBe(32)
    const groups = formatted.split("-")
    expect(groups).toHaveLength(14)
    for (const group of groups) {
      expect(group).toHaveLength(4)
      expect(group).toMatch(/^[0-9A-HJKMNP-Z]{4}$/)
    }
  })

  it("round-trips generation and parsing without loss of entropy", async () => {
    const { formatted, entropy } = await generateRecoveryKey()
    const parsed = await parseRecoveryKey(formatted)

    expect(parsed).toEqual(entropy)
  })

  it("formatRecoveryKey formats deterministic 32-byte entropy correctly", async () => {
    const entropy = new Uint8Array(32).fill(42)
    const formatted = await formatRecoveryKey(entropy)

    const parsed = await parseRecoveryKey(formatted)
    expect(parsed).toEqual(entropy)
  })

  it("extractLastGroup extracts the last 4 characters", async () => {
    const { formatted } = await generateRecoveryKey()
    const last = extractLastGroup(formatted)
    const expected = formatted.split("-").pop()!

    expect(last).toBe(expected)
  })

  it("tolerates lowercase, spaces, and missing dashes", async () => {
    const { formatted, entropy } = await generateRecoveryKey()

    const noDashes = formatted.replace(/-/g, "").toLowerCase()
    expect(await parseRecoveryKey(noDashes)).toEqual(entropy)

    const withSpaces = formatted.replace(/-/g, " ")
    expect(await parseRecoveryKey(withSpaces)).toEqual(entropy)
  })

  it("corrects Crockford typos (O/o -> 0, I/i/L/l -> 1)", async () => {
    // Generate an entropy whose checksum passes, then replace a '0' with 'O' or '1' with 'I'
    const { formatted, entropy } = await generateRecoveryKey()

    if (formatted.includes("0")) {
      const typoO = formatted.replace("0", "O")
      expect(await parseRecoveryKey(typoO)).toEqual(entropy)
    }

    if (formatted.includes("1")) {
      const typoI = formatted.replace("1", "I")
      expect(await parseRecoveryKey(typoI)).toEqual(entropy)

      const typoL = formatted.replace("1", "L")
      expect(await parseRecoveryKey(typoL)).toEqual(entropy)
    }
  })

  it("fails when any single character is altered (checksum catches typo)", async () => {
    const { formatted } = await generateRecoveryKey()

    const raw = formatted.replace(/-/g, "")
    // Change first character
    const charToChange = raw[0]!
    const replacement = charToChange === "A" ? "B" : "A"
    const corrupted = replacement + raw.slice(1)

    await expect(parseRecoveryKey(corrupted)).rejects.toThrow(
      /Checksum validation failed/
    )
  })

  it("fails when two characters are swapped", async () => {
    const { formatted } = await generateRecoveryKey()

    const raw = formatted.replace(/-/g, "")
    // Find two different characters and swap them
    let idx1 = 0
    let idx2 = 1
    while (idx2 < raw.length && raw[idx1] === raw[idx2]) {
      idx2++
    }

    const chars = raw.split("")
    const tmp = chars[idx1]!
    chars[idx1] = chars[idx2]!
    chars[idx2] = tmp

    const swapped = chars.join("")
    await expect(parseRecoveryKey(swapped)).rejects.toThrow(
      /Checksum validation failed/
    )
  })

  it("rejects keys with invalid characters", async () => {
    await expect(
      parseRecoveryKey("INVALID-KEY-WITH-SYMBOLS!-$#@")
    ).rejects.toThrow()
  })

  it("rejects keys with incorrect lengths", async () => {
    await expect(parseRecoveryKey("SHORT-KEY")).rejects.toThrow(
      /Invalid recovery key length/
    )
  })
})
