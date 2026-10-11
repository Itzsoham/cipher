import { describe, expect, it } from "vitest"
import { isValidWebUrl, sanitizeWebUrl } from "../src/lib/vault/entry-types"

describe("Entry URL Safety & Validation", () => {
  it("allows valid https and http URLs", () => {
    expect(isValidWebUrl("https://example.com")).toBe(true)
    expect(isValidWebUrl("http://localhost:3000")).toBe(true)
    expect(isValidWebUrl("https://github.com/Itzsoham/cipher")).toBe(true)
  })

  it("rejects dangerous or unexpected schemes", () => {
    expect(isValidWebUrl("javascript:alert(1)")).toBe(false)
    expect(isValidWebUrl("data:text/html,<script>alert(1)</script>")).toBe(false)
    expect(isValidWebUrl("vbscript:msgbox(1)")).toBe(false)
    expect(isValidWebUrl("ftp://ftp.example.com")).toBe(false)
    expect(isValidWebUrl("file:///etc/passwd")).toBe(false)
  })

  it("rejects malformed or empty inputs", () => {
    expect(isValidWebUrl("")).toBe(false)
    expect(isValidWebUrl("   ")).toBe(false)
    expect(isValidWebUrl(undefined)).toBe(false)
    expect(isValidWebUrl("not a url")).toBe(false)
  })

  it("sanitizes URLs correctly", () => {
    expect(sanitizeWebUrl("  https://google.com  ")).toBe("https://google.com")
    expect(sanitizeWebUrl("javascript:alert(1)")).toBeNull()
  })
})

