import { describe, expect, it } from "vitest"

import { CRYPTO_VERSION } from "../src/index"

// Placeholder until the Phase 2 crypto tests land.
describe("@cipher/crypto", () => {
  it("exports the crypto version", () => {
    expect(CRYPTO_VERSION).toBe(1)
  })
})
