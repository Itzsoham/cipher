import { createHmac } from "node:crypto"

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function base32Decode(input: string) {
  const clean = input.replace(/=+$/, "").toUpperCase()
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of clean) {
    const index = BASE32.indexOf(char)
    if (index === -1) throw new Error(`Invalid base32 character: ${char}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), matching Better Auth's defaults. */
export function totp(secret: string, now = Date.now()) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 1000 / 30)))
  const hmac = createHmac("sha1", base32Decode(secret)).update(counter).digest()
  const offset = hmac[hmac.length - 1]! & 0x0f
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000
  return code.toString().padStart(6, "0")
}
