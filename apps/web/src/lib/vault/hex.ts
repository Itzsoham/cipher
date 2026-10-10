/**
 * Helpers for converting between hex strings and Uint8Array<ArrayBuffer>.
 */

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.trim().toLowerCase()
  if (clean.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd number of characters")
  }
  const length = clean.length / 2
  const buf = new Uint8Array(new ArrayBuffer(length))
  for (let i = 0; i < length; i++) {
    const byte = parseInt(clean.substring(i * 2, i * 2 + 2), 16)
    if (isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i * 2}`)
    }
    buf[i] = byte
  }
  return buf
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = ""
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0")
  }
  return hex
}
