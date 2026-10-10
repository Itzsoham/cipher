const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const DECODE_MAP: Record<string, number> = {}

for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
  DECODE_MAP[CROCKFORD_ALPHABET.charAt(i)] = i
}

// Typo correction aliases per Crockford base32 spec
DECODE_MAP["O"] = 0
DECODE_MAP["I"] = 1
DECODE_MAP["L"] = 1

function encodeBase32(buffer: Uint8Array): string {
  let bits = 0
  let value = 0
  let output = ""

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]!
    bits += 8
    while (bits >= 5) {
      output += CROCKFORD_ALPHABET.charAt((value >>> (bits - 5)) & 31)
      bits -= 5
    }
  }
  if (bits > 0) {
    output += CROCKFORD_ALPHABET.charAt((value << (5 - bits)) & 31)
  }
  return output
}

function decodeBase32(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/[-\s]/g, "")
  if (cleaned.length !== 56) {
    throw new Error(
      `Invalid recovery key length: expected 56 characters, got ${cleaned.length}`
    )
  }

  let bits = 0
  let value = 0
  const output: number[] = []

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned.charAt(i)
    const decoded = DECODE_MAP[char]
    if (decoded === undefined) {
      throw new Error(`Invalid character in recovery key: "${char}"`)
    }
    value = (value << 5) | decoded
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }

  if (output.length !== 35) {
    throw new Error(`Invalid decoded byte length: expected 35, got ${output.length}`)
  }

  return new Uint8Array(output)
}

/**
 * Encodes 32-byte entropy into a 56-character formatted recovery key with a 24-bit SHA-256 checksum.
 * Groups the output into 14 groups of 4 characters separated by hyphens.
 */
export async function formatRecoveryKey(entropy: Uint8Array): Promise<string> {
  if (entropy.byteLength !== 32) {
    throw new Error(`Recovery key entropy must be 32 bytes, got ${entropy.byteLength}`)
  }

  const hashBuffer = await crypto.subtle.digest("SHA-256", entropy as BufferSource)
  const checksum = new Uint8Array(hashBuffer).slice(0, 3)

  const combined = new Uint8Array(35)
  combined.set(entropy)
  combined.set(checksum, 32)

  const encoded = encodeBase32(combined)

  const groups: string[] = []
  for (let i = 0; i < encoded.length; i += 4) {
    groups.push(encoded.slice(i, i + 4))
  }
  return groups.join("-")
}

/**
 * Generates a fresh random 32-byte recovery key and formats it into 14 groups of 4.
 */
export async function generateRecoveryKey(): Promise<{
  formatted: string
  entropy: Uint8Array
}> {
  const entropy = crypto.getRandomValues(new Uint8Array(32))
  const formatted = await formatRecoveryKey(entropy)
  return { formatted, entropy }
}

/**
 * Parses and verifies a formatted recovery key string.
 * Strips hyphens and whitespace, applies Crockford typo corrections (O->0, I/L->1),
 * verifies the 24-bit SHA-256 checksum, and returns the 32-byte entropy.
 *
 * @throws Error if character set, length, or checksum is invalid.
 */
export async function parseRecoveryKey(key: string): Promise<Uint8Array> {
  const combined = decodeBase32(key)
  const entropy = combined.slice(0, 32)
  const checksum = combined.slice(32, 35)

  const hashBuffer = await crypto.subtle.digest("SHA-256", entropy as BufferSource)
  const expectedChecksum = new Uint8Array(hashBuffer).slice(0, 3)

  for (let i = 0; i < 3; i++) {
    if (checksum[i] !== expectedChecksum[i]) {
      throw new Error(
        "Checksum validation failed. Please check for typos in your recovery key."
      )
    }
  }

  return entropy
}

/**
 * Helper to extract the last 4 characters from a formatted recovery key.
 */
export function extractLastGroup(formattedKey: string): string {
  const cleaned = formattedKey.toUpperCase().replace(/[-\s]/g, "")
  return cleaned.slice(-4)
}
