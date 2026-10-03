/**
 * Length-prefixed, bucketed padding — M12.
 *
 * Layout of the padded buffer (all bytes):
 *
 *   ┌──────────────────┬──────────────────────┬──────────────────────┐
 *   │  length (4 B BE) │  plaintext bytes …   │  zero padding …      │
 *   └──────────────────┴──────────────────────┴──────────────────────┘
 *
 * Total size = max(PADDING_MIN_BYTES, nextMultipleOf(PADDING_BUCKET_BYTES,
 *                  PADDING_HEADER_BYTES + plaintext.byteLength))
 *
 * The length field stores the number of plaintext bytes (not including the
 * 4-byte header), as a big-endian uint32. The zero bytes after the plaintext
 * are padding and are stripped on decode using the stored length.
 */

import {
  PADDING_BUCKET_BYTES,
  PADDING_HEADER_BYTES,
  PADDING_MIN_BYTES,
} from "./constants.js"

/**
 * Returns the padded size for a given plaintext length.
 * Exported so callers can size buffers without running the full pad.
 */
export function paddedSize(plaintextLength: number): number {
  const raw = PADDING_HEADER_BYTES + plaintextLength
  const bucketed =
    Math.ceil(raw / PADDING_BUCKET_BYTES) * PADDING_BUCKET_BYTES
  return Math.max(bucketed, PADDING_MIN_BYTES)
}

/**
 * Pads `plaintext` into a new `Uint8Array` using the scheme above.
 *
 * @param plaintext - The UTF-8 bytes to pad (already encoded by the caller).
 * @returns A new `Uint8Array` whose size is a multiple of `PADDING_BUCKET_BYTES`
 *          and at least `PADDING_MIN_BYTES`.
 */
export function pad(plaintext: Uint8Array): Uint8Array {
  const size = paddedSize(plaintext.byteLength)
  const buf = new Uint8Array(size)

  // Write 4-byte big-endian length prefix.
  const view = new DataView(buf.buffer)
  view.setUint32(0, plaintext.byteLength, false /* big-endian */)

  // Copy plaintext after the header; the rest stays zero (padding).
  buf.set(plaintext, PADDING_HEADER_BYTES)

  return buf
}

/**
 * Strips padding from a decrypted buffer, returning the original plaintext.
 *
 * @param padded - The decrypted buffer produced by `pad()` before encryption.
 * @throws {RangeError} if the buffer is too short or the stored length is
 *   larger than the buffer allows (indicates tampering or a bug).
 */
export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.byteLength < PADDING_MIN_BYTES) {
    throw new RangeError(
      `unpad: buffer too short (${padded.byteLength} B); minimum is ${PADDING_MIN_BYTES} B.`,
    )
  }

  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength)
  const length = view.getUint32(0, false /* big-endian */)

  const maxPlaintextLength = padded.byteLength - PADDING_HEADER_BYTES
  if (length > maxPlaintextLength) {
    throw new RangeError(
      `unpad: stored length ${length} exceeds available bytes ${maxPlaintextLength}; buffer may be tampered.`,
    )
  }

  // Return a copy so the caller doesn't hold a reference into the padded buffer.
  return padded.slice(PADDING_HEADER_BYTES, PADDING_HEADER_BYTES + length)
}
