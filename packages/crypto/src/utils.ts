/**
 * Internal utility: coerce any Uint8Array to Uint8Array<ArrayBuffer>.
 *
 * TypeScript 5.9 made Uint8Array generic. WebCrypto DOM types (BufferSource)
 * require Uint8Array<ArrayBuffer>, but TextEncoder.encode() and some other
 * browser APIs return Uint8Array<ArrayBufferLike>. This helper guarantees the
 * correct type by copying into a fresh ArrayBuffer-backed view when needed.
 *
 * The copy only happens if the underlying buffer is NOT a plain ArrayBuffer
 * (i.e. it is a SharedArrayBuffer), which in practice never occurs in this
 * codebase. The common case — crypto.getRandomValues, TextEncoder, slice —
 * all already return ArrayBuffer-backed views, so this is a zero-copy no-op
 * at runtime in virtually every call.
 */
export function ab(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  if (u8.buffer instanceof ArrayBuffer) {
    // Fast path: already the right type; cast is safe.
    return u8 as Uint8Array<ArrayBuffer>
  }
  // Slow path: copy (SharedArrayBuffer, which we never produce).
  const copy = new Uint8Array(new ArrayBuffer(u8.byteLength))
  copy.set(u8)
  return copy
}

/**
 * Allocate a fresh Uint8Array<ArrayBuffer> of the given length.
 * Use this instead of `new Uint8Array(n)` when the result must satisfy
 * WebCrypto's BufferSource parameter in TS 5.9+.
 */
export function allocBytes(length: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new ArrayBuffer(length))
}

/**
 * Fill a new Uint8Array<ArrayBuffer> with cryptographically random bytes.
 */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const buf = allocBytes(length)
  crypto.getRandomValues(buf)
  return buf
}
