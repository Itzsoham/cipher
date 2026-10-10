import { argon2id } from "hash-wasm"

export interface KdfWorkerRequest {
  password: string
  salt: Uint8Array
  iterations: number
  memorySize: number
  parallelism: number
  hashLength: number
}

self.onmessage = async (event: MessageEvent<KdfWorkerRequest>) => {
  try {
    const { password, salt, iterations, memorySize, parallelism, hashLength } =
      event.data

    const derivedKey = await argon2id({
      password,
      salt,
      iterations,
      memorySize,
      parallelism,
      hashLength,
      outputType: "binary",
    })

    // Extract raw ArrayBuffer slice for transferable postMessage
    const buffer = derivedKey.buffer.slice(
      derivedKey.byteOffset,
      derivedKey.byteOffset + derivedKey.byteLength
    )

    // Using [buffer] as transferable detaches it from the worker's accessible memory
    ;(
      self as unknown as {
        postMessage: (msg: unknown, transfer: Transferable[]) => void
      }
    ).postMessage({ derivedKey: buffer }, [buffer])
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : "Argon2id derivation failed"
    self.postMessage({ error: message })
  }
}
