import { argon2id } from "hash-wasm"

export interface KdfParams {
  password: string
  salt: Uint8Array
  iterations: number
  memorySize: number
  parallelism: number
  hashLength: number
}

/**
 * Derives a key using Argon2id via a dedicated Web Worker when supported,
 * transferring the resulting ArrayBuffer. Falls back to main-thread execution
 * in environments where Worker is unavailable (e.g. Node tests, SSR).
 */
export async function deriveKeyWithWorker(
  params: KdfParams
): Promise<Uint8Array> {
  if (typeof Worker === "undefined") {
    // Fallback for test / headless environments without Worker support
    const result = await argon2id({
      password: params.password,
      salt: params.salt,
      iterations: params.iterations,
      memorySize: params.memorySize,
      parallelism: params.parallelism,
      hashLength: params.hashLength,
      outputType: "binary",
    })
    return result
  }

  return new Promise((resolve, reject) => {
    try {
      const worker = new Worker(
        new URL("../../workers/kdf.worker.ts", import.meta.url),
        { type: "module" }
      )

      worker.onmessage = (event: MessageEvent) => {
        worker.terminate()
        if (event.data?.error) {
          reject(new Error(event.data.error))
        } else if (event.data?.derivedKey) {
          resolve(new Uint8Array(event.data.derivedKey))
        } else {
          reject(new Error("Worker returned invalid response"))
        }
      }

      worker.onerror = (error: ErrorEvent) => {
        worker.terminate()
        reject(
          new Error(error.message || "Failed to execute worker for Argon2id")
        )
      }

      worker.postMessage(params)
    } catch {
      // If worker instantiation fails (e.g. CSP blob restriction or sandboxing),
      // gracefully fall back to direct execution
      argon2id({
        password: params.password,
        salt: params.salt,
        iterations: params.iterations,
        memorySize: params.memorySize,
        parallelism: params.parallelism,
        hashLength: params.hashLength,
        outputType: "binary",
      })
        .then(resolve)
        .catch(reject)
    }
  })
}
