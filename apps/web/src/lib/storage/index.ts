import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command,
  type ListObjectsV2CommandOutput,
} from "@aws-sdk/client-s3"
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"
import fs from "node:fs/promises"
import type { Dirent } from "node:fs"
import path from "node:path"
import crypto from "node:crypto"

export interface StorageDriver {
  getPresignedUploadUrl(params: {
    key: string
    contentLength: number
    expiresInSeconds: number
  }): Promise<{ uploadUrl: string }>

  getPresignedDownloadUrl(params: {
    key: string
    expiresInSeconds: number
  }): Promise<{ downloadUrl: string }>

  headObject(key: string): Promise<{ contentLength: number; exists: boolean }>

  deleteObject(key: string): Promise<void>

  deleteObjects(keys: string[]): Promise<{ deleted: string[]; failed: string[] }>

  listAllObjects(prefix: string): AsyncIterable<{ key: string; lastModified: Date }>
}

class R2StorageDriver implements StorageDriver {
  private client: S3Client
  private bucket: string

  constructor() {
    const accountId = process.env.R2_ACCOUNT_ID
    const accessKeyId = process.env.R2_ACCESS_KEY_ID
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY
    const bucket = process.env.R2_BUCKET_NAME
    const endpoint = process.env.R2_ENDPOINT

    if (!accountId || !accessKeyId || !secretAccessKey || !bucket || !endpoint) {
      throw new Error(
        "R2StorageDriver: Missing required R2 environment variables. " +
          "Ensure R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME, and R2_ENDPOINT are configured."
      )
    }

    this.bucket = bucket
    this.client = new S3Client({
      region: "auto",
      endpoint,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      forcePathStyle: false,
    })
  }

  async getPresignedUploadUrl(params: {
    key: string
    contentLength: number
    expiresInSeconds: number
  }): Promise<{ uploadUrl: string }> {
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: params.key,
      ContentType: "application/octet-stream",
    })

    const uploadUrl = await getSignedUrl(this.client, command, {
      expiresIn: params.expiresInSeconds,
    })

    return { uploadUrl }
  }

  async getPresignedDownloadUrl(params: {
    key: string
    expiresInSeconds: number
  }): Promise<{ downloadUrl: string }> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: params.key,
    })

    const downloadUrl = await getSignedUrl(this.client, command, {
      expiresIn: params.expiresInSeconds,
    })

    return { downloadUrl }
  }

  async headObject(key: string): Promise<{ contentLength: number; exists: boolean }> {
    try {
      const res = await this.client.send(
        new HeadObjectCommand({
          Bucket: this.bucket,
          Key: key,
        })
      )
      return {
        contentLength: res.ContentLength ?? 0,
        exists: true,
      }
    } catch (err: unknown) {
      const code = (err as { name?: string })?.name
      if (code === "NotFound" || code === "NoSuchKey") {
        return { contentLength: 0, exists: false }
      }
      throw err
    }
  }

  async deleteObject(key: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key,
      })
    )
  }

  async deleteObjects(keys: string[]): Promise<{ deleted: string[]; failed: string[] }> {
    if (keys.length === 0) return { deleted: [], failed: [] }

    // S3 allows max 1000 keys per request
    const chunks: string[][] = []
    for (let i = 0; i < keys.length; i += 1000) {
      chunks.push(keys.slice(i, i + 1000))
    }

    const deleted: string[] = []
    const failed: string[] = []

    for (const chunk of chunks) {
      const res = await this.client.send(
        new DeleteObjectsCommand({
          Bucket: this.bucket,
          Delete: {
            Objects: chunk.map((Key) => ({ Key })),
            Quiet: false,
          },
        })
      )
      if (res.Deleted) {
        deleted.push(...res.Deleted.map((d) => d.Key!).filter(Boolean))
      }
      if (res.Errors) {
        failed.push(...res.Errors.map((e) => e.Key!).filter(Boolean))
      }
    }

    return { deleted, failed }
  }

  async *listAllObjects(prefix: string): AsyncIterable<{ key: string; lastModified: Date }> {
    let continuationToken: string | undefined = undefined

    do {
      const res: ListObjectsV2CommandOutput = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: prefix,
          ContinuationToken: continuationToken,
        })
      )

      if (res.Contents) {
        for (const item of res.Contents) {
          if (item.Key && item.LastModified) {
            yield {
              key: item.Key,
              lastModified: item.LastModified,
            }
          }
        }
      }

      continuationToken = res.NextContinuationToken
    } while (continuationToken)
  }
}

class LocalStorageDriver implements StorageDriver {
  private baseDir: string
  private secret: string

  constructor(baseDir?: string, secret?: string) {
    this.baseDir = baseDir ?? path.resolve(process.cwd(), ".storage")
    this.secret =
      secret ??
      process.env.LOCAL_STORAGE_SECRET ??
      process.env.BETTER_AUTH_SECRET ??
      "cipher-local-storage-dev-secret-32-bytes"
  }

  private sanitizeKey(key: string): string {
    if (
      key.includes("..") ||
      path.isAbsolute(key) ||
      key.startsWith("/") ||
      key.startsWith("\\")
    ) {
      throw new Error("Path traversal attempted")
    }
    const normalized = path.normalize(key)
    if (normalized.includes("..") || path.isAbsolute(normalized)) {
      throw new Error("Path traversal attempted")
    }
    return normalized
  }

  private getFilePath(key: string): string {
    const cleanKey = this.sanitizeKey(key)
    return path.join(this.baseDir, cleanKey)
  }

  generateSignature(key: string, expires: number, contentLength: number): string {
    return crypto
      .createHmac("sha256", this.secret)
      .update(`${key}:${expires}:${contentLength}`)
      .digest("hex")
  }

  verifySignature(
    key: string,
    expires: number,
    contentLength: number,
    sig: string
  ): boolean {
    const expected = this.generateSignature(key, expires, contentLength)
    if (expected.length !== sig.length) return false
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))
  }

  async getPresignedUploadUrl(params: {
    key: string
    contentLength: number
    expiresInSeconds: number
  }): Promise<{ uploadUrl: string }> {
    const expires = Math.floor(Date.now() / 1000) + params.expiresInSeconds
    const sig = this.generateSignature(params.key, expires, params.contentLength)
    const base = process.env.BETTER_AUTH_URL || "http://localhost:3000"
    const uploadUrl = `${base}/api/vault/files/local-storage?key=${encodeURIComponent(
      params.key
    )}&exp=${expires}&len=${params.contentLength}&sig=${sig}`

    return { uploadUrl }
  }

  async getPresignedDownloadUrl(params: {
    key: string
    expiresInSeconds: number
  }): Promise<{ downloadUrl: string }> {
    const expires = Math.floor(Date.now() / 1000) + params.expiresInSeconds
    // For download, contentLength is 0 or ignored in signature
    const sig = this.generateSignature(params.key, expires, 0)
    const base = process.env.BETTER_AUTH_URL || "http://localhost:3000"
    const downloadUrl = `${base}/api/vault/files/local-storage?key=${encodeURIComponent(
      params.key
    )}&exp=${expires}&len=0&sig=${sig}`

    return { downloadUrl }
  }

  async headObject(key: string): Promise<{ contentLength: number; exists: boolean }> {
    try {
      const filePath = this.getFilePath(key)
      const stat = await fs.stat(filePath)
      return { contentLength: stat.size, exists: true }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return { contentLength: 0, exists: false }
      }
      throw err
    }
  }

  async deleteObject(key: string): Promise<void> {
    try {
      const filePath = this.getFilePath(key)
      await fs.unlink(filePath)
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err
      }
    }
  }

  async deleteObjects(keys: string[]): Promise<{ deleted: string[]; failed: string[] }> {
    const deleted: string[] = []
    const failed: string[] = []

    for (const key of keys) {
      try {
        await this.deleteObject(key)
        deleted.push(key)
      } catch {
        failed.push(key)
      }
    }

    return { deleted, failed }
  }

  async *listAllObjects(prefix: string): AsyncIterable<{ key: string; lastModified: Date }> {
    const cleanPrefix = this.sanitizeKey(prefix)
    const targetDir = path.join(this.baseDir, cleanPrefix)

    async function* walk(dir: string, currentPrefix: string): AsyncIterable<{ key: string; lastModified: Date }> {
      let entries: Dirent[]
      try {
        entries = await fs.readdir(dir, { withFileTypes: true })
      } catch {
        return
      }

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name)
        const relKey = path.posix.join(currentPrefix, entry.name)
        if (entry.isDirectory()) {
          yield* walk(fullPath, relKey)
        } else if (entry.isFile()) {
          const stat = await fs.stat(fullPath)
          yield { key: relKey, lastModified: stat.mtime }
        }
      }
    }

    yield* walk(targetDir, cleanPrefix)
  }

  // Internal helper for the mock route to store/read files
  async saveFile(key: string, buffer: Buffer): Promise<void> {
    const filePath = this.getFilePath(key)
    await fs.mkdir(path.dirname(filePath), { recursive: true })
    await fs.writeFile(filePath, buffer)
  }

  async readFile(key: string): Promise<Buffer> {
    const filePath = this.getFilePath(key)
    return fs.readFile(filePath)
  }
}

function initializeStorage(): StorageDriver {
  const driverType = process.env.STORAGE_DRIVER || "local"
  const isVercel = Boolean(process.env.VERCEL || process.env.VERCEL_ENV)

  // Fail-fast in production deployments (Vercel):
  // Ephemeral disk would silently lose files permanently if local storage were used.
  if (isVercel && driverType !== "r2") {
    throw new Error(
      `CRITICAL CONFIGURATION ERROR: STORAGE_DRIVER must be set to "r2" in production on Vercel! Current: "${driverType}".`
    )
  }

  if (driverType === "r2") {
    return new R2StorageDriver()
  }

  return new LocalStorageDriver()
}

export const storage = initializeStorage()
export { LocalStorageDriver }
