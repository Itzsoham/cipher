import { auth } from "@/lib/auth"
import { checkRateLimit } from "@/lib/rate-limit"
import { storage } from "@/lib/storage"
import { AES_GCM_IV_BYTES } from "@cipher/crypto"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const MAX_TOTAL_CIPHERTEXT_BYTES = 20 * 1024 * 1024 // 20 MiB
const MAX_ENTRY_CIPHERTEXT_BYTES = 64 * 1024 // 64 KiB
const MAX_BASE64_LENGTH = Math.ceil(MAX_ENTRY_CIPHERTEXT_BYTES / 3) * 4 + 4
const MAX_FILE_CIPHERTEXT_BYTES = 25 * 1024 * 1024 + 16 // 25 MB + 16 bytes tag
const MAX_USER_FILE_QUOTA_BYTES = 250 * 1024 * 1024 // 250 MiB

const updateEntrySchema = z.object({
  encryptedData: z
    .string()
    .min(1)
    .max(MAX_BASE64_LENGTH)
    .refine(
      (val) => {
        try {
          const buf = Buffer.from(val, "base64")
          return buf.length <= MAX_ENTRY_CIPHERTEXT_BYTES
        } catch {
          return false
        }
      },
      { message: "encryptedData exceeds 64 KiB" }
    ),
  iv: z
    .string()
    .length(AES_GCM_IV_BYTES * 2, `iv must be ${AES_GCM_IV_BYTES * 2} hex characters`)
    .regex(/^[0-9a-fA-F]+$/),
  cryptoVersion: z.number().int().positive().default(1),
  vaultKeyVersion: z.number().int().positive().default(1),
  entryVersion: z.number().int().positive(),
  // Optional replacement file parameters for type "file"
  r2Key: z.string().regex(/^u\/[^/]+\/[0-9a-fA-F-]{36}$/).optional(),
  blobIv: z.string().length(AES_GCM_IV_BYTES * 2).regex(/^[0-9a-fA-F]+$/).optional(),
  blobSize: z.number().int().min(17).max(MAX_FILE_CIPHERTEXT_BYTES).optional(),
})

interface RouteContext {
  params: Promise<{ id: string }>
}

export async function PUT(req: Request, context: RouteContext) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await context.params
  const idParsed = z.string().uuid().safeParse(id)
  if (!idParsed.success) {
    return Response.json({ error: "Invalid entry ID" }, { status: 400 })
  }

  const rateCheck = await checkRateLimit({
    key: `entry-mutation:${session.user.id}`,
    limit: 60,
  })
  if (!rateCheck.success) {
    return Response.json({ error: "Rate limit exceeded" }, { status: 429 })
  }

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  const parsed = updateEntrySchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { data } = parsed
  const dataBuffer = Buffer.from(data.encryptedData, "base64")
  const ivBuffer = Buffer.from(data.iv, "hex")

  // Check existence and verify ownership
  const existing = await prisma.vaultEntry.findUnique({
    where: { id },
  })

  if (!existing || existing.userId !== session.user.id) {
    return Response.json({ error: "Entry not found" }, { status: 404 })
  }

  // Quota recheck with delta for encryptedData
  const allEntries = await prisma.vaultEntry.findMany({
    where: { userId: session.user.id },
    select: { id: true, encryptedData: true },
  })
  const currentTotal = allEntries.reduce(
    (acc, curr) => acc + (curr.id === id ? 0 : curr.encryptedData.length),
    0
  )
  if (currentTotal + dataBuffer.length > MAX_TOTAL_CIPHERTEXT_BYTES) {
    return Response.json(
      { error: "Total ciphertext quota (20 MiB) exceeded" },
      { status: 413 }
    )
  }

  // File replacement validation & quota
  let newR2Key: string | null = null
  let newBlobIv: Buffer | null = null
  let newBlobSize: number | null = null
  const oldR2KeyToDelete =
    existing.type === "file" && data.r2Key && data.r2Key !== existing.r2Key
      ? existing.r2Key
      : null

  if (existing.type === "file" && data.r2Key) {
    if (!data.r2Key.startsWith(`u/${session.user.id}/`)) {
      return Response.json(
        { error: "Forbidden: r2Key does not belong to session user" },
        { status: 403 }
      )
    }

    if (!data.blobIv || !data.blobSize) {
      return Response.json(
        { error: "blobIv and blobSize are required when replacing file" },
        { status: 400 }
      )
    }

    // Verify HeadObject
    const head = await storage.headObject(data.r2Key)
    if (!head.exists || head.contentLength !== data.blobSize) {
      return Response.json(
        { error: "Storage object not found or size mismatch" },
        { status: 422 }
      )
    }

    // Re-check quota with subtraction of old blobSize
    const userFiles = await prisma.vaultEntry.findMany({
      where: { userId: session.user.id, type: "file", blobSize: { not: null } },
      select: { id: true, blobSize: true },
    })
    const totalFileBytesWithoutThis = userFiles.reduce(
      (acc, curr) => acc + (curr.id === id ? 0 : (curr.blobSize ?? 0)),
      0
    )
    if (totalFileBytesWithoutThis + data.blobSize > MAX_USER_FILE_QUOTA_BYTES) {
      return Response.json(
        { error: "Total file storage quota (250 MiB) exceeded" },
        { status: 413 }
      )
    }

    newR2Key = data.r2Key
    newBlobIv = Buffer.from(data.blobIv, "hex")
    newBlobSize = data.blobSize
  }

  // Atomic Compare-And-Swap update
  let rowsUpdated = 0
  if (newR2Key !== null) {
    rowsUpdated = await prisma.$executeRaw`
      UPDATE "VaultEntry"
      SET "encryptedData" = ${dataBuffer},
          "iv" = ${ivBuffer},
          "cryptoVersion" = ${data.cryptoVersion},
          "vaultKeyVersion" = ${data.vaultKeyVersion},
          "r2Key" = ${newR2Key},
          "blobIv" = ${newBlobIv},
          "blobSize" = ${newBlobSize},
          "entryVersion" = "entryVersion" + 1,
          "updatedAt" = NOW()
      WHERE "id" = ${id}::uuid
        AND "userId" = ${session.user.id}
        AND "entryVersion" = ${data.entryVersion}
    `
  } else {
    rowsUpdated = await prisma.$executeRaw`
      UPDATE "VaultEntry"
      SET "encryptedData" = ${dataBuffer},
          "iv" = ${ivBuffer},
          "cryptoVersion" = ${data.cryptoVersion},
          "vaultKeyVersion" = ${data.vaultKeyVersion},
          "entryVersion" = "entryVersion" + 1,
          "updatedAt" = NOW()
      WHERE "id" = ${id}::uuid
        AND "userId" = ${session.user.id}
        AND "entryVersion" = ${data.entryVersion}
    `
  }

  if (rowsUpdated === 0) {
    return Response.json(
      { error: "Stale version: entry was modified elsewhere" },
      { status: 409 }
    )
  }

  // SAFE DELETION ORDER: Only AFTER DB CAS succeeds, delete old R2 object if replaced
  if (oldR2KeyToDelete) {
    try {
      await storage.deleteObject(oldR2KeyToDelete)
    } catch (err) {
      console.warn("Non-fatal: failed to delete old replaced R2 object", err)
    }
  }

  const updatedEntry = await prisma.vaultEntry.findUnique({
    where: { id },
    select: { entryVersion: true, updatedAt: true },
  })

  return Response.json({
    entryVersion: updatedEntry?.entryVersion ?? data.entryVersion + 1,
    updatedAt: updatedEntry?.updatedAt.toISOString(),
  })
}

export async function DELETE(req: Request, context: RouteContext) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await context.params
  const idParsed = z.string().uuid().safeParse(id)
  if (!idParsed.success) {
    return Response.json({ error: "Invalid entry ID" }, { status: 400 })
  }

  const rateCheck = await checkRateLimit({
    key: `entry-mutation:${session.user.id}`,
    limit: 60,
  })
  if (!rateCheck.success) {
    return Response.json({ error: "Rate limit exceeded" }, { status: 429 })
  }

  const url = new URL(req.url)
  const versionParam = url.searchParams.get("v")
  const expectedVersion = versionParam ? parseInt(versionParam, 10) : null

  if (expectedVersion !== null && isNaN(expectedVersion)) {
    return Response.json({ error: "Invalid version parameter" }, { status: 400 })
  }

  // Read entry first to identify r2Key if it's a file entry
  const existing = await prisma.vaultEntry.findUnique({
    where: { id },
    select: { id: true, userId: true, type: true, r2Key: true, entryVersion: true },
  })

  if (!existing || existing.userId !== session.user.id) {
    return Response.json({ error: "Entry not found" }, { status: 404 })
  }

  if (expectedVersion !== null && existing.entryVersion !== expectedVersion) {
    return Response.json(
      { error: "Stale version: entry was modified elsewhere" },
      { status: 409 }
    )
  }

  // SAFE DELETION ORDER:
  // 1. Delete DB row atomically
  if (expectedVersion !== null) {
    const rowsDeleted = await prisma.$executeRaw`
      DELETE FROM "VaultEntry"
      WHERE "id" = ${id}::uuid
        AND "userId" = ${session.user.id}
        AND "entryVersion" = ${expectedVersion}
    `
    if (rowsDeleted === 0) {
      return Response.json(
        { error: "Stale version: entry was modified elsewhere" },
        { status: 409 }
      )
    }
  } else {
    await prisma.vaultEntry.delete({
      where: { id },
    })
  }

  // 2. Only after DB row is deleted: delete R2 object
  if (existing.type === "file" && existing.r2Key) {
    try {
      await storage.deleteObject(existing.r2Key)
    } catch (err) {
      console.warn("Non-fatal: failed to delete R2 object for entry", existing.r2Key, err)
    }
  }

  return Response.json({ success: true })
}
