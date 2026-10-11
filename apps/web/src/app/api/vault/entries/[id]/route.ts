import { auth } from "@/lib/auth"
import { checkRateLimit } from "@/lib/rate-limit"
import { AES_GCM_IV_BYTES } from "@cipher/crypto"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const MAX_TOTAL_CIPHERTEXT_BYTES = 20 * 1024 * 1024 // 20 MiB
const MAX_ENTRY_CIPHERTEXT_BYTES = 64 * 1024 // 64 KiB
const MAX_BASE64_LENGTH = Math.ceil(MAX_ENTRY_CIPHERTEXT_BYTES / 3) * 4 + 4

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

  // Check existence and verify quota considering the size delta
  const existing = await prisma.vaultEntry.findUnique({
    where: { id },
  })

  if (!existing || existing.userId !== session.user.id) {
    return Response.json({ error: "Entry not found" }, { status: 404 })
  }

  // Quota recheck with delta
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

  // Atomic Compare-And-Swap update
  const rowsUpdated = await prisma.$executeRaw`
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

  if (rowsUpdated === 0) {
    return Response.json(
      { error: "Stale version: entry was modified elsewhere" },
      { status: 409 }
    )
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

  if (expectedVersion !== null) {
    const rowsDeleted = await prisma.$executeRaw`
      DELETE FROM "VaultEntry"
      WHERE "id" = ${id}::uuid
        AND "userId" = ${session.user.id}
        AND "entryVersion" = ${expectedVersion}
    `

    if (rowsDeleted === 0) {
      // Check if entry exists for this user to distinguish 404 from 409
      const exists = await prisma.vaultEntry.findUnique({
        where: { id },
      })
      if (!exists || exists.userId !== session.user.id) {
        return Response.json({ error: "Entry not found" }, { status: 404 })
      }
      return Response.json(
        { error: "Stale version: entry was modified elsewhere" },
        { status: 409 }
      )
    }

    return Response.json({ success: true })
  }

  // Without version check (fallback, though client always sends ?v=)
  const existing = await prisma.vaultEntry.findUnique({
    where: { id },
  })
  if (!existing || existing.userId !== session.user.id) {
    return Response.json({ error: "Entry not found" }, { status: 404 })
  }

  await prisma.vaultEntry.delete({
    where: { id },
  })

  return Response.json({ success: true })
}

