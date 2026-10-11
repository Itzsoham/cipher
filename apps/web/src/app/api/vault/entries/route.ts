import { auth } from "@/lib/auth"
import { checkRateLimit } from "@/lib/rate-limit"
import { AES_GCM_IV_BYTES } from "@cipher/crypto"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const MAX_USER_ENTRIES = 5000
const MAX_TOTAL_CIPHERTEXT_BYTES = 20 * 1024 * 1024 // 20 MiB
const MAX_ENTRY_CIPHERTEXT_BYTES = 64 * 1024 // 64 KiB
const MAX_BASE64_LENGTH = Math.ceil(MAX_ENTRY_CIPHERTEXT_BYTES / 3) * 4 + 4

const createEntrySchema = z.object({
  id: z.string().uuid(),
  type: z.enum(["password", "secure_note"]),
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
})

const bulkDeleteSchema = z.object({
  ids: z.array(z.string().uuid()).min(1).max(100),
  v: z.record(z.string(), z.number().int().positive()).optional(),
})

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const entries = await prisma.vaultEntry.findMany({
    where: { userId: session.user.id },
    orderBy: { updatedAt: "desc" },
    select: {
      id: true,
      type: true,
      cryptoVersion: true,
      vaultKeyVersion: true,
      entryVersion: true,
      encryptedData: true,
      iv: true,
      createdAt: true,
      updatedAt: true,
    },
  })

  const payload = entries.map((entry) => ({
    id: entry.id,
    type: entry.type,
    cryptoVersion: entry.cryptoVersion,
    vaultKeyVersion: entry.vaultKeyVersion,
    entryVersion: entry.entryVersion,
    encryptedData: Buffer.from(entry.encryptedData).toString("base64"),
    iv: Buffer.from(entry.iv).toString("hex"),
    createdAt: entry.createdAt.toISOString(),
    updatedAt: entry.updatedAt.toISOString(),
  }))

  return Response.json(payload)
}

export async function POST(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
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

  const parsed = createEntrySchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { data } = parsed
  const dataBuffer = Buffer.from(data.encryptedData, "base64")
  const ivBuffer = Buffer.from(data.iv, "hex")

  try {
    const result = await prisma.$transaction(async (tx) => {
      // 1. Quota check: entry count
      const count = await tx.vaultEntry.count({
        where: { userId: session.user.id },
      })
      if (count >= MAX_USER_ENTRIES) {
        throw new Error("ENTRY_COUNT_EXCEEDED")
      }

      // 2. Quota check: total ciphertext size
      const existingEntries = await tx.vaultEntry.findMany({
        where: { userId: session.user.id },
        select: { encryptedData: true },
      })
      const totalBytes = existingEntries.reduce(
        (acc, curr) => acc + curr.encryptedData.length,
        0
      )
      if (totalBytes + dataBuffer.length > MAX_TOTAL_CIPHERTEXT_BYTES) {
        throw new Error("CIPHERTEXT_QUOTA_EXCEEDED")
      }

      // 3. Create entry
      return await tx.vaultEntry.create({
        data: {
          id: data.id,
          userId: session.user.id,
          type: data.type,
          cryptoVersion: data.cryptoVersion,
          vaultKeyVersion: data.vaultKeyVersion,
          entryVersion: 1,
          encryptedData: dataBuffer,
          iv: ivBuffer,
        },
      })
    })

    return Response.json(
      {
        id: result.id,
        entryVersion: result.entryVersion,
        createdAt: result.createdAt.toISOString(),
      },
      { status: 201 }
    )
  } catch (err: unknown) {
    if (err instanceof Error) {
      if (err.message === "ENTRY_COUNT_EXCEEDED") {
        return Response.json(
          { error: "Maximum entry quota (5,000) reached" },
          { status: 400 }
        )
      }
      if (err.message === "CIPHERTEXT_QUOTA_EXCEEDED") {
        return Response.json(
          { error: "Total ciphertext quota (20 MiB) exceeded" },
          { status: 413 }
        )
      }
    }
    // Handle unique constraint failure (e.g. duplicate id)
    if (typeof err === "object" && err !== null && "code" in err && err.code === "P2002") {
      return Response.json({ error: "Entry with this id already exists" }, { status: 409 })
    }
    throw err
  }
}

export async function DELETE(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
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

  const parsed = bulkDeleteSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { ids, v } = parsed.data

  // Fetch all requested entries owned by user to verify ownership and versions
  const entries = await prisma.vaultEntry.findMany({
    where: {
      id: { in: ids },
      userId: session.user.id,
    },
    select: { id: true, entryVersion: true },
  })

  const toDelete: string[] = []
  const stale: string[] = []

  for (const entry of entries) {
    if (v && v[entry.id] !== undefined) {
      if (v[entry.id] === entry.entryVersion) {
        toDelete.push(entry.id)
      } else {
        stale.push(entry.id)
      }
    } else {
      toDelete.push(entry.id)
    }
  }

  let deletedCount = 0
  if (toDelete.length > 0) {
    const res = await prisma.vaultEntry.deleteMany({
      where: {
        id: { in: toDelete },
        userId: session.user.id,
      },
    })
    deletedCount = res.count
  }

  return Response.json({
    deleted: deletedCount,
    stale,
  })
}

