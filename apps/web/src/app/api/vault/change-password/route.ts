import { auth } from "@/lib/auth"
import {
  KDF_CEILING,
  KDF_FLOOR,
  KDF_SALT_BYTES,
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  VK_BYTES,
} from "@cipher/crypto"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const changePasswordSchema = z.object({
  kdfSalt: z
    .string()
    .length(KDF_SALT_BYTES * 2)
    .regex(/^[0-9a-fA-F]+$/),
  kdfAlgorithm: z.literal("argon2id"),
  kdfMemoryKiB: z
    .number()
    .min(KDF_FLOOR.memoryCost)
    .max(KDF_CEILING.memoryCost),
  kdfIterations: z.number().min(KDF_FLOOR.timeCost).max(KDF_CEILING.timeCost),
  kdfParallelism: z
    .number()
    .min(KDF_FLOOR.parallelism)
    .max(KDF_CEILING.parallelism),
  masterWrappedKey: z
    .string()
    .length((VK_BYTES + AES_GCM_TAG_BYTES) * 2)
    .regex(/^[0-9a-fA-F]+$/),
  masterWrapIv: z
    .string()
    .length(AES_GCM_IV_BYTES * 2)
    .regex(/^[0-9a-fA-F]+$/),
  expectedUpdatedAt: z.string(),
})

export async function POST(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const body = await req.json()
  const parsed = changePasswordSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { data } = parsed

  const result = await prisma.vaultConfig.updateMany({
    where: {
      userId: session.user.id,
      updatedAt: new Date(data.expectedUpdatedAt),
    },
    data: {
      kdfSalt: Buffer.from(data.kdfSalt, "hex"),
      kdfAlgorithm: data.kdfAlgorithm,
      kdfMemoryKiB: data.kdfMemoryKiB,
      kdfIterations: data.kdfIterations,
      kdfParallelism: data.kdfParallelism,
      masterWrappedKey: Buffer.from(data.masterWrappedKey, "hex"),
      masterWrapIv: Buffer.from(data.masterWrapIv, "hex"),
    },
  })

  if (result.count === 0) {
    return Response.json(
      { error: "Conflict: Vault configuration has changed in another session" },
      { status: 409 }
    )
  }

  const updated = await prisma.vaultConfig.findUniqueOrThrow({
    where: { userId: session.user.id },
  })

  return Response.json({
    success: true,
    updatedAt: updated.updatedAt.toISOString(),
  })
}
