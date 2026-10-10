import { auth } from "@/lib/auth"
import {
  KDF_CEILING,
  KDF_FLOOR,
  KDF_SALT_BYTES,
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  VK_BYTES,
  RECOVERY_HKDF_SALT_BYTES,
} from "@cipher/crypto"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const setupSchema = z.object({
  kdfSalt: z
    .string()
    .length(KDF_SALT_BYTES * 2, `kdfSalt must be ${KDF_SALT_BYTES * 2} hex characters`)
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
  recoveryHkdfSalt: z
    .string()
    .length(RECOVERY_HKDF_SALT_BYTES * 2)
    .regex(/^[0-9a-fA-F]+$/),
  recoveryWrappedKey: z
    .string()
    .length((VK_BYTES + AES_GCM_TAG_BYTES) * 2)
    .regex(/^[0-9a-fA-F]+$/),
  recoveryWrapIv: z
    .string()
    .length(AES_GCM_IV_BYTES * 2)
    .regex(/^[0-9a-fA-F]+$/),
  autoLockMinutes: z.number().int().min(1).max(30).optional().default(5),
})

export async function POST(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const body = await req.json()
  const parsed = setupSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { data } = parsed

  const existing = await prisma.vaultConfig.findUnique({
    where: { userId: session.user.id },
  })

  if (existing) {
    return Response.json(
      { error: "Vault config already exists for this user" },
      { status: 409 }
    )
  }

  const config = await prisma.vaultConfig.create({
    data: {
      userId: session.user.id,
      kdfSalt: Buffer.from(data.kdfSalt, "hex"),
      kdfAlgorithm: data.kdfAlgorithm,
      kdfMemoryKiB: data.kdfMemoryKiB,
      kdfIterations: data.kdfIterations,
      kdfParallelism: data.kdfParallelism,
      masterWrappedKey: Buffer.from(data.masterWrappedKey, "hex"),
      masterWrapIv: Buffer.from(data.masterWrapIv, "hex"),
      recoveryHkdfSalt: Buffer.from(data.recoveryHkdfSalt, "hex"),
      recoveryWrappedKey: Buffer.from(data.recoveryWrappedKey, "hex"),
      recoveryWrapIv: Buffer.from(data.recoveryWrapIv, "hex"),
      autoLockMinutes: data.autoLockMinutes,
    },
  })

  return Response.json({
    success: true,
    updatedAt: config.updatedAt.toISOString(),
  })
}
