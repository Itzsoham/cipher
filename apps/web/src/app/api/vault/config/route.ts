import { auth } from "@/lib/auth"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const config = await prisma.vaultConfig.findUnique({
    where: { userId: session.user.id },
  })

  if (!config) {
    return Response.json({ error: "Vault config not found" }, { status: 404 })
  }

  return Response.json({
    kdfSalt: Buffer.from(config.kdfSalt).toString("hex"),
    kdfAlgorithm: config.kdfAlgorithm,
    kdfMemoryKiB: config.kdfMemoryKiB,
    kdfIterations: config.kdfIterations,
    kdfParallelism: config.kdfParallelism,
    masterWrappedKey: Buffer.from(config.masterWrappedKey).toString("hex"),
    masterWrapIv: Buffer.from(config.masterWrapIv).toString("hex"),
    recoveryHkdfSalt: Buffer.from(config.recoveryHkdfSalt).toString("hex"),
    recoveryWrappedKey: Buffer.from(config.recoveryWrappedKey).toString("hex"),
    recoveryWrapIv: Buffer.from(config.recoveryWrapIv).toString("hex"),
    autoLockMinutes: config.autoLockMinutes,
    updatedAt: config.updatedAt.toISOString(),
    vaultKeyVersion: config.vaultKeyVersion,
    userId: config.userId,
  })
}
