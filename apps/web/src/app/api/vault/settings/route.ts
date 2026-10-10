import { auth } from "@/lib/auth"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const settingsSchema = z.object({
  autoLockMinutes: z.number().int().min(1).max(30),
})

export async function PATCH(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const body = await req.json()
  const parsed = settingsSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { data } = parsed

  const config = await prisma.vaultConfig.findUnique({
    where: { userId: session.user.id },
  })

  if (!config) {
    return Response.json({ error: "Vault config not found" }, { status: 404 })
  }

  const updated = await prisma.vaultConfig.update({
    where: { userId: session.user.id },
    data: {
      autoLockMinutes: data.autoLockMinutes,
    },
  })

  return Response.json({
    success: true,
    autoLockMinutes: updated.autoLockMinutes,
    updatedAt: updated.updatedAt.toISOString(),
  })
}
