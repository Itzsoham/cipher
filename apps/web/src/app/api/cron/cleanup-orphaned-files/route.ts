import { storage } from "@/lib/storage"
import { prisma } from "@cipher/db"
import crypto from "node:crypto"

export async function GET(req: Request) {
  const cronSecret = process.env.CRON_SECRET
  if (!cronSecret) {
    return Response.json(
      { error: "Cron secret is not configured on this server" },
      { status: 500 }
    )
  }

  const authHeader = req.headers.get("authorization")
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const providedToken = authHeader.slice(7).trim()

  // Constant-time comparison
  const expectedBuf = Buffer.from(cronSecret)
  const providedBuf = Buffer.from(providedToken)

  if (
    expectedBuf.length !== providedBuf.length ||
    !crypto.timingSafeEqual(expectedBuf, providedBuf)
  ) {
    return Response.json(
      { error: "Forbidden: invalid cron secret" },
      { status: 403 }
    )
  }

  // 1. Get all active r2Keys from the database
  const activeEntries = await prisma.vaultEntry.findMany({
    where: {
      type: "file",
      r2Key: { not: null },
    },
    select: { r2Key: true },
  })

  const activeKeySet = new Set(
    activeEntries.map((e) => e.r2Key!).filter(Boolean)
  )

  // 2. Identify orphaned keys in R2 older than 24 hours
  const now = Date.now()
  const ONE_DAY_MS = 24 * 60 * 60 * 1000
  const orphanKeys: string[] = []

  for await (const obj of storage.listAllObjects("u/")) {
    if (!activeKeySet.has(obj.key)) {
      const age = now - obj.lastModified.getTime()
      if (age > ONE_DAY_MS) {
        orphanKeys.push(obj.key)
      }
    }
  }

  // 3. Batched delete (up to 1,000 per call, handled internally by deleteObjects)
  let cleanedCount = 0
  if (orphanKeys.length > 0) {
    const res = await storage.deleteObjects(orphanKeys)
    cleanedCount = res.deleted.length
  }

  return Response.json({
    cleaned: cleanedCount,
    foundOrphans: orphanKeys.length,
  })
}
