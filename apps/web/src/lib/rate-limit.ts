import { prisma } from "@cipher/db"

interface RateLimitOptions {
  key: string
  limit?: number
  windowMs?: number
}

/**
 * Database-backed rate limiter for API routes using the Prisma RateLimit model.
 * Enforces `limit` requests per `windowMs` window (default 60 req / 60 sec).
 */
export async function checkRateLimit({
  key,
  limit = 60,
  windowMs = 60_000,
}: RateLimitOptions): Promise<{ success: boolean; remaining: number }> {
  const now = BigInt(Date.now())
  const windowStart = now - BigInt(windowMs)

  const record = await prisma.rateLimit.findUnique({
    where: { key },
  })

  if (!record || record.lastRequest < windowStart) {
    await prisma.rateLimit.upsert({
      where: { key },
      create: {
        id: crypto.randomUUID(),
        key,
        count: 1,
        lastRequest: now,
      },
      update: {
        count: 1,
        lastRequest: now,
      },
    })
    return { success: true, remaining: limit - 1 }
  }

  if (record.count >= limit) {
    return { success: false, remaining: 0 }
  }

  await prisma.rateLimit.update({
    where: { key },
    data: {
      count: record.count + 1,
      lastRequest: now,
    },
  })

  return { success: true, remaining: limit - (record.count + 1) }
}

