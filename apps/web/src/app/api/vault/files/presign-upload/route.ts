import { auth } from "@/lib/auth"
import { checkRateLimit } from "@/lib/rate-limit"
import { storage } from "@/lib/storage"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"
import { z } from "zod"

const MAX_FILE_CIPHERTEXT_BYTES = 25 * 1024 * 1024 + 16 // 25 MB plaintext + 16 bytes tag
const MAX_USER_FILE_QUOTA_BYTES = 250 * 1024 * 1024 // 250 MiB total per user

const presignUploadSchema = z.object({
  entryId: z.string().uuid(),
  blobSize: z.number().int().min(17).max(MAX_FILE_CIPHERTEXT_BYTES),
})

export async function POST(req: Request) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  // 1. Separate rate limit for presign: 10 requests / minute
  const rateCheck = await checkRateLimit({
    key: `file-presign:${session.user.id}`,
    limit: 10,
    windowMs: 60_000,
  })
  if (!rateCheck.success) {
    return Response.json(
      { error: "Presign rate limit exceeded" },
      { status: 429 }
    )
  }

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  const parsed = presignUploadSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 }
    )
  }

  const { blobSize } = parsed.data

  // 2. Check user's current total stored file quota
  const fileEntries = await prisma.vaultEntry.findMany({
    where: {
      userId: session.user.id,
      type: "file",
      blobSize: { not: null },
    },
    select: { blobSize: true },
  })

  const currentTotalBytes = fileEntries.reduce(
    (acc, e) => acc + (e.blobSize ?? 0),
    0
  )

  if (currentTotalBytes + blobSize > MAX_USER_FILE_QUOTA_BYTES) {
    return Response.json(
      {
        error: "Storage quota exceeded",
        message: "You have exceeded your 250 MiB file storage quota.",
      },
      { status: 413 }
    )
  }

  // 3. Generate canonical R2 key: u/<userId>/<uuid>
  const r2Key = `u/${session.user.id}/${crypto.randomUUID()}`

  // 4. Generate presigned upload URL (valid for 5 minutes / 300 seconds)
  const { uploadUrl } = await storage.getPresignedUploadUrl({
    key: r2Key,
    contentLength: blobSize,
    expiresInSeconds: 300,
  })

  return Response.json({
    uploadUrl,
    r2Key,
  })
}
