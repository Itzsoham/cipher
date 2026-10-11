import { auth } from "@/lib/auth"
import { storage } from "@/lib/storage"
import { prisma } from "@cipher/db"
import { headers } from "next/headers"

interface RouteProps {
  params: Promise<{ id: string }>
}

export async function GET(_req: Request, { params }: RouteProps) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await params

  const entry = await prisma.vaultEntry.findUnique({
    where: { id },
    select: {
      id: true,
      userId: true,
      type: true,
      r2Key: true,
    },
  })

  if (!entry || entry.userId !== session.user.id) {
    return Response.json({ error: "File entry not found" }, { status: 404 })
  }

  if (entry.type !== "file" || !entry.r2Key) {
    return Response.json(
      { error: "Requested entry is not a valid file entry" },
      { status: 400 }
    )
  }

  // Generate presigned download URL (valid for 5 minutes / 300 seconds)
  const { downloadUrl } = await storage.getPresignedDownloadUrl({
    key: entry.r2Key,
    expiresInSeconds: 300,
  })

  return Response.json({ downloadUrl })
}
