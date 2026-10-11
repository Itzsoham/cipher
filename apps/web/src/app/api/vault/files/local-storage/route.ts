import { storage, LocalStorageDriver } from "@/lib/storage"
import { NextRequest, NextResponse } from "next/server"

export async function PUT(req: NextRequest) {
  if (process.env.VERCEL === "1" || process.env.VERCEL_ENV === "production") {
    return NextResponse.json(
      { error: "Local storage endpoint is strictly disabled in production" },
      { status: 403 }
    )
  }

  if (!(storage instanceof LocalStorageDriver)) {
    return NextResponse.json(
      { error: "Local storage endpoint is only available when STORAGE_DRIVER is local" },
      { status: 400 }
    )
  }

  const { searchParams } = new URL(req.url)
  const key = searchParams.get("key")
  const expStr = searchParams.get("exp")
  const lenStr = searchParams.get("len")
  const sig = searchParams.get("sig")

  if (!key || !expStr || !lenStr || !sig) {
    return NextResponse.json({ error: "Missing required query parameters" }, { status: 400 })
  }

  const exp = parseInt(expStr, 10)
  const declaredLen = parseInt(lenStr, 10)

  if (isNaN(exp) || isNaN(declaredLen)) {
    return NextResponse.json({ error: "Invalid exp or len" }, { status: 400 })
  }

  if (Math.floor(Date.now() / 1000) > exp) {
    return NextResponse.json({ error: "Presigned URL expired" }, { status: 403 })
  }

  if (!storage.verifySignature(key, exp, declaredLen, sig)) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 403 })
  }

  // Path traversal guard
  if (key.includes("..") || key.startsWith("/") || key.startsWith("\\")) {
    return NextResponse.json({ error: "Invalid key format" }, { status: 400 })
  }

  const arrayBuffer = await req.arrayBuffer()
  const buffer = Buffer.from(arrayBuffer)

  // Enforce Content-Length matches the signed value
  if (buffer.length !== declaredLen) {
    return NextResponse.json(
      { error: `Uploaded payload size (${buffer.length}) does not match signed length (${declaredLen})` },
      { status: 400 }
    )
  }

  await storage.saveFile(key, buffer)
  return new NextResponse(null, { status: 200 })
}

export async function GET(req: NextRequest) {
  if (process.env.VERCEL === "1" || process.env.VERCEL_ENV === "production") {
    return NextResponse.json(
      { error: "Local storage endpoint is strictly disabled in production" },
      { status: 403 }
    )
  }

  if (!(storage instanceof LocalStorageDriver)) {
    return NextResponse.json(
      { error: "Local storage endpoint is only available when STORAGE_DRIVER is local" },
      { status: 400 }
    )
  }

  const { searchParams } = new URL(req.url)
  const key = searchParams.get("key")
  const expStr = searchParams.get("exp")
  const sig = searchParams.get("sig")

  if (!key || !expStr || !sig) {
    return NextResponse.json({ error: "Missing required query parameters" }, { status: 400 })
  }

  const exp = parseInt(expStr, 10)
  if (isNaN(exp)) {
    return NextResponse.json({ error: "Invalid exp" }, { status: 400 })
  }

  if (Math.floor(Date.now() / 1000) > exp) {
    return NextResponse.json({ error: "Presigned URL expired" }, { status: 403 })
  }

  if (!storage.verifySignature(key, exp, 0, sig)) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 403 })
  }

  // Path traversal guard
  if (key.includes("..") || key.startsWith("/") || key.startsWith("\\")) {
    return NextResponse.json({ error: "Invalid key format" }, { status: 400 })
  }

  try {
    const buffer = await storage.readFile(key)
    return new NextResponse(new Uint8Array(buffer), {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": buffer.length.toString(),
      },
    })
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return NextResponse.json({ error: "File not found" }, { status: 404 })
    }
    throw err
  }
}
