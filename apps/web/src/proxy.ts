import { getSessionCookie } from "better-auth/cookies"
import { NextResponse, type NextRequest } from "next/server"

const PROTECTED_PREFIXES = ["/vault", "/settings"]

function buildCsp(nonce: string) {
  const isDev = process.env.NODE_ENV === "development"
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // Radix and sonner set inline style attributes, which nonces cannot cover.
    "style-src 'self' 'unsafe-inline'",
    "worker-src 'self' blob:",
    "connect-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ].join("; ")
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl

  // Cheap cookie check only. The (app) layout verifies the session for real.
  const isProtected = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  )
  if (isProtected && !getSessionCookie(request)) {
    const url = new URL("/sign-in", request.url)
    url.searchParams.set("next", `${pathname}${search}`)
    return withSecurityHeaders(NextResponse.redirect(url))
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString("base64")
  const csp = buildCsp(nonce)

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set("x-nonce", nonce)
  requestHeaders.set("Content-Security-Policy", csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set("Content-Security-Policy", csp)
  return withSecurityHeaders(response)
}

function withSecurityHeaders(response: NextResponse) {
  response.headers.set("Referrer-Policy", "no-referrer")
  response.headers.set("X-Content-Type-Options", "nosniff")
  response.headers.set("X-Frame-Options", "DENY")
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  )
  return response
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
}
