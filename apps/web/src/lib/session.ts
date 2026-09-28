import "server-only"

import { headers } from "next/headers"
import { redirect } from "next/navigation"
import { cache } from "react"

import { auth } from "@/lib/auth"

/** The verified session for a signed-in page. Redirects when there is none. */
export const requireSession = cache(async () => {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) redirect("/sign-in")
  return session
})
