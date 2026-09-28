import Link from "next/link"

import { requireSession } from "@/lib/session"

import { SignOutButton } from "./sign-out-button"

export default async function AppLayout({
  children,
}: {
  children: React.ReactNode
}) {
  // proxy.ts only checks that a cookie exists; this verifies the session.
  const { user } = await requireSession()

  return (
    <div className="flex min-h-svh flex-col">
      <header className="flex items-center justify-between gap-4 border-b px-6 py-3">
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/vault" className="font-mono tracking-widest uppercase">
            Cipher
          </Link>
          <Link href="/settings/security" className="text-muted-foreground">
            Security
          </Link>
        </nav>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-muted-foreground" data-testid="account-email">
            {user.email}
          </span>
          <SignOutButton />
        </div>
      </header>
      <main className="mx-auto w-full max-w-3xl flex-1 p-6">{children}</main>
    </div>
  )
}
