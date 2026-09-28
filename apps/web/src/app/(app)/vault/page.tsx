import { requireSession } from "@/lib/session"

export default async function VaultPage() {
  const { user } = await requireSession()

  return (
    <section className="flex flex-col gap-2">
      <h1 className="text-xl font-medium">Vault</h1>
      <p className="text-sm text-muted-foreground">
        Signed in as {user.email}. Vault setup and entries arrive in later
        phases.
      </p>
    </section>
  )
}
