import { requireSession } from "@/lib/session"
import { VaultView } from "./vault-view"

export default async function VaultPage() {
  const { user } = await requireSession()

  return (
    <div className="space-y-6">
      <VaultView user={user} />
    </div>
  )
}
