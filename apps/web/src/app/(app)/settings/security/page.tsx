import { requireSession } from "@/lib/session"

import { TwoFactorSettings } from "./two-factor-settings"

export default async function SecuritySettingsPage() {
  const { user } = await requireSession()

  return (
    <section className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-medium">Security</h1>
        <p className="text-sm text-muted-foreground">
          Two-factor login protects your account sign-in. It is separate from
          your master password.
        </p>
      </div>
      <TwoFactorSettings enabled={Boolean(user.twoFactorEnabled)} />
    </section>
  )
}
