"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { Button } from "@cipher/ui/components/button"
import { FieldGroup } from "@cipher/ui/components/field"

import { AuthCard } from "@/components/auth-card"
import { FormAlert } from "@/components/form-alert"
import { FormField } from "@/components/form-field"
import { authClient } from "@/lib/auth-client"
import { totpCode } from "@/lib/validation"

const totpSchema = z.object({ code: totpCode })
const backupSchema = z.object({
  code: z.string().trim().min(1, "Enter a backup code."),
})

export default function TwoFactorPage() {
  const router = useRouter()
  const [useBackup, setUseBackup] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const form = useForm<{ code: string }>({
    resolver: zodResolver(useBackup ? backupSchema : totpSchema),
    defaultValues: { code: "" },
  })

  async function onSubmit({ code }: { code: string }) {
    setError(null)
    const { error } = useBackup
      ? await authClient.twoFactor.verifyBackupCode({ code })
      : await authClient.twoFactor.verifyTotp({ code })
    if (error) {
      setError(error.message ?? "That code did not work.")
      return
    }
    router.push("/vault")
    router.refresh()
  }

  return (
    <AuthCard
      title="Two-factor login"
      description={
        useBackup
          ? "Enter one of your backup codes."
          : "Enter the 6-digit code from your authenticator app."
      }
    >
      <form method="post" onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={error} />
          <FormField
            control={form.control}
            name="code"
            label={useBackup ? "Backup code" : "Authentication code"}
            autoComplete="one-time-code"
            inputMode={useBackup ? "text" : "numeric"}
          />
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Verify
          </Button>
          <Button
            type="button"
            variant="link"
            onClick={() => {
              setUseBackup((v) => !v)
              setError(null)
              form.reset({ code: "" })
            }}
          >
            {useBackup ? "Use authenticator app" : "Use a backup code"}
          </Button>
        </FieldGroup>
      </form>
    </AuthCard>
  )
}
