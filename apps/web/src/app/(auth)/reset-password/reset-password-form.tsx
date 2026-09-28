"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { Button } from "@cipher/ui/components/button"
import { FieldGroup } from "@cipher/ui/components/field"

import { FormAlert } from "@/components/form-alert"
import { FormField } from "@/components/form-field"
import { authClient } from "@/lib/auth-client"
import { newPassword } from "@/lib/validation"

const schema = z
  .object({ password: newPassword, confirm: z.string() })
  .refine((v) => v.password === v.confirm, {
    path: ["confirm"],
    message: "Passwords do not match.",
  })

export function ResetPasswordForm({ token }: { token: string }) {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { password: "", confirm: "" },
  })

  async function onSubmit(values: z.infer<typeof schema>) {
    setError(null)
    const { error } = await authClient.resetPassword({
      newPassword: values.password,
      token,
    })
    if (error) {
      setError(error.message ?? "Could not reset the password.")
      return
    }
    router.push("/sign-in?reset=1")
  }

  return (
    <form method="post" onSubmit={form.handleSubmit(onSubmit)} noValidate>
      <FieldGroup>
        <FormAlert message={error} />
        <FormField
          control={form.control}
          name="password"
          label="New password"
          type="password"
          autoComplete="new-password"
          description="At least 12 characters."
        />
        <FormField
          control={form.control}
          name="confirm"
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
        />
        <Button type="submit" disabled={form.formState.isSubmitting}>
          Update password
        </Button>
      </FieldGroup>
    </form>
  )
}
