"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import Link from "next/link"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { Button } from "@cipher/ui/components/button"
import { FieldGroup } from "@cipher/ui/components/field"

import { AuthCard } from "@/components/auth-card"
import { FormAlert } from "@/components/form-alert"
import { FormField } from "@/components/form-field"
import { authClient } from "@/lib/auth-client"
import { email } from "@/lib/validation"

const schema = z.object({ email })

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: "" },
  })

  async function onSubmit(values: z.infer<typeof schema>) {
    setError(null)
    const { error } = await authClient.requestPasswordReset({
      email: values.email,
      redirectTo: "/reset-password",
    })
    if (error) {
      setError(error.message ?? "Could not send the reset email.")
      return
    }
    setSent(true)
  }

  return (
    <AuthCard
      title="Reset account password"
      description="Resetting your account password does not change your master password or your vault."
      footer={
        <Link href="/sign-in" className="underline underline-offset-4">
          Back to sign in
        </Link>
      }
    >
      {sent ? (
        <FormAlert
          variant="default"
          message="If an account exists for that email, a reset link is on its way."
        />
      ) : (
        <form method="post" onSubmit={form.handleSubmit(onSubmit)} noValidate>
          <FieldGroup>
            <FormAlert message={error} />
            <FormField
              control={form.control}
              name="email"
              label="Email"
              type="email"
              autoComplete="email"
            />
            <Button type="submit" disabled={form.formState.isSubmitting}>
              Send reset link
            </Button>
          </FieldGroup>
        </form>
      )}
    </AuthCard>
  )
}
