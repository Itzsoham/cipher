"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { Button } from "@cipher/ui/components/button"
import { FieldGroup } from "@cipher/ui/components/field"

import { FormAlert } from "@/components/form-alert"
import { FormField } from "@/components/form-field"
import { authClient } from "@/lib/auth-client"
import { email } from "@/lib/validation"

const schema = z.object({
  email,
  password: z.string().min(1, "Enter your password."),
})

export function SignInForm({ next }: { next: string }) {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "" },
  })

  async function onSubmit(values: z.infer<typeof schema>) {
    setError(null)
    const { data, error } = await authClient.signIn.email(values)
    if (error) {
      setError(
        error.code === "EMAIL_NOT_VERIFIED"
          ? "Verify your email before signing in. Check your inbox for the link."
          : (error.message ?? "Sign-in failed.")
      )
      return
    }
    // The two-factor plugin redirects to /2fa on its own.
    if (data && "twoFactorRedirect" in data && data.twoFactorRedirect) return
    router.push(next)
    router.refresh()
  }

  return (
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
        <FormField
          control={form.control}
          name="password"
          label="Password"
          type="password"
          autoComplete="current-password"
        />
        <Button type="submit" disabled={form.formState.isSubmitting}>
          Sign in
        </Button>
        <Link
          href="/forgot-password"
          className="text-center text-sm underline underline-offset-4"
        >
          Forgot password?
        </Link>
      </FieldGroup>
    </form>
  )
}
