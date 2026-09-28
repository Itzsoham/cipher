"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import Link from "next/link"
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
import { email, newPassword } from "@/lib/validation"

const schema = z
  .object({ email, password: newPassword, confirm: z.string() })
  .refine((v) => v.password === v.confirm, {
    path: ["confirm"],
    message: "Passwords do not match.",
  })

export default function SignUpPage() {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "", confirm: "" },
  })

  async function onSubmit(values: z.infer<typeof schema>) {
    setError(null)
    const { error } = await authClient.signUp.email({
      email: values.email,
      password: values.password,
      name: values.email.split("@")[0] ?? values.email,
      callbackURL: "/sign-in?verified=1",
    })
    if (error) {
      setError(error.message ?? "Sign-up failed.")
      return
    }
    router.push(`/verify-email?email=${encodeURIComponent(values.email)}`)
  }

  return (
    <AuthCard
      title="Create account"
      description="Sign-up is limited to invited emails."
      footer={
        <p>
          Already have an account?{" "}
          <Link href="/sign-in" className="underline underline-offset-4">
            Sign in
          </Link>
        </p>
      }
    >
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
            label="Account password"
            type="password"
            autoComplete="new-password"
            description="At least 12 characters. This is not your master password."
          />
          <FormField
            control={form.control}
            name="confirm"
            label="Confirm password"
            type="password"
            autoComplete="new-password"
          />
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Create account
          </Button>
        </FieldGroup>
      </form>
    </AuthCard>
  )
}
