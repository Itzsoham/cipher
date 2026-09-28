import Link from "next/link"

import { AuthCard } from "@/components/auth-card"
import { FormAlert } from "@/components/form-alert"

import { ResetPasswordForm } from "./reset-password-form"

export default async function ResetPasswordPage({
  searchParams,
}: PageProps<"/reset-password">) {
  const params = await searchParams
  const token = Array.isArray(params.token) ? params.token[0] : params.token
  const invalid = !token || Boolean(params.error)

  return (
    <AuthCard
      title="Choose a new password"
      footer={
        <Link href="/sign-in" className="underline underline-offset-4">
          Back to sign in
        </Link>
      }
    >
      {invalid ? (
        <FormAlert message="This reset link is invalid or has expired. Request a new one." />
      ) : (
        <ResetPasswordForm token={token} />
      )}
    </AuthCard>
  )
}
