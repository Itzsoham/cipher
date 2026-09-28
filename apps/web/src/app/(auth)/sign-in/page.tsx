import Link from "next/link"

import { AuthCard } from "@/components/auth-card"
import { FormAlert } from "@/components/form-alert"
import { safeNext } from "@/lib/validation"

import { SignInForm } from "./sign-in-form"

export default async function SignInPage({
  searchParams,
}: PageProps<"/sign-in">) {
  const params = await searchParams
  const one = (key: string) => {
    const value = params[key]
    return Array.isArray(value) ? value[0] : value
  }

  let notice: string | null = null
  let error: string | null = null
  if (one("error")) {
    error = "That link is invalid or has expired. Request a new one."
  } else if (one("verified")) {
    notice = "Email verified. You can sign in now."
  } else if (one("reset")) {
    notice = "Password updated. Sign in with your new password."
  }

  return (
    <AuthCard
      title="Sign in"
      description="Use your account email and password."
      footer={
        <p>
          No account?{" "}
          <Link href="/sign-up" className="underline underline-offset-4">
            Sign up
          </Link>
        </p>
      }
    >
      <div className="flex flex-col gap-4">
        <FormAlert message={notice} variant="default" />
        <FormAlert message={error} />
        <SignInForm next={safeNext(one("next"))} />
      </div>
    </AuthCard>
  )
}
