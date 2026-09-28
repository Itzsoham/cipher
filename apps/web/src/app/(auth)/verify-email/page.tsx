import Link from "next/link"

import { AuthCard } from "@/components/auth-card"

import { ResendVerification } from "./resend-verification"

export default async function VerifyEmailPage({
  searchParams,
}: PageProps<"/verify-email">) {
  const { email } = await searchParams
  const address = Array.isArray(email) ? email[0] : email

  return (
    <AuthCard
      title="Check your email"
      description={
        address
          ? `We sent a verification link to ${address}.`
          : "We sent you a verification link."
      }
      footer={
        <Link href="/sign-in" className="underline underline-offset-4">
          Back to sign in
        </Link>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        <p>Open the link to verify your account, then sign in.</p>
        {address && <ResendVerification email={address} />}
      </div>
    </AuthCard>
  )
}
