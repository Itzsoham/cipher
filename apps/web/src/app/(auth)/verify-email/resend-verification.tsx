"use client"

import { useState } from "react"
import { toast } from "sonner"

import { Button } from "@cipher/ui/components/button"

import { authClient } from "@/lib/auth-client"

export function ResendVerification({ email }: { email: string }) {
  const [pending, setPending] = useState(false)

  async function resend() {
    setPending(true)
    const { error } = await authClient.sendVerificationEmail({
      email,
      callbackURL: "/sign-in?verified=1",
    })
    setPending(false)
    if (error) toast.error(error.message ?? "Could not resend the email.")
    else toast.success("Verification email sent.")
  }

  return (
    <Button variant="outline" onClick={resend} disabled={pending}>
      Resend email
    </Button>
  )
}
