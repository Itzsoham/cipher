"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import { QRCodeSVG } from "qrcode.react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"

import { Button } from "@cipher/ui/components/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@cipher/ui/components/card"
import { FieldGroup } from "@cipher/ui/components/field"

import { FormAlert } from "@/components/form-alert"
import { FormField } from "@/components/form-field"
import { authClient } from "@/lib/auth-client"
import { totpCode } from "@/lib/validation"

const passwordSchema = z.object({
  password: z.string().min(1, "Enter your account password."),
})
const codeSchema = z.object({ code: totpCode })

type Setup = { totpURI: string; backupCodes: string[] }

export function TwoFactorSettings({ enabled }: { enabled: boolean }) {
  const [setup, setSetup] = useState<Setup | null>(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Two-factor login</CardTitle>
        <CardDescription>
          {enabled
            ? "On. Sign-in asks for a code from your authenticator app."
            : "Off. Add an authenticator app (TOTP) to your sign-in."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {setup ? (
          <ConfirmSetup setup={setup} onDone={() => setSetup(null)} />
        ) : (
          <PasswordStep enabled={enabled} onSetup={setSetup} />
        )}
      </CardContent>
    </Card>
  )
}

function PasswordStep({
  enabled,
  onSetup,
}: {
  enabled: boolean
  onSetup: (setup: Setup) => void
}) {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof passwordSchema>>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { password: "" },
  })

  async function onSubmit({ password }: z.infer<typeof passwordSchema>) {
    setError(null)
    if (enabled) {
      const { error } = await authClient.twoFactor.disable({ password })
      if (error) return setError(error.message ?? "Could not turn it off.")
      toast.success("Two-factor login turned off.")
      form.reset()
      router.refresh()
      return
    }
    const { data, error } = await authClient.twoFactor.enable({ password })
    if (error || data?.method !== "totp")
      return setError(error?.message ?? "Could not start setup.")
    onSetup({ totpURI: data.totpURI, backupCodes: data.backupCodes })
  }

  return (
    <form method="post" onSubmit={form.handleSubmit(onSubmit)} noValidate>
      <FieldGroup>
        <FormAlert message={error} />
        <FormField
          control={form.control}
          name="password"
          label="Account password"
          type="password"
          autoComplete="current-password"
        />
        <Button
          type="submit"
          variant={enabled ? "destructive" : "default"}
          disabled={form.formState.isSubmitting}
        >
          {enabled ? "Turn off two-factor login" : "Set up two-factor login"}
        </Button>
      </FieldGroup>
    </form>
  )
}

function ConfirmSetup({ setup, onDone }: { setup: Setup; onDone: () => void }) {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const form = useForm<z.infer<typeof codeSchema>>({
    resolver: zodResolver(codeSchema),
    defaultValues: { code: "" },
  })
  const secret = new URL(setup.totpURI).searchParams.get("secret")

  async function onSubmit({ code }: z.infer<typeof codeSchema>) {
    setError(null)
    const { error } = await authClient.twoFactor.verifyTotp({ code })
    if (error) return setError(error.message ?? "That code did not work.")
    toast.success("Two-factor login is on.")
    onDone()
    router.refresh()
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col items-start gap-3 text-sm">
        <p>1. Scan this QR code with your authenticator app.</p>
        <div className="rounded-md bg-white p-3">
          <QRCodeSVG value={setup.totpURI} size={176} />
        </div>
        {secret && (
          <p className="text-muted-foreground">
            Or enter this key:{" "}
            <code className="font-mono break-all text-foreground">
              {secret}
            </code>
          </p>
        )}
      </div>
      <div className="flex flex-col gap-2 text-sm">
        <p>2. Save these backup codes somewhere safe. Each works once.</p>
        <ul className="grid grid-cols-2 gap-1 rounded-md border p-3 font-mono">
          {setup.backupCodes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ul>
      </div>
      <form method="post" onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={error} />
          <FormField
            control={form.control}
            name="code"
            label="3. Enter the 6-digit code to confirm"
            autoComplete="one-time-code"
            inputMode="numeric"
          />
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Turn on two-factor login
          </Button>
        </FieldGroup>
      </form>
    </div>
  )
}
