import { Alert, AlertDescription } from "@cipher/ui/components/alert"

export function FormAlert({
  message,
  variant = "destructive",
}: {
  message?: string | null
  variant?: "default" | "destructive"
}) {
  if (!message) return null
  return (
    <Alert variant={variant}>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}
