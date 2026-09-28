import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@cipher/ui/components/card"

export function AuthCard({
  title,
  description,
  footer,
  children,
}: {
  title: string
  description?: React.ReactNode
  footer?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>
          <h1>{title}</h1>
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>{children}</CardContent>
      {footer && (
        <CardFooter className="text-sm text-muted-foreground">
          {footer}
        </CardFooter>
      )}
    </Card>
  )
}
