export default function AuthLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
      <p className="font-mono text-sm tracking-widest text-muted-foreground uppercase">
        Cipher
      </p>
      {children}
    </main>
  )
}
