import { mkdir, writeFile } from "node:fs/promises"
import path from "node:path"

export type MailMessage = {
  to: string
  subject: string
  text: string
  /** The action link in the message, kept separately so tests can read it. */
  url?: string
}

type Transport = (message: MailMessage & { from: string }) => Promise<void>

// Writes each message to .mail/*.json. Used in dev, test and CI.
const fileTransport: Transport = async (message) => {
  const dir = process.env.MAIL_DIR ?? path.join(process.cwd(), ".mail")
  await mkdir(dir, { recursive: true })
  const createdAt = new Date().toISOString()
  const name = `${Date.now()}-${crypto.randomUUID()}.json`
  await writeFile(
    path.join(dir, name),
    JSON.stringify({ ...message, createdAt }, null, 2)
  )
}

function getTransport(): Transport {
  const transport = process.env.MAIL_TRANSPORT ?? "file"
  switch (transport) {
    case "file":
      return fileTransport
    // "resend" is added once a Resend API key is available.
    default:
      throw new Error(`Unsupported MAIL_TRANSPORT: ${transport}`)
  }
}

export async function sendMail(message: MailMessage) {
  const from = process.env.MAIL_FROM ?? "Cipher <onboarding@resend.dev>"
  await getTransport()({ ...message, from })
}
