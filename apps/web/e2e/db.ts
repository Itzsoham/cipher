import pg from "pg"

import { E2E_DOMAIN } from "./constants"

async function withClient<T>(fn: (client: pg.Client) => Promise<T>) {
  const client = new pg.Client({ connectionString: process.env.DATABASE_URL })
  await client.connect()
  try {
    return await fn(client)
  } finally {
    await client.end()
  }
}

/** Deletes e2e accounts (sessions, accounts and 2FA rows cascade). */
export function deleteE2eUsers() {
  return withClient(async (client) => {
    await client.query(`DELETE FROM "user" WHERE email LIKE $1`, [
      `%@${E2E_DOMAIN}`,
    ])
    await client.query(`DELETE FROM "verification" WHERE identifier LIKE $1`, [
      `%@${E2E_DOMAIN}%`,
    ])
  })
}

export function userExists(email: string) {
  return withClient(async (client) => {
    const { rowCount } = await client.query(
      `SELECT 1 FROM "user" WHERE email = $1`,
      [email]
    )
    return rowCount === 1
  })
}

/** Every request comes from 127.0.0.1, so tests would share one bucket. */
export function clearRateLimits() {
  return withClient((client) => client.query(`DELETE FROM "rateLimit"`))
}
