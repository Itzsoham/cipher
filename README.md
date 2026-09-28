# Cipher

A personal, zero-knowledge encrypted vault for passwords, secure notes and files. Web only. See [docs/PLAN.md](docs/PLAN.md) for the full plan and [SECURITY.md](SECURITY.md) for the security model and its limits.

**Status:** Phase 1 (scaffold, schema, account auth, tests, CI). Vault crypto starts in Phase 2.

## Layout

| Path | What it is |
|---|---|
| `apps/web` | Next.js 16 app (App Router). Better Auth, pages, `src/proxy.ts` (CSP and auth redirect). |
| `packages/ui` | shadcn/ui components and the Tailwind v4 stylesheet, shared as `@cipher/ui`. |
| `packages/db` | Prisma 7 schema, migrations and the `prisma` client (`@cipher/db`). |
| `packages/crypto` | Vault crypto. Skeleton only until Phase 2. |
| `packages/eslint-config`, `packages/typescript-config` | Shared config. |

## Setup

Requires Node 22.

```sh
corepack enable            # or: corepack enable --install-directory <dir on PATH> pnpm
pnpm install
cp .env.example .env       # then fill it in (see below)
pnpm --filter @cipher/db db:migrate
pnpm dev                   # http://localhost:3000
```

There is one `.env`, at the repo root. `apps/web/scripts/next.mjs`, `prisma.config.ts` and `playwright.config.ts` read it when present. Variables already set in the environment always win, so CI and Vercel need no file.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Neon **pooled** connection, used at runtime. |
| `DIRECT_URL` | Neon **direct** connection, used by Prisma migrations. |
| `BETTER_AUTH_SECRET` | At least 32 random bytes (`openssl rand -base64 32`). |
| `BETTER_AUTH_URL` | Public origin of the app. |
| `SIGNUP_ALLOWLIST` | Comma-separated emails allowed to sign up. Empty refuses everyone. |
| `MAIL_TRANSPORT` | `file` (writes to `apps/web/.mail/*.json`). Resend comes later. |
| `MAIL_FROM` | Sender shown on messages. |

Until Resend is wired up, verification and reset links are in `apps/web/.mail/`. Open the newest JSON file and follow its `url`.

## Commands

```sh
pnpm turbo typecheck lint test build   # what CI runs first
pnpm turbo test:e2e                    # Playwright (builds, then runs on port 3100)
pnpm --filter @cipher/db db:migrate    # create/apply a migration (dev)
pnpm --filter @cipher/db db:deploy     # apply migrations (CI/prod)
pnpm --filter @cipher/db db:studio     # Prisma Studio
```

The e2e suite uses accounts at `@e2e.test` and deletes them (and clears rate-limit rows) before each run. Locally it runs against `DATABASE_URL`. In CI it runs against a throwaway `postgres:17` container.

## Notes

- **pnpm 10, not 12.** The corepack bundled with Node 22.15 cannot run pnpm 11+, so `packageManager` pins `pnpm@10.34.5`. For the same reason CI uses `pnpm/action-setup@v4`.
- **Schema.** The Better Auth models were generated once with `auth generate`. `schema.prisma` is maintained by hand from now on.
- **Allowlist responses.** A refused sign-up gets the same response as an accepted one (Better Auth does this when email verification is required), so the API does not reveal which emails are allowlisted. No account is created and no mail is sent.
