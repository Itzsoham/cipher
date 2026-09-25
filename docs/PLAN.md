# Cipher v1: Plan (revised after gap review)

## Context
This is a new project (the `cipher/` folder is empty and not yet a git repository). The goal is a personal, zero-knowledge encrypted vault (passwords, secure notes, files), delivered as a web app only and hosted on **Vercel**. The code goes to **https://github.com/Itzsoham/cipher.git** (confirmed reachable, currently empty).

This plan covers **Phase 1 (scaffold, schema, auth, tests, CI)** in detail. **Work stops after Phase 1 for your confirmation.** The crypto package (Phase 2) starts with a plain-language walkthrough before any code, as you asked.

Decisions so far:
- Recovery uses a **wrapped vault key**.
- Only **type and timestamps** are stored in plaintext.
- Package manager is **pnpm via corepack**.
- Login is **email and password**, plus email verification and account password reset (see S2).
- UI uses **shadcn/ui** with Tailwind v4.

### Versions (checked on npm, 2026-09-25)
| Package | Version | Why |
|---|---|---|
| next | **16.3.x** | Latest stable. Better Auth 1.7 supports `next ^16`. Note that `middleware.ts` is now **`proxy.ts`**. |
| prisma / @prisma/client | **7.10.x** | Latest *stable*. npm's `latest` tag currently points to `8.0.0-rc.17` (a release candidate), and Better Auth's peer range stops at `^7`, so 8 is ruled out. |
| @prisma/adapter-pg | 7.10.x | Prisma 7 requires a driver adapter. `adapter-pg` works with Neon from Vercel's Node runtime **and** with a plain Postgres container in CI. |
| better-auth | 1.7.x | |
| react | 19.x · tailwindcss 4.3.x · shadcn CLI 4.x · turbo 2.11.x · @playwright/test 1.63.x | |

Node: 22.15 locally satisfies Prisma 7 (`^22.12`) and Next 16 (`>=20.9`). `engines.node` is set to `22.x` to match Vercel.

---

## Security model
- **Vault Key (VK):** a random 256-bit key generated in the browser. It encrypts every entry and every file.
- **Master password:** runs through Argon2id (salt plus stored parameters) to produce KEK_m, which wraps the VK with AES-256-GCM. The result is `masterWrappedKey`. A wrong password makes the GCM tag check fail, so no separate password verifier is stored.
- **Recovery key:** 256 random bits in grouped base32 with a checksum. It runs through HKDF-SHA256 to produce KEK_r, which wraps the VK. The result is `recoveryWrappedKey`.
- **Changing the password or recovering** only re-wraps the VK. Data is never re-encrypted. A new recovery key is issued after each recovery.
- **The account password (Better Auth) and the master password are independent.** Resetting the account password by email never touches the vault.
- **Web-delivery caveat, and its mitigations:** the server ships the JavaScript that does the crypto. Mitigations: a strict CSP with nonces, no third-party scripts or analytics, `frame-ancestors 'none'`, and `no-referrer`.

### Fixes for the serious issues
| # | Gap | Fix |
|---|---|---|
| S1 | Anyone could sign up | Sign-up is restricted by the `SIGNUP_ALLOWLIST` environment variable (comma-separated emails). It is enforced on the server in Better Auth `databaseHooks.user.create.before`, which throws `APIError("FORBIDDEN")`. If the variable is empty, all sign-ups are refused. Hiding the UI is not relied on. |
| S2 | No way to reset the account password | **Resend** is added, with Better Auth `emailVerification` (`requireEmailVerification: true`) and `sendResetPassword`. A `mailer` abstraction has two transports: `resend` (production) and `file` (dev, test and CI, which writes messages to `.mail/*.json` so Playwright can read the links). Resend's `onboarding@resend.dev` sender only delivers to the Resend account owner, which is enough for a personal vault. A verified domain can come later. |
| S3 | The password-change flow wouldn't work with a non-extractable VK | Two ways of holding the VK:<br>- **Session:** the VK is imported as a *non-extractable* `CryptoKey` and used only for encrypt/decrypt.<br>- **Re-wrap (password change or recovery):** unwrap it again from the stored wrap as a *short-lived extractable* key, wrap it under the new KEK, and drop every reference.<br>The raw VK bytes exist only inside that one function call. |
| S4 | Downgrading the Argon2 settings | `packages/crypto` hard-codes a **floor** (m ≥ 64 MiB, t ≥ 3, p ≥ 1) and a **ceiling** (m ≤ 1 GiB, t ≤ 10, p ≤ 4, to stop a server from pushing absurd values). It refuses any server-supplied settings outside those bounds, before deriving anything. |
| S5 | "Wiped from memory" was overstated | On lock:<br>- drop the VK;<br>- clear the decrypted entries store, the search index, all form state and the React Query cache;<br>- remount the vault tree.<br>Copying a secret sets a 30-second timer that clears the clipboard, but only if the tab still has focus (a browser limit). A `SECURITY.md` states plainly that JavaScript cannot guarantee memory is erased: plaintext may linger until garbage collection. |
| S6 | Versions not pinned | Pinned as listed above. The schema uses Prisma 7 syntax: `prisma.config.ts` holds the datasource URL, and the generator is `prisma-client` with an explicit `output`. |

### Fixes for the moderate issues
| # | Gap | Fix |
|---|---|---|
| M7 | The auth tool could overwrite the schema | `@better-auth/cli generate` runs **once**. After that, `schema.prisma` is maintained by hand, with a comment at the top saying so. |
| M8 | Offline brute-forcing of the master password | Better Auth `rateLimit: { enabled: true, storage: "database" }` (in-memory storage is useless on serverless) with stricter custom rules for `/sign-in/*`. Also adds **account two-factor login** (Better Auth `twoFactor` plugin, TOTP) for *account login*. This is separate from vault TOTP entries, which are still out of scope. |
| M9 | Account and master password could be the same | A strong warning at vault setup ("must differ from your account password"). Plus a strength meter (zxcvbn-ts) with a minimum score. |
| M10 | Multiple tabs | A `BroadcastChannel("cipher-vault")` carries `lock` and `activity` messages, so locking or activity in any tab applies to every tab. Idle means no activity in *any* tab. |
| M11 | CSP details | `proxy.ts` generates a nonce per request. The CSP is:<br>- `script-src 'self' 'nonce-…' 'strict-dynamic'`<br>- `worker-src 'self' blob:`<br>- `connect-src 'self'` plus the R2 endpoint (Phase 5)<br>- `img-src 'self' data: blob:`<br>- `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`<br>`'wasm-unsafe-eval'` is added **only if** hash-wasm is chosen in Phase 2. R2 bucket CORS (PUT and GET only, from the app origin) is part of Phase 5. |
| M12 | Encrypted sizes reveal lengths | Plaintext is padded to buckets (the next multiple of 256 bytes, minimum 512) before encryption, with the length stored inside the encrypted data. Specified in Phase 2. |
| M13 | Files left behind in R2 | On Phase 5 saves, the server checks that `r2Key` starts with `u/<sessionUserId>/` and that the object exists (a HEAD request). Account deletion first deletes the user's R2 prefix. A **Vercel Cron** job (daily) removes objects that have no matching `VaultEntry` and are more than 24 hours old. |
| M14 | No size limits on the server | Zod validation on every vault route:<br>- `encryptedData` ≤ 64 KiB;<br>- `iv` is exactly 12 bytes;<br>- ≤ 5,000 entries per user;<br>- files ≤ 25 MB, enforced by signing `ContentLength` into the presigned PUT (5-minute expiry).<br>The `id` must be a UUID, and updates must match `userId`. |
| M15 | Argon2 may be too slow | See the Phase 2 benchmark rule below. |

---

## Proposed Prisma schema (Prisma 7; for your review)
The Better Auth models (`User`, `Session`, `Account`, `Verification`, `TwoFactor`, `RateLimit`) are generated once, and `User` then gets back-relations to `vaultConfig VaultConfig?` and `entries VaultEntry[]`.

```prisma
generator client {
  provider = "prisma-client"
  output   = "../src/generated/prisma"
}
datasource db { provider = "postgresql" }   // URL lives in prisma.config.ts

enum EntryType { password secure_note file }

model VaultConfig {
  userId              String   @id
  user                User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  cryptoVersion       Int      @default(1)
  vaultKeyVersion     Int      @default(1)    // for future VK rotation
  kdfAlgorithm        String                  // "argon2id"
  kdfSalt             Bytes                   // 16 bytes
  kdfMemoryKiB        Int
  kdfIterations       Int
  kdfParallelism      Int
  masterWrappedKey    Bytes
  masterWrapIv        Bytes
  recoveryHkdfSalt    Bytes
  recoveryWrappedKey  Bytes
  recoveryWrapIv      Bytes
  recoveryCreatedAt   DateTime @default(now())
  autoLockMinutes     Int      @default(5)
  createdAt           DateTime @default(now())
  updatedAt           DateTime @updatedAt
}

model VaultEntry {
  id              String    @id @db.Uuid   // client-generated; bound into AES-GCM AAD
  userId          String
  user            User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  type            EntryType                // plaintext (your choice)
  cryptoVersion   Int       @default(1)
  vaultKeyVersion Int       @default(1)
  encryptedData   Bytes                    // padded JSON (title, site, username, … | fileName, mimeType, size)
  iv              Bytes
  r2Key           String?   @unique        // "u/<userId>/<uuid>", never derived from filename
  blobIv          Bytes?
  blobSize        Int?
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt      // last-write-wins
  @@index([userId])
}
```

**What the server can see:** the number of entries by type, when each was created and edited, the approximate file size, and the rough size of each entry (padded to buckets). Everything else is encrypted. The AAD binds `entryId`, `userId`, `type`, `cryptoVersion` and `vaultKeyVersion`, so ciphertexts can't be swapped between entries or have their type changed.

Approving this plan approves the schema. The first migration runs only after approval.

---

## Phase 1: what gets built

### Repository and tooling
- Scaffold with `pnpm dlx shadcn@latest init`, using the **Next.js monorepo template**. That gives a Turborepo, `apps/web`, and a shared `packages/ui` with Tailwind v4 already wired. Then rename `@workspace/*` to `@cipher/*` and add `packages/db` and `packages/crypto`.
- Layout:
  - Root files: `package.json` (with `packageManager: pnpm@<latest>` and engines `22.x`), `pnpm-workspace.yaml`, `turbo.json` (build, dev, lint, typecheck, test, test:e2e, db:generate), `tsconfig` base, `.gitignore`, `.env.example`, `README.md`, `SECURITY.md`.
  - `apps/web`: Next 16 with the App Router, plus `components.json` (shadcn aliases point to `@cipher/ui`).
  - `packages/ui`: shadcn components in `src/components`, `src/styles/globals.css`, and its own `components.json`.
  - `packages/db`: `prisma/schema.prisma`, `prisma.config.ts`, and `src/index.ts`, which exports a `prisma` singleton through `PrismaPg` that is safe with hot reload.
  - `packages/crypto`: **a skeleton only**. No crypto code until the Phase 2 walkthrough is approved.
- **Tailwind v4 with shadcn:** `packages/ui/src/styles/globals.css` contains `@import "tailwindcss"`, the shadcn theme tokens, and `@source "../../../apps/**/*.{ts,tsx}"` plus `@source "../**/*.{ts,tsx}"`. `apps/web` imports that CSS, so the classes used by the shared components are generated. Initial shadcn components: button, input, label, card, form, sonner, dialog, alert.
- **Git:** `git init -b main`, add `origin` as `https://github.com/Itzsoham/cipher.git`, and make a first commit. Push to `origin main` once the Phase 1 verification passes. `.env*` and `.mail/` are gitignored.

### apps/web auth
- `src/lib/auth.ts` configures `betterAuth` with:
  - the Prisma adapter;
  - `emailAndPassword` with `minPasswordLength: 12`, `requireEmailVerification`, and `sendResetPassword`;
  - `emailVerification.sendVerificationEmail`;
  - the plugins `twoFactor()` and `nextCookies()`;
  - database-backed `rateLimit`;
  - the allowlist hook from S1.
- `src/lib/mailer.ts` holds the Resend and file transports.
- `src/lib/auth-client.ts` uses `createAuthClient` with the `twoFactorClient` plugin.
- `src/app/api/auth/[...all]/route.ts` uses `toNextJsHandler(auth)`.
- `src/proxy.ts` does two things: it redirects to sign-in when there is no session cookie (`getSessionCookie`), and it sets the CSP nonce and security headers. The `(app)` layout also runs a real `auth.api.getSession` check on the server.
- Pages:
  - `(auth)`: sign-in, sign-up, verify-email, forgot-password, reset-password, 2fa.
  - `(app)`: `/vault` is a placeholder with the account email and sign-out; `/settings/security` enables or disables account two-factor login.
- `.env.example` lists `DATABASE_URL` (Neon, pooled), `DIRECT_URL` (for migrations), `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL`, `SIGNUP_ALLOWLIST`, `RESEND_API_KEY`, `MAIL_FROM` and `MAIL_TRANSPORT`.

### Tests and CI (basic cases for now)
- **Playwright** (`apps/web/e2e`), run with `MAIL_TRANSPORT=file`:
  1. A non-allowlisted sign-up is rejected.
  2. An allowlisted sign-up leads to a verification email, then the link verifies the account and it can sign in.
  3. An unverified sign-in is blocked.
  4. Sign-out works, and `/vault` redirects to sign-in when signed out.
  5. Forgot password: the reset link works, the old password fails, and the new one works.
  6. The response headers include the CSP with a nonce, `frame-ancestors 'none'` and `no-referrer`.
- **Vitest** is wired into `packages/crypto` (a placeholder test for now; the real crypto tests come in Phase 2).
- **GitHub Actions** (`.github/workflows/ci.yml`), on push and PR:
  - pnpm install (cached);
  - `turbo typecheck lint test build`;
  - Playwright against a `postgres:17` service container, after `prisma migrate deploy`;
  - on failure, upload the Playwright report.

### What I need from you
- Neon pooled and direct URLs (a dev branch).
- A Resend API key. The file transport works without one, but a real inbox needs it.
- Your email for `SIGNUP_ALLOWLIST`.
- For Vercel: connect the GitHub repo and set the same environment variables. I'll document exactly which ones.

### Phase 1 verification
1. `corepack enable && pnpm install`, then `pnpm turbo typecheck lint build` passes.
2. `pnpm --filter @cipher/db db:migrate` runs against the Neon dev branch. Prisma Studio shows the auth tables plus empty `VaultConfig` and `VaultEntry` tables.
3. `pnpm turbo test:e2e` passes locally, with all six Playwright cases green.
4. A manual pass with `pnpm dev`: the sign-up → verify → sign-in → enable 2FA → sign-out → sign-in with TOTP flow works.
5. Push to GitHub; the CI run is green.

**Stop here and confirm with you.**

---

## Later phases (each one starts after your go-ahead)

**Phase 2: packages/crypto.** First a plain-language walkthrough for approval. It covers the KDF, AES-GCM with a random 96-bit IV, the AAD layout, padding, the recovery key encoding and checksum, the two ways of holding the VK, and the KDF floor and ceiling.

**Benchmark rule (your instruction):**
- Benchmark `@noble/hashes` and `argon2-browser` at 64 MiB and 3 passes, in a Web Worker.
- Run them on desktop Chrome and on a mid-range mobile profile (Chrome DevTools CPU throttling at 4–6x, plus a real phone if one is available).
- If either takes more than about 1–1.5 s on desktop or about 3 s on mobile, switch to **hash-wasm** without asking again, and add `'wasm-unsafe-eval'` to the CSP.
- Report the actual numbers and the final choice either way.

Then the implementation, with Vitest tests:
- round trips;
- tampering with the ciphertext, IV or AAD makes decryption fail;
- a wrong password fails;
- KDF settings below the floor or above the ceiling are rejected;
- recovery re-wraps the key correctly;
- padding round trips;
- Argon2id and HKDF known-answer vectors.

**Phase 3: vault flows.**
- Setup: master password with the strength meter and the "must differ from your account password" warning, then the recovery key shown once. You confirm it by typing the last group, and there is a `.txt` download.
- Unlock, forgot master password (via the recovery key), and change master password.
- In-memory VK only, cleanup on lock (S5), clipboard clearing, auto-lock synced across tabs (M10, default 5 minutes, configurable).
- Playwright: setup → lock → unlock, wrong password, recovery.

**Phase 4: entries.**
- Server routes with the Zod limits from M14.
- Create, edit and delete for password and secure-note entries.
- In-memory search.
- A password generator using `getRandomValues` with rejection sampling.
- Playwright for adding, editing, deleting and searching.

**Phase 5: files.**
- Encrypt in the browser, then upload through a presigned PUT (with a signed `ContentLength`).
- Download through a presigned GET, then decrypt and save in the browser.
- R2 CORS settings, the ownership check and HEAD check (M13), and the Vercel Cron cleanup of orphaned files.
- A 25 MB cap, because v1 uses single-shot AES-GCM.

## Post-v1 roadmap (planned, not built in v1)
- **Encrypted export and backup:** a `.cipher` export file that contains all entries and files, encrypted under a separate export password (Argon2id) so it can be restored without the server. It also covers the "Neon lost" and "both secrets lost" cases. Import restores into a fresh vault.
- **Vault Key rotation:** generate a new VK, then re-encrypt every entry and R2 file in the browser in resumable batches (tracked by `vaultKeyVersion`, which the schema already has). Finally re-wrap under the master password and recovery key and increase `VaultConfig.vaultKeyVersion`. Triggered manually, or suggested after a recovery.
- Chunked streaming encryption for files over 25 MB.
- A verified Resend sending domain.
