# Security

Cipher is a personal, zero-knowledge vault. This file says what it protects against, how, and where the limits are. The full design is in [docs/PLAN.md](docs/PLAN.md).

## Two separate passwords

- **Account password** (Better Auth) signs you in to the server. It can be reset by email. It never touches the vault.
- **Master password** (Phase 3) unlocks the vault in your browser. The server never sees it. There is no email reset for it. The only way back in without it is the recovery key.

Use different values for the two. Two-factor login (TOTP) protects the account sign-in only.

## What the server can see

Account email, sessions, and for the vault: the type of each entry, when it was created and edited, the approximate size of each entry (padded to 256-byte buckets) and of each file. Everything else is encrypted in the browser before upload.

## Account protections (Phase 1)

- Sign-up is limited to `SIGNUP_ALLOWLIST`, enforced on the server in a database hook. Refused sign-ups look the same as accepted ones from outside, so the allowlist cannot be probed.
- Email verification is required before sign-in.
- Passwords are at least 12 characters.
- Rate limits are stored in the database (they must survive serverless cold starts), with stricter rules for sign-in, two-factor, reset and verification endpoints.
- Optional TOTP two-factor login with backup codes.
- A password reset revokes existing sessions.

## Browser hardening

- A Content Security Policy with a fresh nonce per request and `'strict-dynamic'`. Scripts run only if Next.js rendered them with that nonce.
- `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`.
- `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.
- No third-party scripts, analytics or fonts from other origins (fonts are self-hosted at build time).
- `style-src` allows `'unsafe-inline'` because UI components set inline `style` attributes. Style injection cannot run script.

## Known limits

- **Web delivery.** The server ships the JavaScript that does the crypto. A compromised server or deployment could ship code that steals the master password. The CSP and the no-third-party rule narrow this, but cannot remove it.
- **Memory.** On lock the app drops the vault key and clears decrypted data from its stores (Phase 3). JavaScript cannot guarantee memory is erased: plaintext may stay in memory until garbage collection.
- **Clipboard.** Copied secrets are cleared after 30 seconds only if the tab still has focus (a browser limit).
- **Email.** Account password reset is only as strong as the email account that receives the link. It still cannot open the vault.

## Reporting

This is a personal project. Report issues privately to the repository owner.
