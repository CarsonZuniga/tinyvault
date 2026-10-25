# Security

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting (Security tab, "Report a
vulnerability"). Do not open a public issue.

## What tinyvault protects against

- Secret values are encrypted at rest with AES-256-GCM using the master key.
  Project, environment and key names are not encrypted.
- Hosts never connect to the vault, so a compromised target host cannot reach it.
- The admin password is stored as an Argon2id hash (64 MiB, 3 iterations,
  parallelism 2, 16-byte salt, 12-character minimum).
- Sessions use HttpOnly, SameSite=Strict cookies, expire after 30 minutes idle
  or 12 hours total, and requests that change state require a CSRF token.
- Login is rate limited to 5 attempts per 15 minutes per IP and 50 globally.
  Behind a proxy, set TINYVAULT_IP_HEADER so the real client IP is used.
- Pushed files are replaced atomically with 0600 permissions. The host key is
  saved on first connection, and pushes stop if it changes until you forget it.
- Reveals, exports, edits and pushes are recorded in the audit log.

## What it does not protect against

- Anyone with both the database and the master key can read every secret.
- The vault's SSH key is trusted on every target host. Protect the vault host.
- There is no built-in TLS. Run it behind a reverse proxy and set
  TINYVAULT_SECURE_COOKIES=true.

## Recommendations

- Use a long admin password.
- Back up the master key somewhere other than next to the database.
- Do not expose the vault to the internet unless you need to.
