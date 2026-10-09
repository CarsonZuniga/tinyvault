# tinyvault

Tiny, KV-only secrets vault for home servers. Admin login only. Secrets are **pushed** to targets; nothing is served to the network.

## Scope
- KV secrets only; no consumer auth (v1)
- Single Go binary, SQLite, HTMX UI
- Read-only-safe defaults; push is opt-in per target

## Model
Project → Environment → Key/Value (+ version history, `${REF}` support)

## Formats
- **Import:** `.env`, JSON, k8s Secret
- **Export:** `.env`, JSON, shell, Docker secrets (file per key), k8s Secret

## Security
- AES-256-GCM at rest, master key from env/file, ciphertext bound to `project/env/key`
- Argon2id admin password, rate limiting, CSRF, secure cookies
- Values hidden by default; never logged
- Audit log of view/change/export/push

## Push
- SSH to target, atomic write (`0600`), hash-based drift detection
- Optional admin-defined post-command
- SSH keys stored encrypted; host keys pinned

## Layout
```
internal/crypto    done
internal/formats   done
internal/store     SQLite: projects, envs, versions, audit
internal/auth      admin login, sessions
internal/push      SSH targets
internal/web       HTMX UI + handlers
```

## Roadmap
1. Store + admin auth
2. Web UI (CRUD, import/export)
3. SSH push + drift status
4. Later: per-project pull tokens, agent, Cloudflare Access
