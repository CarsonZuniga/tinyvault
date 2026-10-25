# Contributing

tinyvault is deliberately small. Bug fixes, tests and docs are welcome. For new
features, please open an issue first so we can check they fit.

## Setup

Requires Go 1.27 or later.

```sh
go build ./cmd/tinyvault
./tinyvault genkey > dev.key
./tinyvault hash-password > dev.hash
export TINYVAULT_MASTER_KEY_FILE=$PWD/dev.key
export TINYVAULT_ADMIN_HASH_FILE=$PWD/dev.hash
export TINYVAULT_DB=$PWD/dev.db
./tinyvault serve
```

The dev key, hash and database are git-ignored. Never commit them.

## Before opening a PR

CI runs these checks, so run them locally first:

```sh
go install honnef.co/go/tools/cmd/staticcheck@2026.2.1
go install mvdan.cc/gofumpt@v0.12.0

go test ./...
go vet ./...
staticcheck ./...
gofumpt -l .   # should print nothing
```

Keep each PR to one focused change, with a test where it makes sense.

## Security issues

Do not open a public issue. See SECURITY.md.
