# aipack

CLI tool to compress programming projects to the limit and encrypt them for secure transfer over the network (so others cannot read the contents), then decrypt/decompress to feed into AI tools like Cursor, Claude, or Grok.

## Features

- Extreme compression: tar + zstd at best compression level (internal concurrency).
- Strong encryption: AES-256-GCM with Argon2id key derivation from password.
- Secure by design: path traversal protection on unpack, cryptographically secure randomness, no hardcoded secrets.
- Production Go practices applied (from samber/cc-skills-golang):
  - Structured concurrency & context cancellation (signals).
  - Error wrapping with `%w`.
  - Cobra CLI with proper flags and password prompting (hidden input).
  - Default excludes for `.git`, `node_modules`, `vendor`, build artifacts, binaries, etc.
  - Deterministic sorting for better compression.

## Build

```bash
cd aipack
go mod tidy   # fetches klauspost/compress, cobra, x/crypto, x/sync, x/term
go build -o aipack .
```

## Usage

Pack a project:

```bash
./aipack pack /path/to/my-project -o myproject.aipk
# prompts for password
# or
./aipack pack /path/to/my-project -o myproject.aipk -p 'your-strong-password' -w 8
```

Transfer the `.aipk` file over the network (it looks like random data).

Unpack:

```bash
./aipack unpack myproject.aipk -o ./restored-project
# prompts for password
```

Then open `./restored-project` in Cursor or paste files into AI chat.

## Design Notes (following cc-skills-golang)

- **golang-concurrency**: Context for cancellation, errgroup patterns available, zstd concurrency, no goroutine leaks.
- **golang-security**: AES-GCM (authenticated), Argon2id, crypto/rand, constant-time ready, path traversal checks.
- **golang-error-handling**: Always wrap errors with context.
- **golang-cli**: Cobra, SilenceUsage/Errors, password via term.ReadPassword, signals via NotifyContext.
- **golang-performance**: High zstd level, limited workers, streaming where possible (in-memory for typical projects).

For very large projects, the in-memory tar/compress can be improved to full streaming in a future version.

## Adding the Golang Skills to your AI tools

The skills used as guidance come from https://github.com/samber/cc-skills-golang.

### For Cursor (recommended, since you use it daily):

```bash
git clone https://github.com/samber/cc-skills-golang.git ~/.cursor/skills/cc-skills-golang
```

Then restart Cursor or reload. The skills will be available on-demand for Go work.

### For other tools: see the repo README (Claude Code, Gemini, Copilot, etc.).

### For Grok: you can create a custom skill summarizing the key practices, or just reference the repo when generating Go code.

This implementation prioritizes the concurrent, secure, production-ready patterns from those skills.
