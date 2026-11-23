# aipack

CLI tool to compress a programming project and encrypt it for transfer, then decrypt and extract it so the sources can be fed to an AI tool.

## Features

- tar + zstd, streamed into framed AES-256-GCM (version 2). The archive is not held in memory as one buffer.
- Argon2id key derivation. Parameters are stored in the header and rejected when they exceed the production cost.
- Version 1 archives (one GCM blob) can still be unpacked.
- Path checks use `filepath.IsLocal` and `os.Root`. Symlinks are not followed while packing and are refused while unpacking.
- Default excludes for `.git`, `node_modules`, `vendor`, build outputs, and binaries.
- Password from a prompt, `AIPACK_PASSWORD`, or `-p` (the flag is warned about because it shows up in the process list).

## Build

Requires Go 1.24 or newer (`os.Root`).

```bash
go build -o aipack .
```

## Usage

```bash
./aipack pack /path/to/my-project -o myproject.aipk
# prompts for a password

AIPACK_PASSWORD='your-strong-password' ./aipack pack /path/to/my-project -o myproject.aipk

./aipack unpack myproject.aipk -o ./restored-project
```

`--max-bytes` defaults to 8 GiB and applies to the source size when packing and to the extracted size when unpacking. `--exclude` adds glob patterns matched against each path component. `--no-default-excludes` turns off the built-in list.

Exit codes: `0` success, `1` operational error, `2` usage error, `130` interrupt.

## Archive format (version 2)

```
magic "AIPK" | version 2 | argon2 time u32 | memory u32 | threads u8
salt 16 | nonce prefix 8
repeated frames: flags u8 | ciphertext length u32 | AES-GCM ciphertext
```

Each frame nonce is `prefix || counter`. The last frame is authenticated as final, so a truncated file does not unpack. Pack writes a temporary file in the destination directory and renames it into place. Unpack extracts into a temporary directory and publishes it only after the archive checks out.

## Tests

```bash
go test -race ./...
```
