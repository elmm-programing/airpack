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
make build
./aipack version
```

`make build` injects the git description as the version. `make test` runs `go test -race ./...`.

Shell completion:

```bash
source <(aipack completion bash)
```

`completion` also supports `zsh`, `fish`, and `powershell`.

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

## Measured example

Shallow clone of [elmm-programing/GymTracker](https://github.com/elmm-programing/GymTracker) at `d575ba2cc703de172efa983449423c65a28ad50b`, packed with default excludes and the default best zstd level:

```bash
AIPACK_PASSWORD='your-strong-password' ./aipack pack GymTracker -o gymtracker.aipk
```

| Tree | Bytes |
| --- | ---: |
| Clone, including `.git` | 6,999,514 |
| Worktree, without `.git` | 5,128,894 |
| Bytes actually packed | 4,999,063 |
| `.aipk` archive | 1,439,585 |

The archive is 3.47 times smaller than the packed bytes (71.2% smaller). The wall time was 0.29 seconds, including Argon2id. Default excludes omitted `.git`, `.vscode/settings.json`, and `android/build/`. Unpack restored all 498 files and 212 directories. `pubspec.yaml` and `lib/core/widgets/skeleton_loading.dart` matched the source byte for byte.

GCM adds a 16-byte tag per 1 MiB frame plus the 38-byte header, so almost all of the savings are from zstd.

## Tests

```bash
go test -race ./...
```
