# Static analysis

## Method and confidence

The sample was analyzed statically as an ELF64 x86-64 Go binary. The sample
was never executed. Function names, package structure, strings, control flow,
and cryptographic parameters were recovered from the binary and cross-checked
against a source-level reconstruction used only for comparison.

This document describes the observed build. Other builds or variants may
differ in paths, thresholds, process lists, or note text. Treat every indicator
as a hunting lead, not a guarantee.

## Identity

- Internal module and package naming uses `encfile`.
- Main package: `encfile/cmd/lock`.
- CLI framework: Cobra, with pflag.
- Go toolchain: 1.22.12, `CGO_ENABLED=0`, `-trimpath`, Linux amd64.
- Version string: `dev`.
- The binary is stripped of some symbol metadata but retains Go build
  information and function metadata.

## Execution flow

### 1. Try-run by default

The `lock` command requires `--lock` to encrypt. Without it, the binary prints a
try-run banner and only scans and counts candidate files. This is useful for
defense: an attacker may first run the binary without `--lock` to estimate the
target set without modifying files.

### 2. Embedded-key check

At start, the command parses an embedded RSA public key. If parsing fails, it
returns an error instead of encrypting. The private key is not embedded.

### 3. Instance lock

The locker opens `/var/tmp/.X11-lock-session.run` and attempts an exclusive,
non-blocking `flock`.

- If another process holds the lock, the binary prints an instance-lock message,
  attempts self-delete, and exits.
- If the filesystem does not support `flock`, it prints a warning and continues.

The lock path is separate from the run marker path.

### 4. Run marker

The run marker is `/var/tmp/.X11-lock-session`.

- The marker is created with `O_CREATE|O_EXCL` and receives the byte `1`.
- If the marker already exists, the binary treats the host as already processed,
  attempts self-delete, and exits.
- The marker is checked before the main encryption loop and claimed again after
  password wrapping, closing a race between concurrent starts.

### 5. Process termination

Before encrypting, the binary runs `killall -9` against:

```text
mongod
redis-server
mysqld
postgres
postmaster
oracle
```

It also has a per-extension holder map for database and Office files. The map
uses Windows process names such as `sqlservr.exe`, `mysqld.exe`, `outlook.exe`,
and `winword.exe`; on Linux those names often do not exist, so the per-extension
kill attempts frequently fail. The fixed daemon list is the more relevant
Linux behavior.

### 6. Discovery

Default roots are:

```text
/home
/var/lib
/var/www
/opt
/srv
```

It also enumerates existing child directories under `/mnt` and `/media`, and
adds non-system top-level directories from `/`.

System-critical and temporary paths are skipped or refused, including `/proc`,
`/sys`, `/dev`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/usr`, `/etc`, `/tmp`, and
`/var/tmp`.

Explicit `--include-dir` paths can enter hidden or normally skipped directories,
but system-critical paths remain refused.

### 7. File selection

The binary carries 181 built-in glob patterns covering documents, databases,
archives, images, media, source/config files, key material, virtual disks, and
machine-learning models. It skips:

- directories matching its excluded-name list;
- dotfiles and dot-directories;
- non-regular files;
- files ending in `.locked`;
- `encfile.keys.txt`, `README_DECRYPT.txt`, `README.txt`, and
  `HOW_TO_DECRYPT.txt`;
- its own executable and backup-name variants;
- files excluded by `--exclude-file`.

Include and exclude lists are appended to the defaults; exclude wins.

### 8. Worker behavior

The worker pool is capped at eight workers. Each file is opened read/write,
optionally locked with `flock`, checked for an existing footer, then encrypted.

On a busy file, the worker kills the matching holder, waits 300 ms, and retries
once. Persistent occupancy is reported as a skip. Other errors are reported as
failures.

On success, the original path is renamed to `<name>.locked`.

### 9. Encryption

The format is described in [encryption-format.md](encryption-format.md).

Key points:

- 32 random bytes are generated and base64-encoded as the password.
- The raw password is RSA-OAEP-SHA256 wrapped under the embedded public key.
- A 16-byte per-file salt and 16-byte per-region nonces come from
  `crypto/rand`.
- Argon2id derives a 64-byte output: AES key and MAC key.
- Full mode encrypts `[0, original_size)` as one region.
- Intermittent mode encrypts five 4 MiB regions: head, tail, and three evenly
  spaced middle regions.
- The footer is appended at EOF, then the file is synced.
- The original mtime is restored.

### 10. Ransom note

For each directory containing selected files, the binary writes
`README_DECRYPT.txt` with mode `0644` before the file loop. The note contains a
manifest of selected filenames and a wrapped-password field. The attacker
contact identifier and exact note text are intentionally not republished.

The note is skipped by the file-selection logic, so it is not encrypted.

### 11. Cleanup

At the end of the run, the binary attempts to delete itself with:

```text
sh -c "sleep 2 && rm -f '<executable path>'"
```

This is launched asynchronously. A host may therefore have no sample binary
left after execution, even though the marker, lock, notes, and encrypted files
remain.

## What was not observed

- No application-level HTTP, HTTPS, or TLS C2.
- No hard-coded command-and-control URLs.
- No cron, systemd, registry, or startup persistence.
- No local private key or key-recovery secret.
- No evidence that the binary exfiltrates file contents.

Network-related symbols in a Go binary can come from standard-library crypto
and certificate code. Their presence alone is not evidence of C2.

## High-value detection points

1. Creation of `/var/tmp/.X11-lock-session` or
   `/var/tmp/.X11-lock-session.run`.
2. `killall -9` against database service names.
3. `sh -c` command containing `sleep 2` and `rm -f` against the running binary.
4. A directory containing `README_DECRYPT.txt` plus `.locked` files.
5. Files whose last four bytes are `ENCF` and whose footer validates as
   `ENCH`.
6. The sample hash or Go build ID, when available.

## Limitations

The analysis is static and build-specific. No runtime detonation was performed.
See [limitations.md](limitations.md).
