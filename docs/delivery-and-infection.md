# Delivery and infection

This document separates two questions that are often conflated:

- **Delivery:** how the binary reaches a host and obtains execution.
- **Infection:** what the binary does after it runs.

The sample is a payload, not an initial-access tool. It contains no delivery
mechanism and no ability to spread on its own.

## Scope and evidence

The conclusions below come from static analysis of the sample and from the
observed incident delivery path. Initial-access specifics, the affected
service, exploit syntax, and victim details are intentionally withheld. The
sample was never executed.

## Does it spread automatically?

No. The following capabilities were not observed:

| Capability | Observed in this sample? |
| --- | --- |
| Network scanning or host discovery | No |
| SMB, SSH, or credential brute force | No |
| Built-in remote-exploit payloads | No |
| Worm-style self-replication | No |
| Command-and-control beaconing | No |
| Email, removable-media, or supply-chain spreading | No |
| Persistence through cron, systemd, or startup entries | No |

It is an offline command-line locker. Each host needs separate delivery and
execution; the binary does not move from an infected host to another host by
itself.

Network-related symbols can appear in Go binaries because of standard-library
crypto and certificate code. Their presence is not evidence of C2.

## How it is delivered

The observed pattern is external compromise followed by payload staging:

1. An attacker obtains execution or application-level access through an
   Internet-exposed service.
2. The attacker uses that access to stage the binary on the host or in a
   location the host can execute.
3. The staged binary is launched with `--lock`.
4. Without `--lock`, the binary only performs a scan-only try-run.

The delivery step is outside the binary. It may be manual, scripted, or part of
a larger exploitation workflow. The locker itself does not create the initial
foothold, discover other hosts, or propagate.

The observed incident used encoded chunks to stage the payload through the
compromised service. Exact commands, service names, and vulnerability details
are not republished; they are not required to detect the locker and would
increase the risk of re-identifying the victim.

## Execution timeline

### 1. Optional try-run

Without `--lock`, the binary prints a try-run banner and counts candidate files
without modifying them. This can reveal target directories, file counts, and
selected filenames in process output or logs.

### 2. Preflight

With `--lock`, the binary:

- verifies that its embedded RSA public key parses;
- opens `/var/tmp/.X11-lock-session.run` and tries an exclusive, non-blocking
  `flock`;
- exits and attempts self-delete if another instance holds the lock;
- checks `/var/tmp/.X11-lock-session` and exits if the run marker already
  exists;
- generates a random per-run password and wraps it with RSA-OAEP-SHA256;
- claims the run marker with `O_CREATE|O_EXCL` and writes `1`.

If the filesystem does not support `flock`, the binary warns and continues.

### 3. Service disruption

Before encrypting, it runs `killall -9` against common database daemon names:

```text
mongod
redis-server
mysqld
postgres
postmaster
oracle
```

It also contains per-extension holder mappings for database and Office files.
Many of those mappings use Windows process names; on Linux, the fixed daemon
list is the more relevant behavior.

### 4. Discovery

Default roots are `/home`, `/var/lib`, `/var/www`, `/opt`, and `/srv`. It also
enumerates child directories under `/mnt` and `/media`, plus non-system
top-level directories under `/`.

It avoids system-critical paths and temporary areas such as `/proc`, `/sys`,
`/dev`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/usr`, `/etc`, `/tmp`, and
`/var/tmp`. Explicit include paths can enter hidden directories, but
system-critical paths remain refused.

### 5. File selection

The binary carries 181 whitelisted glob patterns covering documents,
databases, archives, source/config files, certificates, images, virtual disks,
and machine-learning models. It skips hidden files, non-regular files,
`.locked` files, its own executable, and its own note/key artifacts.

### 6. Encryption

Each selected file is modified in place:

- **Full mode:** the entire original body is encrypted with AES-256-CTR.
- **Intermittent mode:** five 4 MiB regions are encrypted, totaling 20 MiB:
  the head, the tail, and three evenly spaced middle regions.

The mode depends on extension and size:

- valuable text/config/data extensions: full below **1 GiB**, intermittent at
  or above 1 GiB;
- other whitelisted files: full below **20 MiB**, intermittent at or above
  20 MiB.

A per-file salt and per-region nonces are generated. Argon2id derives the AES
and HMAC keys from the random password and salt. The password itself is wrapped
with RSA-OAEP-SHA256 under the embedded public key; the note carries that
wrapped value. This is not one shared wrapped AES key.

An `ENCH ... ENCF` footer is appended with the salt, original size, mode,
region offsets, region lengths, nonces, and HMAC-SHA256. The original mtime is
restored, atime is set to the current time, and the file is renamed to
`<name>.locked` after a successful write.

### 7. Database and application impact

Full mode destroys the entire file body. Intermittent mode destroys only the
selected 20 MiB.

For large databases, intermittent encryption may hit control structures,
metadata pages, indexes, or WAL files if they fall inside the selected
regions. It does **not** guarantee that every control page is encrypted.
Partial page damage can still make a database fail to start or fail
consistency checks, even when large data ranges remain untouched.

### 8. Extortion note

For each directory containing selected files, the binary writes
`README_DECRYPT.txt` with mode `0644` before encrypting the files. The note
contains a directory manifest and a wrapped-password field. Attacker contact
details, payment amounts, and the exact note body are not republished.

The note is skipped by the selection logic, so it is not encrypted.

### 9. Cleanup

At the end of the run, the binary attempts to remove itself:

```text
sh -c "sleep 2 && rm -f '<executable path>'"
```

The shell is launched asynchronously. The host may retain no sample binary
after execution, while the marker, lock, notes, and `.locked` files remain.

## What this means for defenders

- Treat the locker and the initial-access vulnerability as separate findings.
  Removing the locker does not close the entry point.
- Look for unusual child processes from Internet-facing services, staged
  files, and encoded transfer activity before the encryption window.
- Hunt for the run-state files, `killall` behavior, ransom notes, `.locked`
  renames, and the `ENCH/ENCF` footer.
- Preserve the marker, lock file, notes, logs, and a copy of any surviving
  binary before cleanup. The sample may delete itself.
- Do not expect a C2 domain or beacon to identify this build.

## Unknowns

- The exact initial-access path is withheld and is not established by the
  binary alone.
- The observed delivery method may not represent every deployment of this
  family.
- No runtime detonation was performed, so process timing and race behavior are
  reconstructed statically.
- Absence of C2 or persistence in this build does not prove absence in every
  variant.

See [analysis.md](analysis.md) for the execution details and
[detection.md](detection.md) for hunting guidance.
