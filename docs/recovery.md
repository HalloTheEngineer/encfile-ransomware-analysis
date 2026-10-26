# Recovery guidance

## First: preserve evidence

1. Isolate the host from the network without wiping memory or disks.
2. Do not run the sample, "decryptors" from the attacker, or untrusted recovery
   utilities.
3. Work from copies or read-only snapshots. Never test a tool against the only
   copy of a file.
4. Record hashes, file sizes, timestamps, and the full paths of notes,
   `.locked` files, and `/var/tmp` artifacts.
5. Capture relevant logs and process telemetry before rebooting.

## Decision tree

### Do you have the operator RSA private key?

The sample embeds only an RSA public key. The private key is not on the victim
host. Without it, the wrapped password cannot be recovered from the public key.

- **No private key:** full recovery of encrypted regions is not possible from
  the file alone. Continue with backup restoration and partial-gap recovery.
- **Private key recovered separately:** recovery may be possible. Use an
  isolated environment, verify the key and wrapped blob, derive the password
  with Argon2id, and decrypt with AES-256-CTR. Validate the HMAC before trusting
  the output. Do not assume a random third-party tool is correct.

### Are backups or snapshots available?

This is the safest and most complete path. Restore to a clean host, verify
application consistency, rotate credentials, and investigate the initial
access path before returning to service.

### Are the files fully or intermittently encrypted?

Use the footer inspector:

```bash
python3 tools/inspect_footer.py --json /path/to/file.locked
```

- `mode: 0` means the whole original file body was encrypted.
- `mode: 1` means five 4 MiB regions were encrypted; other ranges remain
  plaintext unless overwritten by the filesystem or other activity.

The `gaps` field lists the unencrypted ranges. A gap is not automatically a
valid file; it is a range that was not part of the encryption plan.

## Partial recovery from intermittent files

For `mode: 1`, copy the unencrypted ranges from a **copy** of the file:

```bash
# Example only: use the offset/length reported by inspect_footer.py
dd if=file.locked of=gap-000.bin \
  iflag=skip_bytes,count_bytes \
  skip=OFFSET count=LENGTH status=progress
```

Then:

- Identify the fragment with `file`, `binwalk`, database page inspection, or
  application-specific parsers.
- Check for internal checksums, page headers, or document structure.
- Treat recovered content as untrusted and potentially incomplete.
- Correlate with backups, replicas, WAL/binlog, caches, and snapshots.
- Do not overwrite original evidence with carved output.

A partial fragment may be useful for triage, but it is not a restored file.
For databases, page-level recovery is usually inconsistent unless the engine's
own recovery tooling can validate the pages.

## What not to do

- Do not pay the ransom solely on the basis of the note.
- Do not run attacker-supplied binaries.
- Do not assume a structurally valid footer means the file is recoverable.
- Do not delete `/var/tmp` artifacts, notes, or logs before capturing them.
- Do not "repair" the footer or truncate the file unless working on a copy and
  documenting every change.

## If a private key is recovered

High-level recovery steps, for authorized responders:

1. Work offline on a copy.
2. Extract the wrapped password blob from the note or key material.
3. Unwrap with RSA-OAEP-SHA256 using the matching private key.
4. Derive the 64-byte Argon2id output with the footer salt and the observed
   parameters (`t=1`, `m=64 MiB`, `p=4`).
5. Use the first 32 bytes as the AES-256-CTR key and the remaining 32 bytes as
   the HMAC key.
6. Verify the HMAC over the footer metadata and ciphertext before decrypting.
7. Decrypt each region with its recorded nonce.
8. Restore the original size and validate the result with application-level
   checks.

Do not publish recovered keys, passwords, victim data, or decrypted files.

## When to escalate

Engage legal counsel, law enforcement, and a professional incident-response
team when regulated data, production databases, or extortion is involved.
Preserve evidence and follow applicable breach-notification requirements.
