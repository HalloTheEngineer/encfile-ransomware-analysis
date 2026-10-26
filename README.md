# encfile ransomware: public defensive analysis

Sanitized, static-only analysis of a Go ransomware family identified here as
**encfile**. The sample was never executed. Victim, host, organization, and
infrastructure details have been removed.

> **Defensive research only.** This repository does not contain the malware
> binary, the full reconstruction source, victim data, or attacker contact
> details. Nothing here guarantees decryption.

## At a glance

| Item | Value |
| --- | --- |
| Family | `encfile` |
| Platform | Linux, ELF64 x86-64 |
| Language | Go 1.22.12 |
| Sample SHA-256 | `a8bfba3c98cc0bf2c6af42e1d17e8d34f5a010509c93fe95daf518a663e2112d` |
| Go build ID | `DMxrfknI4YYxMXGiraOX/ebhea_EiXmH1EXNFTqHU/9gcXc7fb_w6bb2Fcmm9_/VswE3-7ZRLy2QP3OzAvD` |
| Embedded RSA-2048 SPKI DER SHA-256 | `2378bf45bb54fb2defc460063c9b43e09870741b62692b7f6acbc3cd7898bb38` |
| Bulk cipher | AES-256-CTR |
| Key derivation | Argon2id, 64 MiB, t=1, p=4, 64-byte output |
| Password wrapping | RSA-2048 OAEP-SHA256 |
| C2 / network exfiltration | None observed in the binary |
| Persistence | None observed |

## Key findings

- The locker uses a per-run random password, but wraps it with an embedded
  RSA-2048 public key. The matching private key is not present on the victim
  host.
- Files are encrypted with AES-256-CTR. Argon2id derives the AES key and
  HMAC-SHA256 key from the random password and a per-file salt.
- Encryption is intermittent for larger files: five 4 MiB regions, totaling
  a fixed 20 MiB per file. Files below the mode threshold are encrypted in
  full.
- Valuable text/config/data extensions remain in full-encryption mode until
  **1 GiB**; other whitelisted files switch to intermittent mode at
  **20 MiB**.
- Encrypted files are renamed with the `.locked` suffix and carry an
  `ENCH ... ENCF` metadata footer. The footer records the salt, original size,
  encryption mode, region offsets, region lengths, and nonces.
- The HMAC is computed over the footer metadata and ciphertext. It cannot be
  verified without the derived MAC key.
- The binary kills common database processes, attempts to kill application
  holders, drops `README_DECRYPT.txt`, restores the original mtime, and then
  deletes itself through a delayed shell command.
- Without the operator RSA private key, fully encrypted files and encrypted
  regions cannot be recovered. Intermittent files may retain plaintext gaps,
  but recovery is partial and must be validated.

## Quick triage

Run these on a suspected host before changing or deleting anything:

```bash
# Ransom notes and locked files in common scan roots
find /home /var/lib /var/www /opt /srv -xdev -type f \
  \( -name 'README_DECRYPT.txt' -o -name '*.locked' \) -print 2>/dev/null

# Run marker and instance lock
stat /var/tmp/.X11-lock-session /var/tmp/.X11-lock-session.run 2>/dev/null

# Process and self-delete indicators
pgrep -af '[k]illall|sleep 2 && rm -f'

# Inspect a suspected footer without decrypting
python3 tools/inspect_footer.py /path/to/suspect.locked
```

Preserve evidence first. Do not run recovery tools against the only copy of a
file. See [docs/recovery.md](docs/recovery.md).

## Repository layout

```text
README.md                     This overview
docs/analysis.md              Static behavior and execution flow
docs/encryption-format.md     Footer, KDF, KEM, and region format
docs/detection.md             Hunting and detection guidance
docs/recovery.md              Safe recovery decision tree
docs/limitations.md           Scope, uncertainty, and false-positive caveats
iocs/                         Hashes, filesystem artifacts, behavior
detections/yara/              Structural footer and note rules
detections/auditd/            File-watch audit rules
detections/sigma/             Linux process-creation rule
tools/inspect_footer.py       Metadata-only footer parser
tools/tests/                  Synthetic, non-victim test fixtures
```

## Detection

Start with [docs/detection.md](docs/detection.md). The highest-signal artifacts
are the separate marker/lock files, `.locked` renames, the `README_DECRYPT.txt`
note, and the ENCH/ENCF footer structure. The YARA footer rule is structural:
it identifies the format, not proof that a particular file was encrypted by
this build.

## Recovery

There is no local private key. The practical recovery paths are:

1. Restore from backups or storage snapshots.
2. Preserve evidence and investigate whether the operator key was recovered
   separately.
3. For intermittent files, identify and carve unencrypted gaps, then validate
   every recovered fragment.
4. Do not modify the only copy. Do not assume a file is unrecoverable merely
   because its footer is malformed.

See [docs/recovery.md](docs/recovery.md) for the full decision tree.

## Scope and ethics

This repository is intended for defenders, incident responders, and detection
engineers. It does not provide a working ransomware sample, a weaponized
builder, victim ciphertext, or attacker contact information. Do not use this
material to deploy, extort, or target systems.

## License

- Documentation: [CC BY 4.0](LICENSE-docs)
- Code: [MIT](LICENSE)

## Contributing

Detection improvements and corrections are welcome. Do not attach live
malware, victim files, credentials, or incident data to public issues. See
[SECURITY.md](SECURITY.md).
