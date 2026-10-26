# Encryption format

This document describes the on-disk format observed in the sample. It is
intended for forensic validation, detection, and recovery planning. It is not a
decryptor and does not provide key material.

## Crypto summary

| Component | Value |
| --- | --- |
| Password | 32 random bytes, base64 RawStd |
| Password wrapping | RSA-2048 OAEP-SHA256, empty label |
| Salt | 16 random bytes per file |
| KDF | Argon2id, t=1, m=64 MiB, p=4, output 64 bytes |
| AES key | Argon2id output `[0:32]` |
| MAC key | Argon2id output `[32:64]` |
| Bulk cipher | AES-256-CTR |
| Region nonce | 16 random bytes per encrypted region |
| Integrity | HMAC-SHA256 over footer metadata and ciphertext |

The password is generated as random bytes, not chosen by the victim. Argon2id
with `t=1` is weak against password guessing, but the 256-bit random password
makes guessing impractical without the RSA-wrapped password.

## Modes and thresholds

The mode is selected from the file extension and size:

- **Valuable extensions** (`.txt`, `.md`, `.log`, `.json`, `.xml`, `.yaml`,
  `.yml`, `.csv`, `.html`, `.htm`, `.css`, `.js`, `.ts`, `.go`, `.py`, `.rs`,
  `.c`, `.h`, `.cpp`, `.java`, `.sh`, `.sql`, `.ini`, `.toml`, `.conf`, `.cfg`):
  full encryption below **1 GiB**, intermittent at or above 1 GiB.
- **All other whitelisted files**: full encryption below **20 MiB**,
  intermittent at or above 20 MiB.

If intermittent planning fails or returns no regions, the implementation falls
back to full encryption.

## Full mode

- `mode = 0`
- `region_count = 1`
- Region: offset `0`, length `original_size`
- The entire file body is XORed with the AES-CTR keystream.

## Intermittent mode

- `mode = 1`
- `region_count = 5`
- Five regions of 4 MiB each, always 20 MiB total:

```text
region 0: offset 0
region 4: offset size - 4 MiB
step    = (size - 20 MiB) / 4
region i (i = 1..3): offset i * (step + 4 MiB)
```

Each region receives a fresh nonce. The middle math requires a file large
enough to hold the head, tail, and three middle regions; if planning cannot
satisfy that constraint, the caller falls back to full encryption.

The gaps between regions remain plaintext. That is why intermittent files may
retain recoverable fragments, but only at the unencrypted offsets.

## Footer layout

The footer is appended at EOF. Offsets below are relative to the start of the
footer, not the start of the file.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `ENCH` |
| 4 | 1 | version, observed `1` |
| 5 | 1 | mode: `0` full, `1` intermittent |
| 6 | 16 | Argon2id salt |
| 22 | 8 | original file size, uint64 little-endian |
| 30 | 1 | region count: `1` full, `5` intermittent |
| 31 | `32 * N` | regions: offset uint64, length uint64, nonce 16 bytes |
| `31 + 32*N` | 32 | HMAC-SHA256 |
| `63 + 32*N` | 4 | footer length, uint32 little-endian |
| `67 + 32*N` | 4 | trailer `ENCF` |

The declared footer length is `0x47 + 32*N`, where `N` is the region count.

The end of the file therefore contains:

```text
[ original data ][ metadata ][ HMAC ][ length ][ ENCF ]
```

The last 8 bytes are the length and trailer:

- `length` at `file_size - 8`
- `ENCF` at `file_size - 4`
- footer start at `file_size - length`

## HMAC coverage

The HMAC is computed over:

1. the serialized metadata bytes from `ENCH` through the last region nonce
   (`31 + 32*N` bytes); and
2. the ciphertext bytes of every region, read back in 256 KiB chunks.

The HMAC does not cover the password, plaintext, filename, or filesystem
metadata. It can detect corruption of the ciphertext and metadata when the MAC
key is available.

## Structural validation versus decryption

The sample's `IsEncrypted` check validates only:

- `ENCF` at `file_size - 4`;
- a plausible length at `file_size - 8`;
- `ENCH` at the computed footer start;
- version `1`;
- mode/count consistency (`0/1` or `1/5`).

It does **not** verify the HMAC. A structurally valid footer is not proof that
the file is authentic, undamaged, or encrypted by this exact build. Use
`tools/inspect_footer.py` for a metadata-only check and validate the HMAC only
when the key is available.

## Size relationships

For a normally produced file:

```text
file_size = original_size + (0x47 + 32*N)
```

If the observed relationship differs, preserve the file and investigate
possible truncation, appended data, filesystem corruption, or a different
variant. The inspector reports the observed sizes and a consistency warning;
it does not modify the file.

## What is not recoverable without the key

- Fully encrypted regions have no plaintext copy in the file.
- The RSA private key is not present in the sample.
- The wrapped password cannot be unwrapped from the public key alone.
- HMAC verification cannot be completed without the derived MAC key.

For recovery guidance, see [recovery.md](recovery.md).
