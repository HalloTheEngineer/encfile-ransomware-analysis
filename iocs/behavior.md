# Behavior indicators

| Behavior | Observed detail | Confidence |
| --- | --- | --- |
| Try-run default | Scans and counts without `--lock` | High |
| Instance lock | `flock` on `/var/tmp/.X11-lock-session.run` | High |
| Run marker | `/var/tmp/.X11-lock-session`, content `1` | High |
| Database termination | `killall -9` for `mongod`, `redis-server`, `mysqld`, `postgres`, `postmaster`, `oracle` | High |
| Per-extension holder kill | `killall` for database/Office process names; many are Windows `.exe` names | Medium on Linux |
| File rename | `<name>` to `<name>.locked` | High |
| Ransom note | `README_DECRYPT.txt`, mode `0644` | High |
| Footer | `ENCH` metadata, `ENCF` trailer, `ENCF` at EOF | High |
| Password wrapping | RSA-2048 OAEP-SHA256 under embedded public key | High |
| Bulk encryption | AES-256-CTR, 256 KiB chunks | High |
| KDF | Argon2id, 64 MiB, t=1, p=4 | High |
| Metadata restore | Original mtime restored after encryption | High |
| Self-delete | `sh -c "sleep 2 && rm -f '<exe>'"` | High |
| Persistence | None observed | High for this build |
| C2 | None observed in the binary | High for this build |
| Exfiltration | Not observed in the binary | Not proven either way |

## Thresholds

- Valuable text/config/data files: full encryption below 1 GiB; five-region
  intermittent at or above 1 GiB.
- Other whitelisted files: full encryption below 20 MiB; five-region
  intermittent at or above 20 MiB.
- Intermittent total is always 20 MiB: five 4 MiB regions.

## Note handling

The note contains a wrapped-password field and a directory manifest. Attacker
contact identifiers and the exact note body are intentionally not republished.
The note is skipped by the encryption loop.
