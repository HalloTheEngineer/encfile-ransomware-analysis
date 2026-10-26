# Detection and hunting

These detections target the observed build. Test them against benign files
before production deployment; several indicators are generic and require
correlation.

## Highest-signal artifacts

| Artifact | Why it matters |
| --- | --- |
| `/var/tmp/.X11-lock-session` | Run marker; content is usually the byte `1` |
| `/var/tmp/.X11-lock-session.run` | Separate `flock` instance-lock file |
| `README_DECRYPT.txt` | Per-directory ransom note, mode `0644` |
| `*.locked` | Successful encryption rename |
| `ENCF` at EOF | Footer trailer |
| `ENCH` at footer start | Footer metadata magic |
| `killall -9` for database names | Pre-encryption process termination |
| `sh -c "sleep 2 && rm -f ..."` | Delayed self-delete |

The two `/var/tmp` paths are distinct. A host may have one without the other,
depending on where execution failed.

## Filesystem hunting

Use read-only commands and preserve evidence:

```bash
find /home /var/lib /var/www /opt /srv -xdev -type f \
  \( -name 'README_DECRYPT.txt' -o -name '*.locked' \) \
  -printf '%T@ %s %p\n' 2>/dev/null | sort -n

stat /var/tmp/.X11-lock-session /var/tmp/.X11-lock-session.run 2>/dev/null

# Show the first bytes of a marker without changing it
od -An -tx1 -N16 /var/tmp/.X11-lock-session 2>/dev/null
```

`README_DECRYPT.txt` is a generic ransom-note name. Correlate it with `.locked`
files, the footer magic, or the `/var/tmp` artifacts.

## Footer validation

The structural footer is the most reliable file-level indicator:

```bash
python3 tools/inspect_footer.py /path/to/suspect.locked
python3 tools/inspect_footer.py --json /path/to/suspect.locked
```

The tool reads metadata only. It does not decrypt, verify the HMAC, or modify
the file. A valid footer means the file matches the observed format; it is not
proof of origin or integrity.

## YARA

```bash
yara -r detections/yara/encfile_locked_footer.yar /mnt/evidence
yara -r detections/yara/encfile_ransom_note.yar /mnt/evidence
```

- The footer rule is structural and supports the observed one-region and
  five-region layouts.
- The note rule is lower confidence and matches a few distinctive phrases, not
  the full note.
- Scan copies or read-only mounts when possible. Large files can make
  whole-filesystem YARA scans expensive.

## Process and audit telemetry

Hunt for a short-lived process tree that runs `killall -9` against database
services and then launches a delayed shell deletion:

```bash
pgrep -af '[k]illall|sleep 2 && rm -f'
```

Useful auditd watches:

```bash
auditctl -w /var/tmp/.X11-lock-session -p wa -k encfile_marker
auditctl -w /var/tmp/.X11-lock-session.run -p wa -k encfile_lock
```

The repository includes persistent rules in
[`detections/auditd/encfile_process_behavior.rules`](../detections/auditd/encfile_process_behavior.rules).
Review the executable path before deploying; distributions may place
`killall` elsewhere.

A Sigma rule for Linux process creation is provided in
[`detections/sigma/encfile_process.yml`](../detections/sigma/encfile_process.yml).
Convert it with your Sigma pipeline and tune it for your environment.

## Correlating behavior

A high-confidence incident usually has several of these together:

1. Marker or lock file creation in `/var/tmp`.
2. `killall` against `mongod`, `redis-server`, `mysqld`, `postgres`,
   `postmaster`, or `oracle`.
3. A `README_DECRYPT.txt` appearing beside newly renamed `.locked` files.
4. A process that removes its own executable after a two-second delay.
5. File mtimes restored after modification.

No single artifact is sufficient. `README_DECRYPT.txt` and `killall` are both
used by benign software in some environments.

## Network detection

No application-level C2 was observed. Do not expect a stable domain, URL, or
TLS fingerprint from this build. Network telemetry may still show access to the
initial vulnerable service, but that is incident-specific and is not part of
the locker format.

## False positives and safety

- `.locked` is used by some applications; confirm the footer.
- `killall` is a normal administrative tool.
- `README_DECRYPT.txt` could be a legitimate recovery note in rare cases.
- The YARA note rule uses short phrases; validate any hit.
- Do not upload victim files or the live sample to public services.
