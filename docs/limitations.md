# Limitations and uncertainty

## Static-only analysis

The sample was never executed. Behavior was recovered from disassembly,
metadata, strings, and a source-level reconstruction used for comparison. This
is strong evidence for the observed build, but it is not a runtime trace.

## One build, not a family

The hash, build ID, paths, thresholds, process list, and note text describe one
sample. Other builds may differ. Do not treat the indicators as a complete
signature for every `encfile` variant.

## No private key

The sample embeds only a public key. The private key is not present on the
victim host. Without it, fully encrypted data cannot be recovered from the
ciphertext alone. Any claim of universal decryption should be treated with
skepticism.

## Intermittent recovery is partial

Intermittent mode leaves gaps, but the gaps are not guaranteed to be intact.
Filesystem activity, journaling, application writes, or later operations can
overwrite them. Carved fragments require validation and may not reconstruct a
usable file.

## Footer checks are structural

`IsEncrypted` and the supplied inspector check magic, length, version, mode,
and region count. They do not verify the HMAC. A crafted file can satisfy the
structure without being a valid encrypted file. HMAC verification requires the
derived MAC key.

## Detection false positives

- `.locked` is a common suffix.
- `killall` is a legitimate administrative tool.
- `README_DECRYPT.txt` may appear in recovery exercises.
- The YARA note rule uses short phrases and is intentionally lower confidence.

Correlate multiple artifacts and validate in context.

## No attribution

This repository does not attribute the sample to a person, group, or campaign.
The removed incident details are not needed for detection and are intentionally
not republished.

## No C2 conclusion

No application-level C2 was observed. This does not prove that no network
activity occurred before or after the locker ran. Initial access and
exfiltration are separate questions from the binary's encryption routine.

## Legal and operational limits

Recovery guidance is general. It does not replace a professional incident
response, legal advice, or application-specific database recovery procedures.
Preserve evidence and work on copies.
