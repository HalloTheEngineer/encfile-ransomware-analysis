# Tools

## inspect_footer.py

Metadata-only parser for the observed `ENCH ... ENCF` footer.

```bash
python3 tools/inspect_footer.py /path/to/suspect.locked
python3 tools/inspect_footer.py --json /path/to/suspect.locked
```

It validates:

- `ENCF` at EOF;
- the declared footer length;
- `ENCH`, version, mode, and region count;
- region bounds and overlap;
- the size relationship;
- plaintext gaps for intermittent files.

It does **not**:

- decrypt anything;
- verify the HMAC;
- repair or modify the file;
- prove the file is malicious.

Use a copy or a read-only mount. A valid footer is a structural observation, not
proof of origin or integrity.

## Tests

```bash
python3 -m unittest discover -s tools/tests -v
```

Fixtures are synthetic and contain no victim data.
