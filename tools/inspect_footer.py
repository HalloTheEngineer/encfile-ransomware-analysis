#!/usr/bin/env python3
"""Inspect an encfile ENCH/ENCF footer without decrypting or modifying it.

The tool reads only the footer region. It validates the structural fields
documented in docs/encryption-format.md, reports encrypted coverage and
plaintext gaps, and deliberately does not verify the HMAC because that requires
the derived MAC key.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAGIC = b"ENCH"
TRAILER = b"ENCF"
VERSION = 1
MIN_FOOTER = 0x47
REGION_SIZE = 32
EXPECTED_REGION_COUNTS = {0: 1, 1: 5}
INTERMITTENT_TOTAL = 20 * 1024 * 1024


class FooterError(ValueError):
    """Raised when the footer is not structurally valid for this format."""


@dataclass(frozen=True)
class Region:
    offset: int
    length: int
    nonce: str


@dataclass(frozen=True)
class FooterInfo:
    file: str
    file_size: int
    footer_start: int
    footer_length: int
    version: int
    mode: int
    mode_label: str
    salt: str
    original_size: int
    region_count: int
    regions: list[Region]
    encrypted_bytes: int
    coverage_percent: float
    gaps: list[dict[str, int]]
    hmac_offset: int
    hmac_verified: bool
    size_consistent: bool
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_exact(fh: Any, offset: int, size: int) -> bytes:
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise FooterError(
            f"truncated read at offset {offset}: wanted {size}, got {len(data)}"
        )
    return data


def _compute_gaps(original_size: int, intervals: list[tuple[int, int]]) -> list[dict[str, int]]:
    gaps: list[dict[str, int]] = []
    cursor = 0
    for start, end in intervals:
        if start > cursor:
            gaps.append({"offset": cursor, "length": start - cursor})
        cursor = max(cursor, end)
    if cursor < original_size:
        gaps.append({"offset": cursor, "length": original_size - cursor})
    return gaps


def parse_footer(path: str | Path) -> FooterInfo:
    """Parse and structurally validate one footer.

    Raises FooterError for an invalid format and OSError for an unreadable path.
    """

    p = Path(path)
    with p.open("rb") as fh:
        fh.seek(0, 2)
        file_size = fh.tell()
        if file_size < 8:
            raise FooterError("file is too small to contain a footer")

        declared_len, trailer = struct.unpack(
            "<I4s", _read_exact(fh, file_size - 8, 8)
        )
        if trailer != TRAILER:
            raise FooterError("last four bytes are not ENCF")
        if declared_len < MIN_FOOTER:
            raise FooterError(
                f"declared footer length {declared_len} is below 0x47"
            )
        if declared_len > file_size:
            raise FooterError(
                f"declared footer length {declared_len} exceeds file size {file_size}"
            )
        if (declared_len - MIN_FOOTER) % REGION_SIZE != 0:
            raise FooterError(
                "declared footer length is not 0x47 plus a multiple of 32"
            )

        expected_regions = (declared_len - MIN_FOOTER) // REGION_SIZE
        metadata_len = declared_len - 40
        if metadata_len < 31:
            raise FooterError("metadata length is too small")

        footer_start = file_size - declared_len
        if footer_start < 0:
            raise FooterError("computed footer start is negative")

        metadata = _read_exact(fh, footer_start, metadata_len)
        if metadata[:4] != MAGIC:
            raise FooterError("footer metadata does not begin with ENCH")

        version = metadata[4]
        mode = metadata[5]
        salt = metadata[6:22].hex()
        original_size = struct.unpack_from("<Q", metadata, 22)[0]
        region_count = metadata[30]

        if version != VERSION:
            raise FooterError(f"unsupported footer version {version}")
        if mode not in EXPECTED_REGION_COUNTS:
            raise FooterError(f"unsupported mode {mode}")
        if region_count != expected_regions:
            raise FooterError(
                f"region count byte {region_count} disagrees with footer length "
                f"({expected_regions} regions)"
            )
        if region_count != EXPECTED_REGION_COUNTS[mode]:
            raise FooterError(
                f"mode {mode} requires {EXPECTED_REGION_COUNTS[mode]} regions, "
                f"found {region_count}"
            )

        regions: list[Region] = []
        pos = 31
        for _ in range(region_count):
            if pos + REGION_SIZE > len(metadata):
                raise FooterError("region table is truncated")
            offset, length, nonce = struct.unpack_from("<QQ16s", metadata, pos)
            regions.append(Region(offset=offset, length=length, nonce=nonce.hex()))
            pos += REGION_SIZE
        if pos != len(metadata):
            raise FooterError("region table does not consume the metadata exactly")

        intervals: list[tuple[int, int]] = []
        for index, region in enumerate(regions):
            if region.length <= 0:
                raise FooterError(f"region {index} has a non-positive length")
            end = region.offset + region.length
            if end > original_size:
                raise FooterError(
                    f"region {index} ends at {end}, beyond original size "
                    f"{original_size}"
                )
            intervals.append((region.offset, end))

        ordered = sorted(intervals)
        for previous, current in zip(ordered, ordered[1:]):
            if current[0] < previous[1]:
                raise FooterError("encrypted regions overlap")

        encrypted_bytes = sum(region.length for region in regions)
        if encrypted_bytes > original_size:
            raise FooterError("encrypted coverage exceeds original size")

        gaps = _compute_gaps(original_size, ordered) if mode == 1 else []
        coverage_percent = (
            round(100.0 * encrypted_bytes / original_size, 4)
            if original_size
            else 0.0
        )

        warnings: list[str] = []
        if original_size + declared_len != file_size:
            warnings.append(
                "file size is not original_size + footer_length; possible "
                "truncation, appended data, or a variant"
            )
        if mode == 0:
            if regions[0].offset != 0 or regions[0].length != original_size:
                warnings.append(
                    "full mode region is not offset 0 with length equal to "
                    "original size"
                )
        elif encrypted_bytes != INTERMITTENT_TOTAL:
            warnings.append(
                "intermittent coverage is not the observed 20 MiB total; "
                "treat geometry as a variant"
            )

        hmac_offset = footer_start + metadata_len
        if hmac_offset + 32 != file_size - 8:
            raise FooterError("HMAC is not immediately before the length field")

        return FooterInfo(
            file=str(p),
            file_size=file_size,
            footer_start=footer_start,
            footer_length=declared_len,
            version=version,
            mode=mode,
            mode_label="full" if mode == 0 else "intermittent",
            salt=salt,
            original_size=original_size,
            region_count=region_count,
            regions=regions,
            encrypted_bytes=encrypted_bytes,
            coverage_percent=coverage_percent,
            gaps=gaps,
            hmac_offset=hmac_offset,
            hmac_verified=False,
            size_consistent=original_size + declared_len == file_size,
            warnings=warnings,
        )


def format_human(info: FooterInfo) -> str:
    lines = [
        f"file: {info.file}",
        f"file_size: {info.file_size} bytes",
        f"footer_start: {info.footer_start}",
        f"footer_length: {info.footer_length}",
        f"version: {info.version}",
        f"mode: {info.mode} ({info.mode_label})",
        f"salt: {info.salt}",
        f"original_size: {info.original_size}",
        f"region_count: {info.region_count}",
        f"hmac_offset: {info.hmac_offset} (not verified)",
        f"encrypted_bytes: {info.encrypted_bytes}",
        f"coverage_percent: {info.coverage_percent}",
        f"size_consistent: {str(info.size_consistent).lower()}",
    ]
    for index, region in enumerate(info.regions):
        lines.append(
            f"region[{index}]: offset={region.offset} "
            f"length={region.length} nonce={region.nonce}"
        )
    if info.gaps:
        for index, gap in enumerate(info.gaps):
            lines.append(
                f"gap[{index}]: offset={gap['offset']} length={gap['length']}"
            )
    else:
        lines.append("gaps: none")
    for warning in info.warnings:
        lines.append(f"warning: {warning}")
    lines.append("note: metadata-only inspection; HMAC was not verified")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect an encfile ENCH/ENCF footer without decrypting"
    )
    parser.add_argument("path", help="path to a suspected .locked file")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    try:
        info = parse_footer(args.path)
    except (OSError, FooterError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_human(info))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
