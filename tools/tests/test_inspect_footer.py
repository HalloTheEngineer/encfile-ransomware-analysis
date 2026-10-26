"""Synthetic tests for inspect_footer.py. No victim data is used."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inspect_footer import FooterError, parse_footer  # noqa: E402


def build_footer(
    original_size: int,
    mode: int,
    regions: list[tuple[int, int, bytes]],
) -> bytes:
    salt = bytes(range(16))
    metadata = bytearray()
    metadata += b"ENCH"
    metadata += bytes([1, mode])
    metadata += salt
    metadata += struct.pack("<Q", original_size)
    metadata += bytes([len(regions)])
    for offset, length, nonce in regions:
        metadata += struct.pack("<QQ", offset, length)
        metadata += nonce
    footer_len = 0x47 + 32 * len(regions)
    return (
        bytes(metadata)
        + bytes(32)  # synthetic HMAC placeholder
        + struct.pack("<I", footer_len)
        + b"ENCF"
    )


def write_locked(
    path: Path,
    original_size: int,
    mode: int,
    regions: list[tuple[int, int, bytes]],
) -> None:
    body = bytes(original_size)
    path.write_bytes(body + build_footer(original_size, mode, regions))


class FooterTests(unittest.TestCase):
    def test_full_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "full.locked"
            write_locked(
                path,
                original_size=4096,
                mode=0,
                regions=[(0, 4096, b"A" * 16)],
            )
            info = parse_footer(path)
            self.assertEqual(info.mode, 0)
            self.assertEqual(info.mode_label, "full")
            self.assertEqual(info.region_count, 1)
            self.assertEqual(info.encrypted_bytes, 4096)
            self.assertEqual(info.coverage_percent, 100.0)
            self.assertEqual(info.gaps, [])
            self.assertTrue(info.size_consistent)
            self.assertFalse(info.hmac_verified)
            self.assertEqual(info.warnings, [])

    def test_intermittent_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intermittent.locked"
            regions = [
                (0, 4096, b"0" * 16),
                (50000, 4096, b"1" * 16),
                (100000, 4096, b"2" * 16),
                (150000, 4096, b"3" * 16),
                (195904, 4096, b"4" * 16),
            ]
            write_locked(path, original_size=200000, mode=1, regions=regions)
            info = parse_footer(path)
            self.assertEqual(info.mode, 1)
            self.assertEqual(info.region_count, 5)
            self.assertEqual(info.encrypted_bytes, 5 * 4096)
            self.assertEqual(len(info.gaps), 4)
            self.assertTrue(info.size_consistent)
            self.assertTrue(
                any("not the observed 20 MiB" in item for item in info.warnings)
            )

    def test_bad_trailer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.locked"
            write_locked(path, 128, 0, [(0, 128, b"A" * 16)])
            raw = bytearray(path.read_bytes())
            raw[-4:] = b"NOPE"
            path.write_bytes(raw)
            with self.assertRaises(FooterError):
                parse_footer(path)

    def test_bad_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad-length.locked"
            write_locked(path, 128, 0, [(0, 128, b"A" * 16)])
            raw = bytearray(path.read_bytes())
            struct.pack_into("<I", raw, len(raw) - 8, 0x66)
            path.write_bytes(raw)
            with self.assertRaises(FooterError):
                parse_footer(path)

    def test_region_out_of_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oob.locked"
            write_locked(path, 128, 0, [(120, 16, b"A" * 16)])
            with self.assertRaises(FooterError):
                parse_footer(path)

    def test_overlapping_regions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "overlap.locked"
            regions = [
                (0, 4096, b"A" * 16),
                (2048, 4096, b"B" * 16),
                (10000, 4096, b"C" * 16),
                (20000, 4096, b"D" * 16),
                (30000, 4096, b"E" * 16),
            ]
            write_locked(path, 40000, 1, regions)
            with self.assertRaises(FooterError):
                parse_footer(path)

    def test_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "count.locked"
            write_locked(path, 128, 0, [(0, 128, b"A" * 16)])
            raw = bytearray(path.read_bytes())
            footer_start = len(raw) - 0x67
            raw[footer_start + 30] = 5
            path.write_bytes(raw)
            with self.assertRaises(FooterError):
                parse_footer(path)

    def test_appended_data_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "extra.locked"
            write_locked(path, 128, 0, [(0, 128, b"A" * 16)])
            raw = bytearray(path.read_bytes())
            raw[128:128] = b"X"
            path.write_bytes(raw)
            info = parse_footer(path)
            self.assertFalse(info.size_consistent)
            self.assertTrue(any("file size" in item for item in info.warnings))


if __name__ == "__main__":
    unittest.main()
