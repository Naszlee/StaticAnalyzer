#!/usr/bin/env python3
"""
make_test_samples.py - Generate safe, synthetic test files for Part 2
(Shannon entropy, section/string/IOC extraction, and edge-case testing).

All data is synthetic/harmless. No real malware or external network targets.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "part2_samples"


def build_high_entropy_pe() -> bytes:
    """Build a harmless synthetic PE with a high-entropy section for section analysis testing."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,       # x86
        2,            # 2 sections: .text and .packed
        1700000000,   # fixed timestamp
        0, 0,
        224,          # SizeOfOptionalHeader
        0x0102,       # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    opt = struct.pack(
        "<HBB7I2I6H4I2H4I2I",
        0x10B, 14, 0,
        0x200, 0x400, 0, 0x1000, 0x1000, 0x3000, 0x400000,
        0x1000, 0x200,
        6, 0, 0, 0, 6, 0,
        0, 0x3000, 0x200, 0,
        3, 0x8140,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    ) + b"\x00" * (16 * 8)

    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text", 0x200, 0x1000, 0x200, 0x200,
        0, 0, 0, 0,
        0x60000020,   # CODE | EXECUTE | READ
    )
    sec_packed = struct.pack(
        "<8sIIIIIIHHI",
        b".packed", 0x400, 0x2000, 0x400, 0x400,
        0, 0, 0, 0,
        0x40000040,   # INITIALIZED_DATA | READ
    )

    headers = (bytes(dos) + b"PE\x00\x00" + coff + opt + sec_text + sec_packed).ljust(0x200, b"\x00")
    text_body = b"\xC3" + b"\x00" * 0x1FF
    packed_body = os.urandom(0x400)
    return headers + text_body + packed_body


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Empty file (0 bytes) -> edge case entropy = 0.0
    (OUT_DIR / "empty.bin").write_bytes(b"")

    # 2. Repetitive / low-entropy file
    (OUT_DIR / "low_entropy.txt").write_text("AAAA\n" * 250, encoding="utf-8")

    # 3. Synthetic / dummy IOCs in plain text -> safe regex & string extraction test
    dummy_content = """\
Sample diagnostic log for static analysis testing only.
Test IPv4 (RFC 5737 documentation range): 192.0.2.45 and 198.51.100.10
Test URL: https://example.test/api/v1/status
Test Domain: safe-test-domain.example
Test Registry string: HKCU\\Software\\SafeTestTool\\Config
Test API names in text: VirtualAlloc CreateRemoteThread CryptEncrypt
"""
    (OUT_DIR / "dummy_iocs.txt").write_text(dummy_content, encoding="utf-8")

    # 4. High-entropy random bytes -> tests high-entropy / packed-like threshold
    (OUT_DIR / "high_entropy.bin").write_bytes(os.urandom(4096))

    # 5. Truncated / malformed PE-like file -> tests safe error handling
    (OUT_DIR / "truncated_pe.bin").write_bytes(b"MZ" + b"\x00" * 10)

    # 6. Harmless synthetic PE with a high-entropy section -> tests per-section entropy
    (OUT_DIR / "high_entropy_sec.pe").write_bytes(build_high_entropy_pe())

    print(f"Created safe test samples in: {OUT_DIR}")


if __name__ == "__main__":
    main()
