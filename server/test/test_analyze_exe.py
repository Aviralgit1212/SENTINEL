
import importlib.util
import os
import struct
import tempfile
import unittest
from pathlib import Path

ANALYZER_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "scripts"
    / "analyze_exe.py"
)

spec = importlib.util.spec_from_file_location(
    "analyze_exe", ANALYZER_PATH
)
analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(analyzer)


def make_minimal_pe(payload=b"legitimate test executable"):
    """Create a tiny synthetic x64 PE for parser tests. Never execute it."""
    pe_offset = 0x80
    optional_size = 0xF0
    section_table = pe_offset + 4 + 20 + optional_size
    raw_pointer = 0x200
    raw_size = 0x200

    data = bytearray(raw_pointer + raw_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"

    coff = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        data,
        coff,
        0x8664,       # x64
        1,            # section count
        0, 0, 0,
        optional_size,
        0x0022,
    )

    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)       # PE32+
    struct.pack_into("<I", data, optional + 16, 0x1000) # entry point RVA
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 56, 0x2000) # image size
    struct.pack_into("<I", data, optional + 60, 0x200)  # header size
    struct.pack_into("<H", data, optional + 68, 3)      # console subsystem
    struct.pack_into("<I", data, optional + 108, 16)    # data directories

    section = section_table
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII",
        data,
        section + 8,
        raw_size,    # virtual size
        0x1000,      # virtual address
        raw_size,    # raw size
        raw_pointer,
    )
    struct.pack_into("<I", data, section + 36, 0x60000020)

    payload = payload[:raw_size]
    data[raw_pointer:raw_pointer + len(payload)] = payload
    return bytes(data)


class ExeAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def analyze_bytes(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return analyzer.analyze(str(path))

    def test_valid_minimal_pe(self):
        result = self.analyze_bytes(
            "sample.exe",
            make_minimal_pe(),
        )
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["architecture"], "x64")
        self.assertEqual(result["sectionCount"], 1)
        self.assertEqual(len(result["sha256"]), 64)

    def test_extracts_suspicious_static_indicators(self):
        payload = (
            b"powershell.exe "
            b"http://example.com "
            b"8.8.8.8"
        )
        result = self.analyze_bytes(
            "indicators.exe",
            make_minimal_pe(payload),
        )
        self.assertTrue(result["ok"], result.get("error"))
        self.assertIn("powershell", result["suspiciousIndicators"])
        self.assertTrue(
            any("http://example.com" in url for url in result["urls"])
        )
        self.assertIn("8.8.8.8", result["ipAddresses"])

    def test_rejects_invalid_pe(self):
        result = self.analyze_bytes(
            "not-really.exe",
            b"MZ" + (b"\0" * 100),
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("error"))

    def test_rejects_random_bytes_without_crashing(self):
        for index in range(25):
            result = self.analyze_bytes(
                f"random-{index}.exe",
                os.urandom(2048),
            )
            self.assertFalse(result["ok"])
            self.assertTrue(result.get("error"))

    def test_rejects_oversized_file_without_hash(self):
        original_limit = analyzer.MAX_FILE_SIZE
        try:
            analyzer.MAX_FILE_SIZE = 32
            result = self.analyze_bytes(
                "too-large.exe",
                b"A" * 33,
            )
            self.assertFalse(result["ok"])
            self.assertFalse(result.get("sha256"))
        finally:
            analyzer.MAX_FILE_SIZE = original_limit


if __name__ == "__main__":
    unittest.main()