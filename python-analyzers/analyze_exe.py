
#!/usr/bin/env python3
"""Static PE analyzer for Sentinel. Never executes the input file."""

import collections
import hashlib
import json
import math
import os
import re
import struct
import sys

MAX_STRINGS = 4000
MAX_STRING_LENGTH = 256
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_SECTION_COUNT = 96

SUSPICIOUS_APIS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory",
    "createremotethread", "ntcreatethreadex", "queueuserapc",
    "setthreadcontext", "openprocess", "winexec", "shellexecutea",
    "shellexecutew", "createprocessa", "createprocessw",
    "urldownloadtofilea", "urldownloadtofilew", "internetopenurl",
    "internetreadfile", "httpsendrequest", "winhttpopen",
    "winhttpsendrequest", "regsetvalueex", "createservicea",
    "createservicew", "startservicea", "startservicew",
    "isdebuggerpresent", "cryptunprotectdata", "readprocessmemory",
}

SUSPICIOUS_TERMS = [
    (r"powershell(?:\.exe)?", "powershell"),
    (r"cmd(?:\.exe)?\s*/c", "command-shell"),
    (r"rundll32(?:\.exe)?", "rundll32"),
    (r"regsvr32(?:\.exe)?", "regsvr32"),
    (r"\\currentversion\\run", "run-key-persistence"),
    (r"appdata\\", "appdata-path"),
    (r"downloadstring|downloadfile|invoke-expression|\biex\b",
     "script-download-or-execution"),
    (r"virtualalloc(?:ex)?|writeprocessmemory|createremotethread",
     "process-injection-api"),
    (r"credential|password|keylog|wallet|cookie",
     "credential-or-data-theft-string"),
]

URL_RE = re.compile(r"(?i)\b(?:https?://|ftp://)[^\s\"'<>]{4,250}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def read_c_string(data, offset, limit=512):
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", "replace")


def calculate_entropy(blob):
    if not blob:
        return 0.0

    counts = collections.Counter(blob)
    length = len(blob)

    return round(
        -sum((n / length) * math.log2(n / length)
             for n in counts.values()),
        3,
    )


def extract_strings(data):
    found = []
    seen = set()

    # ASCII strings
    for match in re.finditer(rb"[\x20-\x7e]{5,}", data):
        value = match.group().decode("ascii", "ignore").strip()
        value = value[:MAX_STRING_LENGTH]

        if value and value not in seen:
            found.append(value)
            seen.add(value)

        if len(found) >= MAX_STRINGS:
            break

    # UTF-16LE strings
    if len(found) < MAX_STRINGS:
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", data):
            value = match.group().decode("utf-16le", "ignore").strip()
            value = value[:MAX_STRING_LENGTH]

            if value and value not in seen:
                found.append(value)
                seen.add(value)

            if len(found) >= MAX_STRINGS:
                break

    return found


def analyze(path):
    actual_size = os.path.getsize(path)

    if actual_size > MAX_FILE_SIZE:
        return {
            "ok": False,
            "error": (
                f"File exceeds static analyzer limit "
                f"({MAX_FILE_SIZE} bytes)."
            ),
            "fileSize": actual_size,
            "sha256": "",
        }

    with open(path, "rb") as file:
        data = file.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:
        return {
            "ok": False,
            "error": "File changed while being read; analysis was stopped.",
            "fileSize": len(data),
            "sha256": "",
        }

    result = {
        "ok": False,
        "fileSize": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": None,
        "machine": None,
        "subsystem": None,
        "entryPointRva": None,
        "sectionCount": 0,
        "sections": [],
        "imports": [],
        "suspiciousImports": [],
        "strings": [],
        "urls": [],
        "ipAddresses": [],
        "suspiciousIndicators": [],
        "hasCertificateTable": False,
        "overlaySize": 0,
        "highEntropySections": [],
    }

    if len(data) < 64 or data[:2] != b"MZ":
        result["error"] = (
            "Missing DOS MZ header; file is not a valid PE executable."
        )
        return result

    pe_offset = read_u32(data, 0x3C)

    if (
        pe_offset is None
        or pe_offset + 24 > len(data)
        or data[pe_offset:pe_offset + 4] != b"PE\0\0"
    ):
        result["error"] = "Missing or invalid PE signature."
        return result

    coff = pe_offset + 4
    machine = read_u16(data, coff)
    section_count = read_u16(data, coff + 2)
    optional_size = read_u16(data, coff + 16)
    optional = coff + 20

    if (
        machine is None
        or section_count is None
        or optional_size is None
        or section_count > MAX_SECTION_COUNT
        or section_count == 0
    ):
        result["error"] = "Malformed PE/COFF header."
        return result

    if optional_size < 2 or optional + optional_size > len(data):
        result["error"] = "Truncated PE optional header."
        return result

    magic = read_u16(data, optional)

    if magic == 0x10B:
        architecture = "x86"
        directory_start = optional + 96
        directory_count_offset = optional + 92
        pointer_size = 4
        image_base = read_u32(data, optional + 28)

    elif magic == 0x20B:
        architecture = "x64"
        directory_start = optional + 112
        directory_count_offset = optional + 108
        pointer_size = 8

        image_base = (
            struct.unpack_from("<Q", data, optional + 24)[0]
            if optional + 32 <= len(data)
            else None
        )

    else:
        result["error"] = (
            f"Unsupported PE optional-header magic: {magic!r}."
        )
        return result

    # PE32+ is used by x64 and ARM64; the COFF machine field distinguishes them.
    if magic == 0x20B and machine == 0xAA64:
        architecture = "arm64"

    expected_machines = {
        "x86": {0x014C},
        "x64": {0x8664, 0x0200},
        "arm64": {0xAA64},
    }

    if machine not in expected_machines[architecture]:
        result["error"] = (
            f"COFF machine 0x{machine:04x} conflicts with "
            f"{architecture} optional header."
        )
        return result

    if optional_size < (96 if magic == 0x10B else 112):
        result["error"] = (
            "PE optional header is too small for its declared format."
        )
        return result

    entry_point = read_u32(data, optional + 16)
    subsystem = read_u16(data, optional + 68)
    directory_count = read_u32(data, directory_count_offset) or 0
    sections_offset = optional + optional_size

    if sections_offset + section_count * 40 > len(data):
        result["error"] = "Truncated PE section table."
        return result

    sections = []

    for index in range(section_count):
        offset = sections_offset + index * 40

        name = data[offset:offset + 8].split(b"\0", 1)[0].decode(
            "ascii", "replace"
        )

        virtual_size = read_u32(data, offset + 8) or 0
        virtual_address = read_u32(data, offset + 12) or 0
        raw_size = read_u32(data, offset + 16) or 0
        raw_pointer = read_u32(data, offset + 20) or 0
        characteristics = read_u32(data, offset + 36) or 0

        raw_range_valid = (
            raw_size == 0
            or (
                raw_pointer <= len(data)
                and raw_size <= len(data) - raw_pointer
            )
        )

        chunk = (
            data[raw_pointer:raw_pointer + raw_size]
            if raw_range_valid
            else b""
        )

        sections.append({
            "name": name,
            "virtualSize": virtual_size,
            "rawSize": raw_size,
            "entropy": calculate_entropy(chunk),
            "executable": bool(characteristics & 0x20000000),
            "writable": bool(characteristics & 0x80000000),
            "readable": bool(characteristics & 0x40000000),
            "rawRangeValid": raw_range_valid,
        })

    def rva_to_offset(rva):
        for index in range(section_count):
            offset = sections_offset + index * 40

            virtual_address = read_u32(data, offset + 12) or 0
            virtual_size = read_u32(data, offset + 8) or 0
            raw_size = read_u32(data, offset + 16) or 0
            raw_pointer = read_u32(data, offset + 20) or 0

            mapped_size = min(virtual_size or raw_size, raw_size)

            if virtual_address <= rva < virtual_address + mapped_size:
                delta = rva - virtual_address
                candidate = raw_pointer + delta

                if (
                    raw_pointer <= len(data)
                    and delta < raw_size
                    and candidate < len(data)
                ):
                    return candidate

                return None

        # Header RVAs may map directly to file offsets.
        return (
            rva
            if 0 <= rva < sections_offset and rva < len(data)
            else None
        )

    imports = []
    suspicious_imports = []

    # Import directory is data-directory entry number 1.
    if directory_count > 1 and directory_start + 16 <= optional + optional_size:
        import_rva = read_u32(data, directory_start + 8) or 0
        import_size = read_u32(data, directory_start + 12) or 0
        import_offset = rva_to_offset(import_rva) if import_rva else None

        if import_offset is not None:
            max_descriptors = min(
                256,
                max(1, import_size // 20 if import_size else 128),
            )

            for index in range(max_descriptors):
                offset = import_offset + index * 20

                if offset + 20 > len(data):
                    break

                (
                    original_thunk,
                    _,
                    _,
                    name_rva,
                    first_thunk,
                ) = struct.unpack_from("<IIIII", data, offset)

                if not any((original_thunk, name_rva, first_thunk)):
                    break

                name_offset = (
                    rva_to_offset(name_rva) if name_rva else None
                )

                dll = read_c_string(
                    data,
                    name_offset if name_offset is not None else -1,
                    256,
                ).lower()

                if not dll:
                    continue

                imports.append({"dll": dll, "functions": []})

                thunk_rva = original_thunk or first_thunk
                thunk_offset = (
                    rva_to_offset(thunk_rva) if thunk_rva else None
                )

                if thunk_offset is None:
                    continue

                for item in range(
                    min(512, (len(data) - thunk_offset) // pointer_size)
                ):
                    start = thunk_offset + item * pointer_size

                    value = int.from_bytes(
                        data[start:start + pointer_size], "little"
                    )

                    if value == 0:
                        break

                    ordinal_flag = 1 << (pointer_size * 8 - 1)

                    if value & ordinal_flag:
                        continue

                    name_offset = rva_to_offset(value)

                    if name_offset is None or name_offset + 2 >= len(data):
                        continue

                    function = read_c_string(data, name_offset + 2, 256)

                    if not function:
                        continue

                    imports[-1]["functions"].append(function)

                    if function.lower() in SUSPICIOUS_APIS:
                        suspicious_imports.append({
                            "dll": dll,
                            "function": function,
                        })

                if sum(len(item["functions"]) for item in imports) >= 1200:
                    break

    strings = extract_strings(data)
    joined = "\n".join(strings)

    urls = sorted({
        value.rstrip(".,;:!?)\\]}")
        for value in URL_RE.findall(joined)
    })[:100]

    ip_addresses = sorted({
        value
        for value in IP_RE.findall(joined)
        if all(0 <= int(part) <= 255 for part in value.split("."))
    })[:100]

    indicators = [
        label
        for pattern, label in SUSPICIOUS_TERMS
        if re.search(pattern, joined, re.I)
    ]

    last_section_end = max(
        [sections_offset + section_count * 40] + [
            (
                read_u32(data, sections_offset + i * 40 + 20) or 0
            ) + (
                read_u32(data, sections_offset + i * 40 + 16) or 0
            )
            for i in range(section_count)
        ]
    )

    overlay_size = max(
        0,
        len(data) - min(last_section_end, len(data)),
    )

    certificate_present = False

    if directory_count > 4 and directory_start + 40 <= optional + optional_size:
        cert_offset = read_u32(data, directory_start + 32) or 0
        cert_size = read_u32(data, directory_start + 36) or 0

        certificate_present = (
            cert_offset > 0
            and cert_size > 0
            and cert_offset + cert_size <= len(data)
        )

    structural_warnings = []

    if any(not section["rawRangeValid"] for section in sections):
        structural_warnings.append("section-raw-range-out-of-bounds")

    raw_ranges = sorted(
        (
            read_u32(data, sections_offset + i * 40 + 20) or 0,
            read_u32(data, sections_offset + i * 40 + 16) or 0,
        )
        for i in range(section_count)
        if (read_u32(data, sections_offset + i * 40 + 16) or 0) > 0
    )

    previous_end = 0

    for start, size in raw_ranges:
        if start < previous_end:
            structural_warnings.append("overlapping-section-raw-ranges")
            break

        previous_end = max(previous_end, start + size)

    if entry_point and not any(
        section["executable"]
        and (
            read_u32(data, sections_offset + i * 40 + 12) or 0
        ) <= entry_point < (
            read_u32(data, sections_offset + i * 40 + 12) or 0
        ) + max(section["virtualSize"], section["rawSize"])
        for i, section in enumerate(sections)
    ):
        structural_warnings.append("entry-point-not-in-executable-section")

    result.update({
        "ok": True,
        "structuralWarnings": sorted(set(structural_warnings)),
        "architecture": architecture,
        "machine": hex(machine or 0),
        "imageBase": image_base,
        "subsystem": subsystem,
        "entryPointRva": entry_point,
        "sectionCount": section_count,
        "sections": sections,
        "imports": imports,
        "suspiciousImports": suspicious_imports,
        "strings": strings,
        "urls": urls,
        "ipAddresses": ip_addresses,
        "suspiciousIndicators": indicators,
        "hasCertificateTable": certificate_present,
        "overlaySize": overlay_size,
        "highEntropySections": [
            section["name"]
            for section in sections
            if section["entropy"] >= 7.2 and section["rawSize"] >= 4096
        ],
    })

    return result


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: analyze_exe.py <file>")

        print(json.dumps(analyze(sys.argv[1]), ensure_ascii=True))

    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": f"EXE analysis failed: {type(exc).__name__}: {exc}",
        }))