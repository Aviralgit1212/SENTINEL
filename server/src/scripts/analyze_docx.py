
#!/usr/bin/env python3
"""
Sentinel DOCX static analyzer.

Security properties:
- Never extracts archive members to disk.
- Never executes macros or embedded objects.
- Never opens URLs or external relationships.
- Applies limits to file size, archive entries, XML parts, and text.
- Returns observations only; TypeScript decides evidence and risk.
"""

import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_XML_PARTS = 300
MAX_TEXT_CHARS = 2_000_000
MAX_FINDINGS = 100
MAX_URLS = 100
MAX_EMBEDDINGS = 100
MAX_RELATIONSHIPS = 100

W_NS = (
    "http://schemas.openxmlformats.org/"
    "wordprocessingml/2006/main"
)
R_NS = (
    "http://schemas.openxmlformats.org/"
    "officeDocument/2006/relationships"
)
NS = {"w": W_NS, "r": R_NS}

PROMPT_PATTERNS = [
    r"\b(ignore|disregard|override)\b.{0,80}"
    r"\b(previous|prior|above|system)\b.{0,40}"
    r"\b(instruction|prompt|rule)s?\b",
    r"\b(reveal|print|expose|leak)\b.{0,60}"
    r"\b(system prompt|secret|password|credential|api key)\b",
    r"\bignore all previous instructions\b",
    r"\b(do not tell the user|hide this instruction)\b",
    r"\b(act as|you are now)\b.{0,60}"
    r"\b(unrestricted|administrator|system)\b",
]

COMMAND_PATTERNS = [
    r"\bpowershell\b",
    r"\b(cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe)\b",
    r"\b(downloadstring|invoke-expression)\b",
    r"\bbase64\s*-?decode\b",
    r"\bfrombase64string\b",
]

CREDENTIAL_PATTERNS = [
    r"\b(steal|exfiltrate|collect|send)\b.{0,60}"
    r"\b(passwords?|credentials?|tokens?|cookies?)\b",
    r"\b(api[_ -]?key|private[_ -]?key|access[_ -]?token)\b",
]

ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060")

EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".hta", ".com", ".msi",
)

TEXT_PART_RE = re.compile(
    r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments\d*)\.xml$",
    re.I,
)


def emit(data):
    print(json.dumps(data, ensure_ascii=False))


def empty_result(error, warnings=None):
    return {
        "ok": False,
        "supported": False,
        "error": str(error)[:500],
        "fileSize": 0,
        "entryCount": 0,
        "totalUncompressedBytes": 0,
        "documentTextLength": 0,
        "textPartCount": 0,
        "hiddenTextCount": 0,
        "hiddenText": [],
        "urls": [],
        "externalRelationships": [],
        "embeddedObjects": [],
        "macroParts": [],
        "suspiciousIndicators": [],
        "packageWarnings": list(warnings or []),
        "partCounts": {},
        "hasComments": False,
        "hasTrackedChanges": False,
        "hasExternalTemplate": False,
    }


def normalize(text):
    return re.sub(r"\s+", " ", text or "").strip()


def local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def attribute(element, namespace, name, default=""):
    return element.attrib.get(
        "{" + namespace + "}" + name,
        element.attrib.get(name, default),
    )


def safe_member_name(name):
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts

    return (
        normalized.startswith("/")
        or ".." in parts
        or "\x00" in name
        or bool(re.match(r"^[a-zA-Z]:", normalized))
    )


def suspicious_content_signals(text):
    normalized = normalize(text).lower()
    signals = []

    for pattern in PROMPT_PATTERNS:
        if re.search(pattern, normalized, re.I | re.S):
            signals.append("prompt-injection-like-instruction")
            break

    for pattern in COMMAND_PATTERNS:
        if re.search(pattern, normalized, re.I | re.S):
            signals.append("command-or-script-indicator")
            break

    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, normalized, re.I | re.S):
            signals.append("credential-theft-language")
            break

    if re.search(r"""https?://[^\s<>'"]+""", text or "", re.I):
        signals.append("contains-url")

    if any(char in (text or "") for char in ZERO_WIDTH_CHARS):
        signals.append("zero-width-characters")

    return sorted(set(signals))


def parse_xml(data):
    # Defense in depth: reject explicit DTD/entity declarations.
    prefix = data[:4096].lower()
    if b"<!doctype" in prefix or b"<!entity" in prefix:
        raise ValueError("DTD/entity declaration in XML part")

    return ET.fromstring(data)


def unique_append(items, value, limit=None):
    if value in items:
        return
    if limit is None or len(items) < limit:
        items.append(value)


def is_text_part(name):
    return bool(TEXT_PART_RE.fullmatch(name))


def inspect_run(run, part_name):
    run_text = "".join(
        element.text or ""
        for element in run.iter()
        if local_name(element.tag) in ("t", "delText", "instrText")
    )

    if not run_text.strip():
        return None

    reasons = []
    rpr = next(
        (child for child in list(run) if local_name(child.tag) == "rPr"),
        None,
    )

    if rpr is not None:
        for prop in list(rpr):
            prop_name = local_name(prop.tag)

            if prop_name in ("vanish", "webHidden", "specVanish"):
                reasons.append("word-hidden-text-property")

            if prop_name == "color":
                color = attribute(prop, W_NS, "val").upper()
                if color in ("FFFFFF", "FEFEFE", "FDFDFD"):
                    reasons.append("white-or-near-white-font")

            if prop_name == "sz":
                try:
                    half_points = int(attribute(prop, W_NS, "val", "0"))
                    if 0 < half_points <= 8:
                        reasons.append("very-small-font")
                except (TypeError, ValueError):
                    pass

    if any(
        local_name(element.tag) in ("delText", "instrText")
        for element in run.iter()
    ):
        reasons.append("deleted-or-field-instruction-text")

    if any(char in run_text for char in ZERO_WIDTH_CHARS):
        reasons.append("zero-width-characters")

    if not reasons:
        return None

    return {
        "part": part_name[:240],
        "textPreview": normalize(run_text)[:240],
        "reasons": sorted(set(reasons)),
        "contentSignals": suspicious_content_signals(run_text),
    }


def run(file_path):
    result = empty_result("Not analyzed")

    try:
        file_size = os.path.getsize(file_path)
        result["fileSize"] = file_size

        if file_size <= 0:
            result["error"] = "The uploaded file is empty."
            result["packageWarnings"] = ["invalid-office-package"]
            return result

        if file_size > MAX_FILE_BYTES:
            result["error"] = "File exceeds the DOCX analyzer size limit."
            result["packageWarnings"] = ["file-size-limit-exceeded"]
            return result

        with open(file_path, "rb") as handle:
            signature = handle.read(4)

        if signature != b"PK\x03\x04":
            result["error"] = (
                "The file does not have a ZIP/Office package signature."
            )
            result["packageWarnings"] = ["invalid-zip-signature"]
            return result

        with zipfile.ZipFile(file_path, "r") as archive:
            infos = archive.infolist()
            result["entryCount"] = len(infos)

            if len(infos) > MAX_ENTRIES:
                result["error"] = "The package contains too many entries."
                result["packageWarnings"] = ["archive-entry-limit-exceeded"]
                return result

            total_uncompressed = sum(max(0, item.file_size) for item in infos)
            result["totalUncompressedBytes"] = total_uncompressed

            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                result["error"] = (
                    "The package exceeds the total uncompressed size limit."
                )
                result["packageWarnings"] = [
                    "archive-expansion-limit-exceeded"
                ]
                return result

            warnings = []
            indicators = []
            hidden_items = []
            urls = []
            external_relationships = []
            embedded_objects = []
            macro_parts = []
            part_counts = {}

            text_char_count = 0
            text_limit_reached = False
            text_part_count = 0
            hidden_count = 0
            has_comments = False
            has_tracked_changes = False
            has_external_template = False

            names = [item.filename for item in infos]
            name_set = set(names)

            required = {"[Content_Types].xml", "word/document.xml"}
            missing = sorted(required - name_set)

            if missing:
                result["error"] = (
                    "Missing required DOCX package part(s): "
                    + ", ".join(missing)
                )
                result["packageWarnings"] = [
                    "missing-required-office-parts"
                ]
                return result

            # Inspect archive metadata without extracting anything.
            for info in infos:
                name = info.filename
                lower = name.lower()

                if safe_member_name(name):
                    unique_append(warnings, "suspicious-archive-path")

                if info.flag_bits & 0x1:
                    unique_append(warnings, "encrypted-archive-entry")

                if info.file_size > MAX_ENTRY_BYTES:
                    unique_append(warnings, "oversized-package-entry")

                if info.file_size > 1024 * 1024 and info.compress_size > 0:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > 100:
                        unique_append(warnings, "high-compression-ratio")

                if "vbaproject.bin" in lower:
                    unique_append(macro_parts, name[:240], MAX_FINDINGS)

                if (
                    lower.startswith("word/embeddings/")
                    or "/embeddings/" in lower
                ):
                    if len(embedded_objects) < MAX_EMBEDDINGS:
                        embedded_objects.append({
                            "name": name[:240],
                            "size": info.file_size,
                            "type": "embedded-object",
                        })

                if lower.endswith(EXECUTABLE_EXTENSIONS):
                    unique_append(
                        indicators,
                        "executable-or-script-like-package-entry",
                    )

                if lower.startswith("word/comments") and lower.endswith(".xml"):
                    has_comments = True

                if lower.endswith((".xml", ".rels")):
                    base = lower.rsplit("/", 1)[-1]
                    part_counts[base] = part_counts.get(base, 0) + 1

            if macro_parts:
                unique_append(indicators, "macro-related-component-detected")

            if embedded_objects:
                unique_append(indicators, "embedded-objects-present")

            xml_names = [
                name for name in names
                if name.lower().endswith((".xml", ".rels"))
            ]

            if len(xml_names) > MAX_XML_PARTS:
                unique_append(warnings, "xml-part-count-limit-exceeded")
                xml_names = xml_names[:MAX_XML_PARTS]

            # Read only bounded XML members. Nothing is extracted to disk.
            for name in xml_names:
                try:
                    info = archive.getinfo(name)

                    if info.file_size > MAX_ENTRY_BYTES:
                        unique_append(warnings, "xml-part-too-large-to-inspect")
                        continue

                    raw = archive.read(name)
                    root = parse_xml(raw)

                except Exception:
                    unique_append(warnings, "malformed-or-unreadable-xml-part")
                    continue

                lower_name = name.lower()

                # Parse external relationships, but never fetch their targets.
                if lower_name.endswith(".rels"):
                    for relationship in root.iter():
                        if local_name(relationship.tag) != "Relationship":
                            continue

                        target = relationship.attrib.get("Target", "")
                        target_mode = relationship.attrib.get("TargetMode", "")
                        rel_type = relationship.attrib.get("Type", "")

                        if target_mode.lower() != "external":
                            continue

                        item = {
                            "sourcePart": name[:240],
                            "target": target[:500],
                            "relationshipType": (
                                rel_type.rsplit("/", 1)[-1][:100]
                            ),
                        }

                        if len(external_relationships) < MAX_RELATIONSHIPS:
                            external_relationships.append(item)

                        if re.match(r"^https?://", target, re.I):
                            unique_append(urls, target[:1000], MAX_URLS)

                        if "attachedtemplate" in rel_type.lower():
                            has_external_template = True

                        if re.match(r"^(?:file:|\\\\|[a-z]:)", target, re.I):
                            unique_append(
                                indicators,
                                "external-file-or-network-path",
                            )

                    continue

                if "comments" in lower_name:
                    has_comments = True

                # Count readable document text only in Word content parts.
                if is_text_part(name):
                    text_part_count += 1

                    for element in root.iter():
                        local = local_name(element.tag)

                        if local in ("ins", "del", "moveFrom", "moveTo"):
                            has_tracked_changes = True

                        if local not in ("t", "delText", "instrText"):
                            continue

                        value = element.text or ""
                        if not value:
                            continue

                        remaining = MAX_TEXT_CHARS - text_char_count
                        if remaining <= 0:
                            text_limit_reached = True
                            break

                        if len(value) > remaining:
                            value = value[:remaining]
                            text_limit_reached = True

                        text_char_count += len(value)

                    # Inspect runs for hidden formatting. The count is
                    # separate from documentTextLength to avoid double counting.
                    for word_run in root.iter():
                        if local_name(word_run.tag) != "r":
                            continue

                        finding = inspect_run(word_run, name)
                        if finding is None:
                            continue

                        hidden_count += 1

                        for signal in finding["contentSignals"]:
                            if signal in (
                                "prompt-injection-like-instruction",
                                "command-or-script-indicator",
                                "credential-theft-language",
                            ):
                                unique_append(indicators, signal)

                        if finding["contentSignals"]:
                            unique_append(
                                indicators,
                                "suspicious-content-in-hidden-text",
                            )

                        if len(hidden_items) < MAX_FINDINGS:
                            hidden_items.append(finding)

                    # Scan bounded text values for suspicious indicators.
                    for element in root.iter():
                        if local_name(element.tag) not in (
                            "t", "delText", "instrText"
                        ):
                            continue

                        value = element.text or ""
                        if not value:
                            continue

                        for signal in suspicious_content_signals(value):
                            if signal != "contains-url":
                                unique_append(indicators, signal)

                    if text_limit_reached:
                        unique_append(warnings, "text-analysis-limit-reached")
                        break

            for relationship in external_relationships:
                target = relationship["target"]
                if re.match(r"^(?:file:|\\\\|[a-z]:)", target, re.I):
                    unique_append(
                        indicators,
                        "external-file-or-network-path",
                    )

            result.update({
                "ok": True,
                "supported": True,
                "error": None,
                "entryCount": len(infos),
                "totalUncompressedBytes": total_uncompressed,
                "documentTextLength": text_char_count,
                "textPartCount": text_part_count,
                "hiddenTextCount": hidden_count,
                "hiddenText": hidden_items,
                "urls": sorted(urls)[:MAX_URLS],
                "externalRelationships": external_relationships[:MAX_RELATIONSHIPS],
                "embeddedObjects": embedded_objects,
                "macroParts": macro_parts,
                "suspiciousIndicators": sorted(set(indicators)),
                "packageWarnings": sorted(set(warnings)),
                "partCounts": part_counts,
                "hasComments": has_comments,
                "hasTrackedChanges": has_tracked_changes,
                "hasExternalTemplate": has_external_template,
            })

            return result

    except zipfile.BadZipFile:
        result["error"] = "The file is not a valid ZIP-based Office package."
        result["packageWarnings"] = ["invalid-office-package"]
        return result

    except (OSError, RuntimeError, ValueError) as exc:
        result["error"] = str(exc)[:500]
        result["packageWarnings"] = ["analysis-error"]
        return result

    except Exception as exc:
        result["error"] = "Unexpected DOCX analyzer error: " + str(exc)[:300]
        result["packageWarnings"] = ["analysis-error"]
        return result


def main():
    if len(sys.argv) != 2:
        emit(empty_result("Usage: analyze_docx.py <file>"))
        return 2

    data = run(sys.argv[1])
    emit(data)
    return 0 if data.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())