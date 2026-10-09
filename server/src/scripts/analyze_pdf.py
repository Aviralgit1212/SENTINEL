import json
import os
import re
import shutil
import subprocess
import sys

import pymupdf


# =========================================================
# Configuration
# =========================================================

MAX_OCR_PAGES = 10
OCR_TIMEOUT_SECONDS = 20
OCR_SCALE = 2

MAX_HIDDEN_TEXT_ITEMS = 100

MIN_SUSPICIOUS_FONT_SIZE = 2.0
PAGE_BOUNDARY_TOLERANCE = 2.0
LIGHT_COLOR_THRESHOLD = 245

ZERO_WIDTH_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
}

PROMPT_INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\bignore\s+(all\s+)?prior\s+instructions\b",
    r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
    r"\bdisregard\s+(all\s+)?prior\s+instructions\b",
    r"\bforget\s+(all\s+)?previous\s+instructions\b",
    r"\bdo\s+not\s+follow\s+(the\s+)?previous\b",
    r"\boverride\s+(the\s+)?system\s+instructions\b",
    r"\bnew\s+instructions\s*:",
    r"\bsystem\s+message\s*:",
    r"\bdeveloper\s+message\s*:",
    r"\bassistant\s+instructions?\s*:",
    r"\byou\s+are\s+now\s+ instructed\b",
    r"\byou\s+are\s+now\s+an?\b",
]

COMMAND_PATTERNS = [
    r"\bcurl\s+https?://",
    r"\bwget\s+https?://",
    r"\b(?:bash|sh|zsh)\s+-c\b",
    r"\bpowershell(?:\.exe)?\s+",
    r"\b(?:cmd|cmd\.exe)\s+/c\b",
    r"\bpython(?:3)?\s+-c\b",
    r"\bnode(?:\.js)?\s+-e\b",
    r"\bchmod\s+\+x\b",
    r"\b(?:rm|del)\s+-rf\b",
    r"\bbase64\s+(?:-d|--decode)\b",
]

CREDENTIAL_PATTERNS = [
    r"\benter\s+(your\s+)?password\b",
    r"\bprovide\s+(your\s+)?password\b",
    r"\benter\s+(your\s+)?otp\b",
    r"\bprovide\s+(your\s+)?otp\b",
    r"\benter\s+(your\s+)?api\s+key\b",
    r"\bprovide\s+(your\s+)?api\s+key\b",
    r"\bsend\s+(your\s+)?credentials\b",
    r"\bshare\s+(your\s+)?credentials\b",
    r"\bprivate\s+key\b",
    r"\bseed\s+phrase\b",
]

OBFUSCATION_PATTERNS = [
    r"\b(?:base64|base32|hex)\s*(?:decode|encoded|encoding)\b",
    r"\b(?:decode|decrypt)\s+this\b",
    r"\b(?:fromcharcode|charcodeat)\b",
]

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".com",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".sh",
    ".bash",
    ".zsh",
    ".elf",
    ".dmg",
    ".app",
}

EXECUTABLE_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdos-program",
    "application/x-sh",
    "application/x-shellscript",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
}

C2PA_MARKERS = {
    "c2pa",
    "content credentials",
    "content-credentials",
}


# =========================================================
# Generic helpers
# =========================================================

def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_text(value):
    if not value:
        return ""

    return re.sub(
        r"\s+",
        " ",
        str(value),
    ).strip()


def normalize_for_comparison(value):
    """
    Normalize text before comparing native PDF text
    against OCR-visible text.

    OCR is imperfect, so this deliberately performs
    conservative normalization instead of requiring
    exact string equality.
    """

    if not value:
        return ""

    value = value.lower()

    value = re.sub(
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "",
        value,
    )

    value = re.sub(
        r"[^a-z0-9]+",
        " ",
        value,
    )

    return re.sub(
        r"\s+",
        " ",
        value,
    ).strip()


def text_tokens(value):
    normalized = normalize_for_comparison(value)

    if not normalized:
        return []

    return normalized.split()


def token_overlap(native_text, visible_text):
    """
    Approximate how much native text is represented
    in the visible OCR text.

    This is intentionally not an exact equality test.
    """

    native_tokens = set(
        token
        for token in text_tokens(native_text)
        if len(token) >= 2
    )

    visible_tokens = set(
        token
        for token in text_tokens(visible_text)
        if len(token) >= 2
    )

    if not native_tokens:
        return 0.0

    overlap = native_tokens.intersection(
        visible_tokens,
    )

    return len(overlap) / len(native_tokens)


# =========================================================
# PDF string helpers
# =========================================================

def extract_pdf_string(
    object_text,
    key,
):
    string_match = re.search(
        rf"/{key}\s*\((.*?)\)",
        object_text,
        re.IGNORECASE | re.DOTALL,
    )

    if string_match:
        return string_match.group(1)

    name_match = re.search(
        rf"/{key}\s*/([^\s<>\[\]()]+)",
        object_text,
        re.IGNORECASE,
    )

    if name_match:
        value = name_match.group(1)

        value = value.replace(
            "#2F",
            "/",
        )

        value = value.replace(
            "#20",
            " ",
        )

        value = value.replace(
            "#23",
            "#",
        )

        return value

    hex_match = re.search(
        rf"/{key}\s*<([0-9A-Fa-f]+)>",
        object_text,
        re.IGNORECASE,
    )

    if hex_match:
        try:
            return bytes.fromhex(
                hex_match.group(1),
            ).decode(
                "utf-8",
                errors="ignore",
            )
        except ValueError:
            return None

    return None


def extract_pdf_name(
    object_text,
    key,
):
    match = re.search(
        rf"/{key}\s*/([^\s<>\[\]()]+)",
        object_text,
        re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(1)


def normalize_mime_type(value):
    if not value:
        return None

    return (
        value
        .replace("#2F", "/")
        .replace("#20", " ")
        .strip()
    )


# =========================================================
# Embedded-file analysis
# =========================================================

def is_c2pa_embedded_file(
    filename,
    mime_type,
    object_text,
):
    combined = " ".join(
        [
            filename or "",
            mime_type or "",
            object_text or "",
        ],
    ).lower()

    return any(
        marker in combined
        for marker in C2PA_MARKERS
    )


def is_executable_like(
    filename,
    mime_type,
):
    filename_lower = (
        (filename or "")
        .strip()
        .lower()
    )

    mime_lower = (
        (mime_type or "")
        .strip()
        .lower()
    )

    for extension in EXECUTABLE_EXTENSIONS:

        if filename_lower.endswith(
            extension,
        ):
            return True

    return mime_lower in EXECUTABLE_MIME_TYPES


def extract_embedded_files(
    document,
):
    embedded_files = []

    xref_count = document.xref_length()

    for xref in range(
        1,
        xref_count,
    ):

        try:

            object_text = document.xref_object(
                xref,
                compressed=False,
            )

            if not object_text:
                continue

            if "/embeddedfile" not in object_text.lower():
                continue

            filename = (
                extract_pdf_string(
                    object_text,
                    "F",
                )
                or extract_pdf_string(
                    object_text,
                    "UF",
                )
            )

            mime_type = normalize_mime_type(
                extract_pdf_name(
                    object_text,
                    "Subtype",
                )
            )

            relationship = extract_pdf_name(
                object_text,
                "AFRelationship",
            )

            size = None

            length_match = re.search(
                r"/Length\s+(\d+)",
                object_text,
                re.IGNORECASE,
            )

            if length_match:

                try:
                    size = int(
                        length_match.group(1),
                    )
                except ValueError:
                    pass

            embedded_files.append(
                {
                    "filename": filename,
                    "mimeType": mime_type,
                    "size": size,
                    "relationship": relationship,
                    "isC2pa": is_c2pa_embedded_file(
                        filename,
                        mime_type,
                        object_text,
                    ),
                    "isExecutableLike": is_executable_like(
                        filename,
                        mime_type,
                    ),
                    "xref": xref,
                },
            )

        except Exception:
            continue

    return embedded_files


# =========================================================
# OCR
# =========================================================

def find_tesseract():
    """Find Tesseract even when the Node process has a limited PATH."""
    discovered = shutil.which("tesseract")
    if discovered:
        return discovered

    for candidate in (
        "/opt/homebrew/bin/tesseract",  # Apple Silicon Homebrew
        "/usr/local/bin/tesseract",     # Intel Homebrew
        "/usr/bin/tesseract",
    ):
        if candidate and os.path.isfile(candidate):
            return candidate

    return None


def run_ocr_text(page, tesseract_path=None):
    """
    OCR a rendered PDF page.

    Returns:
        text
    """

    try:

        pixmap = page.get_pixmap(
            matrix=pymupdf.Matrix(
                OCR_SCALE,
                OCR_SCALE,
            ),
            alpha=False,
        )

        image_bytes = pixmap.tobytes(
            "png",
        )

        executable = tesseract_path or find_tesseract()
        if not executable:
            return ""

        result = subprocess.run(
            [
                executable,
                "stdin",
                "stdout",
                "--psm",
                "6",
            ],
            input=image_bytes,
            capture_output=True,
            timeout=OCR_TIMEOUT_SECONDS,
        )

        if result.returncode != 0:
            return ""

        return result.stdout.decode(
            "utf-8",
            errors="ignore",
        ).strip()

    except (
        subprocess.TimeoutExpired,
        OSError,
    ):
        return ""


def run_ocr_tsv(page, tesseract_path=None):
    """
    OCR the rendered page using Tesseract TSV.

    TSV gives us word-level bounding boxes, which lets
    Sentinel compare the native PDF text layer against
    text that is actually visible in the rendered page.
    """

    try:

        pixmap = page.get_pixmap(
            matrix=pymupdf.Matrix(
                OCR_SCALE,
                OCR_SCALE,
            ),
            alpha=False,
        )

        image_bytes = pixmap.tobytes(
            "png",
        )

        executable = tesseract_path or find_tesseract()
        if not executable:
            return {
                "text": "",
                "words": [],
            }

        result = subprocess.run(
            [
                executable,
                "stdin",
                "stdout",
                "--psm",
                "6",
                "tsv",
            ],
            input=image_bytes,
            capture_output=True,
            timeout=OCR_TIMEOUT_SECONDS,
        )

        if result.returncode != 0:
            return {
                "text": "",
                "words": [],
            }

        output = result.stdout.decode(
            "utf-8",
            errors="ignore",
        )

        lines = output.splitlines()

        if not lines:
            return {
                "text": "",
                "words": [],
            }

        words = []

        for line in lines[1:]:

            parts = line.split("\t")

            if len(parts) < 12:
                continue

            text = parts[11].strip()

            if not text:
                continue

            try:

                confidence = float(
                    parts[10],
                )

            except ValueError:

                confidence = -1

            try:

                words.append(
                    {
                        "text": text,
                        "confidence": round(
                            confidence,
                            2,
                        ),
                        "left": int(parts[6]),
                        "top": int(parts[7]),
                        "width": int(parts[8]),
                        "height": int(parts[9]),
                    },
                )

            except ValueError:
                continue

        visible_text = " ".join(
            item["text"]
            for item in words
        )

        return {
            "text": visible_text.strip(),
            "words": words,
        }

    except (
        subprocess.TimeoutExpired,
        OSError,
    ):
        return {
            "text": "",
            "words": [],
        }


# =========================================================
# Hidden-text analysis
# =========================================================

def color_to_rgb(color):
    try:

        color = int(color)

        return (
            (color >> 16) & 255,
            (color >> 8) & 255,
            color & 255,
        )

    except (
        TypeError,
        ValueError,
    ):
        return None


def is_light_color(color):
    rgb = color_to_rgb(
        color,
    )

    if rgb is None:
        return False

    red, green, blue = rgb

    return (
        red >= LIGHT_COLOR_THRESHOLD
        and green >= LIGHT_COLOR_THRESHOLD
        and blue >= LIGHT_COLOR_THRESHOLD
    )


def detect_zero_width_characters(text):
    found = []

    for character in text:

        if character in ZERO_WIDTH_CHARS:

            if character not in found:
                found.append(
                    character,
                )

    return found


def analyze_hidden_content_text(text):
    """
    Analyze text discovered through a hidden-text
    detector.

    This does NOT execute the discovered content.
    """

    signals = []
    urls = []

    normalized = normalize_text(
        text,
    )

    if not normalized:
        return {
            "signals": signals,
            "urls": urls,
            "riskHints": [],
        }

    zero_width = detect_zero_width_characters(
        text,
    )

    if zero_width:
        signals.append(
            "zero-width-characters",
        )

    url_matches = re.findall(
        r"https?://[^\s<>()\"']+",
        text,
        re.IGNORECASE,
    )

    if url_matches:

        urls = sorted(
            set(url_matches),
        )

        signals.append(
            "contains-url",
        )

    for pattern in PROMPT_INJECTION_PATTERNS:

        if re.search(
            pattern,
            normalized,
            re.IGNORECASE,
        ):

            signals.append(
                "prompt-injection",
            )

            break

    for pattern in COMMAND_PATTERNS:

        if re.search(
            pattern,
            normalized,
            re.IGNORECASE,
        ):

            signals.append(
                "command-execution",
            )

            break

    for pattern in CREDENTIAL_PATTERNS:

        if re.search(
            pattern,
            normalized,
            re.IGNORECASE,
        ):

            signals.append(
                "credential-request",
            )

            break

    for pattern in OBFUSCATION_PATTERNS:

        if re.search(
            pattern,
            normalized,
            re.IGNORECASE,
        ):

            signals.append(
                "possible-obfuscation",
            )

            break

    risk_hints = []

    if "prompt-injection" in signals:
        risk_hints.append("high")

    if "command-execution" in signals:
        risk_hints.append("high")

    if "credential-request" in signals:
        risk_hints.append("high")

    if "possible-obfuscation" in signals:
        risk_hints.append("medium")

    if "contains-url" in signals:
        risk_hints.append("low")

    return {
        "signals": sorted(
            set(signals),
        ),
        "urls": urls,
        "riskHints": risk_hints,
    }


def rects_overlap(
    first,
    second,
):
    """
    Determine whether two rectangles overlap.
    """

    try:

        ax0, ay0, ax1, ay1 = first
        bx0, by0, bx1, by1 = second

        return not (
            ax1 <= bx0
            or bx1 <= ax0
            or ay1 <= by0
            or by1 <= ay0
        )

    except (
        TypeError,
        ValueError,
    ):
        return False


def detect_hidden_text(
    document,
):
    """
    Multi-signal hidden text detector.

    Detection layers:

    1. Very small text.
    2. Very light text.
    3. Near-zero bounding boxes.
    4. Text outside page boundaries.
    5. Text with zero-width characters.
    6. Text-layer vs rendered-page OCR comparison.
    7. Suspicious content inside detected hidden text.

    Important:
    OCR comparison is a candidate detector, not absolute
    proof. OCR can miss legitimate text.
    """

    findings = []

    tesseract_path = find_tesseract()
    tesseract_available = tesseract_path is not None

    for page_number in range(
        document.page_count,
    ):

        if len(findings) >= MAX_HIDDEN_TEXT_ITEMS:
            break

        try:

            page = document.load_page(
                page_number,
            )

            page_rect = page.rect

            text_dict = page.get_text(
                "dict",
            )

            # -----------------------------------------------------
            # OCR visible text
            # -----------------------------------------------------

            ocr_result = {
                "text": "",
                "words": [],
            }

            if tesseract_available:

                ocr_result = run_ocr_tsv(
                    page,
                    tesseract_path,
                )

            visible_ocr_text = ocr_result[
                "text"
            ]

            # -----------------------------------------------------
            # Native spans
            # -----------------------------------------------------

            for block in text_dict.get(
                "blocks",
                [],
            ):

                if "lines" not in block:
                    continue

                for line in block.get(
                    "lines",
                    [],
                ):

                    for span in line.get(
                        "spans",
                        [],
                    ):

                        text = (
                            span.get("text")
                            or ""
                        )

                        if not text.strip():
                            continue

                        bbox = span.get(
                            "bbox",
                        )

                        if (
                            not bbox
                            or len(bbox) != 4
                        ):
                            continue

                        x0, y0, x1, y1 = bbox

                        font_size = safe_float(
                            span.get("size"),
                        )

                        color = span.get(
                            "color",
                            0,
                        )

                        reasons = []

                        confidence = 0.0

                        # -------------------------------------------------
                        # Signal 1: tiny font
                        # -------------------------------------------------

                        if (
                            font_size > 0
                            and font_size
                            < MIN_SUSPICIOUS_FONT_SIZE
                        ):

                            reasons.append(
                                "very-small-font",
                            )

                            confidence += 0.25

                        # -------------------------------------------------
                        # Signal 2: near-zero bounding box
                        # -------------------------------------------------

                        width = abs(
                            x1 - x0,
                        )

                        height = abs(
                            y1 - y0,
                        )

                        if (
                            width <= 0.1
                            or height <= 0.1
                        ):

                            reasons.append(
                                "near-zero-bounding-box",
                            )

                            confidence += 0.25

                        # -------------------------------------------------
                        # Signal 3: outside page
                        # -------------------------------------------------

                        outside_page = (
                            x1
                            < page_rect.x0
                            - PAGE_BOUNDARY_TOLERANCE
                            or x0
                            > page_rect.x1
                            + PAGE_BOUNDARY_TOLERANCE
                            or y1
                            < page_rect.y0
                            - PAGE_BOUNDARY_TOLERANCE
                            or y0
                            > page_rect.y1
                            + PAGE_BOUNDARY_TOLERANCE
                        )

                        if outside_page:

                            reasons.append(
                                "outside-page-boundary",
                            )

                            confidence += 0.30

                        # -------------------------------------------------
                        # Signal 4: very light text
                        # -------------------------------------------------

                        if is_light_color(
                            color,
                        ):

                            reasons.append(
                                "very-light-text",
                            )

                            confidence += 0.30

                        # -------------------------------------------------
                        # Signal 5: zero-width characters
                        # -------------------------------------------------

                        zero_width = (
                            detect_zero_width_characters(
                                text,
                            )
                        )

                        if zero_width:

                            reasons.append(
                                "zero-width-characters",
                            )

                            confidence += 0.20

                        # -------------------------------------------------
                        # Signal 6: native text not visible in OCR
                        # -------------------------------------------------

                        visible_overlap = (
                            token_overlap(
                                text,
                                visible_ocr_text,
                            )
                        )

                        native_word_count = len(
                            text_tokens(text),
                        )

                        if (
                            tesseract_available
                            and native_word_count >= 2
                            and visible_overlap < 0.20
                            and visible_ocr_text
                        ):

                            reasons.append(
                                "not-visible-in-rendered-page",
                            )

                            confidence += 0.40

                        # -------------------------------------------------
                        # We don't report normal visible text.
                        #
                        # OCR mismatch alone can be noisy, so require
                        # either a structural hidden signal or a strong
                        # OCR mismatch.
                        # -------------------------------------------------

                        if not reasons:
                            continue

                        content_analysis = (
                            analyze_hidden_content_text(
                                text,
                            )
                        )

                        for signal in content_analysis[
                            "signals"
                        ]:

                            if signal == "prompt-injection":
                                confidence += 0.25

                            elif signal == "command-execution":
                                confidence += 0.25

                            elif signal == "credential-request":
                                confidence += 0.25

                            elif signal == "possible-obfuscation":
                                confidence += 0.15

                            elif signal == "contains-url":
                                confidence += 0.05

                        confidence = min(
                            round(
                                confidence,
                                3,
                            ),
                            1.0,
                        )

                        findings.append(
                            {
                                "page": page_number + 1,
                                "text": text[:1000],
                                "fontSize": round(
                                    font_size,
                                    3,
                                ),
                                "bbox": [
                                    round(
                                        float(x0),
                                        2,
                                    ),
                                    round(
                                        float(y0),
                                        2,
                                    ),
                                    round(
                                        float(x1),
                                        2,
                                    ),
                                    round(
                                        float(y1),
                                        2,
                                    ),
                                ],
                                "color": color_to_rgb(
                                    color,
                                ),
                                "reasons": sorted(
                                    set(reasons),
                                ),
                                "contentSignals": (
                                    content_analysis[
                                        "signals"
                                    ]
                                ),
                                "urls": (
                                    content_analysis[
                                        "urls"
                                    ]
                                ),
                                "visibleOverlap": round(
                                    visible_overlap,
                                    3,
                                ),
                                "ocrChecked": (
                                    tesseract_available
                                ),
                                "confidence": confidence,
                            },
                        )

                        if len(findings) >= (
                            MAX_HIDDEN_TEXT_ITEMS
                        ):
                            return findings

        except Exception:
            continue

    return findings


# =========================================================
# OpenAction
# =========================================================

def normalize_action_type(value):

    if not value:
        return "Unknown"

    value = str(value).strip()

    known_types = {
        "GoTo": "GoTo",
        "GoToR": "GoToR",
        "URI": "URI",
        "JavaScript": "JavaScript",
        "Launch": "Launch",
        "Named": "Unknown",
    }

    return known_types.get(
        value,
        "Unknown",
    )


def extract_open_action(
    document,
):
    result = {
        "present": False,
        "type": None,
        "rawType": None,
        "target": None,
    }

    try:

        catalog_xref = document.pdf_catalog()

        if not catalog_xref:
            return result

        catalog_object = document.xref_object(
            catalog_xref,
            compressed=False,
        )

        if not catalog_object:
            return result

        open_action_match = re.search(
            r"/OpenAction\s+(\d+)\s+(\d+)\s+R",
            catalog_object,
            re.IGNORECASE,
        )

        if not open_action_match:

            inline_match = re.search(
                r"/OpenAction\s*<<([\s\S]*?)>>",
                catalog_object,
                re.IGNORECASE,
            )

            if not inline_match:
                return result

            action_object = (
                inline_match.group(1)
            )

        else:

            action_xref = int(
                open_action_match.group(1),
            )

            action_object = document.xref_object(
                action_xref,
                compressed=False,
            )

            if not action_object:

                result["present"] = True
                result["type"] = "Unknown"

                return result

        result["present"] = True

        action_type_match = re.search(
            r"/S\s*/([A-Za-z0-9]+)",
            action_object,
            re.IGNORECASE,
        )

        if action_type_match:

            raw_type = (
                action_type_match.group(1)
            )

            result["rawType"] = raw_type

            result["type"] = (
                normalize_action_type(
                    raw_type,
                )
            )

        else:

            result["type"] = "Unknown"

        if result["type"] == "URI":

            uri_match = re.search(
                r"/URI\s*\((.*?)\)",
                action_object,
                re.IGNORECASE | re.DOTALL,
            )

            if uri_match:

                result["target"] = (
                    uri_match.group(1)
                )

            else:

                uri_hex_match = re.search(
                    r"/URI\s*<([0-9A-Fa-f]+)>",
                    action_object,
                    re.IGNORECASE,
                )

                if uri_hex_match:

                    try:

                        result["target"] = (
                            bytes.fromhex(
                                uri_hex_match.group(1),
                            ).decode(
                                "utf-8",
                                errors="ignore",
                            )
                        )

                    except ValueError:
                        pass

        elif result["type"] == "Launch":

            file_match = re.search(
                r"/F\s*\((.*?)\)",
                action_object,
                re.IGNORECASE | re.DOTALL,
            )

            if file_match:
                result["target"] = (
                    file_match.group(1)
                )

        elif result["type"] == "JavaScript":

            javascript_match = re.search(
                r"/JS\s*(?:\((.*?)\)|<([0-9A-Fa-f]+)>)",
                action_object,
                re.IGNORECASE | re.DOTALL,
            )

            if javascript_match:

                javascript_text = (
                    javascript_match.group(1)
                    or javascript_match.group(2)
                    or ""
                )

                if javascript_match.group(2):

                    try:

                        javascript_text = (
                            bytes.fromhex(
                                javascript_text,
                            ).decode(
                                "utf-8",
                                errors="ignore",
                            )
                        )

                    except ValueError:
                        pass

                result["target"] = (
                    javascript_text[:200]
                    if javascript_text
                    else None
                )

        elif result["type"] == "GoTo":

            result["target"] = (
                "internal document destination"
            )

        elif result["type"] == "GoToR":

            file_match = re.search(
                r"/F\s*\((.*?)\)",
                action_object,
                re.IGNORECASE | re.DOTALL,
            )

            if file_match:

                result["target"] = (
                    file_match.group(1)
                )

            else:

                result["target"] = (
                    "remote document destination"
                )

        return result

    except Exception:
        return result


# =========================================================
# Main PDF analysis
# =========================================================

def analyze_pdf(path):

    result = {
        "ok": False,

        "metadata": {},

        "pageCount": 0,

        "urls": [],

        "javascriptCount": 0,

        "embeddedFileCount": 0,

        "embeddedFiles": [],

        "annotationCount": 0,

        "formFieldCount": 0,

        "openAction": {
            "present": False,
            "type": None,
            "rawType": None,
            "target": None,
        },

        "hasOpenAction": False,

        "hasLaunchAction": False,

        "hasAdditionalActions": False,

        "hasRichMedia": False,

        "hasAcroForm": False,

        "hasXfa": False,

        "extractedTextLength": 0,

        "suspiciousObjects": [],

        # -----------------------------------------------------
        # Hidden text
        # -----------------------------------------------------

        "hiddenText": {
            "count": 0,
            "items": [],
        },

        # -----------------------------------------------------
        # OCR
        # -----------------------------------------------------

        "ocrAttempted": False,

        "ocrAvailable": False,

        "ocrTextLength": 0,

        "ocrPageCount": 0,

        "ocrText": "",

        "ocrErrors": [],

        "textSource": "none",
    }

    try:

        document = pymupdf.open(
            path,
        )

        result["ok"] = True

        # =====================================================
        # Metadata
        # =====================================================

        result["metadata"] = {
            key: value
            for key, value in (
                document.metadata or {}
            ).items()
            if value
        }

        result["pageCount"] = (
            document.page_count
        )

        # =====================================================
        # Page analysis
        # =====================================================

        all_text = []

        urls = []

        annotations = 0

        form_fields = 0

        for page in document:

            text = page.get_text(
                "text",
            ) or ""

            if text.strip():

                all_text.append(
                    text,
                )

            for link in page.get_links():

                uri = link.get(
                    "uri",
                )

                if uri:
                    urls.append(
                        uri,
                    )

            try:

                page_annotations = (
                    page.annots()
                )

                if page_annotations:

                    annotations += sum(
                        1
                        for _ in page_annotations
                    )

            except Exception:
                pass

            try:

                widgets = page.widgets()

                if widgets:

                    form_fields += sum(
                        1
                        for _ in widgets
                    )

            except Exception:
                pass

        extracted_text = "\n".join(
            all_text,
        ).strip()

        result["extractedTextLength"] = len(
            extracted_text,
        )

        result["urls"] = sorted(
            set(urls),
        )

        result["annotationCount"] = (
            annotations
        )

        result["formFieldCount"] = (
            form_fields
        )

        # =====================================================
        # OpenAction
        # =====================================================

        open_action = extract_open_action(
            document,
        )

        result["openAction"] = (
            open_action
        )

        result["hasOpenAction"] = (
            open_action["present"]
        )

        # =====================================================
        # Embedded files
        # =====================================================

        embedded_files = (
            extract_embedded_files(
                document,
            )
        )

        result["embeddedFiles"] = (
            embedded_files
        )

        result["embeddedFileCount"] = (
            len(embedded_files)
        )

        # =====================================================
        # Suspicious PDF objects
        # =====================================================

        suspicious_objects = []

        javascript_count = 0

        has_launch_action = False

        has_additional_actions = False

        has_rich_media = False

        has_acro_form = False

        has_xfa = False

        xref_count = document.xref_length()

        for xref in range(
            1,
            xref_count,
        ):

            try:

                object_text = (
                    document.xref_object(
                        xref,
                        compressed=False,
                    )
                )

                if not object_text:
                    continue

                lower = object_text.lower()

                if re.search(r"/(?:javascript|js)\b", lower):

                    javascript_count += 1

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "javascript",
                        },
                    )

                if re.search(r"/aa\b", lower):

                    has_additional_actions = True

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "additional-actions",
                        },
                    )

                if "/launch" in lower:

                    has_launch_action = True

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "launch",
                        },
                    )

                if "/embeddedfile" in lower:

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "embedded-file",
                        },
                    )

                if "/richmedia" in lower:

                    has_rich_media = True

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "richmedia",
                        },
                    )

                if "/acroform" in lower:

                    has_acro_form = True

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "acroform",
                        },
                    )

                if "/xfa" in lower:

                    has_xfa = True

                    suspicious_objects.append(
                        {
                            "xref": xref,
                            "type": "xfa",
                        },
                    )

            except Exception:
                continue

        result["javascriptCount"] = (
            javascript_count
        )

        result["hasLaunchAction"] = (
            has_launch_action
        )

        result["hasAdditionalActions"] = (
            has_additional_actions
        )

        result["hasRichMedia"] = (
            has_rich_media
        )

        result["hasAcroForm"] = (
            has_acro_form
        )

        result["hasXfa"] = (
            has_xfa
        )

        # =====================================================
        # Hidden-text pipeline
        # =====================================================

        hidden_text = detect_hidden_text(
            document,
        )

        result["hiddenText"] = {
            "count": len(
                hidden_text,
            ),
            "items": hidden_text,
        }

        # Add hidden text as suspicious objects
        # without duplicating every individual finding.
        if hidden_text:

            suspicious_objects.append(
                {
                    "xref": 0,
                    "type": "hidden-text",
                },
            )

        # =====================================================
        # Deduplicate suspicious objects
        # =====================================================

        unique_objects = []

        seen_objects = set()

        for item in suspicious_objects:

            key = (
                item["xref"],
                item["type"],
            )

            if key not in seen_objects:

                seen_objects.add(
                    key,
                )

                unique_objects.append(
                    item,
                )

        result["suspiciousObjects"] = (
            unique_objects
        )

        # =====================================================
        # OCR for pages without a native text layer
        # =====================================================

        tesseract_path = find_tesseract()
        result["ocrAvailable"] = tesseract_path is not None

        native_page_count = 0
        pages_needing_ocr = []

        for page_number in range(document.page_count):
            page = document.load_page(page_number)
            page_text = page.get_text("text") or ""
            if page_text.strip():
                native_page_count += 1
            else:
                pages_needing_ocr.append(page_number)

        ocr_parts = []
        successful_ocr_pages = 0
        attempted_pages = 0

        if tesseract_path:
            # OCR only pages that have no native text. This also handles
            # mixed PDFs where some pages are scanned and others are digital.
            for page_number in pages_needing_ocr[:MAX_OCR_PAGES]:
                attempted_pages += 1
                page = document.load_page(page_number)
                try:
                    pixmap = page.get_pixmap(
                        matrix=pymupdf.Matrix(OCR_SCALE, OCR_SCALE),
                        alpha=False,
                    )
                    image_bytes = pixmap.tobytes("png")
                    ocr_result = subprocess.run(
                        [tesseract_path, "stdin", "stdout", "--psm", "6"],
                        input=image_bytes,
                        capture_output=True,
                        timeout=OCR_TIMEOUT_SECONDS,
                    )

                    if ocr_result.returncode != 0:
                        error_text = ocr_result.stderr.decode(
                            "utf-8", errors="ignore"
                        ).strip()
                        result["ocrErrors"].append({
                            "page": page_number + 1,
                            "error": error_text or f"Tesseract exited with code {ocr_result.returncode}",
                        })
                        continue

                    page_ocr_text = ocr_result.stdout.decode(
                        "utf-8", errors="ignore"
                    ).strip()
                    if page_ocr_text:
                        ocr_parts.append(page_ocr_text)
                        successful_ocr_pages += 1
                    else:
                        result["ocrErrors"].append({
                            "page": page_number + 1,
                            "error": "OCR ran but returned no readable text",
                        })

                except subprocess.TimeoutExpired:
                    result["ocrErrors"].append({
                        "page": page_number + 1,
                        "error": f"OCR timed out after {OCR_TIMEOUT_SECONDS} seconds",
                    })
                except Exception as ocr_error:
                    result["ocrErrors"].append({
                        "page": page_number + 1,
                        "error": str(ocr_error)[:300],
                    })

        combined_ocr_text = "\n".join(ocr_parts).strip()

        # "ocrAttempted" also records that OCR was required but could not
        # be run. The evidence layer uses this to warn when scanned pages
        # were not inspectable because Tesseract is missing.
        ocr_required = bool(pages_needing_ocr)
        result["ocrAttempted"] = attempted_pages > 0 or (
            ocr_required and not tesseract_path
        )

        if ocr_required and not tesseract_path:
            result["ocrErrors"].append({
                "error": "Scanned/image-only page(s) detected, but Tesseract OCR is not installed or was not found.",
            })

        result["ocrPageCount"] = successful_ocr_pages
        result["ocrText"] = combined_ocr_text
        result["ocrTextLength"] = len(combined_ocr_text)

        if extracted_text and combined_ocr_text:
            result["textSource"] = "mixed"
        elif extracted_text:
            result["textSource"] = "native"
        elif combined_ocr_text:
            result["textSource"] = "ocr"
        else:
            result["textSource"] = "none"

        if len(pages_needing_ocr) > MAX_OCR_PAGES and tesseract_path:
            result["ocrErrors"].append({
                "error": f"OCR page limit reached: processed at most {MAX_OCR_PAGES} pages without native text",
            })

        document.close()

        print(
            json.dumps(
                result,
                ensure_ascii=False,
            ),
        )

    except Exception as error:

        result["ok"] = False

        result["error"] = str(
            error,
        )

        print(
            json.dumps(
                result,
                ensure_ascii=False,
            ),
        )

        sys.exit(1)


# =========================================================
# CLI
# =========================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": (
                        "PDF path was not provided"
                    ),
                },
            ),
        )

        sys.exit(1)

    analyze_pdf(
        sys.argv[1],
    )