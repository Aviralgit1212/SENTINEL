import json
import re
import shutil
import subprocess
import sys

import pymupdf


MAX_OCR_PAGES = 10
OCR_TIMEOUT_SECONDS = 15


def run_ocr(page):
    """
    Render one PDF page to PNG and send it directly to Tesseract.
    No temporary image file is created.
    """
    pixmap = page.get_pixmap(
        matrix=pymupdf.Matrix(2, 2),
        alpha=False,
    )

    image_bytes = pixmap.tobytes("png")

    try:
        result = subprocess.run(
            ["tesseract", "stdin", "stdout", "--psm", "6"],
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

    except (subprocess.TimeoutExpired, OSError):
        return ""


def normalize_action_type(value):
    """
    Converts a PDF action type into a controlled value.

    Unknown actions are reported as Unknown instead of
    guessing what the PDF is trying to do.
    """

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

    return known_types.get(value, "Unknown")


def extract_open_action(document):
    """
    Inspect the PDF catalog and determine what its OpenAction does.

    Returns:

        {
            "present": bool,
            "type": str | None,
            "rawType": str | None,
            "target": str | None
        }

    This is fact extraction only.
    No risk score or severity is assigned here.
    """

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

        # ---------------------------------------------------------
        # Find /OpenAction reference
        # ---------------------------------------------------------

        open_action_match = re.search(
            r"/OpenAction\s+(\d+)\s+(\d+)\s+R",
            catalog_object,
            re.IGNORECASE,
        )

        if not open_action_match:
            # Some PDFs may store the action inline.
            inline_match = re.search(
                r"/OpenAction\s*<<([\s\S]*?)>>",
                catalog_object,
                re.IGNORECASE,
            )

            if not inline_match:
                return result

            action_object = inline_match.group(1)

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

        # ---------------------------------------------------------
        # Determine action type
        # ---------------------------------------------------------

        action_type_match = re.search(
            r"/S\s*/([A-Za-z0-9]+)",
            action_object,
            re.IGNORECASE,
        )

        if action_type_match:
            raw_type = action_type_match.group(1)

            result["rawType"] = raw_type
            result["type"] = normalize_action_type(
                raw_type,
            )

        else:
            result["type"] = "Unknown"

        # ---------------------------------------------------------
        # Extract useful target information
        # ---------------------------------------------------------

        if result["type"] == "URI":

            uri_match = re.search(
                r"/URI\s*\((.*?)\)",
                action_object,
                re.IGNORECASE | re.DOTALL,
            )

            if uri_match:
                result["target"] = uri_match.group(1)

            else:
                uri_hex_match = re.search(
                    r"/URI\s*<([0-9A-Fa-f]+)>",
                    action_object,
                    re.IGNORECASE,
                )

                if uri_hex_match:
                    try:
                        result["target"] = bytes.fromhex(
                            uri_hex_match.group(1),
                        ).decode(
                            "utf-8",
                            errors="ignore",
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
                result["target"] = file_match.group(1)

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
                        javascript_text = bytes.fromhex(
                            javascript_text,
                        ).decode(
                            "utf-8",
                            errors="ignore",
                        )
                    except ValueError:
                        pass

                # Do NOT expose the entire JavaScript payload.
                # Only expose a bounded preview.
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
                result["target"] = file_match.group(1)

            else:
                result["target"] = (
                    "remote document destination"
                )

        return result

    except Exception:
        return result


def analyze_pdf(path):
    result = {
        "ok": False,
        "metadata": {},
        "pageCount": 0,
        "urls": [],
        "javascriptCount": 0,
        "embeddedFileCount": 0,
        "annotationCount": 0,
        "formFieldCount": 0,

        # ---------------------------------------------------------
        # OpenAction
        # ---------------------------------------------------------

        "openAction": {
            "present": False,
            "type": None,
            "rawType": None,
            "target": None,
        },

        # Legacy compatibility field.
        "hasOpenAction": False,

        "hasLaunchAction": False,
        "hasAdditionalActions": False,
        "hasRichMedia": False,
        "hasAcroForm": False,
        "hasXfa": False,

        "extractedTextLength": 0,

        "suspiciousObjects": [],

        # ---------------------------------------------------------
        # OCR
        # ---------------------------------------------------------

        "ocrAttempted": False,
        "ocrAvailable": False,
        "ocrTextLength": 0,
        "ocrPageCount": 0,
        "ocrText": "",
        "textSource": "none",
    }

    try:
        document = pymupdf.open(path)

        result["ok"] = True

        # ---------------------------------------------------------
        # Metadata
        # ---------------------------------------------------------

        result["metadata"] = {
            key: value
            for key, value in (document.metadata or {}).items()
            if value
        }

        result["pageCount"] = document.page_count

        # ---------------------------------------------------------
        # Page-level analysis
        # ---------------------------------------------------------

        all_text = []
        urls = []
        annotations = 0
        form_fields = 0

        for page in document:

            # -----------------------------------------------------
            # Native PDF text
            # -----------------------------------------------------

            text = page.get_text("text") or ""

            if text.strip():
                all_text.append(text)

            # -----------------------------------------------------
            # Links / URLs
            # -----------------------------------------------------

            for link in page.get_links():

                uri = link.get("uri")

                if uri:
                    urls.append(uri)

            # -----------------------------------------------------
            # Annotations
            # -----------------------------------------------------

            try:
                page_annotations = page.annots()

                if page_annotations:
                    annotations += sum(
                        1
                        for _ in page_annotations
                    )

            except Exception:
                pass

            # -----------------------------------------------------
            # Form fields
            # -----------------------------------------------------

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

        result["annotationCount"] = annotations
        result["formFieldCount"] = form_fields

        # ---------------------------------------------------------
        # OpenAction analysis
        # ---------------------------------------------------------

        open_action = extract_open_action(
            document,
        )

        result["openAction"] = open_action

        result["hasOpenAction"] = (
            open_action["present"]
        )

        # ---------------------------------------------------------
        # PDF structure / suspicious object analysis
        # ---------------------------------------------------------

        suspicious_objects = []

        javascript_count = 0
        embedded_file_count = 0

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

                object_text = document.xref_object(
                    xref,
                    compressed=False,
                )

                if not object_text:
                    continue

                lower = object_text.lower()

                # -------------------------------------------------
                # JavaScript
                # -------------------------------------------------

                if (
                    "/javascript" in lower
                    or "/js" in lower
                ):

                    javascript_count += 1

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "javascript",
                    })

                # -------------------------------------------------
                # Additional actions
                # -------------------------------------------------

                if "/aa" in lower:

                    has_additional_actions = True

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "additional-actions",
                    })

                # -------------------------------------------------
                # Launch
                # -------------------------------------------------

                if "/launch" in lower:

                    has_launch_action = True

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "launch",
                    })

                # -------------------------------------------------
                # Embedded files
                #
                # IMPORTANT:
                # Do NOT treat /Filespec alone as proof of an
                # embedded file. A FileSpec can reference a file
                # without containing an embedded-file stream.
                #
                # We currently require the explicit /EmbeddedFile
                # marker.
                # -------------------------------------------------

                if "/embeddedfile" in lower:

                    embedded_file_count += 1

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "embedded-file",
                    })

                # -------------------------------------------------
                # Rich media
                # -------------------------------------------------

                if "/richmedia" in lower:

                    has_rich_media = True

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "richmedia",
                    })

                # -------------------------------------------------
                # AcroForm
                # -------------------------------------------------

                if "/acroform" in lower:

                    has_acro_form = True

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "acroform",
                    })

                # -------------------------------------------------
                # XFA
                # -------------------------------------------------

                if "/xfa" in lower:

                    has_xfa = True

                    suspicious_objects.append({
                        "xref": xref,
                        "type": "xfa",
                    })

            except Exception:
                continue

        result["javascriptCount"] = (
            javascript_count
        )

        result["embeddedFileCount"] = (
            embedded_file_count
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

        result["hasXfa"] = has_xfa

        # ---------------------------------------------------------
        # Remove duplicate suspicious objects
        # ---------------------------------------------------------

        unique_objects = []

        seen_objects = set()

        for item in suspicious_objects:

            key = (
                item["xref"],
                item["type"],
            )

            if key not in seen_objects:

                seen_objects.add(key)

                unique_objects.append(
                    item,
                )

        result["suspiciousObjects"] = (
            unique_objects
        )

        # ---------------------------------------------------------
        # OCR
        # ---------------------------------------------------------

        if extracted_text:

            result["textSource"] = "native"

        else:

            result["ocrAttempted"] = True

            tesseract_path = shutil.which(
                "tesseract",
            )

            if tesseract_path:

                result["ocrAvailable"] = True

                ocr_pages = min(
                    document.page_count,
                    MAX_OCR_PAGES,
                )

                ocr_parts = []

                for page_number in range(
                    ocr_pages,
                ):

                    page = document.load_page(
                        page_number,
                    )

                    ocr_text = run_ocr(
                        page,
                    )

                    if ocr_text:
                        ocr_parts.append(
                            ocr_text,
                        )

                combined_ocr_text = "\n".join(
                    ocr_parts,
                ).strip()

                result["ocrPageCount"] = (
                    ocr_pages
                )

                result["ocrText"] = (
                    combined_ocr_text
                )

                result["ocrTextLength"] = len(
                    combined_ocr_text,
                )

                if combined_ocr_text:

                    result["textSource"] = "ocr"

                else:

                    result["textSource"] = "none"

            else:

                result["textSource"] = "none"

        document.close()

        print(
            json.dumps(
                result,
                ensure_ascii=False,
            ),
        )

    except Exception as error:

        result["ok"] = False
        result["error"] = str(error)

        print(
            json.dumps(
                result,
                ensure_ascii=False,
            ),
        )

        sys.exit(1)


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps({
                "ok": False,
                "error": "PDF path was not provided",
            }),
        )

        sys.exit(1)

    analyze_pdf(
        sys.argv[1],
    )