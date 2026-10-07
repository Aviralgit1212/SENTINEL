import json
import sys

import pymupdf


def analyze_pdf(file_path):
    document = pymupdf.open(file_path)

    metadata = document.metadata or {}

    urls = []
    javascript_count = 0
    embedded_file_count = 0
    annotation_count = 0
    form_field_count = 0

    has_open_action = False
    has_launch_action = False
    has_additional_actions = False
    has_rich_media = False
    has_acroform = False
    has_xfa = False

    extracted_text_length = 0

    suspicious_objects = []

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    cleaned_metadata = {}

    for key, value in metadata.items():
        if value:
            cleaned_metadata[key] = str(value)

    # ---------------------------------------------------------
    # Page-level inspection
    # ---------------------------------------------------------

    for page_number, page in enumerate(document, start=1):

        text = page.get_text("text")
        extracted_text_length += len(text)

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

        annotations = page.annots()

        if annotations:
            for annotation in annotations:
                annotation_count += 1

                content = annotation.info.get("content")

                if content:
                    urls.append(content)

        # -----------------------------------------------------
        # Form widgets
        # -----------------------------------------------------

        widgets = page.widgets()

        if widgets:
            for _widget in widgets:
                form_field_count += 1

    # ---------------------------------------------------------
    # Embedded files
    # ---------------------------------------------------------

    try:
        embedded_file_count = document.embfile_count()
    except Exception:
        embedded_file_count = 0

    # ---------------------------------------------------------
    # Inspect PDF objects
    # ---------------------------------------------------------

    for xref in range(1, document.xref_length()):

        try:
            object_text = document.xref_object(
                xref,
                compressed=False,
            )

            if not object_text:
                continue

            lower = object_text.lower()

            # ---------------------------------------------
            # JavaScript
            # ---------------------------------------------

            if "/javascript" in lower or "/js" in lower:
                javascript_count += 1

                suspicious_objects.append({
                    "xref": xref,
                    "type": "javascript",
                })

            # ---------------------------------------------
            # OpenAction
            # ---------------------------------------------

            if "/openaction" in lower:
                has_open_action = True

                suspicious_objects.append({
                    "xref": xref,
                    "type": "openaction",
                })

            # ---------------------------------------------
            # Additional Actions
            # ---------------------------------------------

            if "/aa" in lower:
                has_additional_actions = True

                suspicious_objects.append({
                    "xref": xref,
                    "type": "additional-action",
                })

            # ---------------------------------------------
            # Launch
            # ---------------------------------------------

            if "/launch" in lower:
                has_launch_action = True

                suspicious_objects.append({
                    "xref": xref,
                    "type": "launch",
                })

            # ---------------------------------------------
            # RichMedia
            # ---------------------------------------------

            if "/richmedia" in lower:
                has_rich_media = True

                suspicious_objects.append({
                    "xref": xref,
                    "type": "richmedia",
                })

            # ---------------------------------------------
            # AcroForm
            # ---------------------------------------------

            if "/acroform" in lower:
                has_acroform = True

            # ---------------------------------------------
            # XFA
            # ---------------------------------------------

            if "/xfa" in lower:
                has_xfa = True

                suspicious_objects.append({
                    "xref": xref,
                    "type": "xfa",
                })

        except Exception:
            continue

    # ---------------------------------------------------------
    # Remove duplicate URLs
    # ---------------------------------------------------------

    urls = list(dict.fromkeys(urls))

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

        if key in seen_objects:
            continue

        seen_objects.add(key)
        unique_objects.append(item)

    return {
        "ok": True,
        "metadata": cleaned_metadata,
        "pageCount": len(document),
        "urls": urls,
        "javascriptCount": javascript_count,
        "embeddedFileCount": embedded_file_count,
        "annotationCount": annotation_count,
        "formFieldCount": form_field_count,
        "hasOpenAction": has_open_action,
        "hasLaunchAction": has_launch_action,
        "hasAdditionalActions": has_additional_actions,
        "hasRichMedia": has_rich_media,
        "hasAcroForm": has_acroform,
        "hasXfa": has_xfa,
        "extractedTextLength": extracted_text_length,
        "suspiciousObjects": unique_objects,
    }


def main():

    if len(sys.argv) != 2:

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "PDF path is required.",
                }
            )
        )

        sys.exit(1)

    file_path = sys.argv[1]

    try:

        result = analyze_pdf(file_path)

        print(json.dumps(result))

    except Exception as error:

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(error),
                }
            )
        )

        sys.exit(1)


if __name__ == "__main__":
    main()