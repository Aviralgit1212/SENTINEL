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
    extracted_text_length = 0

    # Metadata
    cleaned_metadata = {}

    for key, value in metadata.items():
        if value:
            cleaned_metadata[key] = str(value)

    # Page-level inspection
    for page in document:
        text = page.get_text("text")
        extracted_text_length += len(text)

        # Links / URLs
        for link in page.get_links():
            uri = link.get("uri")

            if uri:
                urls.append(uri)

        # Annotations
        annotations = page.annots()

        if annotations:
            for annotation in annotations:
                annotation_count += 1

                uri = annotation.info.get("content")

                if uri:
                    urls.append(uri)

        # Form widgets
        widgets = page.widgets()

        if widgets:
            for _widget in widgets:
                form_field_count += 1

    # Embedded files
    try:
        embedded_file_count = document.embfile_count()
    except Exception:
        embedded_file_count = 0

    # PDF JavaScript
    try:
        javascript = document.get_page_text("javascript")

        if javascript:
            javascript_count = len(javascript)
    except Exception:
        pass

    # Inspect raw PDF objects for security-related structures.
    for xref in range(1, document.xref_length()):
        try:
            object_text = document.xref_object(
                xref,
                compressed=False,
            )

            if not object_text:
                continue

            lower = object_text.lower()

            if "/javascript" in lower:
                javascript_count += 1

            if "/openaction" in lower:
                has_open_action = True

            if "/launch" in lower:
                has_launch_action = True

        except Exception:
            continue

    # Remove duplicate URLs.
    urls = list(dict.fromkeys(urls))

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
        "extractedTextLength": extracted_text_length,
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