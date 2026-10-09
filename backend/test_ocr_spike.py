from __future__ import annotations

import sys
from pathlib import Path

import pytesseract
from PIL import Image
from pytesseract import Output


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "Usage: python test_ocr_spike.py <image-path>"
        )
        raise SystemExit(1)

    image_path = Path(sys.argv[1])

    if not image_path.exists():
        print(
            f"ERROR: Image not found: {image_path}"
        )
        raise SystemExit(1)

    try:
        image = Image.open(image_path)
        image.load()
    except Exception as exc:
        print(
            f"ERROR: Could not open image: {exc}"
        )
        raise SystemExit(1)

    print(
        f"Image: {image_path.name}"
    )
    print(
        f"Size: {image.width} x {image.height}"
    )
    print(
        f"Mode: {image.mode}"
    )

    # --------------------------------------------------
    # RAW OCR TEXT
    # --------------------------------------------------

    try:
        text = pytesseract.image_to_string(
            image,
            lang="eng",
        )
    except Exception as exc:
        print(
            f"ERROR: Tesseract OCR failed: {exc}"
        )
        raise SystemExit(1)

    print()
    print("========== OCR TEXT ==========")
    print(text.strip())

    # --------------------------------------------------
    # OCR WORD DATA + BOUNDING BOXES
    # --------------------------------------------------

    try:
        data = pytesseract.image_to_data(
            image,
            lang="eng",
            output_type=Output.DICT,
        )
    except Exception as exc:
        print(
            f"ERROR: OCR bounding-box extraction failed: {exc}"
        )
        raise SystemExit(1)

    print()
    print("========== OCR WORD BOXES ==========")

    word_count = 0

    for index, raw_text in enumerate(
        data["text"]
    ):
        word = raw_text.strip()

        if not word:
            continue

        try:
            confidence = float(
                data["conf"][index]
            )
        except (
            ValueError,
            TypeError,
        ):
            confidence = -1.0

        left = int(
            data["left"][index]
        )
        top = int(
            data["top"][index]
        )
        width = int(
            data["width"][index]
        )
        height = int(
            data["height"][index]
        )

        print(
            f"text={word!r} "
            f"conf={confidence:.1f} "
            f"box=({left},{top},{width},{height})"
        )

        word_count += 1

    print()
    print("========== TARGET CHECK ==========")

    target = "555-123-4567"

    if target in text:
        print(
            f"PHONE TARGET FOUND: PASS ({target})"
        )
    else:
        print(
            f"PHONE TARGET FOUND: FAIL ({target})"
        )

    print()
    print("========== SUMMARY ==========")

    print(
        f"OCR words detected: {word_count}"
    )

    if word_count == 0:
        print(
            "OCR RESULT: FAIL"
        )
        raise SystemExit(2)

    print(
        "OCR RESULT: PASS"
    )


if __name__ == "__main__":
    main()