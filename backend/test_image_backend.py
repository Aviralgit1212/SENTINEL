from __future__ import annotations

from pathlib import Path

import asyncio
import base64
import io

from fastapi import HTTPException
from PIL import Image, ImageDraw, ImageFont
from starlette.datastructures import UploadFile

from extraction.image_ocr import extract_image
from main import scan_file


BASE_DIR = Path(__file__).resolve().parent

REAL_IMAGE = (
    BASE_DIR / "AI_Guardian_OCR_Real_1.png"
)

TARGET_PHONE = "555-123-4567"

TARGET_CARD = "4111 1111 1111 1111"


def _font(size: int = 72):
    candidates = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    )

    for candidate in candidates:
        try:
            return ImageFont.truetype(
                candidate,
                size,
            )
        except OSError:
            continue

    return ImageFont.load_default()


def _make_image(
    text: str,
) -> bytes:
    image = Image.new(
        "RGB",
        (1800, 400),
        "white",
    )

    draw = ImageDraw.Draw(
        image
    )

    draw.text(
        (60, 120),
        text,
        fill="black",
        font=_font(),
    )

    output = io.BytesIO()

    image.save(
        output,
        format="PNG",
    )

    return output.getvalue()


def _run_scan_file(
    image_bytes: bytes,
    filename: str,
) -> dict:
    upload = UploadFile(
        filename=filename,
        file=io.BytesIO(image_bytes),
    )

    class RequestStub:
        headers = {
            "X-Sentinel-Site": "https://test.example",
            "X-Sentinel-Cache-Choice": "rescan",
        }

    return asyncio.run(
        scan_file(RequestStub(), upload)
    )


def test_safe_image_allows() -> None:
    image_bytes = _make_image(
        "AI Guardian safe project status"
    )

    response = _run_scan_file(
        image_bytes,
        "AI_Guardian_Backend_Safe.png",
    )

    assert response["risk"] == "LOW"

    assert response["decision"] == "ALLOW"

    assert (
        response["redacted_file_base64"]
        is None
    )

    assert (
        response["redacted_filename"]
        is None
    )

    assert (
        response["redacted_mime_type"]
        is None
    )

    print(
        "6.4.5 image SAFE -> LOW/ALLOW: PASS"
    )


def test_sensitive_image_redacts() -> None:
    image_bytes = _make_image(TARGET_PHONE)
    filename = "synthetic_phone.png"

    response = _run_scan_file(
        image_bytes,
        filename,
    )

    assert response["risk"] == "MEDIUM"

    assert response["decision"] == "REDACT"

    assert response["redacted_file_base64"]

    assert response["redacted_filename"] == (
        f"redacted_{filename}"
    )

    assert response["redacted_mime_type"] == (
        "image/png"
    )

    redacted_bytes = (
        base64.b64decode(
            response["redacted_file_base64"]
        )
    )

    verification = extract_image(
        redacted_bytes
    )

    assert TARGET_PHONE not in (
        verification.full_text
    )

    print(
        "6.4.5 image PHONE -> MEDIUM/REDACT: PASS"
    )

    print(
        "6.4.5 image safe Base64 output: PASS"
    )

    print(
        "6.4.5 backend re-OCR verification: PASS"
    )


def test_critical_image_blocks() -> None:
    image_bytes = _make_image(
        TARGET_CARD
    )

    response = _run_scan_file(
        image_bytes,
        "AI_Guardian_Backend_Block.png",
    )

    assert response["risk"] == "CRITICAL"

    assert response["decision"] == "BLOCK"

    assert (
        response["redacted_file_base64"]
        is None
    )

    assert (
        response["redacted_filename"]
        is None
    )

    assert (
        response["redacted_mime_type"]
        is None
    )

    print(
        "6.4.5 image CREDIT_CARD -> CRITICAL/BLOCK: PASS"
    )


def test_corrupted_image_fails_extraction() -> None:
    response = _run_scan_file(b"not an image", "synthetic_corrupt.png")
    assert response["decision"] == "INCOMPLETE"
    assert response["scan_status"] == "INCOMPLETE"


def main() -> None:
    test_safe_image_allows()

    test_sensitive_image_redacts()

    test_critical_image_blocks()

    test_corrupted_image_fails_extraction()

    print(
        "6.4.5 IMAGE BACKEND INTEGRATION: PASS"
    )


if __name__ == "__main__":
    main()
