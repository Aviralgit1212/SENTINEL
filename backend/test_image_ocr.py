from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont

from extraction.image_ocr import OCRRegion, extract_image

TARGET_PHONE = "555-123-4567"


def _synthetic_image(text: str) -> bytes:
    image = Image.new("RGB", (1800, 420), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", 74)
    draw.text((55, 90), text, fill="black", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_synthetic_sensitive_text_extraction() -> None:
    result = extract_image(_synthetic_image(f"Phone: {TARGET_PHONE}"))
    assert TARGET_PHONE in result.full_text
    assert result.regions
    phone_regions = [region for region in result.regions if region.text == TARGET_PHONE]
    assert len(phone_regions) == 1
    phone = phone_regions[0]
    assert isinstance(phone, OCRRegion)
    assert phone.width > 0 and phone.height > 0 and phone.confidence >= 0


def test_synthetic_multiline_extraction() -> None:
    result = extract_image(_synthetic_image("Sentinel synthetic OCR test"))
    assert "Sentinel" in result.full_text
    assert "synthetic" in result.full_text
    assert "OCR" in result.full_text
    assert len(result.regions) >= 3


def test_corrupted_image_rejected() -> None:
    try:
        extract_image(b"this is not a valid image")
    except ValueError:
        return
    raise AssertionError("Corrupted image was not rejected.")


def test_empty_image_rejected() -> None:
    try:
        extract_image(b"")
    except ValueError:
        return
    raise AssertionError("Empty image was not rejected.")
