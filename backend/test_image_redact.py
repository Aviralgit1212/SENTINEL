from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont

from extraction.image_ocr import extract_image
from redact.image_mapping import map_entity_text_to_regions
from redact.image_redact import (
    ImageRedactionError,
    redact_and_verify_image,
    redact_image_regions,
    verify_redacted_image_bytes,
)

TARGET_PHONE = "555-123-4567"
TARGET_LABEL = "CONFIDENTIAL"


def _synthetic_image() -> bytes:
    image = Image.new("RGB", (1800, 440), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", 74)
    draw.text((55, 80), f"Phone: {TARGET_PHONE}", fill="black", font=font)
    draw.text((55, 235), TARGET_LABEL, fill="black", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _span(image_bytes: bytes, target: str) -> tuple[int, int, str]:
    text = extract_image(image_bytes).full_text
    start = text.index(target)
    return start, start + len(target), target


def test_single_region_redaction_and_verification() -> None:
    source = _synthetic_image()
    result = redact_and_verify_image(source, [_span(source, TARGET_PHONE)])
    assert result.redacted_bytes and result.mime_type == "image/png" and result.extension == ".png"
    assert TARGET_PHONE not in extract_image(result.redacted_bytes).full_text


def test_pixel_content_changes_at_sensitive_region() -> None:
    source = _synthetic_image()
    original_ocr = extract_image(source)
    mapped = map_entity_text_to_regions(original_ocr.full_text, original_ocr.regions, TARGET_PHONE)
    result = redact_image_regions(source, mapped)
    with Image.open(io.BytesIO(source)) as before, Image.open(io.BytesIO(result.redacted_bytes)) as after:
        assert before.size == after.size
        assert before.convert("RGB").tobytes() != after.convert("RGB").tobytes()
    verify_redacted_image_bytes(result.redacted_bytes, [TARGET_PHONE])


def test_multiple_sensitive_regions_redacted() -> None:
    source = _synthetic_image()
    spans = [_span(source, TARGET_PHONE), _span(source, TARGET_LABEL)]
    result = redact_and_verify_image(source, spans)
    output = extract_image(result.redacted_bytes).full_text
    assert TARGET_PHONE not in output
    assert TARGET_LABEL not in output


def test_mapping_to_redaction_contract() -> None:
    source = _synthetic_image()
    result = extract_image(source)
    mapped = map_entity_text_to_regions(result.full_text, result.regions, TARGET_PHONE)
    assert len(mapped) >= 1
    redacted = redact_image_regions(source, mapped)
    verify_redacted_image_bytes(redacted.redacted_bytes, [TARGET_PHONE])


def test_verification_failure_is_fail_closed() -> None:
    failed = False
    try:
        verify_redacted_image_bytes(_synthetic_image(), [TARGET_PHONE])
    except ImageRedactionError:
        failed = True
    assert failed


def test_invalid_empty_image_rejected() -> None:
    try:
        redact_image_regions(b"", [])
    except ImageRedactionError:
        return
    raise AssertionError("Empty image was not rejected.")


def test_invalid_no_entity_rejected() -> None:
    try:
        redact_and_verify_image(_synthetic_image(), [])
    except ImageRedactionError:
        return
    raise AssertionError("No-entity redaction was not rejected.")
