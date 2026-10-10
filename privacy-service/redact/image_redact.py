from __future__ import annotations

import io
from dataclasses import dataclass

from PIL import Image, ImageDraw

from extraction.image_ocr import OCRRegion, extract_image
from redact.image_mapping import map_entity_to_regions


REDACTION_COLOR = (0, 0, 0)
PADDING_PIXELS = 3


class ImageRedactionError(Exception):
    """Raised when image redaction or verification cannot be completed."""


@dataclass(frozen=True)
class ImageRedactionResult:
    """Verified redacted image bytes and metadata."""

    redacted_bytes: bytes
    mime_type: str
    extension: str


def _normalize_format(
    image_format: str,
) -> tuple[str, str]:
    """
    Convert a Pillow format into a stable MIME type and extension.
    """

    normalized = image_format.upper()

    if normalized == "PNG":
        return (
            "image/png",
            ".png",
        )

    if normalized in {"JPEG", "JPG"}:
        return (
            "image/jpeg",
            ".jpg",
        )

    raise ImageRedactionError(
        f"Unsupported image format for redaction: {image_format}"
    )


def _expand_box(
    region: OCRRegion,
    image_width: int,
    image_height: int,
    padding: int = PADDING_PIXELS,
) -> tuple[int, int, int, int]:
    """
    Expand an OCR bounding box by a small safety margin and clamp it
    to the image boundaries.
    """

    left = max(
        0,
        region.left - padding,
    )

    top = max(
        0,
        region.top - padding,
    )

    right = min(
        image_width,
        region.left + region.width + padding,
    )

    bottom = min(
        image_height,
        region.top + region.height + padding,
    )

    if right <= left or bottom <= top:
        raise ImageRedactionError(
            "OCR region produced an invalid redaction rectangle."
        )

    return (
        left,
        top,
        right,
        bottom,
    )


def _redact_regions(
    image: Image.Image,
    regions: list[OCRRegion],
) -> None:
    """
    Permanently paint every mapped OCR region with an opaque fill.
    """

    if not regions:
        raise ImageRedactionError(
            "No OCR regions were supplied for redaction."
        )

    working = image.convert("RGB")

    draw = ImageDraw.Draw(
        working
    )

    for region in regions:
        box = _expand_box(
            region,
            working.width,
            working.height,
        )

        draw.rectangle(
            box,
            fill=REDACTION_COLOR,
        )

    image.paste(
        working,
    )


def _serialize_image(
    image: Image.Image,
    image_format: str,
) -> bytes:
    """
    Serialize the complete redacted image to fresh bytes.
    """

    output = io.BytesIO()

    save_format = image_format.upper()

    save_kwargs: dict[str, object] = {}

    if save_format in {"JPEG", "JPG"}:
        # JPEG has no alpha channel, so flatten to RGB.
        image = image.convert("RGB")

        save_format = "JPEG"

        save_kwargs["quality"] = 95
        save_kwargs["optimize"] = True

    elif save_format == "PNG":
        # RGB output removes alpha-channel ambiguity around redaction.
        image = image.convert("RGB")

    else:
        raise ImageRedactionError(
            f"Unsupported image serialization format: {image_format}"
        )

    try:
        image.save(
            output,
            format=save_format,
            **save_kwargs,
        )

    except Exception as exc:
        raise ImageRedactionError(
            "Could not serialize redacted image."
        ) from exc

    redacted_bytes = output.getvalue()

    if not redacted_bytes:
        raise ImageRedactionError(
            "Redacted image serialization produced empty bytes."
        )

    return redacted_bytes


def redact_image_regions(
    image_bytes: bytes,
    regions: list[OCRRegion],
) -> ImageRedactionResult:
    """
    Apply opaque pixel redaction to mapped OCR regions.

    Verification is handled separately by redact_and_verify_image().
    """

    if not image_bytes:
        raise ImageRedactionError(
            "Cannot redact an empty image."
        )

    if not regions:
        raise ImageRedactionError(
            "Cannot redact an image without OCR regions."
        )

    try:
        with Image.open(
            io.BytesIO(image_bytes)
        ) as source:

            source.load()

            image_format = source.format

            if image_format is None:
                raise ImageRedactionError(
                    "Input image format could not be determined."
                )

            mime_type, extension = _normalize_format(
                image_format
            )

            working = source.convert(
                "RGB"
            )

            _redact_regions(
                working,
                regions,
            )

            redacted_bytes = _serialize_image(
                working,
                image_format,
            )

    except ImageRedactionError:
        raise

    except Exception as exc:
        raise ImageRedactionError(
            "Could not open or redact image."
        ) from exc

    return ImageRedactionResult(
        redacted_bytes=redacted_bytes,
        mime_type=mime_type,
        extension=extension,
    )


def verify_redacted_image_bytes(
    redacted_bytes: bytes,
    original_sensitive_values: list[str],
) -> None:
    """
    Reopen the generated image, OCR it again, and confirm that none of
    the original sensitive values remain detectable.

    Any failure is fail-closed by raising ImageRedactionError.
    """

    if not redacted_bytes:
        raise ImageRedactionError(
            "Redacted image bytes are empty."
        )

    if not original_sensitive_values:
        raise ImageRedactionError(
            "No sensitive values supplied for verification."
        )

    try:
        result = extract_image(
            redacted_bytes
        )

    except Exception as exc:
        raise ImageRedactionError(
            "Could not reopen or re-OCR the redacted image."
        ) from exc

    verification_text = result.full_text

    for sensitive_value in original_sensitive_values:

        if not isinstance(
            sensitive_value,
            str,
        ):
            raise ImageRedactionError(
                "Sensitive verification value must be a string."
            )

        if not sensitive_value:
            raise ImageRedactionError(
                "Sensitive verification value cannot be empty."
            )

        if sensitive_value in verification_text:
            raise ImageRedactionError(
                "Post-redaction verification found an original "
                "sensitive value in the generated image."
            )


def redact_and_verify_image(
    image_bytes: bytes,
    entity_matches: list[tuple[int, int, str]],
) -> ImageRedactionResult:
    """
    Map entity spans to OCR regions, redact all mapped regions,
    reopen and re-OCR the generated image, and verify absence.

    entity_matches contains:

        (
            entity_start,
            entity_end,
            original_sensitive_value,
        )
    """

    if not entity_matches:
        raise ImageRedactionError(
            "No sensitive entity matches supplied."
        )

    try:
        original_result = extract_image(
            image_bytes
        )

    except Exception as exc:
        raise ImageRedactionError(
            "Could not OCR the source image."
        ) from exc

    all_regions: list[OCRRegion] = []

    original_sensitive_values: list[str] = []

    for (
        entity_start,
        entity_end,
        sensitive_value,
    ) in entity_matches:

        if (
            not isinstance(
                sensitive_value,
                str,
            )
            or not sensitive_value
        ):
            raise ImageRedactionError(
                "Invalid sensitive entity value."
            )

        mapped_regions = map_entity_to_regions(
            original_result.regions,
            entity_start,
            entity_end,
        )

        all_regions.extend(
            mapped_regions
        )

        original_sensitive_values.append(
            sensitive_value
        )

    # Deduplicate overlapping references to the same OCR region.
    unique_regions: list[OCRRegion] = []

    seen: set[
        tuple[str, int, int, int, int, int]
    ] = set()

    for region in all_regions:

        key = (
            region.text,
            region.left,
            region.top,
            region.width,
            region.height,
            region.line_id,
        )

        if key in seen:
            continue

        seen.add(key)

        unique_regions.append(
            region
        )

    result = redact_image_regions(
        image_bytes,
        unique_regions,
    )

    verify_redacted_image_bytes(
        result.redacted_bytes,
        original_sensitive_values,
    )

    return result