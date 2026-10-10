from __future__ import annotations

import io
from dataclasses import dataclass

import pytesseract
from PIL import Image, UnidentifiedImageError
from pytesseract import Output


@dataclass(frozen=True)
class OCRRegion:
    """
    One OCR-recognized word and its image-space location.

    These regions are internal positional metadata.
    Only full_text will be consumed by Scanner.
    """

    text: str
    left: int
    top: int
    width: int
    height: int
    confidence: float
    line_id: int


@dataclass(frozen=True)
class ImageOCRResult:
    """
    Result of one OCR pass over an image.

    full_text:
        Plain OCR text in reading order.

    regions:
        Positional OCR metadata corresponding to words in full_text.
    """

    full_text: str
    regions: list[OCRRegion]


def _build_line_id_map(
    data: dict[str, list],
) -> dict[tuple[int, int, int], int]:
    """
    Convert Tesseract's block/paragraph/line identifiers into
    compact sequential line IDs.
    """

    line_id_map: dict[
        tuple[int, int, int],
        int,
    ] = {}

    next_line_id = 0

    total = len(data["text"])

    for index in range(total):
        raw_text = str(
            data["text"][index]
        ).strip()

        if not raw_text:
            continue

        block_num = int(
            data["block_num"][index]
        )

        par_num = int(
            data["par_num"][index]
        )

        line_num = int(
            data["line_num"][index]
        )

        key = (
            block_num,
            par_num,
            line_num,
        )

        if key not in line_id_map:
            line_id_map[key] = next_line_id
            next_line_id += 1

    return line_id_map


def _extract_regions(
    data: dict[str, list],
) -> list[OCRRegion]:
    """
    Convert Tesseract image_to_data output into OCRRegion objects.

    Empty OCR tokens are ignored.
    Reading order remains Tesseract's supplied order.
    """

    regions: list[OCRRegion] = []

    line_id_map = _build_line_id_map(
        data
    )

    total = len(data["text"])

    for index in range(total):
        word = str(
            data["text"][index]
        ).strip()

        if not word:
            continue

        block_num = int(
            data["block_num"][index]
        )

        par_num = int(
            data["par_num"][index]
        )

        line_num = int(
            data["line_num"][index]
        )

        line_id = line_id_map[
            (
                block_num,
                par_num,
                line_num,
            )
        ]

        try:
            confidence = float(
                data["conf"][index]
            )
        except (
            ValueError,
            TypeError,
        ):
            confidence = -1.0

        regions.append(
            OCRRegion(
                text=word,
                left=int(
                    data["left"][index]
                ),
                top=int(
                    data["top"][index]
                ),
                width=int(
                    data["width"][index]
                ),
                height=int(
                    data["height"][index]
                ),
                confidence=confidence,
                line_id=line_id,
            )
        )

    return regions


def _build_full_text(
    regions: list[OCRRegion],
) -> str:
    """
    Build deterministic OCR text from OCR regions.

    Words on the same OCR line are separated by one space.
    A new OCR line becomes a newline.

    This deterministic construction is important because later
    redaction logic will map Scanner character spans back to
    these regions.
    """

    if not regions:
        return ""

    lines: list[list[OCRRegion]] = []

    current_line_id = regions[0].line_id
    current_line: list[OCRRegion] = []

    for region in regions:
        if region.line_id != current_line_id:
            lines.append(
                current_line
            )

            current_line = []
            current_line_id = region.line_id

        current_line.append(region)

    if current_line:
        lines.append(
            current_line
        )

    line_texts: list[str] = []

    for line in lines:
        line_texts.append(
            " ".join(
                region.text
                for region in line
            )
        )

    return "\n".join(line_texts)


def extract_image(
    image_bytes: bytes,
) -> ImageOCRResult:
    """
    Extract text and positional OCR regions from image bytes.

    Supported image formats are whatever Pillow/Tesseract can decode;
    the initial Guardian scope is PNG/JPG/JPEG.

    Processing is entirely in memory.

    Returns:
        ImageOCRResult containing:
            - full_text
            - OCR regions with coordinates/confidence

    Raises:
        ValueError:
            If the image is empty, corrupted, unreadable, or OCR
            cannot be initialized correctly.
    """

    if not image_bytes:
        raise ValueError(
            "Image file is empty."
        )

    try:
        with Image.open(
            io.BytesIO(image_bytes)
        ) as image:
            image.load()

            try:
                data = pytesseract.image_to_data(
                    image,
                    lang="eng",
                    config="--psm 6",
                    output_type=Output.DICT,
                )
            except pytesseract.TesseractNotFoundError as exc:
                raise ValueError(
                    "Tesseract OCR engine is not available."
                ) from exc

            except pytesseract.TesseractError as exc:
                raise ValueError(
                    "Tesseract OCR failed."
                ) from exc

    except UnidentifiedImageError as exc:
        raise ValueError(
            "Corrupted or unreadable image file."
        ) from exc

    except OSError as exc:
        raise ValueError(
            "Corrupted or unreadable image file."
        ) from exc

    regions = _extract_regions(
        data
    )

    full_text = _build_full_text(
        regions
    )

    return ImageOCRResult(
        full_text=full_text,
        regions=regions,
    )