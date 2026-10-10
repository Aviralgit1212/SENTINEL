from __future__ import annotations

from dataclasses import dataclass

from extraction.image_ocr import OCRRegion


@dataclass(frozen=True)
class OCRRegionSpan:
    """OCR region plus its character span inside ImageOCRResult.full_text."""

    region: OCRRegion
    start: int
    end: int


def build_region_spans(
    regions: list[OCRRegion],
) -> list[OCRRegionSpan]:
    """
    Reconstruct the exact character spans used by image_ocr._build_full_text().

    Words on the same line are separated by one space.
    Different OCR lines are separated by one newline.
    """

    if not regions:
        return []

    spans: list[OCRRegionSpan] = []
    cursor = 0
    current_line_id = regions[0].line_id

    for index, region in enumerate(regions):
        if index > 0:
            if region.line_id != current_line_id:
                cursor += 1
                current_line_id = region.line_id
            else:
                cursor += 1

        start = cursor
        end = start + len(region.text)

        spans.append(
            OCRRegionSpan(
                region=region,
                start=start,
                end=end,
            )
        )

        cursor = end

    return spans


def map_entity_to_regions(
    regions: list[OCRRegion],
    entity_start: int,
    entity_end: int,
) -> list[OCRRegion]:
    """
    Map a Scanner/Policy character span to all overlapping OCR regions.

    The entity span uses the same half-open interval convention:
        [entity_start, entity_end)

    A region is selected when its character span overlaps the entity span.
    """

    if entity_start < 0:
        raise ValueError(
            "Entity start offset cannot be negative."
        )

    if entity_end <= entity_start:
        raise ValueError(
            "Entity span must be non-empty."
        )

    spans = build_region_spans(regions)

    if not spans:
        raise ValueError(
            "Cannot map an entity when OCR returned no regions."
        )

    matches: list[OCRRegion] = []

    for span in spans:
        overlaps = (
            span.start < entity_end
            and span.end > entity_start
        )

        if overlaps:
            matches.append(span.region)

    if not matches:
        raise ValueError(
            "Entity span could not be mapped to OCR regions."
        )

    return matches


def map_entity_text_to_regions(
    full_text: str,
    regions: list[OCRRegion],
    entity_text: str,
) -> list[OCRRegion]:
    """
    Convenience helper for tests and format-specific callers.

    Finds the first exact occurrence of entity_text in full_text and maps
    that character span to OCR regions.
    """

    if not entity_text:
        raise ValueError(
            "Entity text cannot be empty."
        )

    start = full_text.find(entity_text)

    if start == -1:
        raise ValueError(
            "Entity text was not found in OCR full_text."
        )

    end = start + len(entity_text)

    return map_entity_to_regions(
        regions,
        start,
        end,
    )