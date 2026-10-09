from __future__ import annotations

from extraction.image_ocr import OCRRegion
from redact.image_mapping import (
    build_region_spans,
    map_entity_text_to_regions,
    map_entity_to_regions,
)


def make_region(
    text: str,
    line_id: int,
) -> OCRRegion:
    return OCRRegion(
        text=text,
        left=10,
        top=10,
        width=max(1, len(text) * 10),
        height=20,
        confidence=95.0,
        line_id=line_id,
    )


def test_single_region_mapping() -> None:
    regions = [
        make_region("Customer", 0),
        make_region("Phone:", 0),
        make_region("555-123-4567", 0),
    ]

    full_text = (
        "Customer Phone: 555-123-4567"
    )

    matches = map_entity_text_to_regions(
        full_text,
        regions,
        "555-123-4567",
    )

    assert len(matches) == 1
    assert matches[0].text == "555-123-4567"

    print(
        "6.4.3 single-region mapping: PASS"
    )


def test_split_region_mapping() -> None:
    regions = [
        make_region("Phone:", 0),
        make_region("555-123-", 0),
        make_region("4567", 0),
    ]

    full_text = (
        "Phone: 555-123-4567"
    )

    start = full_text.index(
        "555-123-4567"
    )

    end = start + len(
        "555-123-4567"
    )

    matches = map_entity_to_regions(
        regions,
        start,
        end,
    )

    assert [
        region.text
        for region in matches
    ] == [
        "555-123-",
        "4567",
    ]

    print(
        "6.4.3 split-region mapping: PASS"
    )


def test_multi_line_mapping() -> None:
    regions = [
        make_region("Reference:", 0),
        make_region("555-", 0),
        make_region("1234", 1),
    ]

    full_text = (
        "Reference: 555-\n1234"
    )

    start = full_text.index(
        "555-"
    )

    end = start + len(
        "555-\n1234"
    )

    matches = map_entity_to_regions(
        regions,
        start,
        end,
    )

    assert [
        region.text
        for region in matches
    ] == [
        "555-",
        "1234",
    ]

    print(
        "6.4.3 multi-line mapping: PASS"
    )


def test_unrelated_regions_excluded() -> None:
    regions = [
        make_region("Email:", 0),
        make_region("person@example.com", 0),
        make_region("Phone:", 0),
        make_region("555-123-4567", 0),
        make_region("Status:", 1),
        make_region("CONFIDENTIAL", 1),
    ]

    full_text = (
        "Email: person@example.com "
        "Phone: 555-123-4567\n"
        "Status: CONFIDENTIAL"
    )

    matches = map_entity_text_to_regions(
        full_text,
        regions,
        "555-123-4567",
    )

    assert [
        region.text
        for region in matches
    ] == [
        "555-123-4567",
    ]

    print(
        "6.4.3 unrelated-region exclusion: PASS"
    )


def test_invalid_span_rejected() -> None:
    regions = [
        make_region("555-123-4567", 0),
    ]

    try:
        map_entity_to_regions(
            regions,
            5,
            5,
        )
    except ValueError:
        print(
            "6.4.3 invalid-span handling: PASS"
        )
        return

    raise AssertionError(
        "Empty entity span was not rejected."
    )


def test_region_spans_are_deterministic() -> None:
    regions = [
        make_region("Customer", 0),
        make_region("Phone:", 0),
        make_region("555-123-4567", 0),
        make_region("Account:", 1),
        make_region("CONFIDENTIAL", 1),
    ]

    spans = build_region_spans(
        regions
    )

    assert [
        (
            span.region.text,
            span.start,
            span.end,
        )
        for span in spans
    ] == [
        ("Customer", 0, 8),
        ("Phone:", 9, 15),
        ("555-123-4567", 16, 28),
        ("Account:", 29, 37),
        ("CONFIDENTIAL", 38, 50),
    ]

    print(
        "6.4.3 deterministic character mapping: PASS"
    )


def main() -> None:
    test_single_region_mapping()
    test_split_region_mapping()
    test_multi_line_mapping()
    test_unrelated_regions_excluded()
    test_invalid_span_rejected()
    test_region_spans_are_deterministic()

    print(
        "6.4.3 IMAGE ENTITY-TO-BOX MAPPING: PASS"
    )


if __name__ == "__main__":
    main()