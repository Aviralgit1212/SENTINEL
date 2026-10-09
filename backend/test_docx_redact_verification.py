from __future__ import annotations

import io

from docx import Document

from redact.docx_redact import (
    DocxRedactionError,
    ParagraphRedactionTarget,
    iter_addressable_paragraphs,
    redact_and_verify_document,
    redact_document_targets,
)


PHONE = "555-123-4567"


def build_test_document() -> bytes:
    document = Document()

    # --------------------------------------------------
    # BODY
    # --------------------------------------------------

    document.add_paragraph(
        f"Contact: {PHONE}"
    )

    # --------------------------------------------------
    # TABLE
    # --------------------------------------------------

    table = document.add_table(
        rows=1,
        cols=1,
    )

    table.cell(
        0,
        0,
    ).text = (
        f"Table contact: {PHONE}"
    )

    # --------------------------------------------------
    # HEADER
    # --------------------------------------------------

    section = document.sections[0]

    section.header.paragraphs[0].text = (
        f"Header contact: {PHONE}"
    )

    # --------------------------------------------------
    # FOOTER
    # --------------------------------------------------

    section.footer.paragraphs[0].text = (
        f"Footer contact: {PHONE}"
    )

    # --------------------------------------------------
    # SPLIT-RUN PHONE NUMBER
    # --------------------------------------------------

    split_paragraph = document.add_paragraph()

    split_paragraph.add_run(
        "Split contact: "
    )

    split_paragraph.add_run(
        "555-"
    )

    split_paragraph.add_run(
        "123-"
    )

    split_paragraph.add_run(
        "4567"
    )

    output = io.BytesIO()

    document.save(
        output
    )

    return output.getvalue()


def create_redaction_targets(
    document: Document,
) -> list[ParagraphRedactionTarget]:
    """
    Find every addressable paragraph containing the known test phone
    number and convert it into a redaction target.
    """

    targets: list[
        ParagraphRedactionTarget
    ] = []

    for item in iter_addressable_paragraphs(
        document
    ):
        paragraph_text = item.paragraph.text

        if PHONE not in paragraph_text:
            continue

        start = paragraph_text.index(
            PHONE
        )

        end = (
            start
            + len(PHONE)
        )

        targets.append(
            ParagraphRedactionTarget(
                address=item,
                entity_start=start,
                entity_end=end,
            )
        )

    return targets


def test_successful_reopen_and_verify() -> None:
    """
    Full successful verification path:

    DOCX
    → targets
    → actual redaction
    → serialize
    → reopen
    → re-extract
    → verify sensitive value absent
    """

    original_bytes = build_test_document()

    document = Document(
        io.BytesIO(
            original_bytes
        )
    )

    targets = create_redaction_targets(
        document
    )

    # Expected locations:
    # 1 body
    # 2 table
    # 3 header
    # 4 footer
    # 5 split-run paragraph
    assert len(targets) == 5

    applied = redact_document_targets(
        document,
        targets,
    )

    assert applied == 5

    redacted_bytes = redact_and_verify_document(
        document,
        [PHONE],
    )

    assert redacted_bytes

    assert redacted_bytes != original_bytes

    # Independently reopen the final generated DOCX.
    reopened = Document(
        io.BytesIO(
            redacted_bytes
        )
    )

    all_text: list[str] = []

    # Body.
    all_text.extend(
        paragraph.text
        for paragraph in reopened.paragraphs
    )

    # Tables.
    for table in reopened.tables:
        for row in table.rows:
            for cell in row.cells:
                all_text.extend(
                    paragraph.text
                    for paragraph in cell.paragraphs
                )

    # Headers / footers.
    for section in reopened.sections:
        all_text.extend(
            paragraph.text
            for paragraph in section.header.paragraphs
        )

        all_text.extend(
            paragraph.text
            for paragraph in section.footer.paragraphs
        )

    combined = "\n".join(
        all_text
    )

    assert PHONE not in combined


def test_verification_rejects_leftover_sensitive_value() -> None:
    """
    Verify the security boundary itself.

    A generated DOCX that still contains the sensitive value must fail
    verification rather than being accepted.
    """

    document = Document()

    document.add_paragraph(
        f"This still contains {PHONE}"
    )

    buffer = io.BytesIO()

    document.save(
        buffer
    )

    generated_bytes = buffer.getvalue()

    try:
        from redact.docx_redact import (
            verify_redacted_docx_bytes,
        )

        verify_redacted_docx_bytes(
            generated_bytes,
            [PHONE],
        )

    except DocxRedactionError:
        pass

    else:
        raise AssertionError(
            "Verification failed to detect a leftover sensitive value."
        )


def test_verification_handles_multiple_original_values() -> None:
    """
    Confirm verification checks every original sensitive value rather than
    stopping after the first one.
    """

    second_phone = "555-987-6543"

    document = Document()

    paragraph = document.add_paragraph(
        f"Values: {PHONE} and {second_phone}"
    )

    addressable = iter_addressable_paragraphs(
        document
    )

    body_item = next(
        item
        for item in addressable
        if item.source == "paragraph"
    )

    first_start = paragraph.text.index(
        PHONE
    )

    first_end = (
        first_start
        + len(PHONE)
    )

    second_start = paragraph.text.index(
        second_phone
    )

    second_end = (
        second_start
        + len(second_phone)
    )

    targets = [
        ParagraphRedactionTarget(
            address=body_item,
            entity_start=first_start,
            entity_end=first_end,
        ),
        ParagraphRedactionTarget(
            address=body_item,
            entity_start=second_start,
            entity_end=second_end,
        ),
    ]

    applied = redact_document_targets(
        document,
        targets,
    )

    assert applied == 2

    redacted_bytes = redact_and_verify_document(
        document,
        [
            PHONE,
            second_phone,
        ],
    )

    assert redacted_bytes


def main() -> None:
    test_successful_reopen_and_verify()

    print(
        "6.3.4 reopen + re-extraction verification: PASS"
    )

    test_verification_rejects_leftover_sensitive_value()

    print(
        "6.3.4 fail-closed verification failure: PASS"
    )

    test_verification_handles_multiple_original_values()

    print(
        "6.3.4 multiple sensitive values verification: PASS"
    )


if __name__ == "__main__":
    main()