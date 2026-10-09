from __future__ import annotations

from collections.abc import Iterable, Mapping

import fitz

from extraction.extraction import extract_text


class RedactionError(RuntimeError):
    """Raised when a PDF cannot be safely redacted and verified."""


def _unique_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if not isinstance(value, str):
            continue
        if not value:
            continue
        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def redact_pdf(
    file_bytes: bytes,
    entities_by_page: Mapping[int, Iterable[str]],
    metadata_entities: Iterable[dict] = (),
) -> bytes:
    """
    Safely redact sensitive PDF text fully in memory.

    Security proof scope:
    apply_redactions()
    + scrub() best-effort sanitization
    + tobytes(garbage=4, incremental=False)
    + re-extraction
    + confirmation that original sensitive strings are absent

    This verifies that the sensitive data is not recoverable through
    Guardian's own text-layer extraction method. It is NOT an absolute
    forensic guarantee against every possible recovery technique.
    """

    if not isinstance(
        file_bytes,
        (bytes, bytearray, memoryview),
    ):
        raise RedactionError(
            "PDF input must be bytes-like data."
        )

    if not file_bytes:
        raise RedactionError(
            "PDF input is empty."
        )

    metadata_entities = list(metadata_entities)
    if not entities_by_page and not metadata_entities:
        raise RedactionError(
            "No redaction targets were supplied for a REDACT decision."
        )

    doc: fitz.Document | None = None

    try:
        try:
            doc = fitz.open(
                stream=bytes(file_bytes),
                filetype="pdf",
            )
        except Exception as exc:
            raise RedactionError(
                "Could not open PDF for redaction."
            ) from exc

        if doc.needs_pass:
            raise RedactionError(
                "Password-protected PDF cannot be redacted safely."
            )

        total_redactions = 0

        for page_number, raw_entities in entities_by_page.items():

            if not isinstance(page_number, int):
                raise RedactionError(
                    "Invalid page number in redaction targets."
                )

            if page_number < 0 or page_number >= len(doc):
                raise RedactionError(
                    "Redaction target references a non-existent PDF page."
                )

            page = doc[page_number]

            for entity_text in _unique_strings(raw_entities):

                try:
                    rects = page.search_for(
                        entity_text
                    )
                except Exception as exc:
                    raise RedactionError(
                        f"Could not locate a detected entity on "
                        f"PDF page {page_number + 1}."
                    ) from exc

                # Scanner found the entity but PDF search could not locate it.
                # Never silently skip this case.
                if not rects:
                    raise RedactionError(
                        f"Redaction target could not be located on "
                        f"PDF page {page_number + 1}."
                    )

                for rect in rects:

                    try:
                        # TRUE PDF REDACTION.
                        # This removes the underlying text when
                        # apply_redactions() is executed.
                        page.add_redact_annot(
                            rect,
                            fill=(0, 0, 0),
                        )
                    except Exception as exc:
                        raise RedactionError(
                            f"Could not create a redaction annotation on "
                            f"PDF page {page_number + 1}."
                        ) from exc

                    total_redactions += 1

        if total_redactions == 0 and not metadata_entities:
            raise RedactionError(
                "No PDF redactions were created."
            )

        # Apply the actual redactions to every page.
        for page in doc:

            try:
                page.apply_redactions(
                    images=0,
                    graphics=0,
                    text=0,
                )
            except Exception as exc:
                raise RedactionError(
                    "Could not apply PDF redactions."
                ) from exc

        # Selectively redact only scanned fields/spans in the standard info
        # dictionary; retain unrelated metadata fields.
        allowed_metadata_fields = {
            "title", "author", "subject", "keywords", "creator", "producer",
        }
        metadata_groups: dict[str, list[dict]] = {}
        for entity in metadata_entities:
            field = entity.get("metadata_field")
            if field not in allowed_metadata_fields:
                raise RedactionError("Unsupported PDF metadata redaction field.")
            metadata_groups.setdefault(field, []).append(entity)
        if metadata_groups:
            metadata = doc.metadata or {}
            preserved = {
                field: str(metadata.get(field) or "")
                for field in (
                    "title", "author", "subject", "keywords", "creator", "producer",
                    "creationDate", "modDate", "trapped",
                )
            }
            for field, field_entities in metadata_groups.items():
                value = preserved[field]
                spans: list[tuple[int, int, str]] = []
                for entity in field_entities:
                    entity_text = entity.get("text")
                    start, end = entity.get("start"), entity.get("end")
                    if (
                        not isinstance(entity_text, str) or not entity_text
                        or not isinstance(start, int) or not isinstance(end, int)
                        or start < 0 or end <= start or end > len(value)
                        or value[start:end] != entity_text
                    ):
                        raise RedactionError("PDF metadata span did not match the inspected property value.")
                    spans.append((start, end, entity_text))
                for start, end, _text in sorted(spans, reverse=True):
                    value = value[:start] + "[REDACTED]" + value[end:]
                preserved[field] = value
            try:
                doc.set_metadata(preserved)
            except Exception as exc:
                raise RedactionError("Could not selectively sanitize PDF metadata.") from exc

        # Best-effort sanitization of known hidden-content vectors.
        # This is NOT treated as an absolute forensic guarantee.
        try:
            doc.scrub(
                attached_files=True,
                clean_pages=True,
                embedded_files=True,
                hidden_text=True,
                javascript=True,
                metadata=False,
                redactions=True,
                redact_images=0,
                remove_links=True,
                reset_fields=True,
                reset_responses=True,
                thumbnails=True,
                xml_metadata=False,
            )
        except Exception as exc:
            raise RedactionError(
                "Could not sanitize the redacted PDF."
            ) from exc

        # FULL REWRITE ONLY.
        # garbage=4 performs maximum unreferenced-object cleanup.
        # incremental=False explicitly prevents incremental saving.
        redacted_bytes = doc.tobytes(
            garbage=4,
            incremental=False,
        )

    except RedactionError:
        raise

    except Exception as exc:
        raise RedactionError(
            "PDF redaction failed unexpectedly."
        ) from exc

    finally:
        if doc is not None:
            doc.close()

    # --------------------------------------------------
    # MANDATORY POST-REDACTION VERIFICATION
    # --------------------------------------------------

    try:
        verification_text = extract_text(
            redacted_bytes,
            "redacted_verification.pdf",
        )
    except Exception as exc:
        raise RedactionError(
            "Could not verify the generated redacted PDF."
        ) from exc

    all_entities = _unique_strings(
        [
            entity_text
            for page_entities in entities_by_page.values()
            for entity_text in page_entities
        ] + [
            entity.get("text", "") for entity in metadata_entities
            if isinstance(entity, dict)
        ]
    )

    for entity_text in all_entities:

        if entity_text in verification_text:
            raise RedactionError(
                "Post-redaction verification found an original sensitive value."
            )

    try:
        verification_doc = fitz.open(stream=redacted_bytes, filetype="pdf")
        try:
            metadata_values = verification_doc.metadata or {}
            verification_metadata = "\n".join(str(metadata_values.get(field) or "") for field in (
                "title", "author", "subject", "keywords", "creator", "producer",
            ))
        finally:
            verification_doc.close()
    except Exception as exc:
        raise RedactionError("Could not verify the generated PDF metadata.") from exc
    for entity_text in all_entities:
        if entity_text in verification_metadata:
            raise RedactionError("Post-redaction verification found an original sensitive metadata value.")

    return redacted_bytes
