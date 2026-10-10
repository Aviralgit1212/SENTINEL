from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

import fitz

from extraction import extract_text


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


def _find_entity_rects_on_page(page: fitz.Page, entity_text: str) -> list[fitz.Rect]:
    """
    Locate bounding rectangles for an entity on a PDF page with progressive fallbacks:
    1. Direct search
    2. Stripped whitespace
    3. Normalized internal whitespace
    4. Text dehyphenation flag
    5. Punctuation-stripped match
    6. Multiline / line-by-line search
    7. Word sequence matching via page.get_text('words')
    8. Hyphenated word break across lines
    9. Individual words for multi-word phrases
    """
    if not entity_text or not isinstance(entity_text, str):
        return []

    # 1. Direct search
    try:
        rects = page.search_for(entity_text)
        if rects:
            return rects
    except Exception:
        pass

    # 2. Stripped whitespace
    stripped = entity_text.strip()
    if stripped and stripped != entity_text:
        try:
            rects = page.search_for(stripped)
            if rects:
                return rects
        except Exception:
            pass

    # 3. Normalized internal whitespace
    normalized = " ".join(entity_text.split())
    if normalized and normalized != entity_text and normalized != stripped:
        try:
            rects = page.search_for(normalized)
            if rects:
                return rects
        except Exception:
            pass

    # 4. Search with TEXT_DEHYPHENATE flag
    try:
        rects = page.search_for(stripped or entity_text, flags=fitz.TEXT_DEHYPHENATE)
        if rects:
            return rects
    except Exception:
        pass

    # 5. Punctuation-stripped match (e.g., trailing periods or commas)
    punct_stripped = (stripped or entity_text).strip(".,;:!?()[]{}'\"")
    if punct_stripped and punct_stripped != stripped:
        try:
            rects = page.search_for(punct_stripped)
            if rects:
                return rects
        except Exception:
            pass

    # 6. Multiline / line-by-line search
    lines = [line.strip() for line in (stripped or entity_text).splitlines() if line.strip()]
    if len(lines) > 1:
        line_rects: list[fitz.Rect] = []
        for line in lines:
            sub_rects = _find_entity_rects_on_page(page, line)
            if sub_rects:
                line_rects.extend(sub_rects)
        if line_rects:
            return line_rects

    # 7. Word sequence matching via page.get_text('words')
    clean = stripped or entity_text
    words = [w.strip() for w in re.split(r"\s+", clean) if w.strip()]
    if words:
        try:
            page_words = page.get_text("words")  # (x0, y0, x1, y1, word, block, line, word_idx)
            n = len(words)

            # Exact word sequence match
            seq_rects: list[fitz.Rect] = []
            for i in range(len(page_words) - n + 1):
                match = True
                for j in range(n):
                    pw = page_words[i + j][4].rstrip(".,;:!?")
                    ew = words[j].rstrip(".,;:!?")
                    if pw.lower() != ew.lower():
                        match = False
                        break
                if match:
                    for j in range(n):
                        w = page_words[i + j]
                        seq_rects.append(fitz.Rect(w[0], w[1], w[2], w[3]))
            if seq_rects:
                return seq_rects

            # Hyphenated word break across lines (e.g., 'tele-' and 'phone' vs 'telephone')
            for i in range(len(page_words) - 1):
                pw1 = page_words[i][4]
                pw2 = page_words[i + 1][4]
                if pw1.endswith("-"):
                    joined = (pw1[:-1] + pw2).rstrip(".,;:!?")
                    if joined.lower() == clean.rstrip(".,;:!?").lower():
                        w1 = page_words[i]
                        w2 = page_words[i + 1]
                        return [
                            fitz.Rect(w1[0], w1[1], w1[2], w1[3]),
                            fitz.Rect(w2[0], w2[1], w2[2], w2[3]),
                        ]

            # If multi-word entity, search individual significant words
            if len(words) > 1:
                all_word_rects: list[fitz.Rect] = []
                for w in words:
                    clean_w = w.strip(".,;:!?()[]{}'\"")
                    if len(clean_w) >= 2:
                        try:
                            wr = page.search_for(clean_w)
                            if wr:
                                all_word_rects.extend(wr)
                        except Exception:
                            pass
                if all_word_rects:
                    return all_word_rects
        except Exception:
            pass

    return []


def redact_pdf(
    file_bytes: bytes,
    entities_by_page: Mapping[int, Iterable[str]],
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

    if not entities_by_page:
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

        all_entities = _unique_strings(
            entity_text
            for page_entities in entities_by_page.values()
            for entity_text in page_entities
        )

        total_redactions = 0

        # Primary pass: locate and redact targets on requested pages
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

                rects = _find_entity_rects_on_page(page, entity_text)

                # Fallback: if not found on specified page, check if entity appears on any other page
                if not rects:
                    for p_idx, other_page in enumerate(doc):
                        if p_idx == page_number:
                            continue
                        alt_rects = _find_entity_rects_on_page(other_page, entity_text)
                        if alt_rects:
                            for rect in alt_rects:
                                other_page.add_redact_annot(rect, fill=(0, 0, 0))
                                total_redactions += 1
                            rects = alt_rects

                # Scanner found the entity but PDF search could not locate it anywhere in the doc.
                # Never silently skip this case.
                if not rects:
                    raise RedactionError(
                        f"Redaction target could not be located on "
                        f"PDF page {page_number + 1}."
                    )

                for rect in rects:
                    try:
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

        # Global sanitization pass: scrub all occurrences of every sensitive entity across ALL pages
        # This prevents post-redaction verification residue failures where the same sensitive target
        # was also present on another page of the document.
        for entity_text in all_entities:
            for other_page in doc:
                extra_rects = _find_entity_rects_on_page(other_page, entity_text)
                for rect in extra_rects:
                    try:
                        other_page.add_redact_annot(rect, fill=(0, 0, 0))
                        total_redactions += 1
                    except Exception:
                        pass

        if total_redactions == 0:
            raise RedactionError(
                "No PDF redactions were created."
            )

        # Apply the actual redactions to every page.
        for page in doc:

            try:
                page.apply_redactions(
                    images=2,
                    graphics=1,
                    text=0,
                )
            except Exception as exc:
                raise RedactionError(
                    "Could not apply PDF redactions."
                ) from exc

        # Best-effort sanitization of known hidden-content vectors.
        # This is NOT treated as an absolute forensic guarantee.
        try:
            doc.scrub(
                attached_files=True,
                clean_pages=True,
                embedded_files=True,
                hidden_text=True,
                javascript=True,
                metadata=True,
                redactions=True,
                redact_images=0,
                remove_links=True,
                reset_fields=True,
                reset_responses=True,
                thumbnails=True,
                xml_metadata=True,
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

    for entity_text in all_entities:
        target = entity_text.strip()
        if not target:
            continue

        if target in verification_text:
            # Word boundary check for short tokens (<= 3 characters) to prevent false substring collisions
            # like 'US' matching inside 'CUSTOMER'
            if len(target) <= 3:
                if re.search(r"\b" + re.escape(target) + r"\b", verification_text):
                    raise RedactionError(
                        "Post-redaction verification found an original sensitive value."
                    )
            else:
                raise RedactionError(
                    "Post-redaction verification found an original sensitive value."
                )

    return redacted_bytes