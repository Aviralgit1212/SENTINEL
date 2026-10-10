"""Focused redaction regression tests; does not require Presidio/NLP models."""
import io
import unittest

import fitz
from docx import Document

from extraction import extract_text
from redact.docx_redact import redact_docx
from redact.pdf_redact import RedactionError, redact_pdf


class RemediationIntegrityTests(unittest.TestCase):
    def test_docx_redaction_uses_offsets_and_removes_target(self):
        stream = io.BytesIO()
        document = Document()
        document.add_paragraph("Contact test@example.com today")
        document.save(stream)
        original = stream.getvalue()
        extracted = extract_text(original, "sample.docx")
        target = "test@example.com"
        start = extracted.index(target)

        redacted = redact_docx(original, [{
            "entity_type": "EMAIL_ADDRESS",
            "text": target,
            "start": start,
            "end": start + len(target),
        }])
        self.assertNotIn(target, extract_text(redacted, "redacted.docx"))
        self.assertGreater(len(redacted), 0)

    def test_pdf_redaction_removes_target_from_text_layer(self):
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Contact test@example.com today")
        original = doc.tobytes()
        doc.close()

        redacted = redact_pdf(original, {0: ["test@example.com"]})
        output = fitz.open(stream=redacted, filetype="pdf")
        try:
            self.assertNotIn("test@example.com", "\n".join(p.get_text() for p in output))
        finally:
            output.close()

    def test_pdf_redaction_fails_closed_for_wrong_page(self):
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Contact test@example.com today")
        original = doc.tobytes()
        doc.close()
        with self.assertRaises(RedactionError):
            redact_pdf(original, {1: ["test@example.com"]})

    def test_pdf_redaction_multiline_and_whitespace_on_page_3(self):
        doc = fitz.open()
        doc.new_page()  # Page 1
        doc.new_page()  # Page 2
        p3 = doc.new_page()  # Page 3
        p3.insert_text((72, 72), "Contact: John\nDoe, email: user@example.com.")
        original = doc.tobytes()
        doc.close()

        # Target multiline and trailing dot/spaces on page 3 (index 2)
        redacted = redact_pdf(original, {2: ["John\nDoe", " user@example.com. "]})
        self.assertGreater(len(redacted), 0)
        output = fitz.open(stream=redacted, filetype="pdf")
        try:
            full_text = "\n".join(p.get_text() for p in output)
            self.assertNotIn("user@example.com", full_text)
            self.assertNotIn("John", full_text)
            self.assertNotIn("Doe", full_text)
        finally:
            output.close()

    def test_pdf_redaction_cross_page_residue_elimination(self):
        # Sensitive email exists on Page 1 and Page 3, but targets only specified Page 3 (index 2)
        doc = fitz.open()
        p1 = doc.new_page()  # Page 1
        p1.insert_text((72, 72), "Confidential contact: secret@corp.org")
        doc.new_page()       # Page 2
        p3 = doc.new_page()  # Page 3
        p3.insert_text((72, 72), "Author: secret@corp.org")
        original = doc.tobytes()
        doc.close()

        # Caller only requests redaction of target on page 3
        redacted = redact_pdf(original, {2: ["secret@corp.org"]})
        self.assertGreater(len(redacted), 0)
        output = fitz.open(stream=redacted, filetype="pdf")
        try:
            full_text = "\n".join(p.get_text() for p in output)
            self.assertNotIn("secret@corp.org", full_text)
        finally:
            output.close()


if __name__ == "__main__":
    unittest.main()

