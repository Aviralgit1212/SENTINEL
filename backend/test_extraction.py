from __future__ import annotations

import fitz

from extraction.extraction import extract_text


def _synthetic_text_pdf() -> bytes:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Synthetic contact: synthetic@example.test")
    content = document.tobytes()
    document.close()
    return content


def test_extract_selectable_text_from_synthetic_pdf() -> None:
    extracted = extract_text(_synthetic_text_pdf(), "synthetic.pdf")
    assert "synthetic@example.test" in extracted


def main() -> None:
    extracted = extract_text(_synthetic_text_pdf(), "synthetic.pdf")
    print("Synthetic PDF extraction:", "PASS" if "synthetic@example.test" in extracted else "FAIL")


if __name__ == "__main__":
    main()
