
from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _valid_verhoeff(value: str) -> bool:
    if not value or not value.isdigit():
        return False

    checksum = 0
    for index, char in enumerate(reversed(value)):
        checksum = _VERHOEFF_D[checksum][
            _VERHOEFF_P[index % 8][int(char)]
        ]

    return checksum == 0


def _normalize_ocr_digits(value: str) -> str:
    """Normalize common OCR confusions before validating Aadhaar candidates."""
    return value.translate(
        str.maketrans(
            {
                "O": "0",
                "Q": "0",
                "D": "0",
                "I": "1",
                "l": "1",
                "|": "1",
            }
        )
    )


class Scanner:
    """Presidio-backed scanner with custom Indian ID and credential patterns."""

    def __init__(self):
        self.analyzer = AnalyzerEngine()

        custom = [
            PatternRecognizer(
                supported_entity="IN_AADHAAR",
                patterns=[
                    Pattern(
                        "aadhaar_candidate",
                        r"(?<![A-Za-z0-9])[0-9OQDIil|](?:[ -]?[0-9OQDIil|]){11}(?![A-Za-z0-9])",
                        0.8,
                    )
                ],
            ),
            PatternRecognizer(
                supported_entity="IN_PAN",
                patterns=[
                    Pattern(
                        "pan_candidate",
                        r"(?i)(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])",
                        0.78,
                    )
                ],
            ),
            PatternRecognizer(
                supported_entity="IN_IFSC",
                patterns=[
                    Pattern(
                        "ifsc_candidate",
                        r"(?i)(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])",
                        0.78,
                    )
                ],
            ),
            PatternRecognizer(
                supported_entity="CREDENTIAL_TOKEN",
                patterns=[
                    Pattern(
                        "credential_token",
                        r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})(?![A-Za-z0-9])",
                        0.9,
                    )
                ],
            ),
        ]

        for recognizer in custom:
            self.analyzer.registry.add_recognizer(recognizer)

        self.entities_to_detect = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "PERSON",
            "IN_AADHAAR",
            "IN_PAN",
            "IN_IFSC",
            "CREDENTIAL_TOKEN",
        ]

    def scan(self, text: str) -> list[dict]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=self.entities_to_detect,
        )

        entities = []

        for result in results:
            value = text[result.start:result.end]

            if result.entity_type == "IN_AADHAAR":
                normalized = _normalize_ocr_digits(value)
                digits = "".join(
                    char for char in normalized if char.isdigit()
                )

                # Reject candidates that fail Aadhaar format/checksum validation.
                if (
                    len(digits) != 12
                    or digits[0] not in "23456789"
                    or not _valid_verhoeff(digits)
                ):
                    continue

            entities.append(
                {
                    "entity_type": result.entity_type,
                    "text": value,
                    "start": result.start,
                    "end": result.end,
                    "confidence": round(float(result.score), 4),
                    "detector": (
                        "presidio"
                        if result.entity_type
                        in {
                            "EMAIL_ADDRESS",
                            "PHONE_NUMBER",
                            "CREDIT_CARD",
                            "US_SSN",
                            "PERSON",
                        }
                        else "sentinel_pattern"
                    ),
                }
            )

        return entities
