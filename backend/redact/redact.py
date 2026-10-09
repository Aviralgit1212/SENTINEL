class Redactor:
    """
    Replaces sensitive entities in text with redaction placeholders.
    """

    def redact(self, text: str, flagged_entities: list[dict]) -> str:
        """
        Return a new string with each flagged entity replaced by
        [REDACTED_<ENTITY_TYPE>].
        """

        # Replace entities from right to left.
        # If we replace something near the beginning first, the text
        # becomes shorter and every position after it shifts left.
        # That would make the original start/end positions incorrect
        # for later replacements.
        sorted_entities = sorted(
            flagged_entities,
            key=lambda entity: entity["start"],
            reverse=True,
        )

        redacted_text = text

        for entity in sorted_entities:
            start = entity["start"]
            end = entity["end"]
            entity_type = entity["entity_type"]

            placeholder = f"[REDACTED_{entity_type}]"

            redacted_text = (
                redacted_text[:start]
                + placeholder
                + redacted_text[end:]
            )

        return redacted_text