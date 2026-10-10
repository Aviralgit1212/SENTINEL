"""Fail-closed limits for extracted and submitted text.

Never truncate security-sensitive input before analysis: doing so can silently
exclude the tail of a document from inspection while presenting the result as
complete. Callers must reject over-limit inputs instead.
"""

from __future__ import annotations


class TextLimitExceeded(ValueError):
    """Raised when complete text exceeds the configured inspection budget."""


def enforce_text_limit(text: str, max_chars: int, *, field: str = "text") -> str:
    if not isinstance(text, str):
        raise TypeError(f"{field} must be text")
    if max_chars < 0:
        raise ValueError("max_chars must be non-negative")
    if len(text) > max_chars:
        raise TextLimitExceeded(
            f"{field} exceeds the {max_chars:,}-character inspection limit; "
            "the content was not truncated or partially scanned."
        )
    return text
