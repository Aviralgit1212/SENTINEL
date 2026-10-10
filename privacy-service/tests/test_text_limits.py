"""Fail-closed inspection-budget tests; intentionally dependency-light."""
import unittest

from limits import TextLimitExceeded, enforce_text_limit


class TextLimitTests(unittest.TestCase):
    def test_accepts_text_at_exact_limit_without_mutation(self):
        text = "x" * 32
        self.assertIs(enforce_text_limit(text, 32), text)

    def test_rejects_text_one_character_over_limit(self):
        with self.assertRaisesRegex(TextLimitExceeded, "not truncated or partially scanned"):
            enforce_text_limit("x" * 33, 32)

    def test_empty_text_is_valid(self):
        self.assertEqual(enforce_text_limit("", 0), "")

    def test_invalid_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            enforce_text_limit("x", -1)

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            enforce_text_limit(None, 32)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
