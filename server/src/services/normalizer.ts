/**
 * SENTINEL Sovereign Core — Unicode & Bidi Sanitization Armor
 * 
 * Protects against:
 * 1. Zero-width character smuggling (\u200B, \u200C, \u200D, \u2060, \uFEFF)
 * 2. Bidirectional text override attacks (Right-to-Left Override \u202E, etc.)
 * 3. Unicode Tag characters (\u{E0001}-\u{E007F} block used in invisible LLM prompt injection)
 * 4. Homoglyph and confusable normalization (NFKC)
 */

export const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g
export const BIDI_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069]/g
export const UNICODE_TAG_REGEX = /[\u{E0001}-\u{E007F}]/gu

export interface NormalizationResult {
  cleanedText: string
  hasZeroWidth: boolean
  zeroWidthCount: number
  hasBidiOverride: boolean
  bidiCount: number
  hasUnicodeTags: boolean
  tagCount: number
  isAltered: boolean
}

export function sanitizeUnicode(rawText: string): NormalizationResult {
  if (!rawText) {
    return {
      cleanedText: '',
      hasZeroWidth: false,
      zeroWidthCount: 0,
      hasBidiOverride: false,
      bidiCount: 0,
      hasUnicodeTags: false,
      tagCount: 0,
      isAltered: false,
    }
  }

  const zeroWidthMatches = rawText.match(ZERO_WIDTH_REGEX)
  const bidiMatches = rawText.match(BIDI_OVERRIDE_REGEX)
  const tagMatches = rawText.match(UNICODE_TAG_REGEX)

  const zeroWidthCount = zeroWidthMatches ? zeroWidthMatches.length : 0
  const bidiCount = bidiMatches ? bidiMatches.length : 0
  const tagCount = tagMatches ? tagMatches.length : 0

  // Strip dangerous invisible / control tokens and apply NFKC canonical normalization
  let cleaned = rawText
    .replace(ZERO_WIDTH_REGEX, '')
    .replace(BIDI_OVERRIDE_REGEX, '')
    .replace(UNICODE_TAG_REGEX, '')
    .normalize('NFKC')

  return {
    cleanedText: cleaned,
    hasZeroWidth: zeroWidthCount > 0,
    zeroWidthCount,
    hasBidiOverride: bidiCount > 0,
    bidiCount,
    hasUnicodeTags: tagCount > 0,
    tagCount,
    isAltered: zeroWidthCount > 0 || bidiCount > 0 || tagCount > 0,
  }
}
