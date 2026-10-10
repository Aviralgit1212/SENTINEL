import type { Verdict } from '../types.js'

export type PrivacyDecision = 'ALLOW' | 'REDACT' | 'BLOCK' | 'UNKNOWN'

// A privacy decision is not interchangeable with a successful scan. In
// particular, BLOCK must never be persisted as allow, and REDACT is not safe
// to release until a verified derivative has actually been produced.
export function privacyDecisionToVerdict(decision: PrivacyDecision): Verdict {
  switch (decision) {
    case 'ALLOW': return 'allow'
    case 'BLOCK': return 'block'
    case 'REDACT': return 'review_required'
    case 'UNKNOWN': return 'review_required'
  }
}

export function privacyDecisionReason(decision: PrivacyDecision): string {
  switch (decision) {
    case 'ALLOW': return 'Privacy assessment allows the content.'
    case 'BLOCK': return 'Privacy assessment blocks the content.'
    case 'REDACT': return 'Privacy assessment requires redaction; no verified redacted derivative has been released.'
    case 'UNKNOWN': return 'Privacy assessment is inconclusive; manual review is required.'
  }
}

