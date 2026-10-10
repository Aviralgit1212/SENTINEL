/**
 * SENTINEL Sovereign Core — Differential Parsing & Disagreement Engine
 * 
 * Compares multi-view representations of artifacts:
 * 1. High-Level DOM AST (PyMuPDF / python-docx text runs)
 * 2. Visual Rendering + OCR Coordinates
 * 3. Low-Level Stream Inventory
 * 
 * Flags:
 * - Micro-text stealth injections (< 2.5pt)
 * - Low-contrast / background-matching text (delta-E contrast)
 * - Off-canvas coordinates
 * - Prompt injection signatures hiding in visual dark zones
 */

import { randomUUID } from 'node:crypto'
import type { Finding } from '../types.js'
import type { SIREntity, SIRGraph } from './sir.js'

export const PROMPT_INJECTION_PATTERNS = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b/i,
  /\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b/i,
  /\bforget\s+(?:all\s+)?previous\s+instructions\b/i,
  /\boverride\s+(?:the\s+)?system\s+instructions\b/i,
  /\bnew\s+instructions?\s*:/i,
  /\bsystem\s+message\s*:/i,
  /\bdeveloper\s+message\s*:/i,
  /\bassistant\s+instructions?\s*:/i,
  /\bdo\s+not\s+tell\s+the\s+user\b/i,
  /\bprint\s+(?:the\s+)?(?:system\s+prompt|credentials|api\s+key)\b/i,
  /\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|jailbroken|administrator)\b/i,
]

export interface DifferentialPerceptionResult {
  hasDisagreement: boolean
  hasPhantomInjection: boolean
  findings: Finding[]
}

export function evaluateDifferentialPerception(sir: SIRGraph): DifferentialPerceptionResult {
  const findings: Finding[] = []
  let hasPhantomInjection = false
  let hasStructuralVisualDisagreement = false

  for (const entity of Object.values(sir.entities)) {
    if (entity.nodeType !== 'run' && entity.nodeType !== 'paragraph') continue

    const text = entity.normalizedText || entity.rawText || ''
    if (!text.trim()) continue

    const attrs = entity.attributes || {}
    const loc = entity.structuralLocation || {}

    // Signal 1: Micro-font size (< 2.5pt)
    const isMicroFont = typeof attrs.fontSizePt === 'number' && attrs.fontSizePt > 0 && attrs.fontSizePt <= 2.5

    // Signal 2: Invisible / Background-matched Contrast
    const isLowContrast = typeof attrs.contrastDeltaE === 'number' && attrs.contrastDeltaE < 1.15

    // Signal 3: Hidden Style (e.g. <w:vanish/> in Word)
    const isHiddenStyle = Boolean(attrs.isHiddenStyle)

    // Signal 4: Off-Canvas Coordinates (e.g. bbox outside visible viewport)
    let isOffCanvas = false
    if (loc.bbox) {
      const [x0, y0, x1, y1] = loc.bbox
      if (x0 < 0 || y0 < 0 || x1 > 2000 || y1 > 2000) {
        isOffCanvas = true
      }
    }

    // Signal 5: Excessive Zero-Width Characters or Bidi Overrides
    const hasUnicodeSmuggling = (attrs.zeroWidthCount || 0) > 3 || (attrs.bidiOverrideCount || 0) > 0

    const isVisuallyStealthy = isMicroFont || isLowContrast || isHiddenStyle || isOffCanvas || hasUnicodeSmuggling
    if (isVisuallyStealthy) hasStructuralVisualDisagreement = true

    // Check for semantic prompt injection patterns
    const matchesPromptInjection = PROMPT_INJECTION_PATTERNS.some((regex) => regex.test(text))

    if (matchesPromptInjection && isVisuallyStealthy) {
      hasPhantomInjection = true
      findings.push({
        id: randomUUID(),
        module: 'content_integrity',
        category: 'phantom_prompt_injection',
        title: 'Stealth AI Prompt Injection Detected',
        description: `Visually invisible text contains instructions targeting AI models (${[
          isMicroFont ? `micro-font: ${attrs.fontSizePt}pt` : null,
          isLowContrast ? 'low contrast ratio' : null,
          isHiddenStyle ? 'hidden document style' : null,
          isOffCanvas ? 'off-canvas location' : null,
          hasUnicodeSmuggling ? 'unicode smuggling' : null,
        ].filter(Boolean).join(', ')}).`,
        severity: 'high',
        source: 'differential-perception-engine',
        location: loc.partPath ? `${loc.partPath} (p.${loc.page ?? 1})` : `Page ${loc.page ?? 1}`,
        evidence: text.slice(0, 200),
      })
    } else if (matchesPromptInjection) {
      findings.push({
        id: randomUUID(),
        module: 'content_integrity',
        category: 'prompt_injection_text',
        title: 'AI Prompt Injection Pattern Detected',
        description: 'Text in document contains instructions attempting to override LLM system prompts.',
        severity: 'medium',
        source: 'prompt-injection-catalog',
        location: loc.partPath || `Page ${loc.page ?? 1}`,
        evidence: text.slice(0, 200),
      })
    } else if (isVisuallyStealthy && text.length > 20) {
      findings.push({
        id: randomUUID(),
        module: 'content_integrity',
        category: 'hidden_content_anomaly',
        title: 'Hidden Document Content Detected',
        description: `Document contains text hidden from standard visual readers (${[
          isMicroFont ? `font size ${attrs.fontSizePt}pt` : null,
          isHiddenStyle ? 'vanish tag' : null,
          isOffCanvas ? 'off-canvas' : null,
        ].filter(Boolean).join(', ')}).`,
        severity: 'low',
        source: 'differential-perception-engine',
        location: loc.partPath || `Page ${loc.page ?? 1}`,
        evidence: text.slice(0, 160),
      })
    }
  }

  return {
    // A visible prompt-injection string is a content-risk finding, but does not
    // by itself prove disagreement between structural and visual representations.
    hasDisagreement: hasStructuralVisualDisagreement,
    hasPhantomInjection,
    findings,
  }
}
