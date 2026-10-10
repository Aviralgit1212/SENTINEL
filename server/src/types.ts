// SENTINEL Sovereign Core — Shared Result & Evidence Model
// Coverage-aware: a missing or failed check is never a clean result.

import type { SIRGraph } from './services/sir.js'
import type { CounterfactualPlan } from './services/counterfactual.js'

export type AnalyzerState =
  | 'completed_no_detections'
  | 'finding'
  | 'failed'
  | 'timed_out'
  | 'unavailable'
  | 'skipped_by_policy'
  | 'not_applicable'
  | 'inconclusive'

export interface Finding {
  id: string
  module: 'threat' | 'privacy' | 'content_integrity' | 'code'
  category: string
  title: string
  description: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  source: string // analyzer/rule identifier
  location?: string // page, part, line, etc.
  evidence?: string // bounded snippet
}

export interface AnalyzerCoverageEntry {
  analyzer: string
  state: AnalyzerState
  detail?: string
}

export type Verdict = 'block' | 'review_required' | 'allow_with_warnings' | 'allow'

export interface ThreatResult {
  antivirus: {
    engine: 'clamav'
    state: AnalyzerState
    detail: string
    threatName?: string
  }
  fileType: {
    declaredExtension: string | null
    detectedExtension: string | null
    detectedMime: string | null
    mismatch: boolean
  }
  pdf?: PdfFactsJson
  exe?: ExeFactsJson
  docx?: DocxFactsJson
  findings: Finding[]
}

export interface PdfFactsJson {
  supported: boolean
  pageCount: number
  javascriptCount: number
  embeddedFileCount: number
  annotationCount: number
  formFieldCount: number
  openAction: { present: boolean; type: string | null; target: string | null }
  urls: string[]
  error?: string
  hiddenText: Array<{ page: number; text: string; reasons: string[]; contentSignals: string[] }>
  ocrAvailable?: boolean
  ocrAttempted?: boolean
  ocrPageCount?: number
  ocrErrors?: Array<{ page?: number; error: string }>
  extractedTextLength?: number
  textSource?: 'native' | 'ocr' | 'mixed' | 'none'
}

export interface ExeFactsJson {
  supported: boolean
  fileSize: number
  architecture: string | null
  imports?: string[]
  suspiciousImports?: string[]
  urls?: string[]
  ipAddresses?: string[]
  highEntropySections?: string[]
  structuralWarnings?: string[]
  error?: string
}

export interface DocxFactsJson {
  supported: boolean
  fileSize: number
  textLength: number
  hiddenTextCount: number
  hiddenTextFindings: Array<{ part?: string; text: string; reasons: string[]; contentSignals: string[] }>
  urls: string[]
  externalRelationships: Array<{ source: string; target: string; relationshipType?: string }>
  embeddedObjects: Array<{ name: string; size?: number; isExecutableLike: boolean }>
  macroParts: string[]
  suspiciousIndicators: string[]
  packageWarnings: string[]
  hasComments: boolean
  hasTrackedChanges: boolean
  hasExternalTemplate: boolean
  error?: string
}

export interface PrivacyResult {
  kind: 'json' | 'pdf' | 'docx' | 'image'
  filename?: string
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
  decision: 'ALLOW' | 'REDACT' | 'BLOCK' | 'UNKNOWN'
  entities: Array<{ entity_type: string; text: string; start: number; end: number; page?: number }>
  redactedText?: string | null
  extractionState: AnalyzerState
  error?: string
}

export interface AssessmentVersion {
  engineVersion: string
  rulesetVersion: string
  policyVersion: string
}

export interface ScanReport {
  scanId: string
  createdAt: string
  filename: string
  size: number
  sha256: string
  coverage: AnalyzerCoverageEntry[]
  threat: ThreatResult | null
  privacy: PrivacyResult | null
  verdict: Verdict
  verdictReason: string
  sirGraph?: SIRGraph
  counterfactualPlan?: CounterfactualPlan
  signatureHmac?: string
  assessment?: AssessmentVersion
}

export interface ScanRecordRow {
  scanId: string
  createdAt: string
  filename: string
  size: number
  sha256: string
  reportJson: string
}

// Convenience factory used by the evidence builders.
export function findingFromEvidence(e: EvidenceInput): Finding {
  return {
    id: crypto.randomUUID(),
    module: 'threat',
    category: e.category,
    title: e.title,
    description: e.description,
    severity: e.severity,
    source: e.source,
    location: e.location,
    evidence: e.evidence,
  }
}

export interface EvidenceInput {
  category: string
  title: string
  description: string
  severity: Finding['severity']
  source: string
  location?: string
  evidence?: string
}
