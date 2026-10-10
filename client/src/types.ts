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
  source: string
  location?: string
  evidence?: string
}

export interface CoverageEntry {
  analyzer: string
  state: AnalyzerState
  detail?: string
}

export interface PdfFacts {
  supported: boolean
  pageCount: number
  javascriptCount: number
  embeddedFileCount: number
  annotationCount: number
  formFieldCount: number
  openAction: { present: boolean; type: string | null; target: string | null }
  urls: string[]
  hiddenText: Array<{ page: number; text: string; reasons: string[]; contentSignals: string[] }>
  error?: string
}

export interface ExeFacts {
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

export interface DocxFacts {
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

export interface ThreatResult {
  antivirus: { engine: string; state: AnalyzerState; detail: string; threatName?: string }
  fileType: {
    declaredExtension: string | null
    detectedExtension: string | null
    detectedMime: string | null
    mismatch: boolean
  }
  pdf?: PdfFacts
  exe?: ExeFacts
  docx?: DocxFacts
  findings: Finding[]
}

export interface PrivacyEntity {
  entity_type: string
  text: string
  start: number
  end: number
  page?: number
}

export interface PrivacyResult {
  kind: 'json' | 'pdf' | 'docx' | 'image'
  filename?: string
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
  decision: 'ALLOW' | 'REDACT' | 'BLOCK' | 'UNKNOWN'
  entities: PrivacyEntity[]
  redactedText?: string | null
  extractionState: AnalyzerState
  scanId?: string
  error?: string
}

export interface CounterfactualBlocker {
  blockerId: string
  findingId?: string
  conditionType: 'MANDATORY_INVARIANT' | 'POLICY_CONSTRAINT' | 'COVERAGE_GAP'
  title: string
  description: string
  resolution: {
    action: string
    target?: string
    estimatedImpact: string
  }
}

export interface CounterfactualPlan {
  targetContext: string
  isSatisfiable: boolean
  blockers: CounterfactualBlocker[]
  minimalActionSequence: Array<{
    step: number
    actionName: string
    description: string
    targetLocation?: string
  }>
}

export interface ScanReport {
  scanId: string
  createdAt: string
  filename: string
  size: number
  sha256: string
  coverage: CoverageEntry[]
  threat: ThreatResult | null
  privacy: PrivacyResult | null
  verdict: 'block' | 'review_required' | 'allow_with_warnings' | 'allow'
  verdictReason: string
  counterfactualPlan?: CounterfactualPlan
  signatureHmac?: string
}
