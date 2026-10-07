export type ScanStatus =
  | 'analyzing'
  | 'completed'
  | 'failed'

export type RiskLevel =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export interface Evidence {
  id: string
  category: string
  title: string
  description: string
  severity: RiskLevel
  source: string
}

export interface FileTypeResult {
  detectedExtension: string | null
  detectedMime: string | null
  detectedType: string | null
  extensionMismatch: boolean
}

export interface HashResult {
  algorithm: 'sha256'
  value: string
}

export interface AntivirusResult {
  engine: 'clamav'
  available: boolean
  status:
    | 'clean'
    | 'threat'
    | 'unavailable'
    | 'error'
  details: string
}

export interface ScanResult {
  scanId: string
  filename: string
  size: number
  status: ScanStatus
  fileType: FileTypeResult
  hash: HashResult
  antivirus: AntivirusResult
  evidence: Evidence[]
  risk: RiskLevel
  recommendation: 'allow' | 'review' | 'block'
  pdfAnalysis?: PdfAnalysis
}

export interface PdfAnalysis {
    supported: boolean
    metadata: Record<string, string>
    pageCount: number
    urls: string[]
    javascriptCount: number
    embeddedFileCount: number
    annotationCount: number
    formFieldCount: number
    hasOpenAction: boolean
    hasLaunchAction: boolean
    extractedTextLength: number
}