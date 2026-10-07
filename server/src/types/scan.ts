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
    score: number
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

    risk: {
        score: number
        level: RiskLevel
    }

    recommendation:
        | 'allow'
        | 'review'
        | 'block'

    pdfAnalysis?: PdfFacts
}

/**
 * Facts extracted from a PDF.
 *
 * This interface intentionally contains observations only.
 * It does not contain risk scores or recommendations.
 */
export interface PdfFacts {
    supported: boolean

    metadata: Record<string, string>

    structure: PdfStructureFacts

    links: {
        urls: string[]
    }

    text: PdfTextFacts

    suspiciousObjects: PdfSuspiciousObject[]
}

export interface PdfStructureFacts {
    pageCount: number

    javascriptCount: number

    embeddedFileCount: number

    annotationCount: number

    formFieldCount: number

    openAction: PdfOpenAction

    hasLaunchAction: boolean

    hasAdditionalActions: boolean

    hasRichMedia: boolean

    hasAcroForm: boolean

    hasXfa: boolean
}

export interface PdfTextFacts {
    nativeTextLength: number

    ocrAttempted: boolean

    ocrAvailable: boolean

    ocrTextLength: number

    ocrPageCount: number

    source:
        | 'native'
        | 'ocr'
        | 'none'
}

export interface PdfSuspiciousObject {
    xref: number
    type: string
}

export interface PdfOpenAction {
    present: boolean

    type:
        | 'GoTo'
        | 'GoToR'
        | 'URI'
        | 'JavaScript'
        | 'Launch'
        | 'Unknown'
        | null

    rawType: string | null

    target: string | null
}