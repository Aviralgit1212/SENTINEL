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

    /** Native PDF text flagged by multi-signal hidden-text analysis. */
    hiddenText: {
        count: number
        items: PdfHiddenTextFinding[]
    }
}


export interface PdfHiddenTextFinding {
    page: number
    text: string
    fontSize: number
    bbox: [number, number, number, number]
    color: [number, number, number] | null
    reasons: string[]
    contentSignals: string[]
    urls: string[]
    visibleOverlap: number
    ocrChecked: boolean
    confidence: number
}

export interface PdfStructureFacts {
    pageCount: number

    javascriptCount: number

    embeddedFileCount: number

    /**
     * Detailed information about files embedded
     * inside the PDF.
     */
    embeddedFiles: PdfEmbeddedFile[]

    annotationCount: number

    formFieldCount: number

    openAction: PdfOpenAction

    hasLaunchAction: boolean

    hasAdditionalActions: boolean

    hasRichMedia: boolean

    hasAcroForm: boolean

    hasXfa: boolean
}

export interface PdfEmbeddedFile {
    /**
     * Embedded filename if available.
     */
    filename: string | null

    /**
     * MIME type reported by the PDF.
     */
    mimeType: string | null

    /**
     * Size of the embedded file in bytes.
     */
    size: number | null

    /**
     * PDF relationship, when available.
     *
     * Example:
     * Source
     * Data
     * Alternative
     */
    relationship: string | null

    /**
     * Whether the embedded object represents
     * C2PA / Content Credentials.
     */
    isC2pa: boolean

    /**
     * Whether the embedded file appears to be
     * executable or script-like.
     */
    isExecutableLike: boolean

    /**
     * PDF object number where the embedded file
     * was found.
     */
    xref: number
}

export interface PdfTextFacts {
    nativeTextLength: number

    ocrAttempted: boolean

    ocrAvailable: boolean

    ocrTextLength: number

    ocrPageCount: number

    errors: Array<{ page?: number; error: string }>

    source:
        | 'native'
        | 'ocr'
        | 'mixed'
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