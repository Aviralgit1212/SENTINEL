import { spawn } from 'node:child_process'
import path from 'node:path'

import type { Evidence } from '../types/scan.js'
import { createEvidence } from '../utils/evidence.js'

interface SuspiciousPdfObject {
    xref: number
    type: string
}

interface PdfAnalysisResult {
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
    hasAdditionalActions: boolean
    hasRichMedia: boolean
    hasAcroForm: boolean
    hasXfa: boolean
    extractedTextLength: number
    suspiciousObjects: SuspiciousPdfObject[]
    evidence: Evidence[]
}

interface PythonResult {
    ok: boolean
    error?: string

    metadata?: Record<string, string>
    pageCount?: number
    urls?: string[]
    javascriptCount?: number
    embeddedFileCount?: number
    annotationCount?: number
    formFieldCount?: number

    hasOpenAction?: boolean
    hasLaunchAction?: boolean
    hasAdditionalActions?: boolean
    hasRichMedia?: boolean
    hasAcroForm?: boolean
    hasXfa?: boolean

    extractedTextLength?: number

    suspiciousObjects?: SuspiciousPdfObject[]
}

export function analyzePdf(
    filePath: string,
): Promise<PdfAnalysisResult> {

    return new Promise((resolve) => {

        const scriptPath = path.resolve(
            process.cwd(),
            'src',
            'scripts',
            'analyze_pdf.py',
        )

        const pythonPath = path.resolve(
            process.cwd(),
            '.venv',
            'bin',
            'python',
        )

        const python = spawn(
            pythonPath,
            [scriptPath, filePath],
            {
                stdio: [
                    'ignore',
                    'pipe',
                    'pipe',
                ],
            },
        )

        let stdout = ''
        let stderr = ''

        python.stdout.on(
            'data',
            (chunk) => {
                stdout += chunk.toString()
            },
        )

        python.stderr.on(
            'data',
            (chunk) => {
                stderr += chunk.toString()
            },
        )

        python.on(
            'error',
            (error) => {

                resolve(
                    createFailedResult(
                        error.message ||
                            'Unable to start the PDF analyzer.',
                    ),
                )
            },
        )

        python.on(
            'close',
            (code) => {

                if (code !== 0) {

                    resolve(
                        createFailedResult(
                            stderr.trim() ||
                                'The PDF analyzer exited with an error.',
                        ),
                    )

                    return
                }

                try {

                    const jsonStart =
                        stdout.indexOf('{')

                    const jsonEnd =
                        stdout.lastIndexOf('}')

                    if (
                        jsonStart === -1 ||
                        jsonEnd === -1 ||
                        jsonEnd <= jsonStart
                    ) {

                        throw new Error(
                            'No valid JSON object was returned by the PDF analyzer.',
                        )
                    }

                    const jsonOutput =
                        stdout.slice(
                            jsonStart,
                            jsonEnd + 1,
                        )

                    const parsed =
                        JSON.parse(
                            jsonOutput,
                        ) as PythonResult

                    if (!parsed.ok) {

                        resolve(
                            createFailedResult(
                                parsed.error ||
                                    'Unknown PDF analysis error.',
                            ),
                        )

                        return
                    }

                    const result: PdfAnalysisResult = {

                        supported: true,

                        metadata:
                            parsed.metadata ?? {},

                        pageCount:
                            parsed.pageCount ?? 0,

                        urls:
                            parsed.urls ?? [],

                        javascriptCount:
                            parsed.javascriptCount ?? 0,

                        embeddedFileCount:
                            parsed.embeddedFileCount ?? 0,

                        annotationCount:
                            parsed.annotationCount ?? 0,

                        formFieldCount:
                            parsed.formFieldCount ?? 0,

                        hasOpenAction:
                            parsed.hasOpenAction ??
                            false,

                        hasLaunchAction:
                            parsed.hasLaunchAction ??
                            false,

                        hasAdditionalActions:
                            parsed.hasAdditionalActions ??
                            false,

                        hasRichMedia:
                            parsed.hasRichMedia ??
                            false,

                        hasAcroForm:
                            parsed.hasAcroForm ??
                            false,

                        hasXfa:
                            parsed.hasXfa ??
                            false,

                        extractedTextLength:
                            parsed.extractedTextLength ??
                            0,

                        suspiciousObjects:
                            parsed.suspiciousObjects ??
                            [],

                        evidence: [],
                    }

                    result.evidence =
                        buildPdfEvidence(
                            result,
                        )

                    resolve(result)

                } catch (error) {

                    resolve(
                        createFailedResult(
                            error instanceof Error
                                ? error.message
                                : 'The PDF analyzer returned an unreadable result.',
                        ),
                    )
                }
            },
        )
    })
}

function createFailedResult(
    description: string,
): PdfAnalysisResult {

    return {

        supported: false,

        metadata: {},

        pageCount: 0,

        urls: [],

        javascriptCount: 0,

        embeddedFileCount: 0,

        annotationCount: 0,

        formFieldCount: 0,

        hasOpenAction: false,

        hasLaunchAction: false,

        hasAdditionalActions: false,

        hasRichMedia: false,

        hasAcroForm: false,

        hasXfa: false,

        extractedTextLength: 0,

        suspiciousObjects: [],

        evidence: [
            createEvidence({
                category: 'pdf-analyzer',

                title:
                    'PDF analysis failed',

                description,

                severity: 'medium',

                source: 'pymupdf',
            }),
        ],
    }
}

function buildPdfEvidence(
    result: PdfAnalysisResult,
): Evidence[] {

    const evidence: Evidence[] = []

    // ---------------------------------------------------------
    // JavaScript
    // ---------------------------------------------------------

    if (
        result.javascriptCount > 0
    ) {

        evidence.push(
            createEvidence({
                category:
                    'active-content',

                title:
                    'JavaScript detected',

                description:
                    `The PDF contains ${result.javascriptCount} JavaScript-related object(s).`,

                severity:
                    'high',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // OpenAction
    // ---------------------------------------------------------

    if (
        result.hasOpenAction
    ) {

        evidence.push(
            createEvidence({
                category:
                    'active-content',

                title:
                    'Automatic document action detected',

                description:
                    'The PDF contains an OpenAction that can trigger an action when the document is opened.',

                severity:
                    'medium',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // Additional Actions
    // ---------------------------------------------------------

    if (
        result.hasAdditionalActions
    ) {

        evidence.push(
            createEvidence({
                category:
                    'active-content',

                title:
                    'Additional PDF actions detected',

                description:
                    'The PDF contains an Additional Actions (/AA) entry that may trigger actions from document events.',

                severity:
                    'medium',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // Launch
    // ---------------------------------------------------------

    if (
        result.hasLaunchAction
    ) {

        evidence.push(
            createEvidence({
                category:
                    'active-content',

                title:
                    'Launch action detected',

                description:
                    'The PDF contains a Launch action capable of starting another resource or application.',

                severity:
                    'high',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // Embedded files
    // ---------------------------------------------------------

    if (
        result.embeddedFileCount > 0
    ) {

        evidence.push(
            createEvidence({
                category:
                    'embedded-content',

                title:
                    'Embedded file detected',

                description:
                    `The PDF contains ${result.embeddedFileCount} embedded file(s).`,

                severity:
                    'medium',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // RichMedia
    // ---------------------------------------------------------

    if (
        result.hasRichMedia
    ) {

        evidence.push(
            createEvidence({
                category:
                    'active-content',

                title:
                    'Rich media content detected',

                description:
                    'The PDF contains RichMedia content that may provide interactive or executable capabilities.',

                severity:
                    'medium',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // XFA
    // ---------------------------------------------------------

    if (
        result.hasXfa
    ) {

        evidence.push(
            createEvidence({
                category:
                    'document-structure',

                title:
                    'XFA form structure detected',

                description:
                    'The PDF contains XFA form structures. These should be inspected as part of deeper document analysis.',

                severity:
                    'low',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // AcroForm
    // ---------------------------------------------------------

    if (
        result.hasAcroForm
    ) {

        evidence.push(
            createEvidence({
                category:
                    'document-structure',

                title:
                    'AcroForm structure detected',

                description:
                    'The PDF contains an AcroForm structure.',

                severity:
                    'low',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // URLs
    // ---------------------------------------------------------

    if (
        result.urls.length > 0
    ) {

        evidence.push(
            createEvidence({
                category:
                    'network',

                title:
                    'URLs detected',

                description:
                    `The PDF contains ${result.urls.length} URL(s) that can be inspected by later threat-intelligence analysis.`,

                severity:
                    'low',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    // ---------------------------------------------------------
    // Form fields
    // ---------------------------------------------------------

    if (
        result.formFieldCount > 0
    ) {

        evidence.push(
            createEvidence({
                category:
                    'document-structure',

                title:
                    'Interactive form fields detected',

                description:
                    `The PDF contains ${result.formFieldCount} form field(s).`,

                severity:
                    'low',

                source:
                    'pdf-analyzer',
            }),
        )
    }

    return evidence
}