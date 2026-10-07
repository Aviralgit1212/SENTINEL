import { spawn } from 'node:child_process'
import path from 'node:path'

import type { Evidence } from '../types/scan.js'
import { createEvidence } from '../utils/evidence.js'

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
    extractedTextLength: number
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
    extractedTextLength?: number
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

        python.on('error', (error) => {
            resolve({
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
                extractedTextLength: 0,
                evidence: [
                    createEvidence({
                        category: 'pdf-analyzer',
                        title:
                            'PDF analyzer unavailable',
                        description:
                            error.message ||
                            'Unable to start the PDF analyzer.',
                        severity: 'medium',
                        source: 'pymupdf',
                    }),
                ],
            })
        })

        python.on('close', (code) => {
            if (code !== 0) {
                resolve({
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
                    extractedTextLength: 0,
                    evidence: [
                        createEvidence({
                            category:
                                'pdf-analyzer',
                            title:
                                'PDF analysis failed',
                            description:
                                stderr.trim() ||
                                'The PDF analyzer exited with an error.',
                            severity: 'medium',
                            source: 'pymupdf',
                        }),
                    ],
                })

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
                    resolve({
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
                        extractedTextLength: 0,
                        evidence: [
                            createEvidence({
                                category:
                                    'pdf-analyzer',
                                title:
                                    'PDF analysis failed',
                                description:
                                    parsed.error ||
                                    'Unknown PDF analysis error.',
                                severity: 'medium',
                                source: 'pymupdf',
                            }),
                        ],
                    })

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
                    extractedTextLength:
                        parsed.extractedTextLength ??
                        0,
                    evidence: [],
                }

                result.evidence =
                    buildPdfEvidence(result)

                resolve(result)
            } catch (error) {
                resolve({
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
                    extractedTextLength: 0,
                    evidence: [
                        createEvidence({
                            category:
                                'pdf-analyzer',
                            title:
                                'Invalid analyzer response',
                            description:
                                error instanceof Error
                                    ? error.message
                                    : 'The PDF analyzer returned an unreadable result.',
                            severity: 'medium',
                            source: 'pymupdf',
                        }),
                    ],
                })
            }
        })
    })
}

function buildPdfEvidence(
    result: PdfAnalysisResult,
): Evidence[] {
    const evidence: Evidence[] = []

    if (result.javascriptCount > 0) {
        evidence.push(
            createEvidence({
                category:
                    'active-content',
                title:
                    'JavaScript detected',
                description:
                    `The PDF contains ${result.javascriptCount} JavaScript action(s).`,
                severity: 'high',
                source:
                    'pdf-analyzer',
            }),
        )
    }

    if (result.hasOpenAction) {
        evidence.push(
            createEvidence({
                category:
                    'active-content',
                title:
                    'Automatic document action detected',
                description:
                    'The PDF contains an OpenAction that can execute when the document is opened.',
                severity: 'medium',
                source:
                    'pdf-analyzer',
            }),
        )
    }

    if (result.hasLaunchAction) {
        evidence.push(
            createEvidence({
                category:
                    'active-content',
                title:
                    'Launch action detected',
                description:
                    'The PDF contains a Launch action capable of starting another resource or application.',
                severity: 'high',
                source:
                    'pdf-analyzer',
            }),
        )
    }

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
                severity: 'medium',
                source:
                    'pdf-analyzer',
            }),
        )
    }

    if (result.urls.length > 0) {
        evidence.push(
            createEvidence({
                category:
                    'network',
                title:
                    'URLs detected',
                description:
                    `The PDF contains ${result.urls.length} URL(s) that can be inspected by later security analysis.`,
                severity: 'low',
                source:
                    'pdf-analyzer',
            }),
        )
    }

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
                severity: 'low',
                source:
                    'pdf-analyzer',
            }),
        )
    }

    return evidence
}