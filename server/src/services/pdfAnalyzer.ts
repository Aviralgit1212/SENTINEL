import { spawn } from 'node:child_process'
import path from 'node:path'

import type {
    PdfFacts,
    PdfOpenAction,
    PdfSuspiciousObject,
} from '../types/scan.js'

interface PythonResult {
    ok: boolean

    metadata?: Record<string, string>

    pageCount?: number

    urls?: string[]

    javascriptCount?: number

    embeddedFileCount?: number

    annotationCount?: number

    formFieldCount?: number

    // --------------------------------
    // OpenAction
    // --------------------------------

    openAction?: {
        present?: boolean

        type?:
            | 'GoTo'
            | 'GoToR'
            | 'URI'
            | 'JavaScript'
            | 'Launch'
            | 'Unknown'
            | null

        rawType?: string | null

        target?: string | null
    }

    // --------------------------------
    // Legacy / structure flags
    // --------------------------------

    hasOpenAction?: boolean

    hasLaunchAction?: boolean

    hasAdditionalActions?: boolean

    hasRichMedia?: boolean

    hasAcroForm?: boolean

    hasXfa?: boolean

    extractedTextLength?: number

    // --------------------------------
    // OCR
    // --------------------------------

    ocrAttempted?: boolean

    ocrAvailable?: boolean

    ocrTextLength?: number

    ocrPageCount?: number

    ocrText?: string

    textSource?: 'native' | 'ocr' | 'none'

    // --------------------------------
    // Suspicious PDF objects
    // --------------------------------

    suspiciousObjects?: PdfSuspiciousObject[]

    error?: string
}

/**
 * Runs the Python/PyMuPDF PDF analyzer
 * and converts its output into normalized PDF facts.
 *
 * IMPORTANT:
 *
 * This service only extracts facts.
 * It does NOT:
 *
 * - create security evidence
 * - assign severity
 * - assign risk scores
 * - make allow/block decisions
 */
export function analyzePdf(
    filePath: string,
): Promise<PdfFacts> {

    return new Promise((resolve) => {

        // --------------------------------
        // Python analyzer path
        // --------------------------------

        const scriptPath = path.resolve(
            process.cwd(),
            'src',
            'scripts',
            'analyze_pdf.py',
        )

        // --------------------------------
        // Python virtual environment
        // --------------------------------

        const pythonPath = path.resolve(
            process.cwd(),
            '.venv',
            'bin',
            'python',
        )

        // --------------------------------
        // Start Python process
        // --------------------------------

        const python = spawn(
            pythonPath,
            [
                scriptPath,
                filePath,
            ],
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

        // --------------------------------
        // Capture stdout
        // --------------------------------

        python.stdout.on(
            'data',
            (chunk) => {

                stdout +=
                    chunk.toString()
            },
        )

        // --------------------------------
        // Capture stderr
        // --------------------------------

        python.stderr.on(
            'data',
            (chunk) => {

                stderr +=
                    chunk.toString()
            },
        )

        // --------------------------------
        // Python process error
        // --------------------------------

        python.on(
            'error',
            (error) => {

                resolve(
                    createFailedFacts(
                        error.message ||
                            'Unable to start the PDF analyzer.',
                    ),
                )
            },
        )

        // --------------------------------
        // Python process completed
        // --------------------------------

        python.on(
            'close',
            (code) => {

                // --------------------------------
                // Non-zero exit code
                // --------------------------------

                if (code !== 0) {

                    resolve(
                        createFailedFacts(
                            stderr.trim() ||
                                'The PDF analyzer exited with an error.',
                        ),
                    )

                    return
                }

                try {

                    // --------------------------------
                    // Find JSON object
                    // --------------------------------

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

                    // --------------------------------
                    // Parse Python result
                    // --------------------------------

                    const parsed =
                        JSON.parse(
                            jsonOutput,
                        ) as PythonResult

                    // --------------------------------
                    // Python reported failure
                    // --------------------------------

                    if (!parsed.ok) {

                        resolve(
                            createFailedFacts(
                                parsed.error ||
                                    'Unknown PDF analysis error.',
                            ),
                        )

                        return
                    }

                    // --------------------------------
                    // Normalize OpenAction
                    // --------------------------------

                    const openAction =
                        normalizeOpenAction(
                            parsed,
                        )

                    // --------------------------------
                    // Normalize PDF facts
                    // --------------------------------

                    const facts: PdfFacts = {

                        supported:
                            true,

                        metadata:
                            parsed.metadata ?? {},

                        // --------------------------------
                        // PDF structure
                        // --------------------------------

                        structure: {

                            pageCount:
                                parsed.pageCount ?? 0,

                            javascriptCount:
                                parsed.javascriptCount ?? 0,

                            embeddedFileCount:
                                parsed.embeddedFileCount ?? 0,

                            annotationCount:
                                parsed.annotationCount ?? 0,

                            formFieldCount:
                                parsed.formFieldCount ?? 0,

                            openAction,

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
                        },

                        // --------------------------------
                        // Links
                        // --------------------------------

                        links: {

                            urls:
                                parsed.urls ?? [],
                        },

                        // --------------------------------
                        // Text / OCR
                        // --------------------------------

                        text: {

                            nativeTextLength:
                                parsed.extractedTextLength ??
                                0,

                            ocrAttempted:
                                parsed.ocrAttempted ??
                                false,

                            ocrAvailable:
                                parsed.ocrAvailable ??
                                false,

                            ocrTextLength:
                                parsed.ocrTextLength ??
                                0,

                            ocrPageCount:
                                parsed.ocrPageCount ??
                                0,

                            source:
                                parsed.textSource ??
                                'none',
                        },

                        // --------------------------------
                        // Suspicious objects
                        // --------------------------------

                        suspiciousObjects:
                            parsed.suspiciousObjects ??
                            [],
                    }

                    resolve(facts)

                } catch (error) {

                    resolve(
                        createFailedFacts(
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

/**
 * Converts the Python OpenAction result into
 * the normalized PdfOpenAction structure.
 *
 * We keep this conservative:
 *
 * - Missing action = no action
 * - Unknown action = Unknown
 * - No guessing about maliciousness
 */
function normalizeOpenAction(
    parsed: PythonResult,
): PdfOpenAction {

    // --------------------------------
    // New Python format
    // --------------------------------

    if (parsed.openAction) {

        const action =
            parsed.openAction

        return {

            present:
                action.present ??
                false,

            type:
                action.type ??
                null,

            rawType:
                action.rawType ??
                null,

            target:
                action.target ??
                null,
        }
    }

    // --------------------------------
    // Backward compatibility
    // --------------------------------
    //
    // If an older Python analyzer output is
    // encountered, preserve the OpenAction fact.
    //
    // We cannot determine its exact behavior,
    // therefore it is classified as Unknown.
    // --------------------------------

    if (parsed.hasOpenAction) {

        return {

            present:
                true,

            type:
                'Unknown',

            rawType:
                null,

            target:
                null,
        }
    }

    // --------------------------------
    // No OpenAction
    // --------------------------------

    return {

        present:
            false,

        type:
            null,

        rawType:
            null,

        target:
            null,
    }
}

/**
 * Creates a safe failed PDF facts object.
 *
 * The failure is represented as facts so that the
 * evidence layer can decide how to report it.
 */
function createFailedFacts(
    description: string,
): PdfFacts {

    return {

        supported:
            false,

        metadata: {
            analysisError:
                description,
        },

        structure: {

            pageCount:
                0,

            javascriptCount:
                0,

            embeddedFileCount:
                0,

            annotationCount:
                0,

            formFieldCount:
                0,

            openAction: {

                present:
                    false,

                type:
                    null,

                rawType:
                    null,

                target:
                    null,
            },

            hasLaunchAction:
                false,

            hasAdditionalActions:
                false,

            hasRichMedia:
                false,

            hasAcroForm:
                false,

            hasXfa:
                false,
        },

        links: {
            urls: [],
        },

        text: {

            nativeTextLength:
                0,

            ocrAttempted:
                false,

            ocrAvailable:
                false,

            ocrTextLength:
                0,

            ocrPageCount:
                0,

            source:
                'none',
        },

        suspiciousObjects: [],
    }
}