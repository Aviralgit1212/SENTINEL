import { randomUUID } from 'node:crypto'
import type { Express } from 'express'

import { calculateSha256 } from './hashService.js'
import { detectFileType } from './fileTypeService.js'
import { scanWithClamAV } from './clamAvService.js'
import { analyzePdf } from './pdfAnalyzer.js'
import { buildPdfEvidence } from './pdfEvidenceBuilder.js'

import { Scan } from '../models/Scan.js'

import {
    calculateRisk,
    createEvidence,
    recommendationForRisk,
    riskLevelFromScore,
} from '../utils/evidence.js'

import type {
    Evidence,
    ScanResult,
} from '../types/scan.js'

export type ScanRequestResult =
    | {
        status: 'completed'
        result: ScanResult
        created: boolean
    }
    | {
        status: 'analyzing'
        scanId: string
        created: false
    }
    | {
        status: 'failed'
        scanId: string
        error: string
        created: false
    }

function isDuplicateKeyError(
    error: unknown,
): boolean {
    return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (
            error as {
                code?: unknown
            }
        ).code === 11000
    )
}

function documentToScanResult(
    scan: Record<string, any>,
): ScanResult {
    return {
        scanId: scan.scanId,

        filename:
            scan.filename,

        size:
            scan.size,

        status:
            scan.status,

        fileType: {
            detectedExtension:
                scan.detectedExtension ??
                null,

            detectedMime:
                scan.mimeType ??
                null,

            detectedType:
                scan.detectedExtension ??
                null,

            extensionMismatch:
                Boolean(
                    scan.extensionMismatch,
                ),
        },

        hash: {
            algorithm: 'sha256',

            value:
                scan.sha256,
        },

        antivirus: {
            engine:
                scan.antivirus?.engine ??
                'clamav',

            available:
                Boolean(
                    scan.antivirus?.available,
                ),

            status:
                scan.antivirus?.status ??
                'error',

            details:
                scan.antivirus?.details ??
                '',
        },

        evidence:
            scan.evidence ?? [],

        risk:
            scan.risk,

        recommendation:
            scan.recommendation,

        pdfAnalysis:
            scan.pdfAnalysis ??
            undefined,
    }
}

export async function getScanResult(
    userId: string,
    scanId: string,
): Promise<ScanResult | null> {
    const scan =
        await Scan.findOne({
            userId,
            scanId,
        }).lean()

    if (!scan) {
        return null
    }

    return documentToScanResult(
        scan,
    )
}

export async function analyzeFile(
    file: Express.Multer.File,
    userId: string,
    scanRequestId: string,
): Promise<ScanRequestResult> {
    /*
     * --------------------------------
     * 1. Cheap deterministic analysis
     * --------------------------------
     *
     * These operations are safe to run twice
     * in a race because they don't create
     * database records or start expensive
     * analysis.
     */

    const fileType =
        await detectFileType(
            file.path,
            file.originalname,
        )

    const sha256 =
        await calculateSha256(
            file.path,
        )

    const scanId =
        randomUUID()

    /*
     * --------------------------------
     * 2. Reserve the logical scan
     * --------------------------------
     *
     * The MongoDB unique index on:
     *
     * userId + scanRequestId
     *
     * guarantees that only ONE request can
     * own this scan.
     */

    try {
        await Scan.create({
            scanId,

            scanRequestId,

            userId,

            filename:
                file.originalname,

            size:
                file.size,

            extension:
                fileType.detectedExtension
                    ? `.${fileType.detectedExtension}`
                    : null,

            detectedExtension:
                fileType.detectedExtension,

            extensionMismatch:
                fileType.extensionMismatch,

            mimeType:
                fileType.detectedMime,

            sha256,

            status:
                'analyzing',

            antivirus: {
                engine:
                    'clamav',

                available:
                    false,

                status:
                    'unavailable',

                details:
                    'Scan is still in progress.',
            },

            /*
             * These fields are required by the
             * MongoDB schema even while analyzing.
             */
            risk: {
                score: 0,
                level: 'low',
            },

            recommendation:
                'allow',

            evidence: [],

            pdfAnalysis:
                null,
        })
    } catch (error) {
        /*
         * Another request won the unique-index
         * race.
         */
        if (
            !isDuplicateKeyError(error)
        ) {
            throw error
        }

        const existing =
            await Scan.findOne({
                userId,
                scanRequestId,
            }).lean()

        if (!existing) {
            throw error
        }

        /*
         * Existing request has already completed.
         */
        if (
            existing.status ===
            'completed'
        ) {
            return {
                status:
                    'completed',

                result:
                    documentToScanResult(
                        existing,
                    ),

                created: false,
            }
        }

        /*
         * Existing request failed.
         */
        if (
            existing.status ===
            'failed'
        ) {
            return {
                status:
                    'failed',

                scanId:
                    existing.scanId,

                error:
                    existing.errorMessage ??
                    'File analysis failed.',

                created: false,
            }
        }

        /*
         * Existing request is currently
         * being analyzed.
         */
        return {
            status:
                'analyzing',

            scanId:
                existing.scanId,

            created: false,
        }
    }

    try {
        /*
         * --------------------------------
         * 3. ClamAV
         * --------------------------------
         */

        const antivirus =
            await scanWithClamAV(
                file.path,
            )

        /*
         * --------------------------------
         * 4. Deep PDF analysis
         * --------------------------------
         */

        const pdfAnalysis =
            fileType.detectedExtension ===
                'pdf'
                ? await analyzePdf(
                    file.path,
                )
                : null

        /*
         * --------------------------------
         * 5. Security evidence
         * --------------------------------
         */

        const evidence: Evidence[] =
            []

        /*
         * File type mismatch
         */
        if (
            fileType.extensionMismatch
        ) {
            evidence.push(
                createEvidence({
                    category:
                        'file-type',

                    title:
                        'File type mismatch',

                    description:
                        'The filename extension does not match the detected file type.',

                    severity:
                        'high',

                    score:
                        15,

                    source:
                        'magic-byte-analysis',
                }),
            )
        }

        /*
         * Malware
         */
        if (
            antivirus.status ===
            'threat'
        ) {
            evidence.push(
                createEvidence({
                    category:
                        'malware',

                    title:
                        'Malware detected',

                    description:
                        antivirus.details,

                    severity:
                        'critical',

                    score:
                        50,

                    source:
                        'clamav',
                }),
            )
        }

        /*
         * ClamAV unavailable
         */
        if (
            antivirus.status ===
            'unavailable'
        ) {
            evidence.push(
                createEvidence({
                    category:
                        'scanner',

                    title:
                        'Antivirus scanner unavailable',

                    description:
                        'ClamAV was not available for this scan.',

                    severity:
                        'medium',

                    score:
                        5,

                    source:
                        'clamav',
                }),
            )
        }

        /*
         * PDF evidence
         */
        if (pdfAnalysis) {
            evidence.push(
                ...buildPdfEvidence(
                    pdfAnalysis,
                ),
            )
        }

        /*
         * --------------------------------
         * 6. Risk calculation
         * --------------------------------
         */

        const riskScore =
            calculateRisk(
                evidence,
            )

        const riskLevel =
            riskLevelFromScore(
                riskScore,
            )

        const risk = {
            score:
                riskScore,

            level:
                riskLevel,
        }

        const scoreRecommendation =
            recommendationForRisk(
                riskScore,
            )

        /*
         * A low aggregate score must not override a high-severity
         * PDF hidden-text finding. Keep existing block/review decisions;
         * only upgrade an otherwise-allow decision to review.
         */
        const hasHighRiskHiddenPdfText = evidence.some(
            (item) =>
                item.category === 'pdf-hidden-text' &&
                item.severity === 'high',
        )

        const recommendation =
            scoreRecommendation === 'allow' &&
                hasHighRiskHiddenPdfText
                ? 'review'
                : scoreRecommendation

        /*
         * --------------------------------
         * 7. Build final result
         * --------------------------------
         */

        const result: ScanResult = {
            scanId,

            filename:
                file.originalname,

            size:
                file.size,

            status:
                'completed',

            fileType,

            hash: {
                algorithm:
                    'sha256',

                value:
                    sha256,
            },

            antivirus: {
                engine:
                    'clamav',

                available:
                    antivirus.available,

                status:
                    antivirus.status,

                details:
                    antivirus.details,
            },

            pdfAnalysis:
                pdfAnalysis
                    ? {
                        supported:
                            pdfAnalysis.supported,

                        metadata:
                            pdfAnalysis.metadata,

                        structure: {
                            pageCount:
                                pdfAnalysis
                                    .structure
                                    .pageCount,

                            javascriptCount:
                                pdfAnalysis
                                    .structure
                                    .javascriptCount,

                            embeddedFileCount:
                                pdfAnalysis
                                    .structure
                                    .embeddedFileCount,

                            annotationCount:
                                pdfAnalysis
                                    .structure
                                    .annotationCount,

                            formFieldCount:
                                pdfAnalysis
                                    .structure
                                    .formFieldCount,

                            embeddedFiles:
                                pdfAnalysis
                                    .structure
                                    .embeddedFiles,

                            openAction: {
                                present:
                                    pdfAnalysis
                                        .structure
                                        .openAction
                                        .present,

                                type:
                                    pdfAnalysis
                                        .structure
                                        .openAction
                                        .type,

                                rawType:
                                    pdfAnalysis
                                        .structure
                                        .openAction
                                        .rawType,

                                target:
                                    pdfAnalysis
                                        .structure
                                        .openAction
                                        .target,
                            },

                            hasLaunchAction:
                                pdfAnalysis
                                    .structure
                                    .hasLaunchAction,

                            hasAdditionalActions:
                                pdfAnalysis
                                    .structure
                                    .hasAdditionalActions,

                            hasRichMedia:
                                pdfAnalysis
                                    .structure
                                    .hasRichMedia,

                            hasAcroForm:
                                pdfAnalysis
                                    .structure
                                    .hasAcroForm,

                            hasXfa:
                                pdfAnalysis
                                    .structure
                                    .hasXfa,
                        },

                        links: {
                            urls:
                                pdfAnalysis
                                    .links
                                    .urls,
                        },


                        text: {
                            nativeTextLength:
                                pdfAnalysis
                                    .text
                                    .nativeTextLength,

                            ocrAttempted:
                                pdfAnalysis
                                    .text
                                    .ocrAttempted,

                            ocrAvailable:
                                pdfAnalysis
                                    .text
                                    .ocrAvailable,

                            ocrTextLength:
                                pdfAnalysis
                                    .text
                                    .ocrTextLength,

                            ocrPageCount:
                                pdfAnalysis
                                    .text
                                    .ocrPageCount,

                            errors:
                                pdfAnalysis
                                    .text
                                    .errors ?? [],

                            source:
                                pdfAnalysis
                                    .text
                                    .source,
                        },

                        suspiciousObjects:
                            pdfAnalysis
                                .suspiciousObjects,

                        hiddenText: {
                            count:
                                pdfAnalysis.hiddenText?.count ??
                                pdfAnalysis.hiddenText?.items?.length ??
                                0,

                            items:
                                pdfAnalysis.hiddenText?.items ?? [],
                        },
                    }
                    : undefined,

            evidence,

            risk,

            recommendation,
        }

        /*
         * --------------------------------
         * 8. Update the RESERVED document
         * --------------------------------
         *
         * We do NOT create another document.
         */

        await Scan.updateOne(
            {
                userId,

                scanRequestId,

                status:
                    'analyzing',
            },

            {
                $set: {
                    status:
                        'completed',

                    antivirus:
                        result.antivirus,

                    risk:
                        result.risk,

                    recommendation:
                        result.recommendation,

                    evidence:
                        result.evidence,

                    pdfAnalysis:
                        result.pdfAnalysis ??
                        null,

                    errorMessage:
                        null,
                },
            },
        )

        return {
            status:
                'completed',

            result,

            created:
                true,
        }
    } catch (error) {
        /*
         * If analysis fails after the reservation,
         * mark that SAME MongoDB document failed.
         */

        const errorMessage =
            error instanceof Error
                ? error.message
                : 'File analysis failed.'

        await Scan.updateOne(
            {
                userId,

                scanRequestId,

                status:
                    'analyzing',
            },

            {
                $set: {
                    status:
                        'failed',

                    errorMessage,
                },
            },
        )

        throw error
    }
}