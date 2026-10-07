import { randomUUID } from 'node:crypto'
import type { Express } from 'express'

import { calculateSha256 } from './hashService.js'
import { detectFileType } from './fileTypeService.js'
import { scanWithClamAV } from './clamAvService.js'
import { analyzePdf } from './pdfAnalyzer.js'
import { buildPdfEvidence } from './pdfEvidenceBuilder.js'

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

export async function analyzeFile(
    file: Express.Multer.File,
): Promise<ScanResult> {

    const scanId = randomUUID()

    // --------------------------------
    // 1. Detect actual file type
    // --------------------------------

    const fileType = await detectFileType(
        file.path,
        file.originalname,
    )

    // --------------------------------
    // 2. Calculate SHA-256 fingerprint
    // --------------------------------

    const sha256 = await calculateSha256(
        file.path,
    )

    // --------------------------------
    // 3. Antivirus scan
    // --------------------------------

    const antivirus = await scanWithClamAV(
        file.path,
    )

    // --------------------------------
    // 4. File-specific deep analysis
    // --------------------------------

    const pdfAnalysis =
        fileType.detectedExtension === 'pdf'
            ? await analyzePdf(file.path)
            : null

    // --------------------------------
    // 5. Collect security evidence
    // --------------------------------

    const evidence: Evidence[] = []

    // --------------------------------
    // File type mismatch
    // --------------------------------

    if (fileType.extensionMismatch) {

        evidence.push(
            createEvidence({
                category: 'file-type',

                title:
                    'File type mismatch',

                description:
                    'The filename extension does not match the detected file type.',

                severity: 'high',

                score: 15,

                source:
                    'magic-byte-analysis',
            }),
        )
    }

    // --------------------------------
    // ClamAV detected malware
    // --------------------------------

    if (
        antivirus.status === 'threat'
    ) {

        evidence.push(
            createEvidence({
                category: 'malware',

                title:
                    'Malware detected',

                description:
                    antivirus.details,

                severity: 'critical',

                score: 50,

                source:
                    'clamav',
            }),
        )
    }

    // --------------------------------
    // ClamAV unavailable
    // --------------------------------

    if (
        antivirus.status === 'unavailable'
    ) {

        evidence.push(
            createEvidence({
                category: 'scanner',

                title:
                    'Antivirus scanner unavailable',

                description:
                    'ClamAV was not available for this scan.',

                severity: 'medium',

                score: 5,

                source:
                    'clamav',
            }),
        )
    }

    // --------------------------------
    // PDF-specific evidence
    // --------------------------------

    if (pdfAnalysis) {

        const pdfEvidence =
            buildPdfEvidence(
                pdfAnalysis,
            )

        evidence.push(
            ...pdfEvidence,
        )
    }

    // --------------------------------
    // 6. Calculate risk score
    // --------------------------------

    const riskScore =
        calculateRisk(
            evidence,
        )

    // --------------------------------
    // 7. Convert score to risk level
    // --------------------------------

    const riskLevel =
        riskLevelFromScore(
            riskScore,
        )

    const risk = {
        score: riskScore,
        level: riskLevel,
    }

    // --------------------------------
    // 8. Determine recommendation
    // --------------------------------

    const recommendation =
        recommendationForRisk(
            riskScore,
        )

    // --------------------------------
    // 9. Build final scan result
    // --------------------------------

    return {

        scanId,

        filename:
            file.originalname,

        size:
            file.size,

        status:
            'completed',

        // --------------------------------
        // File type
        // --------------------------------

        fileType,

        // --------------------------------
        // SHA-256
        // --------------------------------

        hash: {

            algorithm:
                'sha256',

            value:
                sha256,
        },

        // --------------------------------
        // Antivirus
        // --------------------------------

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

        // --------------------------------
        // PDF facts
        // --------------------------------

        pdfAnalysis:
            pdfAnalysis
                ? {

                    supported:
                        pdfAnalysis.supported,

                    metadata:
                        pdfAnalysis.metadata,

                    // --------------------------------
                    // PDF structure
                    // --------------------------------

                    structure: {

                        pageCount:
                            pdfAnalysis.structure.pageCount,

                        javascriptCount:
                            pdfAnalysis.structure.javascriptCount,

                        embeddedFileCount:
                            pdfAnalysis.structure.embeddedFileCount,

                        annotationCount:
                            pdfAnalysis.structure.annotationCount,

                        formFieldCount:
                            pdfAnalysis.structure.formFieldCount,

                        // --------------------------------
                        // OpenAction
                        // --------------------------------

                        openAction: {

                            present:
                                pdfAnalysis.structure.openAction.present,

                            type:
                                pdfAnalysis.structure.openAction.type,

                            rawType:
                                pdfAnalysis.structure.openAction.rawType,

                            target:
                                pdfAnalysis.structure.openAction.target,
                        },

                        // --------------------------------
                        // Other PDF actions / structures
                        // --------------------------------

                        hasLaunchAction:
                            pdfAnalysis.structure.hasLaunchAction,

                        hasAdditionalActions:
                            pdfAnalysis.structure.hasAdditionalActions,

                        hasRichMedia:
                            pdfAnalysis.structure.hasRichMedia,

                        hasAcroForm:
                            pdfAnalysis.structure.hasAcroForm,

                        hasXfa:
                            pdfAnalysis.structure.hasXfa,
                    },

                    // --------------------------------
                    // Links
                    // --------------------------------

                    links: {

                        urls:
                            pdfAnalysis.links.urls,
                    },

                    // --------------------------------
                    // Text / OCR
                    // --------------------------------

                    text: {

                        nativeTextLength:
                            pdfAnalysis.text.nativeTextLength,

                        ocrAttempted:
                            pdfAnalysis.text.ocrAttempted,

                        ocrAvailable:
                            pdfAnalysis.text.ocrAvailable,

                        ocrTextLength:
                            pdfAnalysis.text.ocrTextLength,

                        ocrPageCount:
                            pdfAnalysis.text.ocrPageCount,

                        source:
                            pdfAnalysis.text.source,
                    },

                    // --------------------------------
                    // Suspicious PDF objects
                    // --------------------------------

                    suspiciousObjects:
                        pdfAnalysis.suspiciousObjects,
                }
                : undefined,

        // --------------------------------
        // Security evidence
        // --------------------------------

        evidence,

        // --------------------------------
        // Risk
        // --------------------------------

        risk,

        // --------------------------------
        // Recommendation
        // --------------------------------

        recommendation,
    }
}