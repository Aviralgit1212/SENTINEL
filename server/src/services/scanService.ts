import { randomUUID } from 'node:crypto'
import type { Express } from 'express'

import { calculateSha256 } from './hashService.js'
import { detectFileType } from './fileTypeService.js'
import { scanWithClamAV } from './clamAvService.js'
import { analyzePdf } from './pdfAnalyzer.js'

import {
    calculateRisk,
    createEvidence,
    recommendationForRisk,
} from '../utils/evidence.js'

import type { ScanResult } from '../types/scan.js'

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
    const evidence = []

    // File type mismatch
    if (fileType.extensionMismatch) {
        evidence.push(
            createEvidence({
                category: 'file-type',
                title: 'File type mismatch',
                description:
                    'The filename extension does not match the detected file type.',
                severity: 'high',
                source: 'magic-byte-analysis',
            }),
        )
    }

    // ClamAV detected malware
    if (antivirus.status === 'threat') {
        evidence.push(
            createEvidence({
                category: 'malware',
                title: 'Malware detected',
                description: antivirus.details,
                severity: 'critical',
                source: 'clamav',
            }),
        )
    }

    // ClamAV unavailable
    if (antivirus.status === 'unavailable') {
        evidence.push(
            createEvidence({
                category: 'scanner',
                title: 'Antivirus scanner unavailable',
                description:
                    'ClamAV was not available for this scan.',
                severity: 'medium',
                source: 'clamav',
            }),
        )
    }

    // PDF-specific evidence
    if (pdfAnalysis) {
        evidence.push(
            ...pdfAnalysis.evidence,
        )
    }

    // --------------------------------
    // 6. Calculate overall risk
    // --------------------------------
    const risk = calculateRisk(evidence)

    // --------------------------------
    // 7. Build final scan result
    // --------------------------------
    return {
        scanId,
        filename: file.originalname,
        size: file.size,
        status: 'completed',

        fileType,

        hash: {
            algorithm: 'sha256',
            value: sha256,
        },

        antivirus: {
            engine: 'clamav',
            available: antivirus.available,
            status: antivirus.status,
            details: antivirus.details,
        },

        // PDF deep-analysis result
        pdfAnalysis: pdfAnalysis
            ? {
                  supported:
                      pdfAnalysis.supported,

                  metadata:
                      pdfAnalysis.metadata,

                  pageCount:
                      pdfAnalysis.pageCount,

                  urls:
                      pdfAnalysis.urls,

                  javascriptCount:
                      pdfAnalysis.javascriptCount,

                  embeddedFileCount:
                      pdfAnalysis.embeddedFileCount,

                  annotationCount:
                      pdfAnalysis.annotationCount,

                  formFieldCount:
                      pdfAnalysis.formFieldCount,

                  hasOpenAction:
                      pdfAnalysis.hasOpenAction,

                  hasLaunchAction:
                      pdfAnalysis.hasLaunchAction,

                  extractedTextLength:
                      pdfAnalysis.extractedTextLength,
              }
            : undefined,

        evidence,

        risk,

        recommendation:
            recommendationForRisk(risk),
    }
}