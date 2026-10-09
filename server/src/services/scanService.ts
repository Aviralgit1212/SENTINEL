import { randomUUID } from 'node:crypto'
import type { Express } from 'express'

import { calculateSha256 } from './hashService.js'
import { detectFileType } from './fileTypeService.js'
import { scanWithClamAV } from './clamAvService.js'
import { analyzePdf } from './pdfAnalyzer.js'
import { buildPdfEvidence } from './pdfEvidenceBuilder.js'
import { analyzeExe } from './exeAnalyzer.js'
import { buildExeEvidence } from './exeEvidenceBuilder.js'

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

    exeAnalysis:
      scan.exeAnalysis ??
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
   * 1. Cheap deterministic analysis
   *
   * These operations do not create database
   * records or start deep analysis.
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
   * 2. Reserve the logical scan.
   *
   * The MongoDB unique index on userId +
   * scanRequestId ensures that only one
   * request owns this logical scan.
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

      risk: {
        score: 0,
        level: 'low',
      },

      recommendation:
        'review',

      evidence: [],

      pdfAnalysis:
        null,

      exeAnalysis:
        null,
    })
  } catch (error) {
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
     * 3. Antivirus scan
     */

    const antivirus =
      await scanWithClamAV(
        file.path,
      )

    /*
     * 4. Deep PDF analysis
     *
     * Keep PDF analysis independent from
     * EXE analysis. A PDF renamed to .exe
     * may go through both checks.
     */

    const pdfAnalysis =
      fileType.detectedExtension ===
      'pdf'
        ? await analyzePdf(
            file.path,
          )
        : null

    /*
     * 5. Static EXE analysis
     *
     * Analyze:
     * - Files detected as EXEs.
     * - Files whose filename ends in .exe,
     *   even if their detected type differs.
     *
     * This catches extension spoofing. The
     * analyzer must inspect the file as data
     * and must never execute it.
     */

    const hasExeExtension =
      /\.exe$/i.test(
        file.originalname,
      )

    const shouldAnalyzeExe =
      fileType.detectedExtension ===
        'exe' ||
      hasExeExtension

    const exeAnalysis =
      shouldAnalyzeExe
        ? await analyzeExe(
            file.path,
          )
        : null

    /*
     * 6. Build security evidence
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
     * Malware detected by ClamAV
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
     * EXE evidence
     */

    if (exeAnalysis) {
      evidence.push(
        ...buildExeEvidence(
          exeAnalysis,
        ),
      )
    }

    /*
     * 7. Calculate risk
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
     * Preserve the PDF hidden-text safeguard.
     */

    const hasHighRiskHiddenPdfText =
      evidence.some(
        (item) =>
          item.category ===
            'pdf-hidden-text' &&
          item.severity === 'high',
      )

    const recommendation =
      scoreRecommendation ===
        'allow' &&
      hasHighRiskHiddenPdfText
        ? 'review'
        : scoreRecommendation

    /*
     * EXE-specific verdict policy:
     *
     * Block:
     *   ClamAV explicitly detected a threat.
     *
     * Review:
     *   AV did not confirm a clean scan,
     *   EXE analysis is unsupported,
     *   extension mismatch exists,
     *   structural warnings exist,
     *   high-severity EXE evidence exists,
     *   or the risk score is elevated.
     *
     * Allow:
     *   Supported EXE analysis, clean AV scan,
     *   and no elevated findings.
     *
     * A review/allow decision is not a guarantee
     * that a file is safe.
     */

    const hasHighSeverityExeEvidence =
      evidence.some(
        (item) =>
          item.category.startsWith(
            'exe-',
          ) &&
          item.severity === 'high',
      )

    const hasExeStructuralWarnings =
      Boolean(
        exeAnalysis?.structuralWarnings?.length,
      )

    const finalRecommendation =
      shouldAnalyzeExe
        ? (
            antivirus.status ===
            'threat'
              ? 'block'
              : (
                  antivirus.status !==
                    'clean' ||
                  !exeAnalysis?.supported ||
                  fileType.extensionMismatch ||
                  hasExeStructuralWarnings ||
                  hasHighSeverityExeEvidence ||
                  riskScore >= 25
                )
                  ? 'review'
                  : 'allow'
          )
        : recommendation

    /*
     * 8. Build final result
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

      exeAnalysis:
        exeAnalysis ?? undefined,

      evidence,

      risk,

      recommendation:
        finalRecommendation,
    }

    /*
     * 9. Update the reserved document.
     *
     * Do not create a second document.
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

          exeAnalysis:
            result.exeAnalysis ??
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
     * If analysis fails after reservation,
     * mark the same MongoDB document failed.
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