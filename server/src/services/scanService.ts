import { randomUUID } from 'node:crypto'
import type { Express } from 'express'

import { calculateSha256 } from './hashService.js'
import { detectFileType } from './fileTypeService.js'
import { scanWithClamAV } from './clamAvService.js'

import { analyzePdf } from './pdfAnalyzer.js'
import { buildPdfEvidence } from './pdfEvidenceBuilder.js'

import { analyzeExe } from './exeAnalyzer.js'
import { buildExeEvidence } from './exeEvidenceBuilder.js'

import { analyzeDocx } from './docxAnalyzer.js'
import { buildDocxEvidence } from './docxEvidenceBuilder.js'

import { analyzeJsonFile } from './jsonAnalyzer.js'
import {
  buildJsonEvidence,
  recommendationForJson,
} from './jsonEvidenceBuilder.js'

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

    docxAnalysis:
      scan.docxAnalysis ??
      undefined,

    jsonAnalysis:
      scan.jsonAnalysis ??
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
   * 1. Cheap deterministic analysis.
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
   * Preserve the existing unique-request
   * and duplicate-request handling.
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

      docxAnalysis:
        null,

      jsonAnalysis:
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
     * 3. Antivirus scan.
     *
     * Existing ClamAV integration is unchanged.
     */

    const antivirus =
      await scanWithClamAV(
        file.path,
      )

    /*
     * 4. Deep PDF analysis.
     */

    const pdfAnalysis =
      fileType.detectedExtension ===
      'pdf'
        ? await analyzePdf(
            file.path,
          )
        : null

    /*
     * 5. Static EXE analysis.
     *
     * Never execute the uploaded file.
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
     * 6. Static DOCX/DOCM analysis.
     */

    const hasDocxExtension =
      /\.(docx|docm)$/i.test(
        file.originalname,
      )

    const shouldAnalyzeDocx =
      fileType.detectedExtension ===
        'docx' ||
      fileType.detectedExtension ===
        'docm' ||
      hasDocxExtension

    const docxAnalysis =
      shouldAnalyzeDocx
        ? await analyzeDocx(
            file.path,
          )
        : null

    /*
     * 7. Static JSON analysis.
     *
     * Analyze files detected as JSON and files
     * named .json, even if their detected type
     * differs. This also allows malformed or
     * extension-spoofed JSON files to be reviewed.
     *
     * The Python analyzer treats file contents
     * as data. It must never execute the contents.
     */

    const hasJsonExtension =
      /\.json$/i.test(
        file.originalname,
      )

    const shouldAnalyzeJson =
      fileType.detectedExtension ===
        'json' ||
      hasJsonExtension

    const jsonAnalysis =
      shouldAnalyzeJson
        ? await analyzeJsonFile(
            file.path,
          )
        : null

    /*
     * 8. Build security evidence.
     */

    const evidence: Evidence[] =
      []

    /*
     * File type mismatch.
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
     * Malware detected by ClamAV.
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
     * ClamAV unavailable.
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
     * PDF evidence.
     */

    if (pdfAnalysis) {
      evidence.push(
        ...buildPdfEvidence(
          pdfAnalysis,
        ),
      )
    }

    /*
     * EXE evidence.
     */

    if (exeAnalysis) {
      evidence.push(
        ...buildExeEvidence(
          exeAnalysis,
        ),
      )
    }

    /*
     * DOCX evidence.
     */

    if (docxAnalysis) {
      evidence.push(
        ...buildDocxEvidence(
          docxAnalysis,
        ),
      )
    }

    /*
     * JSON evidence.
     */

    if (jsonAnalysis) {
      evidence.push(
        ...buildJsonEvidence(
          jsonAnalysis,
        ),
      )
    }

    /*
     * 9. Shared risk scoring.
     *
     * JSON evidence joins the existing evidence
     * array. The shared risk calculator is unchanged.
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
     * 10. EXE-specific verdict policy.
     *
     * Existing EXE policy is preserved.
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

    /*
     * 11. DOCX-specific verdict policy.
     *
     * Existing DOCX policy is preserved.
     */

    const hasHighSeverityDocxEvidence =
      evidence.some(
        (item) =>
          item.category.startsWith(
            'docx-',
          ) &&
          (
            item.severity === 'high' ||
            item.severity === 'critical'
          ),
      )

    const hasDocxReviewIndicators =
      Boolean(
        docxAnalysis && (
          !docxAnalysis.supported ||
          docxAnalysis.packageWarnings.length > 0 ||
          docxAnalysis.hiddenTextCount > 0 ||
          docxAnalysis.embeddedObjects.length > 0 ||
          docxAnalysis.macroParts.length > 0 ||
          docxAnalysis.hasExternalTemplate ||
          docxAnalysis.suspiciousIndicators.length > 0
        ),
      )

    const docxRecommendation =
      !shouldAnalyzeDocx
        ? recommendation
        : antivirus.status === 'threat'
          ? 'block'
          : (
              antivirus.status !== 'clean' ||
              !docxAnalysis?.supported ||
              fileType.extensionMismatch ||
              hasHighSeverityDocxEvidence ||
              hasDocxReviewIndicators ||
              riskScore >= 15
            )
              ? 'review'
              : 'allow'

    /*
     * 12. JSON-specific verdict policy.
     *
     * This uses the existing JSON evidence
     * and recommendation helpers.
     *
     * Explicit ClamAV threat -> block.
     * Unsupported/incomplete JSON analysis,
     * suspicious findings, extension mismatch,
     * non-clean AV status, or elevated risk
     * -> review.
     */

    const jsonRecommendation =
      jsonAnalysis
        ? recommendationForJson(
            jsonAnalysis,
            antivirus.status,
            fileType.extensionMismatch,
            riskScore,
          )
        : recommendation

    /*
     * 13. Final recommendation.
     *
     * Preserve existing EXE and DOCX priority.
     * JSON policy applies to JSON scans.
     * Other file types use the existing policy.
     */

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
        : shouldAnalyzeDocx
          ? docxRecommendation
          : shouldAnalyzeJson
            ? jsonRecommendation
            : recommendation

    /*
     * 14. Build final result.
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

      docxAnalysis:
        docxAnalysis ?? undefined,

      jsonAnalysis:
        jsonAnalysis ?? undefined,

      evidence,

      risk,

      recommendation:
        finalRecommendation,
    }

    /*
     * 15. Update the reserved MongoDB document.
     *
     * No second scan document is created.
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

          docxAnalysis:
            result.docxAnalysis ??
            null,

          jsonAnalysis:
            result.jsonAnalysis ??
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
     * Mark the reserved document as failed
     * if analysis fails after reservation.
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
