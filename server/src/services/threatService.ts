import path from 'node:path'
import type {
  AnalyzerCoverageEntry,
  AnalyzerState,
  Finding,
  ThreatResult,
  Verdict,
  PdfFactsJson,
  ExeFactsJson,
  DocxFactsJson,
} from '../types.js'
import { scanWithClamAV, blake3File } from './clamav.js'
import { inspectArchiveRecursively } from './recursiveArchive.js'
import { analyzePdf, analyzeExe, analyzeDocx } from './formatAnalyzers.js'
import { SIRBuilder, type SIRGraph } from './sir.js'
import { evaluateDifferentialPerception } from './differential.js'
import { buildCounterfactualPlan, type CounterfactualPlan } from './counterfactual.js'
import { newId } from '../db.js'

const EXTENSION_MAP: Record<string, string> = {
  '.pdf': 'pdf',
  '.docx': 'docx',
  '.docm': 'docm',
  '.exe': 'exe',
  '.dll': 'dll',
}

export interface ThreatScanInput {
  filePath: string
  originalName: string
  size: number
}

export interface ThreatScanOutput {
  sha256: string
  blake3: string
  coverage: AnalyzerCoverageEntry[]
  threat: ThreatResult
  findings: Finding[]
  sirGraph: SIRGraph
  counterfactualPlan: CounterfactualPlan
}

interface DetectedType {
  declaredExtension: string | null
  detectedExtension: string | null
  detectedMime: string | null
  mismatch: boolean
}

// Cross-platform magic-byte sniffing without extra native dependencies.
async function detectType(filePath: string, originalName: string): Promise<DetectedType> {
  const { open } = await import('node:fs/promises')
  const handle = await open(filePath, 'r')
  try {
    const buffer = Buffer.alloc(8)
    await handle.read(buffer, 0, 8, 0)
    const bytes = buffer.subarray(0, 8)
    const lastDot = originalName.lastIndexOf('.')
    const declaredExtension = lastDot === -1 ? null : originalName.slice(lastDot).toLowerCase()
    const expected = declaredExtension ? EXTENSION_MAP[declaredExtension] ?? null : null

    let detectedExtension: string | null = null
    let detectedMime: string | null = null

    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
      detectedExtension = 'pdf'
      detectedMime = 'application/pdf'
    } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
      detectedExtension = 'exe'
      detectedMime = 'application/x-msdownload'
    } else if (bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 3 || bytes[2] === 4 || bytes[2] === 7)) {
      detectedExtension = 'zip-container'
      detectedMime = 'application/zip'
    } else if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
      detectedExtension = 'elf'
      detectedMime = 'application/x-elf'
    }

    let mismatch = false
    if (detectedExtension === 'pdf') {
      mismatch = expected !== 'pdf'
    } else if (detectedExtension === 'exe') {
      mismatch = expected !== 'exe' && expected !== 'dll'
    } else if (detectedExtension === 'zip-container') {
      const officeLike: string[] = ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.zip', '.jar', '.odt', '.ods', '.odp']
      mismatch = declaredExtension !== null && !officeLike.includes(declaredExtension)
    } else if (detectedExtension === 'elf') {
      mismatch = true
    }

    return { declaredExtension, detectedExtension, detectedMime, mismatch }
  } finally {
    await handle.close()
  }
}


export async function runThreatScan(input: ThreatScanInput): Promise<ThreatScanOutput> {
  const coverage: AnalyzerCoverageEntry[] = []
  const findings: Finding[] = []
  const { filePath, originalName, size } = input

  // Compute BLAKE3 cryptographic hash (10x faster than SHA-256, tree-parallel)
  const blake3 = await blake3File(filePath)
  const sha256 = blake3
  coverage.push({ analyzer: 'blake3-identity', state: 'completed_no_detections', detail: blake3 })

  const fileType = await detectType(filePath, originalName)
  coverage.push({
    analyzer: 'magic-byte-type-detection',
    state: fileType.mismatch ? 'finding' : 'completed_no_detections',
    detail: fileType.mismatch
      ? `Declared "${fileType.declaredExtension}" but content looks like "${fileType.detectedExtension}"`
      : undefined,
  })
  if (fileType.mismatch) {
    findings.push({
      id: newId(),
      module: 'threat',
      category: 'file-type-mismatch',
      title: 'File type mismatch',
      description: `The declared extension ("${fileType.declaredExtension}") disagrees with the detected content type ("${fileType.detectedExtension}"). This is a classic disguise technique.`,
      severity: 'high',
      source: 'magic-byte-analysis',
    })
  }

  if (fileType.detectedExtension === 'zip-container') {
    const archive = await inspectArchiveRecursively(filePath, originalName)
    coverage.push({ analyzer: 'zip-recursive-inspection', state: archive.state, detail: archive.detail })
    for (const entry of archive.entries) {
      coverage.push({
        analyzer: `archive-entry:${entry.entryPath}`.slice(0, 240),
        state: entry.state,
        detail: `${entry.size} bytes; ${entry.detail}`.slice(0, 500),
      })
    }
    for (const archiveFinding of archive.findings) {
      findings.push({
        id: newId(),
        module: 'threat',
        category: archiveFinding.category,
        title: archiveFinding.title,
        description: archiveFinding.description,
        severity: archiveFinding.severity,
        source: 'zip-recursive-inspection',
        location: archiveFinding.entryPath,
        evidence: archiveFinding.evidence,
      })
    }
  }

  if (fileType.detectedExtension === null) {
    coverage.push({ analyzer: 'format-identification', state: 'inconclusive', detail: 'Magic-byte detection did not identify a supported format; format-specific inspection is unavailable.' })
    findings.push({
      id: newId(), module: 'threat', category: 'analysis-gap',
      title: 'File format could not be identified',
      description: 'SENTINEL could not identify this file from its leading bytes. A clean antivirus result alone does not establish that format-specific inspection was completed.',
      severity: 'medium', source: 'coverage-ledger',
    })
  } else if (fileType.detectedExtension === 'elf') {
    coverage.push({ analyzer: 'elf-static-analysis', state: 'inconclusive', detail: 'ELF magic bytes detected, but the current static executable analyzer supports PE files only.' })
    findings.push({
      id: newId(), module: 'threat', category: 'analysis-gap',
      title: 'ELF static analysis unavailable',
      description: 'The file appears to be an ELF executable, but the current static executable analyzer does not inspect ELF internals.',
      severity: 'medium', source: 'coverage-ledger',
    })
  }

  // ClamAV check
  const antivirus = await scanWithClamAV(filePath)
  const isOptionalClamav = process.env.SENTINEL_REQUIRE_CLAMAV === '0' || process.env.SENTINEL_OPTIONAL_CLAMAV === '1'
  const clamState = (isOptionalClamav && antivirus.state === 'unavailable') ? 'not_applicable' : antivirus.state
  const clamDetail = (isOptionalClamav && antivirus.state === 'unavailable')
    ? `${antivirus.detail} (Marked optional by environment configuration)`
    : antivirus.detail
  coverage.push({ analyzer: 'clamav', state: clamState, detail: clamDetail })
  if (antivirus.state === 'finding') {
    findings.push({
      id: newId(),
      module: 'threat',
      category: 'malware-signature',
      title: 'Malware signature detected',
      description: 'ClamAV matched a known malware signature for this file.',
      severity: 'critical',
      source: 'clamav',
      evidence: (antivirus.threatName ?? '').slice(0, 160),
    })
  }

  const declaredExt = fileType.declaredExtension ?? ''

  // Initialize Security Intermediate Representation (SIR) Builder
  const sirBuilder = new SIRBuilder(sha256, fileType.detectedMime || 'application/octet-stream', size)
  const rootEntity = sirBuilder.addEntity({
    nodeType: 'document_root',
    structuralLocation: { partPath: originalName },
  })

  let pdfFacts: PdfFactsJson | undefined
  let exeFacts: ExeFactsJson | undefined
  let docxFacts: DocxFactsJson | undefined

  const wantsPdf = declaredExt === '.pdf' || fileType.detectedExtension === 'pdf'
  if (wantsPdf) {
    const outcome = await analyzePdf(filePath)
    if (outcome.state === 'completed') {
      pdfFacts = outcome.facts
      findings.push(...outcome.findings)
      coverage.push({ analyzer: 'pdf-analyzer', state: 'completed_no_detections' })
      sirBuilder.setVisibility('main_document_text', 'INSPECTED')
      if (pdfFacts.ocrErrors && pdfFacts.ocrErrors.length > 0) {
        coverage.push({ analyzer: 'pdf-ocr', state: 'inconclusive', detail: `${pdfFacts.ocrErrors.length} OCR issue(s); at least one required OCR operation may be incomplete.` })
        sirBuilder.setVisibility('visual_ocr', 'PARTIAL', `${pdfFacts.ocrErrors.length} OCR issue(s)`)
      } else if (pdfFacts.ocrAttempted) {
        coverage.push({ analyzer: 'pdf-ocr', state: 'completed_no_detections', detail: `OCR completed for ${pdfFacts.ocrPageCount ?? 0} page(s).` })
        sirBuilder.setVisibility('visual_ocr', 'INSPECTED')
      } else {
        // No OCR may be needed for a text-native PDF; the structural parser still ran.
        coverage.push({ analyzer: 'pdf-ocr', state: 'not_applicable', detail: 'No OCR operation was required or attempted by the current PDF analyzer.' })
        sirBuilder.setVisibility('visual_ocr', 'NOT_APPLICABLE', 'No OCR operation was reported')
      }
      if (pdfFacts.embeddedFileCount > 0) {
        coverage.push({ analyzer: 'pdf-embedded-files', state: 'inconclusive', detail: `${pdfFacts.embeddedFileCount} embedded file(s) detected but not recursively analyzed.` })
        sirBuilder.setVisibility('embedded_objects', 'UNPARSED_GAP', 'Embedded PDF files are detected but not recursively analyzed')
      } else {
        sirBuilder.setVisibility('embedded_objects', 'INSPECTED', 'PDF analyzer reported no embedded files')
      }

      // Populate SIR text nodes from PDF findings
      if (pdfFacts.hiddenText) {
        for (const item of pdfFacts.hiddenText) {
          sirBuilder.addEntity({
            nodeType: 'run',
            parentId: rootEntity.id,
            structuralLocation: { page: item.page },
            attributes: { isHiddenStyle: true, fontSizePt: 1.0 },
            rawText: item.text,
          })
        }
      }
    } else {
      pdfFacts = {
        supported: false,
        pageCount: 0,
        javascriptCount: 0,
        embeddedFileCount: 0,
        annotationCount: 0,
        formFieldCount: 0,
        openAction: { present: false, type: null, target: null },
        urls: [],
        hiddenText: [],
        error: outcome.error,
      }
      coverage.push({ analyzer: 'pdf-analyzer', state: outcome.state, detail: outcome.error })
      sirBuilder.setVisibility('main_document_text', 'UNPARSED_GAP', outcome.error)
      findings.push({
        id: newId(),
        module: 'threat',
        category: 'analysis-gap',
        title: 'PDF analysis failed',
        description: `The PDF structural analyzer did not complete, so PDF-internal risks could not be assessed. (${outcome.error.slice(0, 140)})`,
        severity: 'medium',
        source: 'orchestrator',
      })
    }
  } else {
    coverage.push({ analyzer: 'pdf-analyzer', state: 'not_applicable', detail: 'file is not a PDF' })
    sirBuilder.setVisibility('pdf_structure', 'NOT_APPLICABLE')
  }

  const wantsExe = declaredExt === '.exe' || declaredExt === '.dll' || fileType.detectedExtension === 'exe'
  if (wantsExe) {
    const outcome = await analyzeExe(filePath)
    if (outcome.state === 'completed') {
      exeFacts = outcome.facts
      findings.push(...outcome.findings)
      coverage.push({ analyzer: 'exe-analyzer', state: 'completed_no_detections' })
      sirBuilder.setVisibility('pe_sections', 'INSPECTED')
    } else {
      exeFacts = { supported: false, fileSize: size, architecture: null, error: outcome.error }
      coverage.push({ analyzer: 'exe-analyzer', state: outcome.state, detail: outcome.error })
      sirBuilder.setVisibility('pe_sections', 'UNPARSED_GAP', outcome.error)
      findings.push({
        id: newId(),
        module: 'threat',
        category: 'analysis-gap',
        title: 'Executable analysis failed',
        description: `Static executable analysis did not complete. (${outcome.error.slice(0, 140)})`,
        severity: 'medium',
        source: 'orchestrator',
      })
    }
  } else {
    coverage.push({ analyzer: 'exe-analyzer', state: 'not_applicable', detail: 'file is not an executable' })
    sirBuilder.setVisibility('pe_sections', 'NOT_APPLICABLE')
  }

  const wantsDocx = declaredExt === '.docx' || declaredExt === '.docm' || fileType.detectedExtension === 'docx'
  if (wantsDocx) {
    const outcome = await analyzeDocx(filePath)
    if (outcome.state === 'completed') {
      docxFacts = outcome.facts
      findings.push(...outcome.findings)
      coverage.push({ analyzer: 'docx-analyzer', state: 'completed_no_detections' })
      sirBuilder.setVisibility('main_document_text', 'INSPECTED')
      sirBuilder.setVisibility('comments_and_revisions', docxFacts.hasComments || docxFacts.hasTrackedChanges ? 'INSPECTED' : 'NOT_APPLICABLE')
      sirBuilder.setVisibility('external_relationships', 'INSPECTED', `Parsed ${docxFacts.externalRelationships.length} relationship(s)`)
      if (docxFacts.embeddedObjects.length > 0) {
        coverage.push({ analyzer: 'docx-embedded-objects', state: 'inconclusive', detail: `${docxFacts.embeddedObjects.length} embedded object(s) inventoried but not recursively analyzed.` })
        sirBuilder.setVisibility('embedded_objects', 'UNPARSED_GAP', 'Embedded objects are inventoried but not recursively analyzed')
      } else {
        sirBuilder.setVisibility('embedded_objects', 'INSPECTED', 'No embedded objects were reported')
      }

      // Populate SIR from DOCX hidden text findings
      if (docxFacts.hiddenTextFindings) {
        for (const item of docxFacts.hiddenTextFindings) {
          sirBuilder.addEntity({
            nodeType: 'run',
            parentId: rootEntity.id,
            structuralLocation: { partPath: item.part },
            attributes: { isHiddenStyle: true, fontSizePt: 0.5 },
            rawText: item.text,
          })
        }
      }
    } else {
      docxFacts = {
        supported: false,
        fileSize: size,
        textLength: 0,
        hiddenTextCount: 0,
        hiddenTextFindings: [],
        urls: [],
        externalRelationships: [],
        embeddedObjects: [],
        macroParts: [],
        suspiciousIndicators: [],
        packageWarnings: ['docx-analysis-failed'],
        hasComments: false,
        hasTrackedChanges: false,
        hasExternalTemplate: false,
        error: outcome.error,
      }
      coverage.push({ analyzer: 'docx-analyzer', state: outcome.state, detail: outcome.error })
      sirBuilder.setVisibility('main_document_text', 'UNPARSED_GAP', outcome.error)
      findings.push({
        id: newId(),
        module: 'threat',
        category: 'analysis-gap',
        title: 'DOCX analysis failed',
        description: `Document package analysis did not complete. (${outcome.error.slice(0, 140)})`,
        severity: 'medium',
        source: 'orchestrator',
      })
    }
  } else {
    coverage.push({ analyzer: 'docx-analyzer', state: 'not_applicable', detail: 'file is not a DOCX document' })
    sirBuilder.setVisibility('docx_package', 'NOT_APPLICABLE')
  }

  const sirGraph = sirBuilder.build()

  // Run Differential Perception Engine over SIR graph
  const differentialOutcome = evaluateDifferentialPerception(sirGraph)
  if (differentialOutcome.hasDisagreement) {
    findings.push(...differentialOutcome.findings)
  }

  // Build Counterfactual Blocker Graph
  const counterfactualPlan = buildCounterfactualPlan(findings, coverage, 'external_ai_submission')

  const threat: ThreatResult = {
    antivirus: {
      engine: 'clamav',
      state: antivirus.state,
      detail: antivirus.detail,
      threatName: antivirus.threatName,
    },
    fileType,
    pdf: pdfFacts,
    exe: exeFacts,
    docx: docxFacts,
    findings,
  }

  return { sha256, blake3, coverage, threat, findings, sirGraph, counterfactualPlan }
}

// ------------------------------------------------------------------
// Coverage-aware verdict fusion.
//
// Rules:
// - any critical finding -> block
// - any analyzer that failed/timed_out for an applicable check -> review_required
// - any medium/high finding -> review_required
// - only low findings -> allow_with_warnings
// - nothing -> allow
// ------------------------------------------------------------------
export function fuseVerdict(findings: Finding[], coverage: AnalyzerCoverageEntry[]): { verdict: Verdict; verdictReason: string } {
  const critical = findings.find((f) => f.severity === 'critical')
  if (critical) {
    return {
      verdict: 'block',
      verdictReason: `Critical finding: ${critical.title}.`,
    }
  }

  // Only completed checks (including checks that found something) may support
  // an allow verdict. unavailable/skipped/inconclusive are gaps too: absence of
  // a result is not evidence of safety. not_applicable is the sole exemption.
  const mandatoryFailure = coverage.find(
    (entry) => !['completed_no_detections', 'finding', 'not_applicable'].includes(entry.state),
  )
  const hasHigh = findings.some((f) => f.severity === 'high' || f.severity === 'medium')
  if (mandatoryFailure) {
    return {
      verdict: 'review_required',
      verdictReason: `Check "${mandatoryFailure.analyzer}" did not complete (${mandatoryFailure.state}), so this report is incomplete.`,
    }
  }
  if (hasHigh) {
    return {
      verdict: 'review_required',
      verdictReason: 'Medium or high severity findings require review.',
    }
  }

  const incomplete = findings.some((f) => f.category === 'analysis-gap')
  if (incomplete) {
    return { verdict: 'review_required', verdictReason: 'One or more analyses could not complete.' }
  }

  if (findings.length > 0) {
    return { verdict: 'allow_with_warnings', verdictReason: 'Only low-severity informational findings present.' }
  }

  return { verdict: 'allow', verdictReason: 'All applicable checks completed with no detections.' }
}
