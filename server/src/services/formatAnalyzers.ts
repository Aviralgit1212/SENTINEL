import { runPythonJson } from './pythonAnalyzer.js'
import type { PdfFactsJson, ExeFactsJson, DocxFactsJson, Finding, EvidenceInput } from '../types.js'
import { findingFromEvidence } from '../types.js'

const TIMEOUT_MS = 60_000
const MAX_STDOUT = 2_000_000

export type PdfAnalyzerOutcome =
  | { state: 'completed'; facts: PdfFactsJson; findings: Finding[] }
  | { state: 'failed' | 'timed_out'; error: string }

interface PythonPdfResult {
  pageCount?: number
  urls?: string[]
  javascriptCount?: number
  embeddedFileCount?: number
  annotationCount?: number
  formFieldCount?: number
  openAction?: { present?: boolean; type?: string | null; target?: string | null }
  hiddenText?: { count?: number; items?: Array<{ page?: number; text?: string; reasons?: string[]; contentSignals?: string[] }> }
  ocrAvailable?: boolean
  ocrAttempted?: boolean
  ocrPageCount?: number
  ocrErrors?: Array<{ page?: number; error?: string }>
  extractedTextLength?: number
  textSource?: 'native' | 'ocr' | 'mixed' | 'none'
  error?: string
  ok?: boolean
}

export async function analyzePdf(filePath: string): Promise<PdfAnalyzerOutcome> {
  const run = await runPythonJson<PythonPdfResult>('analyze_pdf.py', [filePath], {
    timeoutMs: TIMEOUT_MS,
    maxStdoutChars: MAX_STDOUT,
  })

  if (!run.ok || !run.data) {
    return { state: run.timedOut ? 'timed_out' : 'failed', error: run.error || 'unknown' }
  }

  const p = run.data
  const facts: PdfFactsJson = {
    supported: true,
    pageCount: p.pageCount ?? 0,
    javascriptCount: p.javascriptCount ?? 0,
    embeddedFileCount: p.embeddedFileCount ?? 0,
    annotationCount: p.annotationCount ?? 0,
    formFieldCount: p.formFieldCount ?? 0,
    openAction: {
      present: p.openAction?.present ?? false,
      type: p.openAction?.type ?? null,
      target: p.openAction?.target ?? null,
    },
    urls: p.urls ?? [],
    hiddenText: (p.hiddenText?.items ?? []).map((item) => ({
      page: item.page ?? 0,
      text: (item.text ?? '').slice(0, 200),
      reasons: item.reasons ?? [],
      contentSignals: item.contentSignals ?? [],
    })),
    ocrAvailable: p.ocrAvailable,
    ocrAttempted: p.ocrAttempted,
    ocrPageCount: p.ocrPageCount,
    ocrErrors: (p.ocrErrors ?? []).map((item) => ({ page: item.page, error: (item.error ?? 'OCR failed').slice(0, 200) })),
    extractedTextLength: p.extractedTextLength,
    textSource: p.textSource,
  }

  const findings = buildPdfFindings(facts)
  return { state: 'completed', facts, findings }
}

function buildPdfFindings(facts: PdfFactsJson): Finding[] {
  const inputs: EvidenceInput[] = []

  if (facts.openAction.present) {
    const type = facts.openAction.type || 'Unknown'
    inputs.push({
      category: type.toLowerCase() === 'launch' ? 'pdf-launch-action' : 'pdf-open-action',
      title: `PDF OpenAction (${type})`,
      description:
        type.toLowerCase() === 'launch'
          ? 'The PDF automatically runs a Launch action when opened, which can start an external program.'
          : `The PDF runs an automatic ${type} action when opened.`,
      severity: type.toLowerCase() === 'launch' ? 'high' : 'medium',
      source: 'analyze_pdf/structure',
      location: 'document-level OpenAction',
      evidence: facts.openAction.target ? String(facts.openAction.target).slice(0, 120) : type,
    })
  }

  if (facts.javascriptCount > 0) {
    inputs.push({
      category: 'pdf-javascript',
      title: 'PDF contains JavaScript',
      description: `The PDF parser identified ${facts.javascriptCount} JavaScript-related structure(s). JavaScript in PDFs is a common obfuscation and exploit vector.`,
      severity: 'high',
      source: 'analyze_pdf/structure',
      location: 'document-level JavaScript objects',
    })
  }

  if (facts.embeddedFileCount > 0) {
    inputs.push({
      category: 'pdf-embedded-files',
      title: 'PDF embeds other files',
      description: `${facts.embeddedFileCount} embedded file(s) detected inside the PDF package.`,
      severity: 'medium',
      source: 'analyze_pdf/structure',
    })
  }

  for (const hidden of facts.hiddenText) {
    const isInjection = hidden.contentSignals.includes('prompt-injection')
    inputs.push({
      category: isInjection ? 'pdf-prompt-injection' : 'pdf-hidden-text',
      title: isInjection ? 'Hidden text contains AI-targeted instructions' : 'Hidden or invisible text detected',
      description: isInjection
        ? 'The PDF contains deliberately hidden text whose content looks like instructions aimed at an AI system (for example, "ignore previous instructions"). This is contextual content-risk evidence, not proof of malware.'
        : `Text is present in the PDF but not visible when rendered (reasons: ${hidden.reasons.join(', ') || 'unknown'}).`,
      severity: isInjection ? 'high' : 'medium',
      source: 'analyze_pdf/hidden-text',
      location: `page ${hidden.page}`,
      evidence: hidden.text.slice(0, 160),
    })
  }

  for (const url of facts.urls.slice(0, 20)) {
    inputs.push({
      category: 'pdf-url',
      title: 'External URL reference',
      description: 'The PDF contains a hyperlink to an external resource. Inspect the destination before trusting the document.',
      severity: 'low',
      source: 'analyze_pdf/links',
      evidence: url.slice(0, 160),
    })
  }

  return inputs.map(findingFromEvidence)
}

// --------------------------------------------------------------------
// EXE
// --------------------------------------------------------------------

export type ExeAnalyzerOutcome =
  | { state: 'completed'; facts: ExeFactsJson; findings: Finding[] }
  | { state: 'failed' | 'timed_out' | 'not_applicable'; error: string }

interface PythonExeResult {
  fileSize?: number
  architecture?: string | null
  imports?: string[]
  suspiciousImports?: string[]
  urls?: string[]
  ipAddresses?: string[]
  highEntropySections?: string[]
  structuralWarnings?: string[]
  error?: string
  ok?: boolean
}

export async function analyzeExe(filePath: string): Promise<ExeAnalyzerOutcome> {
  const run = await runPythonJson<PythonExeResult>('analyze_exe.py', [filePath], {
    timeoutMs: 30_000,
    maxStdoutChars: MAX_STDOUT,
  })

  if (!run.ok || !run.data) {
    if ((run.error || '').toLowerCase().includes('not a valid pe')) {
      return { state: 'not_applicable', error: run.error || 'not a valid PE' }
    }
    return { state: run.timedOut ? 'timed_out' : 'failed', error: run.error || 'unknown' }
  }

  const p = run.data
  const facts: ExeFactsJson = {
    supported: true,
    fileSize: p.fileSize ?? 0,
    architecture: p.architecture ?? null,
    imports: (p.imports ?? []).slice(0, 60),
    suspiciousImports: p.suspiciousImports ?? [],
    urls: p.urls ?? [],
    ipAddresses: p.ipAddresses ?? [],
    highEntropySections: p.highEntropySections ?? [],
    structuralWarnings: p.structuralWarnings ?? [],
  }

  const inputs: EvidenceInput[] = []

  if (facts.suspiciousImports && facts.suspiciousImports.length > 0) {
    inputs.push({
      category: 'exe-suspicious-imports',
      title: 'Suspicious imported functions',
      description: 'The executable imports APIs commonly associated with process injection, keylogging, or anti-analysis.',
      severity: 'high',
      source: 'analyze_exe/imports',
      evidence: facts.suspiciousImports.join(', ').slice(0, 200),
    })
  }

  if (facts.highEntropySections && facts.highEntropySections.length > 0) {
    inputs.push({
      category: 'exe-high-entropy',
      title: 'High-entropy sections (possible packing)',
      description: `High entropy in: ${facts.highEntropySections.join(', ')}. Packing is a heuristic, not proof of malicious intent.`,
      severity: 'medium',
      source: 'analyze_exe/sections',
    })
  }

  if (facts.structuralWarnings && facts.structuralWarnings.length > 0) {
    inputs.push({
      category: 'exe-structural',
      title: 'PE structural anomalies',
      description: 'The PE structure contains anomalies that warrant review.',
      severity: 'medium',
      source: 'analyze_exe/structure',
      evidence: facts.structuralWarnings.join(', ').slice(0, 200),
    })
  }

  for (const url of (facts.urls ?? []).slice(0, 20)) {
    inputs.push({
      category: 'exe-url',
      title: 'URL embedded in binary',
      description: 'The binary contains an embedded URL, often associated with downloaders or command-and-control endpoints.',
      severity: 'medium',
      source: 'analyze_exe/strings',
      evidence: url.slice(0, 160),
    })
  }

  for (const ip of (facts.ipAddresses ?? []).slice(0, 20)) {
    inputs.push({
      category: 'exe-ip',
      title: 'Embedded IP address',
      description: 'The binary contains an embedded IP address, often associated with command-and-control endpoints.',
      severity: 'medium',
      source: 'analyze_exe/strings',
      evidence: ip,
    })
  }

  return { state: 'completed', facts, findings: inputs.map(findingFromEvidence) }
}

// --------------------------------------------------------------------
// DOCX
// --------------------------------------------------------------------

export type DocxAnalyzerOutcome =
  | { state: 'completed'; facts: DocxFactsJson; findings: Finding[] }
  | { state: 'failed' | 'timed_out'; error: string }

interface PythonDocxResult {
  fileSize?: number
  documentTextLength?: number
  hiddenTextCount?: number
  hiddenText?: Array<{ part?: string; textPreview?: string; reasons?: string[]; contentSignals?: string[] }>
  urls?: string[]
  externalRelationships?: Array<{ sourcePart?: string; target?: string; relationshipType?: string }>
  embeddedObjects?: Array<{ name?: string; size?: number; type?: string }>
  macroParts?: string[]
  suspiciousIndicators?: string[]
  packageWarnings?: string[]
  hasComments?: boolean
  hasTrackedChanges?: boolean
  hasExternalTemplate?: boolean
  error?: string
  ok?: boolean
}

export async function analyzeDocx(filePath: string): Promise<DocxAnalyzerOutcome> {
  const run = await runPythonJson<PythonDocxResult>('analyze_docx.py', [filePath], {
    timeoutMs: 30_000,
    maxStdoutChars: MAX_STDOUT,
  })

  if (!run.ok || !run.data) {
    return { state: run.timedOut ? 'timed_out' : 'failed', error: run.error || 'unknown' }
  }

  const p = run.data
  const facts: DocxFactsJson = {
    supported: true,
    fileSize: p.fileSize ?? 0,
    textLength: p.documentTextLength ?? 0,
    hiddenTextCount: p.hiddenTextCount ?? 0,
    hiddenTextFindings: (p.hiddenText ?? []).map((item) => ({
      part: item.part,
      text: (item.textPreview ?? '').slice(0, 200),
      reasons: item.reasons ?? [],
      contentSignals: item.contentSignals ?? [],
    })),
    urls: p.urls ?? [],
    externalRelationships: (p.externalRelationships ?? []).map((item) => ({
      source: item.sourcePart ?? '',
      target: item.target ?? '',
      relationshipType: item.relationshipType,
    })),
    embeddedObjects: (p.embeddedObjects ?? []).map((item, index) => {
      const name = item.name ?? `embedded-object-${index + 1}`
      const executableExtension = /\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|hta|com|msi)$/i
      const executableType = /x-msdownload|x-dosexec|x-executable|x-sharedlib|x-msdos-program/i
      return {
        name,
        size: item.size,
        isExecutableLike: executableExtension.test(name) || executableType.test(item.type ?? ''),
      }
    }),
    macroParts: p.macroParts ?? [],
    suspiciousIndicators: p.suspiciousIndicators ?? [],
    packageWarnings: p.packageWarnings ?? [],
    hasComments: p.hasComments ?? false,
    hasTrackedChanges: p.hasTrackedChanges ?? false,
    hasExternalTemplate: p.hasExternalTemplate ?? false,
  }

  const inputs: EvidenceInput[] = []

  if (facts.macroParts.length > 0) {
    inputs.push({
      category: 'docx-macros',
      title: 'Macro-enabled document',
      description: `The document contains macro part(s): ${facts.macroParts.join(', ').slice(0, 120)}. Macros are a primary Office malware delivery mechanism.`,
      severity: 'high',
      source: 'analyze_docx/package',
    })
  }

  if (facts.hasExternalTemplate) {
    inputs.push({
      category: 'docx-external-template',
      title: 'External template reference',
      description: 'The document references an external template url, a known remote-payload technique.',
      severity: 'high',
      source: 'analyze_docx/relationships',
    })
  }

  for (const object of facts.embeddedObjects) {
    if (object.isExecutableLike) {
      inputs.push({
        category: 'docx-embedded-executable',
        title: 'Embedded executable object',
        description: `The document embeds "${object.name}", which looks like an executable. This warrants urgent review.`,
        severity: 'critical',
        source: 'analyze_docx/package',
        location: object.name,
      })
    }
  }

  for (const hidden of facts.hiddenTextFindings) {
    const isInjection = hidden.contentSignals.includes('prompt-injection-like-instruction')
    inputs.push({
      category: isInjection ? 'docx-prompt-injection' : 'docx-hidden-text',
      title: isInjection ? 'Hidden text contains AI-targeted instructions' : 'Hidden text in document',
      description: isInjection
        ? 'Hidden document text looks like instructions aimed at an AI system (e.g., "disregard prior instructions"). Contextual content-risk evidence, not proof of malware.'
        : 'Document contains text that is not shown to the reader.',
      severity: isInjection ? 'high' : 'medium',
      source: 'analyze_docx/hidden-text',
      location: hidden.part,
      evidence: hidden.text.slice(0, 160),
    })
  }

  if (facts.suspiciousIndicators.length > 0) {
    for (const indicator of facts.suspiciousIndicators.slice(0, 10)) {
      if (indicator === 'prompt-injection-like-instruction' || indicator === 'suspicious-content-in-hidden-text') continue
      inputs.push({
        category: 'docx-suspicious',
        title: 'Suspicious content indicator',
        description: 'The document profiler flagged a suspicious indicator.',
        severity: 'medium',
        source: 'analyze_docx/content',
        evidence: indicator,
      })
    }
  }

  for (const rel of facts.externalRelationships.slice(0, 20)) {
    if (/^https?:/i.test(rel.target)) {
      inputs.push({
        category: 'docx-external-link',
        title: 'External hyperlink relationship',
        description: 'The document links to an external resource.',
        severity: 'low',
        source: 'analyze_docx/relationships',
        evidence: rel.target.slice(0, 160),
      })
    }
  }

  return { state: 'completed', facts, findings: inputs.map(findingFromEvidence) }
}
