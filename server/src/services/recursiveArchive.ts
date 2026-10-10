import fs from 'node:fs/promises'
import path from 'node:path'
import { inspectZipArchive, type ArchiveEntryMetadata } from './archiveArmor.js'
import { newTemporaryDirectory, cleanupTemporaryDirectory } from './workspace.js'
import { runArchiveWorker } from './archiveWorker.js'
import { scanWithClamAV } from './clamav.js'
import { analyzePdf, analyzeDocx, analyzeExe } from './formatAnalyzers.js'
import type { AnalyzerState, Finding } from '../types.js'

const MAX_DEPTH = 3
const MAX_ENTRIES_PER_SCAN = 2_000
const MAX_ENTRY_OUTPUT = 10 * 1024 * 1024
const MAX_TOTAL_OUTPUT = 50 * 1024 * 1024
const MAX_RATIO = 10

export interface RecursiveArchiveFinding {
  category: string
  title: string
  description: string
  severity: Finding['severity']
  evidence?: string
  entryPath: string
  depth: number
}
export interface RecursiveEntryResult {
  entryPath: string
  depth: number
  size: number
  sha256?: string
  state: AnalyzerState
  detail: string
}
export interface RecursiveArchiveResult {
  state: AnalyzerState
  detail: string
  entriesVisited: number
  bytesExpanded: number
  findings: RecursiveArchiveFinding[]
  entries: RecursiveEntryResult[]
}

async function extractEntryBounded(
  archivePath: string,
  entry: ArchiveEntryMetadata,
  destination: string,
  remainingTotal: number,
): Promise<{ bytes: number; detail: string; sandboxed: boolean }> {
  if (entry.flags & 0x0001) throw new Error('encrypted entry cannot be decrypted by this worker')
  if (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) throw new Error(`unsupported compression method ${entry.compressionMethod}`)
  if (entry.uncompressedSize > MAX_ENTRY_OUTPUT) throw new Error(`entry declared size exceeds ${MAX_ENTRY_OUTPUT} bytes`)
  if (entry.uncompressedSize > remainingTotal) throw new Error('archive expansion budget exhausted')
  if (entry.uncompressedSize > 0 && (entry.compressedSize === 0 || entry.uncompressedSize / Math.max(1, entry.compressedSize) > MAX_RATIO)) {
    throw new Error(`declared compression ratio exceeds ${MAX_RATIO}:1`)
  }
  if (!Number.isSafeInteger(entry.dataOffset + entry.compressedSize)) throw new Error('entry byte range exceeds safe integer bounds')
  const result = await runArchiveWorker({
    archivePath, destination, dataOffset: entry.dataOffset, compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize, crc32: entry.crc32, method: entry.compressionMethod,
    remainingTotal,
  })
  return { bytes: result.bytes, sandboxed: result.sandboxed, detail: `isolated worker decompressed and CRC-32 verified (${result.bytes} bytes; ${result.sandboxed ? 'bubblewrap namespace sandbox' : 'explicit development-only prlimit fallback'})` }
}

async function scanExtractedFile(filePath: string, entryPath: string, depth: number, budget: { entries: number; expandedBytes: number }): Promise<{ state: AnalyzerState; detail: string; findings: RecursiveArchiveFinding[]; nested?: RecursiveArchiveResult }> {
  const findings: RecursiveArchiveFinding[] = []
  const av = await scanWithClamAV(filePath)
  if (av.state === 'finding') findings.push({ category: 'archive-structure-anomaly', title: 'Malware signature in archived entry', description: `ClamAV detected a threat in archived entry ${entryPath}.`, severity: 'critical', evidence: (av.threatName ?? '').slice(0, 160), entryPath, depth })

  const handle = await fs.open(filePath, 'r')
  let head: Buffer
  try {
    head = Buffer.alloc(8)
    const read = await handle.read(head, 0, 8, 0)
    head = head.subarray(0, read.bytesRead)
  } finally { await handle.close() }

  let state: AnalyzerState = av.state
  const detailParts = [`ClamAV: ${av.state}`]
  if (head.subarray(0, 4).toString('ascii') === '%PDF') {
    const result = await analyzePdf(filePath)
    if (result.state === 'completed') {
      detailParts.push(`PDF structural analysis completed (${result.facts.pageCount} page(s))`)
      for (const finding of result.findings) findings.push({ category: finding.category, title: finding.title, description: finding.description, severity: finding.severity, evidence: finding.evidence, entryPath, depth })
    } else { state = result.state; detailParts.push(`PDF analyzer ${result.state}: ${result.error}`) }
  } else if (head[0] === 0x4d && head[1] === 0x5a) {
    const result = await analyzeExe(filePath)
    if (result.state === 'completed') {
      detailParts.push('PE static analysis completed')
      for (const finding of result.findings) findings.push({ category: finding.category, title: finding.title, description: finding.description, severity: finding.severity, evidence: finding.evidence, entryPath, depth })
    } else { state = result.state === 'not_applicable' ? 'inconclusive' : result.state; detailParts.push(`PE analyzer ${result.state}: ${result.error}`) }
  } else if (head[0] === 0x50 && head[1] === 0x4b && (head[2] === 3 || head[2] === 5 || head[2] === 7)) {
    if (/\.docm?$/i.test(entryPath)) {
      const docx = await analyzeDocx(filePath)
      if (docx.state === 'completed') {
        detailParts.push(`DOCX package analysis completed (${docx.facts.textLength} text characters)`)
        for (const finding of docx.findings) findings.push({ category: finding.category, title: finding.title, description: finding.description, severity: finding.severity, evidence: finding.evidence, entryPath, depth })
      } else {
        state = docx.state
        detailParts.push(`DOCX analyzer ${docx.state}: ${docx.error}`)
      }
    }
    if (depth >= MAX_DEPTH) { state = 'inconclusive'; detailParts.push(`Nested container depth limit (${MAX_DEPTH}) reached`) }
    else {
      const nested = await inspectArchiveRecursively(filePath, entryPath, depth + 1, budget)
      detailParts.push(`Nested container: ${nested.entriesVisited} entries; ${nested.state}`)
      findings.push(...nested.findings)
      let combinedState = nested.state
      if (av.state === 'finding' || nested.state === 'finding') combinedState = 'finding'
      else if (av.state !== 'completed_no_detections' && nested.state === 'completed_no_detections') combinedState = av.state
      else if (state === 'inconclusive' || nested.state === 'inconclusive') combinedState = 'inconclusive'
      return { state: combinedState, detail: detailParts.join('; '), findings, nested }
    }
  }
  if (av.state === 'finding') state = 'finding'
  else if (av.state !== 'completed_no_detections' && state === 'completed_no_detections') state = av.state
  return { state, detail: detailParts.join('; '), findings }
}

/**
 * Bounded recursive ZIP inspection. Each member is streamed to a unique RAM-vault
 * file, decoded under actual-output limits, checked for size/CRC consistency,
 * scanned with ClamAV, and sent to the existing PDF/PE analyzers or recursively
 * inspected when it is another ZIP. Unsupported/encrypted members remain gaps.
 */
export async function inspectArchiveRecursively(
  archivePath: string,
  displayPath = path.basename(archivePath),
  depth = 0,
  budget: { entries: number; expandedBytes: number } = { entries: 0, expandedBytes: 0 },
): Promise<RecursiveArchiveResult> {
  const findings: RecursiveArchiveFinding[] = []
  const entries: RecursiveEntryResult[] = []
  if (depth > MAX_DEPTH) return { state: 'inconclusive', detail: 'Maximum nested archive depth exceeded.', entriesVisited: 0, bytesExpanded: 0, findings, entries }

  const metadata = await inspectZipArchive(archivePath)
  findings.push(...metadata.findings.map((f) => ({ ...f, entryPath: displayPath, depth })))
  if (!metadata.entries) return { state: metadata.state === 'completed_no_detections' ? 'inconclusive' : metadata.state, detail: metadata.detail, entriesVisited: 0, bytesExpanded: 0, findings, entries }

  let state: AnalyzerState = metadata.state
  let expandedHere = 0
  const expandedAtStart = budget.expandedBytes
  for (const item of metadata.entries) {
    budget.entries += 1
    const entryPath = `${displayPath}!/${item.name}`
    if (budget.entries > MAX_ENTRIES_PER_SCAN) {
      findings.push({ category: 'archive-structure-anomaly', title: 'Recursive archive entry budget exceeded', description: `The artifact exceeded the ${MAX_ENTRIES_PER_SCAN}-entry recursive inspection budget. Remaining members were not inspected.`, severity: 'high', entryPath, depth })
      entries.push({ entryPath, depth, size: item.uncompressedSize, state: 'inconclusive', detail: 'Global entry-count budget exceeded; member not extracted.' })
      state = 'inconclusive'
      break
    }
    if (item.isDirectory) {
      entries.push({ entryPath, depth, size: 0, state: 'completed_no_detections', detail: 'Directory entry; no payload to scan.' })
      continue
    }
    if (item.uncompressedSize > MAX_TOTAL_OUTPUT - budget.expandedBytes) {
      findings.push({ category: 'archive-decompression-bomb', title: 'Recursive expansion budget exhausted', description: `Further extraction would exceed the ${MAX_TOTAL_OUTPUT}-byte aggregate decoded-data budget.`, severity: 'high', entryPath, depth })
      entries.push({ entryPath, depth, size: item.uncompressedSize, state: 'inconclusive', detail: 'Global expansion budget exhausted; member not extracted.' })
      state = 'inconclusive'
      break
    }

    let workerDir: string | undefined
    try {
      workerDir = await newTemporaryDirectory()
      const tempPath = path.join(workerDir, 'member.bin')
      const extracted = await extractEntryBounded(archivePath, item, tempPath, MAX_TOTAL_OUTPUT - budget.expandedBytes)
      budget.expandedBytes += extracted.bytes
      expandedHere += extracted.bytes
      const scanned = await scanExtractedFile(tempPath, entryPath, depth, budget)
      findings.push(...scanned.findings)
      entries.push({ entryPath, depth, size: extracted.bytes, state: scanned.state, detail: `${extracted.detail}; ${scanned.detail}` })
      if (scanned.nested) entries.push(...scanned.nested.entries)
      if (scanned.state === 'finding') state = 'finding'
      else if (!['completed_no_detections', 'finding', 'not_applicable'].includes(scanned.state) && state !== 'finding') state = 'inconclusive'
      if (scanned.nested && scanned.nested.state === 'inconclusive' && state !== 'finding') state = 'inconclusive'
    } catch (error) {
      const detail = error instanceof Error ? error.message.slice(0, 220) : 'unknown extraction failure'
      findings.push({ category: 'archive-structure-anomaly', title: 'Archive member could not be safely inspected', description: `Member extraction or verification failed: ${detail}. The member was not treated as clean.`, severity: 'medium', entryPath, depth })
      entries.push({ entryPath, depth, size: item.uncompressedSize, state: 'inconclusive', detail })
      if (state !== 'finding') state = 'inconclusive'
    } finally {
      if (workerDir) await cleanupTemporaryDirectory(workerDir)
    }
  }
  if (metadata.state === 'finding') state = 'finding'
  else if (metadata.state !== 'completed_no_detections' && state === 'completed_no_detections') state = metadata.state
  const gapCount = entries.filter((entry) => !['completed_no_detections', 'finding', 'not_applicable'].includes(entry.state)).length
  return {
    state,
    detail: `${metadata.entryCount ?? 0} direct member(s); ${entries.length} member result(s) recorded; ${expandedHere} bytes expanded at depth ${depth}; ${gapCount} member gap(s). Nested data was inspected only within explicit resource limits.`,
    entriesVisited: entries.length,
    bytesExpanded: budget.expandedBytes - expandedAtStart,
    findings,
    entries,
  }
}
