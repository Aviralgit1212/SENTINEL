import { DatabaseSync } from 'node:sqlite'
import { mkdirSync } from 'node:fs'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import type { ScanReport } from './types.js'

// Node >=22.5 ships an experimental built-in SQLite driver (node:sqlite).
// Using it avoids native builds entirely — the environment stays reproducible.

const dataDir = path.resolve(process.cwd(), 'data')
mkdirSync(dataDir, { recursive: true })

const db = new DatabaseSync(path.join(dataDir, 'sentinel.db'))

db.exec(`
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  verdict TEXT NOT NULL,
  report_json TEXT NOT NULL,
  engine_version TEXT NOT NULL DEFAULT 'unknown',
  ruleset_version TEXT NOT NULL DEFAULT 'unknown',
  policy_version TEXT NOT NULL DEFAULT 'unknown'
)
`)

// Idempotent migrations for databases created by earlier SENTINEL stages.
const existingColumns = new Set((db.prepare('PRAGMA table_info(scans)').all() as Array<{ name: string }>).map((column) => column.name))
for (const [name, declaration] of [
  ['engine_version', "TEXT NOT NULL DEFAULT 'unknown'"],
  ['ruleset_version', "TEXT NOT NULL DEFAULT 'unknown'"],
  ['policy_version', "TEXT NOT NULL DEFAULT 'unknown'"],
] as const) {
  if (!existingColumns.has(name)) db.exec(`ALTER TABLE scans ADD COLUMN ${name} ${declaration}`)
}
try {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256)`)
  db.exec(`CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)`)
} catch {
  // indexes are best-effort
}

export interface ScanRow {
  scan_id: string
  created_at: string
  filename: string
  size: number
  sha256: string
  verdict: string
  report_json: string
}

const insertStmt = db.prepare(`
  INSERT INTO scans (scan_id, created_at, filename, size, sha256, verdict, report_json, engine_version, ruleset_version, policy_version)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`)

const byIdStmt = db.prepare(`SELECT * FROM scans WHERE scan_id = ?`)
const byHashStmt = db.prepare(`
  SELECT scan_id, created_at, filename, size, sha256, verdict, engine_version, ruleset_version, policy_version
  FROM scans WHERE sha256 = ? ORDER BY created_at DESC LIMIT 50
`)
const recentStmt = db.prepare(`
  SELECT scan_id, created_at, filename, size, sha256, verdict, engine_version, ruleset_version, policy_version
  FROM scans ORDER BY created_at DESC LIMIT 100
`)
const deleteStmt = db.prepare(`DELETE FROM scans WHERE scan_id = ?`)
const deleteAllStmt = db.prepare(`DELETE FROM scans`)

/** Persist a minimized report: never retain raw privacy entity text or evidence snippets. */
export function minimizePersistedReport(report: ScanReport): ScanReport {
  const minimized: ScanReport = {
    ...report,
    // The persisted copy is a metadata/evidence index, not a document-content vault.
    signatureHmac: undefined,
    sirGraph: report.sirGraph ? {
      ...report.sirGraph,
      entities: Object.fromEntries(Object.entries(report.sirGraph.entities).map(([id, entity]) => [id, {
        ...entity,
        rawText: entity.rawText === undefined ? undefined : '[WITHHELD]',
        normalizedText: entity.normalizedText === undefined ? undefined : '[WITHHELD]',
        rawBytesRef: undefined,
      }])),
    } : undefined,
    threat: report.threat ? {
      ...report.threat,
      findings: report.threat.findings.map((finding) => ({ ...finding, evidence: undefined })),
      pdf: report.threat.pdf ? {
        ...report.threat.pdf,
        hiddenText: report.threat.pdf.hiddenText.map((item) => ({ ...item, text: '[WITHHELD]' })),
      } : undefined,
      docx: report.threat.docx ? {
        ...report.threat.docx,
        hiddenTextFindings: report.threat.docx.hiddenTextFindings.map((item) => ({ ...item, text: '[WITHHELD]' })),
      } : undefined,
    } : null,
    privacy: report.privacy ? {
      ...report.privacy,
      entities: report.privacy.entities.map((entity) => ({ ...entity, text: '[WITHHELD]' })),
      redactedText: null,
    } : null,
  }
  return minimized
}

export function saveScanReport(report: ScanReport): string {
  const persisted = minimizePersistedReport(report)
  insertStmt.run(
    report.scanId,
    report.createdAt,
    report.filename,
    report.size,
    report.sha256,
    report.verdict,
    JSON.stringify(persisted),
    report.assessment?.engineVersion ?? 'unknown',
    report.assessment?.rulesetVersion ?? 'unknown',
    report.assessment?.policyVersion ?? 'unknown',
  )
  return report.scanId
}

export function getScanRow(scanId: string): ScanRow | undefined {
  return byIdStmt.get(scanId) as ScanRow | undefined
}

export function getScanReport(scanId: string): ScanReport | null {
  const row = getScanRow(scanId)
  return row ? (JSON.parse(row.report_json) as ScanReport) : null
}

export interface HistoryEntry {
  scan_id: string
  created_at: string
  filename: string
  size: number
  sha256: string
  verdict: string
  engine_version: string
  ruleset_version: string
  policy_version: string
}

export function historyForHash(sha256: string): HistoryEntry[] {
  return byHashStmt.all(sha256) as unknown as HistoryEntry[]
}

export function recentScans(): HistoryEntry[] {
  return recentStmt.all() as unknown as HistoryEntry[]
}

export function deleteScan(scanId: string): boolean {
  return Number(deleteStmt.run(scanId).changes) > 0
}

export function clearHistory(): number {
  return Number(deleteAllStmt.run().changes)
}

export function newId(): string {
  return randomUUID()
}
