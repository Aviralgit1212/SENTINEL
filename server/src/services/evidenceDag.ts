import { blake3 } from '@noble/hashes/blake3.js'
import type { ScanReport } from '../types.js'

function blake3Hex(input: string): string {
  return Buffer.from(blake3(Buffer.from(input, 'utf8'))).toString('hex')
}

export type EvidenceNodeKind = 'artifact' | 'analyzer' | 'finding' | 'policy'
export interface EvidenceNode { id: string; kind: EvidenceNodeKind; label: string; state?: string; digest?: string; attributes?: Record<string, string | number | boolean | null> }
export interface EvidenceEdge { from: string; to: string; relation: 'analyzed' | 'produced' | 'informed' | 'decided' }
export interface EvidenceDag { schemaVersion: '1.0'; graphSha256: string; nodes: EvidenceNode[]; edges: EvidenceEdge[] }

/** Build a deterministic, content-minimized evidence graph from a stored report. */
export function buildEvidenceDag(report: ScanReport): EvidenceDag {
  const nodes: EvidenceNode[] = [{ id: `artifact:${report.sha256}`, kind: 'artifact', label: report.filename, digest: report.sha256, attributes: { size: report.size } }]
  const edges: EvidenceEdge[] = []
  for (const coverage of report.coverage) {
    const id = `analyzer:${coverage.analyzer}`
    nodes.push({ id, kind: 'analyzer', label: coverage.analyzer, state: coverage.state, attributes: { detail: coverage.detail?.slice(0, 240) ?? null } })
    edges.push({ from: `artifact:${report.sha256}`, to: id, relation: 'analyzed' })
  }
  const findings = report.threat?.findings ?? []
  for (const finding of findings) {
    const id = `finding:${finding.id}`
    const evidenceDigest = finding.evidence ? blake3Hex(finding.evidence) : undefined
    nodes.push({ id, kind: 'finding', label: finding.title, state: finding.severity, digest: evidenceDigest, attributes: { module: finding.module, category: finding.category, source: finding.source, location: finding.location ?? null } })
    edges.push({ from: `artifact:${report.sha256}`, to: id, relation: 'produced' })
    const analyzer = `analyzer:${report.coverage.find((c) => c.analyzer === finding.source)?.analyzer ?? finding.source.split('/')[0]}`
    if (nodes.some((node) => node.id === analyzer)) edges.push({ from: analyzer, to: id, relation: 'produced' })
  }
  const policyId = `policy:${report.scanId}`
  nodes.push({ id: policyId, kind: 'policy', label: report.verdict, state: report.verdict, attributes: { reason: report.verdictReason, policyVersion: report.assessment?.policyVersion ?? 'unknown' } })
  for (const node of nodes.filter((item) => item.kind === 'finding' || item.kind === 'analyzer')) edges.push({ from: node.id, to: policyId, relation: 'informed' })
  const canonical = JSON.stringify({ schemaVersion: '1.0', nodes, edges })
  return { schemaVersion: '1.0', graphSha256: blake3Hex(canonical), nodes, edges }
}
