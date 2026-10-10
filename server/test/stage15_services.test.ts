import test from 'node:test'
import assert from 'node:assert/strict'
import { auditSource } from '../src/services/codeAudit.js'
import { buildEvidenceDag } from '../src/services/evidenceDag.js'
import { fuseVerdict } from '../src/services/threatService.js'
import { runToolchainAudit } from '../src/services/toolchainAudit.js'
import type { ScanReport } from '../src/types.js'

test('Stage 15 source audit reports likely credential and unsafe TLS patterns without executing source', () => {
  const result = auditSource('const key = "AKIA1234567890ABCDEF";\nconst opts = { rejectUnauthorized: false };', 'app.ts')
  assert.equal(result.state, 'completed')
  assert.equal(result.languageHint, 'typescript')
  assert.ok(result.findings.some((f) => f.category === 'hardcoded-cloud-key' && f.severity === 'critical'))
  assert.ok(result.findings.some((f) => f.category === 'tls-verification-disabled'))
  assert.ok(result.limitations.length >= 3)
  assert.equal(result.sha256.length, 64)
})

test('Stage 15 evidence graph is deterministic and links artifact, analyzer, finding, and policy', () => {
  const report: ScanReport = {
    scanId: 'scan-1', createdAt: '2026-01-01T00:00:00.000Z', filename: 'x.bin', size: 3, sha256: 'a'.repeat(64),
    coverage: [{ analyzer: 'format-identification', state: 'inconclusive', detail: 'unknown bytes' }],
    threat: { antivirus: { engine: 'clamav', state: 'unavailable', detail: 'not installed' }, fileType: { declaredExtension: '.bin', detectedExtension: null, detectedMime: null, mismatch: false }, findings: [{ id: 'f-1', module: 'threat', category: 'unknown-format', title: 'Unknown format', description: 'Review required', severity: 'medium', source: 'format-identification' }] },
    privacy: null, verdict: 'review_required', verdictReason: 'Coverage incomplete', assessment: { engineVersion: '1', rulesetVersion: '1', policyVersion: '1' },
  }
  const a = buildEvidenceDag(report)
  const b = buildEvidenceDag(report)
  assert.equal(a.graphSha256, b.graphSha256)
  assert.ok(a.nodes.some((n) => n.kind === 'artifact'))
  assert.ok(a.nodes.some((n) => n.kind === 'finding'))
  assert.ok(a.nodes.some((n) => n.kind === 'policy' && n.state === 'review_required'))
  assert.ok(a.edges.some((e) => e.relation === 'informed'))
})

test('fail-closed verdict fusion never allows incomplete analyzer coverage', () => {
  const result = fuseVerdict([], [{ analyzer: 'pdf', state: 'unavailable' }])
  assert.equal(result.verdict, 'review_required')
})


test('Stage 16 optional scanner integration distinguishes unavailable tools from a clean audit', async () => {
  const previousConfig = process.env.SENTINEL_SEMGREP_CONFIG
  const previousGitleaks = process.env.SENTINEL_GITLEAKS_BIN
  const previousSemgrep = process.env.SENTINEL_SEMGREP_BIN
  process.env.SENTINEL_SEMGREP_CONFIG = ''
  process.env.SENTINEL_GITLEAKS_BIN = '/definitely/missing/gitleaks'
  process.env.SENTINEL_SEMGREP_BIN = '/definitely/missing/semgrep'
  try {
    const result = await runToolchainAudit('const x = 1', 'example.ts')
    assert.notEqual(result.state, 'completed')
    assert.ok(result.runs.some((r) => r.tool === 'semgrep' && r.state === 'blocked'))
    assert.ok(result.runs.some((r) => r.tool === 'gitleaks' && r.state === 'blocked'))
    assert.ok(result.notes.some((note) => note.includes('not interpreted as a clean result')))
  } finally {
    if (previousConfig === undefined) delete process.env.SENTINEL_SEMGREP_CONFIG; else process.env.SENTINEL_SEMGREP_CONFIG = previousConfig
    if (previousGitleaks === undefined) delete process.env.SENTINEL_GITLEAKS_BIN; else process.env.SENTINEL_GITLEAKS_BIN = previousGitleaks
    if (previousSemgrep === undefined) delete process.env.SENTINEL_SEMGREP_BIN; else process.env.SENTINEL_SEMGREP_BIN = previousSemgrep
  }
})
