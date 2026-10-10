import test from 'node:test'
import assert from 'node:assert/strict'
import { assertEntitiesBelongToScan, registerPrivacyScanBinding } from '../src/services/scanBinding.js'
import { minimizePersistedReport } from '../src/db.js'
import type { ScanReport } from '../src/types.js'

const entity = { entity_type: 'EMAIL_ADDRESS', text: 'arsh@example.test', start: 4, end: 21 }
const binding = {
  scanId: 'scan-stage4-test',
  sha256: 'a'.repeat(64),
  filename: 'report.docx',
  entities: [entity],
}

test('binding accepts entities returned by the exact scan', () => {
  registerPrivacyScanBinding(binding)
  const resolved = assertEntitiesBelongToScan(binding.scanId, [entity])
  assert.equal(resolved.sha256, binding.sha256)
  assert.equal(resolved.filename, binding.filename)
})

test('binding rejects fabricated or modified entities', () => {
  registerPrivacyScanBinding(binding)
  assert.throws(() => assertEntitiesBelongToScan(binding.scanId, [{ ...entity, text: 'other@example.test' }]), /does not belong/)
  assert.throws(() => assertEntitiesBelongToScan(binding.scanId, [{ ...entity, start: 5 }]), /does not belong/)
})

test('binding rejects a missing or expired scan id', () => {
  assert.throws(() => assertEntitiesBelongToScan('missing-stage4-scan', []), /missing or expired/)
})

test('persisted report withholds raw PII and evidence snippets', () => {
  const report: ScanReport = {
    scanId: 'scan-minimize-test',
    createdAt: new Date(0).toISOString(),
    filename: 'report.docx',
    size: 10,
    sha256: 'b'.repeat(64),
    coverage: [],
    threat: {
      antivirus: { engine: 'clamav', state: 'completed_no_detections', detail: 'clean' },
      fileType: { declaredExtension: '.docx', detectedExtension: '.docx', detectedMime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', mismatch: false },
      findings: [{ id: 'f1', module: 'threat', category: 'test', title: 'Test', description: 'Description', severity: 'low', source: 'test-rule', evidence: 'arsh@example.test' }],
    },
    privacy: { kind: 'docx', risk: 'HIGH', decision: 'REDACT', entities: [entity], extractionState: 'completed_no_detections', redactedText: 'arsh@example.test' },
    sirGraph: { artifactSha256: 'b'.repeat(64), mimeType: 'application/test', totalSizeBytes: 10, entities: { e1: { id: 'e1', nodeType: 'run', structuralLocation: {}, attributes: {}, rawText: 'arsh@example.test', normalizedText: 'arsh@example.test', rawBytesRef: 'memory:offset:4' } }, relationships: [], visibilityLedger: {} },
    verdict: 'review_required',
    verdictReason: 'Test fixture',
  }
  const minimized = minimizePersistedReport(report)
  assert.equal(minimized.privacy?.entities[0]?.text, '[WITHHELD]')
  assert.equal(minimized.privacy?.redactedText, null)
  assert.equal(minimized.threat?.findings[0]?.evidence, undefined)
  assert.equal(minimized.signatureHmac, undefined)
  assert.equal(minimized.sirGraph?.entities.e1?.rawText, '[WITHHELD]')
  assert.equal(minimized.sirGraph?.entities.e1?.normalizedText, '[WITHHELD]')
  assert.equal(minimized.sirGraph?.entities.e1?.rawBytesRef, undefined)
  // The in-memory response object is not mutated by persistence minimization.
  assert.equal(report.privacy?.entities[0]?.text, 'arsh@example.test')
})
