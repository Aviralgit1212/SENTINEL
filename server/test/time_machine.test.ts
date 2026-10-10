import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { compareAssessments } from '../src/services/timeMachine.js'
import type { ScanReport } from '../src/types.js'

function report(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    scanId: 'scan-a',
    createdAt: '2026-10-10T10:00:00.000Z',
    filename: 'sample.pdf',
    size: 123,
    sha256: 'a'.repeat(64),
    coverage: [{ analyzer: 'clamav', state: 'completed_no_detections' }],
    threat: { antivirus: { engine: 'clamav', state: 'completed_no_detections', detail: 'no detections' }, fileType: { declaredExtension: '.pdf', detectedExtension: 'pdf', detectedMime: 'application/pdf', mismatch: false }, findings: [] },
    privacy: null,
    verdict: 'allow',
    verdictReason: 'No findings',
    assessment: { engineVersion: '3.0.0', rulesetVersion: 'rules-a', policyVersion: 'policy-a' },
    ...overrides,
  }
}

describe('Security Time Machine assessment comparison', () => {
  it('reports finding additions, removals, verdict and coverage changes for the same artifact', () => {
    const old = report({
      threat: { antivirus: { engine: 'clamav', state: 'completed_no_detections', detail: 'no detections' }, fileType: { declaredExtension: '.pdf', detectedExtension: 'pdf', detectedMime: 'application/pdf', mismatch: false }, findings: [
        { id: 'old', module: 'threat', category: 'suspicious-url', title: 'Suspicious URL', description: 'URL found', severity: 'medium', source: 'pdf-analyzer', location: 'page 1' },
      ] },
    })
    const current = report({
      scanId: 'scan-b', createdAt: '2026-10-10T11:00:00.000Z', verdict: 'review_required', verdictReason: 'New rule and parser gap',
      assessment: { engineVersion: '3.1.0', rulesetVersion: 'rules-b', policyVersion: 'policy-a' },
      coverage: [{ analyzer: 'clamav', state: 'completed_no_detections' }, { analyzer: 'pdf-ocr', state: 'failed', detail: 'OCR unavailable' }],
      threat: { antivirus: { engine: 'clamav', state: 'completed_no_detections', detail: 'no detections' }, fileType: { declaredExtension: '.pdf', detectedExtension: 'pdf', detectedMime: 'application/pdf', mismatch: false }, findings: [
        { id: 'new', module: 'threat', category: 'hidden-text', title: 'Hidden text', description: 'Text has low visibility', severity: 'high', source: 'pdf-analyzer', location: 'page 2' },
      ] },
    })
    const delta = compareAssessments(old, current)
    assert.equal(delta.sameArtifact, true)
    assert.equal(delta.verdictChanged, true)
    assert.equal(delta.assessmentVersionChanged, true)
    assert.equal(delta.findings.added.length, 1)
    assert.equal(delta.findings.removed.length, 1)
    assert.ok(delta.coverage.some((entry) => entry.analyzer === 'pdf-ocr' && entry.before === null && entry.after === 'failed'))
    assert.match(delta.limitations.join(' '), /not a fresh scan/i)
  })

  it('rejects comparison across different artifact hashes', () => {
    assert.throws(() => compareAssessments(report(), report({ sha256: 'b'.repeat(64) })), /identical artifact SHA-256/)
  })
})
