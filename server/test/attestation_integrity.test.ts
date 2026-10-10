import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateSarifPackage, verifySarifSignature, verifySarifPublicSignature, signingKeyId, publicSigningKeyId } from '../src/services/attestation.js'
import type { ScanReport } from '../src/types.js'

// Isolate this test's persistent key from a developer's normal SENTINEL data directory.
const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-attestation-test-'))
process.env.SENTINEL_SIGNING_KEY_PATH = path.join(testRoot, 'key', 'sentinel.key')
after(() => fs.rmSync(testRoot, { recursive: true, force: true }))

function report(): ScanReport {
  return {
    scanId: 'attestation-test', createdAt: '2026-10-10T10:00:00.000Z', filename: 'sample.pdf', size: 1,
    sha256: 'a'.repeat(64), coverage: [{ analyzer: 'test', state: 'completed_no_detections' }],
    threat: { antivirus: { engine: 'clamav', state: 'completed_no_detections', detail: 'test' }, fileType: { declaredExtension: '.pdf', detectedExtension: 'pdf', detectedMime: 'application/pdf', mismatch: false }, findings: [] },
    privacy: null, verdict: 'allow', verdictReason: 'test',
    assessment: { engineVersion: '3.0.0', rulesetVersion: 'rules-test', policyVersion: 'policy-test' },
  }
}

describe('Persistent local attestation integrity', () => {
  it('creates a private 32-byte key and verifies an untampered SARIF export', () => {
    const { sarif, signature } = generateSarifPackage(report())
    const keyPath = process.env.SENTINEL_SIGNING_KEY_PATH!
    const stat = fs.statSync(keyPath)
    assert.equal(fs.readFileSync(keyPath).length, 32)
    assert.equal(stat.mode & 0o777, 0o600)
    assert.equal(verifySarifSignature(sarif, signature), true)
    assert.equal(verifySarifPublicSignature(sarif), true)
    assert.equal(publicSigningKeyId().length, 24)
    const privateKeyPath = `${keyPath}.ed25519-private.pem`
    assert.equal(fs.statSync(privateKeyPath).mode & 0o777, 0o600)
    assert.match(fs.readFileSync(privateKeyPath, 'utf8'), /BEGIN PRIVATE KEY/)
    const reordered = JSON.parse(JSON.stringify(sarif, (_key, value) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return Object.fromEntries(Object.entries(value).reverse())
      }
      return value
    }))
    assert.equal(verifySarifSignature(reordered, signature), true)
    const keyId = signingKeyId()
    assert.equal(keyId.length, 16)
    // A fresh Node process must load the same persisted key, proving that a restart
    // does not silently rotate the signing identity and invalidate old exports.
    const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', "import { signingKeyId } from './src/services/attestation.ts'; process.stdout.write(signingKeyId())"], {
      cwd: process.cwd(), env: { ...process.env, SENTINEL_SIGNING_KEY_PATH: keyPath }, encoding: 'utf8',
    })
    assert.equal(child.status, 0, child.stderr)
    assert.equal(child.stdout, keyId)
  })

  it('rejects tampered payloads and malformed signatures', () => {
    const { sarif, signature } = generateSarifPackage(report())
    const tampered = structuredClone(sarif) as Record<string, unknown>
    const runs = tampered.runs as Array<{ properties: Record<string, unknown> }>
    runs[0].properties.verdict = 'block'
    assert.equal(verifySarifSignature(tampered, signature), false)
    assert.equal(verifySarifPublicSignature(tampered), false)
    assert.equal(verifySarifSignature(sarif, 'not-a-signature'), false)
    const badKeyId = structuredClone(sarif) as Record<string, unknown>
    const badRuns = badKeyId.runs as Array<{ properties: Record<string, Record<string, unknown>> }>
    badRuns[0].properties.publicKeySignature.keyId = '0'.repeat(24)
    assert.equal(verifySarifPublicSignature(badKeyId), false)
  })
})
