import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'
import { verifyRedactionPayload } from '../src/services/redactionIntegrity.js'

function payload(bytes: Buffer) {
  return {
    output_b64: bytes.toString('base64'),
    output_filename: 'report-redacted.docx',
    output_sha256: createHash('sha256').update(bytes).digest('hex'),
    output_size: bytes.length,
    verified: true,
  }
}

describe('Redaction output integrity', () => {
  it('accepts output only when bytes, size, hash and verification flag agree', () => {
    const bytes = Buffer.from('verified derivative')
    assert.deepEqual(verifyRedactionPayload(payload(bytes)), {
      ...payload(bytes),
      verified: true,
    })
  })

  it('rejects a service that reports verified without a true verification flag', () => {
    assert.throws(() => verifyRedactionPayload({ ...payload(Buffer.from('x')), verified: 'true' }))
  })

  it('rejects mismatched output hashes', () => {
    assert.throws(() => verifyRedactionPayload({ ...payload(Buffer.from('x')), output_sha256: '0'.repeat(64) }), /hash does not match/)
  })

  it('rejects mismatched output sizes', () => {
    assert.throws(() => verifyRedactionPayload({ ...payload(Buffer.from('x')), output_size: 99 }), /size does not match/)
  })

  it('rejects path-like output filenames', () => {
    assert.throws(() => verifyRedactionPayload({ ...payload(Buffer.from('x')), output_filename: '../leak.docx' }), /filename/)
  })

  it('rejects malformed base64', () => {
    assert.throws(() => verifyRedactionPayload({ ...payload(Buffer.from('x')), output_b64: 'not base64!' }), /encoding/)
  })
})

import { findResidualRedactionTargets } from '../src/services/redactionIntegrity.js'

describe('Fresh derivative residue verification', () => {
  it('detects exact target values remaining in freshly extracted derivative text', () => {
    assert.deepEqual(findResidualRedactionTargets('Label: [REDACTED], email: arsh@example.com', [
      { text: 'Name' }, { text: 'arsh@example.com' }, { text: 'arsh@example.com' },
    ]), ['arsh@example.com'])
  })

  it('returns no residuals when all target values are absent', () => {
    assert.deepEqual(findResidualRedactionTargets('Name: [REDACTED]', [{ text: 'Arsh' }, { text: 'arsh@example.com' }]), [])
  })
})
