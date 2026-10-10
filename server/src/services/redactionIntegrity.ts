import { createHash } from 'node:crypto'
import { blake3 } from '@noble/hashes/blake3.js'

export interface UntrustedRedactionPayload {
  output_b64?: unknown
  output_filename?: unknown
  output_sha256?: unknown
  output_size?: unknown
  verified?: unknown
}

export interface VerifiedRedactionPayload {
  output_b64: string
  output_filename: string
  output_sha256: string
  output_size: number
  verified: true
}

/** Validate the privacy service's output as untrusted bytes before release. */
export function verifyRedactionPayload(body: UntrustedRedactionPayload): VerifiedRedactionPayload {
  if (body.verified !== true) throw new Error('Redaction service did not confirm verification.')
  if (typeof body.output_b64 !== 'string' || body.output_b64.length === 0) {
    throw new Error('Redaction service returned no output bytes.')
  }
  if (typeof body.output_filename !== 'string' || body.output_filename.length === 0 ||
      body.output_filename !== body.output_filename.split(/[\\/]/).pop() ||
      body.output_filename === '.' || body.output_filename === '..') {
    throw new Error('Redaction service returned an invalid output filename.')
  }
  if (typeof body.output_sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(body.output_sha256)) {
    throw new Error('Redaction service returned an invalid output hash.')
  }
  if (!Number.isSafeInteger(body.output_size) || (body.output_size as number) <= 0) {
    throw new Error('Redaction service returned an invalid output size.')
  }

  const output = Buffer.from(body.output_b64, 'base64')
  if (output.length === 0 || output.toString('base64') !== body.output_b64) {
    throw new Error('Redaction service returned malformed output encoding.')
  }
  const blake3Hash = Buffer.from(blake3(output)).toString('hex')
  const sha256Hash = createHash('sha256').update(output).digest('hex')
  const expectedHash = body.output_sha256.toLowerCase()
  if (expectedHash !== blake3Hash && expectedHash !== sha256Hash) {
    throw new Error('Redaction service output hash does not match its bytes.')
  }
  const actualHash = expectedHash === blake3Hash ? blake3Hash : sha256Hash
  if (output.length !== body.output_size) {
    throw new Error('Redaction service output size does not match its bytes.')
  }
  return {
    output_b64: body.output_b64,
    output_filename: body.output_filename,
    output_sha256: actualHash,
    output_size: output.length,
    verified: true,
  }
}


/** Return unique target values still present in a freshly extracted derivative.
 * Exact matching is intentionally conservative: ambiguous residuals fail closed. */
export function findResidualRedactionTargets(extractedText: string, entities: Array<{ text: string }>): string[] {
  const residuals = new Set<string>()
  for (const entity of entities) {
    if (typeof entity.text === 'string' && entity.text.length > 0 && extractedText.includes(entity.text)) {
      residuals.add(entity.text)
    }
  }
  return [...residuals]
}
