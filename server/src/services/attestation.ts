/**
 * SENTINEL Sovereign Core — Cryptographic Attestation & SARIF Signer
 * 
 * Formats findings into OASIS SARIF v2.1 schema and signs the
 * evidence package with a machine-root HMAC-SHA256 key.
 */

import { createHmac, randomBytes, timingSafeEqual, createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import type { ScanReport, Finding } from '../types.js'

let MACHINE_ROOT_KEY: Buffer | undefined
let ED25519_PRIVATE_KEY: KeyObject | undefined
let ED25519_PUBLIC_KEY: KeyObject | undefined

/**
 * Load a stable machine-local HMAC key. The key is deliberately local and
 * symmetric: it allows this installation to verify its own exports, but is
 * not a public-key signature and must not be described as public non-repudiation.
 */
function getMachineKey(): Buffer {
  if (MACHINE_ROOT_KEY) return MACHINE_ROOT_KEY
  const keyPath = path.resolve(process.env.SENTINEL_SIGNING_KEY_PATH || path.join(process.cwd(), 'data', 'sentinel-signing.key'))
  fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 })

  try {
    const stat = fs.lstatSync(keyPath)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('SENTINEL signing key must be a regular, non-symlink file.')
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error('SENTINEL signing key permissions are too broad; require mode 0600.')
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('SENTINEL signing key must be owned by the service user.')
    const key = fs.readFileSync(keyPath)
    if (key.length !== 32) throw new Error('SENTINEL signing key must contain exactly 32 random bytes.')
    MACHINE_ROOT_KEY = key
    return key
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }

  const candidate = randomBytes(32)
  let fd: number | undefined
  try {
    fd = fs.openSync(keyPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600)
    fs.writeFileSync(fd, candidate)
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = undefined
    MACHINE_ROOT_KEY = candidate
    return candidate
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd)
    // Another process may have initialized the key concurrently. Re-read and
    // validate it rather than overwriting it or using a transient key.
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return getMachineKey()
    throw new Error(`Unable to initialize persistent SENTINEL signing key: ${error instanceof Error ? error.message : 'unknown error'}`)
  }
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value !== null && typeof value === 'object') {
    const input = value as Record<string, unknown>
    const output: Record<string, unknown> = {}
    for (const key of Object.keys(input).sort()) {
      if (input[key] !== undefined) output[key] = canonicalize(input[key])
    }
    return output
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Attestation payload contains a non-finite number.')
  if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
    throw new Error('Attestation payload contains a non-JSON value.')
  }
  return value
}

function stableJson(value: unknown): string {
  // Canonical key ordering makes verification independent of object key order
  // while preserving array order and the exact represented JSON values.
  const json = JSON.stringify(canonicalize(value))
  if (typeof json !== 'string') throw new Error('Attestation payload is not JSON serializable.')
  return json
}


/** Load or create a machine-local Ed25519 signing identity. The private key is
 * never exported. The public key is embedded in each receipt so any recipient
 * can verify integrity; identity trust still requires pinning the public key. */
function getEd25519Keys(): { privateKey: KeyObject; publicKey: KeyObject } {
  if (ED25519_PRIVATE_KEY && ED25519_PUBLIC_KEY) return { privateKey: ED25519_PRIVATE_KEY, publicKey: ED25519_PUBLIC_KEY }
  const hmacPath = path.resolve(process.env.SENTINEL_SIGNING_KEY_PATH || path.join(process.cwd(), 'data', 'sentinel-signing.key'))
  const privatePath = `${hmacPath}.ed25519-private.pem`
  fs.mkdirSync(path.dirname(privatePath), { recursive: true, mode: 0o700 })
  try {
    const stat = fs.lstatSync(privatePath)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('SENTINEL Ed25519 private key must be a regular, non-symlink file.')
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error('SENTINEL Ed25519 private key permissions are too broad; require mode 0600.')
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('SENTINEL Ed25519 private key must be owned by the service user.')
    const privateKey = createPrivateKey(fs.readFileSync(privatePath))
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('SENTINEL signing key is not Ed25519.')
    const publicKey = createPublicKey(privateKey)
    ED25519_PRIVATE_KEY = privateKey
    ED25519_PUBLIC_KEY = publicKey
    return { privateKey, publicKey }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  const pair = generateKeyPairSync('ed25519')
  const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
  let fd: number | undefined
  try {
    fd = fs.openSync(privatePath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600)
    fs.writeFileSync(fd, pem)
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = undefined
    ED25519_PRIVATE_KEY = pair.privateKey
    ED25519_PUBLIC_KEY = pair.publicKey
    return { privateKey: pair.privateKey, publicKey: pair.publicKey }
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd)
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return getEd25519Keys()
    throw new Error(`Unable to initialize persistent SENTINEL Ed25519 key: ${error instanceof Error ? error.message : 'unknown error'}`)
  }
}

function publicKeyPem(): string {
  return getEd25519Keys().publicKey.export({ type: 'spki', format: 'pem' }).toString()
}

export function publicSigningKeyId(): string {
  const der = getEd25519Keys().publicKey.export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(der).digest('hex').slice(0, 24)
}

export function sarifPublicKeyId(sarif: unknown): string | null {
  try {
    const value = sarif as { runs?: Array<{ properties?: { publicKeySignature?: { keyId?: unknown } } }> }
    const keyId = value?.runs?.[0]?.properties?.publicKeySignature?.keyId
    return typeof keyId === 'string' && /^[a-f0-9]{24}$/.test(keyId) ? keyId : null
  } catch {
    return null
  }
}

/** Verifies a self-contained Ed25519 receipt. This proves payload integrity
 * under the embedded key, not that the key belongs to a trusted organization. */
export function verifySarifPublicSignature(sarif: unknown): boolean {
  try {
    if (!sarif || typeof sarif !== 'object') return false
    const clone = structuredClone(sarif) as Record<string, unknown>
    const runs = clone.runs
    if (!Array.isArray(runs) || !runs[0] || typeof runs[0] !== 'object') return false
    const properties = (runs[0] as Record<string, unknown>).properties
    if (!properties || typeof properties !== 'object') return false
    const props = properties as Record<string, unknown>
    const envelope = props.publicKeySignature
    if (!envelope || typeof envelope !== 'object') return false
    const e = envelope as Record<string, unknown>
    if (e.algorithm !== 'Ed25519' || typeof e.signature !== 'string' || typeof e.publicKey !== 'string' || typeof e.keyId !== 'string') return false
    const publicKey = createPublicKey(e.publicKey)
    if (publicKey.asymmetricKeyType !== 'ed25519') return false
    const actualId = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 24)
    if (actualId !== e.keyId) return false
    delete props.publicKeySignature
    return cryptoVerify(null, Buffer.from(stableJson(clone)), publicKey, Buffer.from(e.signature, 'base64'))
  } catch {
    return false
  }
}

export function verifySarifSignature(sarif: unknown, signature: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(signature)) return false
  let expected: Buffer
  try {
    const clone = structuredClone(sarif) as Record<string, unknown>
    if (Array.isArray(clone.runs) && clone.runs[0] && typeof clone.runs[0] === 'object') {
      const properties = (clone.runs[0] as Record<string, unknown>).properties
      if (properties && typeof properties === 'object') delete (properties as Record<string, unknown>).publicKeySignature
    }
    expected = createHmac('sha256', getMachineKey()).update(stableJson(clone)).digest()
  } catch {
    return false
  }
  const supplied = Buffer.from(signature, 'hex')
  return supplied.length === expected.length && timingSafeEqual(supplied, expected)
}

export function signingKeyId(): string {
  return createHash('sha256').update(getMachineKey()).digest('hex').slice(0, 16)
}

export interface SarifResult {
  ruleId: string
  level: 'error' | 'warning' | 'note'
  message: { text: string }
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string }
      region?: { snippet?: { text: string } }
    }
  }>
}

export function generateSarifPackage(report: ScanReport): {
  sarif: Record<string, unknown>
  signature: string
  publicSignature: string
  publicKey: string
  publicKeyId: string
} {
  const sarifResults: SarifResult[] = []

  const allFindings: Finding[] = [
    ...(report.threat?.findings ?? []),
  ]

  for (const f of allFindings) {
    let level: SarifResult['level'] = 'note'
    if (f.severity === 'critical' || f.severity === 'high') level = 'error'
    else if (f.severity === 'medium') level = 'warning'

    sarifResults.push({
      ruleId: f.category || f.source,
      level,
      message: { text: `${f.title}: ${f.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: report.filename },
            region: f.evidence ? { snippet: { text: f.evidence } } : undefined,
          },
        },
      ],
    })
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SENTINEL-Sovereign-Core',
            version: '3.0.0',
            informationUri: 'https://github.com/sentinel/sentinel-workbench',
            rules: [],
          },
        },
        artifacts: [
          {
            location: { uri: report.filename },
            hashes: {
              'sha-256': report.sha256,
            },
          },
        ],
        results: sarifResults,
        properties: {
          scanId: report.scanId,
          verdict: report.verdict,
          verdictReason: report.verdictReason,
          coverage: report.coverage,
          assessment: report.assessment ?? { engineVersion: 'unknown', rulesetVersion: 'unknown', policyVersion: 'unknown' },
          signature: { algorithm: 'HMAC-SHA256', keyId: signingKeyId(), trustScope: 'local-installation-only' },
          inTotoAttestation: {
            _type: 'https://in-toto.io/Statement/v1',
            subject: [{ name: report.filename, digest: { sha256: report.sha256 } }],
            predicateType: 'https://slsa.dev/provenance/v1.2',
            predicate: {
              buildDefinition: {
                buildType: 'https://sentinel.local/investigation/v3',
              },
            },
          },
        },
      },
    ],
  }

  const payload = stableJson(sarif)
  const signature = createHmac('sha256', getMachineKey()).update(payload).digest('hex')
  const keys = getEd25519Keys()
  const publicSignature = cryptoSign(null, Buffer.from(payload), keys.privateKey).toString('base64')
  const firstRun = (sarif.runs[0] as { properties: Record<string, unknown> })
  firstRun.properties.publicKeySignature = {
    algorithm: 'Ed25519',
    keyId: publicSigningKeyId(),
    publicKey: publicKeyPem(),
    signature: publicSignature,
    trustModel: 'self-contained-integrity; pin keyId to trust signer identity',
  }

  return { sarif, signature, publicSignature, publicKey: publicKeyPem(), publicKeyId: publicSigningKeyId() }
}
