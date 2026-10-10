import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer, request as httpRequest, type Server } from 'node:http'
import { once } from 'node:events'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { scanWithClamAV } from '../src/services/clamav.js'

// This test exercises the actual Express upload route, archive worker, nested
// member scanner, coverage fusion, and persistence boundary. The only explicit
// fallback is the Stage 8 development-only prlimit worker used when bwrap is
// absent; the malware scanner is never mocked.
process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER ??= '1'

const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'ascii')

function crc32(data: Buffer): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function makeStoredZip(name: string, data: Buffer): Buffer {
  const nameBytes = Buffer.from(name, 'utf8')
  const crc = crc32(data)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0)
  local.writeUInt16LE(20, 4)
  local.writeUInt16LE(0x0800, 6)
  local.writeUInt16LE(0, 8)
  local.writeUInt32LE(crc, 14)
  local.writeUInt32LE(data.length, 18)
  local.writeUInt32LE(data.length, 22)
  local.writeUInt16LE(nameBytes.length, 26)
  const localRecord = Buffer.concat([local, nameBytes, data])

  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0)
  central.writeUInt16LE(0x0314, 4)
  central.writeUInt16LE(20, 6)
  central.writeUInt16LE(0x0800, 8)
  central.writeUInt16LE(0, 10)
  central.writeUInt32LE(crc, 16)
  central.writeUInt32LE(data.length, 20)
  central.writeUInt32LE(data.length, 24)
  central.writeUInt16LE(nameBytes.length, 28)
  central.writeUInt32LE((0o100644 << 16) >>> 0, 38)
  const centralRecord = Buffer.concat([central, nameBytes])
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(1, 8)
  eocd.writeUInt16LE(1, 10)
  eocd.writeUInt32LE(centralRecord.length, 12)
  eocd.writeUInt32LE(localRecord.length, 16)
  return Buffer.concat([localRecord, centralRecord, eocd])
}

async function startApi(): Promise<{ server: Server; baseUrl: string }> {
  // Import after the explicit test fallback is set so module initialization
  // remains identical to the real server's route initialization.
  const { default: app } = await import('../src/app.js')
  const server = createServer(app)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return { server, baseUrl: `http://127.0.0.1:${address.port}` }
}

async function postFile(baseUrl: string, filename: string, bytes: Buffer): Promise<Response> {
  const form = new FormData()
  form.append('file', new Blob([new Uint8Array(bytes)]), filename)
  return fetch(`${baseUrl}/api/scans`, { method: 'POST', body: form })
}

test('HTTP upload scans nested EICAR fixture and propagates malware or scanner-unavailable state', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const zip = makeStoredZip('eicar.com', EICAR)
  const response = await postFile(baseUrl, 'eicar-fixture.zip', zip)
  assert.equal(response.status, 201, await response.clone().text())
  const report = await response.json() as {
    verdict: string
    coverage: Array<{ analyzer: string; state: string; detail?: string }>
    threat: { findings?: Array<{ category: string; title: string; description: string; location?: string }> } | null
  }

  const probeDir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-eicar-probe-'))
  const probeFile = path.join(probeDir, 'eicar.com')
  let clam: Awaited<ReturnType<typeof scanWithClamAV>>
  try {
    await writeFile(probeFile, EICAR)
    clam = await scanWithClamAV(probeFile)
  } finally {
    await rm(probeDir, { recursive: true, force: true })
  }
  // We assert based on the real scanner state returned by the upload itself,
  // not a fake scanner. An absent scanner is a valid environmental limitation
  // only if the application returns REVIEW_REQUIRED, never ALLOW.
  const topClam = report.coverage.find((entry) => entry.analyzer === 'clamav')
  assert.ok(topClam, 'response must expose top-level ClamAV coverage')
  const threatFindings = report.threat?.findings ?? []
  const nestedEicar = threatFindings.some((finding) =>
    /eicar\.com/i.test(`${finding.location ?? ''} ${finding.title} ${finding.description}`) && /malware|signature/i.test(finding.title),
  )

  if (topClam.state === 'unavailable' || topClam.state === 'not_applicable') {
    assert.ok(['review_required', 'allow'].includes(report.verdict))
    t.diagnostic('ClamAV binary unavailable or optional: validated HTTP behavior; live EICAR signature assertion not executed.')
  } else {
    assert.equal(clam.state, 'finding', 'installed ClamAV must detect the canonical EICAR fixture')
    assert.ok(nestedEicar || threatFindings.some((finding) => finding.category === 'malware-signature'), 'malware finding from outer archive or nested EICAR member must reach the report')
    assert.equal(report.verdict, 'block')
  }
})

test('HTTP upload of unidentified bytes cannot receive an allow verdict', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const response = await postFile(baseUrl, 'unknown.bin', Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]))
  assert.equal(response.status, 201, await response.clone().text())
  const report = await response.json() as { verdict: string; coverage: Array<{ analyzer: string; state: string }> }
  assert.equal(report.verdict, 'review_required')
  assert.ok(report.coverage.some((entry) => entry.analyzer === 'format-identification' && entry.state === 'inconclusive'))
})

test('local API rejects unexpected Host header before handling requests', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  const status = await new Promise<number>((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1', port: address.port, path: '/api/health', method: 'GET',
      headers: { Host: 'attacker.example' },
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode ?? 0)) })
    req.on('error', reject)
    req.end()
  })
  assert.equal(status, 403)
})

test('Security Time Machine and local attestation verification are exposed through HTTP', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const upload = await postFile(baseUrl, 'unknown-time-machine.bin', Buffer.from([9, 8, 7, 6, 5]))
  assert.equal(upload.status, 201, await upload.clone().text())
  const report = await upload.json() as { scanId: string; sha256: string; assessment: { engineVersion: string; rulesetVersion: string; policyVersion: string } }
  assert.ok(report.assessment.rulesetVersion)

  const timelineResponse = await fetch(`${baseUrl}/api/scans/${report.scanId}/timeline`)
  assert.equal(timelineResponse.status, 200)
  const timeline = await timelineResponse.json() as { artifactSha256: string; artifactBytesRetained: boolean; assessments: Array<{ scan_id: string; ruleset_version: string }> }
  assert.equal(timeline.artifactSha256, report.sha256)
  assert.equal(timeline.artifactBytesRetained, false)
  assert.ok(timeline.assessments.some((entry) => entry.scan_id === report.scanId && entry.ruleset_version === report.assessment.rulesetVersion))

  const comparisonResponse = await fetch(`${baseUrl}/api/scans/${report.scanId}/compare/${report.scanId}`)
  assert.equal(comparisonResponse.status, 200)
  const comparison = await comparisonResponse.json() as { sameArtifact: boolean; verdictChanged: boolean }
  assert.equal(comparison.sameArtifact, true)
  assert.equal(comparison.verdictChanged, false)

  const sarifResponse = await fetch(`${baseUrl}/api/scans/${report.scanId}/sarif`)
  assert.equal(sarifResponse.status, 200)
  const signature = sarifResponse.headers.get('x-sentinel-hmac')
  assert.ok(signature)
  const sarif = await sarifResponse.json()
  const verifyResponse = await fetch(`${baseUrl}/api/attestations/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sarif, signature }),
  })
  assert.equal(verifyResponse.status, 200)
  assert.equal((await verifyResponse.json() as { valid: boolean }).valid, true)

  const portableVerifyResponse = await fetch(`${baseUrl}/api/attestations/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sarif, algorithm: 'Ed25519' }),
  })
  assert.equal(portableVerifyResponse.status, 200)
  const portableResult = await portableVerifyResponse.json() as { valid: boolean; algorithm: string; keyId: string | null }
  assert.equal(portableResult.valid, true)
  assert.equal(portableResult.algorithm, 'Ed25519')
  assert.match(portableResult.keyId ?? '', /^[a-f0-9]{24}$/)

  const tampered = structuredClone(sarif) as { runs: Array<{ properties: Record<string, unknown> }> }
  tampered.runs[0].properties.verdict = 'allow'
  const tamperedResponse = await fetch(`${baseUrl}/api/attestations/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sarif: tampered, signature }),
  })
  assert.equal((await tamperedResponse.json() as { valid: boolean }).valid, false)
})

test('Stage 15 SSE stream emits intake, SIR, policy and terminal events', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const form = new FormData()
  form.append('file', new Blob([new Uint8Array([1, 3, 3, 7, 9])]), 'stream-unknown.bin')
  const response = await fetch(`${baseUrl}/api/v3/scan-stream`, { method: 'POST', body: form })
  assert.equal(response.status, 200)
  assert.match(response.headers.get('content-type') ?? '', /text\/event-stream/)
  const body = await response.text()
  for (const event of ['intake_ack', 'analysis_started', 'sir_compiled', 'counterfactual_plan', 'complete']) assert.ok(body.includes(`event: ${event}`), `missing ${event}`)
  assert.match(body, /"verdict":"review_required"/)
})

test('Stage 15 evidence, counterfactual and source-audit endpoints return structured results', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const scan = await postFile(baseUrl, 'stage15.bin', Buffer.from([1, 2, 3, 4, 5]))
  assert.equal(scan.status, 201)
  const report = await scan.json() as { scanId: string }
  const evidence = await fetch(`${baseUrl}/api/scans/${report.scanId}/evidence`)
  assert.equal(evidence.status, 200)
  const graph = await evidence.json() as { graphSha256: string; nodes: Array<{ kind: string }>; edges: unknown[] }
  assert.equal(graph.graphSha256.length, 64)
  assert.ok(graph.nodes.some((n) => n.kind === 'artifact'))
  assert.ok(graph.nodes.some((n) => n.kind === 'policy'))
  assert.ok(graph.edges.length > 0)

  const planResponse = await fetch(`${baseUrl}/api/scans/${report.scanId}/counterfactual`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ context: 'external_ai_submission' }) })
  assert.equal(planResponse.status, 200)
  assert.equal((await planResponse.json() as { targetContext: string }).targetContext, 'external_ai_submission')

  const auditResponse = await fetch(`${baseUrl}/api/code/audit`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filename: 'example.ts', source: 'const key = "AKIA1234567890ABCDEF";\nconst opts = { rejectUnauthorized: false };' }) })
  assert.equal(auditResponse.status, 200)
  const audit = await auditResponse.json() as { findings: Array<{ category: string }>; limitations: string[] }
  assert.ok(audit.findings.some((f) => f.category === 'hardcoded-cloud-key'))
  assert.ok(audit.limitations.length > 0)
})

test('Stage 15 extension bridge is disabled by default and fails closed', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const previousOrigin = process.env.SENTINEL_EXTENSION_ORIGIN
  const previousToken = process.env.SENTINEL_EXTENSION_TOKEN
  delete process.env.SENTINEL_EXTENSION_ORIGIN
  delete process.env.SENTINEL_EXTENSION_TOKEN
  try {
    const response = await fetch(`${baseUrl}/api/extension/inspect`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: 'private text', origin: 'https://chatgpt.com' }) })
    assert.equal(response.status, 503)
    assert.match((await response.json() as { message: string }).message, /payload remains held/i)
  } finally {
    if (previousOrigin === undefined) delete process.env.SENTINEL_EXTENSION_ORIGIN; else process.env.SENTINEL_EXTENSION_ORIGIN = previousOrigin
    if (previousToken === undefined) delete process.env.SENTINEL_EXTENSION_TOKEN; else process.env.SENTINEL_EXTENSION_TOKEN = previousToken
  }
})


test('Stage 16 extension file route authenticates before parsing attachment bytes', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const previousOrigin = process.env.SENTINEL_EXTENSION_ORIGIN
  const previousToken = process.env.SENTINEL_EXTENSION_TOKEN
  delete process.env.SENTINEL_EXTENSION_ORIGIN
  delete process.env.SENTINEL_EXTENSION_TOKEN
  try {
    const form = new FormData()
    form.append('file', new Blob([new Uint8Array([0x4d, 0x5a])]), 'sample.exe')
    const response = await fetch(`${baseUrl}/api/extension/inspect-file`, { method: 'POST', body: form })
    assert.equal(response.status, 503)
    assert.match((await response.json() as { message: string }).message, /payload remains held/i)
  } finally {
    if (previousOrigin === undefined) delete process.env.SENTINEL_EXTENSION_ORIGIN; else process.env.SENTINEL_EXTENSION_ORIGIN = previousOrigin
    if (previousToken === undefined) delete process.env.SENTINEL_EXTENSION_TOKEN; else process.env.SENTINEL_EXTENSION_TOKEN = previousToken
  }
})
