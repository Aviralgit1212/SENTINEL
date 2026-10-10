import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { once } from 'node:events'
import fs from 'node:fs'
import path from 'node:path'
import { getScanReport } from '../src/db.js'

process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER ??= '1'

async function startApi(): Promise<{ server: Server; baseUrl: string }> {
  const { default: app } = await import('../src/app.js')
  const server = createServer(app)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return { server, baseUrl: `http://127.0.0.1:${address.port}` }
}

async function uploadFile(baseUrl: string, endpoint: string, filename: string, content: Buffer, headers: Record<string, string> = {}): Promise<Response> {
  const form = new FormData()
  form.append('file', new Blob([new Uint8Array(content)], { type: 'application/octet-stream' }), filename)
  return fetch(`${baseUrl}${endpoint}`, {
    method: 'POST',
    headers: {
      Host: '127.0.0.1',
      ...headers,
    },
    body: form,
  })
}

test('Gate 01-08: Complete Release Acceptance Suite', async (t) => {
  const { server, baseUrl } = await startApi()
  t.after(() => server.close())

  // 1. Health & Storage Subsystem Invariant
  await t.test('Health check confirms Sovereign Core and operational storage tier', async () => {
    const res = await fetch(`${baseUrl}/api/health`, { headers: { Host: '127.0.0.1' } })
    assert.equal(res.status, 200)
    const data = await res.json() as { ok: boolean; version: string; storageTier: string; clamav: { engine: string; binaryAvailable: boolean } }
    assert.equal(data.ok, true)
    assert.equal(data.version, '3.0.0-sovereign')
    assert.ok(['ram', 'secure_temp'].includes(data.storageTier), `unexpected storage tier: ${data.storageTier}`)
    assert.ok(data.clamav && typeof data.clamav.binaryAvailable === 'boolean')
  })

  // 2. Two-Phase SSE Streaming API
  let streamingScanId = ''
  let streamingSha256 = ''
  await t.test('Two-Phase SSE Scan Stream emits complete lifecycle events and typed SIR', async () => {
    const testDoc = Buffer.from('Ordinary text document for acceptance verification.', 'utf8')
    const res = await uploadFile(baseUrl, '/api/v3/scan-stream', 'acceptance-sample.txt', testDoc)
    assert.equal(res.status, 200)
    assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/)

    const text = await res.text()
    assert.match(text, /event: intake_ack/)
    assert.match(text, /event: sir_compiled/)
    assert.match(text, /event: counterfactual_plan/)
    assert.match(text, /event: complete/)

    const completeMatch = /event: complete\ndata: (\{.*\})/.exec(text)
    assert.ok(completeMatch, 'complete event must exist in stream')
    const completeData = JSON.parse(completeMatch[1]) as { scanId: string; sha256: string; verdict: string; signatureHmac: string }
    assert.ok(completeData.scanId)
    assert.ok(completeData.sha256)
    assert.ok(completeData.signatureHmac)
    streamingScanId = completeData.scanId
    streamingSha256 = completeData.sha256

    const report = getScanReport(streamingScanId)
    assert.ok(report)
    assert.equal(report.sha256, streamingSha256)
    assert.ok(report.sirGraph)
    assert.ok(report.sirGraph.visibilityLedger)
    assert.ok(report.counterfactualPlan)
  })

  // 3. Evidence DAG & Provenance
  await t.test('Evidence DAG constructs deterministic content-minimized graph', async () => {
    assert.ok(streamingScanId)
    const res = await fetch(`${baseUrl}/api/scans/${streamingScanId}/evidence`, { headers: { Host: '127.0.0.1' } })
    assert.equal(res.status, 200)
    const dag = await res.json() as { schemaVersion: string; graphSha256: string; nodes: Array<{ kind: string }>; edges: Array<{ relation: string }> }
    assert.equal(dag.schemaVersion, '1.0')
    assert.equal(dag.graphSha256.length, 64)
    assert.ok(dag.nodes.some(n => n.kind === 'artifact'))
    assert.ok(dag.nodes.some(n => n.kind === 'analyzer'))
    assert.ok(dag.nodes.some(n => n.kind === 'policy'))
    assert.ok(dag.edges.some(e => e.relation === 'analyzed'))
  })

  // 4. Counterfactual Blocker Graph
  await t.test('Counterfactual Planner returns minimal resolution sequence', async () => {
    assert.ok(streamingScanId)
    const res = await fetch(`${baseUrl}/api/scans/${streamingScanId}/counterfactual`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ context: 'external_ai_submission' }),
    })
    assert.equal(res.status, 200)
    const plan = await res.json() as { targetContext: string; isSatisfiable: boolean; blockers: unknown[]; minimalActionSequence: unknown[] }
    assert.equal(plan.targetContext, 'external_ai_submission')
    assert.equal(typeof plan.isSatisfiable, 'boolean')
    assert.ok(Array.isArray(plan.blockers))
  })

  // 5. Security Time Machine
  await t.test('Security Time Machine verifies historical assessments and delta comparisons', async () => {
    assert.ok(streamingScanId)
    const timelineRes = await fetch(`${baseUrl}/api/scans/${streamingScanId}/timeline`, { headers: { Host: '127.0.0.1' } })
    assert.equal(timelineRes.status, 200)
    const timeline = await timelineRes.json() as { artifactSha256: string; assessments: unknown[]; artifactBytesRetained: boolean }
    assert.equal(timeline.artifactSha256, streamingSha256)
    assert.equal(timeline.artifactBytesRetained, false)

    // Compare with itself (zero diff)
    const compareRes = await fetch(`${baseUrl}/api/scans/${streamingScanId}/compare/${streamingScanId}`, { headers: { Host: '127.0.0.1' } })
    assert.equal(compareRes.status, 200)
    const comparison = await compareRes.json() as { verdictChanged: boolean; findings: { added: unknown[]; removed: unknown[] } }
    assert.equal(comparison.verdictChanged, false)
    assert.equal(comparison.findings.added.length, 0)
    assert.equal(comparison.findings.removed.length, 0)
  })

  // 6. Cryptographic SARIF Attestation & Portable Ed25519 Verification
  await t.test('SARIF Export provides non-repudiation and detects tampering', async () => {
    assert.ok(streamingScanId)
    const sarifRes = await fetch(`${baseUrl}/api/scans/${streamingScanId}/sarif`, { headers: { Host: '127.0.0.1' } })
    assert.equal(sarifRes.status, 200)
    const hmacSig = sarifRes.headers.get('x-sentinel-hmac')
    assert.ok(hmacSig && hmacSig.length === 64)
    const sarifDoc = await sarifRes.json()

    // Verify valid export
    const verifyRes = await fetch(`${baseUrl}/api/attestations/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ sarif: sarifDoc, signature: hmacSig, algorithm: 'HMAC-SHA256' }),
    })
    assert.equal(verifyRes.status, 200)
    const verifyResult = await verifyRes.json() as { valid: boolean; portableSignatureValid: boolean }
    assert.equal(verifyResult.valid, true)
    assert.equal(verifyResult.portableSignatureValid, true)

    // Reject tampered export
    const tampered = structuredClone(sarifDoc) as { runs: Array<{ properties: { verdict: string } }> }
    tampered.runs[0].properties.verdict = 'tampered_verdict'
    const tamperedRes = await fetch(`${baseUrl}/api/attestations/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ sarif: tampered, signature: hmacSig, algorithm: 'HMAC-SHA256' }),
    })
    const tamperedResult = await tamperedRes.json() as { valid: boolean }
    assert.equal(tamperedResult.valid, false)
  })

  // 7. Code Audit & Toolchain Gap Accounting
  await t.test('Code Audit flags hardcoded secrets and unconfigured toolchain gracefully', async () => {
    const maliciousCode = [
      'const apiKey = "AKIAIOSFODNN7EXAMPLE";',
      'db.query("SELECT * FROM users WHERE id = " + req.query.id);',
    ].join('\n')

    const auditRes = await fetch(`${baseUrl}/api/code/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ source: maliciousCode, filename: 'app.ts' }),
    })
    assert.equal(auditRes.status, 200)
    const auditData = await auditRes.json() as { findings: Array<{ category: string; severity: string }> }
    assert.ok(auditData.findings.some(f => f.category === 'hardcoded-cloud-key'))
    assert.ok(auditData.findings.some(f => f.category === 'possible-sql-injection'))

    const toolchainRes = await fetch(`${baseUrl}/api/code/audit/toolchain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ source: maliciousCode, filename: 'app.ts' }),
    })
    assert.equal(toolchainRes.status, 200)
    const toolchainData = await toolchainRes.json() as { toolchain: { runs: Array<{ tool: string; state: string }> } }
    assert.ok(toolchainData.toolchain.runs.some(r => r.tool === 'semgrep' && ['blocked', 'completed'].includes(r.state)))
  })

  // 8. AI Guardian Extension Bridge Security
  await t.test('AI Guardian extension bridge requires valid pairing token and origin', async () => {
    // Unauthenticated or unpaired request fails closed (403 or 503)
    const unpairedRes = await fetch(`${baseUrl}/api/extension/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Host: '127.0.0.1' },
      body: JSON.stringify({ text: 'Sensitive text', origin: 'https://chatgpt.com' }),
    })
    assert.ok([403, 503].includes(unpairedRes.status), `unexpected status: ${unpairedRes.status}`)
  })
})
