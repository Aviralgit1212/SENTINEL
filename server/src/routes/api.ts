import { Router, type Request, type Response } from 'express'
import multer from 'multer'
import path from 'node:path'
import fs from 'node:fs/promises'
import { createHash, timingSafeEqual } from 'node:crypto'
import {
  runThreatScan,
  fuseVerdict,
} from '../services/threatService.js'
import {
  privacyScanText,
  privacyScanFile,
  privacyRedactFile,
  privacyExtractText,
  privacyServiceHealth,
} from '../services/privacyClient.js'
import {
  saveScanReport,
  getScanReport,
  historyForHash,
  recentScans,
  deleteScan,
  clearHistory,
  newId,
} from '../db.js'
import type { ScanReport, PrivacyResult, Finding } from '../types.js'
import {
  uploadsDirectory,
  newTemporaryPath,
  cleanupTemporaryFile,
  getVaultStorageTier,
} from '../services/workspace.js'
import { generateSarifPackage, verifySarifSignature, verifySarifPublicSignature, signingKeyId, publicSigningKeyId, sarifPublicKeyId } from '../services/attestation.js'
import { currentAssessmentVersion } from '../services/assessmentVersion.js'
import { compareAssessments } from '../services/timeMachine.js'
import { privacyDecisionToVerdict, privacyDecisionReason } from '../services/verdictPolicy.js'
import { registerPrivacyScanBinding, assertEntitiesBelongToScan } from '../services/scanBinding.js'
import { getClamAVCapability, blake3File } from '../services/clamav.js'
import { buildEvidenceDag } from '../services/evidenceDag.js'
import { auditSource } from '../services/codeAudit.js'
import { runToolchainAudit } from '../services/toolchainAudit.js'
import { buildCounterfactualPlan, type SecurityActionContext } from '../services/counterfactual.js'
import { findResidualRedactionTargets } from '../services/redactionIntegrity.js'

const router = Router()

// Cross-platform Local RAM Vault: max upload ceiling 100MB
const MAX_FILE_MB = Number(process.env.MAX_FILE_SIZE_MB ?? 100)
if (!Number.isFinite(MAX_FILE_MB) || MAX_FILE_MB <= 0 || MAX_FILE_MB > 1024) {
  throw new Error('MAX_FILE_SIZE_MB must be a number greater than 0 and at most 1024.')
}

// Resolving this at startup intentionally fails closed when strict RAM storage
// is unavailable. Multer never gets a chance to silently choose disk storage.
const upload = multer({
  dest: uploadsDirectory(),
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024, files: 1, fields: 10, fieldSize: 64 * 1024, parts: 12 },
})

function safeError(res: Response, code: number, message: string, requestId?: string) {
  res.status(code).json({ code, message, requestId, retryable: code >= 500 })
}

function extensionPairingGuard(req: Request, res: Response, next: () => void) {
  const expectedOrigin = process.env.SENTINEL_EXTENSION_ORIGIN
  const expectedToken = process.env.SENTINEL_EXTENSION_TOKEN
  const origin = req.headers.origin
  const suppliedToken = req.header('X-Sentinel-Pairing-Token') ?? ''
  if (!expectedOrigin || !expectedToken) return safeError(res, 503, 'Extension gateway is not configured; payload remains held.')
  if (origin !== expectedOrigin) return safeError(res, 403, 'Unpaired extension origin.')
  const expected = Buffer.from(expectedToken, 'utf8')
  const supplied = Buffer.from(suppliedToken, 'utf8')
  if (expected.length < 32 || supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return safeError(res, 403, 'Invalid pairing token.')
  next()
}

// ------------------------------------------------------------------
// Health
// ------------------------------------------------------------------
router.get('/health', async (_req: Request, res: Response) => {
  const privacy = await privacyServiceHealth()
  const clamav = getClamAVCapability()
  res.json({
    ok: true,
    service: 'sentinel-server',
    version: '3.0.0-sovereign',
    storageTier: getVaultStorageTier(),
    privacyService: privacy,
    // Capability, not a claim that signature databases loaded successfully.
    clamav,
  })
})

// ------------------------------------------------------------------
// Threat scan: POST /api/scans (multipart)
// ------------------------------------------------------------------
router.post('/scans', upload.single('file'), async (req: Request, res: Response) => {
  try {
    const file = req.file
    if (!file) {
      return safeError(res, 400, 'No file was uploaded.')
    }

    const result = await runThreatScan({
      filePath: file.path,
      originalName: file.originalname,
      size: file.size,
    })

    const { verdict, verdictReason } = fuseVerdict(result.findings, result.coverage)

    const initialReport: ScanReport = {
      scanId: newId(),
      createdAt: new Date().toISOString(),
      filename: file.originalname,
      size: file.size,
      sha256: result.sha256,
      blake3: result.blake3,
      coverage: result.coverage,
      threat: result.threat,
      privacy: null,
      verdict,
      verdictReason,
      sirGraph: result.sirGraph,
      counterfactualPlan: result.counterfactualPlan,
      assessment: currentAssessmentVersion(),
    }

    // Sign the report with machine-root HMAC-SHA256
    const { signature } = generateSarifPackage(initialReport)
    const report: ScanReport = {
      ...initialReport,
      signatureHmac: signature,
    }

    saveScanReport(report)

    const historical = historyForHash(result.sha256).filter((row) => (row as { scan_id: string }).scan_id !== report.scanId)

    res.status(201).json({
      ...report,
      priorReportsForSameFile: historical.length,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Scan failed'
    console.error('[threat] scan failed:', message)
    safeError(res, 500, 'Threat scan failed.')
  } finally {
    if (req.file?.path) cleanupTemporaryFile(req.file.path)
  }
})

// ------------------------------------------------------------------
// Stage 15: two-phase SSE scan stream. Events are evidence snapshots, not a
// claim that the scan has completed until the final `complete` event.
// ------------------------------------------------------------------
router.post('/v3/scan-stream', upload.single('file'), async (req: Request, res: Response) => {
  const file = req.file
  if (!file) return safeError(res, 400, 'No file was uploaded.')
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()
  const emit = (event: string, data: unknown) => {
    if (res.writableEnded || res.destroyed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }
  try {
    const sha256 = await hashFile(file.path)
    emit('intake_ack', { filename: path.basename(file.originalname), size: file.size, sha256 })
    emit('analysis_started', { phases: ['threat', 'coverage', 'sir', 'policy'] })
    const result = await runThreatScan({ filePath: file.path, originalName: file.originalname, size: file.size })
    emit('sir_compiled', { nodeCount: Object.keys(result.sirGraph.entities).length, visibility: result.sirGraph.visibilityLedger })
    for (const finding of result.findings) emit('finding', finding)
    emit('counterfactual_plan', result.counterfactualPlan)
    const { verdict, verdictReason } = fuseVerdict(result.findings, result.coverage)
    const initial: ScanReport = {
      scanId: newId(), createdAt: new Date().toISOString(), filename: path.basename(file.originalname), size: file.size,
      sha256: result.sha256, coverage: result.coverage, threat: result.threat, privacy: null, verdict, verdictReason,
      sirGraph: result.sirGraph, counterfactualPlan: result.counterfactualPlan, assessment: currentAssessmentVersion(),
    }
    const { signature } = generateSarifPackage(initial)
    const report: ScanReport = { ...initial, signatureHmac: signature }
    saveScanReport(report)
    emit('complete', { scanId: report.scanId, sha256: report.sha256, verdict: report.verdict, verdictReason: report.verdictReason, coverage: report.coverage, signatureHmac: report.signatureHmac })
  } catch (error) {
    emit('error', { message: error instanceof Error ? error.message.slice(0, 180) : 'Scan failed', verdict: 'review_required' })
  } finally {
    cleanupTemporaryFile(file.path)
    if (!res.writableEnded) res.end()
  }
})

// ------------------------------------------------------------------
// Stage 15: evidence graph, policy counterfactual, and bounded source audit.
// ------------------------------------------------------------------
router.get('/scans/:scanId/evidence', (req: Request, res: Response) => {
  const report = getScanReport(req.params.scanId)
  if (!report) return safeError(res, 404, 'Scan not found.')
  return res.json(buildEvidenceDag(report))
})

router.post('/scans/:scanId/counterfactual', (req: Request, res: Response) => {
  const report = getScanReport(req.params.scanId)
  if (!report) return safeError(res, 404, 'Scan not found.')
  const body = req.body as { context?: unknown }
  const contexts: SecurityActionContext[] = ['external_ai_submission', 'external_email_transfer', 'internal_archival', 'executable_deployment']
  const context = body?.context === undefined ? 'external_ai_submission' : body.context
  if (typeof context !== 'string' || !contexts.includes(context as SecurityActionContext)) return safeError(res, 400, 'Unsupported security action context.')
  const findings = report.threat?.findings ?? []
  return res.json(buildCounterfactualPlan(findings, report.coverage, context as SecurityActionContext))
})

router.post('/code/audit/toolchain', async (req: Request, res: Response) => {
  const body = req.body as { source?: unknown; filename?: unknown }
  if (!body || typeof body.source !== 'string') return safeError(res, 400, 'Provide source or a dependency manifest as a UTF-8 string.')
  if (Buffer.byteLength(body.source, 'utf8') > 900_000) return safeError(res, 413, 'Source exceeds the 900KB audit limit.')
  if (!body.source.trim()) return safeError(res, 400, 'Source cannot be empty.')
  const filename = typeof body.filename === 'string' ? path.basename(body.filename).slice(0, 160) : 'source.txt'
  const heuristic = auditSource(body.source, filename)
  const toolchain = await runToolchainAudit(body.source, filename)
  return res.json({ heuristic, toolchain, verdict: toolchain.state === 'completed' && !heuristic.findings.some(f => f.severity === 'critical') ? 'review_required' : 'review_required', policyNote: 'This endpoint never emits ALLOW. Review scanner findings and coverage before making a release decision.' })
})

router.post('/code/audit', (req: Request, res: Response) => {
  const body = req.body as { source?: unknown; filename?: unknown }
  if (!body || typeof body.source !== 'string') return safeError(res, 400, 'Provide source as a UTF-8 string.')
  if (Buffer.byteLength(body.source, 'utf8') > 900_000) return safeError(res, 413, 'Source exceeds the 900KB audit limit.')
  const filename = typeof body.filename === 'string' ? path.basename(body.filename).slice(0, 160) : 'source.txt'
  if (!body.source.trim()) return safeError(res, 400, 'Source cannot be empty.')
  return res.json(auditSource(body.source, filename))
})

// ------------------------------------------------------------------
// History & SARIF Export
// ------------------------------------------------------------------
router.get('/scans', (_req: Request, res: Response) => {
  res.json(recentScans())
})

router.get('/scans/:scanId', (req: Request, res: Response) => {
  const report = getScanReport(req.params.scanId)
  if (!report) return safeError(res, 404, 'Scan not found.')
  res.json(report)
})

router.get('/scans/:scanId/sarif', (req: Request, res: Response) => {
  const report = getScanReport(req.params.scanId)
  if (!report) return safeError(res, 404, 'Scan not found.')
  const { sarif, signature } = generateSarifPackage(report)
  res.setHeader('Content-Type', 'application/json')
  res.setHeader('X-Sentinel-HMAC', signature)
  res.setHeader('X-Sentinel-Signature-Algorithm', 'Ed25519')
  res.setHeader('X-Sentinel-Signing-Key-Id', publicSigningKeyId())
  res.json(sarif)
})

// Security Time Machine: compare historical assessments of the same bytes.
// No stored artifact is re-scanned here; callers must upload again for a fresh assessment.
router.get('/scans/:scanId/timeline', (req: Request, res: Response) => {
  const report = getScanReport(req.params.scanId)
  if (!report) return safeError(res, 404, 'Scan not found.')
  res.json({
    artifactSha256: report.sha256,
    assessments: historyForHash(report.sha256),
    artifactBytesRetained: false,
  })
})

router.get('/scans/:scanId/compare/:otherScanId', (req: Request, res: Response) => {
  const baseline = getScanReport(req.params.otherScanId)
  const current = getScanReport(req.params.scanId)
  if (!baseline || !current) return safeError(res, 404, 'One or both scans were not found.')
  try {
    return res.json(compareAssessments(baseline, current))
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid assessment comparison.'
    return safeError(res, 409, message)
  }
})

// Verify portable Ed25519 integrity, plus optional installation-local HMAC integrity.
// An embedded public key proves self-consistency, not signer identity: consumers must pin keyId.
router.post('/attestations/verify', (req: Request, res: Response) => {
  const body = req.body as { sarif?: unknown; signature?: unknown; algorithm?: unknown }
  if (!body || typeof body !== 'object' || body.sarif === undefined) {
    return safeError(res, 400, 'Provide a SARIF document.')
  }
  const publicValid = verifySarifPublicSignature(body.sarif)
  if (body.algorithm === 'Ed25519' || body.signature === undefined) {
    return res.json({ valid: publicValid, algorithm: 'Ed25519', keyId: publicValid ? sarifPublicKeyId(body.sarif) : null, trustScope: 'self-contained-integrity; pin keyId for signer identity' })
  }
  if (typeof body.signature !== 'string') return safeError(res, 400, 'Signature must be a string.')
  const hmacValid = verifySarifSignature(body.sarif, body.signature)
  return res.json({ valid: hmacValid, algorithm: 'HMAC-SHA256', keyId: signingKeyId(), trustScope: 'local-installation-only', portableSignatureValid: publicValid })
})

router.delete('/scans/:scanId', (req: Request, res: Response) => {
  const ok = deleteScan(req.params.scanId)
  if (!ok) return safeError(res, 404, 'Scan not found.')
  res.json({ deleted: true })
})

router.delete('/scans', (_req: Request, res: Response) => {
  const deleted = clearHistory()
  res.json({ deleted })
})

// ------------------------------------------------------------------
// AI Guardian extension bridge. This route requires an explicitly configured
// origin and high-entropy pairing token; it never allows missing-token fallback.
// ------------------------------------------------------------------
router.post('/extension/inspect', async (req: Request, res: Response) => {
  const expectedOrigin = process.env.SENTINEL_EXTENSION_ORIGIN
  const expectedToken = process.env.SENTINEL_EXTENSION_TOKEN
  const origin = req.headers.origin
  const suppliedToken = req.header('X-Sentinel-Pairing-Token') ?? ''
  if (!expectedOrigin || !expectedToken) return safeError(res, 503, 'Extension gateway is not configured; payload remains held.')
  if (origin !== expectedOrigin) return safeError(res, 403, 'Unpaired extension origin.')
  const expected = Buffer.from(expectedToken, 'utf8')
  const supplied = Buffer.from(suppliedToken, 'utf8')
  if (expected.length < 32 || supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    return safeError(res, 403, 'Invalid pairing token.')
  }
  const body = req.body as { text?: unknown; origin?: unknown }
  if (typeof body?.text !== 'string' || !body.text.trim() || body.text.length > 200_000) return safeError(res, 400, 'Text must be non-empty and at most 200,000 characters.')
  const allowedAiOrigins = new Set(['https://chatgpt.com', 'https://chat.openai.com', 'https://claude.ai', 'https://gemini.google.com'])
  if (typeof body.origin !== 'string' || !allowedAiOrigins.has(body.origin)) return safeError(res, 403, 'Unsupported AI destination origin.')
  try {
    const result = await privacyScanText(body.text)
    // No original text is echoed or logged by this route.
    return res.json({ decision: result.decision, risk: result.risk, entities: result.entities.map((e) => ({ entity_type: e.entity_type, start: e.start, end: e.end })), redactedText: result.redactedText, extractionState: result.extractionState })
  } catch {
    return safeError(res, 503, 'Local privacy analyzer unavailable; payload remains held.')
  }
})


// ------------------------------------------------------------------
// Privacy: text scan
// ------------------------------------------------------------------
router.post('/privacy/scan-text', async (req: Request, res: Response) => {
  try {
    const text = typeof (req.body as { text?: unknown })?.text === 'string' ? (req.body as { text: string }).text : ''
    if (!text.trim()) return safeError(res, 400, 'Text is required.')
    const result = await privacyScanText(text)
    res.json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    safeError(res, 502, `Privacy service unavailable: ${message.slice(0, 160)}`)
  }
})

// ------------------------------------------------------------------
// Privacy: file scan (multipart)
// ------------------------------------------------------------------
router.post('/privacy/scan-file', upload.single('file'), async (req: Request, res: Response) => {
  try {
    const file = req.file
    if (!file) return safeError(res, 400, 'No file was uploaded.')

    const scan = await privacyScanFile(file.path, file.mimetype, file.originalname)

    const initialReport: ScanReport = {
      scanId: newId(),
      createdAt: new Date().toISOString(),
      filename: file.originalname,
      size: file.size,
      sha256: await hashFile(file.path),
      coverage: [
        { analyzer: 'sha256-identity', state: 'completed_no_detections' },
        { analyzer: 'privacy-extraction', state: scan.result.extractionState },
      ],
      threat: null,
      privacy: scan.result,
      verdict: privacyDecisionToVerdict(scan.result.decision),
      verdictReason: privacyDecisionReason(scan.result.decision),
      assessment: currentAssessmentVersion(),
    }
    const { signature } = generateSarifPackage(initialReport)
    const report: ScanReport = {
      ...initialReport,
      signatureHmac: signature,
    }
    registerPrivacyScanBinding({ scanId: report.scanId, sha256: report.sha256, filename: report.filename, entities: scan.result.entities })
    saveScanReport(report)

    res.status(201).json({ ...scan.result, scanId: report.scanId, sourceSha256: report.sha256, priorReportsForSameFile: historyForHash(report.sha256).length - 1 })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error('[privacy] scan failed:', message)
    safeError(res, 502, message.slice(0, 240))
  } finally {
    if (req.file?.path) cleanupTemporaryFile(req.file.path)
  }
})

// Stage 16: extension attachment inspection uses the same pairing controls as text inspection.
router.post('/extension/inspect-file', extensionPairingGuard, upload.single('file'), async (req: Request, res: Response) => {
  try {
    if (!req.file) return safeError(res, 400, 'No attachment was uploaded.')
    const result = await runThreatScan({ filePath: req.file.path, originalName: req.file.originalname, size: req.file.size })
    const { verdict, verdictReason } = fuseVerdict(result.findings, result.coverage)
    const initialReport: ScanReport = {
      scanId: newId(), createdAt: new Date().toISOString(), filename: path.basename(req.file.originalname), size: req.file.size,
      sha256: result.sha256, coverage: result.coverage, threat: result.threat, privacy: null, verdict, verdictReason,
      sirGraph: result.sirGraph, counterfactualPlan: result.counterfactualPlan, assessment: currentAssessmentVersion(),
    }
    const { signature } = generateSarifPackage(initialReport)
    const report: ScanReport = { ...initialReport, signatureHmac: signature }
    saveScanReport(report)
    return res.json({ scanId: report.scanId, sha256: report.sha256, verdict: report.verdict, verdictReason: report.verdictReason, coverage: report.coverage })
  } catch {
    return safeError(res, 503, 'Local attachment inspection failed; attachment remains held.')
  } finally { if (req.file?.path) cleanupTemporaryFile(req.file.path) }
})


// ------------------------------------------------------------------
// Privacy: redact file (multipart + entities_json)
// ------------------------------------------------------------------
router.post('/privacy/redact-file', upload.single('file'), async (req: Request, res: Response) => {
  let outputPath: string | null = null
  let outputRegistered = false
  try {
    const file = req.file
    if (!file) return safeError(res, 400, 'No file was uploaded.')

    const fields = req.body as { entities_json?: string; scan_id?: string }
    const scanId = typeof fields.scan_id === 'string' ? fields.scan_id : ''
    if (!scanId) return safeError(res, 400, 'scan_id is required; run a privacy scan before redaction.')
    const binding = assertEntitiesBelongToScan(scanId, [])
    const uploadedHash = await hashFile(file.path)
    if (uploadedHash !== binding.sha256) {
      return safeError(res, 409, 'Uploaded file does not match the source artifact used by this privacy scan.')
    }
    const rawEntities = fields.entities_json
    if (!rawEntities) return safeError(res, 400, 'entities_json is required.')

    const parsedEntities: unknown = JSON.parse(rawEntities)
    if (!Array.isArray(parsedEntities) || parsedEntities.length === 0 || parsedEntities.length > 1000) {
      return safeError(res, 400, 'entities_json must be a non-empty array of at most 1000 entities.')
    }
    const entities = parsedEntities as Array<{
      entity_type: string
      text: string
      start: number
      end: number
      page?: number
    }>
    for (const entity of entities) {
      if (!entity || typeof entity !== 'object' || typeof entity.text !== 'string' || !entity.text.trim() ||
          typeof entity.entity_type !== 'string' || !Number.isSafeInteger(entity.start) ||
          !Number.isSafeInteger(entity.end) || entity.start < 0 || entity.end <= entity.start ||
          entity.end - entity.start !== entity.text.length ||
          (entity.page !== undefined && (!Number.isSafeInteger(entity.page) || entity.page < 0))) {
        return safeError(res, 400, 'Each redaction entity must have valid type, text, offsets, and optional page.')
      }
    }

    assertEntitiesBelongToScan(scanId, entities)
    const redaction = await privacyRedactFile(await fs.readFile(file.path), binding.filename, entities)
    const outputBuffer = Buffer.from(redaction.output_b64, 'base64')
    if (!redaction.verified || outputBuffer.length === 0) {
      return safeError(res, 422, 'Redaction service did not produce a verified non-empty derivative.')
    }

    // Stage 18: independently extract the newly produced bytes and verify that
    // none of the exact source targets remain. Failure to extract is a hard stop.
    const freshExtraction = await privacyExtractText(outputBuffer, redaction.output_filename)
    const residualTargets = findResidualRedactionTargets(freshExtraction.text, entities)
    if (residualTargets.length > 0) {
      return safeError(res, 422, `Redaction residue detected (${residualTargets.length} target value(s)); derivative withheld.`)
    }

    outputPath = newTemporaryPath(redaction.output_filename)
    await fs.writeFile(outputPath, outputBuffer)

    const token = path.basename(outputPath)
    registerDownload(token, outputPath)
    outputRegistered = true

    res.status(201).json({
      downloadUrl: `/api/privacy/download/${token}`,
      filename: redaction.output_filename,
      sha256: redaction.output_sha256,
      size: redaction.output_size,
      verified: redaction.verified,
      freshVerification: { state: 'completed_no_target_residue', extractionKind: freshExtraction.kind, targetCount: entities.length },
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error('[privacy] redaction failed:', message)
    safeError(res, 422, `Redaction failed: ${message.slice(0, 200)}`)
  } finally {
    if (req.file?.path) cleanupTemporaryFile(req.file.path)
    if (outputPath && !outputRegistered) cleanupTemporaryFile(outputPath)
  }
})

// Temporary verified-output download. Files are single-use and expire.
const downloads = new Map<string, { path: string; expires: number; timer: NodeJS.Timeout }>()
const DOWNLOAD_TTL_MS = 10 * 60 * 1000
function registerDownload(token: string, filePath: string): void {
  const timer = setTimeout(() => {
    const entry = downloads.get(token)
    if (entry?.path === filePath) downloads.delete(token)
    void cleanupTemporaryFile(filePath)
  }, DOWNLOAD_TTL_MS)
  timer.unref()
  downloads.set(token, { path: filePath, expires: Date.now() + DOWNLOAD_TTL_MS, timer })
}

router.get('/privacy/download/:token', (req: Request, res: Response) => {
  const token = req.params.token
  const entry = downloads.get(token)
  if (!entry) return safeError(res, 404, 'Download not found or expired.')
  downloads.delete(token)
  clearTimeout(entry.timer)
  if (Date.now() > entry.expires) {
    void cleanupTemporaryFile(entry.path)
    return safeError(res, 410, 'Download expired.')
  }

  // Single-use download. Remove the derivative whether transfer succeeds or
  // fails; this prevents verified output from lingering after delivery.
  let cleaned = false
  const cleanup = () => {
    if (cleaned) return
    cleaned = true
    void cleanupTemporaryFile(entry.path)
  }
  res.once('finish', cleanup)
  res.once('close', cleanup)
  res.download(entry.path, (error) => {
    if (error && !res.headersSent) safeError(res, 500, 'Verified output could not be downloaded.')
    cleanup()
  })
})

// Normalize Multer errors, which occur before route handlers are entered.
router.use((error: unknown, _req: Request, res: Response, _next: (error?: unknown) => void) => {
  if (error instanceof multer.MulterError) {
    const tooLarge = error.code === 'LIMIT_FILE_SIZE'
    return safeError(res, tooLarge ? 413 : 400, tooLarge
      ? `File exceeds the configured ${MAX_FILE_MB} MB upload limit.`
      : `Upload rejected: ${error.message}`)
  }
  if (error instanceof Error && /SENTINEL strict RAM vault unavailable/.test(error.message)) {
    return safeError(res, 503, 'Strict RAM vault unavailable; file intake is disabled.')
  }
  return safeError(res, 500, 'Upload processing failed.')
})

async function hashFile(filePath: string): Promise<string> {
  return blake3File(filePath)
}

export default router
