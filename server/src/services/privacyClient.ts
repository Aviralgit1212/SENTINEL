import { verifyRedactionPayload } from './redactionIntegrity.js'
import type { PrivacyResult, AnalyzerState } from '../types.js'

const PRIVACY_SERVICE_URL = process.env.PRIVACY_SERVICE_URL ?? 'http://127.0.0.1:8100'
const TIMEOUT_MS = 120_000

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

export async function privacyServiceHealth(): Promise<{ ok: boolean; detail: string }> {
  try {
    const response = await fetchWithTimeout(`${PRIVACY_SERVICE_URL}/ping`, { method: 'GET' })
    if (!response.ok) return { ok: false, detail: `HTTP ${response.status}` }
    const body = (await response.json()) as { ok?: boolean; scanner?: string }
    return { ok: Boolean(body.ok), detail: body.ok ? 'scanner ready' : 'scanner not ready' }
  } catch {
    return { ok: false, detail: 'unreachable' }
  }
}

export interface PrivacyScanFileResult {
  result: PrivacyResult
  entities: Array<{ entity_type: string; text: string; start: number; end: number; page?: number }>
}

export async function privacyScanText(text: string): Promise<PrivacyResult> {
  const response = await fetchWithTimeout(`${PRIVACY_SERVICE_URL}/scan/json`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: text.slice(0, 200_000) }),
  })
  if (!response.ok) {
    throw new Error(`privacy service HTTP ${response.status}`)
  }
  const body = (await response.json()) as {
    entities: PrivacyResult['entities']
    risk: PrivacyResult['risk']
    decision: PrivacyResult['decision']
    redacted_text: string | null
    error?: string
  }
  return {
    kind: 'json',
    risk: body.risk,
    decision: body.decision,
    entities: body.entities,
    redactedText: body.redacted_text,
    extractionState: 'completed_no_detections',
    error: body.error,
  }
}

export async function privacyScanFile(
  filePath: string,
  declaredMime: string | null,
  originalName: string,
): Promise<PrivacyScanFileResult> {
  const data = (await import('node:fs/promises')).readFile(filePath)
  const blob = new Blob([await data])
  const form = new FormData()
  form.append('file', blob, originalName)

  const response = await fetchWithTimeout(`${PRIVACY_SERVICE_URL}/privacy/scan-file`, {
    method: 'POST',
    body: form,
  })
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null
    throw new Error(detail?.detail || `privacy service HTTP ${response.status}`)
  }
  const body = (await response.json()) as {
    kind: PrivacyResult['kind']
    risk: PrivacyResult['risk']
    decision: PrivacyResult['decision']
    entities: PrivacyResult['entities']
    extracted_char_count?: number
  }
  return {
    result: {
      kind: body.kind,
      filename: originalName,
      risk: body.risk,
      decision: body.decision,
      entities: body.entities,
      redactedText: null,
      extractionState: 'completed_no_detections',
    },
    entities: body.entities,
  }
}

export async function privacyExtractState(error: unknown): Promise<PrivacyResult> {
  const message = error instanceof Error ? error.message : String(error)
  const state: AnalyzerState = /abort|timed out/i.test(message) ? 'timed_out' : 'failed'
  return {
    kind: 'json',
    risk: 'UNKNOWN',
    decision: 'UNKNOWN',
    entities: [],
    redactedText: null,
    extractionState: state,
    error: message.slice(0, 300),
  }
}


/** Extract text from derivative bytes using the format-aware privacy service.
 * Callers must treat an exception as verification failure, never as a clean result. */
export async function privacyExtractText(fileBuffer: Buffer, originalName: string): Promise<{ kind: string; text: string }> {
  const blob = new Blob([new Uint8Array(fileBuffer)])
  const form = new FormData()
  form.append('file', blob, originalName)
  const response = await fetchWithTimeout(`${PRIVACY_SERVICE_URL}/privacy/extract-text`, { method: 'POST', body: form })
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null
    throw new Error(detail?.detail || `privacy extraction HTTP ${response.status}`)
  }
  const body = (await response.json()) as { kind?: unknown; text?: unknown }
  if (typeof body.kind !== 'string' || typeof body.text !== 'string') throw new Error('Privacy extraction returned an invalid response.')
  return { kind: body.kind, text: body.text }
}

export interface RedactRequestEntities {
  entity_type: string
  text: string
  start: number
  end: number
  page?: number
}

export async function privacyRedactFile(
  fileBuffer: Buffer,
  originalName: string,
  entities: RedactRequestEntities[],
): Promise<{
  output_b64: string
  output_filename: string
  output_sha256: string
  output_size: number
  verified: boolean
}> {
  const blob = new Blob([new Uint8Array(fileBuffer)])
  const form = new FormData()
  form.append('file', blob, originalName)
  form.append('entities_json', JSON.stringify(entities))

  const response = await fetchWithTimeout(`${PRIVACY_SERVICE_URL}/privacy/redact-file`, {
    method: 'POST',
    body: form,
  })
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null
    throw new Error(detail?.detail || `privacy service HTTP ${response.status}`)
  }
  const body = (await response.json()) as {
    output_b64?: unknown
    output_filename?: unknown
    output_sha256?: unknown
    output_size?: unknown
    verified?: unknown
  }
  return verifyRedactionPayload(body)
}
