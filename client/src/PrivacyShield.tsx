import { useState } from 'react'
import type { PrivacyResult, PrivacyEntity } from './types.js'

const ENTITY_LABELS: Record<string, string> = {
  EMAIL_ADDRESS: 'Email',
  PHONE_NUMBER: 'Phone',
  CREDIT_CARD: 'Credit card',
  US_SSN: 'SSN',
  PERSON: 'Person',
  IP_ADDRESS: 'IP address',
}

function decisionClass(decision: string): string {
  if (decision === 'BLOCK') return 'bad'
  if (decision === 'REDACT') return 'warn'
  if (decision === 'ALLOW') return 'ok'
  return 'muted'
}

export default function PrivacyShield() {
  const [text, setText] = useState('')
  const [validating, setValidating] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<PrivacyResult | null>(null)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [fileForRedact, setFileForRedact] = useState<File | null>(null)
  const [redacted, setRedacted] = useState<{ filename: string; sha256: string; verified: boolean; downloadUrl: string } | null>(null)

  async function scanText() {
    setBusy(true)
    setError(null)
    setResult(null)
    setRedacted(null)
    setFileForRedact(null)
    try {
      const response = await fetch('/api/privacy/scan-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      })
      const data = await response.json()
      if (!response.ok) setError(data.message || 'Scan failed')
      else setResult(data)
      setSelected(new Set(data.entities?.map((_: unknown, i: number) => i) ?? []))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error')
    } finally {
      setBusy(false)
    }
  }

  async function scanFile(file: File) {
    setBusy(true)
    setError(null)
    setResult(null)
    setRedacted(null)
    setFileForRedact(file)
    try {
      const body = new FormData()
      body.append('file', file)
      const response = await fetch('/api/privacy/scan-file', { method: 'POST', body })
      const data = await response.json()
      if (!response.ok) setError(data.message || data.detail || 'Scan failed')
      else setResult(data)
      setSelected(new Set(data.entities?.map((_: unknown, i: number) => i) ?? []))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error')
    } finally {
      setBusy(false)
    }
  }

  async function redact() {
    if (!fileForRedact || !result) return
    setValidating(true)
    setError(null)
    try {
      const entities: PrivacyEntity[] = result.entities.filter((_, i) => selected.has(i))
      const body = new FormData()
      body.append('file', fileForRedact)
      if (!result.scanId) {
        setError('This scan has no source identity. Scan the file again before redacting.')
        return
      }
      body.append('scan_id', result.scanId)
      body.append('entities_json', JSON.stringify(entities))
      const response = await fetch('/api/privacy/redact-file', { method: 'POST', body })
      const data = await response.json()
      if (!response.ok) setError(data.message || 'Redaction failed')
      else setRedacted(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error')
    } finally {
      setValidating(false)
    }
  }

  const originalShaNote =
    result?.extractionState === 'failed' || result?.extractionState === 'timed_out'
      ? 'Extraction did not complete: sensitive data may be present but undetectable.'
      : null

  return (
    <section>
      <div className="panel">
        <h2>Privacy Shield</h2>
        <p className="muted">
          Detect sensitive entities in text or documents, review them, then generate a redacted output that is re-scanned and
          verified before download.
        </p>

        <textarea
          rows={6}
          placeholder="Paste text to inspect: e.g., 'Contact Ash at ash@example.com, card 4111 1111 1111 1111' or upload a document below"
          value={text}
          onChange={(event) => setText(event.target.value)}
          disabled={busy}
        />
        <div className="row">
          <button className="primary" onClick={scanText} disabled={busy || !text.trim()}>
            {busy ? 'Scanning…' : 'Scan text'}
          </button>
          <input
            type="file"
            accept=".pdf,.docx,.docm,.png,.jpg,.jpeg"
            disabled={busy}
            onChange={(event) => {
              const file = event.target.files?.[0]
              if (file) void scanFile(file)
            }}
          />
        </div>
        {error && <p className="error">{error}</p>}
      </div>

      {result && (
        <div className="panel">
          <div className="report-head">
            <h3>
              Result{' '}
              <span className={`badge ${decisionClass(result.decision)}`}>{result.decision}</span>
              <span className="badge muted">risk: {result.risk}</span>
              {result.kind && <span className="badge muted">kind: {result.kind}</span>}
            </h3>
          </div>

          {originalShaNote && <p className="error">{originalShaNote}</p>}

          <h4>Entities ({result.entities.length})</h4>
          {result.entities.length === 0 ? (
            <p className="muted">No sensitive entities detected in the regions that were extractable.</p>
          ) : (
            <>
              <div className="entity-list">
                {result.entities.map((entity, index) => (
                  <label key={index} className="entity-row">
                    <input
                      type="checkbox"
                      checked={selected.has(index)}
                      onChange={(event) => {
                        const next = new Set(selected)
                        if (event.target.checked) next.add(index)
                        else next.delete(index)
                        setSelected(next)
                      }}
                    />
                    <span className={`pill ${entity.entity_type}`}>{ENTITY_LABELS[entity.entity_type] ?? entity.entity_type}</span>
                    <code className="entity-text">{entity.text.length > 40 ? `${entity.text.slice(0, 37)}…` : entity.text}</code>
                    {typeof entity.page === 'number' && <span className="muted">page {entity.page}</span>}
                  </label>
                ))}
              </div>
              <p className="muted small">Checked entities will be redacted. Unchecked ones are left in place.</p>
            </>
          )}

          {result.redactedText && (
            <div>
              <h4>Redacted text</h4>
              <pre className="redacted-preview">{result.redactedText}</pre>
            </div>
          )}

          {fileForRedact && result.entities.length > 0 && (
            <div className="row">
              <button className="primary" onClick={redact} disabled={validating || selected.size === 0}>
                {validating ? 'Redacting & verifying…' : `Redact ${selected.size} selected entity/entities`}
              </button>
            </div>
          )}

          {redacted && (
            <div className="panel verified-panel">
              <h4>
                ✔ Verified redacted output — <span className="mono">{redacted.filename}</span>
              </h4>
              <p className="muted small">
                The generated file was re-opened and re-scanned. No original sensitive values remain in the inspected regions.
                Identity (BLAKE3): <span className="mono">{redacted.sha256.slice(0, 24)}…</span>
              </p>
              <a className="button" href={redacted.downloadUrl}>
                Download verified output
              </a>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
