import { useState, useEffect } from 'react'

interface HistoryEntry {
  scan_id: string
  filename: string
  created_at: string
  verdict: string
  sha256: string
}

interface AssessmentComparison {
  sameArtifact: boolean
  artifactSha256: string
  verdictChanged: boolean
  findings: {
    added: Array<{ title: string; severity: string; description: string }>
    removed: Array<{ title: string; severity: string; description: string }>
    unchangedCount: number
  }
  coverage: Array<{ analyzer: string; before: string | null; after: string | null; changed: boolean }>
  limitations: string[]
}

interface VerificationResult {
  valid: boolean
  algorithm: string
  keyId: string | null
  trustScope: string
  portableSignatureValid?: boolean
}

export default function TimeMachineAttestation() {
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [selectedScan, setSelectedScan] = useState<string>('')
  const [compareScan, setCompareScan] = useState<string>('')
  const [comparison, setComparison] = useState<AssessmentComparison | null>(null)
  const [sarifInput, setSarifInput] = useState('')
  const [signatureInput, setSignatureInput] = useState('')
  const [verifyResult, setVerifyResult] = useState<VerificationResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void loadHistory()
  }, [])

  async function loadHistory() {
    try {
      const res = await fetch('/api/scans')
      if (res.ok) {
        const data = await res.json()
        setHistory(data)
        if (data.length > 0) setSelectedScan(data[0].scan_id)
      }
    } catch {
      // ignore
    }
  }

  async function handleCompare() {
    if (!selectedScan || !compareScan) return
    setBusy(true)
    setError(null)
    setComparison(null)
    try {
      const res = await fetch(`/api/scans/${selectedScan}/compare/${compareScan}`)
      const data = await res.json()
      if (!res.ok) {
        setError(data.message || 'Comparison failed')
      } else {
        setComparison(data)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error')
    } finally {
      setBusy(false)
    }
  }

  async function handleVerifySarif() {
    if (!sarifInput.trim()) return
    setBusy(true)
    setError(null)
    setVerifyResult(null)
    try {
      const parsed = JSON.parse(sarifInput)
      const res = await fetch('/api/attestations/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sarif: parsed,
          signature: signatureInput.trim() || undefined,
          algorithm: signatureInput.trim() ? 'HMAC-SHA256' : 'Ed25519',
        }),
      })
      const data = await res.json()
      if (!res.ok) setError(data.message || 'Verification rejected')
      else setVerifyResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid SARIF JSON or network error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      {/* 1. Security Time Machine */}
      <div className="panel">
        <h2>Security Time Machine: Historical Assessments & Delta Rescans</h2>
        <p className="muted">
          Decouples byte identity (SHA-256) from evolving security rules. Compares past assessments of the exact same artifact
          to audit finding changes without retaining raw files on disk.
        </p>

        <div className="row" style={{ marginTop: '12px' }}>
          <div>
            <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block' }}>Current / Target Assessment:</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              style={{ padding: '6px', background: '#0b0f14', color: '#fff', border: '1px solid #29323d', borderRadius: '4px' }}
            >
              {history.map((h) => (
                <option key={h.scan_id} value={h.scan_id}>
                  {h.filename} ({h.verdict}) — {new Date(h.created_at).toLocaleTimeString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block' }}>Baseline to Compare Against:</label>
            <select
              value={compareScan}
              onChange={(e) => setCompareScan(e.target.value)}
              style={{ padding: '6px', background: '#0b0f14', color: '#fff', border: '1px solid #29323d', borderRadius: '4px' }}
            >
              <option value="">Select a prior scan…</option>
              {history.map((h) => (
                <option key={h.scan_id} value={h.scan_id}>
                  {h.filename} ({h.verdict}) — {new Date(h.created_at).toLocaleTimeString()}
                </option>
              ))}
            </select>
          </div>

          <button className="primary" onClick={handleCompare} disabled={busy || !selectedScan || !compareScan} style={{ alignSelf: 'flex-end' }}>
            {busy ? 'Comparing…' : 'Compute Epistemic Delta'}
          </button>
        </div>

        {error && <p className="error" style={{ marginTop: '12px' }}>{error}</p>}
      </div>

      {comparison && (
        <div className="panel">
          <div className="report-head">
            <h3>
              Epistemic Delta Report{' '}
              <span className={`badge ${comparison.verdictChanged ? 'warn' : 'ok'}`}>
                Verdict Changed: {comparison.verdictChanged ? 'YES' : 'NO'}
              </span>
            </h3>
            <div className="muted mono small">Artifact SHA-256: {comparison.artifactSha256}</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginTop: '12px' }}>
            <div style={{ background: '#0d1319', padding: '12px', borderRadius: '6px', border: '1px solid #1d2937' }}>
              <h4 style={{ margin: '0 0 8px', color: '#f87171' }}>Added Findings ({comparison.findings.added.length})</h4>
              {comparison.findings.added.length === 0 ? (
                <p className="muted small">No new findings introduced in this ruleset snapshot.</p>
              ) : (
                comparison.findings.added.map((f, i) => (
                  <div key={i} style={{ marginBottom: '6px', fontSize: '12px' }}>
                    <strong>+ {f.title}</strong>: {f.description}
                  </div>
                ))
              )}
            </div>

            <div style={{ background: '#0d1319', padding: '12px', borderRadius: '6px', border: '1px solid #1d2937' }}>
              <h4 style={{ margin: '0 0 8px', color: '#4ade80' }}>Removed Findings ({comparison.findings.removed.length})</h4>
              {comparison.findings.removed.length === 0 ? (
                <p className="muted small">No findings resolved or removed.</p>
              ) : (
                comparison.findings.removed.map((f, i) => (
                  <div key={i} style={{ marginBottom: '6px', fontSize: '12px' }}>
                    <strong>- {f.title}</strong>: {f.description}
                  </div>
                ))
              )}
            </div>
          </div>

          <div style={{ marginTop: '12px', fontSize: '12px', color: '#64748b' }}>
            Unchanged Findings Count: {comparison.findings.unchangedCount}
          </div>
        </div>
      )}

      {/* 2. Cryptographic Attestation Verification */}
      <div className="panel">
        <h2>Cryptographic Attestation & SARIF Integrity Verifier</h2>
        <p className="muted">
          Validates OASIS SARIF v2.1 attestation documents against machine-root HMAC-SHA256 and portable Ed25519 digital signatures.
          Detects any tampering in verdicts, findings, or visibility ledgers.
        </p>

        <textarea
          rows={6}
          placeholder="Paste SARIF JSON document here to verify authenticity…"
          value={sarifInput}
          onChange={(e) => setSarifInput(e.target.value)}
          disabled={busy}
          style={{ fontFamily: 'ui-monospace, monospace', fontSize: '11px' }}
        />

        <div className="row">
          <input
            type="text"
            placeholder="Optional HMAC-SHA256 Hex Signature (leave empty to verify embedded Ed25519 public signature)"
            value={signatureInput}
            onChange={(e) => setSignatureInput(e.target.value)}
            style={{ flex: 1, padding: '8px', background: '#0b0f14', color: '#fff', border: '1px solid #29323d', borderRadius: '4px' }}
          />
          <button className="primary" onClick={handleVerifySarif} disabled={busy || !sarifInput.trim()}>
            {busy ? 'Verifying…' : 'Verify Signature'}
          </button>
        </div>

        {verifyResult && (
          <div
            style={{
              marginTop: '14px',
              padding: '12px',
              borderRadius: '6px',
              background: verifyResult.valid ? '#4ade8011' : '#f8717111',
              border: `1px solid ${verifyResult.valid ? '#4ade8044' : '#f8717144'}`,
            }}
          >
            <h4 style={{ margin: 0, color: verifyResult.valid ? '#4ade80' : '#f87171' }}>
              {verifyResult.valid ? '✔ Cryptographically Valid Attestation' : '✖ Signature Verification Failed / Tampered Document'}
            </h4>
            <div style={{ fontSize: '12px', marginTop: '6px', color: '#d7e2ec' }}>
              <div><strong>Algorithm:</strong> {verifyResult.algorithm}</div>
              <div><strong>Key ID:</strong> {verifyResult.keyId ?? 'None'}</div>
              <div><strong>Trust Scope:</strong> {verifyResult.trustScope}</div>
              {verifyResult.portableSignatureValid !== undefined && (
                <div><strong>Portable Ed25519 Valid:</strong> {verifyResult.portableSignatureValid ? 'YES' : 'NO'}</div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
