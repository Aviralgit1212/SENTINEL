import { useCallback, useState, useEffect } from 'react'
import type { ScanReport, Finding, CoverageEntry } from './types.js'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const

function CoverageBadge({ entry }: { entry: CoverageEntry }) {
  const styles: Record<string, string> = {
    completed_no_detections: 'ok',
    finding: 'warn',
    failed: 'bad',
    timed_out: 'bad',
    unavailable: 'bad',
    inconclusive: 'warn',
    skipped_by_policy: 'muted',
    not_applicable: 'muted',
  }
  const labels: Record<string, string> = {
    completed_no_detections: '✔ completed',
    finding: '⚑ finding',
    failed: '✖ failed',
    timed_out: '✖ timed out',
    unavailable: '✖ unavailable',
    inconclusive: '≈ inconclusive',
    skipped_by_policy: '— skipped',
    not_applicable: '— n/a',
  }
  return (
    <div className={`coverage-item ${styles[entry.state] ?? 'muted'}`} title={entry.detail ?? ''}>
      <span className="coverage-name">{entry.analyzer}</span>
      <span className={`badge ${styles[entry.state] ?? 'muted'}`}>
        {labels[entry.state] ?? entry.state}
      </span>
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className={`finding sev-${finding.severity}`}>
      <div className="finding-head">
        <span className={`sev-pill ${finding.severity}`}>{finding.severity}</span>
        <strong>{finding.title}</strong>
        <span className="muted finding-source">
          {finding.source}
          {finding.location ? ` · ${finding.location}` : ''}
        </span>
      </div>
      <p>{finding.description}</p>
      {finding.evidence ? <pre className="evidence">{finding.evidence}</pre> : null}
    </div>
  )
}

export default function ThreatInspector() {
  const [report, setReport] = useState<ScanReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<Array<{ scan_id: string; filename: string; created_at: string; verdict: string }>>([])

  const loadHistory = useCallback(async () => {
    try {
      const response = await fetch('/api/scans')
      if (response.ok) setHistory(await response.json())
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    void loadHistory()
  }, [loadHistory])

  const upload = useCallback(
    async (file: File) => {
      setBusy(true)
      setError(null)
      try {
        const body = new FormData()
        body.append('file', file)
        const response = await fetch('/api/scans', { method: 'POST', body })
        const data = await response.json()
        if (!response.ok) {
          setError(data.message || `Scan failed (HTTP ${response.status})`)
          setReport(null)
        } else {
          setReport(data)
        }
        await loadHistory()
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Network error')
      } finally {
        setBusy(false)
      }
    },
    [loadHistory],
  )

  const sortedFindings = report?.threat?.findings
    ? [...report.threat.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    : []

  const verdictClass: Record<string, string> = {
    block: 'bad',
    review_required: 'warn',
    allow_with_warnings: 'warn',
    allow: 'ok',
  }

  return (
    <section>
      <div className="panel">
        <h2>Threat & Content Inspector</h2>
        <p className="muted">
          Upload any file for structural inspection, malware signature check, stealth prompt-injection detection, and counterfactual remediation planning.
        </p>
        <input
          type="file"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) void upload(file)
          }}
        />
        {busy && <p className="scan-note">Compiling Security IR & Analyzing… (ClamAV + Differential AST)</p>}
        {error && <p className="error">{error}</p>}
      </div>

      {report && (
        <>
          <div className="panel">
            <div className="report-head">
              <h3>
                {report.filename}{' '}
                <span className={`verdict ${verdictClass[report.verdict]}`}>{report.verdict.replace(/_/g, ' ')}</span>
              </h3>
              <div className="muted mono small">
                sha256: <span className="mono">{report.sha256.slice(0, 24)}…</span> · {(report.size / 1024).toFixed(1)} KB ·{' '}
                {new Date(report.createdAt).toLocaleString()}
              </div>
            </div>
            <p className="verdict-reason">{report.verdictReason}</p>

            {report.signatureHmac && (
              <div style={{ marginTop: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="badge ok" title={`Machine Root HMAC: ${report.signatureHmac}`}>
                  ✔ Machine-Signed Evidence (HMAC-SHA256: {report.signatureHmac.slice(0, 12)}…)
                </span>{' '}
                <a
                  href={`/api/scans/${report.scanId}/sarif`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ fontSize: '0.85rem', marginLeft: '0.5rem', textDecoration: 'underline' }}
                >
                  Download SARIF v2.1 Package
                </a>
              </div>
            )}

            <h4>Visibility & Coverage</h4>
            <div className="coverage-grid">
              {report.coverage.map((entry) => (
                <CoverageBadge key={entry.analyzer} entry={entry} />
              ))}
            </div>
          </div>

          {report.counterfactualPlan && report.counterfactualPlan.blockers.length > 0 && (
            <div className="panel" style={{ borderLeft: '4px solid var(--accent, #3b82f6)' }}>
              <h3>Counterfactual Security: Required Actions to Allow</h3>
              <p className="muted">
                Target Action: <code>{report.counterfactualPlan.targetContext}</code>. The following sequence of minimal transformations will satisfy policy:
              </p>
              <ol style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
                {report.counterfactualPlan.minimalActionSequence.map((step) => (
                  <li key={step.step} style={{ marginBottom: '0.5rem' }}>
                    <strong>{step.actionName.replace(/_/g, ' ')}</strong>: {step.description}
                    {step.targetLocation ? <span className="muted"> ({step.targetLocation})</span> : null}
                  </li>
                ))}
              </ol>
            </div>
          )}

          <div className="panel">
            <h3>Findings ({sortedFindings.length})</h3>
            {sortedFindings.length === 0 ? (
              <p className="muted">No findings detected by any active analyzer.</p>
            ) : (
              <div className="findings-list">
                {sortedFindings.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {history.length > 0 && (
        <div className="panel">
          <h3>Recent Local Scans</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #333' }}>
                <th style={{ padding: '0.5rem 0' }}>File</th>
                <th>Verdict</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {history.slice(0, 10).map((h) => (
                <tr key={h.scan_id} style={{ borderBottom: '1px solid #222' }}>
                  <td style={{ padding: '0.5rem 0' }}>{h.filename}</td>
                  <td>
                    <span className={`sev-pill ${h.verdict === 'block' ? 'critical' : h.verdict === 'allow' ? 'low' : 'medium'}`}>
                      {h.verdict}
                    </span>
                  </td>
                  <td className="muted">{new Date(h.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
