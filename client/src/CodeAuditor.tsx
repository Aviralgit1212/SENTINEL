import { useState } from 'react'
import type { Finding } from './types.js'

interface ToolRun {
  tool: string
  state: 'completed' | 'blocked' | 'failed' | 'timed_out'
  exitCode: number | null
  durationMs: number
  summary: string
  findings?: unknown[]
}

interface ToolchainAuditResult {
  state: 'completed' | 'partial' | 'blocked'
  runs: ToolRun[]
  notes: string[]
}

interface AuditResponse {
  sha256: string
  bytes: number
  languageHint: string
  state: 'completed' | 'inconclusive'
  findings: Finding[]
  limitations: string[]
}

const SAMPLE_CODE = `import express from 'express'
import mysql from 'mysql'

const app = express()
const db = mysql.createConnection({
  host: 'localhost',
  user: 'admin',
  password: 'dummy', // Hardcoded credential
})

app.get('/user', (req, res) => {
  // Unsafe query concatenation (SQL Injection)
  const sql = "SELECT * FROM users WHERE id = " + req.query.id
  db.query(sql, (err, rows) => {
    res.json(rows)
  })
})
`

export default function CodeAuditor() {
  const [source, setSource] = useState(SAMPLE_CODE)
  const [filename, setFilename] = useState('server.ts')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [heuristic, setHeuristic] = useState<AuditResponse | null>(null)
  const [toolchain, setToolchain] = useState<ToolchainAuditResult | null>(null)

  async function runAudit() {
    if (!source.trim()) return
    setBusy(true)
    setError(null)
    setHeuristic(null)
    setToolchain(null)

    try {
      // 1. Run local heuristic code audit
      const heurRes = await fetch('/api/code/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename }),
      })
      if (!heurRes.ok) throw new Error(`Heuristic audit failed (HTTP ${heurRes.status})`)
      const heurData = await heurRes.json()
      setHeuristic(heurData)

      // 2. Run offline toolchain audit (Semgrep, Gitleaks, OSV)
      const toolRes = await fetch('/api/code/audit/toolchain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename }),
      })
      if (toolRes.ok) {
        const toolData = await toolRes.json()
        setToolchain(toolData.toolchain)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Audit failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <div className="panel">
        <h2>Module 4: Code & Dependency Auditor</h2>
        <p className="muted">
          Static code analysis and dependency auditing without code execution. Runs heuristic AST pattern matching and
          queries local offline scanners (Semgrep, Gitleaks, OSV-Scanner).
        </p>

        <div className="row" style={{ marginBottom: '10px' }}>
          <label style={{ fontSize: '13px', color: '#94a3b8' }}>Filename: </label>
          <input
            type="text"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            style={{ width: '220px', padding: '6px 10px', background: '#0b0f14', color: '#fff', border: '1px solid #29323d', borderRadius: '4px' }}
          />
          <button className="primary" onClick={runAudit} disabled={busy || !source.trim()}>
            {busy ? 'Auditing…' : 'Run Code Audit'}
          </button>
        </div>

        <textarea
          rows={12}
          value={source}
          onChange={(e) => setSource(e.target.value)}
          disabled={busy}
          style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}
        />
        {error && <p className="error">{error}</p>}
      </div>

      {heuristic && (
        <div className="panel">
          <div className="report-head">
            <h3>
              Heuristic Audit Results{' '}
              <span className={`badge ${heuristic.findings.length > 0 ? 'bad' : 'ok'}`}>
                {heuristic.findings.length} Finding{heuristic.findings.length === 1 ? '' : 's'}
              </span>
              <span className="badge muted">lang: {heuristic.languageHint}</span>
              <span className="badge muted">size: {heuristic.bytes} B</span>
            </h3>
          </div>

          <div className="findings-list" style={{ marginTop: '12px' }}>
            {heuristic.findings.length === 0 ? (
              <p className="muted">No heuristic security violations detected.</p>
            ) : (
              heuristic.findings.map((f) => (
                <div key={f.id} className={`finding sev-${f.severity}`}>
                  <div className="finding-head">
                    <span className={`sev-pill ${f.severity}`}>{f.severity}</span>
                    <strong>{f.title}</strong>
                    <span className="muted finding-source">{f.location}</span>
                  </div>
                  <p>{f.description}</p>
                  {f.evidence && <pre className="evidence">{f.evidence}</pre>}
                </div>
              ))
            )}
          </div>

          {heuristic.limitations.length > 0 && (
            <div style={{ marginTop: '14px', fontSize: '12px', color: '#64748b' }}>
              <strong>Operational Limitations:</strong>
              <ul style={{ paddingLeft: '1.25rem', margin: '4px 0 0' }}>
                {heuristic.limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {toolchain && (
        <div className="panel">
          <h3>Local Toolchain Scanner Execution</h3>
          <p className="muted" style={{ fontSize: '12px' }}>
            External security binaries are called in offline, non-networked mode. Missing binaries or missing local configurations
            are explicitly reported as coverage gaps (never assumed clean).
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px', marginTop: '10px' }}>
            {toolchain.runs.map((run) => (
              <div
                key={run.tool}
                style={{
                  background: '#0d1319',
                  border: '1px solid #1d2937',
                  borderRadius: '6px',
                  padding: '12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong>{run.tool.toUpperCase()}</strong>
                  <span className={`badge ${run.state === 'completed' ? 'ok' : run.state === 'blocked' ? 'warn' : 'bad'}`}>
                    {run.state}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>{run.summary}</p>
                <div style={{ marginTop: '6px', fontSize: '11px', color: '#64748b' }}>
                  Execution time: {run.durationMs}ms {run.exitCode !== null ? `· Exit code: ${run.exitCode}` : ''}
                </div>
              </div>
            ))}
          </div>

          {toolchain.notes.length > 0 && (
            <div style={{ marginTop: '12px', fontSize: '12px', color: '#64748b' }}>
              {toolchain.notes.map((note, idx) => (
                <div key={idx}>· {note}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
