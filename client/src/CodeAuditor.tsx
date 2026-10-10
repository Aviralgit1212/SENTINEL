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
  blake3?: string
  sha256: string
  bytes: number
  languageHint: string
  state: 'completed' | 'inconclusive'
  findings: Finding[]
  limitations: string[]
}

const PRESETS = [
  {
    name: 'Node.js (SQLi & Secret)',
    filename: 'server.ts',
    code: `import express from 'express'
import mysql from 'mysql'

const app = express()
const db = mysql.createConnection({
  host: 'localhost',
  user: 'admin',
  password: 'SuperSecretDatabasePassword123!', // Hardcoded credential
})

app.get('/user', (req, res) => {
  // Unsafe query concatenation (SQL Injection)
  const sql = "SELECT * FROM users WHERE id = " + req.query.id
  db.query(sql, (err, rows) => {
    res.json(rows)
  })
})
`,
  },
  {
    name: 'Python (RCE & Deserialization)',
    filename: 'app.py',
    code: `import os
import pickle
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/backup')
def backup():
    # Command Injection
    target = request.args.get('target')
    os.system("tar -czf backup.tar.gz " + target)
    return "Backup created"

@app.route('/session', methods=['POST'])
def load_session():
    # Unsafe Deserialization
    data = request.get_data()
    session_data = pickle.loads(data)
    return f"Welcome {session_data}"
`,
  },
  {
    name: 'NPM Manifest (Known CVEs)',
    filename: 'package.json',
    code: `{
  "name": "sample-microservice",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.16.0",
    "minimist": "1.2.0",
    "axios": "0.21.0"
  }
}
`,
  },
  {
    name: 'Python Manifest (Known CVEs)',
    filename: 'requirements.txt',
    code: `pyyaml==5.3.1
requests==2.25.1
urllib3==1.26.5
pillow==9.5.0
jinja2==3.0.1
sqlparse==0.4.3
`,
  },
]

export default function CodeAuditor() {
  const [source, setSource] = useState(PRESETS[0].code)
  const [filename, setFilename] = useState(PRESETS[0].filename)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [heuristic, setHeuristic] = useState<AuditResponse | null>(null)
  const [toolchain, setToolchain] = useState<ToolchainAuditResult | null>(null)

  function loadPreset(preset: (typeof PRESETS)[number]) {
    setFilename(preset.filename)
    setSource(preset.code)
    setHeuristic(null)
    setToolchain(null)
    setError(null)
  }

  async function runAudit() {
    if (!source.trim()) return
    setBusy(true)
    setError(null)
    setHeuristic(null)
    setToolchain(null)

    try {
      // 1. Run local heuristic & CVE dependency audit
      const heurRes = await fetch('/api/code/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename }),
      })
      if (!heurRes.ok) throw new Error(`Heuristic audit failed (HTTP ${heurRes.status})`)
      const heurData = await heurRes.json()
      setHeuristic(heurData)

      // 2. Run offline toolchain audit (Semgrep, Gitleaks, OSV, Trivy)
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
          Static code analysis and dependency auditing without code execution. Runs heuristic AST pattern matching,
          detects known CVE vulnerabilities in package manifests, and queries local offline scanners (Semgrep, Gitleaks, OSV-Scanner, Trivy).
        </p>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', margin: '12px 0' }}>
          <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>PRESETS:</span>
          {PRESETS.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => loadPreset(p)}
              disabled={busy}
              style={{
                fontSize: '11px',
                padding: '4px 10px',
                background: filename === p.filename ? '#1e293b' : '#0b0f14',
                borderColor: filename === p.filename ? '#3b82f6' : '#29323d',
                color: filename === p.filename ? '#60a5fa' : '#94a3b8',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              {p.name}
            </button>
          ))}
        </div>

        <div className="row" style={{ marginBottom: '10px' }}>
          <label style={{ fontSize: '13px', color: '#94a3b8' }}>Filename: </label>
          <input
            type="text"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            style={{
              width: '220px',
              padding: '6px 10px',
              background: '#0b0f14',
              color: '#fff',
              border: '1px solid #29323d',
              borderRadius: '4px',
            }}
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
              Heuristic & Dependency Audit Results{' '}
              <span className={`badge ${heuristic.findings.length > 0 ? 'bad' : 'ok'}`}>
                {heuristic.findings.length} Finding{heuristic.findings.length === 1 ? '' : 's'}
              </span>
              <span className="badge muted">lang: {heuristic.languageHint}</span>
              <span className="badge muted">blake3: {(heuristic.blake3 || heuristic.sha256).slice(0, 16)}…</span>
              <span className="badge muted">size: {heuristic.bytes} B</span>
            </h3>
          </div>

          <div className="findings-list" style={{ marginTop: '12px' }}>
            {heuristic.findings.length === 0 ? (
              <p className="muted">No security violations or vulnerable dependencies detected.</p>
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
              <strong>Operational Scope:</strong>
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
            External security scanners run in isolated offline mode with sovereign embedded engines active.
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '12px',
              marginTop: '10px',
            }}
          >
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
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '6px',
                  }}
                >
                  <strong>{run.tool.toUpperCase()}</strong>
                  <span
                    className={`badge ${
                      run.state === 'completed' ? 'ok' : run.state === 'blocked' ? 'warn' : 'bad'
                    }`}
                  >
                    {run.state}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>{run.summary}</p>
                <div style={{ marginTop: '6px', fontSize: '11px', color: '#64748b' }}>
                  Execution time: {run.durationMs}ms {run.exitCode !== null ? `· Exit code: ${run.exitCode}` : ''}
                </div>

                {Array.isArray(run.findings) && run.findings.length > 0 && (
                  <div style={{ marginTop: '10px', borderTop: '1px solid #1d2937', paddingTop: '8px' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#f59e0b', marginBottom: '6px' }}>
                      Detected {run.findings.length} item(s):
                    </div>
                    <div style={{ maxHeight: '160px', overflowY: 'auto' }}>
                      {run.findings.map((finding: any, fIdx: number) => {
                        const title =
                          finding.title ||
                          finding.Description ||
                          finding.check_id ||
                          finding.RuleID ||
                          'Security Finding'
                        const detail =
                          finding.description ||
                          finding.extra?.message ||
                          finding.Match ||
                          finding.message ||
                          ''
                        const loc =
                          finding.location ||
                          (finding.File && finding.StartLine ? `${finding.File}:${finding.StartLine}` : '') ||
                          (finding.path && finding.start?.line ? `${finding.path}:${finding.start.line}` : '')
                        return (
                          <div
                            key={fIdx}
                            style={{
                              background: '#131b24',
                              padding: '6px 8px',
                              borderRadius: '4px',
                              marginBottom: '4px',
                              fontSize: '11px',
                            }}
                          >
                            <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{title}</div>
                            {loc && <div style={{ color: '#64748b', fontSize: '10px' }}>{loc}</div>}
                            {detail && <div style={{ color: '#94a3b8', marginTop: '2px' }}>{detail}</div>}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
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
