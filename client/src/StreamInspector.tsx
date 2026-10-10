import { useState } from 'react'

interface StreamEvent {
  event: string
  data: any
  timestamp: string
}

export default function StreamInspector() {
  const [file, setFile] = useState<File | null>(null)
  const [streaming, setStreaming] = useState(false)
  const [events, setEvents] = useState<StreamEvent[]>([])
  const [error, setError] = useState<string | null>(null)
  const [finalReport, setFinalReport] = useState<any>(null)

  async function startStreaming() {
    if (!file) return
    setStreaming(true)
    setEvents([])
    setError(null)
    setFinalReport(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/v3/scan-stream', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok || !response.body) {
        throw new Error(`Failed to initialize stream (HTTP ${response.status})`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        // Process SSE lines
        const lines = buffer.split('\n\n')
        buffer = lines.pop() || ''

        for (const block of lines) {
          if (!block.trim()) continue
          let currentEvent = 'message'
          let currentData = ''

          for (const line of block.split('\n')) {
            if (line.startsWith('event: ')) {
              currentEvent = line.slice(7).trim()
            } else if (line.startsWith('data: ')) {
              currentData = line.slice(6).trim()
            }
          }

          if (currentData) {
            try {
              const parsed = JSON.parse(currentData)
              const ev: StreamEvent = {
                event: currentEvent,
                data: parsed,
                timestamp: new Date().toLocaleTimeString(),
              }
              setEvents((prev) => [...prev, ev])

              if (currentEvent === 'complete') {
                setFinalReport(parsed)
              }
            } catch {
              // raw string
            }
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Streaming failed')
    } finally {
      setStreaming(false)
    }
  }

  return (
    <section>
      <div className="panel">
        <h2>Module 5: Two-Phase SSE Live Inspection Stream</h2>
        <p className="muted">
          Streams real-time evidence events from the Zero-Disk RAM Vault. Watch artifacts transform from raw bytes into Security
          Intermediate Representation (SIR), observe component visibility ledgers, and view counterfactual blocker resolutions.
        </p>

        <div className="row">
          <input
            type="file"
            disabled={streaming}
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          <button className="primary" onClick={startStreaming} disabled={streaming || !file}>
            {streaming ? 'Streaming Telemetry…' : 'Start SSE Live Stream'}
          </button>
        </div>
        {error && <p className="error" style={{ marginTop: '10px' }}>{error}</p>}
      </div>

      {events.length > 0 && (
        <div className="panel">
          <h3>Telemetry Event Stream ({events.length} Events)</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
            {events.map((ev, index) => (
              <div
                key={index}
                style={{
                  background: '#0d1319',
                  border: '1px solid #1d2937',
                  borderRadius: '6px',
                  padding: '10px 14px',
                  borderLeft: `3px solid ${
                    ev.event === 'complete' ? '#4ade80' : ev.event === 'finding' ? '#f87171' : '#38bdf8'
                  }`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, color: '#e2e8f0' }}>
                    <span className="pill" style={{ marginRight: '8px' }}>{ev.event}</span>
                    {ev.event === 'intake_ack' && `Received: ${ev.data.filename} (${ev.data.size} B)`}
                    {ev.event === 'analysis_started' && 'Multi-pass analysis pipeline initiated'}
                    {ev.event === 'sir_compiled' && `Security IR graph compiled (${ev.data.nodeCount} nodes)`}
                    {ev.event === 'finding' && `${ev.data.severity?.toUpperCase()}: ${ev.data.title}`}
                    {ev.event === 'counterfactual_plan' && 'Counterfactual Blocker Dependency Graph constructed'}
                    {ev.event === 'complete' && `Sealed Verdict: ${ev.data.verdict?.toUpperCase()}`}
                  </span>
                  <span className="muted small mono">{ev.timestamp}</span>
                </div>

                {ev.event === 'sir_compiled' && ev.data.visibility && (
                  <div style={{ marginTop: '8px', fontSize: '12px' }}>
                    <strong>Visibility Ledger Scopes:</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                      {Object.entries(ev.data.visibility).map(([scope, val]: [string, any]) => (
                        <span key={scope} className={`badge ${val.status === 'INSPECTED' ? 'ok' : 'warn'}`}>
                          {scope}: {val.status}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {ev.event === 'finding' && ev.data.description && (
                  <p style={{ margin: '6px 0 0', fontSize: '12px', color: '#94a3b8' }}>
                    {ev.data.description}
                  </p>
                )}

                {ev.event === 'complete' && (
                  <div style={{ marginTop: '8px', fontSize: '12px', color: '#4ade80' }}>
                    <div><strong>Verdict Reason:</strong> {ev.data.verdictReason}</div>
                    <div><strong>Machine Root HMAC:</strong> <span className="mono">{ev.data.signatureHmac}</span></div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {finalReport && (
        <div className="panel" style={{ borderLeft: '4px solid #4ade80' }}>
          <h3>Investigation Completed</h3>
          <p className="muted" style={{ margin: '4px 0 10px' }}>
            All pipeline passes executed. Cryptographic attestation generated and persisted to local database.
          </p>
          <div className="row">
            <span className={`badge ${finalReport.verdict === 'allow' ? 'ok' : finalReport.verdict === 'block' ? 'bad' : 'warn'}`}>
              Verdict: {finalReport.verdict}
            </span>
            <span className="muted small mono">Scan ID: {finalReport.scanId}</span>
            <a
              href={`/api/scans/${finalReport.scanId}/sarif`}
              target="_blank"
              rel="noreferrer"
              className="button"
              style={{ padding: '4px 10px', fontSize: '12px' }}
            >
              Export Signed SARIF
            </a>
          </div>
        </div>
      )}
    </section>
  )
}
