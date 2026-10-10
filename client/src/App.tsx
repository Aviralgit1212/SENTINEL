import { useState } from 'react'
import ThreatInspector from './ThreatInspector.js'
import PrivacyShield from './PrivacyShield.js'
import CodeAuditor from './CodeAuditor.js'
import TimeMachineAttestation from './TimeMachineAttestation.js'
import StreamInspector from './StreamInspector.js'
import './app.css'

type Tool = 'threat' | 'stream' | 'privacy' | 'code' | 'timemachine'

export default function App() {
  const [tool, setTool] = useState<Tool>('threat')

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="logo">SENTINEL</span>
          <span className="tagline">Sovereign Core v3.0</span>
        </div>
        <nav className="tabs">
          <button
            className={`tab ${tool === 'threat' ? 'active' : ''}`}
            onClick={() => setTool('threat')}
          >
            Threat Inspector
          </button>
          <button
            className={`tab ${tool === 'stream' ? 'active' : ''}`}
            onClick={() => setTool('stream')}
          >
            SSE Live Stream
          </button>
          <button
            className={`tab ${tool === 'privacy' ? 'active' : ''}`}
            onClick={() => setTool('privacy')}
          >
            Privacy Shield
          </button>
          <button
            className={`tab ${tool === 'code' ? 'active' : ''}`}
            onClick={() => setTool('code')}
          >
            Code Auditor
          </button>
          <button
            className={`tab ${tool === 'timemachine' ? 'active' : ''}`}
            onClick={() => setTool('timemachine')}
          >
            Time Machine & Attestations
          </button>
        </nav>
      </header>
      <main className="content">
        {tool === 'threat' && <ThreatInspector />}
        {tool === 'stream' && <StreamInspector />}
        {tool === 'privacy' && <PrivacyShield />}
        {tool === 'code' && <CodeAuditor />}
        {tool === 'timemachine' && <TimeMachineAttestation />}
      </main>
      <footer className="footnote">
        Local-first analysis · findings are evidence-backed · zero NAND writes · failed checks are never reported as clean
      </footer>
    </div>
  )
}

