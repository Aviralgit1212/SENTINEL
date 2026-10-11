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
          <span className="logo">S</span>
          <span className="logo-word">SENTINEL</span>
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
        <div className="tab-pane" style={{ display: tool === 'threat' ? 'block' : 'none' }}>
          <ThreatInspector />
        </div>
        <div className="tab-pane" style={{ display: tool === 'stream' ? 'block' : 'none' }}>
          <StreamInspector />
        </div>
        <div className="tab-pane" style={{ display: tool === 'privacy' ? 'block' : 'none' }}>
          <PrivacyShield />
        </div>
        <div className="tab-pane" style={{ display: tool === 'code' ? 'block' : 'none' }}>
          <CodeAuditor />
        </div>
        <div className="tab-pane" style={{ display: tool === 'timemachine' ? 'block' : 'none' }}>
          <TimeMachineAttestation />
        </div>
      </main>
      <footer className="footnote">
        Local-first analysis · findings are evidence-backed · zero NAND writes · failed checks are never reported as clean
      </footer>
    </div>
  )
}

