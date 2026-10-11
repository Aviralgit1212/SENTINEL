import './AnalyzerSection.css'

const engines = [
  {
    name: 'Local malware scanner',
    detail: 'ClamAV signature-based malware scanning.',
    status: 'Configured',
  },
  {
    name: 'Static file analysis',
    detail:
      'Python analyzers inspect PDF, DOCX, EXE, and JSON files.',
    status: 'Configured',
  },
  {
    name: 'Microsoft Defender',
    detail: 'Windows antivirus integration.',
    status: 'Not connected',
  },
  {
    name: 'VirusTotal',
    detail: 'Multi-engine reputation and detection lookup.',
    status: 'Not connected',
  },
  {
    name: 'AI content analysis',
    detail:
      'Static inspection for hidden instructions and suspicious content.',
    status: 'Configured',
  },
]

export default function AnalyzerSection() {
  return (
    <section className="panel" aria-labelledby="engines-title">
      <div className="panel-head">
        <div>
          <h2 id="engines-title">Analysis engines</h2>
          <p>
            Overview of the analysis capabilities configured in Sentinel.
          </p>
        </div>
      </div>

      <ul className="engines">
        {engines.map((engine) => {
          const connected = engine.status === 'Configured'

          return (
            <li key={engine.name}>
              <div>
                <strong>{engine.name}</strong>
                <span>{engine.detail}</span>
              </div>

              <span
                className={`engine-status ${
                  connected ? 'engine-status--configured' : ''
                }`}
              >
                {engine.status}
              </span>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
