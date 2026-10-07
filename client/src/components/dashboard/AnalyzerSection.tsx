import './AnalyzerSection.css'

const engines = [
  {
    name: 'Local malware scanner',
    detail: 'Signature scan that runs on this machine.',
  },
  {
    name: 'Microsoft Defender',
    detail: 'Verdicts from Windows antivirus.',
  },
  {
    name: 'VirusTotal',
    detail: 'Reputation lookup across many engines.',
  },
  {
    name: 'Local AI analysis',
    detail: 'Reads extracted text for hidden instructions.',
  },
]

export default function AnalyzerSection() {
  return (
    <section className="panel" aria-labelledby="engines-title">
      <div className="panel-head">
        <div>
          <h2 id="engines-title">Analysis engines</h2>
          <p>None are connected in this build, so no file can be scanned yet.</p>
        </div>
      </div>

      <ul className="engines">
        {engines.map((engine) => (
          <li key={engine.name}>
            <div>
              <strong>{engine.name}</strong>
              <span>{engine.detail}</span>
            </div>
            <span className="engine-status">Not connected</span>
          </li>
        ))}
      </ul>
    </section>
  )
}
