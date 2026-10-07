import { useLocation, useNavigate } from 'react-router-dom'

import './ScanPage.css'

export default function ScanPage() {
  const location = useLocation()
  const navigate = useNavigate()

  const fileName =
    typeof location.state?.fileName === 'string' ? location.state.fileName : null

  return (
    <main className="page scan-page">
      <h1>Inspection isn’t connected yet</h1>

      <p>
        {fileName ? (
          <>
            Sentinel received <code>{fileName}</code> but did not upload or
            analyse it.
          </>
        ) : (
          'No file was selected.'
        )}{' '}
        This screen can show a verdict once the inspection API is connected.
      </p>

      <button
        type="button"
        className="btn btn-primary"
        onClick={() => navigate('/dashboard')}
      >
        Back to dashboard
      </button>
    </main>
  )
}
