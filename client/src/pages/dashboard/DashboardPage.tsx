import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

import AnalyzerSection from '../../components/dashboard/AnalyzerSection'
import RecentScans from '../../components/dashboard/RecentScans'
import UploadPanel from '../../components/dashboard/UploadPanel'
import './DashboardPage.css'

export default function DashboardPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const [historyOpen, setHistoryOpen] = useState(false)

  // The header's "History" link asks for the dialog through router state.
  useEffect(() => {
    if (location.state?.openHistory) {
      setHistoryOpen(true)
      navigate('/dashboard', { replace: true, state: null })
    }
  }, [location.state, navigate])

  return (
    <main className="page dashboard">
      <header className="dashboard-head">
        <h1>Inspect a file</h1>
        <p>
          Check a PDF, DOCX or image before you open it or give it to an AI
          tool.
        </p>
      </header>

      <UploadPanel
        onSelected={(file) =>
          navigate('/scan', {
            state: {
              file,
            },
          })
        }
      />

      <RecentScans
        historyOpen={historyOpen}
        onOpenHistory={() => setHistoryOpen(true)}
        onCloseHistory={() => setHistoryOpen(false)}
      />

      <AnalyzerSection />
    </main>
  )
}
