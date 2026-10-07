import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, X } from 'lucide-react'

import { sampleScans } from '../../data/sampleScans'
import type { Risk, ScanRecord } from '../../types/sentinel'
import { formatDate } from '../../utils/formatDate'
import { readPreferences } from '../../utils/preferences'
import type { DateFormat } from '../../utils/preferences'
import { RiskBadge } from '../ui/RiskBadge'
import './RecentScans.css'

interface Props {
  onOpenHistory: () => void
  historyOpen: boolean
  onCloseHistory: () => void
}

type RiskFilter = Risk | 'all'

function ScanTable({
  records,
  dateFormat,
}: {
  records: ScanRecord[]
  dateFormat: DateFormat
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th scope="col">File</th>
            <th scope="col">Scanned</th>
            <th scope="col">Risk</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <tr key={record.id}>
              <td className="file">{record.name}</td>
              <td>{formatDate(record.scannedAt, dateFormat)}</td>
              <td>
                <RiskBadge risk={record.risk} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function RecentScans({
  onOpenHistory,
  historyOpen,
  onCloseHistory,
}: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const [dateFormat] = useState(() => readPreferences().dateFormat)
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')

  // <dialog> handles focus trapping and Escape for us.
  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return

    if (historyOpen && !dialog.open) dialog.showModal()
    if (!historyOpen && dialog.open) dialog.close()
  }, [historyOpen])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()

    return sampleScans.filter(
      (scan) =>
        (query === '' || scan.name.toLowerCase().includes(query)) &&
        (riskFilter === 'all' || scan.risk === riskFilter),
    )
  }, [search, riskFilter])

  function clearFilters() {
    setSearch('')
    setRiskFilter('all')
  }

  function handleClose() {
    clearFilters()
    onCloseHistory()
  }

  return (
    <>
      <section className="panel" aria-labelledby="recent-title">
        <div className="panel-head">
          <div>
            <h2 id="recent-title">Recent scans</h2>
            <p>Sample data. Real results will appear here once scanning is connected.</p>
          </div>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={onOpenHistory}
            aria-haspopup="dialog"
          >
            View all
          </button>
        </div>

        <ScanTable records={sampleScans} dateFormat={dateFormat} />
      </section>

      <dialog
        ref={dialogRef}
        className="history"
        aria-labelledby="history-title"
        onClose={handleClose}
        onClick={(event) => {
          // A click on the backdrop targets the dialog element itself.
          if (event.target === event.currentTarget) onCloseHistory()
        }}
      >
        <div className="history-inner">
          <header className="history-head">
            <h2 id="history-title">Scan history</h2>

            <button
              type="button"
              className="btn btn-ghost history-close"
              onClick={onCloseHistory}
              aria-label="Close scan history"
            >
              <X aria-hidden="true" />
            </button>
          </header>

          <div className="history-toolbar">
            <label className="history-search">
              <Search aria-hidden="true" />
              <input
                type="search"
                placeholder="Search by file name"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                aria-label="Search scan history by file name"
              />
            </label>

            <select
              value={riskFilter}
              onChange={(event) => setRiskFilter(event.target.value as RiskFilter)}
              aria-label="Filter by risk"
            >
              <option value="all">All risks</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>

          {filtered.length > 0 ? (
            <ScanTable records={filtered} dateFormat={dateFormat} />
          ) : (
            <div className="history-empty">
              <p>No scans match your search.</p>
              <button type="button" className="btn btn-secondary" onClick={clearFilters}>
                Clear filters
              </button>
            </div>
          )}

          <p className="history-foot">
            {filtered.length} of {sampleScans.length} records. Sample data.
          </p>
        </div>
      </dialog>
    </>
  )
}
