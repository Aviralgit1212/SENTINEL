import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, X } from 'lucide-react'

import type {
  Risk,
  ScanHistoryResponse,
  ScanRecord,
} from '../../types/sentinel'
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

const API_BASE_URL = 'http://localhost:5001'

function mapScanToRecord(scan: ScanHistoryResponse): ScanRecord {
  return {
    id: scan.scanId,
    name: scan.filename,
    scannedAt: scan.createdAt,
    risk: scan.risk.level,
  }
}

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

              <td>
                {formatDate(record.scannedAt, dateFormat)}
              </td>

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

  const [dateFormat] = useState(
    () => readPreferences().dateFormat,
  )

  const [search, setSearch] = useState('')

  const [riskFilter, setRiskFilter] =
    useState<RiskFilter>('all')

  const [scans, setScans] = useState<ScanRecord[]>([])

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState<string | null>(null)

  // --------------------------------
  // Load real scan history
  // --------------------------------

  useEffect(() => {
    let cancelled = false

    async function loadHistory() {
      setLoading(true)
      setError(null)

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/scans`,
        )

        const data =
          (await response.json()) as ScanHistoryResponse[]

        if (!response.ok) {
          throw new Error(
            'Failed to load scan history.',
          )
        }

        if (!Array.isArray(data)) {
          throw new Error(
            'Invalid scan history response.',
          )
        }

        if (!cancelled) {
          setScans(
            data.map(mapScanToRecord),
          )
        }
      } catch (historyError) {
        if (!cancelled) {
          setError(
            historyError instanceof Error
              ? historyError.message
              : 'Unable to load scan history.',
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    void loadHistory()

    return () => {
      cancelled = true
    }
  }, [])

  // --------------------------------
  // Dialog
  // --------------------------------

  useEffect(() => {
    const dialog = dialogRef.current

    if (!dialog) return

    if (historyOpen && !dialog.open) {
      dialog.showModal()
    }

    if (!historyOpen && dialog.open) {
      dialog.close()
    }
  }, [historyOpen])

  // --------------------------------
  // Filtering
  // --------------------------------

  const filtered = useMemo(() => {
    const query = search
      .trim()
      .toLowerCase()

    return scans.filter(
      (scan) =>
        (
          query === '' ||
          scan.name
            .toLowerCase()
            .includes(query)
        ) &&
        (
          riskFilter === 'all' ||
          scan.risk === riskFilter
        ),
    )
  }, [scans, search, riskFilter])

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
      <section
        className="panel"
        aria-labelledby="recent-title"
      >
        <div className="panel-head">
          <div>
            <h2 id="recent-title">
              Recent scans
            </h2>

            <p>
              Your latest file analysis results.
            </p>
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

        {loading ? (
          <div className="history-empty">
            <p>Loading scan history...</p>
          </div>
        ) : error ? (
          <div className="history-empty">
            <p>{error}</p>
          </div>
        ) : scans.length === 0 ? (
          <div className="history-empty">
            <p>
              No scans yet. Upload a file to
              start your first analysis.
            </p>
          </div>
        ) : (
          <ScanTable
            records={scans.slice(0, 5)}
            dateFormat={dateFormat}
          />
        )}
      </section>

      <dialog
        ref={dialogRef}
        className="history"
        aria-labelledby="history-title"
        onClose={handleClose}
        onClick={(event) => {
          if (
            event.target ===
            event.currentTarget
          ) {
            onCloseHistory()
          }
        }}
      >
        <div className="history-inner">
          <header className="history-head">
            <h2 id="history-title">
              Scan history
            </h2>

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
                onChange={(event) =>
                  setSearch(
                    event.target.value,
                  )
                }
                aria-label="Search scan history by file name"
              />
            </label>

            <select
              value={riskFilter}
              onChange={(event) =>
                setRiskFilter(
                  event.target
                    .value as RiskFilter,
                )
              }
              aria-label="Filter by risk"
            >
              <option value="all">
                All risks
              </option>

              <option value="low">
                Low
              </option>

              <option value="medium">
                Medium
              </option>

              <option value="high">
                High
              </option>

              <option value="critical">
                Critical
              </option>
            </select>
          </div>

          {loading ? (
            <div className="history-empty">
              <p>
                Loading scan history...
              </p>
            </div>
          ) : error ? (
            <div className="history-empty">
              <p>{error}</p>
            </div>
          ) : filtered.length > 0 ? (
            <ScanTable
              records={filtered}
              dateFormat={dateFormat}
            />
          ) : (
            <div className="history-empty">
              <p>
                {scans.length === 0
                  ? 'No scans have been recorded yet.'
                  : 'No scans match your search.'}
              </p>

              {scans.length > 0 && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={clearFilters}
                >
                  Clear filters
                </button>
              )}
            </div>
          )}

          <p className="history-foot">
            {filtered.length} of{' '}
            {scans.length} records.
          </p>
        </div>
      </dialog>
    </>
  )
}