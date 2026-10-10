
import { useEffect, useState } from 'react'
import { useAuth } from '@clerk/clerk-react'
import {
  useLocation,
  useNavigate,
  useParams,
} from 'react-router-dom'
import {
  ShieldCheck,
  FileCheck2,
  Fingerprint,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ArrowLeft,
  FileText,
  ScanSearch,
} from 'lucide-react'

import './ScanPage.css'

interface ScanResult {
  scanId: string
  filename: string
  size: number
  status: 'analyzing' | 'completed' | 'failed'

  fileType: {
    detectedExtension: string | null
    detectedMime: string | null
    detectedType: string | null
    extensionMismatch: boolean
  }

  hash: {
    algorithm: string
    value: string
  }

  antivirus: {
    engine: string
    available: boolean
    status: string
    details: string
  }

  evidence: {
    id: string
    category: string
    title: string
    description: string
    severity: string
    source: string
    score: number
  }[]

  risk?: {
    score?: number
    level?: 'low' | 'medium' | 'high' | 'critical'
  }

  recommendation?: 'allow' | 'review' | 'block'
}

const API_BASE_URL = 'http://localhost:5001'

const POLL_INTERVAL_MS = 1000
const MAX_POLL_ATTEMPTS = 180

/*
 * Reuse in-flight scan requests during React StrictMode
 * development remounts.
 */
const inFlightScans = new Map<
  string,
  Promise<ScanResult>
>()

function isScanResult(
  value: unknown,
): value is ScanResult {
  if (
    typeof value !== 'object' ||
    value === null
  ) {
    return false
  }

  const result = value as Partial<ScanResult>

  return (
    typeof result.scanId === 'string' &&
    typeof result.filename === 'string' &&
    result.status === 'completed' &&
    typeof result.fileType === 'object' &&
    result.fileType !== null &&
    typeof result.hash === 'object' &&
    result.hash !== null &&
    typeof result.antivirus === 'object' &&
    result.antivirus !== null &&
    Array.isArray(result.evidence)
  )
}

async function readJson(
  response: Response,
): Promise<unknown> {
  const text = await response.text()

  if (!text) {
    return null
  }

  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new Error(
      `Server returned an invalid response (${response.status}).`,
    )
  }
}

function getErrorMessage(
  data: unknown,
  fallback: string,
): string {
  if (
    typeof data === 'object' &&
    data !== null &&
    'error' in data &&
    typeof data.error === 'string'
  ) {
    return data.error
  }

  return fallback
}

/*
 * Retrieves an existing scan from MongoDB through the
 * authenticated GET /api/scans/:scanId endpoint.
 *
 * If the scan is still analyzing, keep polling.
 */
async function waitForScanResult(
  scanId: string,
  token: string,
): Promise<ScanResult> {
  for (
    let attempt = 0;
    attempt < MAX_POLL_ATTEMPTS;
    attempt += 1
  ) {
    const response = await fetch(
      `${API_BASE_URL}/api/scans/${encodeURIComponent(
        scanId,
      )}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    )

    const data = await readJson(response)

    if (!response.ok) {
      throw new Error(
        getErrorMessage(
          data,
          'Unable to retrieve the scan result.',
        ),
      )
    }

    if (isScanResult(data)) {
      return data
    }

    if (
      typeof data === 'object' &&
      data !== null &&
      'status' in data
    ) {
      const status = data.status

      if (status === 'failed') {
        throw new Error(
          getErrorMessage(data, 'File analysis failed.'),
        )
      }

      if (status === 'analyzing') {
        await new Promise<void>((resolve) => {
          window.setTimeout(
            resolve,
            POLL_INTERVAL_MS,
          )
        })

        continue
      }
    }

    throw new Error(
      'The server returned an unexpected scan result. Check the GET /api/scans/:scanId response format.',
    )
  }

  throw new Error(
    'The scan is taking longer than expected. Please try again from scan history.',
  )
}

/*
 * Performs the actual POST request for a new scan.
 */
async function executeScan(
  file: File,
  scanRequestId: string,
  getToken: () => Promise<string | null>,
): Promise<ScanResult> {
  const token = await getToken()

  if (!token) {
    throw new Error(
      'Your session has expired. Please sign in again.',
    )
  }

  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(
    `${API_BASE_URL}/api/scans`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Scan-Request-Id': scanRequestId,
      },
      body: formData,
    },
  )

  const data = await readJson(response)

  /*
   * If the backend already created this scan,
   * retrieve its result instead of submitting again.
   */
  if (response.status === 202) {
    if (
      typeof data === 'object' &&
      data !== null &&
      'scanId' in data &&
      typeof data.scanId === 'string'
    ) {
      return waitForScanResult(
        data.scanId,
        token,
      )
    }

    throw new Error(
      'The server did not return a scan ID.',
    )
  }

  if (!response.ok) {
    throw new Error(
      getErrorMessage(data, 'Scan failed.'),
    )
  }

  if (!isScanResult(data)) {
    throw new Error(
      'The server returned an invalid scan result.',
    )
  }

  return data
}

/*
 * Reuse a request with the same scanRequestId.
 */
function requestScan(
  file: File,
  scanRequestId: string,
  getToken: () => Promise<string | null>,
): Promise<ScanResult> {
  const existing = inFlightScans.get(scanRequestId)

  if (existing) {
    return existing
  }

  const promise = executeScan(
    file,
    scanRequestId,
    getToken,
  )

  inFlightScans.set(scanRequestId, promise)

  void promise.then(
    () => {
      if (
        inFlightScans.get(scanRequestId) === promise
      ) {
        inFlightScans.delete(scanRequestId)
      }
    },
    () => {
      if (
        inFlightScans.get(scanRequestId) === promise
      ) {
        inFlightScans.delete(scanRequestId)
      }
    },
  )

  return promise
}

export default function ScanPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const { scanId: historyScanId } = useParams()

  const { getToken } = useAuth()

  const file =
    location.state?.file instanceof File
      ? (location.state.file as File)
      : null

  const scanRequestId =
    typeof location.state?.scanRequestId === 'string'
      ? (location.state.scanRequestId as string)
      : null

  const [result, setResult] =
    useState<ScanResult | null>(null)

  const [loading, setLoading] = useState(false)

  const [error, setError] =
    useState<string | null>(null)

  /*
   * Load a saved scan when the URL is /scan/:scanId.
   *
   * This does not need the original File object.
   */
  useEffect(() => {
    if (!historyScanId) {
      return
    }

    let cancelled = false

    async function loadSavedResult() {
      setLoading(true)
      setError(null)
      setResult(null)

      try {
        const token = await getToken()

        if (!token) {
          throw new Error(
            'Your session has expired. Please sign in again.',
          )
        }

        const savedResult = await waitForScanResult(
          historyScanId!,
          token,
        )

        if (!cancelled) {
          setResult(savedResult)
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : 'Unable to load the saved scan result.',
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    void loadSavedResult()

    return () => {
      cancelled = true
    }
  }, [historyScanId, getToken])

  /*
   * Run a new scan only when a file was passed
   * through router state.
   */
  useEffect(() => {
    if (historyScanId || !file || !scanRequestId) {
      return
    }

    let cancelled = false

    async function runScan() {
      setLoading(true)
      setError(null)
      setResult(null)

      try {
        const scanResult = await requestScan(
          file!,
          scanRequestId!,
          getToken,
        )

        if (!cancelled) {
          setResult(scanResult)
        }
      } catch (scanError) {
        if (!cancelled) {
          setError(
            scanError instanceof Error
              ? scanError.message
              : 'Unable to scan the file.',
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    void runScan()

    return () => {
      cancelled = true
    }
  }, [
    historyScanId,
    file,
    scanRequestId,
    getToken,
  ])

  /*
   * Only show the missing-file state when this is
   * not a saved-history route.
   */
  if (!historyScanId && (!file || !scanRequestId)) {
    return (
      <main className="page scan-page">
        <div className="scan-state-card">
          <FileText size={42} />

          <h1>No file selected</h1>

          <p>
            Return to the dashboard and choose a file
            to scan, or open a result from scan history.
          </p>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => navigate('/dashboard')}
          >
            <ArrowLeft size={17} />
            Back to dashboard
          </button>
        </div>
      </main>
    )
  }

  /*
   * Loading state for new scans and saved results.
   */
  if (loading) {
    return (
      <main className="page scan-page">
        <div className="scan-state-card">
          <div className="scan-loader">
            <ScanSearch size={38} />
          </div>

          <h1>
            {historyScanId
              ? 'Loading saved result'
              : 'Analyzing file'}
          </h1>

          <p>
            SENTINEL is inspecting{' '}
            <strong>
              {file?.name ?? 'your previously scanned file'}
            </strong>.
          </p>

          <div className="scan-progress">
            <span />
          </div>

          <small>
            {historyScanId
              ? 'Retrieving the original analysis from scan history...'
              : 'Checking file type, SHA-256 fingerprint, and antivirus signals...'}
          </small>
        </div>
      </main>
    )
  }

  /*
   * Error state.
   */
  if (error) {
    return (
      <main className="page scan-page">
        <div className="scan-state-card error-state">
          <XCircle size={42} />

          <h1>
            {historyScanId
              ? 'Unable to load result'
              : 'Scan failed'}
          </h1>

          <p>{error}</p>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => navigate('/dashboard')}
          >
            <ArrowLeft size={17} />
            Back to dashboard
          </button>
        </div>
      </main>
    )
  }

  if (!result) {
    return (
      <main className="page scan-page">
        <div className="scan-state-card">
          <ScanSearch size={38} />
          <h1>Preparing result</h1>
          <p>Please wait while the result is loaded.</p>
        </div>
      </main>
    )
  }

  /*
   * Safe display values.
   */
  const riskScore =
    typeof result.risk?.score === 'number'
      ? result.risk.score
      : 0

  const riskLevel =
    result.risk?.level ?? 'unknown'

  const recommendation =
    result.recommendation ?? 'review'

  const riskLabel =
    riskLevel === 'unknown'
      ? 'Unknown'
      : riskLevel.charAt(0).toUpperCase() +
        riskLevel.slice(1)

  const recommendationLabel =
    recommendation.charAt(0).toUpperCase() +
    recommendation.slice(1)

  const riskClass =
    riskLevel === 'low'
      ? 'risk-low'
      : riskLevel === 'medium'
        ? 'risk-medium'
        : riskLevel === 'high'
          ? 'risk-high'
          : riskLevel === 'critical'
            ? 'risk-critical'
            : 'risk-unknown'

  const RecommendationIcon =
    recommendation === 'allow'
      ? CheckCircle2
      : recommendation === 'block'
        ? XCircle
        : AlertTriangle

  return (
    <main className="page scan-page">
      {/* Header */}
      <header className="scan-header">
        <div>
          <div className="scan-header-label">
            <ShieldCheck size={17} />
            SENTINEL SECURITY SCAN
          </div>

          <h1>Security Result</h1>

          <p>
            Analysis completed for{' '}
            <strong>{result.filename}</strong>
          </p>
        </div>

        <div className="scan-status-badge">
          <CheckCircle2 size={16} />
          Scan Complete
        </div>
      </header>

      {/* Main risk card */}
      <section className={`risk-card ${riskClass}`}>
        <div className="risk-card-top">
          <div>
            <span className="section-eyebrow">
              OVERALL SECURITY RISK
            </span>

            <div className="risk-score">
              {riskScore}
              <span>/100</span>
            </div>

            <div className="risk-level">
              <ShieldAlert size={18} />
              {riskLabel} Risk
            </div>
          </div>

          <div className="risk-icon">
            <ShieldCheck size={54} />
          </div>
        </div>

        <div className="risk-bar">
          <span
            style={{
              width: `${Math.min(
                Math.max(riskScore, 0),
                100,
              )}%`,
            }}
          />
        </div>

        <div className="recommendation">
          <div className="recommendation-icon">
            <RecommendationIcon size={21} />
          </div>

          <div>
            <span>RECOMMENDATION</span>
            <strong>{recommendationLabel}</strong>
          </div>
        </div>
      </section>

      {/* File verification + antivirus */}
      <div className="scan-grid">
        {/* File verification */}
        <section className="scan-card">
          <div className="card-heading">
            <div className="card-icon">
              <FileCheck2 size={20} />
            </div>

            <div>
              <span>FILE SECURITY</span>
              <h2>File Verification</h2>
            </div>
          </div>

          <div className="info-list">
            <div className="info-row">
              <span>Detected type</span>
              <strong>
                {result.fileType.detectedType ?? 'Unknown'}
              </strong>
            </div>

            <div className="info-row">
              <span>MIME type</span>
              <strong>
                {result.fileType.detectedMime ?? 'Unknown'}
              </strong>
            </div>

            <div className="info-row">
              <span>Extension</span>
              <strong>
                {result.fileType.detectedExtension ?? 'Unknown'}
              </strong>
            </div>

            <div className="info-row">
              <span>Extension mismatch</span>
              <strong
                className={
                  result.fileType.extensionMismatch
                    ? 'danger-text'
                    : 'success-text'
                }
              >
                {result.fileType.extensionMismatch
                  ? 'Detected'
                  : 'None'}
              </strong>
            </div>
          </div>
        </section>

        {/* Antivirus */}
        <section className="scan-card">
          <div className="card-heading">
            <div className="card-icon">
              <ShieldCheck size={20} />
            </div>

            <div>
              <span>MALWARE CHECK</span>
              <h2>Antivirus</h2>
            </div>
          </div>

          <div className="antivirus-status">
            <div
              className={
                result.antivirus.available
                  ? 'av-icon av-safe'
                  : 'av-icon av-warning'
              }
            >
              {result.antivirus.available ? (
                <CheckCircle2 size={25} />
              ) : (
                <AlertTriangle size={25} />
              )}
            </div>

            <div>
              <strong>
                {result.antivirus.available
                  ? result.antivirus.status
                  : 'Unavailable'}
              </strong>

              <span>{result.antivirus.engine}</span>
            </div>
          </div>

          <p className="card-description">
            {result.antivirus.details}
          </p>
        </section>
      </div>

      {/* Fingerprint */}
      <section className="scan-card fingerprint-card">
        <div className="card-heading">
          <div className="card-icon">
            <Fingerprint size={20} />
          </div>

          <div>
            <span>FILE IDENTITY</span>
            <h2>File Fingerprint</h2>
          </div>
        </div>

        <p className="fingerprint-description">
          Cryptographic fingerprint generated for this
          file using {result.hash.algorithm}.
        </p>

        <div className="hash-box">
          <code>{result.hash.value}</code>
        </div>
      </section>

      {/* Security evidence */}
      <section className="scan-card evidence-card">
        <div className="card-heading">
          <div className="card-icon">
            <ShieldAlert size={20} />
          </div>

          <div>
            <span>ANALYSIS OUTPUT</span>
            <h2>Security Evidence</h2>
          </div>

          <div className="evidence-count">
            {result.evidence.length}
          </div>
        </div>

        {result.evidence.length === 0 ? (
          <div className="no-evidence">
            <CheckCircle2 size={24} />

            <div>
              <strong>No security findings</strong>

              <p>
                No suspicious findings were generated
                by the current analyzers.
              </p>
            </div>
          </div>
        ) : (
          <div className="evidence-list">
            {result.evidence.map((item) => (
              <article
                className="evidence-item"
                key={item.id}
              >
                <div className="evidence-marker">
                  <ShieldAlert size={18} />
                </div>

                <div className="evidence-content">
                  <div className="evidence-title-row">
                    <strong>{item.title}</strong>

                    <span className="severity-badge">
                      {item.severity}
                    </span>
                  </div>

                  <p>{item.description}</p>

                  <div className="evidence-meta">
                    <span>
                      Category: {item.category}
                    </span>

                    <span>
                      Source: {item.source}
                    </span>

                    <span>
                      Score: {item.score}
                    </span>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {/* Footer */}
      <div className="scan-footer">
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => navigate('/dashboard')}
        >
          <ArrowLeft size={17} />
          Back to dashboard
        </button>

        <span>Scan ID: {result.scanId}</span>
      </div>
    </main>
  )
}