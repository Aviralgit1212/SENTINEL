import { useEffect, useState } from 'react'
import { useAuth } from '@clerk/clerk-react'
import {
  useLocation,
  useNavigate,
} from 'react-router-dom'

import './ScanPage.css'

interface ScanResult {
  scanId: string
  filename: string
  size: number

  status:
    | 'analyzing'
    | 'completed'
    | 'failed'

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

  risk: {
    score: number
    level:
      | 'low'
      | 'medium'
      | 'high'
      | 'critical'
  }

  recommendation:
    | 'allow'
    | 'review'
    | 'block'
}

const API_BASE_URL =
  'http://localhost:5001'

const POLL_INTERVAL_MS = 1000

const MAX_POLL_ATTEMPTS = 180

/*
 * React StrictMode can mount, unmount and mount
 * the component again during development.
 *
 * This map makes both mounts reuse the same
 * in-flight request.
 *
 * Backend idempotency remains the real protection.
 */
const inFlightScans = new Map<
  string,
  Promise<ScanResult>
>()

function isScanResult(
  value: unknown,
): value is ScanResult {
  return (
    typeof value === 'object' &&
    value !== null &&
    'scanId' in value &&
    'status' in value &&
    (value as { status?: unknown }).status ===
      'completed'
  )
}

/*
 * Safely parse server responses.

 * This also prevents errors such as:
 *
 * Unexpected token '<'
 *
 * when the server accidentally returns HTML.
 */
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

/*
 * If another request already created the scan,
 * the backend returns 202 + scanId.
 *
 * We wait for that existing scan instead of
 * starting another analysis.
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
    await new Promise<void>((resolve) => {
      window.setTimeout(
        resolve,
        POLL_INTERVAL_MS,
      )
    })

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
      const message =
        typeof data === 'object' &&
        data !== null &&
        'error' in data &&
        typeof (
          data as {
            error?: unknown
          }
        ).error === 'string'
          ? (
              data as {
                error: string
              }
            ).error
          : 'Unable to retrieve the scan result.'

      throw new Error(message)
    }

    if (isScanResult(data)) {
      return data
    }

    if (
      typeof data === 'object' &&
      data !== null &&
      'status' in data
    ) {
      const status = (
        data as {
          status?: unknown
          error?: unknown
        }
      ).status

      if (status === 'failed') {
        const errorMessage = (
          data as unknown as {
            error?: unknown
          }
        ).error

        throw new Error(
          typeof errorMessage === 'string'
            ? errorMessage
            : 'File analysis failed.',
        )
      }

      if (status === 'analyzing') {
        continue
      }
    }

    throw new Error(
      'The server returned an invalid scan status.',
    )
  }

  throw new Error(
    'The scan is taking longer than expected. Please check the scan history.',
  )
}

/*
 * Performs the actual POST request.
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

  formData.append(
    'file',
    file,
  )

  const response = await fetch(
    `${API_BASE_URL}/api/scans`,
    {
      method: 'POST',

      headers: {
        Authorization: `Bearer ${token}`,

        /*
         * This identifies the logical scan.
         */
        'X-Scan-Request-Id':
          scanRequestId,
      },

      body: formData,
    },
  )

  const data = await readJson(response)

  /*
   * Another request already created the scan.
   *
   * Don't analyze again. Wait for the existing
   * scan to finish.
   */
  if (response.status === 202) {
    if (
      typeof data === 'object' &&
      data !== null &&
      'scanId' in data &&
      typeof (
        data as {
          scanId?: unknown
        }
      ).scanId === 'string'
    ) {
      return waitForScanResult(
        (
          data as {
            scanId: string
          }
        ).scanId,
        token,
      )
    }

    throw new Error(
      'The server did not return a scan ID.',
    )
  }

  if (!response.ok) {
    const message =
      typeof data === 'object' &&
      data !== null &&
      'error' in data &&
      typeof (
        data as {
          error?: unknown
        }
      ).error === 'string'
        ? (
            data as {
              error: string
            }
          ).error
        : 'Scan failed.'

    throw new Error(message)
  }

  if (!isScanResult(data)) {
    throw new Error(
      'The server returned an invalid scan result.',
    )
  }

  return data
}

/*
 * Reuse an existing request for the same
 * scanRequestId.
 *
 * This specifically protects the frontend
 * from React StrictMode duplicate effects.
 */
function requestScan(
  file: File,
  scanRequestId: string,
  getToken: () => Promise<string | null>,
): Promise<ScanResult> {
  const existing =
    inFlightScans.get(scanRequestId)

  if (existing) {
    return existing
  }

  const promise = executeScan(
    file,
    scanRequestId,
    getToken,
  )

  inFlightScans.set(
    scanRequestId,
    promise,
  )

  void promise.then(
    () => {
      if (
        inFlightScans.get(scanRequestId) ===
        promise
      ) {
        inFlightScans.delete(
          scanRequestId,
        )
      }
    },

    () => {
      if (
        inFlightScans.get(scanRequestId) ===
        promise
      ) {
        inFlightScans.delete(
          scanRequestId,
        )
      }
    },
  )

  return promise
}

export default function ScanPage() {
  const location = useLocation()
  const navigate = useNavigate()

  const { getToken } = useAuth()

  const file =
    location.state?.file instanceof File
      ? location.state.file
      : null

  const scanRequestId =
    typeof location.state?.scanRequestId ===
    'string'
      ? location.state.scanRequestId
      : null

  const [result, setResult] =
    useState<ScanResult | null>(null)

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState<string | null>(null)

  useEffect(() => {
    if (!file || !scanRequestId) {
      return
    }

    let cancelled = false

    async function runScan() {
      setLoading(true)
      setError(null)

      try {
        const scanResult =
          await requestScan(
            file,
            scanRequestId,
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
    file,
    scanRequestId,
    getToken,
  ])

  // --------------------------------
  // No file
  // --------------------------------

  if (!file || !scanRequestId) {
    return (
      <main className="page scan-page">
        <h1>No file selected</h1>

        <p>
          Return to the dashboard and choose
          a file to scan.
        </p>

        <button
          type="button"
          className="btn btn-primary"
          onClick={() =>
            navigate('/dashboard')
          }
        >
          Back to dashboard
        </button>
      </main>
    )
  }

  // --------------------------------
  // Loading
  // --------------------------------

  if (loading) {
    return (
      <main className="page scan-page">
        <h1>Analyzing file</h1>

        <p>
          SENTINEL is inspecting{' '}
          <strong>{file.name}</strong>.
        </p>

        <p>
          Checking file type, SHA-256
          fingerprint, antivirus signals, and
          deep file content...
        </p>
      </main>
    )
  }

  // --------------------------------
  // Error
  // --------------------------------

  if (error) {
    return (
      <main className="page scan-page">
        <h1>Scan failed</h1>

        <p>{error}</p>

        <button
          type="button"
          className="btn btn-primary"
          onClick={() =>
            navigate('/dashboard')
          }
        >
          Back to dashboard
        </button>
      </main>
    )
  }

  if (!result) {
    return null
  }

  // --------------------------------
  // Result
  // --------------------------------

  return (
    <main className="page scan-page">
      <h1>Scan complete</h1>

      <p>
        <strong>
          {result.filename}
        </strong>
      </p>

      <section>
        <h2>Risk</h2>

        <p>
          Risk score:{' '}
          <strong>
            {result.risk.score}/100
          </strong>
        </p>

        <p>
          Risk level:{' '}
          <strong>
            {result.risk.level.toUpperCase()}
          </strong>
        </p>

        <p>
          Recommendation:{' '}
          <strong>
            {result.recommendation.toUpperCase()}
          </strong>
        </p>
      </section>

      <section>
        <h2>File verification</h2>

        <p>
          Detected type:{' '}
          {result.fileType.detectedType ??
            'Unknown'}
        </p>

        <p>
          MIME:{' '}
          {result.fileType.detectedMime ??
            'Unknown'}
        </p>

        <p>
          Extension mismatch:{' '}
          {result.fileType.extensionMismatch
            ? 'Yes'
            : 'No'}
        </p>
      </section>

      <section>
        <h2>SHA-256</h2>

        <code>
          {result.hash.value}
        </code>
      </section>

      <section>
        <h2>Antivirus</h2>

        <p>
          {result.antivirus.available
            ? result.antivirus.status
            : 'Unavailable'}
        </p>

        <p>
          {result.antivirus.details}
        </p>
      </section>

      <section>
        <h2>Evidence</h2>

        {result.evidence.length === 0 ? (
          <p>
            No security findings were
            generated by the current
            analyzers.
          </p>
        ) : (
          <ul>
            {result.evidence.map(
              (item) => (
                <li key={item.id}>
                  <strong>
                    {item.title}
                  </strong>{' '}
                  — {item.description}
                </li>
              ),
            )}
          </ul>
        )}
      </section>

      <button
        type="button"
        className="btn btn-primary"
        onClick={() =>
          navigate('/dashboard')
        }
      >
        Back to dashboard
      </button>
    </main>
  )
}