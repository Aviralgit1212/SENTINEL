import { execFile } from 'node:child_process'

interface ClamResult {
  available: boolean
  status:
    | 'clean'
    | 'threat'
    | 'unavailable'
    | 'error'
  details: string
}

export function scanWithClamAV(
  filePath: string,
): Promise<ClamResult> {
  return new Promise((resolve) => {
    execFile(
      'clamscan',
      ['--no-summary', filePath],
      {
        timeout: 120_000,
      },
      (error, stdout, stderr) => {

        // -----------------------------------------------------
        // Clean
        // -----------------------------------------------------

        if (!error) {
          resolve({
            available: true,
            status: 'clean',
            details: 'ClamAV found no threats.',
          })

          return
        }

        // -----------------------------------------------------
        // Threat detected
        // -----------------------------------------------------

        if (error.code === 1) {
          resolve({
            available: true,
            status: 'threat',
            details:
              sanitizeClamOutput(stdout) ||
              'ClamAV detected a threat.',
          })

          return
        }

        // -----------------------------------------------------
        // ClamAV unavailable
        // -----------------------------------------------------

        if (
          typeof error.message === 'string' &&
          error.message.includes('ENOENT')
        ) {
          resolve({
            available: false,
            status: 'unavailable',
            details:
              'ClamAV is not installed or not available on PATH.',
          })

          return
        }

        // -----------------------------------------------------
        // Other error
        // -----------------------------------------------------

        resolve({
          available: false,
          status: 'error',
          details:
            sanitizeClamOutput(stderr) ||
            sanitizeClamOutput(error.message) ||
            'ClamAV scan failed.',
        })
      },
    )
  })
}

// ---------------------------------------------------------
// Remove local filesystem paths from ClamAV output.
// ---------------------------------------------------------

function sanitizeClamOutput(
  output: string,
): string {

  const value =
    output.trim()

  if (!value) {
    return ''
  }

  // ClamAV normally returns:
  //
  // /some/local/path/file.pdf: OK
  //
  // or:
  //
  // /some/local/path/file.pdf: Malware.Name FOUND
  //
  // Keep only the security result.

  const separatorIndex =
    value.lastIndexOf(': ')

  if (
    separatorIndex !== -1 &&
    separatorIndex < value.length - 2
  ) {
    return value.slice(
      separatorIndex + 2,
    ).trim()
  }

  return value
}