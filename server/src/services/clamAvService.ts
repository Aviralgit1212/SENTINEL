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
        if (!error) {
          resolve({
            available: true,
            status: 'clean',
            details: stdout.trim() || 'No threats detected.',
          })

          return
        }

        if (error.code === 1) {
          resolve({
            available: true,
            status: 'threat',
            details:
              stdout.trim() ||
              'ClamAV detected a threat.',
          })

          return
        }

        if (
          typeof error.message === 'string' &&
          error.message.includes('ENOENT')
        ) {
          resolve({
            available: false,
            status: 'unavailable',
            details: 'ClamAV is not installed or not on PATH.',
          })

          return
        }

        resolve({
          available: false,
          status: 'error',
          details:
            stderr.trim() ||
            error.message ||
            'ClamAV scan failed.',
        })
      },
    )
  })
}