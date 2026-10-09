
import { spawn } from 'node:child_process'
import path from 'node:path'

import type { DocxFacts } from '../types/scan.js'

interface PythonDocxResult {
  ok?: boolean
  supported?: boolean
  error?: string
  fileSize?: number
  entryCount?: number
  totalUncompressedBytes?: number
  documentTextLength?: number
  textPartCount?: number
  hiddenTextCount?: number
  hiddenText?: Array<{
    part?: string
    textPreview?: string
    reasons?: string[]
    contentSignals?: string[]
  }>
  urls?: string[]
  externalRelationships?: Array<{
    sourcePart?: string
    target?: string
    relationshipType?: string
  }>
  embeddedObjects?: Array<{
    name?: string
    size?: number
    type?: string
  }>
  macroParts?: string[]
  suspiciousIndicators?: string[]
  packageWarnings?: string[]
  partCounts?: Record<string, number>
  hasComments?: boolean
  hasTrackedChanges?: boolean
  hasExternalTemplate?: boolean
}

const MAX_STDOUT = 2_000_000
const MAX_STDERR = 200_000
const TIMEOUT_MS = 30_000

function failedFacts(error: string): DocxFacts {
  return {
    supported: false,
    error,
    fileSize: 0,
    entryCount: 0,
    uncompressedSize: 0,
    textLength: 0,
    hiddenTextCount: 0,
    hiddenTextFindings: [],
    urls: [],
    externalRelationships: [],
    embeddedObjects: [],
    macroParts: [],
    suspiciousIndicators: [],
    packageWarnings: ['docx-analysis-failed'],
    partCounts: {},
    hasComments: false,
    hasTrackedChanges: false,
    hasExternalTemplate: false,
  }
}

function normalizePythonResult(
  parsed: PythonDocxResult,
): DocxFacts {
  return {
    supported: true,
    fileSize: parsed.fileSize ?? 0,
    entryCount: parsed.entryCount ?? 0,

    // Adapt the Python analyzer's field names to scan.ts.
    uncompressedSize: parsed.totalUncompressedBytes ?? 0,
    textLength: parsed.documentTextLength ?? 0,

    hiddenTextCount: parsed.hiddenTextCount ?? 0,
    hiddenTextFindings: (parsed.hiddenText ?? []).map(
      (item) => ({
        text: item.textPreview ?? '',
        reasons: item.reasons ?? [],
        contentSignals: item.contentSignals ?? [],
        part: item.part,
      }),
    ),

    urls: parsed.urls ?? [],

    externalRelationships: (
      parsed.externalRelationships ?? []
    ).map((item) => ({
      source: item.sourcePart ?? '',
      target: item.target ?? '',
      relationshipType: item.relationshipType,
    })),

    embeddedObjects: (parsed.embeddedObjects ?? []).map(
      (item, index) => {
        const name = item.name ?? `embedded-object-${index + 1}`
        const type = item.type ?? ''

        const executableExtension =
          /\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|hta|com|msi)$/i

        const executableType =
          /x-msdownload|x-dosexec|x-executable|x-sharedlib|x-msdos-program/i

        return {
          name,
          size: item.size,
          isExecutableLike:
            executableExtension.test(name) ||
            executableType.test(type),
        }
      },
    ),

    macroParts: parsed.macroParts ?? [],
    suspiciousIndicators: parsed.suspiciousIndicators ?? [],
    packageWarnings: parsed.packageWarnings ?? [],
    partCounts: parsed.partCounts ?? {},
    hasComments: parsed.hasComments ?? false,
    hasTrackedChanges: parsed.hasTrackedChanges ?? false,
    hasExternalTemplate: parsed.hasExternalTemplate ?? false,
  }
}

export function analyzeDocx(
  filePath: string,
): Promise<DocxFacts> {
  return new Promise((resolve) => {
    const scriptPath = path.resolve(
      process.cwd(),
      'src',
      'scripts',
      'analyze_docx.py',
    )

    const pythonPath =
      process.env.PYTHON_EXECUTABLE ||
      path.resolve(process.cwd(), '.venv', 'bin', 'python')

    const child = spawn(
      pythonPath,
      [scriptPath, filePath],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      },
    )

    let stdout = ''
    let stderr = ''
    let settled = false
    let timeout: NodeJS.Timeout

    const finish = (facts: DocxFacts) => {
      if (settled) return

      settled = true
      clearTimeout(timeout)
      resolve(facts)
    }

    timeout = setTimeout(() => {
      child.kill('SIGKILL')

      finish(
        failedFacts(
          'DOCX analysis timed out after 30 seconds.',
        ),
      )
    }, TIMEOUT_MS)

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8')

      if (stdout.length > MAX_STDOUT) {
        child.kill('SIGKILL')

        finish(
          failedFacts(
            'DOCX analyzer output exceeded the safety limit.',
          ),
        )
      }
    })

    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8')

      if (stderr.length > MAX_STDERR) {
        stderr = stderr.slice(-MAX_STDERR)
      }
    })

    child.on('error', (error) => {
      finish(
        failedFacts(
          `Unable to start DOCX analyzer: ${error.message}`,
        ),
      )
    })

    child.on('close', () => {
      if (settled) return

      try {
        const start = stdout.indexOf('{')
        const end = stdout.lastIndexOf('}')

        if (start < 0 || end <= start) {
          finish(
            failedFacts(
              stderr.trim() ||
                'DOCX analyzer returned no valid JSON.',
            ),
          )
          return
        }

        const parsed = JSON.parse(
          stdout.slice(start, end + 1),
        ) as PythonDocxResult

        if (!parsed.ok) {
          const failed = failedFacts(
            parsed.error ||
              stderr.trim() ||
              'The file is not a valid DOCX package.',
          )

          failed.fileSize = parsed.fileSize ?? 0
          failed.packageWarnings =
            parsed.packageWarnings ?? [
              'invalid-or-unsupported-docx',
            ]

          finish(failed)
          return
        }

        finish(normalizePythonResult(parsed))
      } catch {
        finish(
          failedFacts(
            stderr.trim() ||
              'DOCX analyzer returned unreadable output.',
          ),
        )
      }
    })
  })
}