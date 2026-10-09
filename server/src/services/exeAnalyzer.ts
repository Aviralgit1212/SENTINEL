
import { spawn } from 'node:child_process'
import path from 'node:path'
import type { ExeFacts } from '../types/scan.js'

interface PythonExeResult {
    ok: boolean
    error?: string
    fileSize?: number
    sha256?: string
    architecture?: 'x86' | 'x64' | 'arm64' | null
    machine?: string | null
    subsystem?: number | null
    entryPointRva?: number | null
    sectionCount?: number
    sections?: ExeFacts['sections']
    imports?: ExeFacts['imports']
    suspiciousImports?: ExeFacts['suspiciousImports']
    strings?: string[]
    urls?: string[]
    ipAddresses?: string[]
    suspiciousIndicators?: string[]
    hasCertificateTable?: boolean
    overlaySize?: number
    highEntropySections?: string[]
    structuralWarnings?: string[]
}

export function analyzeExe(filePath: string): Promise<ExeFacts> {
    return new Promise((resolve) => {
        const scriptPath = path.resolve(
            process.cwd(), 'src', 'scripts', 'analyze_exe.py',
        )
        const configuredPython = process.env.PYTHON_EXECUTABLE
        const venvPython = path.resolve(process.cwd(), '.venv', 'bin', 'python')
        const pythonPath = configuredPython || venvPython

        const child = spawn(pythonPath, [scriptPath, filePath], {
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
        })

        let stdout = ''
        let stderr = ''
        let settled = false
        let timeout: NodeJS.Timeout

        const finish = (facts: ExeFacts) => {
            if (settled) return
            settled = true
            if (timeout) clearTimeout(timeout)
            resolve(facts)
        }

        timeout = setTimeout(() => {
            child.kill('SIGKILL')
            finish(failedFacts('Static EXE analysis timed out after 30 seconds.'))
        }, 30_000)

        child.stdout.on('data', (chunk) => {
            stdout += chunk.toString()
            if (stdout.length > 2_000_000) {
                child.kill('SIGKILL')
                finish(failedFacts('EXE analyzer output exceeded the safety limit.'))
            }
        })

        child.stderr.on('data', (chunk) => {
            stderr += chunk.toString()
            if (stderr.length > 200_000) stderr = stderr.slice(-200_000)
        })

        child.on('error', (error) => finish(failedFacts(error.message)))

        child.on('close', (code) => {
            try {
                const start = stdout.indexOf('{')
                const end = stdout.lastIndexOf('}')

                if (code !== 0 || start < 0 || end <= start) {
                    finish(failedFacts(
                        stderr.trim() || 'The EXE analyzer did not return valid JSON.',
                    ))
                    return
                }

                const parsed = JSON.parse(
                    stdout.slice(start, end + 1),
                ) as PythonExeResult

                if (!parsed.ok) {
                    finish({
                        ...failedFacts(
                            parsed.error || 'The file is not a valid PE executable.',
                        ),
                        fileSize: parsed.fileSize ?? 0,
                        sha256: parsed.sha256 ?? '',
                    })
                    return
                }

                finish({
                    supported: true,
                    fileSize: parsed.fileSize ?? 0,
                    sha256: parsed.sha256 ?? '',
                    architecture: parsed.architecture ?? null,
                    machine: parsed.machine ?? null,
                    subsystem: parsed.subsystem ?? null,
                    entryPointRva: parsed.entryPointRva ?? null,
                    sectionCount: parsed.sectionCount ?? 0,
                    sections: parsed.sections ?? [],
                    imports: parsed.imports ?? [],
                    suspiciousImports: parsed.suspiciousImports ?? [],
                    strings: parsed.strings ?? [],
                    urls: parsed.urls ?? [],
                    ipAddresses: parsed.ipAddresses ?? [],
                    suspiciousIndicators: parsed.suspiciousIndicators ?? [],
                    hasCertificateTable: parsed.hasCertificateTable ?? false,
                    overlaySize: parsed.overlaySize ?? 0,
                    highEntropySections: parsed.highEntropySections ?? [],
                    structuralWarnings: parsed.structuralWarnings ?? [],
                })
            } catch {
                finish(failedFacts(
                    stderr.trim() || 'The EXE analyzer returned unreadable output.',
                ))
            }
        })
    })
}

function failedFacts(error: string): ExeFacts {
    return {
        supported: false,
        error,
        fileSize: 0,
        sha256: '',
        architecture: null,
        machine: null,
        subsystem: null,
        entryPointRva: null,
        sectionCount: 0,
        sections: [],
        imports: [],
        suspiciousImports: [],
        strings: [],
        urls: [],
        ipAddresses: [],
        suspiciousIndicators: [],
        hasCertificateTable: false,
        overlaySize: 0,
        highEntropySections: [],
    }
}