import { spawn, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream, existsSync } from 'node:fs'
import type { AnalyzerState } from '../types.js'

const SCAN_TIMEOUT_MS = 120_000
const MAX_OUTPUT_BYTES = 64 * 1024
const MAX_DIAGNOSTIC_BYTES = 16 * 1024

function resolvePrlimit(): string | null {
  if (process.platform !== 'linux') return null
  for (const candidate of ['/usr/bin/prlimit', '/bin/prlimit']) {
    try { if (existsSync(candidate)) return candidate } catch { /* continue */ }
  }
  return null
}

function resolveClamScan(): string | null {
  for (const candidate of ['/usr/bin/clamscan', '/usr/local/bin/clamscan', '/bin/clamscan']) {
    try { if (existsSync(candidate)) return candidate } catch { /* continue */ }
  }
  if (process.platform !== 'linux' && process.env.SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS === '1') return 'clamscan'
  return null
}

export interface ClamAVCapability {
  engine: 'clamscan-cli'
  binaryAvailable: boolean
  resourceLimitsAvailable: boolean
  readyForAttempt: boolean
  detail: string
}

/**
 * Report actual local execution prerequisites. This is deliberately not called
 * a successful malware-engine health check: binary presence and prlimit do not
 * prove that signature databases are installed, current, or loadable.
 */
export function getClamAVCapability(): ClamAVCapability {
  const scanner = resolveClamScan()
  const resourceLimitsAvailable = process.platform === 'linux' ? resolvePrlimit() !== null : process.env.SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS === '1'
  const binaryAvailable = scanner !== null
  const readyForAttempt = binaryAvailable && resourceLimitsAvailable
  return {
    engine: 'clamscan-cli',
    binaryAvailable,
    resourceLimitsAvailable,
    readyForAttempt,
    detail: !binaryAvailable
      ? 'ClamAV clamscan executable is not installed in a trusted location.'
      : !resourceLimitsAvailable
        ? 'ClamAV binary exists, but required process resource limits are unavailable.'
        : 'ClamAV binary and resource-limit prerequisites are present; signature database readiness is not yet verified.',
  }
}

function killProcessGroup(child: ChildProcess): void {
  if (!child.pid) return
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL')
    else child.kill('SIGKILL')
  } catch {
    try { child.kill('SIGKILL') } catch { /* already exited */ }
  }
}

export function scanWithClamAV(filePath: string): Promise<{
  state: AnalyzerState
  detail: string
  threatName?: string
}> {
  return new Promise((resolve) => {
    const scanner = resolveClamScan()
    if (!scanner) {
      resolve({ state: 'unavailable', detail: 'ClamAV clamscan executable is not installed in a trusted location.' })
      return
    }

    const prlimit = resolvePrlimit()
    if (process.platform === 'linux' && !prlimit) {
      resolve({ state: 'unavailable', detail: 'Linux prlimit is unavailable; SENTINEL refused to run ClamAV without process resource limits.' })
      return
    }
    if (process.platform !== 'linux' && process.env.SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS !== '1') {
      resolve({ state: 'unavailable', detail: 'ClamAV resource limits are unavailable on this platform; unsandboxed execution was not enabled.' })
      return
    }

    const command = prlimit ?? scanner
    const args = prlimit
      ? ['--as=3221225472', '--cpu=120', '--fsize=16777216', '--nofile=128', '--core=0', '--', scanner, '--no-summary', filePath]
      : ['--no-summary', filePath]

    let settled = false
    let stdout = ''
    let stderr = ''
    let outputBytes = 0
    let timer: NodeJS.Timeout | undefined
    let child: ChildProcess

    const finish = (result: { state: AnalyzerState; detail: string; threatName?: string }) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolve(result)
    }

    try {
      child = spawn(command, args, {
        shell: false,
        detached: process.platform !== 'win32',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          PATH: '/usr/local/bin:/usr/bin:/bin',
          LANG: 'C',
          LC_ALL: 'C',
        },
      })
    } catch (error) {
      finish({ state: 'failed', detail: `ClamAV could not start: ${safeErrorText(String(error))}` })
      return
    }

    timer = setTimeout(() => {
      killProcessGroup(child)
      finish({ state: 'timed_out', detail: `ClamAV exceeded ${SCAN_TIMEOUT_MS} ms; process group terminated.` })
    }, SCAN_TIMEOUT_MS)
    timer.unref?.()

    child.stdout?.on('data', (chunk: Buffer) => {
      if (settled) return
      outputBytes += chunk.length
      if (outputBytes > MAX_OUTPUT_BYTES) {
        killProcessGroup(child)
        finish({ state: 'failed', detail: 'ClamAV output exceeded its 64 KiB limit; process group terminated.' })
        return
      }
      stdout += chunk.toString('utf8')
    })
    child.stderr?.on('data', (chunk: Buffer) => {
      if (settled) return
      stderr = (stderr + chunk.toString('utf8')).slice(-MAX_DIAGNOSTIC_BYTES)
    })
    child.on('error', (error: NodeJS.ErrnoException) => {
      finish({
        state: error.code === 'ENOENT' ? 'unavailable' : 'failed',
        detail: error.code === 'ENOENT' ? 'ClamAV executable could not be found.' : `ClamAV process error: ${safeErrorText(error.message)}`,
      })
    })
    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return
      if (code === 0) {
        finish({ state: 'completed_no_detections', detail: 'ClamAV reported no known signature match.' })
        return
      }
      if (code === 1 && /FOUND\s*$/m.test(stdout)) {
        const raw = sanitizeClamOutput(stdout) || 'ClamAV detected a threat.'
        finish({ state: 'finding', detail: raw, threatName: raw })
        return
      }
      const diagnostic = sanitizeClamOutput(stderr) || sanitizeClamOutput(stdout)
      const missingExecutable = /failed to execute .*clamscan|no such file or directory/i.test(diagnostic)
      finish({
        state: missingExecutable ? 'unavailable' : 'failed',
        detail: diagnostic || `ClamAV failed (exit=${String(code)} signal=${String(signal)}).`,
      })
    })
  })
}

export function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(filePath)
    stream.on('data', (chunk) => hash.update(chunk as never))
    stream.on('error', reject)
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

export async function blake3File(filePath: string): Promise<string> {
  const { blake3 } = await import('@noble/hashes/blake3.js')
  const { open } = await import('node:fs/promises')
  const handle = await open(filePath, 'r')
  try {
    const hasher = blake3.create({})
    const buffer = Buffer.alloc(64 * 1024)
    let bytesRead = 0
    while ((bytesRead = (await handle.read(buffer, 0, buffer.length)).bytesRead) > 0) {
      hasher.update(buffer.subarray(0, bytesRead))
    }
    return Buffer.from(hasher.digest()).toString('hex')
  } finally {
    await handle.close()
  }
}

// Remove local filesystem paths from ClamAV output and bound returned evidence.
function sanitizeClamOutput(output: string): string {
  const value = output.trim()
  if (!value) return ''
  const lines = value.split(/\r?\n/).map((line) => {
    const separatorIndex = line.lastIndexOf(': ')
    return separatorIndex !== -1 && separatorIndex < line.length - 2
      ? line.slice(separatorIndex + 2).trim()
      : line.trim()
  })
  return lines.join('\n').slice(0, 1200)
}

function safeErrorText(value: string): string {
  return value.replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 500)
}
