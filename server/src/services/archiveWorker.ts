import { spawn, type ChildProcess } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export interface ArchiveWorkerJob {
  archivePath: string
  destination: string
  dataOffset: number
  compressedSize: number
  uncompressedSize: number
  crc32: number
  method: number
  remainingTotal: number
}
export interface ArchiveWorkerResult { bytes: number; crc32: number; sandboxed: boolean }

function executable(candidates: string[]): string | null {
  for (const candidate of candidates) {
    try { if (fs.statSync(candidate).isFile()) return candidate } catch { /* try next */ }
  }
  return null
}
function workerPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [path.resolve(here, '../../../archive-worker.mjs'), path.resolve(here, '../../archive-worker.mjs')]
  const found = candidates.find((candidate) => fs.existsSync(candidate))
  if (!found) throw new Error('Trusted archive worker script is missing from the installation.')
  return found
}
function processGroupKill(child: ChildProcess): void {
  if (!child.pid) return
  try { process.kill(-child.pid, 'SIGKILL') } catch { try { child.kill('SIGKILL') } catch { /* already exited */ } }
}
function parentDirectories(absolutePath: string): string[] {
  const dirs: string[] = []
  let current = path.dirname(absolutePath)
  while (current !== path.dirname(current)) { dirs.unshift(current); current = path.dirname(current) }
  return [...new Set(dirs.filter((dir) => dir !== '/'))]
}
function bwrapArgs(worker: string, job: ArchiveWorkerJob): string[] {
  const nodeBinary = fs.realpathSync(process.execPath)
  const args = [
    '--die-with-parent', '--new-session', '--unshare-all',
    '--ro-bind', '/usr', '/usr',
    '--ro-bind', '/etc', '/etc',
  ]
  for (const target of ['/lib', '/lib64', '/bin', '/sbin']) {
    try {
      if (fs.existsSync(target)) args.push('--ro-bind', fs.realpathSync(target), target)
    } catch { /* optional system path */ }
  }
  args.push('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/sentinel')
  const neededDirs = new Set([...parentDirectories(job.archivePath), ...parentDirectories(job.destination), ...parentDirectories(nodeBinary)])
  for (const dir of [...neededDirs].sort((a, b) => a.length - b.length)) {
    // /dev exists after --dev; /tmp exists after --tmpfs. Other parents are created explicitly.
    if (dir === '/dev' || dir === '/tmp') continue
    args.push('--dir', dir)
  }
  args.push(
    '--ro-bind', nodeBinary, nodeBinary,
    '--ro-bind', worker, '/sentinel/archive-worker.mjs',
    '--ro-bind', job.archivePath, job.archivePath,
    '--bind', path.dirname(job.destination), path.dirname(job.destination),
    '--chdir', path.dirname(job.destination), '--', nodeBinary, '/sentinel/archive-worker.mjs',
  )
  return args
}

/**
 * Run decompression outside the API process. Linux production mode requires
 * bubblewrap for mount+network namespace isolation and prlimit for resource
 * limits. A prlimit-only fallback is available solely through an explicit
 * development/test opt-in and is always reported as unsandboxed.
 */
export function runArchiveWorker(job: ArchiveWorkerJob): Promise<ArchiveWorkerResult> {
  const allowDevFallback = process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER === '1'
  const prlimit = process.platform === 'linux' ? executable(['/usr/bin/prlimit', '/bin/prlimit']) : null
  const bwrap = process.platform === 'linux' ? executable(['/usr/bin/bwrap', '/bin/bwrap']) : null

  if (process.platform !== 'linux') {
    if (!allowDevFallback && process.env.SENTINEL_ALLOW_CROSS_PLATFORM !== '1') {
      return Promise.reject(new Error('Archive worker requires Linux process isolation. On non-Linux platforms, explicitly set SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER=1 for development.'))
    }
  } else {
    if (!prlimit) return Promise.reject(new Error('prlimit is unavailable; archive member was not decompressed.'))
    if (!bwrap && !allowDevFallback) return Promise.reject(new Error('bubblewrap is unavailable; strict archive worker requires filesystem and network namespace isolation. Member was not decompressed.'))
  }

  let worker: string
  try { worker = workerPath() } catch (error) { return Promise.reject(error) }
  const sandboxed = Boolean(bwrap)
  const baseCommand = sandboxed ? bwrap! : process.execPath
  const baseArgs = sandboxed ? bwrapArgs(worker, job) : [worker]
  const spawnCommand = prlimit ?? baseCommand
  const commandArgs = prlimit
    ? [
        '--as=1610612736', '--cpu=3', '--fsize=10485760', '--nofile=32', '--core=0', '--', baseCommand, ...baseArgs,
      ]
    : baseArgs

  return new Promise((resolve, reject) => {
    let settled = false
    let stdout = ''
    let stderr = ''
    let timer: NodeJS.Timeout
    let child: ChildProcess
    const settle = (error?: Error, result?: ArchiveWorkerResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(result!)
    }
    try {
      child = spawn(spawnCommand, commandArgs, {
        stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32', shell: false, windowsHide: true,
        env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', NODE_NO_WARNINGS: '1' },
      })
    } catch (error) {
      settle(new Error(`Unable to start archive worker: ${String(error).slice(0, 240)}`)); return
    }
    timer = setTimeout(() => { processGroupKill(child); settle(new Error('Archive worker exceeded 10-second wall-clock limit; process group terminated.')) }, 10_000)
    timer.unref?.()
    child.stdout?.on('data', (chunk: Buffer) => {
      if (settled) return
      stdout += chunk.toString('utf8')
      if (Buffer.byteLength(stdout) > 16_384) { processGroupKill(child); settle(new Error('Archive worker output exceeded 16 KiB.')) }
    })
    child.stderr?.on('data', (chunk: Buffer) => { if (!settled) stderr = (stderr + chunk.toString('utf8')).slice(-4000) })
    child.on('error', (error) => settle(new Error(`Archive worker could not start: ${error.message.slice(0, 240)}`)))
    child.on('close', (code, signal) => {
      if (settled) return
      let result: { ok?: boolean; bytes?: number; crc32?: number; error?: string }
      try { result = JSON.parse(stdout.trim()) } catch { settle(new Error(`Archive worker returned invalid JSON (exit=${String(code)}, signal=${String(signal)}): ${stderr.slice(-240)}`)); return }
      if (code !== 0 || result.ok !== true || !Number.isSafeInteger(result.bytes) || !Number.isSafeInteger(result.crc32)) {
        settle(new Error(`Archive worker rejected member: ${(result.error ?? stderr ?? `exit=${String(code)}`).slice(0, 300)}`)); return
      }
      settle(undefined, { bytes: result.bytes!, crc32: result.crc32!, sandboxed })
    })
    child.stdin?.end(JSON.stringify(job))
  })
}
