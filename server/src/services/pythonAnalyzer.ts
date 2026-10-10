/**
 * SENTINEL analyzer process boundary.
 *
 * Analyzers process attacker-controlled files and must not execute inside the
 * Express process. On Linux, prlimit applies kernel-enforced address-space,
 * CPU, file-size, descriptor and core-dump limits before Python starts. The
 * process is also placed in its own process group so a timeout/output breach
 * kills descendants, not just the immediate Python process.
 *
 * This is resource containment, NOT a filesystem/network namespace sandbox.
 * Use an OS/container sandbox (e.g. bubblewrap or a dedicated service account)
 * for a stronger hostile-code boundary. We never silently claim those controls.
 */
import { spawn, type ChildProcess } from 'node:child_process'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

export function analyzerScriptDir(): string {
  // Resolve relative to this module, not the caller's working directory. This
  // works for both tsx source execution and compiled server/dist execution.
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../python-analyzers')
}

function resolvePython(): string {
  if (process.env.PYTHON_EXECUTABLE) return process.env.PYTHON_EXECUTABLE

  const isWin = process.platform === 'win32'
  const projectRoot = path.resolve(analyzerScriptDir(), '..')
  const serverRoot = path.resolve(projectRoot, 'server')
  const candidates = [
    // Prefer the dedicated analyzer environment so PDF dependencies are not
    // accidentally resolved from an unrelated system Python installation.
    path.resolve(projectRoot, 'python-analyzers', '.venv', isWin ? 'Scripts/python.exe' : 'bin/python'),
    path.resolve(serverRoot, '.venv', isWin ? 'Scripts/python.exe' : 'bin/python'),
    path.resolve(projectRoot, '.venv', isWin ? 'Scripts/python.exe' : 'bin/python'),
    '/usr/bin/python3',
    '/usr/local/bin/python3',
  ]
  for (const candidate of candidates) {
    try { if (fs.existsSync(candidate)) return candidate } catch { /* continue */ }
  }
  return isWin ? 'python' : 'python3'
}

function resolvePrlimit(): string | null {
  if (process.platform !== 'linux') return null
  for (const candidate of ['/usr/bin/prlimit', '/bin/prlimit']) {
    try { if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate } catch { /* continue */ }
  }
  return null
}

export interface PythonRun<T> {
  ok: boolean
  data: T | null
  error: string | null
  timedOut: boolean
  resourceLimited: boolean
}

export interface SpawnLimits {
  timeoutMs: number
  maxStdoutChars: number
  /** Soft/hard RLIMIT_AS in MiB. Defaults to 1536 MiB. */
  memoryLimitMb?: number
  /** RLIMIT_FSIZE in MiB, limiting files an analyzer can create. Defaults to 16 MiB. */
  outputFileLimitMb?: number
}

export interface BoundedProcessOptions extends SpawnLimits {
  executable: string
  args: string[]
  cwd?: string
  env?: NodeJS.ProcessEnv
  /** Use prlimit on Linux; never silently downgrade if unavailable. */
  requireResourceLimits?: boolean
}

function safeErrorText(value: string, max = 1200): string {
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').trim().slice(0, max)
}

function killProcessTree(child: ChildProcess): void {
  if (!child.pid) return
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL')
    else child.kill('SIGKILL')
  } catch {
    try { child.kill('SIGKILL') } catch { /* process already exited */ }
  }
}

/** Run one process with bounded wall time, output, and (on Linux) kernel limits. */
export function runBoundedProcess<T = unknown>(options: BoundedProcessOptions): Promise<PythonRun<T>> {
  const {
    timeoutMs,
    maxStdoutChars,
    memoryLimitMb = 1536,
    outputFileLimitMb = 16,
    requireResourceLimits = true,
  } = options

  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    return Promise.resolve({ ok: false, data: null, error: 'Invalid analyzer timeout configuration.', timedOut: false, resourceLimited: false })
  }
  if (!Number.isSafeInteger(maxStdoutChars) || maxStdoutChars < 1 || maxStdoutChars > 10_000_000) {
    return Promise.resolve({ ok: false, data: null, error: 'Invalid analyzer output limit configuration.', timedOut: false, resourceLimited: false })
  }
  if (!Number.isSafeInteger(memoryLimitMb) || memoryLimitMb < 128 || memoryLimitMb > 8192 ||
      !Number.isSafeInteger(outputFileLimitMb) || outputFileLimitMb < 1 || outputFileLimitMb > 256) {
    return Promise.resolve({ ok: false, data: null, error: 'Invalid analyzer resource-limit configuration.', timedOut: false, resourceLimited: false })
  }

  const prlimit = resolvePrlimit()
  if (requireResourceLimits && process.platform === 'linux' && !prlimit) {
    return Promise.resolve({ ok: false, data: null, error: 'Linux resource limiter (prlimit) is unavailable; analyzer was not started.', timedOut: false, resourceLimited: false })
  }
  if (requireResourceLimits && process.platform !== 'linux' && process.env.SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS !== '1') {
    return Promise.resolve({ ok: false, data: null, error: 'Kernel resource limits are unavailable on this platform. Set SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS=1 only for an explicitly accepted development risk.', timedOut: false, resourceLimited: false })
  }

  const resourceLimited = Boolean(prlimit)
  const cpuSeconds = Math.max(2, Math.min(60, Math.ceil(timeoutMs / 1000)))
  const command = prlimit ?? options.executable
  const commandArgs = prlimit
    ? [
        `--as=${memoryLimitMb * 1024 * 1024}`,
        `--cpu=${cpuSeconds}`,
        `--fsize=${outputFileLimitMb * 1024 * 1024}`,
        '--nofile=64',
        '--core=0',
        '--',
        options.executable,
        ...options.args,
      ]
    : options.args

  return new Promise((resolve) => {
    let settled = false
    let stdout = ''
    let stderr = ''
    let stdoutBytes = 0
    let stderrBytes = 0
    let timer: NodeJS.Timeout | undefined
    let child: ChildProcess

    const settle = (result: PythonRun<T>) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolve(result)
    }

    try {
      child = spawn(command, commandArgs, {
        cwd: options.cwd,
        env: options.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        detached: process.platform !== 'win32',
        shell: false,
      })
    } catch (error) {
      settle({ ok: false, data: null, error: `Unable to start analyzer: ${safeErrorText(String(error))}`, timedOut: false, resourceLimited })
      return
    }

    timer = setTimeout(() => {
      killProcessTree(child)
      settle({ ok: false, data: null, error: `Analyzer exceeded wall-clock limit (${timeoutMs} ms). Process group terminated.`, timedOut: true, resourceLimited })
    }, timeoutMs)
    timer.unref?.()

    child.stdout?.on('data', (chunk: Buffer) => {
      if (settled) return
      stdoutBytes += chunk.length
      if (stdoutBytes > maxStdoutChars) {
        killProcessTree(child)
        settle({ ok: false, data: null, error: `Analyzer stdout exceeded ${maxStdoutChars} bytes; process group terminated.`, timedOut: false, resourceLimited })
        return
      }
      stdout += chunk.toString('utf8')
    })

    child.stderr?.on('data', (chunk: Buffer) => {
      if (settled) return
      stderrBytes += chunk.length
      // Keep only a bounded tail; stderr is diagnostic, never trusted output.
      stderr = (stderr + chunk.toString('utf8')).slice(-16_000)
    })

    child.on('error', (error: Error) => {
      settle({ ok: false, data: null, error: `Unable to start analyzer: ${safeErrorText(error.message)}`, timedOut: false, resourceLimited })
    })

    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return
      if (code !== 0) {
        const diagnostics = safeErrorText(stderr) || `exit=${String(code)} signal=${String(signal)}`
        settle({ ok: false, data: null, error: `Analyzer process failed (${diagnostics}).`, timedOut: false, resourceLimited })
        return
      }
      // Strictly require one JSON document. Do not salvage an arbitrary brace
      // substring from mixed logs, which could turn noisy output into a result.
      try {
        const parsed = JSON.parse(stdout.trim()) as T & { ok?: boolean; error?: string }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          settle({ ok: false, data: null, error: 'Analyzer returned JSON of an unexpected shape.', timedOut: false, resourceLimited })
          return
        }
        if (parsed.ok === false) {
          settle({ ok: false, data: null, error: safeErrorText(parsed.error || 'Analyzer reported failure.'), timedOut: false, resourceLimited })
          return
        }
        settle({ ok: true, data: parsed as T, error: null, timedOut: false, resourceLimited })
      } catch {
        settle({ ok: false, data: null, error: `Analyzer returned invalid or mixed JSON output${stderrBytes ? ` (${safeErrorText(stderr, 240)})` : ''}.`, timedOut: false, resourceLimited })
      }
    })
  })
}

/** Execute a named, repository-owned Python analyzer under the same boundary. */
export function runPythonJson<T>(scriptFile: string, args: string[], limits: SpawnLimits): Promise<PythonRun<T>> {
  const allowedScripts = new Set(['analyze_pdf.py', 'analyze_docx.py', 'analyze_exe.py'])
  if (!allowedScripts.has(scriptFile)) {
    return Promise.resolve({ ok: false, data: null, error: 'Invalid analyzer script name.', timedOut: false, resourceLimited: false })
  }
  const baseDir = analyzerScriptDir()
  const scriptPath = path.resolve(baseDir, scriptFile)
  if (!scriptPath.startsWith(`${baseDir}${path.sep}`)) {
    return Promise.resolve({ ok: false, data: null, error: 'Analyzer script path escaped the trusted analyzer directory.', timedOut: false, resourceLimited: false })
  }

  // Do not pass application secrets or arbitrary inherited variables into a
  // parser process. Only retain values needed to start Python reliably.
  const env: NodeJS.ProcessEnv = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PYTHONNOUSERSITE: '1',
    PYTHONDONTWRITEBYTECODE: '1',
  }
  if (process.platform === 'win32') {
    for (const key of ['SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key]
    env.PATH = process.env.PATH
  }

  return runBoundedProcess<T>({
    ...limits,
    executable: resolvePython(),
    args: ['-I', scriptPath, ...args],
    cwd: baseDir,
    env,
    requireResourceLimits: true,
  })
}
