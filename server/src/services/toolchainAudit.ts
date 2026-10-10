import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { randomUUID } from 'node:crypto'
import { auditDependencies } from './codeAudit.js'

export type ToolState = 'completed' | 'blocked' | 'failed' | 'timed_out'
export interface ToolRun {
  tool: string
  state: ToolState
  exitCode: number | null
  durationMs: number
  summary: string
  findings?: unknown[]
}
export interface ToolchainAudit {
  state: 'completed' | 'partial' | 'blocked'
  runs: ToolRun[]
  notes: string[]
}

const timeoutMs = 20_000
const maxOutput = 2_000_000

function run(
  command: string,
  args: string[],
  cwd: string
): Promise<{
  code: number | null
  stdout: string
  stderr: string
  timedOut: boolean
  error?: string
  durationMs: number
}> {
  return new Promise((resolve) => {
    const started = Date.now()
    let stdout = '',
      stderr = '',
      timedOut = false,
      settled = false
    let child: ChildProcess
    try {
      child = spawn(command, args, {
        cwd,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_NOSYSTEM: '1',
        },
      })
    } catch (e) {
      resolve({
        code: null,
        stdout,
        stderr,
        timedOut: false,
        error: String(e),
        durationMs: Date.now() - started,
      })
      return
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGTERM')
      setTimeout(() => child.kill('SIGKILL'), 500).unref()
    }, timeoutMs)
    const collect = (target: 'stdout' | 'stderr', chunk: Buffer) => {
      if (target === 'stdout') stdout += chunk.toString('utf8')
      else stderr += chunk.toString('utf8')
      if (stdout.length + stderr.length > maxOutput) {
        timedOut = true
        child.kill('SIGTERM')
      }
    }
    child.stdout?.on('data', (b: Buffer) => collect('stdout', b))
    child.stderr?.on('data', (b: Buffer) => collect('stderr', b))
    child.on('error', (e: Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({
        code: null,
        stdout,
        stderr,
        timedOut,
        error: e.message,
        durationMs: Date.now() - started,
      })
    })
    child.on('close', (code: number | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({
        code,
        stdout,
        stderr,
        timedOut,
        durationMs: Date.now() - started,
      })
    })
  })
}

function parseJsonArray(s: string): unknown[] | undefined {
  try {
    const value = JSON.parse(s)
    if (Array.isArray(value)) return value
    if (Array.isArray(value?.results)) return value.results
    if (Array.isArray(value?.findings)) return value.findings
    if (Array.isArray(value?.Results)) return value.Results
    return []
  } catch {
    return undefined
  }
}

function runEmbeddedGitleaks(source: string, filename: string): unknown[] {
  const findings: unknown[] = []
  const lines = source.split(/\r?\n/)
  const patterns = [
    { rule: 'generic-api-key', regex: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]/i, title: 'Generic API Key / Secret Token' },
    { rule: 'aws-access-key-id', regex: /AKIA[0-9A-Z]{16}/, title: 'AWS Access Key ID' },
    { rule: 'github-pat', regex: /gh[pousr]_[A-Za-z0-9]{36,}/, title: 'GitHub Personal Access Token' },
    { rule: 'stripe-api-key', regex: /sk_live_[A-Za-z0-9]{24,}/, title: 'Stripe Live API Key' },
    { rule: 'private-key', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, title: 'Private Key Material' },
    { rule: 'hardcoded-password', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{3,}['"]/i, title: 'Hardcoded Password in Source' },
    { rule: 'database-uri-credential', regex: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"]+:[^@\s'"]+@/i, title: 'Database URI with Embedded Password' },
  ]

  for (let i = 0; i < lines.length; i++) {
    for (const pat of patterns) {
      if (pat.regex.test(lines[i])) {
        findings.push({
          Description: pat.title,
          RuleID: pat.rule,
          File: filename,
          StartLine: i + 1,
          Match: lines[i].trim().slice(0, 120),
          Secret: '***REDACTED***',
        })
      }
    }
  }
  return findings
}

function runEmbeddedSemgrep(source: string, filename: string): unknown[] {
  const findings: unknown[] = []
  const lines = source.split(/\r?\n/)
  const semgrepRules = [
    {
      check_id: 'javascript.express.security.sql-injection',
      regex: /(?:query|execute)\s*\(\s*[`"'][^`"']*\$\{|(?:query|execute)\s*\(\s*[^,\n]+\s*\+\s*(?:req\.|request\.|params\.|query\.)|(?:sql|query|stmt)\s*=\s*['"`].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\+\s*(?:req\.|request\.|params\.|query\.|input|[a-zA-Z0-9_]+)|(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^;\n]*['"`]\s*\+\s*(?:req\.|request\.|params\.|query\.)/i,
      message: 'Detected SQL query constructed directly from user input without parameterized queries.',
      severity: 'ERROR',
    },
    {
      check_id: 'javascript.node.security.child-process-command-injection',
      regex: /(?:exec|execSync|spawn|popen|system)\s*\(\s*(?:`[^`]*\$\{|[^,\n]+\+\s*(?:req\.|request\.|params\.|query\.|input))/i,
      message: 'Direct command execution with unvalidated user input may result in remote command injection.',
      severity: 'ERROR',
    },
    {
      check_id: 'python.security.evasive-reflection',
      regex: /(?:__builtins__|globals\(\)\.get|locals\(\)\.get|__dict__\.get|getattr\s*\([^)]*(?:eval|exec|system|popen|spawn))/i,
      message: 'Evasive dynamic execution via built-ins reflection / dynamic function lookup.',
      severity: 'ERROR',
    },
    {
      check_id: 'python.security.dynamic-import',
      regex: /(?:__import__\s*\(|importlib\.import_module\s*\()/i,
      message: 'Dynamic module loading via __import__ or importlib.',
      severity: 'WARNING',
    },
    {
      check_id: 'generic.security.destructive-command',
      regex: /(?:rm\s+-rf\s+(?:--no-preserve-root\s+)?\/|format\s+[a-zA-Z]:|dd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/)/i,
      message: 'Destructive system command signature detected.',
      severity: 'ERROR',
    },
    {
      check_id: 'generic.security.tls-verification-disabled',
      regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*['"]?\s*[:=]\s*['"]?0|verify\s*=\s*False)/i,
      message: 'TLS certificate verification is disabled, allowing man-in-the-middle attacks.',
      severity: 'WARNING',
    },
    {
      check_id: 'python.lang.security.deserialization.pickle',
      regex: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:SafeLoader|CSafeLoader))/i,
      message: 'Unsafe deserialization of untrusted input can execute arbitrary code.',
      severity: 'ERROR',
    },
  ]

  for (let i = 0; i < lines.length; i++) {
    for (const rule of semgrepRules) {
      if (rule.regex.test(lines[i])) {
        findings.push({
          check_id: rule.check_id,
          path: filename,
          start: { line: i + 1, col: 1 },
          extra: {
            message: rule.message,
            severity: rule.severity,
            lines: lines[i].trim().slice(0, 140),
          },
        })
      }
    }
  }
  return findings
}

/** Runs optional offline/local scanners without a shell. Each tool is independently reported; absence never means clean. */
export async function runToolchainAudit(
  source: string,
  filename: string
): Promise<ToolchainAudit> {
  const notes: string[] = []
  const runs: ToolRun[] = []
  const root = process.platform === 'linux' ? '/dev/shm' : os.tmpdir()
  let dir = ''
  try {
    dir = await mkdtemp(path.join(root, 'sentinel-audit-'))
    const safeName =
      path
        .basename(filename)
        .replace(/[^A-Za-z0-9._-]/g, '_')
        .slice(0, 120) || `source-${randomUUID()}.txt`
    const file = path.join(dir, safeName)
    await writeFile(file, source, { mode: 0o600, flag: 'wx' })

    // --------------------------------------------------
    // 1. SEMGREP
    // --------------------------------------------------
    const semgrep = process.env.SENTINEL_SEMGREP_BIN || 'semgrep'
    const semgrepConfig = process.env.SENTINEL_SEMGREP_CONFIG
    const embeddedFindings = runEmbeddedSemgrep(source, safeName)
    if (!semgrepConfig) {
      runs.push({
        tool: 'semgrep',
        state: 'blocked',
        exitCode: null,
        durationMs: 0,
        summary:
          'Set SENTINEL_SEMGREP_CONFIG to a trusted local ruleset path; remote auto-config is intentionally disabled.',
        findings: embeddedFindings.length > 0 ? embeddedFindings : undefined,
      })
    } else {
      const r = await run(
        semgrep,
        ['scan', '--json', '--config', semgrepConfig, '--no-git-ignore', file],
        dir
      )
      const parsed = parseJsonArray(r.stdout)
      runs.push({
        tool: 'semgrep',
        state: r.timedOut
          ? 'timed_out'
          : r.error
          ? 'blocked'
          : parsed === undefined
          ? 'failed'
          : r.code === 0 || r.code === 1
          ? 'completed'
          : 'failed',
        exitCode: r.code,
        durationMs: r.durationMs,
        summary: r.error
          ? (r.error.includes('ENOENT') ? `CLI not found in PATH; embedded rule engine active (${embeddedFindings.length} match(es)).` : r.error)
          : (r.stderr.slice(0, 300) || `Semgrep exited ${r.code}`),
        findings: parsed ?? (r.error && embeddedFindings.length > 0 ? embeddedFindings : undefined),
      })
    }

    // --------------------------------------------------
    // 2. GITLEAKS
    // --------------------------------------------------
    const gitleaksBin = process.env.SENTINEL_GITLEAKS_BIN || 'gitleaks'
    const g = await run(
      gitleaksBin,
      [
        'detect',
        '--no-git',
        '--source',
        dir,
        '--report-format',
        'json',
        '--report-path',
        '/dev/stdout',
        '--exit-code',
        '0',
      ],
      dir
    )
    const gParsed = parseJsonArray(g.stdout)
    const embeddedSecrets = runEmbeddedGitleaks(source, safeName)
    runs.push({
      tool: 'gitleaks',
      state: g.timedOut
        ? 'timed_out'
        : g.error
        ? 'blocked'
        : gParsed === undefined
        ? 'failed'
        : g.code === 0
        ? 'completed'
        : 'failed',
      exitCode: g.code,
      durationMs: g.durationMs,
      summary: g.error
        ? (g.error.includes('ENOENT') ? `CLI not found in PATH; embedded secret engine active (${embeddedSecrets.length} secret(s) found).` : g.error)
        : (g.stderr.slice(0, 300) || `Gitleaks exited ${g.code}`),
      findings: gParsed ?? (g.error && embeddedSecrets.length > 0 ? embeddedSecrets : undefined),
    })

    // --------------------------------------------------
    // 3. OSV-SCANNER
    // --------------------------------------------------
    const isManifest = /(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements(\.txt)?|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|pom\.xml|gradle\.lockfile)$/i.test(
      safeName
    ) || (source.trim().startsWith('{') && /"dependencies"/.test(source)) || /__requires__\s*=\s*\[/i.test(source)

    if (!isManifest) {
      runs.push({
        tool: 'osv-scanner',
        state: 'blocked',
        exitCode: null,
        durationMs: 0,
        summary:
          'Not applicable to raw source files. Submit a supported dependency manifest (package.json, requirements.txt, Cargo.lock, etc.) for CVE vulnerability auditing.',
      })
    } else {
      const osvBin = process.env.SENTINEL_OSV_SCANNER_BIN || 'osv-scanner'
      const o = await run(
        osvBin,
        ['scan', 'source', '--format', 'json', '--recursive', dir],
        dir
      )
      const oParsed = parseJsonArray(o.stdout)
      const depAdvisories = auditDependencies(source, safeName)
      runs.push({
        tool: 'osv-scanner',
        state: o.timedOut
          ? 'timed_out'
          : o.error
          ? 'blocked'
          : oParsed === undefined
          ? 'failed'
          : o.code === 0 || o.code === 1
          ? 'completed'
          : 'failed',
        exitCode: o.code,
        durationMs: o.durationMs,
        summary: o.error
          ? (o.error.includes('ENOENT') ? `CLI not found in PATH; embedded advisory engine active (${depAdvisories.length} advisory match(es)).` : o.error)
          : (o.stderr.slice(0, 300) || `OSV-Scanner exited ${o.code}`),
        findings: oParsed ?? (o.error && depAdvisories.length > 0 ? depAdvisories : undefined),
      })
    }

    // --------------------------------------------------
    // 4. TRIVY
    // --------------------------------------------------
    const trivyBin = process.env.SENTINEL_TRIVY_BIN || 'trivy'
    const t = await run(trivyBin, ['fs', '--format', 'json', '--quiet', dir], dir)
    const tParsed = parseJsonArray(t.stdout)
    const trivyEmbedded = runEmbeddedSemgrep(source, safeName)
    runs.push({
      tool: 'trivy',
      state: t.timedOut
        ? 'timed_out'
        : t.error
        ? 'blocked'
        : tParsed === undefined
        ? 'failed'
        : t.code === 0
        ? 'completed'
        : 'failed',
      exitCode: t.code,
      durationMs: t.durationMs,
      summary: t.error
        ? (t.error.includes('ENOENT') ? `CLI not found in PATH; embedded security inspection active (${trivyEmbedded.length} item(s)).` : t.error)
        : (t.stderr.slice(0, 300) || `Trivy exited ${t.code}`),
      findings: tParsed ?? (t.error && trivyEmbedded.length > 0 ? trivyEmbedded : undefined),
    })
  } catch (e) {
    notes.push(`Toolchain setup failed: ${String(e).slice(0, 240)}`)
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => undefined)
  }

  const successful = runs.filter((x) => x.state === 'completed').length
  const state =
    successful === runs.length && runs.length > 0
      ? 'completed'
      : successful > 0
      ? 'partial'
      : 'blocked'
  if (process.platform !== 'linux') {
    notes.push(
      'This platform uses the OS temporary directory; strict RAM-only handling requires a verified RAM-backed temporary root.'
    )
  }
  notes.push(
    'Tool outputs are advisory and must be normalized/reviewed; scanner exit codes and formats vary by installed version.'
  )
  notes.push(
    'Missing tools, absent trusted Semgrep configuration, unsupported manifests, and execution failures are not interpreted as a clean result.'
  )
  return { state, runs, notes }
}
