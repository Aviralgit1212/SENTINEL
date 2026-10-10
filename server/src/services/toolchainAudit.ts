import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { randomUUID } from 'node:crypto'

export type ToolState = 'completed' | 'blocked' | 'failed' | 'timed_out'
export interface ToolRun { tool: string; state: ToolState; exitCode: number | null; durationMs: number; summary: string; findings?: unknown[] }
export interface ToolchainAudit { state: 'completed' | 'partial' | 'blocked'; runs: ToolRun[]; notes: string[] }
const timeoutMs = 20_000
const maxOutput = 2_000_000

function run(command: string, args: string[], cwd: string): Promise<{code:number|null; stdout:string; stderr:string; timedOut:boolean; error?:string; durationMs:number}> {
  return new Promise((resolve) => {
    const started = Date.now()
    let stdout = '', stderr = '', timedOut = false, settled = false
    let child: ChildProcess
    try { child = spawn(command, args, { cwd, shell: false, windowsHide: true, stdio: ['ignore','pipe','pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1' } }) }
    catch (e) { resolve({code:null,stdout,stderr,timedOut:false,error:String(e),durationMs:Date.now()-started}); return }
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 500).unref() }, timeoutMs)
    const collect = (target: 'stdout'|'stderr', chunk: Buffer) => {
      if (target === 'stdout') stdout += chunk.toString('utf8'); else stderr += chunk.toString('utf8')
      if (stdout.length + stderr.length > maxOutput) { timedOut = true; child.kill('SIGTERM') }
    }
    child.stdout?.on('data', (b:Buffer) => collect('stdout', b)); child.stderr?.on('data', (b:Buffer) => collect('stderr', b))
    child.on('error', (e:Error) => { if (settled) return; settled = true; clearTimeout(timer); resolve({code:null,stdout,stderr,timedOut,error:e.message,durationMs:Date.now()-started}) })
    child.on('close', (code:number|null) => { if (settled) return; settled = true; clearTimeout(timer); resolve({code,stdout,stderr,timedOut,durationMs:Date.now()-started}) })
  })
}

function parseJsonArray(s: string): unknown[] | undefined {
  try { const value = JSON.parse(s); if (Array.isArray(value)) return value; if (Array.isArray(value?.results)) return value.results; if (Array.isArray(value?.findings)) return value.findings; if (Array.isArray(value?.Results)) return value.Results; return [] } catch { return undefined }
}

/** Runs optional offline/local scanners without a shell. Each tool is independently reported; absence never means clean. */
export async function runToolchainAudit(source: string, filename: string): Promise<ToolchainAudit> {
  const notes: string[] = []
  const runs: ToolRun[] = []
  const root = process.platform === 'linux' ? '/dev/shm' : os.tmpdir()
  let dir = ''
  try {
    dir = await mkdtemp(path.join(root, 'sentinel-audit-'))
    const safeName = path.basename(filename).replace(/[^A-Za-z0-9._-]/g, '_').slice(0,120) || `source-${randomUUID()}.txt`
    const file = path.join(dir, safeName)
    await writeFile(file, source, { mode: 0o600, flag: 'wx' })
    const semgrep = process.env.SENTINEL_SEMGREP_BIN || 'semgrep'
    const semgrepConfig = process.env.SENTINEL_SEMGREP_CONFIG
    if (!semgrepConfig) {
      runs.push({tool:'semgrep',state:'blocked',exitCode:null,durationMs:0,summary:'Set SENTINEL_SEMGREP_CONFIG to a trusted local ruleset path; remote auto-config is intentionally disabled.'})
    } else {
      const r = await run(semgrep, ['scan','--json','--config',semgrepConfig,'--no-git-ignore',file], dir)
      const parsed = parseJsonArray(r.stdout)
      runs.push({tool:'semgrep',state:r.timedOut?'timed_out':r.error?'blocked':parsed===undefined?'failed':r.code===0||r.code===1?'completed':'failed',exitCode:r.code,durationMs:r.durationMs,summary:r.error || (r.stderr.slice(0,300) || `Semgrep exited ${r.code}`),findings:parsed})
    }
    const gitleaksBin = process.env.SENTINEL_GITLEAKS_BIN || 'gitleaks'
    const g = await run(gitleaksBin, ['detect','--no-git','--source',dir,'--report-format','json','--report-path','/dev/stdout','--exit-code','0'], dir)
    const gParsed = parseJsonArray(g.stdout)
    runs.push({tool:'gitleaks',state:g.timedOut?'timed_out':g.error?'blocked':gParsed===undefined?'failed':g.code===0?'completed':'failed',exitCode:g.code,durationMs:g.durationMs,summary:g.error || (g.stderr.slice(0,300) || `Gitleaks exited ${g.code}`),findings:gParsed})
    // OSV-Scanner can inspect manifests/lockfiles. For source-only inputs, explicitly mark not applicable.
    if (!/(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements(\.txt)?|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|pom\.xml|gradle\.lockfile)$/i.test(safeName)) {
      runs.push({tool:'osv-scanner',state:'blocked',exitCode:null,durationMs:0,summary:'Not applicable to this source file. Submit a supported dependency manifest or lockfile for dependency vulnerability scanning.'})
    } else {
      const osvBin = process.env.SENTINEL_OSV_SCANNER_BIN || 'osv-scanner'
      const o = await run(osvBin, ['scan','source','--format','json','--recursive',dir], dir)
      const oParsed = parseJsonArray(o.stdout)
      runs.push({tool:'osv-scanner',state:o.timedOut?'timed_out':o.error?'blocked':oParsed===undefined?'failed':o.code===0||o.code===1?'completed':'failed',exitCode:o.code,durationMs:o.durationMs,summary:o.error || (o.stderr.slice(0,300) || `OSV-Scanner exited ${o.code}`),findings:oParsed})
    }
    const trivyBin = process.env.SENTINEL_TRIVY_BIN || 'trivy'
    const t = await run(trivyBin, ['fs', '--format', 'json', '--quiet', dir], dir)
    const tParsed = parseJsonArray(t.stdout)
    runs.push({
      tool: 'trivy',
      state: t.timedOut ? 'timed_out' : t.error ? 'blocked' : tParsed === undefined ? 'failed' : t.code === 0 ? 'completed' : 'failed',
      exitCode: t.code,
      durationMs: t.durationMs,
      summary: t.error || (t.stderr.slice(0, 300) || `Trivy exited ${t.code}`),
      findings: tParsed,
    })
  } catch (e) {
    notes.push(`Toolchain setup failed: ${String(e).slice(0,240)}`)
  } finally { if (dir) await rm(dir, {recursive:true,force:true}).catch(()=>undefined) }
  const successful = runs.filter(x => x.state === 'completed').length
  const state = successful === runs.length && runs.length > 0 ? 'completed' : successful > 0 ? 'partial' : 'blocked'
  if (process.platform !== 'linux') notes.push('This platform uses the OS temporary directory; strict RAM-only handling requires a verified RAM-backed temporary root.')
  notes.push('Tool outputs are advisory and must be normalized/reviewed; scanner exit codes and formats vary by installed version.')
  notes.push('Missing tools, absent trusted Semgrep configuration, unsupported manifests, and execution failures are not interpreted as a clean result.')
  return {state,runs,notes}
}
