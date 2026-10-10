import { createHash } from 'node:crypto'
import type { Finding } from '../types.js'

export interface CodeAuditResult {
  sha256: string
  bytes: number
  languageHint: string
  state: 'completed' | 'inconclusive'
  findings: Finding[]
  limitations: string[]
}

const RULES: Array<{ id: string; regex: RegExp; title: string; severity: Finding['severity']; description: string }> = [
  { id: 'possible-sql-injection', regex: /(?:query|execute)\s*\(\s*[`"'][^`"']*\$\{|(?:query|execute)\s*\(\s*[^,\n]+\s*\+\s*(?:req\.|request\.|params\.|query\.)/i, title: 'Possible SQL query construction from dynamic input', severity: 'high', description: 'Potentially unsafe dynamic query construction. Confirm parameterization in the relevant database driver.' },
  { id: 'shell-command-construction', regex: /(?:exec|execSync|spawn)\s*\(\s*(?:`[^`]*\$\{|[^,\n]+\+\s*(?:req\.|request\.|params\.|query\.))/i, title: 'Possible shell command construction from request data', severity: 'high', description: 'Potential command injection risk. Prefer argument arrays and avoid shell interpretation.' },
  { id: 'tls-verification-disabled', regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*['"]?\s*[:=]\s*['"]?0)/i, title: 'TLS certificate verification disabled', severity: 'high', description: 'Disabling certificate verification weakens server identity validation.' },
  { id: 'embedded-private-key', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, title: 'Private key material embedded in source', severity: 'critical', description: 'Private key material appears in the submitted source. Treat it as compromised and rotate it.' },
  { id: 'hardcoded-cloud-key', regex: /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk_live_[A-Za-z0-9]{16,})/, title: 'Possible hard-coded credential', severity: 'critical', description: 'A credential-like token appears in source. Validate safely and rotate if genuine.' },
  { id: 'unsafe-deserialization', regex: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:SafeLoader|CSafeLoader))/i, title: 'Potentially unsafe deserialization', severity: 'high', description: 'Deserializing untrusted data may execute code or instantiate unsafe objects.' },
]

export function auditSource(source: string, filename = 'source.txt'): CodeAuditResult {
  const bytes = Buffer.byteLength(source, 'utf8')
  const sha256 = createHash('sha256').update(source).digest('hex')
  const findings: Finding[] = []
  const lines = source.split(/\r?\n/)
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      if (!rule.regex.test(lines[i])) continue
      findings.push({ id: `code-${rule.id}-${i + 1}`, module: 'code', category: rule.id, title: rule.title, description: rule.description, severity: rule.severity, source: `sentinel-code-rule/${rule.id}`, location: `${filename}:${i + 1}`, evidence: lines[i].trim().slice(0, 180) })
      if (findings.length >= 200) break
    }
    if (findings.length >= 200) break
  }
  return { sha256, bytes, languageHint: inferLanguage(filename), state: source.trim() ? 'completed' : 'inconclusive', findings, limitations: ['Heuristic rules only; this is not a substitute for Semgrep, CodeQL, Gitleaks, or language-aware static analysis.', 'A clean result means no configured pattern matched, not that the source is secure.', 'The endpoint does not execute submitted code.'] }
}
function inferLanguage(filename: string): string {
  const ext = filename.toLowerCase().split('.').pop()
  const map: Record<string, string> = { ts: 'typescript', tsx: 'typescript-react', js: 'javascript', jsx: 'javascript-react', py: 'python', c: 'c', h: 'c-header', cpp: 'cpp', rs: 'rust', go: 'go', java: 'java', php: 'php', rb: 'ruby', sh: 'shell' }
  return ext ? map[ext] ?? 'unknown' : 'unknown'
}
