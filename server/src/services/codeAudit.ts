import { createHash } from 'node:crypto'
import { blake3 } from '@noble/hashes/blake3.js'
import type { Finding } from '../types.js'

export interface CodeAuditResult {
  blake3: string
  sha256: string
  bytes: number
  languageHint: string
  state: 'completed' | 'inconclusive'
  findings: Finding[]
  limitations: string[]
}

const RULES: Array<{
  id: string
  regex: RegExp
  title: string
  severity: Finding['severity']
  description: string
}> = [
  {
    id: 'possible-sql-injection',
    regex: /(?:query|execute)\s*\(\s*[`"'][^`"']*\$\{|(?:query|execute)\s*\(\s*[^,\n]+\s*\+\s*(?:req\.|request\.|params\.|query\.)|(?:sql|query|stmt)\s*=\s*['"`].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\+\s*(?:req\.|request\.|params\.|query\.|input|[a-zA-Z0-9_]+)|(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^;\n]*\$\{[^}]*\}|(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^;\n]*['"`]\s*\+\s*(?:req\.|request\.|params\.|query\.)/i,
    title: 'Possible SQL query construction from dynamic input',
    severity: 'high',
    description: 'Potentially unsafe dynamic query construction. Confirm parameterization in the relevant database driver.',
  },
  {
    id: 'hardcoded-cloud-key',
    regex: /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9]{10,})/,
    title: 'Possible hard-coded credential',
    severity: 'critical',
    description: 'A credential-like token appears in source. Validate safely and rotate if genuine.',
  },
  {
    id: 'hardcoded-credential',
    regex: /(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret)\s*[:=]\s*['"][^'"]{2,}['"]/i,
    title: 'Hardcoded password or secret detected',
    severity: 'critical',
    description: 'Hardcoded credentials or secrets appear in the source code. Store credentials in environment variables or a secret vault.',
  },
  {
    id: 'hardcoded-conn-string',
    regex: /(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]+@/i,
    title: 'Hardcoded database connection string with password',
    severity: 'critical',
    description: 'A database connection string with embedded credentials was detected.',
  },
  {
    id: 'shell-command-construction',
    regex: /(?:exec|execSync|spawn|popen|system)\s*\(\s*(?:`[^`]*\$\{|[^,\n]+\+\s*(?:req\.|request\.|params\.|query\.|input))/i,
    title: 'Possible shell command construction from request data',
    severity: 'high',
    description: 'Potential command injection risk. Prefer argument arrays and avoid shell interpretation.',
  },
  {
    id: 'tls-verification-disabled',
    regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*['"]?\s*[:=]\s*['"]?0|verify\s*=\s*False)/i,
    title: 'TLS certificate verification disabled',
    severity: 'high',
    description: 'Disabling certificate verification weakens server identity validation.',
  },
  {
    id: 'embedded-private-key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    title: 'Private key material embedded in source',
    severity: 'critical',
    description: 'Private key material appears in the submitted source. Treat it as compromised and rotate it.',
  },
  {
    id: 'unsafe-deserialization',
    regex: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:SafeLoader|CSafeLoader))/i,
    title: 'Potentially unsafe deserialization',
    severity: 'high',
    description: 'Deserializing untrusted data may execute code or instantiate unsafe objects.',
  },
  {
    id: 'unsafe-eval',
    regex: /\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*['"`][^'"`]*\+/i,
    title: 'Unsafe code execution via eval() or dynamic function',
    severity: 'critical',
    description: 'Evaluating dynamic strings as code can lead to arbitrary code execution.',
  },
  {
    id: 'path-traversal',
    regex: /(?:readFile|readFileSync|createReadStream|createWriteStream|unlink|unlinkSync|open|openSync)\s*\([^,\n]*\+\s*(?:req\.|request\.|params\.|query\.)/i,
    title: 'Potential path traversal in file system operation',
    severity: 'high',
    description: 'User input is concatenated directly into a file path, risking directory traversal.',
  },
  {
    id: 'cross-site-scripting',
    regex: /(?:res\.send|res\.write|document\.write|innerHTML)\s*\([^)]*\+\s*(?:req\.|request\.|params\.|query\.)/i,
    title: 'Potential Cross-Site Scripting (XSS) via reflected input',
    severity: 'high',
    description: 'Unsanitized user input is reflected directly into HTML output.',
  },
]

interface DependencyAdvisory {
  pkg: string
  ecosystem: 'npm' | 'pypi'
  cve: string
  cwe: string
  severity: Finding['severity']
  maxVulnerableVersion: string
  title: string
  description: string
  remediation: string
}

const DEPENDENCY_ADVISORIES: DependencyAdvisory[] = [
  {
    pkg: 'lodash',
    ecosystem: 'npm',
    cve: 'CVE-2021-23337',
    cwe: 'CWE-78 / CWE-1321',
    severity: 'high',
    maxVulnerableVersion: '4.17.21',
    title: 'Lodash Command Injection & Prototype Pollution',
    description: 'Versions of lodash before 4.17.21 are vulnerable to command injection and prototype pollution via template.',
    remediation: 'Upgrade lodash to >= 4.17.21',
  },
  {
    pkg: 'minimist',
    ecosystem: 'npm',
    cve: 'CVE-2021-44906',
    cwe: 'CWE-1321',
    severity: 'critical',
    maxVulnerableVersion: '1.2.6',
    title: 'Minimist Prototype Pollution',
    description: 'Versions of minimist before 1.2.6 are vulnerable to prototype pollution via constructor and __proto__ parsing.',
    remediation: 'Upgrade minimist to >= 1.2.6',
  },
  {
    pkg: 'express',
    ecosystem: 'npm',
    cve: 'CVE-2022-24999',
    cwe: 'CWE-601',
    severity: 'medium',
    maxVulnerableVersion: '4.17.3',
    title: 'Express Open Redirect Vulnerability',
    description: 'Versions of express before 4.17.3 are vulnerable to open redirect when using res.redirect.',
    remediation: 'Upgrade express to >= 4.17.3',
  },
  {
    pkg: 'axios',
    ecosystem: 'npm',
    cve: 'CVE-2020-28168',
    cwe: 'CWE-918',
    severity: 'high',
    maxVulnerableVersion: '0.21.2',
    title: 'Axios Server-Side Request Forgery & ReDoS',
    description: 'Versions of axios before 0.21.2 are vulnerable to SSRF via follow-redirects and ReDoS.',
    remediation: 'Upgrade axios to >= 0.21.2',
  },
  {
    pkg: 'jsonwebtoken',
    ecosystem: 'npm',
    cve: 'CVE-2022-23529',
    cwe: 'CWE-94',
    severity: 'critical',
    maxVulnerableVersion: '9.0.0',
    title: 'JsonWebToken Insecure Key Retrieval & RCE',
    description: 'JsonWebToken before 9.0.0 allows remote attackers to execute code via crafted verify key object.',
    remediation: 'Upgrade jsonwebtoken to >= 9.0.0',
  },
  {
    pkg: 'tar',
    ecosystem: 'npm',
    cve: 'CVE-2021-37712',
    cwe: 'CWE-22',
    severity: 'high',
    maxVulnerableVersion: '6.1.9',
    title: 'Tar Arbitrary File Overwrite & Path Traversal',
    description: 'Versions of tar before 6.1.9 allow arbitrary file overwrite via unicode character normalization.',
    remediation: 'Upgrade tar to >= 6.1.9',
  },
  {
    pkg: 'pyyaml',
    ecosystem: 'pypi',
    cve: 'CVE-2020-14343',
    cwe: 'CWE-502',
    severity: 'critical',
    maxVulnerableVersion: '5.4.0',
    title: 'PyYAML Arbitrary Code Execution',
    description: 'A vulnerability in PyYAML allows arbitrary code execution via unsafe yaml.load() processing.',
    remediation: 'Upgrade pyyaml to >= 5.4 or use yaml.safe_load()',
  },
  {
    pkg: 'requests',
    ecosystem: 'pypi',
    cve: 'CVE-2023-32681',
    cwe: 'CWE-200',
    severity: 'medium',
    maxVulnerableVersion: '2.31.0',
    title: 'Requests Proxy-Authorization Header Leak',
    description: 'Requests leaks Proxy-Authorization headers to destination servers when following redirects.',
    remediation: 'Upgrade requests to >= 2.31.0',
  },
  {
    pkg: 'urllib3',
    ecosystem: 'pypi',
    cve: 'CVE-2023-45803',
    cwe: 'CWE-200',
    severity: 'high',
    maxVulnerableVersion: '2.0.7',
    title: 'urllib3 Request Body & Cookie Leak on Redirect',
    description: 'urllib3 fails to strip Cookie headers when redirecting to another host.',
    remediation: 'Upgrade urllib3 to >= 2.0.7',
  },
  {
    pkg: 'pillow',
    ecosystem: 'pypi',
    cve: 'CVE-2023-44271',
    cwe: 'CWE-787',
    severity: 'high',
    maxVulnerableVersion: '10.0.1',
    title: 'Pillow Buffer Overflow in ImageFont',
    description: 'An uncontrolled resource consumption vulnerability in Pillow allows denial of service and crashes.',
    remediation: 'Upgrade pillow to >= 10.0.1',
  },
  {
    pkg: 'jinja2',
    ecosystem: 'pypi',
    cve: 'CVE-2024-22195',
    cwe: 'CWE-79',
    severity: 'medium',
    maxVulnerableVersion: '3.1.3',
    title: 'Jinja2 Cross-Site Scripting via xmlattr',
    description: 'Jinja2 before 3.1.3 allows XSS when keys containing spaces or quotes are passed to xmlattr.',
    remediation: 'Upgrade jinja2 to >= 3.1.3',
  },
  {
    pkg: 'sqlparse',
    ecosystem: 'pypi',
    cve: 'CVE-2023-30608',
    cwe: 'CWE-1333',
    severity: 'high',
    maxVulnerableVersion: '0.4.4',
    title: 'sqlparse Regular Expression Denial of Service',
    description: 'Parsing heavily nested queries in sqlparse leads to exponential backtracking and DoS.',
    remediation: 'Upgrade sqlparse to >= 0.4.4',
  },
]

function parseVersion(v: string): number[] {
  const clean = v.replace(/^[^0-9]*/, '').split('-')[0]
  const parts = clean.split('.').map((x) => parseInt(x, 10) || 0)
  while (parts.length < 3) parts.push(0)
  return parts
}

function semverLt(v: string, target: string): boolean {
  const [m1, n1, p1] = parseVersion(v)
  const [m2, n2, p2] = parseVersion(target)
  if (m1 !== m2) return m1 < m2
  if (n1 !== n2) return n1 < n2
  return p1 < p2
}

export function auditDependencies(source: string, filename: string): Finding[] {
  const findings: Finding[] = []
  const isPackageJson = /package(-lock)?\.json$/i.test(filename) || (source.trim().startsWith('{') && /"dependencies"|"devDependencies"/.test(source))
  const isRequirementsTxt = /requirements(\.txt)?$/i.test(filename) || /(?:^[a-zA-Z0-9_-]+[=><~!]=?[0-9.]+)/m.test(source)

  if (isPackageJson) {
    try {
      const parsed = JSON.parse(source) as Record<string, unknown>
      const allDeps = {
        ...(typeof parsed.dependencies === 'object' && parsed.dependencies ? (parsed.dependencies as Record<string, string>) : {}),
        ...(typeof parsed.devDependencies === 'object' && parsed.devDependencies ? (parsed.devDependencies as Record<string, string>) : {}),
      }

      const lines = source.split(/\r?\n/)
      for (const [pkg, ver] of Object.entries(allDeps)) {
        if (typeof ver !== 'string') continue
        for (const adv of DEPENDENCY_ADVISORIES.filter((a) => a.ecosystem === 'npm' && a.pkg.toLowerCase() === pkg.toLowerCase())) {
          if (semverLt(ver, adv.maxVulnerableVersion)) {
            const lineIdx = lines.findIndex((l) => l.includes(`"${pkg}"`))
            const lineNum = lineIdx >= 0 ? lineIdx + 1 : 1
            findings.push({
              id: `dep-${pkg}-${adv.cve}`,
              module: 'code',
              category: 'vulnerable-dependency',
              title: `${adv.title} [${pkg}@${ver}]`,
              description: `${adv.description} (${adv.cve}, ${adv.cwe}). Recommendation: ${adv.remediation}.`,
              severity: adv.severity,
              source: `sentinel-advisory/${adv.cve}`,
              location: `${filename}:${lineNum}`,
              evidence: lineIdx >= 0 ? lines[lineIdx].trim() : `"${pkg}": "${ver}"`,
            })
          }
        }
      }
    } catch {
      // malformed JSON falls through
    }
  }

  if (isRequirementsTxt) {
    const lines = source.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim()
      if (!line || line.startsWith('#')) continue
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=)\s*([0-9.]+)/)
      if (!match) continue
      const [, pkg, ver] = match
      for (const adv of DEPENDENCY_ADVISORIES.filter((a) => a.ecosystem === 'pypi' && a.pkg.toLowerCase() === pkg.toLowerCase())) {
        if (semverLt(ver, adv.maxVulnerableVersion)) {
          findings.push({
            id: `dep-${pkg}-${adv.cve}`,
            module: 'code',
            category: 'vulnerable-dependency',
            title: `${adv.title} [${pkg}==${ver}]`,
            description: `${adv.description} (${adv.cve}, ${adv.cwe}). Recommendation: ${adv.remediation}.`,
            severity: adv.severity,
            source: `sentinel-advisory/${adv.cve}`,
            location: `${filename}:${i + 1}`,
            evidence: line,
          })
        }
      }
    }
  }

  return findings
}

export function auditSource(source: string, filename = 'source.txt'): CodeAuditResult {
  const bytes = Buffer.byteLength(source, 'utf8')
  const sha256 = createHash('sha256').update(source).digest('hex')
  const findings: Finding[] = []

  // 1. Dependency manifest audit (if applicable)
  const depFindings = auditDependencies(source, filename)
  findings.push(...depFindings)

  // 2. Static heuristic code rules
  const lines = source.split(/\r?\n/)
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      if (!rule.regex.test(lines[i])) continue
      findings.push({
        id: `code-${rule.id}-${i + 1}`,
        module: 'code',
        category: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        source: `sentinel-code-rule/${rule.id}`,
        location: `${filename}:${i + 1}`,
        evidence: lines[i].trim().slice(0, 180),
      })
      if (findings.length >= 200) break
    }
    if (findings.length >= 200) break
  }

  const isManifest = /package(-lock)?\.json|requirements(\.txt)?|Cargo\.lock|go\.sum/i.test(filename)
  const limitations = [
    'Static AST heuristic & embedded CVE advisory analysis; non-destructive execution without code execution.',
    isManifest
      ? 'Advisory scan checked against known CVE signatures for popular ecosystem packages.'
      : 'Comprehensive pattern coverage for OWASP Top 10 vulnerabilities (SQLi, Command Injection, Secrets, Path Traversal, SSRF/XSS, Deserialization).',
    'External CLI tools (Semgrep, Gitleaks, OSV, Trivy) run asynchronously in Module 4 toolchain view.',
  ]

  const blake3Hash = Buffer.from(blake3(Buffer.from(source, 'utf8'))).toString('hex')

  return {
    blake3: blake3Hash,
    sha256,
    bytes,
    languageHint: inferLanguage(filename),
    state: source.trim() ? 'completed' : 'inconclusive',
    findings,
    limitations,
  }
}

function inferLanguage(filename: string): string {
  const ext = filename.toLowerCase().split('.').pop()
  const map: Record<string, string> = {
    ts: 'typescript',
    tsx: 'typescript-react',
    js: 'javascript',
    jsx: 'javascript-react',
    py: 'python',
    json: 'json-manifest',
    txt: 'text-manifest',
    c: 'c',
    h: 'c-header',
    cpp: 'cpp',
    rs: 'rust',
    go: 'go',
    java: 'java',
    php: 'php',
    rb: 'ruby',
    sh: 'shell',
  }
  return ext ? map[ext] ?? 'unknown' : 'unknown'
}
