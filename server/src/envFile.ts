// Minimal .env loader: parses the repo-root .env this project ships with
// (simple KEY=VALUE pairs, # comments, optional quotes) and applies values
// that are not already present in process.env. No dependency needed.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export function loadEnvFile(explicitPath?: string): void {
  const here = path.dirname(fileURLToPath(import.meta.url))
  // src/ -> server/ -> repo root
  const rootEnv = explicitPath ?? path.resolve(here, '..', '..', '.env')
  let text: string
  try {
    text = readFileSync(rootEnv, 'utf8')
  } catch {
    return
  }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue
    let value = line.slice(eq + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    if (process.env[key] === undefined) process.env[key] = value
  }
}
