import { randomUUID } from 'node:crypto'
import type { PrivacyResult } from '../types.js'

export type BoundEntity = PrivacyResult['entities'][number]
interface ScanBinding {
  scanId: string
  sha256: string
  filename: string
  expiresAt: number
  entities: BoundEntity[]
}

const bindings = new Map<string, ScanBinding>()
const TTL_MS = 30 * 60 * 1000
const MAX_BINDINGS = 500

function prune(now = Date.now()): void {
  for (const [id, binding] of bindings) {
    if (binding.expiresAt <= now) bindings.delete(id)
  }
  while (bindings.size > MAX_BINDINGS) {
    const oldest = bindings.keys().next().value as string | undefined
    if (!oldest) break
    bindings.delete(oldest)
  }
}

export function registerPrivacyScanBinding(input: {
  scanId: string
  sha256: string
  filename: string
  entities: BoundEntity[]
}): void {
  prune()
  bindings.set(input.scanId, {
    ...input,
    entities: input.entities.map((entity) => ({ ...entity })),
    expiresAt: Date.now() + TTL_MS,
  })
  prune()
}

export function getPrivacyScanBinding(scanId: string): Readonly<ScanBinding> | undefined {
  prune()
  const binding = bindings.get(scanId)
  return binding ? { ...binding, entities: binding.entities.map((entity) => ({ ...entity })) } : undefined
}

/** Only permit redaction targets that were actually emitted by this scan. */
export function assertEntitiesBelongToScan(scanId: string, entities: BoundEntity[]): ScanBinding {
  const binding = getPrivacyScanBinding(scanId)
  if (!binding) throw new Error('Scan binding is missing or expired; run a fresh privacy scan.')

  const available = new Map<string, number>()
  for (const entity of binding.entities) {
    const key = entityKey(entity)
    available.set(key, (available.get(key) ?? 0) + 1)
  }
  for (const entity of entities) {
    const key = entityKey(entity)
    const count = available.get(key) ?? 0
    if (count < 1) throw new Error('Redaction target does not belong to the selected privacy scan.')
    available.set(key, count - 1)
  }
  return binding as ScanBinding
}

function entityKey(entity: BoundEntity): string {
  // JSON encoding preserves exact text and offsets without ambiguous delimiters.
  return JSON.stringify([entity.entity_type, entity.text, entity.start, entity.end, entity.page ?? null])
}
