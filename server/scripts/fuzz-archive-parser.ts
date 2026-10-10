import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { inspectZipArchive } from '../src/services/archiveArmor.js'

function crc32(data: Buffer): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function makeSeedZip(): Buffer {
  const name = Buffer.from('fuzz/seed.txt')
  const payload = Buffer.from('SENTINEL archive parser fuzz seed; all content is synthetic.')
  const crc = crc32(payload)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6)
  local.writeUInt32LE(crc, 14); local.writeUInt32LE(payload.length, 18); local.writeUInt32LE(payload.length, 22); local.writeUInt16LE(name.length, 26)
  const localRecord = Buffer.concat([local, name, payload])
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(0x0314, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x0800, 8)
  central.writeUInt32LE(crc, 16); central.writeUInt32LE(payload.length, 20); central.writeUInt32LE(payload.length, 24); central.writeUInt16LE(name.length, 28)
  central.writeUInt32LE((0o100644 << 16) >>> 0, 38)
  const centralRecord = Buffer.concat([central, name])
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10)
  end.writeUInt32LE(centralRecord.length, 12); end.writeUInt32LE(localRecord.length, 16)
  return Buffer.concat([localRecord, centralRecord, end])
}

function mutate(seed: Buffer, iteration: number, next: () => number): Buffer {
  const mode = iteration % 6
  if (mode === 0) return seed.subarray(0, next() % (seed.length + 1))
  const mutant = Buffer.from(seed)
  if (mode === 1) {
    const offset = next() % mutant.length
    mutant[offset] = mutant[offset]! ^ (1 << (next() % 8))
  } else if (mode === 2) {
    const offset = next() % mutant.length
    const count = Math.min(1 + next() % 12, mutant.length - offset)
    mutant.fill(next() & 0xff, offset, offset + count)
  } else if (mode === 3) {
    // Target metadata fields and signatures more often than arbitrary payload bytes.
    const offsets = [0, 4, 6, 14, 18, 22, 26, 28, 30, 32, 34, 36, 38, 42, mutant.length - 22, mutant.length - 18, mutant.length - 14, mutant.length - 10, mutant.length - 6]
    const offset = offsets[next() % offsets.length]!
    if (offset >= 0 && offset < mutant.length) mutant[offset] = mutant[offset]! ^ (1 << (next() % 8))
  } else if (mode === 4) {
    const offset = next() % mutant.length
    const inserted = Buffer.alloc(1 + next() % 8, next() & 0xff)
    return Buffer.concat([mutant.subarray(0, offset), inserted, mutant.subarray(offset)])
  } else {
    const offset = next() % mutant.length
    const count = 1 + next() % Math.min(16, mutant.length - offset)
    return Buffer.concat([mutant.subarray(0, offset), mutant.subarray(offset + count)])
  }
  return mutant
}

const iterations = Number(process.env.SENTINEL_FUZZ_ITERATIONS ?? 5000)
if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 1_000_000) {
  throw new Error('SENTINEL_FUZZ_ITERATIONS must be an integer from 1 to 1000000.')
}
const seedValue = Number(process.env.SENTINEL_FUZZ_SEED ?? 0x5e471e1)
if (!Number.isSafeInteger(seedValue) || seedValue < 0 || seedValue > 0xffffffff) {
  throw new Error('SENTINEL_FUZZ_SEED must be an unsigned 32-bit integer.')
}
let state = seedValue >>> 0
const next = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state }
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-archive-fuzz-'))
const input = path.join(directory, 'candidate.zip')
const seed = makeSeedZip()
let accepted = 0
let rejected = 0
let errors = 0
const started = Date.now()
try {
  for (let i = 0; i < iterations; i += 1) {
    const candidate = mutate(seed, i, next)
    await fs.writeFile(input, candidate, { mode: 0o600 })
    try {
      const result = await inspectZipArchive(input)
      if (!['completed_no_detections', 'finding', 'inconclusive'].includes(result.state)) {
        throw new Error(`Undocumented parser state: ${String(result.state)}`)
      }
      if (result.detail.length > 2000 || result.findings.length > 10_000) {
        throw new Error('Parser output exceeded diagnostic/result bounds.')
      }
      if (result.state === 'inconclusive') rejected += 1
      else accepted += 1
    } catch (error) {
      errors += 1
      const artifactDir = process.env.SENTINEL_FUZZ_ARTIFACT_DIR
      if (artifactDir) {
        await fs.mkdir(artifactDir, { recursive: true, mode: 0o700 })
        await fs.writeFile(path.join(artifactDir, `crash-seed-${seedValue.toString(16)}-iteration-${i}.zip`), candidate, { mode: 0o600 })
      }
      throw new Error(`Parser failure at iteration=${i}, seed=${seedValue}, bytes=${candidate.length}; ${String(error)}`)
    }
  }
} finally {
  await fs.rm(directory, { recursive: true, force: true })
}
console.log(JSON.stringify({ harness: 'sentinel-zip-mutation-fuzz', iterations, seed: seedValue, accepted, safelyRejected: rejected, uncaughtFailures: errors, elapsedMs: Date.now() - started }, null, 2))
if (errors !== 0) process.exitCode = 1
