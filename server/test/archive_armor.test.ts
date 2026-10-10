import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { inspectZipArchive } from '../src/services/archiveArmor.js'
import { inspectArchiveRecursively } from '../src/services/recursiveArchive.js'
import { newTemporaryPath, cleanupTemporaryFile } from '../src/services/workspace.js'
import { deflateRawSync } from 'node:zlib'
import { runThreatScan, fuseVerdict } from '../src/services/threatService.js'
import { runArchiveWorker } from '../src/services/archiveWorker.js'

// Explicit test-only opt-in where bubblewrap is absent; production remains fail-closed.
process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER ??= '1'

interface ZipFixtureEntry {
  name: string
  data?: Buffer
  uncompressedData?: Buffer
  compressedSize?: number
  uncompressedSize?: number
  flags?: number
  method?: number
  unixMode?: number
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let i = 0; i < 8; i += 1) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function makeZip(entries: ZipFixtureEntry[]): Buffer {
  const localParts: Buffer[] = []
  const centralParts: Buffer[] = []
  let localOffset = 0

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8')
    const data = entry.data ?? Buffer.from('x')
    const rawData = entry.uncompressedData ?? data
    const compressedSize = entry.compressedSize ?? data.length
    const uncompressedSize = entry.uncompressedSize ?? rawData.length
    const crc = crc32(rawData)
    const flags = entry.flags ?? 0x0800
    const method = entry.method ?? 0

    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(flags, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(compressedSize, 18)
    local.writeUInt32LE(uncompressedSize, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    localParts.push(local, name, data)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(0x0314, 4) // Unix host, ZIP version 2.0
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(flags, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(compressedSize, 20)
    central.writeUInt32LE(uncompressedSize, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt16LE(0, 30)
    central.writeUInt16LE(0, 32)
    central.writeUInt16LE(0, 34)
    central.writeUInt16LE(0, 36)
    central.writeUInt32LE((((entry.unixMode ?? 0o100644) & 0xffff) << 16) >>> 0, 38)
    central.writeUInt32LE(localOffset, 42)
    centralParts.push(central, name)
    localOffset += local.length + name.length + data.length
  }

  const localBytes = Buffer.concat(localParts)
  const centralBytes = Buffer.concat(centralParts)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(centralBytes.length, 12)
  eocd.writeUInt32LE(localBytes.length, 16)
  eocd.writeUInt16LE(0, 20)
  return Buffer.concat([localBytes, centralBytes, eocd])
}

async function inspectFixture(bytes: Buffer) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-zip-fixture-'))
  const filePath = path.join(directory, 'fixture.zip')
  try {
    await fs.writeFile(filePath, bytes)
    return await inspectZipArchive(filePath)
  } finally {
    await fs.rm(directory, { recursive: true, force: true })
  }
}

test('archive armor validates a well-formed stored ZIP without decompressing it', async () => {
  const result = await inspectFixture(makeZip([{ name: 'docs/readme.txt', data: Buffer.from('hello') }]))
  assert.equal(result.state, 'completed_no_detections')
  assert.equal(result.entryCount, 1)
  assert.equal(result.totalUncompressedBytes, 5)
  assert.match(result.detail, /not decompressed or scanned/i)
})

test('archive armor detects path traversal entries', async () => {
  const result = await inspectFixture(makeZip([{ name: '../escape.txt' }]))
  assert.equal(result.state, 'finding')
  assert.ok(result.findings.some((finding) => finding.category === 'archive-path-traversal'))
})

test('archive armor detects high compression ratios and aggregate expansion bombs', async () => {
  const result = await inspectFixture(makeZip([{ name: 'payload.bin', data: Buffer.from('x'), compressedSize: 1, uncompressedSize: 100 * 1024 * 1024 }]))
  assert.equal(result.state, 'finding')
  assert.ok(result.findings.some((finding) => finding.category === 'archive-decompression-bomb'))
  assert.ok(result.findings.some((finding) => /aggregate expansion/i.test(finding.title)))
})

test('archive armor detects encrypted and symlink entries', async () => {
  const result = await inspectFixture(makeZip([
    { name: 'locked.bin', flags: 0x0801 },
    { name: 'link', unixMode: 0o120777 },
  ]))
  assert.ok(result.findings.some((finding) => finding.category === 'archive-encrypted-entry'))
  assert.ok(result.findings.some((finding) => finding.category === 'archive-symlink-entry'))
})

test('archive armor fails closed on truncated or malformed ZIP metadata', async () => {
  const valid = makeZip([{ name: 'a.txt' }])
  const truncated = await inspectFixture(valid.subarray(0, valid.length - 5))
  assert.equal(truncated.state, 'inconclusive')
  const malformed = Buffer.from(valid)
  malformed.writeUInt32LE(0x12345678, 0)
  const badHeader = await inspectFixture(malformed)
  assert.equal(badHeader.state, 'inconclusive')
})


async function inspectRecursiveFixture(bytes: Buffer) {
  const filePath = newTemporaryPath('fixture.zip')
  try {
    await fs.writeFile(filePath, bytes, { mode: 0o600 })
    return await inspectArchiveRecursively(filePath, 'fixture.zip')
  } finally {
    await cleanupTemporaryFile(filePath)
  }
}

test('recursive archive worker actually decompresses, CRC-verifies, and records each member', async () => {
  const payload = Buffer.from('SENTINEL recursive archive fixture')
  const compressed = deflateRawSync(payload)
  const result = await inspectRecursiveFixture(makeZip([{ name: 'folder/payload.txt', data: compressed, uncompressedData: payload, method: 8 }]))
  assert.equal(result.entriesVisited, 1)
  assert.equal(result.bytesExpanded, payload.length)
  assert.equal(result.entries[0]?.size, payload.length)
  assert.match(result.entries[0]?.detail ?? '', /CRC-32 verified/)
  // ClamAV is optional in unit-test environments; absence must remain a gap, not clean.
  assert.ok(['inconclusive', 'finding'].includes(result.state))
})

test('recursive archive worker rejects a CRC mismatch and does not treat the member as clean', async () => {
  const valid = makeZip([{ name: 'payload.txt', data: Buffer.from('real payload') }])
  const corrupted = Buffer.from(valid)
  const nameLength = corrupted.readUInt16LE(26)
  const dataLength = corrupted.readUInt32LE(18)
  const centralOffset = 30 + nameLength + dataLength
  corrupted.writeUInt32LE(0x12345678, centralOffset + 16)
  // Central-directory CRC is intentionally wrong, so decoded bytes must fail verification.
  const result = await inspectRecursiveFixture(corrupted)
  assert.ok(['finding', 'inconclusive'].includes(result.state))
  assert.ok(result.findings.some((finding) => /could not be safely inspected/i.test(finding.title)))
  assert.match(result.entries[0]?.detail ?? '', /CRC-32 mismatch/i)
})

test('recursive archive worker recursively inspects nested ZIP content within a shared budget', async () => {
  const inner = makeZip([{ name: 'inner.txt', data: Buffer.from('nested content') }])
  const outer = makeZip([{ name: 'nested.zip', data: inner }])
  const result = await inspectRecursiveFixture(outer)
  assert.ok(result.entries.some((entry) => entry.entryPath.includes('nested.zip!/inner.txt')))
  assert.ok(result.bytesExpanded >= inner.length + Buffer.byteLength('nested content'))
  assert.ok(result.entriesVisited >= 2)
})


test('threat pipeline exposes recursive member coverage and fails closed when ClamAV is unavailable', async () => {
  const filePath = newTemporaryPath('fixture.zip')
  const bytes = makeZip([{ name: 'document.txt', data: Buffer.from('ordinary text') }])
  try {
    await fs.writeFile(filePath, bytes, { mode: 0o600 })
    const scan = await runThreatScan({ filePath, originalName: 'fixture.zip', size: bytes.length })
    assert.ok(scan.coverage.some((entry) => entry.analyzer === 'zip-recursive-inspection'))
    const memberCoverage = scan.coverage.find((entry) => entry.analyzer.startsWith('archive-entry:'))
    assert.ok(memberCoverage)
    assert.ok(['unavailable', 'inconclusive', 'failed', 'timed_out'].includes(memberCoverage.state))
    assert.equal(fuseVerdict(scan.findings, scan.coverage).verdict, 'review_required')
  } finally {
    await cleanupTemporaryFile(filePath)
  }
})


test('archive armor rejects overlapping local-file data ranges', async () => {
  const valid = makeZip([
    { name: 'first.txt', data: Buffer.from('AAAA') },
    { name: 'second.txt', data: Buffer.from('BBBB') },
  ])
  const eocdOffset = valid.length - 22
  const centralOffset = valid.readUInt32LE(eocdOffset + 16)
  const firstCentralLength = 46 + valid.readUInt16LE(centralOffset + 28) + valid.readUInt16LE(centralOffset + 30) + valid.readUInt16LE(centralOffset + 32)
  const secondCentral = centralOffset + firstCentralLength
  valid.writeUInt32LE(0, secondCentral + 42)
  const result = await inspectFixture(valid)
  assert.equal(result.state, 'inconclusive')
  assert.match(result.detail, /overlap/i)
})

test('archive worker fails closed when strict namespace isolation is required but unavailable', async () => {
  const fsSync = await import('node:fs')
  const hasBwrap = ['/usr/bin/bwrap', '/bin/bwrap'].some((candidate) => { try { return fsSync.existsSync(candidate) } catch { return false } })
  if (hasBwrap) return
  const previous = process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER
  delete process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER
  try {
    await assert.rejects(() => runArchiveWorker({
      archivePath: '/dev/null', destination: '/dev/null/out', dataOffset: 0, compressedSize: 0,
      uncompressedSize: 0, crc32: 0, method: 0, remainingTotal: 0,
    }), /bubblewrap is unavailable/i)
  } finally {
    if (previous !== undefined) process.env.SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER = previous
  }
})

test('deterministic malformed ZIP mutation corpus never throws out of the metadata parser', async () => {
  const seed = makeZip([{ name: 'safe.txt', data: Buffer.from('stable payload') }])
  for (let index = 0; index < 100; index += 1) {
    const mutated = Buffer.from(seed)
    const offset = (index * 37 + 3) % mutated.length
    mutated[offset] = mutated[offset]! ^ (1 << (index % 8))
    const result = await inspectFixture(mutated)
    assert.ok(['finding', 'inconclusive', 'completed_no_detections'].includes(result.state))
  }
})
