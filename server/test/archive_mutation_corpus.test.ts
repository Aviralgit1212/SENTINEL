import test from 'node:test'
import assert from 'node:assert/strict'
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
  const name = Buffer.from('corpus/readme.txt')
  const payload = Buffer.from('SENTINEL deterministic archive parser mutation seed')
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

test('ZIP metadata parser survives a deterministic 300-case mutation corpus without uncaught exceptions', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-zip-mutation-corpus-'))
  const file = path.join(dir, 'mutant.zip')
  const seed = makeSeedZip()
  let state = 0x51e71e1
  let parsed = 0
  let inconclusive = 0
  try {
    for (let i = 0; i < 300; i += 1) {
      const mutant = Buffer.from(seed)
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0
      const edits = 1 + (state % 4)
      for (let j = 0; j < edits; j += 1) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0
        const offset = state % mutant.length
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0
        mutant[offset] = mutant[offset]! ^ (1 << (state % 8))
      }
      await fs.writeFile(file, mutant)
      const result = await inspectZipArchive(file)
      assert.ok(['completed_no_detections', 'finding', 'inconclusive'].includes(result.state))
      assert.ok(result.detail.length <= 2000)
      assert.ok(Array.isArray(result.findings))
      parsed += 1
      if (result.state === 'inconclusive') inconclusive += 1
    }
    assert.equal(parsed, 300)
    assert.ok(inconclusive > 0, 'mutated structural fixtures should exercise safe rejection paths')
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})
