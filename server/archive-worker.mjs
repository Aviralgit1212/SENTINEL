#!/usr/bin/env node
// Minimal trusted decompression worker. It receives a single JSON job on stdin
// and emits exactly one JSON result on stdout. Do not import application code.
import fs from 'node:fs'
import { createReadStream, createWriteStream } from 'node:fs'
import { createInflateRaw } from 'node:zlib'
import { Readable } from 'node:stream'
import { once } from 'node:events'
import path from 'node:path'

const MAX_JOB_BYTES = 16 * 1024
const MAX_ENTRY_OUTPUT = 10 * 1024 * 1024
const MAX_RATIO = 10

function crcTable() {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n += 1) {
    let c = n
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
    table[n] = c >>> 0
  }
  return table
}
const CRC_TABLE = crcTable()
function updateCrc(crc, bytes) {
  let c = crc >>> 0
  for (const byte of bytes) c = (CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8)) >>> 0
  return c >>> 0
}
async function readJob() {
  const chunks = []
  let size = 0
  for await (const chunk of process.stdin) {
    size += chunk.length
    if (size > MAX_JOB_BYTES) throw new Error('worker job exceeds input limit')
    chunks.push(chunk)
  }
  const job = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (!job || typeof job !== 'object' || Array.isArray(job)) throw new Error('invalid worker job')
  if (typeof job.archivePath !== 'string' || !path.isAbsolute(job.archivePath)) throw new Error('invalid archive path')
  if (typeof job.destination !== 'string' || !path.isAbsolute(job.destination)) throw new Error('invalid destination path')
  if (![0, 8].includes(job.method)) throw new Error('unsupported compression method')
  for (const field of ['dataOffset', 'compressedSize', 'uncompressedSize', 'crc32', 'remainingTotal']) {
    if (!Number.isSafeInteger(job[field]) || job[field] < 0) throw new Error(`invalid ${field}`)
  }
  if (job.uncompressedSize > MAX_ENTRY_OUTPUT || job.uncompressedSize > job.remainingTotal) throw new Error('declared output exceeds worker budget')
  if (job.uncompressedSize > 0 && (job.compressedSize === 0 || job.uncompressedSize / job.compressedSize > MAX_RATIO)) throw new Error('declared compression ratio exceeds policy')
  const archiveStat = fs.statSync(job.archivePath)
  if (!archiveStat.isFile() || job.dataOffset + job.compressedSize > archiveStat.size) throw new Error('compressed data range exceeds archive bounds')
  const destParent = fs.realpathSync(path.dirname(job.destination))
  if (destParent !== path.dirname(job.destination)) throw new Error('destination parent must be canonical')
  return job
}

async function main() {
  let output
  try {
    const job = await readJob()
    const input = job.compressedSize === 0
      ? Readable.from([])
      : createReadStream(job.archivePath, { start: job.dataOffset, end: job.dataOffset + job.compressedSize - 1 })
    const decoder = job.method === 8 ? createInflateRaw() : null
    const source = decoder ? input.pipe(decoder) : input
    output = createWriteStream(job.destination, { flags: 'wx', mode: 0o600 })
    let bytes = 0
    let crc = 0xffffffff
    for await (const value of source) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value)
      bytes += chunk.length
      if (bytes > MAX_ENTRY_OUTPUT || bytes > job.remainingTotal) throw new Error('actual output exceeded worker budget')
      if (job.compressedSize === 0 ? bytes > 0 : bytes / job.compressedSize > MAX_RATIO) throw new Error('actual compression ratio exceeds policy')
      crc = updateCrc(crc, chunk)
      if (!output.write(chunk)) await once(output, 'drain')
    }
    output.end()
    await once(output, 'close')
    const actualCrc = (crc ^ 0xffffffff) >>> 0
    if (bytes !== job.uncompressedSize) throw new Error(`decoded size mismatch: expected ${job.uncompressedSize}, got ${bytes}`)
    if (actualCrc !== job.crc32) throw new Error('CRC-32 mismatch after decompression')
    process.stdout.write(JSON.stringify({ ok: true, bytes, crc32: actualCrc }))
  } catch (error) {
    output?.destroy()
    process.stdout.write(JSON.stringify({ ok: false, error: String(error?.message ?? error).slice(0, 300) }))
    process.exitCode = 1
  }
}
await main()
