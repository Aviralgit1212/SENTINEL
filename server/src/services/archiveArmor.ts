import fs from 'node:fs/promises'
import type { AnalyzerState } from '../types.js'
import { sanitizeArchivePath } from './workspace.js'

const EOCD_SIGNATURE = 0x06054b50
const CENTRAL_SIGNATURE = 0x02014b50
const LOCAL_SIGNATURE = 0x04034b50
const MAX_EOCD_SEARCH = 22 + 65_535
const MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
const MAX_ENTRIES = 10_000
const MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
const MAX_COMPRESSION_RATIO = 10

export interface ArchiveArmorFinding {
  category: 'archive-path-traversal' | 'archive-decompression-bomb' | 'archive-encrypted-entry' | 'archive-symlink-entry' | 'archive-structure-anomaly'
  title: string
  description: string
  severity: 'medium' | 'high' | 'critical'
  evidence?: string
}

export interface ArchiveEntryMetadata {
  index: number
  name: string
  flags: number
  compressionMethod: number
  crc32: number
  compressedSize: number
  uncompressedSize: number
  dataOffset: number
  isDirectory: boolean
}

export interface ArchiveArmorResult {
  state: AnalyzerState
  detail: string
  format: 'zip' | 'zip64' | 'unknown'
  entryCount?: number
  totalCompressedBytes?: number
  totalUncompressedBytes?: number
  entries?: ArchiveEntryMetadata[]
  findings: ArchiveArmorFinding[]
}

async function readExact(handle: fs.FileHandle, length: number, position: number): Promise<Buffer> {
  if (!Number.isSafeInteger(length) || length < 0 || !Number.isSafeInteger(position) || position < 0) {
    throw new Error('Invalid archive read bounds')
  }
  const buffer = Buffer.alloc(length)
  let offset = 0
  while (offset < length) {
    const result = await handle.read(buffer, offset, length - offset, position + offset)
    if (result.bytesRead <= 0) throw new Error('Unexpected end of archive')
    offset += result.bytesRead
  }
  return buffer
}

function structuralGap(detail: string, format: 'zip' | 'zip64' | 'unknown' = 'zip'): ArchiveArmorResult {
  return { state: 'inconclusive', detail, format, findings: [{
    category: 'archive-structure-anomaly',
    title: 'Archive structure could not be fully validated',
    description: detail,
    severity: 'medium',
  }] }
}

/**
 * Inspect ZIP metadata without decompressing attacker-controlled streams.
 * This validates directory bounds, local-header references, portable paths,
 * encryption flags, symlink entries, declared expansion ratios, and aggregate
 * uncompressed size. It is not a full decompressor or recursive content scan.
 */
export async function inspectZipArchive(filePath: string): Promise<ArchiveArmorResult> {
  let handle: fs.FileHandle | undefined
  try {
    handle = await fs.open(filePath, 'r')
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size < 22) return structuralGap('File is too small to contain a valid ZIP end-of-central-directory record.')

    const tailLength = Math.min(stat.size, MAX_EOCD_SEARCH)
    const tailOffset = stat.size - tailLength
    const tail = await readExact(handle, tailLength, tailOffset)
    let eocdIndex = -1
    for (let i = tail.length - 22; i >= 0; i -= 1) {
      if (tail.readUInt32LE(i) !== EOCD_SIGNATURE) continue
      const commentLength = tail.readUInt16LE(i + 20)
      if (i + 22 + commentLength === tail.length) { eocdIndex = i; break }
    }
    if (eocdIndex < 0) return structuralGap('ZIP end-of-central-directory record is missing, truncated, or followed by unexplained trailing data.')

    const eocd = tail.subarray(eocdIndex)
    const diskNumber = eocd.readUInt16LE(4)
    const centralDisk = eocd.readUInt16LE(6)
    const entriesOnDisk = eocd.readUInt16LE(8)
    const entryCount = eocd.readUInt16LE(10)
    const centralSize = eocd.readUInt32LE(12)
    const centralOffset = eocd.readUInt32LE(16)
    const eocdAbsoluteOffset = tailOffset + eocdIndex

    if ([entriesOnDisk, entryCount].includes(0xffff) || [centralSize, centralOffset].includes(0xffffffff)) {
      return structuralGap('ZIP64 metadata is present or required, but ZIP64 directory parsing is not implemented.', 'zip64')
    }
    if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount) {
      return structuralGap('Multi-disk ZIP archives are unsupported and cannot be completely validated.')
    }
    if (entryCount > MAX_ENTRIES) return structuralGap(`Archive declares ${entryCount} entries; the inspection limit is ${MAX_ENTRIES}.`)
    if (centralSize > MAX_CENTRAL_DIRECTORY_BYTES) return structuralGap(`Central directory exceeds the ${MAX_CENTRAL_DIRECTORY_BYTES}-byte inspection limit.`)
    if (centralOffset + centralSize > eocdAbsoluteOffset || centralOffset + centralSize > stat.size) {
      return structuralGap('Central directory offsets extend beyond the archive or overlap the end record.')
    }
    if (centralOffset + centralSize !== eocdAbsoluteOffset) {
      return structuralGap('Unrecognized data exists between the central directory and end record; full structure validation is incomplete.')
    }

    const central = await readExact(handle, centralSize, centralOffset)
    const findings: ArchiveArmorFinding[] = []
    let cursor = 0
    let totalCompressed = 0
    let totalUncompressed = 0
    const seenNames = new Set<string>()
    const entries: ArchiveEntryMetadata[] = []
    const localExtents: Array<{ start: number; end: number; name: string }> = []

    for (let index = 0; index < entryCount; index += 1) {
      if (cursor + 46 > central.length || central.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) {
        return structuralGap(`Central directory entry ${index} is truncated or has an invalid signature.`)
      }
      const flags = central.readUInt16LE(cursor + 8)
      const compressionMethod = central.readUInt16LE(cursor + 10)
      const crc32 = central.readUInt32LE(cursor + 16)
      const compressedSize = central.readUInt32LE(cursor + 20)
      const uncompressedSize = central.readUInt32LE(cursor + 24)
      const nameLength = central.readUInt16LE(cursor + 28)
      const extraLength = central.readUInt16LE(cursor + 30)
      const commentLength = central.readUInt16LE(cursor + 32)
      const diskStart = central.readUInt16LE(cursor + 34)
      const externalAttributes = central.readUInt32LE(cursor + 38)
      const localHeaderOffset = central.readUInt32LE(cursor + 42)
      const recordLength = 46 + nameLength + extraLength + commentLength
      if (cursor + recordLength > central.length) return structuralGap(`Central directory entry ${index} exceeds directory bounds.`)
      if ([compressedSize, uncompressedSize, localHeaderOffset].includes(0xffffffff) || diskStart === 0xffff) {
        return structuralGap(`ZIP64 entry metadata at index ${index} is not supported.`, 'zip64')
      }
      if (diskStart !== 0) return structuralGap(`Entry ${index} references a different disk.`)

      const nameBytes = central.subarray(cursor + 46, cursor + 46 + nameLength)
      let entryName: string
      try {
        entryName = (flags & 0x0800) !== 0
          ? new TextDecoder('utf-8', { fatal: true }).decode(nameBytes)
          : nameBytes.toString('latin1')
      } catch {
        findings.push({
          category: 'archive-structure-anomaly', title: 'Invalid UTF-8 archive entry name',
          description: `Entry ${index} declares UTF-8 but its name is not valid UTF-8.`, severity: 'high', evidence: `entry #${index}`,
        })
        cursor += recordLength
        continue
      }
      const extraStart = cursor + 46 + nameLength
      const extra = central.subarray(extraStart, extraStart + extraLength)
      let extraCursor = 0
      while (extraCursor + 4 <= extra.length) {
        const extraId = extra.readUInt16LE(extraCursor)
        const extraDataLength = extra.readUInt16LE(extraCursor + 2)
        if (extraCursor + 4 + extraDataLength > extra.length) return structuralGap(`Malformed extra field in entry ${index}.`)
        if (extraId === 0x0001) return structuralGap(`ZIP64 extra field in entry ${index} is unsupported.`, 'zip64')
        if (extraId === 0x7075) {
          findings.push({ category: 'archive-structure-anomaly', title: 'Alternate Unicode archive path metadata', description: `Entry ${index} contains a Unicode Path extra field; alternate path interpretations require manual review.`, severity: 'medium', evidence: `entry #${index}` })
        }
        extraCursor += 4 + extraDataLength
      }
      if (extraCursor !== extra.length) return structuralGap(`Malformed trailing extra-field bytes in entry ${index}.`)

      if (entryName.includes('\0')) {
        findings.push({ category: 'archive-path-traversal', title: 'NUL byte in archive entry name', description: 'An archive entry name contains a NUL byte and has ambiguous interpretation across extraction libraries.', severity: 'high', evidence: `entry #${index}` })
      } else {
        try {
          sanitizeArchivePath('/sentinel-archive-root', entryName)
        } catch (error) {
          findings.push({ category: 'archive-path-traversal', title: 'Unsafe archive entry path', description: 'An archive entry attempts to use an absolute path or traverse outside the extraction root.', severity: 'high', evidence: entryName.slice(0, 160) })
        }
      }
      if (seenNames.has(entryName)) {
        findings.push({ category: 'archive-structure-anomaly', title: 'Duplicate archive entry name', description: 'Multiple central-directory records use the same entry name; extraction behavior may differ between tools.', severity: 'medium', evidence: entryName.slice(0, 160) })
      }
      seenNames.add(entryName)

      if ((flags & 0x0001) !== 0) {
        findings.push({ category: 'archive-encrypted-entry', title: 'Encrypted archive entry', description: 'Encrypted entries cannot be inspected by the current metadata-only pipeline.', severity: 'medium', evidence: entryName.slice(0, 160) })
      }
      const unixMode = (externalAttributes >>> 16) & 0xffff
      if ((unixMode & 0o170000) === 0o120000) {
        findings.push({ category: 'archive-symlink-entry', title: 'Symbolic link in archive', description: 'Archive symlinks can redirect extraction outside the intended directory unless the extractor explicitly prevents it.', severity: 'high', evidence: entryName.slice(0, 160) })
      }
      if (compressionMethod !== 0 && compressionMethod !== 8 && compressionMethod !== 12 && compressionMethod !== 14) {
        findings.push({ category: 'archive-structure-anomaly', title: 'Unsupported ZIP compression method', description: `Entry uses unsupported compression method ${compressionMethod}; its content cannot be verified by the current archive guard.`, severity: 'medium', evidence: entryName.slice(0, 160) })
      }

      totalCompressed += compressedSize
      totalUncompressed += uncompressedSize
      if (!Number.isSafeInteger(totalCompressed) || !Number.isSafeInteger(totalUncompressed)) return structuralGap('Archive size totals exceed safe integer bounds.')
      if (uncompressedSize > 0 && (compressedSize === 0 || uncompressedSize / Math.max(compressedSize, 1) > MAX_COMPRESSION_RATIO)) {
        findings.push({ category: 'archive-decompression-bomb', title: 'Extreme per-entry compression ratio', description: `Entry declares ${uncompressedSize} uncompressed bytes from ${compressedSize} compressed bytes, exceeding the ${MAX_COMPRESSION_RATIO}:1 policy limit.`, severity: 'high', evidence: entryName.slice(0, 160) })
      }

      // Verify each local header and data extent without decompressing content.
      if (localHeaderOffset + 30 > centralOffset) return structuralGap(`Local header for entry ${index} overlaps the central directory.`)
      const local = await readExact(handle, 30, localHeaderOffset)
      if (local.readUInt32LE(0) !== LOCAL_SIGNATURE) return structuralGap(`Entry ${index} points to an invalid local file header.`)
      const localFlags = local.readUInt16LE(6)
      const localMethod = local.readUInt16LE(8)
      const localCrc32 = local.readUInt32LE(14)
      const localCompressedSize = local.readUInt32LE(18)
      const localUncompressedSize = local.readUInt32LE(22)
      const localNameLength = local.readUInt16LE(26)
      const localExtraLength = local.readUInt16LE(28)
      if (localFlags !== flags || localMethod !== compressionMethod || localNameLength !== nameLength) {
        findings.push({ category: 'archive-structure-anomaly', title: 'Local and central ZIP headers disagree', description: `Entry ${index} has conflicting local and central header metadata.`, severity: 'high', evidence: entryName.slice(0, 160) })
      }
      // With general-purpose bit 3 clear, sizes and CRC must be present and
      // consistent in both headers. With bit 3 set, the local zeros are valid
      // because a data descriptor follows the compressed stream.
      if ((flags & 0x0008) === 0 && (localCrc32 !== crc32 || localCompressedSize !== compressedSize || localUncompressedSize !== uncompressedSize)) {
        findings.push({ category: 'archive-structure-anomaly', title: 'Local and central ZIP size/CRC metadata disagree', description: `Entry ${index} has conflicting CRC or size fields without a data-descriptor flag.`, severity: 'high', evidence: entryName.slice(0, 160) })
      }
      const localNameAndExtraLength = localNameLength + localExtraLength
      const dataOffset = localHeaderOffset + 30 + localNameAndExtraLength
      const dataEnd = dataOffset + compressedSize
      if (dataEnd > centralOffset || dataEnd > stat.size || dataEnd < dataOffset) return structuralGap(`Compressed data for entry ${index} overlaps the central directory or exceeds file bounds.`)
      localExtents.push({ start: localHeaderOffset, end: dataEnd, name: entryName })
      const localName = await readExact(handle, localNameLength, localHeaderOffset + 30)
      if (!localName.equals(nameBytes)) {
        findings.push({ category: 'archive-structure-anomaly', title: 'Local and central entry names disagree', description: `Entry ${index} uses different names in local and central ZIP headers.`, severity: 'high', evidence: entryName.slice(0, 160) })
      }

      entries.push({ index, name: entryName, flags, compressionMethod, crc32, compressedSize, uncompressedSize, dataOffset, isDirectory: entryName.endsWith('/') || entryName.endsWith('\\') })
      cursor += recordLength
    }

    if (cursor !== central.length) return structuralGap('Central directory contains unparsed trailing bytes.')
    localExtents.sort((a, b) => a.start - b.start || a.end - b.end)
    for (let index = 1; index < localExtents.length; index += 1) {
      const previous = localExtents[index - 1]!
      const current = localExtents[index]!
      if (current.start < previous.end) {
        return structuralGap(`Local file records overlap: ${previous.name.slice(0, 80)} intersects ${current.name.slice(0, 80)}. Ambiguous overlapping payload ranges are not decompressed.`)
      }
    }
    if (totalUncompressed > MAX_UNCOMPRESSED_BYTES) {
      findings.push({ category: 'archive-decompression-bomb', title: 'Archive exceeds aggregate expansion limit', description: `Entries declare ${totalUncompressed} uncompressed bytes, exceeding the ${MAX_UNCOMPRESSED_BYTES}-byte aggregate policy limit.`, severity: 'high' })
    }

    return {
      state: findings.length ? 'finding' : 'completed_no_detections',
      detail: findings.length
        ? `${entryCount} ZIP entries inspected; ${findings.length} archive armor finding(s). Nested content was not decompressed or scanned.`
        : `${entryCount} ZIP entries and local-header extents validated. Nested content was not decompressed or scanned.`,
      format: 'zip',
      entryCount,
      totalCompressedBytes: totalCompressed,
      totalUncompressedBytes: totalUncompressed,
      entries,
      findings,
    }
  } catch (error) {
    return structuralGap(`ZIP metadata parser failed safely: ${error instanceof Error ? error.message.slice(0, 240) : 'unknown error'}`)
  } finally {
    await handle?.close().catch(() => undefined)
  }
}
