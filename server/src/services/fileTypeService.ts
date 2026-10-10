
import { readFile, stat } from 'node:fs/promises'
import { fileTypeFromFile } from 'file-type'

const MAX_JSON_DETECTION_SIZE = 10 * 1024 * 1024

const extensionMap: Record<string, string> = {
  '.pdf': 'pdf',
  '.docx': 'docx',
  '.doc': 'doc',
  '.xlsx': 'xlsx',
  '.xls': 'xls',
  '.pptx': 'pptx',
  '.ppt': 'ppt',
  '.png': 'png',
  '.jpg': 'jpg',
  '.jpeg': 'jpg',
  '.gif': 'gif',
  '.webp': 'webp',
  '.zip': 'zip',
  '.json': 'json',
  '.txt': 'txt',
  '.html': 'html',
  '.htm': 'html',
  '.svg': 'svg',
  '.exe': 'exe',
  '.dll': 'dll',
}

/**
 * Detect valid JSON in a file that has no recognized
 * binary signature.
 *
 * This function never executes file contents and makes
 * no network requests.
 *
 * The size limit matches the JSON analyzer's expected
 * input limit. Oversized files are not parsed here.
 */
async function isValidJsonFile(
  filePath: string,
  originalExtension: string,
): Promise<boolean> {
  try {
    const fileStats = await stat(filePath)

    if (
      !fileStats.isFile() ||
      fileStats.size === 0 ||
      fileStats.size > MAX_JSON_DETECTION_SIZE
    ) {
      return false
    }

    const buffer = await readFile(filePath)

    // JSON text should be UTF-8. A BOM, if present,
    // is removed before JSON.parse().
    let content = buffer.toString('utf8')

    if (content.startsWith('\uFEFF')) {
      content = content.slice(1)
    }

    // Avoid classifying arbitrary text as JSON merely
    // because it contains ordinary words.
    //
    // A .json file may contain any valid JSON value,
    // including strings, numbers, booleans, and null.
    // For other extensions, only attempt content-based
    // detection for object or array documents.
    const trimmed = content.trim()

    if (!trimmed) {
      return false
    }

    if (
      originalExtension !== '.json' &&
      !trimmed.startsWith('{') &&
      !trimmed.startsWith('[')
    ) {
      return false
    }

    JSON.parse(content)
    return true
  } catch {
    // Invalid JSON, unreadable files, and decoding or
    // parsing failures must not crash file detection.
    return false
  }
}

export async function detectFileType(
  filePath: string,
  originalName: string,
) {
  // First priority remains signature-based detection.
  // This preserves detection for supported binary formats.
  const detected = await fileTypeFromFile(filePath)

  const lastDot = originalName.lastIndexOf('.')

  const extension =
    lastDot === -1
      ? ''
      : originalName.slice(lastDot).toLowerCase()

  const expectedType = extensionMap[extension] ?? null

  let detectedExtension =
    detected?.ext?.toLowerCase() ?? null

  let detectedMime =
    detected?.mime ?? null

  // Only fall back to JSON detection when the signature
  // detector did not identify the file.
  //
  // A recognized binary file renamed to .json will retain
  // its detected binary type rather than being called JSON.
  if (
    detectedExtension === null &&
    await isValidJsonFile(filePath, extension)
  ) {
    detectedExtension = 'json'
    detectedMime = 'application/json'
  }

  const extensionMismatch =
    Boolean(expectedType && detectedExtension) &&
    expectedType !== detectedExtension

  return {
    detectedExtension,
    detectedMime,
    detectedType: detectedExtension,
    extensionMismatch,
  }
}