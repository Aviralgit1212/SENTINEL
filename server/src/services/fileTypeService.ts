import { fileTypeFromFile } from 'file-type'

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
  '.dll': 'dll'
}

export async function detectFileType(
  filePath: string,
  originalName: string,
) {
  const detected = await fileTypeFromFile(filePath)

  const lastDot = originalName.lastIndexOf('.')

  const extension =
    lastDot === -1
      ? ''
      : originalName
          .slice(lastDot)
          .toLowerCase()

  const expectedType = extensionMap[extension] ?? null

  const detectedExtension =
    detected?.ext?.toLowerCase() ?? null

  const extensionMismatch =
    Boolean(expectedType && detectedExtension) &&
    expectedType !== detectedExtension

  return {
    detectedExtension,
    detectedMime: detected?.mime ?? null,
    detectedType: detected?.ext ?? null,
    extensionMismatch,
  }
}