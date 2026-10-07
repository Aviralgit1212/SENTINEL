import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'

export function calculateSha256(
  filePath: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(filePath)

    stream.on('data', (chunk) => {
      hash.update(chunk)
    })

    stream.on('end', () => {
      resolve(hash.digest('hex'))
    })

    stream.on('error', reject)
  })
}