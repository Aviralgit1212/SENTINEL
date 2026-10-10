/**
 * SENTINEL Sovereign Core — ephemeral working vault.
 *
 * On Linux, strict RAM-vault mode is the default: /dev/shm must be a real
 * tmpfs mount and must be writable. There is deliberately no silent fallback
 * to os.tmpdir(), because that directory may reside on persistent storage.
 *
 * Disk-backed temporary storage is an explicit development-only opt-in via
 * SENTINEL_ALLOW_DISK_TEMP=1. It must never be described as RAM-only mode.
 */

import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'
import { randomBytes } from 'node:crypto'
import { newId } from '../db.js'

let vaultDir: string | undefined

function isShmTmpfs(): boolean {
  if (process.platform !== 'linux') return false
  try {
    const mounts = fs.readFileSync('/proc/mounts', 'utf8')
    return mounts.split('\n').some((line) => {
      const fields = line.split(' ')
      const mountPoint = fields[1]?.replace(/\\040/g, ' ')
      const fsType = fields[2]
      return mountPoint === '/dev/shm' && fsType === 'tmpfs'
    })
  } catch {
    return false
  }
}

function prepareDirectory(directory: string): string {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  const stat = fs.lstatSync(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`SENTINEL vault path must be a real directory: ${directory}`)
  }
  // Keep raw upload files private to the local user on POSIX platforms.
  if (process.platform !== 'win32') {
    fs.chmodSync(directory, 0o700)
  }
  fs.accessSync(directory, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK)
  return fs.realpathSync(directory)
}

function processVault(root: string): string {
  // Each server process gets an isolated directory so one instance can never
  // reap another instance's active upload or redacted derivative.
  const entries = fs.readdirSync(root, { withFileTypes: true })
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const match = /^(\d+)-[a-f0-9-]+$/.exec(entry.name)
    if (!match) continue
    const pid = Number(match[1])
    if (!Number.isSafeInteger(pid) || pid <= 0 || pid === process.pid) continue
    try {
      process.kill(pid, 0) // success or EPERM means a process may still own it
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') {
        fs.rmSync(path.join(root, entry.name), { recursive: true, force: true })
      }
    }
  }

  const ownDir = prepareDirectory(path.join(root, `${process.pid}-${randomBytes(12).toString('hex')}`))
  process.once('exit', () => {
    try { fs.rmSync(ownDir, { recursive: true, force: true }) } catch { /* best effort on process exit */ }
  })
  return ownDir
}

function resolveVaultDir(): string {
  if (vaultDir) return vaultDir

  if (process.platform === 'linux' && isShmTmpfs()) {
    const root = prepareDirectory('/dev/shm/.sentinel-vault')
    if (!root.startsWith('/dev/shm/')) {
      throw new Error('SENTINEL RAM vault resolved outside /dev/shm; refusing file intake.')
    }
    vaultDir = processVault(root)
    return vaultDir
  }

  if (process.env.SENTINEL_ALLOW_DISK_TEMP === '1') {
    const root = prepareDirectory(path.join(os.tmpdir(), '.sentinel-vault'))
    console.warn('[sentinel] WARNING: explicit disk-backed temporary mode enabled; RAM-only guarantee is disabled.')
    vaultDir = processVault(root)
    return vaultDir
  }

  // Cross-platform support for macOS / Windows
  if (process.platform !== 'linux') {
    const root = prepareDirectory(path.join(os.tmpdir(), '.sentinel-vault'))
    console.info(`[sentinel] Host is ${process.platform}: using private temporary directory under os.tmpdir(); strict Linux /dev/shm tmpfs is unavailable.`)
    vaultDir = processVault(root)
    return vaultDir
  }

  throw new Error(
    'SENTINEL strict RAM vault unavailable: /dev/shm is not a writable tmpfs. ' +
    'File intake is disabled. For development only, explicitly set SENTINEL_ALLOW_DISK_TEMP=1.',
  )
}

export function getVaultStorageTier(): 'ram' | 'secure_temp' {
  if (process.platform === 'linux' && isShmTmpfs() && process.env.SENTINEL_ALLOW_DISK_TEMP !== '1') {
    return 'ram'
  }
  return 'secure_temp'
}
export function uploadsDirectory(): string {
  return resolveVaultDir()
}

export function newTemporaryPath(originalName: string): string {
  const safeSuffix = path.extname(originalName).slice(0, 12).replace(/[^a-zA-Z0-9._-]/g, '')
  return path.join(resolveVaultDir(), `${newId()}${safeSuffix}`)
}

export function isVaultPath(filePath: string): boolean {
  const vault = path.resolve(resolveVaultDir())
  const candidate = path.resolve(filePath)
  return candidate.startsWith(`${vault}${path.sep}`)
}

export function sanitizeArchivePath(destinationDir: string, relativePath: string): string {
  // Archive names are attacker-controlled and may be produced on a different
  // operating system. Normalize both slash styles before applying host-path
  // resolution so Windows drive/UNC and backslash traversal names are rejected
  // consistently even when the scanner itself runs on Linux.
  if (typeof relativePath !== 'string' || relativePath.length === 0 || relativePath.includes('\0')) {
    throw new Error('Invalid archive entry path')
  }
  const portable = relativePath.replace(/\\/g, '/')
  if (portable.startsWith('/') || /^[a-zA-Z]:/.test(portable) || portable.startsWith('//')) {
    throw new Error(`Absolute archive path blocked: ${relativePath}`)
  }
  const root = path.resolve(destinationDir)
  const resolved = path.resolve(root, ...portable.split('/'))
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Path traversal attempt blocked: ${relativePath}`)
  }
  return resolved
}

/**
 * Unlink an ephemeral file. Overwriting is intentionally not called secure
 * erasure: filesystem and memory semantics do not guarantee physical wiping.
 */
export async function cleanupTemporaryFile(filePath: string): Promise<void> {
  try {
    if (!isVaultPath(filePath)) {
      console.error('[sentinel] refused to clean a path outside the configured vault')
      return
    }
    const stat = await fs.promises.lstat(filePath)
    if (stat.isFile() || stat.isSymbolicLink()) await fs.promises.unlink(filePath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.warn('[sentinel] temporary-file cleanup failed')
    }
  }
}

/** Best-effort cleanup of stale files left by a prior crashed process. */
export async function reapStaleVaultFiles(maxAgeMs = 15 * 60 * 1000): Promise<number> {
  const directory = resolveVaultDir()
  const now = Date.now()
  let removed = 0
  for (const entry of await fs.promises.readdir(directory, { withFileTypes: true })) {
    if (!entry.isFile()) continue
    const fullPath = path.join(directory, entry.name)
    try {
      const stat = await fs.promises.stat(fullPath)
      if (now - stat.mtimeMs >= maxAgeMs) {
        await fs.promises.unlink(fullPath)
        removed += 1
      }
    } catch {
      // Another request may have removed it; cleanup is best-effort.
    }
  }
  return removed
}

/** Create a private, unique directory under the active vault for worker outputs. */
export async function newTemporaryDirectory(): Promise<string> {
  const root = resolveVaultDir()
  const directory = path.join(root, `worker-${randomBytes(16).toString('hex')}`)
  await fs.promises.mkdir(directory, { recursive: false, mode: 0o700 })
  const stat = await fs.promises.lstat(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink() || !directory.startsWith(`${root}${path.sep}`)) {
    await fs.promises.rm(directory, { recursive: true, force: true }).catch(() => undefined)
    throw new Error('Unable to create a contained archive-worker directory.')
  }
  return directory
}

/** Remove a worker directory only after proving it is inside the active vault. */
export async function cleanupTemporaryDirectory(directory: string): Promise<void> {
  try {
    const root = path.resolve(resolveVaultDir())
    const candidate = path.resolve(directory)
    if (!candidate.startsWith(`${root}${path.sep}`)) {
      console.error('[sentinel] refused to remove a directory outside the configured vault')
      return
    }
    const stat = await fs.promises.lstat(candidate)
    if (!stat.isDirectory() || stat.isSymbolicLink()) return
    await fs.promises.rm(candidate, { recursive: true, force: true, maxRetries: 2, retryDelay: 50 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') console.warn('[sentinel] archive-worker directory cleanup failed')
  }
}
