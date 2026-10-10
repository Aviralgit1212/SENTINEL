import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
  uploadsDirectory,
  newTemporaryPath,
  isVaultPath,
  sanitizeArchivePath,
  cleanupTemporaryFile,
} from '../src/services/workspace.js'

test('strict Linux vault resolves to a private directory under /dev/shm', () => {
  const directory = uploadsDirectory()
  if (process.platform === 'linux') {
    assert.ok(directory.startsWith('/dev/shm/'), `unexpected vault path: ${directory}`)
    const mode = fs.statSync(directory).mode & 0o777
    assert.equal(mode, 0o700)
  }
})

test('generated temporary paths remain inside the vault', () => {
  const filePath = newTemporaryPath('../../private.docx')
  assert.equal(isVaultPath(filePath), true)
  assert.equal(path.dirname(filePath), uploadsDirectory())
})

test('archive path sanitizer rejects traversal outside the destination', () => {
  const root = path.join(os.tmpdir(), 'sentinel-archive-test')
  assert.throws(() => sanitizeArchivePath(root, '../../escape.txt'), /Path traversal attempt blocked/)
  assert.equal(sanitizeArchivePath(root, 'folder/file.txt'), path.join(root, 'folder', 'file.txt'))
})

test('cleanup refuses to unlink files outside the configured vault', async () => {
  const outside = path.join(os.tmpdir(), `sentinel-outside-${process.pid}-${Date.now()}`)
  fs.writeFileSync(outside, 'keep me')
  try {
    await cleanupTemporaryFile(outside)
    assert.equal(fs.readFileSync(outside, 'utf8'), 'keep me')
  } finally {
    fs.rmSync(outside, { force: true })
  }
})

test('cleanup removes a temporary file inside the vault', async () => {
  const filePath = newTemporaryPath('cleanup-test.bin')
  fs.writeFileSync(filePath, Buffer.from('ephemeral'))
  assert.equal(fs.existsSync(filePath), true)
  await cleanupTemporaryFile(filePath)
  assert.equal(fs.existsSync(filePath), false)
})

test('archive path sanitizer rejects Windows-style traversal on Linux', () => {
  const root = path.join(os.tmpdir(), 'sentinel-archive-test')
  assert.throws(() => sanitizeArchivePath(root, '..\\..\\escape.txt'), /Path traversal attempt blocked/)
  assert.throws(() => sanitizeArchivePath(root, 'C:\\Windows\\system.ini'), /Absolute archive path blocked/)
  assert.throws(() => sanitizeArchivePath(root, '\\\\server\\share\\payload'), /Absolute archive path blocked/)
  assert.throws(() => sanitizeArchivePath(root, '/etc/passwd'), /Absolute archive path blocked/)
  assert.throws(() => sanitizeArchivePath(root, 'folder\\..\\..\\escape.txt'), /Path traversal attempt blocked/)
  assert.equal(sanitizeArchivePath(root, 'folder\\nested\\file.txt'), path.join(root, 'folder', 'nested', 'file.txt'))
})

test('archive path sanitizer rejects empty and NUL-containing entry names', () => {
  const root = path.join(os.tmpdir(), 'sentinel-archive-test')
  assert.throws(() => sanitizeArchivePath(root, ''), /Invalid archive entry path/)
  assert.throws(() => sanitizeArchivePath(root, 'folder\u0000file.txt'), /Invalid archive entry path/)
})
