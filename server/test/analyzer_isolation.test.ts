import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import fs from 'node:fs'
import { runBoundedProcess, analyzerScriptDir } from '../src/services/pythonAnalyzer.js'

const linuxWithPrlimit = process.platform === 'linux' && ['/usr/bin/prlimit', '/bin/prlimit'].some((p) => {
  try { return fs.existsSync(p) } catch { return false }
})

test('analyzer script directory is resolved from module location, not process cwd', () => {
  assert.equal(path.basename(analyzerScriptDir()), 'python-analyzers')
  assert.match(analyzerScriptDir(), /python-analyzers$/)
})

test('bounded runner rejects invalid timeout and resource limits before spawning', async () => {
  const result = await runBoundedProcess({
    executable: process.execPath,
    args: ['-e', 'process.stdout.write("{}")'],
    timeoutMs: 1,
    maxStdoutChars: 100,
  })
  assert.equal(result.ok, false)
  assert.match(result.error ?? '', /timeout configuration/i)
})

test('bounded runner accepts one valid JSON document under Linux resource limits', { skip: !linuxWithPrlimit }, async () => {
  const result = await runBoundedProcess<{ ok: boolean; value: number }>({
    executable: '/usr/bin/python3',
    args: ['-c', 'import json; print(json.dumps({"ok": True, "value": 7}))'],
    timeoutMs: 3000,
    maxStdoutChars: 1024,
    memoryLimitMb: 512,
  })
  assert.equal(result.ok, true, result.error ?? '')
  assert.equal(result.resourceLimited, true)
  assert.deepEqual(result.data, { ok: true, value: 7 })
})

test('bounded runner rejects mixed log output instead of salvaging JSON from it', { skip: !linuxWithPrlimit }, async () => {
  const result = await runBoundedProcess({
    executable: '/usr/bin/python3',
    args: ['-c', 'print("debug {\\\"ok\\\":true} trailing")'],
    timeoutMs: 3000,
    maxStdoutChars: 1024,
  })
  assert.equal(result.ok, false)
  assert.match(result.error ?? '', /invalid or mixed JSON/i)
})

test('bounded runner kills a process that exceeds wall-clock time', { skip: !linuxWithPrlimit }, async () => {
  const result = await runBoundedProcess({
    executable: '/usr/bin/python3',
    args: ['-c', 'import time; time.sleep(10)'],
    timeoutMs: 300,
    maxStdoutChars: 1024,
    memoryLimitMb: 512,
  })
  assert.equal(result.ok, false)
  assert.equal(result.timedOut, true)
  assert.match(result.error ?? '', /wall-clock limit/i)
})

test('bounded runner kills a process when stdout exceeds its cap', { skip: !linuxWithPrlimit }, async () => {
  const result = await runBoundedProcess({
    executable: '/usr/bin/python3',
    args: ['-c', 'print("x" * 1000000)'],
    timeoutMs: 3000,
    maxStdoutChars: 1024,
    memoryLimitMb: 512,
  })
  assert.equal(result.ok, false)
  assert.match(result.error ?? '', /stdout exceeded/i)
})

test('bounded runner refuses to silently downgrade when Linux prlimit is required but absent', async () => {
  // A non-Linux platform exercises the unavailable-limiter path naturally.
  // On Linux, availability is asserted by the dedicated resource-limited tests.
  if (process.platform === 'linux' && linuxWithPrlimit) return
  const result = await runBoundedProcess({
    executable: process.execPath,
    args: ['-e', 'process.stdout.write("{}")'],
    timeoutMs: 1000,
    maxStdoutChars: 100,
    requireResourceLimits: true,
  })
  assert.equal(result.ok, false)
  assert.equal(result.resourceLimited, false)
})

test('Python runner refuses non-allowlisted analyzer scripts', async () => {
  const { runPythonJson } = await import('../src/services/pythonAnalyzer.js')
  const result = await runPythonJson('arbitrary.py', [], { timeoutMs: 1000, maxStdoutChars: 100 })
  assert.equal(result.ok, false)
  assert.match(result.error ?? '', /invalid analyzer script name/i)
})
