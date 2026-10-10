import test from 'node:test'
import assert from 'node:assert/strict'
import { scanWithClamAV } from '../src/services/clamav.js'

test('ClamAV never reports a nonexistent input as clean', async () => {
  const result = await scanWithClamAV(`/tmp/sentinel-nonexistent-${process.pid}-${Date.now()}.bin`)
  assert.notEqual(result.state, 'completed_no_detections')
  assert.ok(['unavailable', 'failed', 'timed_out'].includes(result.state))
})
