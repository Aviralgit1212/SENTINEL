import test from 'node:test'
import assert from 'node:assert/strict'
import { getClamAVCapability } from '../src/services/clamav.js'

test('ClamAV health reports binary and resource prerequisites rather than import success', () => {
  const capability = getClamAVCapability()
  assert.equal(capability.engine, 'clamscan-cli')
  assert.equal(capability.readyForAttempt, capability.binaryAvailable && capability.resourceLimitsAvailable)
  assert.ok(capability.detail.length > 0)
  if (!capability.binaryAvailable) assert.match(capability.detail, /not installed/i)
  // Presence is intentionally not equated with signature database readiness.
  if (capability.readyForAttempt) assert.match(capability.detail, /database readiness is not yet verified/i)
})
