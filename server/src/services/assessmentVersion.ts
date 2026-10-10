import type { AssessmentVersion } from '../types.js'

// Version identifiers are explicit and overrideable for controlled rollouts.
// Bump RULESET when detection logic/rules change and POLICY when verdict semantics change.
export function currentAssessmentVersion(): AssessmentVersion {
  return {
    engineVersion: process.env.SENTINEL_ENGINE_VERSION?.trim() || '3.0.0-sovereign',
    rulesetVersion: process.env.SENTINEL_RULESET_VERSION?.trim() || 'rules-2026.10.1',
    policyVersion: process.env.SENTINEL_POLICY_VERSION?.trim() || 'policy-v3',
  }
}
