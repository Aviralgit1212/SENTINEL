import type { Evidence, RiskLevel } from '../types/scan.js'

let evidenceCounter = 0

export function createEvidence(
  input: Omit<Evidence, 'id'>,
): Evidence {
  evidenceCounter += 1

  return {
    id: `E${String(evidenceCounter).padStart(3, '0')}`,
    ...input,
  }
}

export function calculateRisk(
  evidence: Evidence[],
): RiskLevel {
  if (
    evidence.some(
      (item) => item.severity === 'critical',
    )
  ) {
    return 'critical'
  }

  if (
    evidence.some(
      (item) => item.severity === 'high',
    )
  ) {
    return 'high'
  }

  if (
    evidence.some(
      (item) => item.severity === 'medium',
    )
  ) {
    return 'medium'
  }

  return 'low'
}

export function recommendationForRisk(
  risk: RiskLevel,
): 'allow' | 'review' | 'block' {
  if (risk === 'critical' || risk === 'high') {
    return 'block'
  }

  if (risk === 'medium') {
    return 'review'
  }

  return 'allow'
}