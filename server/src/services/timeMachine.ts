import type { ScanReport, Finding, AnalyzerCoverageEntry } from '../types.js'

function stableFindingKey(finding: Finding): string {
  return [finding.module, finding.source, finding.category, finding.title, finding.location ?? ''].join('\u001f')
}

function findingMap(report: ScanReport): Map<string, Finding> {
  const map = new Map<string, Finding>()
  for (const finding of report.threat?.findings ?? []) {
    const key = stableFindingKey(finding)
    // Duplicate findings are represented by a count suffix so one additional
    // occurrence is visible rather than collapsed into the same map entry.
    let candidate = key
    let index = 2
    while (map.has(candidate)) candidate = `${key}\u001f${index++}`
    map.set(candidate, finding)
  }
  return map
}

function coverageMap(report: ScanReport): Map<string, AnalyzerCoverageEntry> {
  return new Map(report.coverage.map((entry) => [entry.analyzer, entry]))
}

export interface AssessmentDelta {
  sameArtifact: true
  artifactSha256: string
  baseline: { scanId: string; createdAt: string; verdict: string; assessment: ScanReport['assessment'] }
  current: { scanId: string; createdAt: string; verdict: string; assessment: ScanReport['assessment'] }
  verdictChanged: boolean
  findings: { added: Finding[]; removed: Finding[]; unchangedCount: number }
  coverage: Array<{ analyzer: string; before: string | null; after: string | null; changed: boolean }>
  assessmentVersionChanged: boolean
  limitations: string[]
}

/** Compare two stored assessments without claiming that either artifact was rescanned now. */
export function compareAssessments(baseline: ScanReport, current: ScanReport): AssessmentDelta {
  if (baseline.sha256 !== current.sha256) throw new Error('Assessment comparison requires identical artifact SHA-256 hashes.')
  const oldFindings = findingMap(baseline)
  const newFindings = findingMap(current)
  const added: Finding[] = []
  const removed: Finding[] = []
  for (const [key, finding] of newFindings) if (!oldFindings.has(key)) added.push(finding)
  for (const [key, finding] of oldFindings) if (!newFindings.has(key)) removed.push(finding)

  const oldCoverage = coverageMap(baseline)
  const newCoverage = coverageMap(current)
  const names = [...new Set([...oldCoverage.keys(), ...newCoverage.keys()])].sort()
  const coverage = names.map((analyzer) => {
    const before = oldCoverage.get(analyzer)?.state ?? null
    const after = newCoverage.get(analyzer)?.state ?? null
    return { analyzer, before, after, changed: before !== after }
  })

  const a = baseline.assessment ?? { engineVersion: 'unknown', rulesetVersion: 'unknown', policyVersion: 'unknown' }
  const b = current.assessment ?? { engineVersion: 'unknown', rulesetVersion: 'unknown', policyVersion: 'unknown' }
  return {
    sameArtifact: true,
    artifactSha256: current.sha256,
    baseline: { scanId: baseline.scanId, createdAt: baseline.createdAt, verdict: baseline.verdict, assessment: baseline.assessment },
    current: { scanId: current.scanId, createdAt: current.createdAt, verdict: current.verdict, assessment: current.assessment },
    verdictChanged: baseline.verdict !== current.verdict,
    findings: { added, removed, unchangedCount: [...newFindings.keys()].filter((key) => oldFindings.has(key)).length },
    coverage,
    assessmentVersionChanged: a.engineVersion !== b.engineVersion || a.rulesetVersion !== b.rulesetVersion || a.policyVersion !== b.policyVersion,
    limitations: [
      'This is a comparison of stored assessments, not a fresh scan.',
      'The original artifact bytes are not retained by the Security Time Machine; a new assessment requires the user to upload the artifact again.',
      'Persisted evidence is minimized, so withheld raw snippets cannot be reconstructed from history.',
    ],
  }
}
