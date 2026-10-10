/**
 * SENTINEL Sovereign Core — Counterfactual Security Engine
 * 
 * Solves the inverse policy query:
 * "What is the minimum set of verifiable transformations required to satisfy Policy X?"
 * 
 * Builds a Blocker Dependency Graph separating:
 * 1. Mandatory Invariants (must be resolved)
 * 2. Coverage Gaps (missing/incomplete analyses)
 * 3. Optional Hardening steps
 */

import { randomUUID } from 'node:crypto'
import type { Finding, AnalyzerCoverageEntry } from '../types.js'

export type SecurityActionContext = 
  | 'external_ai_submission'
  | 'external_email_transfer'
  | 'internal_archival'
  | 'executable_deployment'

export interface CounterfactualBlocker {
  blockerId: string
  findingId?: string
  conditionType: 'MANDATORY_INVARIANT' | 'POLICY_CONSTRAINT' | 'COVERAGE_GAP'
  title: string
  description: string
  resolution: {
    action: 'REDACT_PII' | 'STRIP_STEALTH_PROMPT' | 'QUARANTINE_MALWARE' | 'RESOLVE_UNPARSED_GAP' | 'MANUAL_REVIEW'
    target?: string
    estimatedImpact: 'LOSSLESS' | 'DESTRUCTIVE'
  }
  dependentChecks: string[]
}

export interface CounterfactualPlan {
  targetContext: SecurityActionContext
  isSatisfiable: boolean
  blockers: CounterfactualBlocker[]
  minimalActionSequence: Array<{
    step: number
    actionName: string
    description: string
    targetLocation?: string
  }>
}

export function buildCounterfactualPlan(
  findings: Finding[],
  coverage: AnalyzerCoverageEntry[],
  targetContext: SecurityActionContext = 'external_ai_submission',
): CounterfactualPlan {
  const blockers: CounterfactualBlocker[] = []

  // 1. Process Findings
  for (const finding of findings) {
    if (finding.severity === 'critical') {
      blockers.push({
        blockerId: `blk_${randomUUID().slice(0, 8)}`,
        findingId: finding.id,
        conditionType: 'MANDATORY_INVARIANT',
        title: `Critical Threat: ${finding.title}`,
        description: finding.description,
        resolution: {
          action: 'QUARANTINE_MALWARE',
          target: finding.location,
          estimatedImpact: 'DESTRUCTIVE',
        },
        dependentChecks: ['clamav', 'magic-byte-analysis'],
      })
    } else if (finding.category === 'phantom_prompt_injection' || finding.category === 'prompt_injection_text') {
      blockers.push({
        blockerId: `blk_${randomUUID().slice(0, 8)}`,
        findingId: finding.id,
        conditionType: 'POLICY_CONSTRAINT',
        title: `AI Prompt Injection: ${finding.title}`,
        description: 'Document contains hidden instructions that could hijack external LLMs.',
        resolution: {
          action: 'STRIP_STEALTH_PROMPT',
          target: finding.location,
          estimatedImpact: 'LOSSLESS',
        },
        dependentChecks: ['differential-perception-engine', 'content-integrity'],
      })
    } else if (finding.module === 'privacy' || finding.severity === 'high') {
      blockers.push({
        blockerId: `blk_${randomUUID().slice(0, 8)}`,
        findingId: finding.id,
        conditionType: 'POLICY_CONSTRAINT',
        title: `Sensitive Information: ${finding.title}`,
        description: finding.description,
        resolution: {
          action: 'REDACT_PII',
          target: finding.location,
          estimatedImpact: 'LOSSLESS',
        },
        dependentChecks: ['privacy-service', 'presidio-rescan'],
      })
    }
  }

  // 2. Process Coverage Gaps
  for (const cov of coverage) {
    if (cov.state === 'failed' || cov.state === 'timed_out' || cov.state === 'inconclusive') {
      blockers.push({
        blockerId: `blk_${randomUUID().slice(0, 8)}`,
        conditionType: 'COVERAGE_GAP',
        title: `Incomplete Analysis: ${cov.analyzer}`,
        description: `Check did not complete successfully (${cov.state}: ${cov.detail ?? 'unknown error'}). Analysis gap must be resolved.`,
        resolution: {
          action: 'RESOLVE_UNPARSED_GAP',
          target: cov.analyzer,
          estimatedImpact: 'LOSSLESS',
        },
        dependentChecks: [cov.analyzer],
      })
    }
  }

  // 3. Build Minimal Dependency Sequence
  const minimalActionSequence = blockers.map((b, idx) => ({
    step: idx + 1,
    actionName: b.resolution.action,
    description: b.title,
    targetLocation: b.resolution.target,
  }))

  const isSatisfiable = !blockers.some((b) => b.resolution.action === 'QUARANTINE_MALWARE')

  return {
    targetContext,
    isSatisfiable,
    blockers,
    minimalActionSequence,
  }
}
