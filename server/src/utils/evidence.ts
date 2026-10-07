import type { Evidence, RiskLevel } from '../types/scan.js'

interface CreateEvidenceInput {
    category: Evidence['category']
    title: string
    description: string
    severity: RiskLevel
    source: string
    score?: number
}

export function createEvidence(
    input: CreateEvidenceInput,
): Evidence {
    return {
        id: crypto.randomUUID(),
        category: input.category,
        title: input.title,
        description: input.description,
        severity: input.severity,
        source: input.source,
        score: input.score ?? severityToScore(input.severity),
    }
}

function severityToScore(
    severity: RiskLevel,
): number {
    switch (severity) {
        case 'low':
            return 2

        case 'medium':
            return 5

        case 'high':
            return 15

        case 'critical':
            return 50
    }
}

export function calculateRisk(
    evidence: Evidence[],
): number {
    const total = evidence.reduce(
        (sum, item) => sum + item.score,
        0,
    )

    return Math.min(total, 100)
}

export function riskLevelFromScore(
    score: number,
): RiskLevel {
    if (score >= 75) {
        return 'critical'
    }

    if (score >= 50) {
        return 'high'
    }

    if (score >= 25) {
        return 'medium'
    }

    return 'low'
}

export function recommendationForRisk(
    score: number,
): 'allow' | 'review' | 'block' {
    if (score >= 50) {
        return 'block'
    }

    if (score >= 25) {
        return 'review'
    }

    return 'allow'
}