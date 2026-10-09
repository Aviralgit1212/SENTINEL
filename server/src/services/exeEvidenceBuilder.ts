
import type { Evidence, ExeFacts } from '../types/scan.js'
import { createEvidence } from '../utils/evidence.js'

export function buildExeEvidence(facts: ExeFacts): Evidence[] {
    const evidence: Evidence[] = []

    if (!facts.supported) {
        evidence.push(createEvidence({
            category: 'exe-structure',
            title: 'PE executable structure could not be validated',
            description: facts.error ||
                'The file did not pass PE structural validation. It was not executed.',
            severity: 'high',
            score: 18,
            source: 'exe-static-analysis',
        }))
        return evidence
    }

    if (facts.structuralWarnings && facts.structuralWarnings.length > 0) {
        evidence.push(createEvidence({
            category: 'exe-structure',
            title: 'Potential PE structure anomalies detected',
            description:
                `Static parser warnings: ${facts.structuralWarnings.join(', ')}. ` +
                'Malformed or unusual layout can be benign, but it prevents a confident trust decision.',
            severity: 'high',
            score: 18,
            source: 'exe-structure-validation',
        }))
    }

    if (facts.suspiciousImports.length > 0) {
        const examples = facts.suspiciousImports
            .slice(0, 8)
            .map((item) => `${item.dll || 'unknown DLL'}!${item.function}`)
            .join(', ')

        const injectionApis = facts.suspiciousImports.some((item) =>
            ['virtualallocex', 'writeprocessmemory', 'createremotethread',
                'ntcreatethreadex'].includes(item.function.toLowerCase()),
        )

        evidence.push(createEvidence({
            category: 'exe-imports',
            title: 'Potentially sensitive Windows APIs imported',
            description:
                `${facts.suspiciousImports.length} import(s) matched API heuristics: ${examples}. ` +
                'These APIs can be used legitimately; their presence alone does not prove malware.',
            severity: injectionApis ? 'high' : 'medium',
            score: facts.suspiciousImports.length >= 3 ? 18 : 10,
            source: 'exe-import-analysis',
        }))
    }

    if (facts.suspiciousIndicators.length > 0) {
        const injection = facts.suspiciousIndicators.includes(
            'process-injection-api',
        )

        evidence.push(createEvidence({
            category: 'exe-strings',
            title: 'Suspicious command or behavior strings detected',
            description:
                `String indicators found: ${facts.suspiciousIndicators.join(', ')}. ` +
                'Strings may be unused code or false positives and need context.',
            severity: injection ? 'high' : 'medium',
            score: injection ? 15 : 8,
            source: 'exe-string-analysis',
        }))
    }

    if (facts.urls.length > 0 || facts.ipAddresses.length > 0) {
        evidence.push(createEvidence({
            category: 'exe-network',
            title: 'Network indicators found in executable',
            description:
                `${facts.urls.length} URL(s) and ${facts.ipAddresses.length} IPv4-looking address(es) ` +
                'found in extracted strings. Sentinel does not contact these indicators.',
            severity: 'low',
            score: 3,
            source: 'exe-string-analysis',
        }))
    }

    if (facts.highEntropySections.length > 0) {
        evidence.push(createEvidence({
            category: 'exe-packing',
            title: 'High-entropy section(s) detected',
            description:
                `Section(s) with high entropy: ${facts.highEntropySections.join(', ')}. ` +
                'This can indicate packing or compression, not necessarily malware.',
            severity: 'medium',
            score: 8,
            source: 'exe-section-analysis',
        }))
    }

    const writableExecutable = facts.sections.filter(
        (section) => section.executable && section.writable,
    )

    if (writableExecutable.length > 0) {
        evidence.push(createEvidence({
            category: 'exe-sections',
            title: 'Writable executable section detected',
            description:
                `Section(s) marked both writable and executable: ` +
                `${writableExecutable.map((section) => section.name).join(', ')}.`,
            severity: 'medium',
            score: 8,
            source: 'exe-section-analysis',
        }))
    }

    if (!facts.hasCertificateTable) {
        evidence.push(createEvidence({
            category: 'exe-signature',
            title: 'No embedded signature table detected',
            description:
                'No Authenticode certificate table was detected. Unsigned programs can be legitimate; ' +
                'this check does not validate signatures or publisher identity.',
            severity: 'low',
            score: 2,
            source: 'exe-signature-presence-check',
        }))
    }

    if (facts.overlaySize > 1024) {
        evidence.push(createEvidence({
            category: 'exe-overlay',
            title: 'Data found after the PE sections',
            description:
                `Approximately ${facts.overlaySize} byte(s) exist after the final section. ` +
                'This can be legitimate appended data or something requiring review.',
            severity: 'low',
            score: 3,
            source: 'exe-structure-analysis',
        }))
    }

    if (facts.sectionCount === 0 || facts.entryPointRva === 0) {
        evidence.push(createEvidence({
            category: 'exe-structure',
            title: 'Unusual PE entry point or section layout',
            description:
                'The PE has no sections or a zero entry-point RVA. Review its structure.',
            severity: 'high',
            score: 15,
            source: 'exe-structure-analysis',
        }))
    }

    return evidence
}