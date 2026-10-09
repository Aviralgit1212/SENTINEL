
import type { Evidence, DocxFacts } from '../types/scan.js'
import { createEvidence } from '../utils/evidence.js'

export function buildDocxEvidence(
  facts: DocxFacts,
): Evidence[] {
  const evidence: Evidence[] = []

  // Fail closed: analysis failure must not be treated as safe.
  if (!facts.supported) {
    evidence.push(
      createEvidence({
        category: 'docx-analysis',
        title: 'DOCX analysis incomplete',
        description:
          `Sentinel could not fully validate or inspect this DOCX package. ` +
          `${facts.error ?? 'The analyzer returned an unsupported result.'} ` +
          'Do not treat an analysis failure as proof that the file is safe.',
        severity: 'high',
        score: 20,
        source: 'docx-static-analysis',
      }),
    )

    return evidence
  }

  // Package integrity and archive safety warnings.
  if (facts.packageWarnings.length > 0) {
    const severeWarnings = facts.packageWarnings.some((warning) =>
      [
        'archive-expansion-limit-exceeded',
        'archive-entry-limit-exceeded',
        'invalid-office-package',
        'invalid-zip-signature',
        'missing-required-office-parts',
        'suspicious-archive-path',
        'encrypted-archive-entry',
        'file-size-limit-exceeded',
        'analysis-error',
        'malformed-or-unreadable-xml-part',
        'xml-part-count-limit-exceeded',
        'xml-part-too-large-to-inspect',
      ].includes(warning),
    )

    evidence.push(
      createEvidence({
        category: 'docx-package',
        title: 'Unusual or risky package structure',
        description:
          `The DOCX package triggered ${facts.packageWarnings.length} package warning(s): ` +
          `${facts.packageWarnings.slice(0, 8).join(', ')}. ` +
          'These findings may indicate malformed or unusually constructed content and require review.',
        severity: severeWarnings ? 'high' : 'medium',
        score: severeWarnings ? 18 : 7,
        source: 'docx-package-analysis',
      }),
    )
  }

  // Hidden text and possible AI-targeted instructions.
  if (facts.hiddenTextCount > 0) {
    const hidden = facts.hiddenTextFindings

    const suspiciousHidden = hidden.some((item) =>
      item.contentSignals.some((signal) =>
        [
          'prompt-injection-like-instruction',
          'command-or-script-indicator',
          'credential-theft-language',
        ].includes(signal),
      ),
    )

    const reasons = [
      ...new Set(hidden.flatMap((item) => item.reasons)),
    ].slice(0, 8)

    const signals = [
      ...new Set(hidden.flatMap((item) => item.contentSignals)),
    ].slice(0, 8)

    const previews = hidden
      .filter((item) => item.text)
      .slice(0, 2)
      .map((item) => `"${item.text.slice(0, 140)}"`)

    evidence.push(
      createEvidence({
        category: 'docx-hidden-content',
        title: suspiciousHidden
          ? 'Suspicious instructions found in hidden document text'
          : 'Potentially hidden document text detected',
        description:
          `${facts.hiddenTextCount} run(s) matched hidden-text heuristics. ` +
          `Formatting signals: ${reasons.join(', ') || 'not specified'}. ` +
          (signals.length
            ? `Content indicators: ${signals.join(', ')}. `
            : '') +
          (previews.length
            ? `Example: ${previews.join('; ')}. `
            : '') +
          'Hidden text can be legitimate. Review the context before deciding whether it is malicious.',
        severity: suspiciousHidden ? 'high' : 'medium',
        score: suspiciousHidden ? 22 : 8,
        source: 'docx-hidden-text-analysis',
      }),
    )
  }

  // Record URLs without opening or fetching them.
  if (facts.urls.length > 0) {
    evidence.push(
      createEvidence({
        category: 'docx-links',
        title: 'URLs found in the document package',
        description:
          `Sentinel found ${facts.urls.length} HTTP/HTTPS URL(s). ` +
          'The URLs were recorded but not opened. A URL alone is not proof of malicious activity.',
        severity: 'low',
        score: 2,
        source: 'docx-relationship-analysis',
      }),
    )
  }

  // External file paths and UNC/network paths.
  const externalFileTargets = facts.externalRelationships.filter(
    (item) =>
      /^(?:file:|\\\\|[a-z]:)/i.test(item.target.trim()),
  )

  if (externalFileTargets.length > 0) {
    evidence.push(
      createEvidence({
        category: 'docx-external-content',
        title: 'External file or network-path relationship',
        description:
          `The package contains ${externalFileTargets.length} external relationship(s) using a file or network path. ` +
          'This may be legitimate in enterprise documents, but it can also expose the user to unexpected external content.',
        severity: 'high',
        score: 18,
        source: 'docx-relationship-analysis',
      }),
    )
  }

  // External template references.
  if (facts.hasExternalTemplate) {
    evidence.push(
      createEvidence({
        category: 'docx-external-content',
        title: 'External Word template reference',
        description:
          'The document references an external template. Sentinel did not contact or download that resource.',
        severity: 'medium',
        score: 8,
        source: 'docx-relationship-analysis',
      }),
    )
  }

  // Embedded objects: inspect metadata only; do not execute them.
  if (facts.embeddedObjects.length > 0) {
    const executableLike = facts.embeddedObjects.some((item) => {
      const filenameLooksExecutable =
        /\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|hta|com|msi)$/i.test(
          item.name,
        )

      return filenameLooksExecutable || item.isExecutableLike === true
    })

    evidence.push(
      createEvidence({
        category: 'docx-embedded-content',
        title: executableLike
          ? 'Executable-like embedded content detected'
          : 'Embedded objects detected',
        description:
          `The DOCX package contains ${facts.embeddedObjects.length} embedded object(s). ` +
          `Examples: ${facts.embeddedObjects
            .slice(0, 5)
            .map((item) => item.name)
            .join(', ')}. ` +
          'Embedded content was not extracted or executed. Embedded objects have not necessarily been scanned independently.',
        severity: executableLike ? 'high' : 'medium',
        score: executableLike ? 25 : 6,
        source: 'docx-embedded-object-analysis',
      }),
    )
  }

  // VBA-related components.
  if (facts.macroParts.length > 0) {
    evidence.push(
      createEvidence({
        category: 'docx-macros',
        title: 'VBA project component detected',
        description:
          `The package contains ${facts.macroParts.length} VBA-related component(s). ` +
          'Macro presence does not prove malicious behavior, but this is unusual for a standard DOCX and requires review.',
        severity: 'high',
        score: 20,
        source: 'docx-package-analysis',
      }),
    )
  }

  // Content and package indicators reported by the Python analyzer.
  const indicators = facts.suspiciousIndicators.filter((indicator) =>
    [
      'command-or-script-indicator',
      'credential-theft-language',
      'external-file-or-network-path',
      'executable-or-script-like-package-entry',
      'macro-related-component-detected',
      'prompt-injection-like-instruction',
      'suspicious-content-in-hidden-text',
    ].includes(indicator),
  )

  if (indicators.length > 0) {
    evidence.push(
      createEvidence({
        category: 'docx-content-indicators',
        title: 'Suspicious document content indicators',
        description:
          `Static inspection identified: ${[...new Set(indicators)]
            .slice(0, 10)
            .join(', ')}. ` +
          'These are heuristic indicators, not a definitive malware verdict.',
        severity: 'high',
        score: 15,
        source: 'docx-content-analysis',
      }),
    )
  }

  // Tracked changes may expose edits or deleted text.
  if (facts.hasTrackedChanges) {
    evidence.push(
      createEvidence({
        category: 'docx-document-structure',
        title: 'Tracked changes detected',
        description:
          'The document contains tracked insertions, deletions, or moved text. This is common in edited documents but may expose content that is not obvious in the final view.',
        severity: 'low',
        score: 1,
        source: 'docx-xml-analysis',
      }),
    )
  }

  // Comments can contain internal or sensitive information.
  if (facts.hasComments) {
    evidence.push(
      createEvidence({
        category: 'docx-document-structure',
        title: 'Document comments detected',
        description:
          'The DOCX contains comments. Comments can include internal or sensitive information and should be reviewed when sharing externally.',
        severity: 'low',
        score: 1,
        source: 'docx-xml-analysis',
      }),
    )
  }

  // No extracted text does not mean the document is safe.
  if (facts.textLength === 0) {
    evidence.push(
      createEvidence({
        category: 'docx-content',
        title: 'No readable document text extracted',
        description:
          'Sentinel did not extract readable text from the inspected XML parts. This can occur with image-only, encrypted, malformed, or unusual documents. It does not mean the file is safe.',
        severity: 'medium',
        score: 5,
        source: 'docx-xml-analysis',
      }),
    )
  }

  return evidence
}