import {
    createEvidence,
} from '../utils/evidence.js'

import type {
    Evidence,
    PdfFacts,
    PdfEmbeddedFile,
} from '../types/scan.js'

export function buildPdfEvidence(
    facts: PdfFacts,
): Evidence[] {

    if (!facts.supported) {
        return []
    }

    const evidence: Evidence[] = []

    // ---------------------------------------------------------
    // JavaScript
    // ---------------------------------------------------------

    if (facts.structure.javascriptCount > 0) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'JavaScript detected',

                description:
                    `The PDF contains ${facts.structure.javascriptCount} JavaScript object(s). PDF JavaScript can be used for legitimate document functionality but may also be abused to perform malicious actions.`,

                severity: 'high',

                score: 20,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // OpenAction
    // ---------------------------------------------------------

    const openAction =
        facts.structure.openAction

    if (openAction.present) {

        switch (openAction.type) {

            case 'GoTo':

                evidence.push(
                    createEvidence({
                        category: 'pdf-navigation',

                        title:
                            'Internal document navigation detected',

                        description:
                            'The PDF uses an OpenAction to navigate to a destination within the document. This is normally benign and does not increase the security risk score.',

                        severity: 'low',

                        score: 0,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break

            case 'GoToR':

                evidence.push(
                    createEvidence({
                        category: 'pdf-navigation',

                        title:
                            'External document navigation detected',

                        description:
                            openAction.target
                                ? `The PDF uses an OpenAction to navigate to another document or resource: ${openAction.target}.`
                                : 'The PDF uses an OpenAction to navigate to another document or resource.',

                        severity: 'medium',

                        score: 5,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break

            case 'URI':

                evidence.push(
                    createEvidence({
                        category: 'pdf-navigation',

                        title:
                            'Automatic URL navigation detected',

                        description:
                            openAction.target
                                ? `The PDF contains an OpenAction that can navigate to the URL: ${openAction.target}. The URL requires separate security analysis.`
                                : 'The PDF contains an OpenAction that can automatically navigate to a URL. The URL requires separate security analysis.',

                        severity: 'low',

                        score: 2,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break

            case 'JavaScript':

                evidence.push(
                    createEvidence({
                        category: 'pdf-security',

                        title:
                            'JavaScript OpenAction detected',

                        description:
                            openAction.target
                                ? `The PDF can execute JavaScript automatically when opened. A bounded JavaScript preview was extracted for further analysis: ${openAction.target}`
                                : 'The PDF can execute JavaScript automatically when opened. Automatically executed PDF JavaScript requires further inspection.',

                        severity: 'high',

                        score: 20,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break

            case 'Launch':

                evidence.push(
                    createEvidence({
                        category: 'pdf-security',

                        title:
                            'Automatic application launch detected',

                        description:
                            openAction.target
                                ? `The PDF can attempt to launch an external application or file when opened. Target: ${openAction.target}.`
                                : 'The PDF can attempt to launch an external application or file when opened.',

                        severity: 'high',

                        score: 25,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break

            case 'Unknown':

                evidence.push(
                    createEvidence({
                        category: 'pdf-security',

                        title:
                            'Unknown automatic PDF action detected',

                        description:
                            openAction.rawType
                                ? `The PDF contains an OpenAction with an unrecognized action type (${openAction.rawType}). The action could not be safely classified and requires further inspection.`
                                : 'The PDF contains an OpenAction whose behavior could not be safely classified and requires further inspection.',

                        severity: 'medium',

                        score: 5,

                        source:
                            'pdf-openaction-analysis',
                    }),
                )

                break
        }
    }

    // ---------------------------------------------------------
    // Additional actions
    // ---------------------------------------------------------

    if (
        facts.structure.hasAdditionalActions
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'Additional PDF actions detected',

                description:
                    'The PDF contains additional actions that may execute automatically in response to document events.',

                severity: 'medium',

                score: 10,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // Launch action
    // ---------------------------------------------------------

    if (
        facts.structure.hasLaunchAction &&
        openAction.type !== 'Launch'
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'Launch action detected',

                description:
                    'The PDF contains a Launch action that may attempt to start an external application or file.',

                severity: 'high',

                score: 25,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // Embedded files
    // ---------------------------------------------------------
    //
    // IMPORTANT:
    //
    // Do NOT assign risk simply because an embedded file exists.
    //
    // C2PA / Content Credentials are commonly used for
    // provenance and authenticity information and should not
    // automatically increase the security score.
    //
    // Executable/script-like embedded files are much more
    // significant and receive high-risk evidence.
    //
    // Other unknown binary attachments receive moderate risk.
    // ---------------------------------------------------------

    const embeddedFiles =
    facts.structure.embeddedFiles

let c2paEvidenceAdded = false

for (
    const embeddedFile of embeddedFiles
) {

    if (embeddedFile.isC2pa) {

        if (!c2paEvidenceAdded) {

            addEmbeddedFileEvidence(
                evidence,
                embeddedFile,
            )

            c2paEvidenceAdded = true
        }

        continue
    }

    addEmbeddedFileEvidence(
        evidence,
        embeddedFile,
    )
}

    // ---------------------------------------------------------
    // Rich media
    // ---------------------------------------------------------

    if (
        facts.structure.hasRichMedia
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'Rich media content detected',

                description:
                    'The PDF contains rich media content.',

                severity: 'medium',

                score: 10,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // XFA
    // ---------------------------------------------------------

    if (
        facts.structure.hasXfa
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'XFA content detected',

                description:
                    'The PDF contains XFA form content, which can include dynamic document behavior.',

                severity: 'medium',

                score: 8,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // URLs
    // ---------------------------------------------------------

    if (
        facts.links.urls.length > 0
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-links',

                title:
                    'URLs detected',

                description:
                    `The PDF contains ${facts.links.urls.length} URL(s). URLs are not inherently malicious but may require further inspection.`,

                severity: 'low',

                score: 2,

                source:
                    'pdf-link-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // OCR
    // ---------------------------------------------------------

    if (
        facts.text.source === 'ocr' &&
        facts.text.ocrAttempted &&
        facts.text.ocrAvailable
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-text',

                title:
                    'Scanned PDF analyzed with OCR',

                description:
                    `No native PDF text was available, so OCR was used to inspect ${facts.text.ocrPageCount} page(s).`,

                severity: 'low',

                score: 2,

                source:
                    'pdf-ocr',
            }),
        )
    }

    // ---------------------------------------------------------
    // OCR unavailable
    // ---------------------------------------------------------

    if (
        facts.text.ocrAttempted &&
        !facts.text.ocrAvailable
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-text',

                title:
                    'OCR unavailable',

                description:
                    'One or more pages lacked native text and OCR was unavailable, so visual text on those pages could not be fully inspected.',

                severity: 'medium',

                score: 5,

                source:
                    'pdf-ocr',
            }),
        )
    }

    // ---------------------------------------------------------
    // OCR incomplete / partial
    // ---------------------------------------------------------

    if (
        facts.text.ocrAttempted &&
        facts.text.ocrAvailable &&
        facts.text.errors.length > 0
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-text',

                title:
                    'OCR incomplete',

                description:
                    `OCR was available, but ${facts.text.errors.length} OCR issue(s) or processing limit(s) were reported. Some visual text may not have been inspected.`,

                severity: 'medium',

                score: 4,

                source:
                    'pdf-ocr',
            }),
        )
    }

    // ---------------------------------------------------------
    // Interactive form fields
    // ---------------------------------------------------------

    if (
        facts.structure.formFieldCount > 0
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-forms',

                title:
                    'Interactive form fields detected',

                description:
                    `The PDF contains ${facts.structure.formFieldCount} interactive form field(s).`,

                severity: 'low',

                score: 1,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // AcroForm
    // ---------------------------------------------------------

    if (
        facts.structure.hasAcroForm
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-forms',

                title:
                    'AcroForm detected',

                description:
                    'The PDF contains an AcroForm structure.',

                severity: 'low',

                score: 1,

                source:
                    'pdf-structure-analysis',
            }),
        )
    }


    // ---------------------------------------------------------
    // Hidden / visually suspicious text
    // ---------------------------------------------------------
    //
    // Findings are heuristic signals, not proof of malware.
    // We aggregate them into one evidence item to avoid flooding
    // the report when a PDF contains many suspicious spans.
    // ---------------------------------------------------------

    const hiddenItems = facts.hiddenText?.items ?? []

    if (hiddenItems.length > 0) {
        const suspiciousContent = hiddenItems.some((item) =>
            item.contentSignals.some((signal) =>
                [
                    'prompt-injection',
                    'command-execution',
                    'credential-request',
                    'possible-obfuscation',
                ].includes(signal),
            ),
        )

        const strongest = hiddenItems
            .slice()
            .sort((a, b) => b.confidence - a.confidence)[0]

        const reasonLabels = [...new Set(
            hiddenItems.flatMap((item) => item.reasons),
        )].slice(0, 6)

        const contentLabels = [...new Set(
            hiddenItems.flatMap((item) => item.contentSignals),
        )].slice(0, 6)

        const preview = strongest?.text
            ? strongest.text.replace(/\s+/g, ' ').slice(0, 220)
            : ''

        evidence.push(
            createEvidence({
                category: 'pdf-hidden-text',
                title: suspiciousContent
                    ? 'Hidden text with suspicious instructions detected'
                    : 'Potentially hidden or visually inconspicuous text detected',
                description:
                    `${hiddenItems.length} text span(s) matched hidden-text heuristics. ` +
                    `Signals: ${reasonLabels.join(', ') || 'unspecified'}. ` +
                    (contentLabels.length
                        ? `Content indicators: ${contentLabels.join(', ')}. `
                        : '') +
                    (preview ? `Example text: "${preview}". ` : '') +
                    'This is a heuristic finding; review the page visually before treating it as malicious.',
                severity: suspiciousContent ? 'high' : 'medium',
                score: suspiciousContent ? 20 : 8,
                source: 'pdf-hidden-text-analysis',
            }),
        )
    }

    return evidence
}

/**
 * Converts embedded-file facts into security evidence.
 *
 * This function deliberately keeps classification separate
 * from PDF parsing. The analyzer tells us what exists;
 * this function decides how much security significance
 * that observation has.
 */
function addEmbeddedFileEvidence(
    evidence: Evidence[],
    embeddedFile: PdfEmbeddedFile,
): void {

    // ---------------------------------------------------------
    // C2PA / Content Credentials
    // ---------------------------------------------------------
    //
    // C2PA metadata is not inherently malicious.
    // Do not increase the risk score.
    // ---------------------------------------------------------

    if (
        embeddedFile.isC2pa
    ) {

        const filename =
            embeddedFile.filename ||
            'Content Credentials'

        evidence.push(
            createEvidence({
                category: 'pdf-provenance',

                title:
                    'Content Credentials detected',

                description:
                    `The PDF contains an embedded C2PA/Content Credentials object${filename ? ` (${filename})` : ''}. This is treated as provenance metadata and does not increase the security risk score.`,

                severity: 'low',

                score: 0,

                source:
                    'pdf-embedded-file-analysis',
            }),
        )

        return
    }

    // ---------------------------------------------------------
    // Executable / script-like embedded file
    // ---------------------------------------------------------

    if (
        embeddedFile.isExecutableLike
    ) {

        const filename =
            embeddedFile.filename ||
            'unknown embedded file'

        const mimeType =
            embeddedFile.mimeType ||
            'unknown MIME type'

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'Executable or script-like embedded file detected',

                description:
                    `The PDF contains an embedded file that appears executable or script-like: ${filename} (${mimeType}). Embedded executable content can be used to deliver or trigger malicious payloads.`,

                severity: 'high',

                score: 25,

                source:
                    'pdf-embedded-file-analysis',
            }),
        )

        return
    }

    // ---------------------------------------------------------
    // Unknown / generic embedded file
    // ---------------------------------------------------------

    const filename =
        embeddedFile.filename ||
        'unknown embedded file'

    const mimeType =
        embeddedFile.mimeType ||
        'unknown MIME type'

    evidence.push(
        createEvidence({
            category: 'pdf-security',

            title:
                'Embedded file detected',

            description:
                `The PDF contains an embedded file: ${filename} (${mimeType}). Embedded attachments can be legitimate, but their contents should be inspected before being trusted.`,

            severity: 'medium',

            score: 5,

            source:
                'pdf-embedded-file-analysis',
        }),
    )
}