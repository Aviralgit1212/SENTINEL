import {
    createEvidence,
} from '../utils/evidence.js'

import type {
    Evidence,
    PdfFacts,
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

                title: 'JavaScript detected',

                description:
                    `The PDF contains ${facts.structure.javascriptCount} JavaScript object(s). PDF JavaScript can be used for legitimate document functionality but may also be abused to perform malicious actions.`,

                severity: 'high',

                score: 20,

                source: 'pdf-structure-analysis',
            }),
        )
    }

    // ---------------------------------------------------------
    // OpenAction
    // ---------------------------------------------------------
    //
    // The existence of an OpenAction alone is NOT considered
    // malicious.
    //
    // We inspect what the action actually does.
    // ---------------------------------------------------------

    const openAction =
        facts.structure.openAction

    if (openAction.present) {

        switch (openAction.type) {

            // -------------------------------------------------
            // GoTo
            // -------------------------------------------------
            //
            // Internal navigation inside the same PDF.
            // Normally benign.
            // -------------------------------------------------

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

            // -------------------------------------------------
            // GoToR
            // -------------------------------------------------
            //
            // Navigation to another document/resource.
            // Needs more inspection but is not inherently
            // malicious.
            // -------------------------------------------------

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

            // -------------------------------------------------
            // URI
            // -------------------------------------------------
            //
            // Opens/navigates to a URL.
            // The URL itself must be analyzed separately.
            // -------------------------------------------------

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

            // -------------------------------------------------
            // JavaScript
            // -------------------------------------------------

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

            // -------------------------------------------------
            // Launch
            // -------------------------------------------------

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

            // -------------------------------------------------
            // Unknown
            // -------------------------------------------------

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
    //
    // Keep this separate from OpenAction because Launch can
    // also appear in other PDF action structures.
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

    if (
        facts.structure.embeddedFileCount > 0
    ) {

        evidence.push(
            createEvidence({
                category: 'pdf-security',

                title:
                    'Embedded files detected',

                description:
                    `The PDF contains ${facts.structure.embeddedFileCount} embedded file(s). Embedded files can be legitimate but may also be used to carry malicious content.`,

                severity: 'medium',

                score: 15,

                source:
                    'pdf-structure-analysis',
            }),
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
                    'The PDF did not contain native text and OCR was unavailable, so visual text could not be fully inspected.',

                severity: 'medium',

                score: 5,

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

    return evidence
}