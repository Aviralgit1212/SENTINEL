/**
 * SENTINEL Sovereign Core — Security Intermediate Representation (SIR)
 * 
 * Compiler-grade intermediate representation graph unifying:
 * - Document structural nodes (sections, paragraphs, XML parts, PE headers)
 * - Content nodes (text runs, character bounding boxes, color contrasts)
 * - Relational nodes (embedded objects, imports, external hyperlinks)
 */

import { createHash, randomUUID } from 'node:crypto'
import { sanitizeUnicode, type NormalizationResult } from './normalizer.js'

export type SIRNodeType = 
  | 'document_root'
  | 'section'
  | 'paragraph'
  | 'run'
  | 'table_cell'
  | 'embedded_object'
  | 'external_relationship'
  | 'pe_header'
  | 'pe_section'
  | 'import_symbol'
  | 'archive_entry'

export interface SIREntity {
  id: string
  nodeType: SIRNodeType
  parentId?: string
  byteRange?: [number, number]
  structuralLocation: {
    partPath?: string
    page?: number
    paragraphIndex?: number
    runIndex?: number
    bbox?: [number, number, number, number] // [x0, y0, x1, y1]
  }
  attributes: {
    fontSizePt?: number
    fontColorHex?: string
    backgroundColorHex?: string
    contrastDeltaE?: number
    isHiddenStyle?: boolean
    zeroWidthCount?: number
    bidiOverrideCount?: number
    entropy?: number
    sha256?: string
  }
  rawText?: string
  normalizedText?: string
  rawBytesRef?: string
}

export interface SIRRelationship {
  sourceId: string
  targetId: string
  relationType: 'contains' | 'references' | 'executes' | 'embeds'
}

export interface VisibilityEntry {
  scope: string
  status: 'INSPECTED' | 'PARTIAL' | 'UNPARSED_GAP' | 'NOT_APPLICABLE'
  coveredBytes?: number
  totalBytes?: number
  reason?: string
}

export interface SIRGraph {
  artifactSha256: string
  mimeType: string
  totalSizeBytes: number
  entities: Record<string, SIREntity>
  relationships: SIRRelationship[]
  visibilityLedger: Record<string, VisibilityEntry>
}

export class SIRBuilder {
  private graph: SIRGraph

  constructor(artifactSha256: string, mimeType: string, totalSizeBytes: number) {
    this.graph = {
      artifactSha256,
      mimeType,
      totalSizeBytes,
      entities: {},
      relationships: [],
      visibilityLedger: {},
    }
  }

  public addEntity(input: {
    id?: string
    nodeType: SIRNodeType
    parentId?: string
    byteRange?: [number, number]
    structuralLocation?: SIREntity['structuralLocation']
    attributes?: SIREntity['attributes']
    rawText?: string
  }): SIREntity {
    const id = input.id || `sir_${randomUUID().slice(0, 8)}`
    let normalizedText: string | undefined
    let zeroWidthCount = input.attributes?.zeroWidthCount || 0
    let bidiOverrideCount = input.attributes?.bidiOverrideCount || 0

    if (input.rawText) {
      const norm = sanitizeUnicode(input.rawText)
      normalizedText = norm.cleanedText
      zeroWidthCount += norm.zeroWidthCount
      bidiOverrideCount += norm.bidiCount
    }

    const entity: SIREntity = {
      id,
      nodeType: input.nodeType,
      parentId: input.parentId,
      byteRange: input.byteRange,
      structuralLocation: input.structuralLocation || {},
      attributes: {
        ...input.attributes,
        zeroWidthCount: zeroWidthCount > 0 ? zeroWidthCount : undefined,
        bidiOverrideCount: bidiOverrideCount > 0 ? bidiOverrideCount : undefined,
      },
      rawText: input.rawText,
      normalizedText,
    }

    this.graph.entities[id] = entity

    if (input.parentId && this.graph.entities[input.parentId]) {
      this.graph.relationships.push({
        sourceId: input.parentId,
        targetId: id,
        relationType: 'contains',
      })
    }

    return entity
  }

  public addRelationship(sourceId: string, targetId: string, relationType: SIRRelationship['relationType']): void {
    this.graph.relationships.push({ sourceId, targetId, relationType })
  }

  public setVisibility(scope: string, status: VisibilityEntry['status'], reason?: string, coveredBytes?: number, totalBytes?: number): void {
    this.graph.visibilityLedger[scope] = {
      scope,
      status,
      reason,
      coveredBytes,
      totalBytes,
    }
  }

  public build(): SIRGraph {
    return this.graph
  }
}
