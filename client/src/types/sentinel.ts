export type Risk = 'low' | 'medium' | 'high'

export interface ScanRecord {
  id: string
  name: string
  /** ISO 8601 timestamp */
  scannedAt: string
  risk: Risk
}
