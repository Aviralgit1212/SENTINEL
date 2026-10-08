export type Risk = 'low' | 'medium' | 'high' | 'critical'

export interface ScanRecord {
  id: string
  name: string
  /** ISO 8601 timestamp */
  scannedAt: string
  risk: Risk
}

export interface ScanHistoryResponse {
  scanId: string
  filename: string
  status: 'analyzing' | 'completed' | 'failed'
  risk: {
    score: number
    level: Risk
  }
  recommendation: 'allow' | 'review' | 'block'
  createdAt: string
}