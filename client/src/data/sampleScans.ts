import type { ScanRecord } from '../types/sentinel'

/** Placeholder records until the scan history API exists. */
export const sampleScans: ScanRecord[] = [
  {
    id: 'sample-1',
    name: 'quarterly-report.pdf',
    scannedAt: '2026-10-02T09:14:00Z',
    risk: 'medium',
  },
  {
    id: 'sample-2',
    name: 'supplier-invoice.docx',
    scannedAt: '2026-09-28T16:40:00Z',
    risk: 'low',
  },
  {
    id: 'sample-3',
    name: 'scanned-contract.pdf',
    scannedAt: '2026-09-21T11:05:00Z',
    risk: 'high',
  },
]
