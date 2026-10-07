import type { DateFormat } from './preferences'

export function formatDate(iso: string, format: DateFormat): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'Unknown'

  const dd = String(date.getDate()).padStart(2, '0')
  const mm = String(date.getMonth() + 1).padStart(2, '0')
  const yyyy = String(date.getFullYear())

  switch (format) {
    case 'MM/DD/YYYY':
      return `${mm}/${dd}/${yyyy}`
    case 'YYYY-MM-DD':
      return `${yyyy}-${mm}-${dd}`
    default:
      return `${dd}/${mm}/${yyyy}`
  }
}
