import type { Risk } from '../../types/sentinel'

const LABELS: Record<Risk, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
}

export function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`risk risk-${risk}`}>{LABELS[risk]}</span>
}
