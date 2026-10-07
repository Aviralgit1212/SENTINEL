export type Theme = 'light' | 'dark' | 'system'
export type ReportView = 'summary' | 'detailed'
export type DateFormat = 'DD/MM/YYYY' | 'MM/DD/YYYY' | 'YYYY-MM-DD'

export interface Preferences {
  theme: Theme
  reportView: ReportView
  dateFormat: DateFormat
}

export const STORAGE_KEY = 'sentinel.settings.v1'
export const HISTORY_STORAGE_KEY = 'sentinel.scan-history.v1'

export const DEFAULT_PREFERENCES: Preferences = {
  theme: 'system',
  reportView: 'detailed',
  dateFormat: 'DD/MM/YYYY',
}

const THEMES: Theme[] = ['light', 'dark', 'system']
const REPORT_VIEWS: ReportView[] = ['summary', 'detailed']
const DATE_FORMATS: DateFormat[] = ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD']

function pick<T extends string>(value: unknown, allowed: T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback
}

export function readPreferences(): Preferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_PREFERENCES

    const saved = JSON.parse(raw) as Partial<Preferences>

    return {
      theme: pick(saved.theme, THEMES, DEFAULT_PREFERENCES.theme),
      reportView: pick(saved.reportView, REPORT_VIEWS, DEFAULT_PREFERENCES.reportView),
      dateFormat: pick(saved.dateFormat, DATE_FORMATS, DEFAULT_PREFERENCES.dateFormat),
    }
  } catch {
    return DEFAULT_PREFERENCES
  }
}

/** Returns false when browser storage is unavailable. */
export function writePreferences(preferences: Preferences): boolean {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences))
    return true
  } catch {
    return false
  }
}

export function applyTheme(theme: Theme) {
  const dark =
    theme === 'dark' ||
    (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)

  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}

/** Keeps "system" in sync with the OS setting for the whole app. */
export function watchSystemTheme() {
  window
    .matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', () => {
      const { theme } = readPreferences()
      if (theme === 'system') applyTheme(theme)
    })
}
