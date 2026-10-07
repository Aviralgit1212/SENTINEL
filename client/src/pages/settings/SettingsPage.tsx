import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useClerk, useUser } from '@clerk/clerk-react'
import { useNavigate } from 'react-router-dom'

import {
  DEFAULT_PREFERENCES,
  HISTORY_STORAGE_KEY,
  STORAGE_KEY,
  applyTheme,
  readPreferences,
  writePreferences,
} from '../../utils/preferences'
import type { DateFormat, Preferences, ReportView, Theme } from '../../utils/preferences'
import './SettingsPage.css'

type Confirm = 'history' | 'account' | null

const CONFIRM_COPY = {
  history: {
    title: 'Clear scan history?',
    body: 'This removes scan records stored in this browser. Records kept on a server are not affected.',
    action: 'Clear history',
  },
  account: {
    title: 'Delete your account?',
    body: 'Your Sentinel account and sign-in are removed permanently. This can’t be undone.',
    action: 'Delete account',
  },
} as const

function Row({
  title,
  hint,
  children,
}: {
  title: string
  hint?: string
  children: ReactNode
}) {
  return (
    <div className="setting-row">
      <div>
        <p className="setting-title">{title}</p>
        {hint && <p className="setting-hint">{hint}</p>}
      </div>
      <div className="setting-control">{children}</div>
    </div>
  )
}

function Segmented<T extends string>({
  name,
  label,
  value,
  options,
  onChange,
}: {
  name: string
  label: string
  value: T
  options: { value: T; label: string }[]
  onChange: (value: T) => void
}) {
  return (
    <fieldset className="segmented">
      <legend className="visually-hidden">{label}</legend>

      {options.map((option) => (
        <label key={option.value}>
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={option.value === value}
            onChange={() => onChange(option.value)}
          />
          <span>{option.label}</span>
        </label>
      ))}
    </fieldset>
  )
}

function ConfirmDialog({
  action,
  busy,
  onConfirm,
  onCancel,
}: {
  action: Confirm
  busy: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return

    if (action && !dialog.open) dialog.showModal()
    if (!action && dialog.open) dialog.close()
  }, [action])

  const copy = action ? CONFIRM_COPY[action] : null

  return (
    <dialog
      ref={ref}
      className="confirm"
      aria-labelledby="confirm-title"
      onClose={onCancel}
    >
      {copy && (
        <div className="confirm-inner">
          <h2 id="confirm-title">{copy.title}</h2>
          <p>{copy.body}</p>

          <div className="confirm-actions">
            <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
            <button type="button" className="btn btn-danger" onClick={onConfirm} disabled={busy}>
              {busy ? 'Working…' : copy.action}
            </button>
          </div>
        </div>
      )}
    </dialog>
  )
}

export default function SettingsPage() {
  const { isLoaded, user } = useUser()
  const { openUserProfile, signOut } = useClerk()
  const navigate = useNavigate()

  const [preferences, setPreferences] = useState<Preferences>(readPreferences)
  const [status, setStatus] = useState('')
  const [confirm, setConfirm] = useState<Confirm>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!status) return
    const timer = window.setTimeout(() => setStatus(''), 4000)
    return () => window.clearTimeout(timer)
  }, [status])

  function save(next: Preferences) {
    setPreferences(next)
    applyTheme(next.theme)

    setStatus(
      writePreferences(next)
        ? 'Saved.'
        : 'Couldn’t save. Browser storage is unavailable, so this change is lost on refresh.',
    )
  }

  function update<K extends keyof Preferences>(key: K, value: Preferences[K]) {
    save({ ...preferences, [key]: value })
  }

  function clearHistory() {
    try {
      localStorage.removeItem(HISTORY_STORAGE_KEY)
      setStatus('Scan history cleared.')
    } catch {
      setStatus('Couldn’t clear scan history. Browser storage is unavailable.')
    }
    setConfirm(null)
  }

  async function deleteAccount() {
    if (!user) return
    setBusy(true)

    try {
      await user.delete()

      try {
        localStorage.removeItem(STORAGE_KEY)
        localStorage.removeItem(HISTORY_STORAGE_KEY)
      } catch {
        // The account is gone; local cleanup is best effort.
      }

      setConfirm(null)
      await signOut()
      navigate('/sign-in', { replace: true })
    } catch (error) {
      console.error('Account deletion failed:', error)
      setStatus(
        'Couldn’t delete the account. Sign in again and retry, or open Manage account.',
      )
      setConfirm(null)
    } finally {
      setBusy(false)
    }
  }

  if (!isLoaded || !user) {
    return (
      <main className="page settings">
        <p className="setting-hint">Loading settings…</p>
      </main>
    )
  }

  const name =
    user.fullName ||
    user.username ||
    user.primaryEmailAddress?.emailAddress ||
    'Sentinel user'
  const email = user.primaryEmailAddress?.emailAddress ?? 'No email on file'
  const initials =
    name
      .split(/\s+/)
      .filter(Boolean)
      .map((part) => part[0])
      .join('')
      .slice(0, 2)
      .toUpperCase() || 'S'

  return (
    <main className="page settings">
      <header className="settings-head">
        <h1>Settings</h1>
        <p className="settings-status" role="status">
          {status}
        </p>
      </header>

      <section aria-labelledby="account-title">
        <h2 id="account-title">Account</h2>

        <div className="account">
          <span className="avatar" aria-hidden="true">
            {initials}
          </span>
          <div>
            <p className="setting-title">{name}</p>
            <p className="setting-hint">{email}</p>
          </div>
          <div className="account-actions">
            <button type="button" className="btn btn-secondary" onClick={() => openUserProfile()}>
              Manage account
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => signOut()}>
              Sign out
            </button>
          </div>
        </div>
      </section>

      <section aria-labelledby="appearance-title">
        <h2 id="appearance-title">Appearance</h2>

        <Row title="Theme" hint="System follows your device setting.">
          <Segmented<Theme>
            name="theme"
            label="Theme"
            value={preferences.theme}
            onChange={(value) => update('theme', value)}
            options={[
              { value: 'light', label: 'Light' },
              { value: 'dark', label: 'Dark' },
              { value: 'system', label: 'System' },
            ]}
          />
        </Row>

        <Row title="Date format" hint="Used in scan lists.">
          <select
            value={preferences.dateFormat}
            onChange={(event) => update('dateFormat', event.target.value as DateFormat)}
            aria-label="Date format"
          >
            <option value="DD/MM/YYYY">DD/MM/YYYY</option>
            <option value="MM/DD/YYYY">MM/DD/YYYY</option>
            <option value="YYYY-MM-DD">YYYY-MM-DD</option>
          </select>
        </Row>
      </section>

      <section aria-labelledby="reports-title">
        <h2 id="reports-title">Reports</h2>

        <Row title="Default view" hint="How findings are laid out when a report opens.">
          <Segmented<ReportView>
            name="report-view"
            label="Default report view"
            value={preferences.reportView}
            onChange={(value) => update('reportView', value)}
            options={[
              { value: 'summary', label: 'Summary' },
              { value: 'detailed', label: 'Detailed' },
            ]}
          />
        </Row>
      </section>

      <section aria-labelledby="data-title">
        <h2 id="data-title">Your data</h2>

        <Row title="Scan history" hint="Removes records stored in this browser.">
          <button type="button" className="btn btn-secondary" onClick={() => setConfirm('history')}>
            Clear history
          </button>
        </Row>

        <Row title="Preferences" hint="Restore every setting on this page to its default.">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => save(DEFAULT_PREFERENCES)}
          >
            Reset
          </button>
        </Row>
      </section>

      <section className="danger" aria-labelledby="delete-title">
        <h2 id="delete-title">Delete account</h2>

        <Row
          title="Delete your Sentinel account"
          hint="Permanently removes your account and sign-in. This can’t be undone."
        >
          <button type="button" className="btn btn-danger" onClick={() => setConfirm('account')}>
            Delete account
          </button>
        </Row>
      </section>

      <ConfirmDialog
        action={confirm}
        busy={busy}
        onCancel={() => setConfirm(null)}
        onConfirm={() => (confirm === 'history' ? clearHistory() : deleteAccount())}
      />
    </main>
  )
}
