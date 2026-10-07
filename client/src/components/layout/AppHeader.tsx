import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'
import { Menu, Plus, X } from 'lucide-react'

import { Wordmark } from '../ui/Logo'
import './AppHeader.css'

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `app-nav-link${isActive ? ' is-active' : ''}`

export default function AppHeader() {
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  const closeMenu = () => setMenuOpen(false)

  function openHistory() {
    closeMenu()
    navigate('/dashboard', { state: { openHistory: true } })
  }

  return (
    <header className="app-header">
      <div className="page app-header-inner">
        <Link to="/dashboard" aria-label="Sentinel dashboard" onClick={closeMenu}>
          <Wordmark />
        </Link>

        <nav
          id="app-nav"
          className="app-nav"
          data-open={menuOpen}
          aria-label="Main"
        >
          <NavLink to="/dashboard" className={linkClass} onClick={closeMenu}>
            Dashboard
          </NavLink>

          <button type="button" className="app-nav-link" onClick={openHistory}>
            History
          </button>

          <NavLink to="/settings" className={linkClass} onClick={closeMenu}>
            Settings
          </NavLink>
        </nav>

        <div className="app-header-actions">
          <Link to="/dashboard" className="btn btn-primary" onClick={closeMenu}>
            <Plus aria-hidden="true" />
            New scan
          </Link>

          <UserButton />

          <button
            type="button"
            className="btn btn-ghost app-menu-toggle"
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
            aria-controls="app-nav"
            onClick={() => setMenuOpen((open) => !open)}
          >
            {menuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
          </button>
        </div>
      </div>
    </header>
  )
}
