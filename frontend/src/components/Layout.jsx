import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { FileText, LayoutGrid, LogOut, Menu, Moon, ShieldCheck, Sun, X } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { SCAN_TYPES } from '../lib/scan'
import { useTheme } from '../lib/theme'
import { useToast } from '../lib/toast'

const COMING_SOON = ['Cloud Security', 'Phishing Simulator', 'Comparaison de scans']

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [isDark, toggleTheme] = useTheme()
  const [open, setOpen] = useState(false)
  const [toast, closeToast] = useToast()

  useEffect(() => setOpen(false), [location.pathname, location.search])
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && setOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const onReports = location.pathname === '/dashboard' && new URLSearchParams(location.search).get('view') === 'rapports'
  const onDashboard = !onReports && (location.pathname === '/dashboard' || location.pathname.startsWith('/scans/'))

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="shell">
      <div className="topbar">
        <button className="btn btn-ghost icon-btn" type="button" onClick={() => setOpen(true)} aria-label="Ouvrir le menu">
          <Menu size={18} strokeWidth={1.8} aria-hidden="true" />
        </button>
        <Link className="brand" to="/dashboard">SuturaSec</Link>
      </div>

      {open && <div className="sidebar-overlay" onClick={() => setOpen(false)} />}

      <aside className={`sidebar${open ? ' open' : ''}`} aria-label="Navigation">
        <Link className="brand" to="/dashboard">
          <ShieldCheck size={22} strokeWidth={1.8} aria-hidden="true" />
          SuturaSec
        </Link>

        <nav className="nav" aria-label="Navigation principale">
          <Link to="/dashboard" aria-current={onDashboard ? 'page' : undefined}>
            <LayoutGrid size={16} strokeWidth={1.8} aria-hidden="true" />
            Tableau de bord
          </Link>
          <Link to="/dashboard?view=rapports" aria-current={onReports ? 'page' : undefined}>
            <FileText size={16} strokeWidth={1.8} aria-hidden="true" />
            Rapports
          </Link>

          <div className="nav-label">Nouvelle analyse</div>
          {SCAN_TYPES.map(({ key, label, icon: Icon }) => (
            <button key={key} type="button" onClick={() => navigate(`/dashboard?scan=${key}`)}>
              <Icon size={16} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
              <span className="plus" aria-hidden="true">+</span>
            </button>
          ))}

          <div className="nav-label">Bientôt</div>
          {COMING_SOON.map((f) => (
            <a key={f} className="disabled" href="#" aria-disabled="true" tabIndex={-1}>
              <span>{f}</span><span className="soon">Soon</span>
            </a>
          ))}
        </nav>

        <div className="user">
          <div className="avatar" aria-hidden="true">{(user?.username || '?').slice(0, 2).toUpperCase()}</div>
          <div className="user-meta">
            <b>{user?.username || '…'}</b>
            <span>{user?.email || 'Plan Free'}</span>
          </div>
          <button className="btn btn-ghost icon-btn theme-btn" type="button" onClick={toggleTheme}
                  aria-label={isDark ? 'Passer en thème clair' : 'Passer en thème sombre'}>
            {isDark ? <Sun size={16} strokeWidth={1.8} aria-hidden="true" /> : <Moon size={16} strokeWidth={1.8} aria-hidden="true" />}
          </button>
          <button className="btn btn-ghost icon-btn" type="button" onClick={handleLogout} aria-label="Déconnexion">
            <LogOut size={16} strokeWidth={1.8} aria-hidden="true" />
          </button>
        </div>
      </aside>

      {toast && (
        <div className={`toast${toast.type === 'error' ? ' error' : ''}`} role="status" aria-live="polite">
          <span className={`dot ${toast.type === 'error' ? 'fail' : 'ok'}`} style={{ marginTop: 6 }} />
          <span style={{ flex: 1 }}>{toast.message}</span>
          <button className="btn btn-ghost icon-btn" type="button" onClick={closeToast} aria-label="Fermer la notification">
            <X size={14} strokeWidth={1.8} aria-hidden="true" />
          </button>
        </div>
      )}

      <main className="main">
        <div className="container">{children}</div>
      </main>
    </div>
  )
}
