import { Shield, LogOut, LayoutDashboard } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const location = useLocation()

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
        <Link to="/dashboard" className="flex items-center gap-2 text-indigo-400 font-bold text-lg">
          <Shield size={22} />
          SamaSecurity
        </Link>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-gray-400">
            Bonjour, <span className="text-white font-medium">{user?.username}</span>
          </span>
          <button
            onClick={logout}
            className="flex items-center gap-1 text-gray-400 hover:text-red-400 transition-colors"
          >
            <LogOut size={16} />
            Déconnexion
          </button>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-6 py-8 max-w-6xl">
        {children}
      </main>
    </div>
  )
}
