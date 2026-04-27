import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Globe, Network, Plus, Trash2, RefreshCw, AlertTriangle, CheckCircle, Clock, XCircle, ShieldCheck, Eye, EyeOff } from 'lucide-react'
import Layout from '../components/Layout'
import { scansApi } from '../services/api'

const SEVERITY_COLORS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-gray-400',
}

const STATUS_ICONS = {
  pending: <Clock size={14} className="text-gray-400" />,
  running: <RefreshCw size={14} className="text-indigo-400 animate-spin" />,
  completed: <CheckCircle size={14} className="text-green-400" />,
  failed: <XCircle size={14} className="text-red-400" />,
}

function RiskBadge({ score }) {
  if (score == null) return <span className="text-gray-500 text-xs">—</span>
  const color = score >= 7 ? 'text-red-400' : score >= 4 ? 'text-yellow-400' : 'text-green-400'
  return <span className={`font-bold text-sm ${color}`}>{score.toFixed(1)}</span>
}

export default function DashboardPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ target: '', scan_type: 'web' })
  const [authForm, setAuthForm] = useState({ login_identifier: '', password: '', login_url: '', provided_token: '' })
  const [showPwd, setShowPwd] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const fetchScans = async () => {
    try {
      const res = await scansApi.list()
      setScans(res.data)
    } catch {
      // silently ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000)
    return () => clearInterval(interval)
  }, [])

  const resetForm = () => {
    setShowForm(false)
    setForm({ target: '', scan_type: 'web' })
    setAuthForm({ login_identifier: '', password: '', login_url: '', provided_token: '' })
    setError('')
    setShowPwd(false)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const auth_config = form.scan_type === 'authenticated_web'
        ? {
            login_identifier: authForm.login_identifier,
            password: authForm.password,
            login_url: authForm.login_url || undefined,
            provided_token: authForm.provided_token || undefined,
          }
        : null
      await scansApi.create(form.target, form.scan_type, auth_config)
      resetForm()
      fetchScans()
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors du lancement du scan')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id, e) => {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm('Supprimer ce scan ?')) return
    await scansApi.delete(id)
    setScans((prev) => prev.filter((s) => s.id !== id))
  }

  const stats = {
    total: scans.length,
    running: scans.filter((s) => s.status === 'running' || s.status === 'pending').length,
    completed: scans.filter((s) => s.status === 'completed').length,
    vulns: scans.reduce((acc, s) => acc + (s.vuln_count || 0), 0),
  }

  return (
    <Layout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold">Tableau de bord</h1>
          <p className="text-gray-400 text-sm mt-1">Gérez vos analyses de sécurité</p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-medium text-sm transition-colors"
        >
          <Plus size={16} />
          Nouveau scan
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Total scans', value: stats.total, color: 'text-white' },
          { label: 'En cours', value: stats.running, color: 'text-indigo-400' },
          { label: 'Terminés', value: stats.completed, color: 'text-green-400' },
          { label: 'Vulnérabilités', value: stats.vulns, color: 'text-yellow-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-gray-400 text-xs mb-1">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Nouveau scan modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-md">
            <h2 className="text-lg font-semibold mb-4">Nouveau scan</h2>
            {error && (
              <div className="bg-red-900/30 border border-red-800 text-red-400 rounded-lg px-4 py-3 text-sm mb-4">
                {error}
              </div>
            )}
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Type de scan</label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { value: 'web', icon: <Globe size={16} />, label: 'Web' },
                    { value: 'network', icon: <Network size={16} />, label: 'Réseau' },
                    { value: 'authenticated_web', icon: <ShieldCheck size={16} />, label: 'Authentifié' },
                  ].map((type) => (
                    <button
                      key={type.value}
                      type="button"
                      onClick={() => setForm({ ...form, scan_type: type.value })}
                      className={`flex flex-col items-center gap-1.5 p-2.5 rounded-lg border transition-colors text-xs ${
                        form.scan_type === type.value
                          ? 'border-indigo-500 bg-indigo-600/20 text-indigo-300'
                          : 'border-gray-700 text-gray-400 hover:border-gray-600'
                      }`}
                    >
                      {type.icon}
                      {type.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Cible</label>
                <input
                  type="text"
                  value={form.target}
                  onChange={(e) => setForm({ ...form, target: e.target.value })}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition-colors"
                  placeholder="https://example.com"
                  required
                />
              </div>

              {form.scan_type === 'authenticated_web' && (
                <div className="space-y-3 border border-indigo-900/50 bg-indigo-950/30 rounded-lg p-3">
                  <p className="text-xs text-indigo-400 font-medium">Identifiants de connexion</p>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Email ou nom d'utilisateur</label>
                    <input
                      type="text"
                      value={authForm.login_identifier}
                      onChange={(e) => setAuthForm({ ...authForm, login_identifier: e.target.value })}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-indigo-500 transition-colors"
                      placeholder="user@example.com"
                      required={form.scan_type === 'authenticated_web'}
                      autoComplete="off"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Mot de passe</label>
                    <div className="relative">
                      <input
                        type={showPwd ? 'text' : 'password'}
                        value={authForm.password}
                        onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 pr-9 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-indigo-500 transition-colors"
                        placeholder="••••••••"
                        required={form.scan_type === 'authenticated_web'}
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPwd(!showPwd)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                      >
                        {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">
                      URL de connexion <span className="text-gray-600">(optionnel)</span>
                    </label>
                    <input
                      type="text"
                      value={authForm.login_url}
                      onChange={(e) => setAuthForm({ ...authForm, login_url: e.target.value })}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-indigo-500 transition-colors"
                      placeholder="/api/auth/login  (auto-détecté si vide)"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">
                      Token Bearer existant <span className="text-gray-600">(optionnel — ignore email/mot de passe)</span>
                    </label>
                    <input
                      type="text"
                      value={authForm.provided_token}
                      onChange={(e) => setAuthForm({ ...authForm, provided_token: e.target.value })}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 text-sm font-mono focus:outline-none focus:border-indigo-500 transition-colors"
                      placeholder="eyJhbGciOi..."
                      autoComplete="off"
                    />
                  </div>
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={resetForm}
                  className="flex-1 border border-gray-700 text-gray-300 hover:bg-gray-800 py-2.5 rounded-lg text-sm transition-colors"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white py-2.5 rounded-lg text-sm font-medium transition-colors"
                >
                  {submitting ? 'Lancement...' : 'Lancer le scan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Liste des scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold">Historique des scans</h2>
          <button onClick={fetchScans} className="text-gray-400 hover:text-white transition-colors">
            <RefreshCw size={16} />
          </button>
        </div>

        {loading ? (
          <div className="px-6 py-12 text-center text-gray-500">Chargement...</div>
        ) : scans.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <AlertTriangle size={32} className="text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">Aucun scan. Lancez votre première analyse.</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {scans.map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50 transition-colors group"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="text-gray-500">
                    {scan.scan_type === 'authenticated_web' ? <ShieldCheck size={18} /> :
                     scan.scan_type === 'network' ? <Network size={18} /> :
                     <Globe size={18} />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-white text-sm font-medium truncate">{scan.target}</p>
                    <p className="text-gray-500 text-xs mt-0.5">
                      {new Date(scan.created_at).toLocaleString('fr-FR')} · {scan.scan_type}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-6 ml-4 shrink-0">
                  <div className="flex items-center gap-1.5 text-xs">
                    {STATUS_ICONS[scan.status]}
                    <span className="text-gray-400 capitalize">{scan.status}</span>
                  </div>
                  <div className="text-xs text-gray-400">
                    <span className="text-white font-medium">{scan.vuln_count}</span> vulns
                  </div>
                  <div className="w-10 text-right">
                    <RiskBadge score={scan.risk_score} />
                  </div>
                  <button
                    onClick={(e) => handleDelete(scan.id, e)}
                    className="text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </Layout>
  )
}
