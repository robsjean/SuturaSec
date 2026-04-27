import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, Globe, Network, RefreshCw, AlertTriangle, Shield, FileText } from 'lucide-react'
import Layout from '../components/Layout'
import { scansApi } from '../services/api'

const SEVERITY_CONFIG = {
  critical: { label: 'Critique', bg: 'bg-red-900/30', border: 'border-red-800', text: 'text-red-400', dot: 'bg-red-500' },
  high: { label: 'Élevé', bg: 'bg-orange-900/30', border: 'border-orange-800', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium: { label: 'Moyen', bg: 'bg-yellow-900/30', border: 'border-yellow-800', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  low: { label: 'Faible', bg: 'bg-blue-900/30', border: 'border-blue-800', text: 'text-blue-400', dot: 'bg-blue-500' },
  info: { label: 'Info', bg: 'bg-gray-800/50', border: 'border-gray-700', text: 'text-gray-400', dot: 'bg-gray-500' },
}

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded-md ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

export default function ScanDetailPage() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchScan = async () => {
    try {
      const res = await scansApi.get(id)
      setScan(res.data)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScan()
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') fetchScan()
    }, 3000)
    return () => clearInterval(interval)
  }, [id, scan?.status])

  if (loading) return (
    <Layout>
      <div className="text-center py-20 text-gray-400">Chargement du scan...</div>
    </Layout>
  )

  if (!scan) return (
    <Layout>
      <div className="text-center py-20 text-gray-400">Scan introuvable.</div>
    </Layout>
  )

  const severityCounts = scan.vulnerabilities.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1
    return acc
  }, {})

  return (
    <Layout>
      <div className="mb-6">
        <Link to="/dashboard" className="flex items-center gap-2 text-gray-400 hover:text-white text-sm transition-colors mb-4">
          <ArrowLeft size={16} />
          Retour au dashboard
        </Link>

        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="text-indigo-400">
              {scan.scan_type === 'web' ? <Globe size={24} /> : <Network size={24} />}
            </div>
            <div>
              <h1 className="text-xl font-bold break-all">{scan.target}</h1>
              <p className="text-gray-400 text-sm mt-0.5">
                {scan.scan_type === 'web' ? 'Analyse Web' : 'Analyse Réseau'} ·{' '}
                {new Date(scan.created_at).toLocaleString('fr-FR')}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {(scan.status === 'pending' || scan.status === 'running') && (
              <button onClick={fetchScan} className="text-gray-400 hover:text-white">
                <RefreshCw size={18} className="animate-spin" />
              </button>
            )}
            {scan.status === 'completed' && (
              <button
                onClick={() => window.open(`/scans/${scan.id}/report?token=${localStorage.getItem('token')}`, '_blank')}
                className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
              >
                <FileText size={15} />
                Rapport PDF
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 col-span-2 md:col-span-1">
          <p className="text-gray-400 text-xs mb-1">Score de risque</p>
          <p className={`text-3xl font-bold ${
            scan.risk_score >= 7 ? 'text-red-400' : scan.risk_score >= 4 ? 'text-yellow-400' : 'text-green-400'
          }`}>
            {scan.risk_score != null ? scan.risk_score.toFixed(1) : '—'}
          </p>
          <p className="text-gray-500 text-xs mt-1">/ 10</p>
        </div>
        {['critical', 'high', 'medium', 'low'].map((sev) => (
          <div key={sev} className={`rounded-xl p-4 border ${SEVERITY_CONFIG[sev].bg} ${SEVERITY_CONFIG[sev].border}`}>
            <p className={`text-xs mb-1 ${SEVERITY_CONFIG[sev].text}`}>{SEVERITY_CONFIG[sev].label}</p>
            <p className="text-2xl font-bold text-white">{severityCounts[sev] || 0}</p>
          </div>
        ))}
      </div>

      {/* Summary */}
      {scan.summary && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6 flex items-start gap-3">
          <Shield size={18} className="text-indigo-400 mt-0.5 shrink-0" />
          <p className="text-gray-300 text-sm">{scan.summary}</p>
        </div>
      )}

      {/* Status badge */}
      {scan.status !== 'completed' && (
        <div className={`rounded-xl p-4 mb-6 border text-sm flex items-center gap-2 ${
          scan.status === 'failed'
            ? 'bg-red-900/20 border-red-800 text-red-400'
            : 'bg-indigo-900/20 border-indigo-800 text-indigo-400'
        }`}>
          {scan.status === 'running' || scan.status === 'pending' ? (
            <RefreshCw size={14} className="animate-spin" />
          ) : (
            <AlertTriangle size={14} />
          )}
          {scan.status === 'pending' && 'Scan en attente de démarrage...'}
          {scan.status === 'running' && 'Scan en cours d\'exécution...'}
          {scan.status === 'failed' && 'Le scan a échoué.'}
        </div>
      )}

      {/* Vulnérabilités */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold">
            Vulnérabilités détectées{' '}
            <span className="text-gray-500 font-normal text-sm">({scan.vulnerabilities.length})</span>
          </h2>
        </div>

        {scan.vulnerabilities.length === 0 ? (
          <div className="px-6 py-12 text-center text-gray-500">
            {scan.status === 'completed' ? 'Aucune vulnérabilité détectée.' : 'En attente des résultats...'}
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {scan.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="px-6 py-5">
                <div className="flex items-start justify-between gap-4 mb-2">
                  <h3 className="font-medium text-white">{vuln.title}</h3>
                  <div className="flex items-center gap-2 shrink-0">
                    {vuln.cvss_score != null && (
                      <span className="text-xs text-gray-400">CVSS {vuln.cvss_score.toFixed(1)}</span>
                    )}
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                </div>

                {vuln.category && (
                  <p className="text-xs text-indigo-400 mb-2">{vuln.category}</p>
                )}
                {vuln.description && (
                  <p className="text-gray-400 text-sm mb-3">{vuln.description}</p>
                )}
                {vuln.evidence && (
                  <div className="bg-gray-800 rounded-lg px-4 py-3 text-xs font-mono text-gray-300 mb-3 overflow-x-auto">
                    {vuln.evidence}
                  </div>
                )}
                {vuln.remediation && (
                  <div className="flex items-start gap-2 text-sm text-green-400 bg-green-900/10 border border-green-900/30 rounded-lg px-4 py-3">
                    <Shield size={14} className="mt-0.5 shrink-0" />
                    <span>{vuln.remediation}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  )
}
