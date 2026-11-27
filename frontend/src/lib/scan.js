import { Globe, Lock, Code, Network, Layers, Eye, Radar } from 'lucide-react'

export const SCAN_TYPES = [
  { key: 'web', label: 'Web', hint: 'OWASP Top 10, TLS, en-têtes', icon: Globe, placeholder: 'https://example.com' },
  { key: 'authenticated_web', label: 'Authentifié', hint: 'Tests derrière la connexion', icon: Lock, placeholder: 'https://app.example.com' },
  { key: 'api', label: 'API', hint: 'OWASP API Top 10 (2023)', icon: Code, placeholder: 'https://api.example.com' },
  { key: 'network', label: 'Réseau', hint: 'Hôtes, ports et services', icon: Network, placeholder: '192.168.1.0/24 ou 192.168.1.1' },
  { key: 'subdomain', label: 'Sous-domaines', hint: 'Découverte et takeover', icon: Layers, placeholder: 'example.com' },
  { key: 'osint', label: 'OSINT', hint: 'WHOIS, DNS, emails, dorks', icon: Eye, placeholder: 'example.com' },
  { key: 'cti', label: 'Threat Intel', hint: 'Réputation IP et domaine', icon: Radar, placeholder: 'example.com ou 1.2.3.4' },
]
export const SCAN_TYPE = Object.fromEntries(SCAN_TYPES.map((t) => [t.key, t]))

export const SEVS = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_LABEL = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible', info: 'Info' }
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
export const sortBySeverity = (vulns) =>
  [...vulns].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || (b.cvss_score || 0) - (a.cvss_score || 0))

export const STATUS = {
  pending: { label: 'En attente', dot: 'pending' },
  running: { label: 'En cours', dot: 'run' },
  completed: { label: 'Terminé', dot: 'ok' },
  failed: { label: 'Échec', dot: 'fail' },
}

export const riskCls = (r) => (r == null ? 'muted' : r >= 7 ? 'c-critical' : r >= 5 ? 'c-high' : r >= 3 ? 'c-medium' : 'c-ok')
export const riskBar = (r) => (r == null ? '' : r >= 7 ? 'critical' : r >= 5 ? 'high' : r >= 3 ? 'medium' : 'ok')
export const riskLabel = (r) => (r >= 7 ? 'Élevé' : r >= 4 ? 'Modéré' : 'Faible')
export const scoreBar = (v) => (v == null ? '' : v >= 60 ? 'ok' : v >= 40 ? 'medium' : 'critical')
export const httpCls = (c) => (c == null ? '' : c < 300 ? 'ok' : c < 400 ? '' : 'warn')

export const fmtDate = (d, long = false) =>
  new Date(d).toLocaleString('fr-FR', long
    ? { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })

export const apiError = (err, fallback) => {
  const d = err?.response?.data?.detail
  if (Array.isArray(d)) return d.map((e) => e.msg).join(' · ')
  return typeof d === 'string' ? d : fallback
}
