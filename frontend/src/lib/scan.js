import { Globe, Lock, Code, Network, Layers, Eye, Radar } from 'lucide-react'

export const SCAN_TYPES = [
  { key: 'web', label: 'Web', hint: 'OWASP Top 10, TLS, en-têtes', icon: Globe,
    desc: 'Audit OWASP Top 10 : en-têtes, TLS, fichiers exposés, injections.',
    placeholder: 'https://example.com', targetHint: 'URL du site. Si vous omettez https://, il sera ajouté.' },
  { key: 'authenticated_web', label: 'Authentifié', hint: 'Tests derrière la connexion', icon: Lock,
    desc: "Tests avec une session connectée : IDOR, CSRF, JWT, contrôle d'accès.",
    placeholder: 'https://app.example.com', targetHint: "URL de l'application. Vous fournirez ci-dessous un compte de test." },
  { key: 'api', label: 'API', hint: 'OWASP API Top 10 (2023)', icon: Code,
    desc: "OWASP API Top 10 : découverte d'endpoints, CORS, limitation de débit.",
    placeholder: 'https://api.example.com', targetHint: "URL de base de l'API (ex. https://api.example.com ou https://example.com/api)." },
  { key: 'network', label: 'Réseau', hint: 'Hôtes, ports et services', icon: Network,
    desc: 'Ports ouverts et services exposés sur les ports les plus courants.',
    placeholder: 'example.com', targetHint: "Nom de domaine ou IP publique, plage CIDR (jusqu'à /24) ou plage d'IP (ex. 1.2.3.10-20). Adresses privées refusées." },
  { key: 'subdomain', label: 'Sous-domaines', hint: 'Découverte et takeover', icon: Layers,
    desc: 'Recense les sous-domaines et détecte les risques de prise de contrôle.',
    placeholder: 'example.com', targetHint: 'Nom de domaine racine, sans https:// (ex. example.com).' },
  { key: 'osint', label: 'OSINT', hint: 'WHOIS, DNS, emails, dorks', icon: Eye,
    desc: 'Reconnaissance non intrusive : sources publiques (DNS, WHOIS, archives, fuites) et visite des pages publiques. Aucun scan de ports.',
    placeholder: 'example.com', targetHint: 'Nom de domaine, sans https:// (ex. example.com).' },
  { key: 'cti', label: 'Threat Intel', hint: 'Réputation IP et domaine', icon: Radar,
    desc: 'Réputation et menaces connues associées à un domaine ou une IP.',
    placeholder: 'example.com', targetHint: 'Nom de domaine ou adresse IP.' },
]

// Vérifications effectuées par chaque scanner (liste informative, pas une progression)
export const SCAN_STEPS = {
  web: ['HTTPS et certificat TLS', 'En-têtes de sécurité', 'Cookies et CORS', 'Fichiers sensibles exposés',
    'Méthodes HTTP autorisées', "Injections SQL et XSS (paramètres d'URL)", 'Redirections ouvertes', 'Limitation de débit'],
  authenticated_web: ['Connexion avec le compte fourni', 'Sécurité de la session et des en-têtes', 'Robustesse du JWT',
    "Contrôle d'accès et IDOR", 'Protection CSRF', 'Exposition de données sensibles',
    'Mass assignment', 'Injection SQL et limitation de débit sur la connexion'],
  api: ['Découverte des endpoints et de la doc (Swagger/OpenAPI)', 'Audit de chaque endpoint', 'Politique CORS',
    'Limitation de débit', 'GraphQL', 'En-têtes de sécurité et méthodes HTTP'],
  network: ['Résolution de la cible', 'Scan des ports les plus courants', 'Identification des services exposés',
    'Services à risque (bases de données, Docker, Redis…)'],
  subdomain: ['Énumération des sous-domaines', 'Résolution DNS', 'Détection des risques de prise de contrôle'],
  osint: ['Enregistrements DNS publics', 'Informations exposées dans les sources publiques'],
  cti: ["Réputation du domaine ou de l'IP", 'Présence dans les listes de menaces connues'],
}

// Les dates de l'API sont en UTC sans fuseau : on force l'interprétation UTC
export const parseDate = (raw) => (raw ? new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : `${raw}Z`) : null)
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
  parseDate(d).toLocaleString('fr-FR', long
    ? { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })

export const apiError = (err, fallback) => {
  const d = err?.response?.data?.detail
  if (Array.isArray(d)) return d.map((e) => e.msg).join(' · ')
  return typeof d === 'string' ? d : fallback
}
