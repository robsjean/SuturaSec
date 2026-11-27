import { Link } from 'react-router-dom'
import { FileText, Globe, ShieldCheck, TriangleAlert, Zap } from 'lucide-react'

const FEATURES = [
  { icon: Globe, title: 'Scanners Web, API et réseau', text: 'OWASP Top 10, TLS, en-têtes, ports et services.' },
  { icon: Zap, title: 'Analyse par IA', text: "Résumé exécutif, chemins d'attaque et plan de remédiation priorisé." },
  { icon: FileText, title: 'Rapports PDF', text: 'Un rapport prêt à partager, avec scores CVSS et conformité.' },
]

export default function AuthLayout({ children }) {
  return (
    <div className="auth">
      <aside className="auth-aside">
        <Link className="brand" to="/login" style={{ padding: 0 }}>
          <ShieldCheck size={22} strokeWidth={1.8} aria-hidden="true" />
          SuturaSec
        </Link>
        <div className="stack" style={{ gap: 32 }}>
          <h2>Détectez les failles avant qu'elles ne soient exploitées.</h2>
          <ul>
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <li key={title}>
                <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                <div><b>{title}</b><span>{text}</span></div>
              </li>
            ))}
          </ul>
        </div>
        <p className="xs muted">OWASP Top 10 · PCI-DSS v4.0 · ISO/IEC 27001:2022 · RGPD</p>
      </aside>
      <main className="auth-main">{children}</main>
    </div>
  )
}

export function FormError({ children }) {
  if (!children) return null
  return (
    <div className="alert" role="alert">
      <TriangleAlert size={16} strokeWidth={1.8} aria-hidden="true" />
      <span>{children}</span>
    </div>
  )
}
