import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Plus, RefreshCw, Search, ShieldCheck, Trash2 } from 'lucide-react'
import Layout from '../components/Layout'
import NewScanDialog from '../components/NewScanDialog'
import { scansApi } from '../services/api'
import { SCAN_TYPES, SCAN_TYPE, STATUS, fmtDate, riskCls, scoreBar } from '../lib/scan'

const FRAMEWORKS = [['OWASP Top 10', 'OWASP Top 10'], ['PCI-DSS', 'PCI-DSS'], ['ISO 27001', 'ISO 27001'], ['RGPD', 'GDPR']]
const SEV_ROWS = [['critical', 'Critique', 'critical_count'], ['high', 'Élevée', 'high_count'], ['medium', 'Moyenne', 'medium_count'], ['low', 'Faible', 'low_count']]

function findings(s) {
  if (s.status !== 'completed') return '—'
  if (s.scan_type === 'subdomain') return `${s.subdomain_count ?? '—'} sous-domaines`
  if (s.scan_type === 'api') return `${s.api_endpoint_count ?? '—'} endpoints`
  return s.vuln_count ?? 0
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [dialogType, setDialogType] = useState(null)
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [frameworks, setFrameworks] = useState(null)

  const fetchScans = useCallback(async () => {
    try {
      const res = await scansApi.list()
      setScans(res.data)
    } catch {
      /* l'intercepteur gère la session expirée */
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchScans() }, [fetchScans])

  // Rafraîchit tant qu'une analyse est en cours
  const hasRunning = scans.some((s) => s.status === 'running' || s.status === 'pending')
  useEffect(() => {
    if (!hasRunning) return
    const t = setInterval(fetchScans, 5000)
    return () => clearInterval(t)
  }, [hasRunning, fetchScans])

  // Ouverture depuis la barre latérale : /dashboard?scan=api
  useEffect(() => {
    const t = params.get('scan')
    if (t) {
      setDialogType(SCAN_TYPE[t] ? t : 'web')
      setParams({}, { replace: true })
    }
  }, [params, setParams])

  const completed = useMemo(() => scans.filter((s) => s.status === 'completed'), [scans])
  const complianceScan = scans.find((s) => s.compliance_score != null) || null
  const sum = (f) => completed.reduce((a, s) => a + (s[f] || 0), 0)

  useEffect(() => {
    if (!complianceScan) return
    scansApi.get(complianceScan.id)
      .then((r) => setFrameworks(r.data.compliance_reports?.frameworks || null))
      .catch(() => {})
  }, [complianceScan?.id])

  const sevRows = SEV_ROWS.map(([key, label, f]) => ({ key, label, n: sum(f) }))
  const sevMax = Math.max(1, ...sevRows.map((r) => r.n))
  const riskRows = completed.filter((s) => s.risk_score != null).slice(0, 10)

  const q = query.trim().toLowerCase()
  const filtered = scans.filter((s) => (!q || s.target.toLowerCase().includes(q)) && (!typeFilter || s.scan_type === typeFilter))

  const handleDelete = async (scan, e) => {
    e.stopPropagation()
    if (!confirm('Supprimer cette analyse ? Cette action est irréversible.')) return
    await scansApi.delete(scan.id)
    setScans((prev) => prev.filter((s) => s.id !== scan.id))
  }

  return (
    <Layout>
      <div className="stack" style={{ gap: 28 }}>
        <header className="page-head">
          <div>
            <h1>Tableau de bord</h1>
            <p>Vue d'ensemble de vos analyses de sécurité.</p>
          </div>
          <button className="btn btn-primary" type="button" onClick={() => setDialogType('web')}>
            <Plus size={16} strokeWidth={2} aria-hidden="true" />
            Nouvelle analyse
          </button>
        </header>

        <section className="stats" aria-label="Indicateurs">
          <div className="stat"><p>Analyses</p><strong>{scans.length}</strong><small>lancées au total</small></div>
          <div className="stat"><p>En cours</p><strong>{scans.filter((s) => s.status === 'running' || s.status === 'pending').length}</strong><small>en exécution</small></div>
          <div className="stat"><p>Vulnérabilités</p><strong>{sum('vuln_count')}</strong><small>sur les analyses terminées</small></div>
          <div className="stat"><p>Critiques</p><strong className={sum('critical_count') > 0 ? 'c-critical' : ''}>{sum('critical_count')}</strong><small>à corriger en priorité</small></div>
        </section>

        {completed.length > 0 && (
          <div className="grid-2">
            <section className="card" aria-labelledby="bysev">
              <div className="card-head"><h2 id="bysev">Par sévérité</h2><p>Analyses terminées</p></div>
              <div className="card-body sev-rows">
                {sevRows.map((s) => (
                  <div className="sev-row" key={s.key}>
                    <span className={`sev ${s.key}`}>{s.label}</span>
                    <div className={`bar ${s.key}`}><span style={{ width: `${(s.n / sevMax) * 100}%` }} /></div>
                    <span className="r num">{s.n}</span>
                  </div>
                ))}
              </div>
            </section>
            <section className="card" aria-labelledby="risk">
              <div className="card-head"><h2 id="risk">Scores de risque</h2><p>10 dernières analyses</p></div>
              <div className="card-body score-bars">
                {riskRows.length === 0 && <p className="small muted">Aucun score disponible.</p>}
                {riskRows.map((s) => {
                  const cls = s.risk_score >= 7 ? 'critical' : s.risk_score >= 4 ? 'medium' : 'ok'
                  return (
                    <Link key={s.id} className="score-bar" to={`/scans/${s.id}`} style={{ color: 'inherit' }}>
                      <span className="name" title={s.target}>{s.target.replace(/^https?:\/\//, '')}</span>
                      <div className={`bar ${cls}`}><span style={{ width: `${s.risk_score * 10}%` }} /></div>
                      <b className={`r num c-${cls}`} style={{ fontWeight: 500 }}>{s.risk_score.toFixed(1)}</b>
                    </Link>
                  )
                })}
              </div>
            </section>
          </div>
        )}

        {complianceScan && (
          <section className="card" aria-labelledby="comp">
            <div className="card-head">
              <div className="stack-sm" style={{ gap: 2 }}>
                <h2 id="comp">Conformité</h2>
                <p className="mono">Dernière analyse · {complianceScan.target}</p>
              </div>
              <Link className="small" to={`/scans/${complianceScan.id}#compliance`}>
                Score {complianceScan.compliance_score.toFixed(0)} / 100 · note {complianceScan.compliance_grade || '—'}
              </Link>
            </div>
            <div className="card-body grid-2" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))' }}>
              {FRAMEWORKS.map(([label, key]) => {
                const fw = (frameworks || []).find((f) => f.framework === key)
                const score = fw ? fw.overall_score : null
                return (
                  <div className="stack-sm" style={{ gap: 6 }} key={label}>
                    <div className="row between small"><span className="t2">{label}</span><b className="num">{score == null ? '—' : `${score.toFixed(0)} %`}</b></div>
                    <div className={`bar ${scoreBar(score)}`}><span style={{ width: `${score || 0}%` }} /></div>
                  </div>
                )
              })}
            </div>
          </section>
        )}

        <section className="card" aria-labelledby="hist">
          <div className="card-head">
            <h2 id="hist">Historique des analyses</h2>
            <div className="row">
              <label className="search">
                <Search size={14} strokeWidth={2} aria-hidden="true" />
                <input type="search" placeholder="Rechercher une cible" aria-label="Rechercher une cible" value={query} onChange={(e) => setQuery(e.target.value)} />
              </label>
              <label className="sr-only" htmlFor="ftype">Filtrer par type</label>
              <select id="ftype" className="input" style={{ minHeight: 36, width: 'auto', padding: '0 10px', fontSize: 13 }}
                      value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                <option value="">Tous les types</option>
                {SCAN_TYPES.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}
              </select>
              <button className="btn btn-ghost icon-btn" type="button" onClick={fetchScans} aria-label="Actualiser">
                <RefreshCw size={16} strokeWidth={1.8} aria-hidden="true" />
              </button>
            </div>
          </div>

          {loading ? (
            <div className="loading"><span className="spinner" aria-hidden="true" />Chargement…</div>
          ) : scans.length === 0 ? (
            <div className="empty">
              <ShieldCheck size={40} strokeWidth={1.4} aria-hidden="true" />
              <h2>Aucune analyse pour l'instant</h2>
              <p style={{ maxWidth: '44ch' }}>Lancez une première analyse sur un site, une API, un domaine ou une plage réseau que vous êtes autorisé à tester.</p>
              <button className="btn btn-primary" type="button" style={{ marginTop: 8 }} onClick={() => setDialogType('web')}>Nouvelle analyse</button>
            </div>
          ) : (
            <div className="table-wrap">
              <table style={{ minWidth: 760 }}>
                <thead>
                  <tr><th>Cible</th><th>Type</th><th>Statut</th><th>Constats</th><th className="r">Risque</th><th className="r">Date</th><th><span className="sr-only">Actions</span></th></tr>
                </thead>
                <tbody>
                  {filtered.map((s) => {
                    const T = SCAN_TYPE[s.scan_type]
                    const st = STATUS[s.status] || { label: s.status, dot: '' }
                    return (
                      <tr key={s.id} className="row-link" onClick={() => navigate(`/scans/${s.id}`)}>
                        <td><Link className="target" to={`/scans/${s.id}`} onClick={(e) => e.stopPropagation()}>{s.target}</Link></td>
                        <td><span className="type">{T && <T.icon size={14} strokeWidth={1.8} aria-hidden="true" />}{T?.label || s.scan_type}</span></td>
                        <td><span className="status"><span className={`dot ${st.dot}`} />{st.label}</span></td>
                        <td className="num">{findings(s)}</td>
                        <td className="r num"><b style={{ fontWeight: 500 }} className={riskCls(s.risk_score)}>{s.risk_score != null ? s.risk_score.toFixed(1) : '—'}</b></td>
                        <td className="r num muted">{fmtDate(s.created_at)}</td>
                        <td className="r">
                          <button className="btn btn-ghost icon-btn row-actions" type="button" onClick={(e) => handleDelete(s, e)} aria-label={`Supprimer l'analyse ${s.target}`}>
                            <Trash2 size={15} strokeWidth={1.8} aria-hidden="true" />
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                  {filtered.length === 0 && (
                    <tr><td colSpan={7} className="muted" style={{ textAlign: 'center', padding: 32 }}>Aucune analyse ne correspond à la recherche.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {dialogType && (
        <NewScanDialog
          initialType={dialogType}
          onClose={() => setDialogType(null)}
          onCreated={(scan) => navigate(`/scans/${scan.id}`)}
        />
      )}
    </Layout>
  )
}
