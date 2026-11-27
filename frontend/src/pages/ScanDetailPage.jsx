import { useCallback, useEffect, useState } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Check, ChevronRight, Download, Search, TriangleAlert } from 'lucide-react'
import Layout from '../components/Layout'
import { scansApi } from '../services/api'
import {
  SCAN_TYPE, SEVS, SEV_LABEL, STATUS, fmtDate, httpCls, riskBar, riskCls, riskLabel, scoreBar, sortBySeverity,
} from '../lib/scan'

/* ---------- Petits composants ---------- */

const Chev = () => <span className="chev"><ChevronRight size={16} strokeWidth={1.8} aria-hidden="true" /></span>

const Sev = ({ s }) => <span className={`sev ${s}`}>{SEV_LABEL[s] || s}</span>

const Empty = ({ children }) => <section className="card empty"><p>{children}</p></section>

function KV({ rows }) {
  return (
    <dl className="kv-list card-body" style={{ paddingTop: 8, paddingBottom: 8 }}>
      {rows.filter(Boolean).map(([k, v, cls]) => (
        <div key={k}><dt>{k}</dt><dd className={cls || ''}>{v ?? '—'}</dd></div>
      ))}
    </dl>
  )
}

const Card = ({ title, aside, children }) => (
  <section className="card">
    <div className="card-head"><h2>{title}</h2>{aside != null && <p>{aside}</p>}</div>
    {children}
  </section>
)

function SearchBox({ value, onChange, label }) {
  return (
    <label className="search">
      <Search size={14} strokeWidth={2} aria-hidden="true" />
      <input type="search" placeholder={label} aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  )
}

function Segmented({ value, onChange, options, label }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map(([v, text]) => (
        <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>{text}</button>
      ))}
    </div>
  )
}

/* ---------- Onglets ---------- */

function Overview({ scan, ai }) {
  if (!scan.summary && !ai.risk_narrative && !ai.quick_wins?.length) return <Empty>Aucune synthèse IA pour cette analyse.</Empty>
  return (
    <div className="stack">
      {scan.summary && (
        <section className="card card-pad stack-sm">
          <div className="row between"><h2>Résumé exécutif</h2><span className="tag">Généré par l'IA</span></div>
          <p className="t2" style={{ maxWidth: '75ch' }}>{scan.summary}</p>
        </section>
      )}
      {ai.risk_narrative && (
        <section className="card card-pad stack-sm">
          <h2>Analyse de risque</h2>
          <p className="t2" style={{ maxWidth: '75ch' }}>{ai.risk_narrative}</p>
        </section>
      )}
      {ai.quick_wins?.length > 0 && (
        <Card title="Actions rapides" aside="Corrections à fort impact et faible effort">
          <ul className="list">
            {ai.quick_wins.map((w, i) => (
              <li key={i}><Check className="check" size={18} strokeWidth={2} aria-hidden="true" /><span>{w}</span></li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

function Vulnerabilities({ vulns, count }) {
  const [sev, setSev] = useState('')
  const [q, setQ] = useState('')
  if (!vulns.length) {
    return (
      <section className="card empty">
        <Check size={40} strokeWidth={1.4} aria-hidden="true" />
        <h2>Aucune vulnérabilité détectée</h2>
        <p>Aucun constat n'a été remonté par cette analyse.</p>
      </section>
    )
  }
  const query = q.trim().toLowerCase()
  const visible = sortBySeverity(vulns).filter((v) =>
    (!sev || v.severity === sev) && (!query || `${v.title} ${v.category || ''}`.toLowerCase().includes(query)))

  return (
    <div className="stack">
      <div className="row between">
        <Segmented label="Filtrer par sévérité" value={sev} onChange={setSev}
                   options={[['', `Toutes · ${vulns.length}`], ...SEVS.filter((s) => count(s)).map((s) => [s, `${SEV_LABEL[s]} · ${count(s)}`])]} />
        <SearchBox value={q} onChange={setQ} label="Rechercher" />
      </div>
      <section className="card" aria-label="Liste des vulnérabilités">
        {visible.map((v, i) => (
          <details key={v.id} className="finding" open={i === 0 && (v.severity === 'critical' || v.severity === 'high')}>
            <summary>
              <Sev s={v.severity} />
              <div><div className="title">{v.title}</div>{v.category && <div className="sub">{v.category}</div>}</div>
              <span className="row" style={{ gap: 10 }}>
                {v.cvss_score != null && <span className="tag mono">CVSS {v.cvss_score.toFixed(1)}</span>}
                <Chev />
              </span>
            </summary>
            <div className="finding-body">
              {v.description && <p>{v.description}</p>}
              {v.evidence && <div><h4>Preuve technique</h4><div className="evidence">{v.evidence}</div></div>}
              {v.remediation && <div><h4>Remédiation</h4><p>{v.remediation}</p></div>}
              {v.attack_techniques?.length > 0 && (
                <div><h4>Techniques MITRE ATT&amp;CK</h4>
                  <div className="tags">
                    {v.attack_techniques.map((t, ti) => <span key={ti} className="tag mono">{t.id || t}{t.tactic ? ` · ${t.tactic}` : ''}</span>)}
                  </div>
                </div>
              )}
            </div>
          </details>
        ))}
        {visible.length === 0 && <p className="muted small" style={{ padding: 20 }}>Aucune vulnérabilité ne correspond au filtre.</p>}
      </section>
    </div>
  )
}

const PROBA = { high: 'élevée', medium: 'moyenne', low: 'faible' }

function AttackPaths({ paths }) {
  if (!paths?.length) return <Empty>Aucun chemin d'attaque modélisé pour cette analyse.</Empty>
  return (
    <div className="stack">
      <p className="small muted">Scénarios d'exploitation identifiés par l'IA à partir des vulnérabilités détectées.</p>
      {paths.map((ap, i) => (
        <section className="card" key={i}>
          <div className="card-head">
            <div className="stack-sm" style={{ gap: 2 }}>
              <h2>{ap.name || ap.title || `Scénario ${i + 1}`}</h2>
              {ap.probability && <p>Probabilité {PROBA[ap.probability] || ap.probability}</p>}
            </div>
            {ap.severity && <Sev s={ap.severity} />}
          </div>
          <div className="card-body grid-2" style={{ gap: 24 }}>
            <div className="stack">
              <p className="label">Étapes</p>
              <ol className="path">{(ap.steps || []).map((st, si) => <li key={si}>{st}</li>)}</ol>
            </div>
            <div className="stack">
              {ap.prerequisites && <div className="stack-sm"><p className="label">Prérequis</p><p className="small t2">{ap.prerequisites}</p></div>}
              {ap.impact && <div className="stack-sm"><p className="label">Impact</p><p className="small t2">{ap.impact}</p></div>}
              {ap.mitre_techniques?.length > 0 && (
                <div className="stack-sm"><p className="label">Techniques MITRE ATT&amp;CK</p>
                  <div className="tags">{ap.mitre_techniques.map((t, ti) => <span key={ti} className="tag mono">{t}</span>)}</div>
                </div>
              )}
            </div>
          </div>
        </section>
      ))}
    </div>
  )
}

function Remediation({ priorities }) {
  if (!priorities?.length) return <Empty>Aucune priorité de remédiation définie.</Empty>
  return (
    <Card title="Plan de remédiation priorisé" aside="Classé par impact sur le risque">
      <ol className="list">
        {priorities.map((p, i) => (
          <li key={i}>
            <span className="step-n">{p.rank || i + 1}</span>
            <div className="stack-sm" style={{ flex: 1 }}>
              <b style={{ fontWeight: 500 }}>{p.action}</b>
              {p.reason && <p className="small t2">{p.reason}</p>}
              <div className="row xs muted" style={{ gap: 16 }}>
                <span>Effort : {p.effort || '—'}</span>
                <span>Impact attendu : {p.impact_if_fixed || '—'}</span>
              </div>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  )
}

const CTRL = { pass: ['ok', 'Conforme'], fail: ['fail', 'Non conforme'], partial: ['warn', 'Partiel'], na: ['', 'N/A'] }

function Compliance({ report }) {
  const [idx, setIdx] = useState(0)
  if (!report) return <Empty>Rapport de conformité non disponible.</Empty>
  const fws = report.frameworks || []
  const fw = fws[idx]
  return (
    <div className="stack">
      <div>
        <h2>Rapport de conformité</h2>
        <p className="small muted">
          Score global <b className="num" style={{ color: 'var(--text)' }}>{report.global_score?.toFixed(0)} / 100</b> · note{' '}
          <b style={{ color: 'var(--text)' }}>{report.global_grade}</b>. {report.summary}
        </p>
      </div>
      <div className="grid-3" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))' }}>
        {fws.map((f, i) => (
          <button key={f.framework} type="button" className="card card-pad stack-sm fw-card" aria-pressed={idx === i} onClick={() => setIdx(i)}
                  style={idx === i ? { borderColor: 'var(--ink)', boxShadow: 'inset 0 0 0 1px var(--ink)' } : undefined}>
            <p className="small">{f.framework} {f.version}</p>
            <div className="score"><strong style={{ fontSize: 28 }}>{f.overall_score?.toFixed(0)}</strong><span>/ 100 · {f.grade}</span></div>
            <div className={`bar ${scoreBar(f.overall_score)}`}><span style={{ width: `${f.overall_score}%` }} /></div>
            <p className="xs muted">{f.passed} conformes · {f.partial || 0} partiels · {f.failed} non conformes</p>
          </button>
        ))}
      </div>
      {fw && (
        <section className="card">
          <div className="card-head">
            <div className="stack-sm" style={{ gap: 2 }}><h2>Contrôles · {fw.framework} {fw.version}</h2>{fw.compliance_statement && <p>{fw.compliance_statement}</p>}</div>
            <p>{(fw.controls || []).length} contrôles</p>
          </div>
          {(fw.controls || []).map((c) => {
            const [cls, label] = CTRL[c.status] || ['', c.status]
            return (
              <details key={c.id} className="finding" open={c.status === 'fail'}>
                <summary className="ctrl-sum">
                  <span className="mono muted">{c.id}</span>
                  <div><div className="title">{c.title}</div>{c.category && <div className="sub">{c.category}</div>}</div>
                  <span className="row" style={{ gap: 12 }}>
                    <span className="num small muted">{c.score != null ? `${c.score} %` : '—'}</span>
                    <span className={`tag ${cls}`}>{label}</span>
                    <Chev />
                  </span>
                </summary>
                <div className="finding-body" style={{ paddingLeft: 20 }}>
                  {c.requirement && <div><h4>Exigence du standard</h4><p>{c.requirement}</p></div>}
                  {c.evidence?.length > 0 && <div><h4>Preuves du scan</h4><ul className="evidence-list">{c.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
                  {c.impact && <div><h4>Impact business / légal</h4><p>{c.impact}</p></div>}
                  {c.status !== 'pass' && c.remediation?.length > 0 && (
                    <div><h4>Plan de remédiation</h4>
                      <ol style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>{c.remediation.map((r, i) => <li key={i}>{r}</li>)}</ol>
                    </div>
                  )}
                  {c.cwe_references?.length > 0 && (
                    <div><h4>Références CWE</h4>
                      <div className="tags">
                        {c.cwe_references.map((cwe) => (
                          <a key={cwe} className="tag mono" target="_blank" rel="noopener noreferrer"
                             href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}>{cwe}</a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </details>
            )
          })}
        </section>
      )}
    </div>
  )
}

const TI_CLS = { critical: 'c-critical', high: 'c-high', medium: 'c-medium', low: 'c-ok' }

function ThreatIntel({ ti }) {
  if (!ti) return <Empty>Données Threat Intelligence non disponibles.</Empty>
  const g = ti.geolocation || {}
  const d = ti.domain_info || {}
  const a = ti.abuse
  const bl = ti.blacklists || {}
  const dns = Object.entries(ti.dns_records || {})
  return (
    <div className="stack">
      <section className="stats">
        <div className="stat"><p>Score de menace</p><strong className={TI_CLS[ti.risk_level] || ''}>{ti.threat_score != null ? ti.threat_score.toFixed(1) : '—'}</strong><small>{SEV_LABEL[ti.risk_level] || '—'}</small></div>
        <div className="stat"><p>Adresse IP</p><strong className="mono" style={{ fontSize: 16, marginTop: 10 }}>{ti.ip || '—'}</strong><small>{ti.domain}</small></div>
        {a?.confidence_score !== undefined && <div className="stat"><p>Score d'abus</p><strong>{a.confidence_score} %</strong><small>{a.total_reports ?? 0} signalements</small></div>}
        <div className="stat"><p>Listes DNSBL</p><strong className={bl.listed > 0 ? 'c-critical' : ''}>{bl.listed ?? 0} / {bl.checked ?? 0}</strong><small>listes de blocage</small></div>
      </section>
      <div className="grid-2">
        {g.country && (
          <Card title="Géolocalisation et ASN">
            <KV rows={[
              ['Pays', `${g.country}${g.country_code ? ` (${g.country_code})` : ''}`],
              ['Ville / Région', [g.city, g.region].filter(Boolean).join(', ') || '—'],
              ['ISP / Org', g.org || g.isp],
              ['ASN', g.asn, 'mono'],
              ['Fuseau horaire', g.timezone],
              ['Datacenter / Hosting', g.is_hosting ? 'Oui' : 'Non'],
            ]} />
          </Card>
        )}
        <Card title="Domaine (RDAP)">
          <KV rows={[
            ['Domaine', ti.domain, 'mono'],
            ['Registrar', d.registrar],
            ['Création', d.creation_date],
            ['Expiration', d.expiry_date],
            d.age_days !== undefined && ['Ancienneté', `${d.age_days} jours`, d.age_days < 30 ? 'c-critical' : d.age_days < 180 ? 'c-medium' : ''],
            d.status?.length > 0 && ['Statut', d.status.join(', '), 'mono xs'],
          ]} />
        </Card>
        {a?.confidence_score !== undefined && (
          <Card title="AbuseIPDB">
            <KV rows={[
              ['Score de confiance', `${a.confidence_score} %`, a.confidence_score >= 50 ? 'c-critical' : ''],
              ['Signalements', a.total_reports ?? 0],
              a.last_reported && ['Dernier signalement', a.last_reported],
              a.usage_type && ["Type d'usage", a.usage_type],
              ['Nœud Tor', a.is_tor ? 'Oui' : 'Non'],
            ]} />
          </Card>
        )}
        <Card title="Listes de blocage DNSBL" aside={`${bl.listed ?? 0} sur ${bl.checked ?? 0}`}>
          <div className="table-wrap"><table><tbody>
            {(bl.hits || []).map((h) => (
              <tr key={h.name}><td className="mono">{h.name}</td><td className="r"><span className={`tag ${h.listed ? 'fail' : 'ok'}`}>{h.listed ? 'Listée' : 'Propre'}</span></td></tr>
            ))}
          </tbody></table></div>
        </Card>
      </div>
      <Card title="Enregistrements DNS">
        <div className="table-wrap"><table>
          <thead><tr><th style={{ width: 90 }}>Type</th><th>Valeur(s)</th></tr></thead>
          <tbody>
            {dns.map(([t, recs]) => <tr key={t}><td className="mono">{t}</td><td className="mono" style={{ overflowWrap: 'anywhere' }}>{[].concat(recs).join(', ')}</td></tr>)}
            {dns.length === 0 && <tr><td colSpan={2} className="muted">Aucun enregistrement DNS récupéré.</td></tr>}
          </tbody>
        </table></div>
      </Card>
    </div>
  )
}

const SRC = { 'crt.sh': 'crt.sh', crtsh: 'crt.sh', hackertarget: 'HackerTarget', bruteforce: 'Brute-force', dns_records: 'DNS', zone_transfer: 'Zone transfer' }

function Subdomains({ sub }) {
  const [filter, setFilter] = useState('')
  const [q, setQ] = useState('')
  if (!sub) return <Empty>Données de sous-domaines non disponibles.</Empty>
  const all = sub.subdomains || []
  const takeovers = all.filter((s) => s.takeover_risk)
  const query = q.trim().toLowerCase()
  const visible = all.filter((s) =>
    (!query || s.subdomain.toLowerCase().includes(query)) &&
    (filter !== 'active' || s.status_code != null) &&
    (filter !== 'takeover' || s.takeover_risk))
  const src = sub.sources || {}
  return (
    <div className="stack">
      {takeovers.length > 0 && (
        <div className="note warn">
          <TriangleAlert size={16} strokeWidth={1.8} aria-hidden="true" />
          <span>{takeovers.length} sous-domaine(s) exposé(s) à une prise de contrôle : {takeovers.map((s) => s.subdomain + (s.takeover_service ? ` (${s.takeover_service})` : '')).join(', ')}.</span>
        </div>
      )}
      <div className="row xs muted" style={{ gap: 8 }}>
        Sources :
        <span className="tag">crt.sh · {src.crtsh ?? 0}</span>
        <span className="tag">HackerTarget · {src.hackertarget ?? 0}</span>
        <span className="tag">Brute-force · {src.bruteforce ?? 0}</span>
        <span className="tag">DNS · {src.dns_records ?? 0}</span>
        <span className={`tag ${sub.zone_transfer_vulnerable ? 'fail' : ''}`}>Zone transfer (AXFR) · {sub.zone_transfer_vulnerable ? 'vulnérable' : 'refusé'}</span>
        <span className={`tag ${sub.wildcard_detected ? 'warn' : ''}`}>Wildcard · {sub.wildcard_detected ? (sub.wildcard_ips || []).join(', ') : 'non détecté'}</span>
      </div>
      <section className="card">
        <div className="card-head">
          <h2>Sous-domaines découverts</h2>
          <div className="row">
            <Segmented label="Filtrer" value={filter} onChange={setFilter} options={[['', 'Tous'], ['active', 'Actifs'], ['takeover', 'Takeover']]} />
            <SearchBox value={q} onChange={setQ} label="Filtrer" />
          </div>
        </div>
        <div className="table-wrap"><table style={{ minWidth: 820 }}>
          <thead><tr><th>Sous-domaine</th><th>HTTP</th><th>IP</th><th>Titre</th><th>Source</th><th className="r">Risque</th></tr></thead>
          <tbody>
            {visible.map((s, i) => (
              <tr key={i}>
                <td>{s.status_code != null
                  ? <a className="target" target="_blank" rel="noopener noreferrer" href={`${s.https ? 'https' : 'http'}://${s.subdomain}`}>{s.subdomain}</a>
                  : <span className="mono">{s.subdomain}</span>}</td>
                <td>{s.status_code != null ? <span className={`tag mono ${httpCls(s.status_code)}`}>{s.https ? 'TLS · ' : ''}{s.status_code}</span> : <span className="muted">—</span>}</td>
                <td className="mono">{(s.ips || []).slice(0, 2).join(', ') + (s.ips?.length > 2 ? ` +${s.ips.length - 2}` : '') || '—'}</td>
                <td title={s.title || ''}>{s.title ? s.title.slice(0, 60) + (s.title.length > 60 ? '…' : '') : '—'}</td>
                <td className="muted">{SRC[s.source] || s.source || '—'}</td>
                <td className="r">{s.takeover_risk && <span className="tag fail" title={s.takeover_service || ''}>Takeover</span>}</td>
              </tr>
            ))}
            {visible.length === 0 && <tr><td colSpan={6} className="muted" style={{ textAlign: 'center', padding: 32 }}>Aucun sous-domaine ne correspond au filtre.</td></tr>}
          </tbody>
        </table></div>
      </section>
    </div>
  )
}

const size = (b) => (b ? (b > 1024 ? `${(b / 1024).toFixed(1)} Ko` : `${b} o`) : '—')

function Api({ api, criticals }) {
  const [q, setQ] = useState('')
  if (!api) return <Empty>Données API non disponibles.</Empty>
  const eps = (api.endpoints_found || []).filter((e) => !q || (e.path || '').includes(q))
  return (
    <div className="stack">
      <section className="stats">
        <div className="stat"><p>Endpoints</p><strong>{api.total_endpoints ?? 0}</strong><small>découverts</small></div>
        <div className="stat"><p>Critiques</p><strong className={criticals > 0 ? 'c-critical' : ''}>{criticals}</strong><small>constats</small></div>
        <div className="stat"><p>Swagger / OpenAPI</p><strong style={{ fontSize: 18, marginTop: 10 }}>{api.swagger_found ? 'Trouvé' : 'Absent'}</strong><small className="mono">{api.swagger_url || ''}</small></div>
        <div className="stat"><p>GraphQL</p><strong style={{ fontSize: 18, marginTop: 10 }} className={api.graphql_found ? 'c-medium' : ''}>{api.graphql_found ? 'Détecté' : 'Absent'}</strong></div>
      </section>
      <section className="card card-pad stack-sm">
        <h2>Couverture OWASP API Top 10 (2023)</h2>
        {api.owasp_coverage?.length ? <div className="tags">{api.owasp_coverage.map((c) => <span key={c} className="tag fail">{c}</span>)}</div>
          : <p className="small muted">Aucune catégorie en échec.</p>}
      </section>
      <section className="card">
        <div className="card-head"><h2>Endpoints découverts</h2><SearchBox value={q} onChange={setQ} label="Filtrer par chemin" /></div>
        <div className="table-wrap"><table style={{ minWidth: 640 }}>
          <thead><tr><th>Méthode</th><th>Endpoint</th><th>Statut</th><th className="r">Taille</th><th className="r">Latence</th></tr></thead>
          <tbody>
            {eps.map((ep, i) => (
              <tr key={i}>
                <td><span className="tag mono">{ep.method || 'GET'}</span></td>
                <td className="mono" style={{ color: 'var(--text)' }}>{ep.path || ep.url}</td>
                <td><span className={`tag mono ${httpCls(ep.status_code)}`}>{ep.status_code ?? '—'}</span></td>
                <td className="r num">{size(ep.response_size)}</td>
                <td className="r num">{ep.response_time_ms ? `${ep.response_time_ms} ms` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </section>
    </div>
  )
}

const sslCls = (d) => (d == null ? '' : d <= 30 ? 'c-critical' : d <= 90 ? 'c-medium' : '')

function Osint({ o }) {
  if (!o) return <Empty>Données OSINT non disponibles.</Empty>
  const ssl = o.ssl_cert || {}
  const wh = o.whois || {}
  const asn = o.asn_info || {}
  const tech = o.technologies || {}
  const dnsTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'].filter((t) => (o.dns_records?.[t] || []).length)
  return (
    <div className="stack">
      <section className="stats">
        <div className="stat"><p>Emails exposés</p><strong>{o.emails_found?.length ?? 0}</strong><small>trouvés publiquement</small></div>
        <div className="stat"><p>Fuites de données</p><strong className={o.breach_data?.breaches_found > 0 ? 'c-critical' : ''}>{o.breach_data?.breaches_found ?? 0}</strong><small>breaches connues</small></div>
        <div className="stat"><p>Exposition GitHub</p><strong className={o.github_exposure?.leaks_found > 0 ? 'c-medium' : ''}>{o.github_exposure?.leaks_found ?? 0}</strong><small>résultats sensibles</small></div>
        <div className="stat"><p>Certificat TLS</p><strong className={sslCls(ssl.days_remaining)}>{ssl.days_remaining != null ? `${ssl.days_remaining} j` : '—'}</strong><small>avant expiration</small></div>
      </section>
      <div className="grid-2">
        <Card title="WHOIS / Domaine"><KV rows={[['Registrar', wh.registrar], ['Organisation', wh.registrant_org], ['Création', (wh.created || '—').slice(0, 10)], ['Expiration', (wh.expires || '—').slice(0, 10)]]} /></Card>
        <Card title="Certificat SSL/TLS"><KV rows={[
          ['Sujet', ssl.subject, 'mono'], ['Émetteur', ssl.issuer],
          ['Expire dans', ssl.days_remaining != null ? `${ssl.days_remaining} jours` : '—', sslCls(ssl.days_remaining)],
          ['Auto-signé', ssl.is_self_signed == null ? '—' : ssl.is_self_signed ? 'Oui' : 'Non', ssl.is_self_signed ? 'c-critical' : ''],
        ]} /></Card>
        <Card title="Infrastructure"><KV rows={[['Adresses IP', (o.ip_addresses || []).join(', ') || '—', 'mono'], ['ASN', asn.asn, 'mono'], ['Organisation', asn.org], ['Pays', asn.country || o.geo_info?.country]]} /></Card>
        <Card title="Technologies détectées"><KV rows={[
          ['Serveur', tech.server, 'mono'], ['X-Powered-By', tech.powered_by, 'mono'], ['CMS', tech.cms],
          tech.frameworks?.length > 0 && ['Frameworks', tech.frameworks.join(', ')],
        ]} /></Card>
      </div>
      {dnsTypes.length > 0 && (
        <Card title="Enregistrements DNS">
          <div className="table-wrap"><table>
            <thead><tr><th style={{ width: 90 }}>Type</th><th>Valeur(s)</th></tr></thead>
            <tbody>{dnsTypes.map((t) => <tr key={t}><td className="mono">{t}</td><td className="mono" style={{ overflowWrap: 'anywhere' }}>{o.dns_records[t].join(', ')}</td></tr>)}</tbody>
          </table></div>
        </Card>
      )}
      <div className="grid-2">
        <Card title="Emails exposés" aside={o.emails_found?.length ?? 0}>
          {o.emails_found?.length
            ? <ul className="list">{o.emails_found.map((e) => <li key={e} style={{ padding: '10px 20px' }}><span className="mono small">{e}</span></li>)}</ul>
            : <p className="card-body small muted">Aucun email trouvé publiquement.</p>}
          {o.breach_data?.breach_names?.length > 0 && (
            <div className="card-body" style={{ borderTop: '1px solid var(--border)' }}>
              <p className="xs muted" style={{ marginBottom: 6 }}>Fuites connues</p>
              <div className="tags">{o.breach_data.breach_names.map((b) => <span key={b} className="tag fail">{b}</span>)}</div>
            </div>
          )}
        </Card>
        <Card title="Ports ouverts" aside={o.open_ports?.length ?? 0}>
          <div className="card-body">
            {o.open_ports?.length
              ? <div className="tags">{o.open_ports.map((p) => <span key={p} className="tag warn mono">{p}</span>)}</div>
              : <p className="small muted">Aucun port ouvert détecté.</p>}
            {o.github_exposure?.sample_repos?.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <p className="xs muted" style={{ marginBottom: 6 }}>Dépôts GitHub mentionnant le domaine</p>
                <div className="tags">{o.github_exposure.sample_repos.map((r) => <span key={r} className="tag mono">{r}</span>)}</div>
              </div>
            )}
          </div>
        </Card>
      </div>
      {o.recommended_dorks?.length > 0 && (
        <Card title="Google Dorks recommandés" aside="Recherches à lancer manuellement">
          <ul className="list">
            {o.recommended_dorks.map((d) => (
              <li key={d} style={{ padding: '10px 20px', alignItems: 'center' }}>
                <code style={{ flex: 1, overflowWrap: 'anywhere' }}>{d}</code>
                <a className="small" target="_blank" rel="noopener noreferrer" href={`https://www.google.com/search?q=${encodeURIComponent(d)}`}>Ouvrir</a>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

/* ---------- Page ---------- */

function tabsFor(scan) {
  const t = scan.scan_type
  const ai = scan.attack_paths || {}
  const tabs = [{ key: 'overview', label: 'Aperçu' }]
  if (t === 'cti') tabs.push({ key: 'threat_intel', label: 'Threat Intel' })
  if (t === 'subdomain') tabs.push({ key: 'subdomains', label: 'Sous-domaines', count: scan.subdomain_results?.total_found })
  if (t === 'api') tabs.push({ key: 'api', label: 'Endpoints', count: scan.api_results?.total_endpoints })
  if (t === 'osint') tabs.push({ key: 'osint', label: 'OSINT' })
  tabs.push({ key: 'vulns', label: 'Vulnérabilités', count: scan.vulnerabilities?.length ?? 0 })
  if (scan.compliance_reports && ['web', 'network', 'authenticated_web'].includes(t)) tabs.push({ key: 'compliance', label: 'Conformité' })
  if (t !== 'cti' && t !== 'osint') {
    tabs.push({ key: 'attacks', label: "Chemins d'attaque", count: ai.attack_paths?.length ?? 0 })
    tabs.push({ key: 'remediation', label: 'Remédiation', count: ai.top_priorities?.length ?? 0 })
  }
  return tabs
}

function duration(scan) {
  if (!scan.completed_at) return ''
  const sec = Math.max(0, Math.round((new Date(scan.completed_at) - new Date(scan.created_at)) / 1000))
  return sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${String(sec % 60).padStart(2, '0')} s`
}

export default function ScanDetailPage() {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchScan = useCallback(async () => {
    try {
      const res = await scansApi.get(id)
      setScan(res.data)
    } catch {
      setScan(null)
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => { setLoading(true); fetchScan() }, [fetchScan])

  const running = scan?.status === 'running' || scan?.status === 'pending'
  useEffect(() => {
    if (!running) return
    const t = setInterval(fetchScan, 3000)
    return () => clearInterval(t)
  }, [running, fetchScan])

  const tabs = scan ? tabsFor(scan) : []
  const hash = location.hash.slice(1)
  const active = tabs.some((t) => t.key === hash) ? hash : 'overview'
  const setTab = (key) => navigate({ hash: key }, { replace: true })

  const openReport = () => {
    const token = localStorage.getItem('token')
    window.open(`/scans/${id}/report?token=${encodeURIComponent(token)}`, '_blank', 'noopener')
  }

  const T = scan && SCAN_TYPE[scan.scan_type]
  const st = scan && (STATUS[scan.status] || { label: scan.status, dot: '' })
  const vulns = scan?.vulnerabilities || []
  const count = (s) => vulns.filter((v) => v.severity === s).length
  const ai = scan?.attack_paths || {}
  const sub = scan?.subdomain_results
  const dur = scan ? duration(scan) : ''

  return (
    <Layout>
      <div className="stack" style={{ gap: 24 }}>
        <nav className="crumbs" aria-label="Fil d'Ariane">
          <Link to="/dashboard">Analyses</Link><span aria-hidden="true">/</span>
          <span style={{ color: 'var(--text)' }}>{scan?.target || '…'}</span>
        </nav>

        {loading && <div className="loading"><span className="spinner" aria-hidden="true" />Chargement de l'analyse…</div>}

        {!loading && !scan && (
          <div className="card empty">
            <h2>Analyse introuvable</h2>
            <p>Elle a peut-être été supprimée.</p>
            <Link className="btn" to="/dashboard" style={{ marginTop: 8 }}>Retour au tableau de bord</Link>
          </div>
        )}

        {!loading && scan && (
          <>
            <header className="page-head" style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <h1 className="mono" style={{ fontFamily: 'var(--mono)', fontSize: 22, overflowWrap: 'anywhere' }}>{scan.target}</h1>
                <div className="meta">
                  <span className="type">{T && <T.icon size={14} strokeWidth={1.8} aria-hidden="true" />}Analyse {T?.label || scan.scan_type}</span>
                  <span className="status"><span className={`dot ${st.dot}`} />{st.label}</span>
                  <span>{fmtDate(scan.created_at, true)}</span>
                  {dur && <span>Durée {dur}</span>}
                </div>
              </div>
              {scan.status === 'completed' && (
                <div className="actions">
                  <button className="btn btn-ink" type="button" onClick={openReport}>
                    <Download size={16} strokeWidth={2} aria-hidden="true" />
                    Rapport PDF
                  </button>
                </div>
              )}
            </header>

            {running && (
              <section className="card card-pad stack" style={{ gap: 16 }} aria-live="polite">
                <div className="row"><span className="spinner" aria-hidden="true" />
                  <h2>{scan.status === 'running' ? 'Analyse en cours' : 'Analyse en attente de démarrage'}</h2></div>
                <div className="bar"><span style={{ width: '40%', background: 'var(--accent)' }} /></div>
                <p className="small muted">Les résultats s'afficheront automatiquement. Vous pouvez quitter cette page : l'analyse continue.</p>
              </section>
            )}

            {scan.status === 'failed' && (
              <section className="card card-pad stack">
                <div className="note fail" role="alert">
                  <TriangleAlert size={16} strokeWidth={1.8} aria-hidden="true" />
                  <div><b style={{ fontWeight: 600 }}>L'analyse n'a pas pu aboutir.</b><br />Vérifiez que la cible est correcte et accessible, puis relancez une analyse.</div>
                </div>
                <div className="actions"><Link className="btn btn-primary" to={`/dashboard?scan=${scan.scan_type}`}>Relancer une analyse</Link></div>
              </section>
            )}

            {scan.status === 'completed' && (
              <>
                {scan.scan_type === 'subdomain' ? (
                  <section className="stats" aria-label="Synthèse">
                    <div className="stat"><p>Sous-domaines</p><strong>{sub?.total_found ?? '—'}</strong><small>découverts</small></div>
                    <div className="stat"><p>Actifs HTTP</p><strong>{sub?.summary?.active_http ?? '—'}</strong><small>répondent</small></div>
                    <div className="stat"><p>Takeover</p><strong className={sub?.summary?.takeover_risks > 0 ? 'c-critical' : ''}>{sub?.summary?.takeover_risks ?? 0}</strong><small>à corriger</small></div>
                    <div className="stat"><p>Dev exposés</p><strong className={sub?.summary?.dev_exposed > 0 ? 'c-medium' : ''}>{sub?.summary?.dev_exposed ?? 0}</strong><small>environnements</small></div>
                  </section>
                ) : (
                  <section className="grid-2" aria-label="Synthèse">
                    <div className="card card-pad stack" style={{ gap: 12 }}>
                      <p className="small muted">Score de risque</p>
                      <div className="score">
                        <strong className={riskCls(scan.risk_score)}>{scan.risk_score != null ? scan.risk_score.toFixed(1) : '—'}</strong>
                        <span>/ 10{scan.risk_score != null ? ` · ${riskLabel(scan.risk_score)}` : ''}</span>
                      </div>
                      <div className={`bar ${riskBar(scan.risk_score)}`}><span style={{ width: `${(scan.risk_score || 0) * 10}%` }} /></div>
                    </div>
                    <div className="card card-pad stack" style={{ gap: 14 }}>
                      <div className="row between"><p className="small muted">Vulnérabilités par sévérité</p><b className="num">{vulns.length}</b></div>
                      {vulns.length > 0 && (
                        <div className="stacked" aria-hidden="true">
                          {SEVS.map((s) => count(s) > 0 && (
                            <span key={s} style={{ width: `${(count(s) / vulns.length) * 100}%`, background: `var(--${s === 'info' ? 'border-strong' : s})` }} />
                          ))}
                        </div>
                      )}
                      <dl className="legend">
                        {SEVS.map((s) => <div key={s}><dt>{SEV_LABEL[s]}</dt><dd>{count(s)}</dd></div>)}
                      </dl>
                    </div>
                  </section>
                )}

                <nav className="tabs" role="tablist" aria-label="Sections de l'analyse">
                  {tabs.map((t) => (
                    <a key={t.key} href={`#${t.key}`} role="tab" aria-selected={active === t.key} aria-current={active === t.key ? 'page' : undefined}
                       onClick={(e) => { e.preventDefault(); setTab(t.key) }}>
                      <span>{t.label}</span>
                      {t.count != null && <span className="count">{t.count}</span>}
                    </a>
                  ))}
                </nav>

                {active === 'overview' && <Overview scan={scan} ai={ai} />}
                {active === 'vulns' && <Vulnerabilities vulns={vulns} count={count} />}
                {active === 'attacks' && <AttackPaths paths={ai.attack_paths} />}
                {active === 'remediation' && <Remediation priorities={ai.top_priorities} />}
                {active === 'compliance' && <Compliance report={scan.compliance_reports} />}
                {active === 'threat_intel' && <ThreatIntel ti={scan.threat_intel} />}
                {active === 'subdomains' && <Subdomains sub={sub} />}
                {active === 'api' && <Api api={scan.api_results} criticals={count('critical')} />}
                {active === 'osint' && <Osint o={scan.osint_results} />}
              </>
            )}
          </>
        )}
      </div>
    </Layout>
  )
}
