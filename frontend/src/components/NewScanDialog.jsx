import { useEffect, useRef, useState } from 'react'
import { TriangleAlert, X } from 'lucide-react'
import { scansApi } from '../services/api'
import { SCAN_TYPES, SCAN_TYPE, apiError } from '../lib/scan'

const EMPTY_AUTH = { login_identifier: '', password: '', login_url: '', provided_token: '' }

export default function NewScanDialog({ initialType = 'web', onClose, onCreated }) {
  const [type, setType] = useState(SCAN_TYPE[initialType] ? initialType : 'web')
  const [target, setTarget] = useState('')
  const [auth, setAuth] = useState(EMPTY_AUTH)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const targetRef = useRef(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose

  useEffect(() => {
    const previous = document.activeElement
    targetRef.current?.focus()
    const onKey = (e) => e.key === 'Escape' && closeRef.current()
    window.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
      previous?.focus?.()
    }
  }, [])

  const setA = (k) => (e) => setAuth({ ...auth, [k]: e.target.value })

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!target.trim()) return setError('Indiquez une cible.')
    let auth_config = null
    if (type === 'authenticated_web') {
      if (!auth.provided_token && (!auth.login_identifier || !auth.password)) {
        return setError("Renseignez l'identifiant et le mot de passe, ou un jeton d'accès.")
      }
      auth_config = {
        login_identifier: auth.login_identifier || 'token',
        password: auth.password || '',
        login_url: auth.login_url || null,
        provided_token: auth.provided_token || null,
      }
    }
    setSubmitting(true)
    try {
      const res = await scansApi.create(target.trim(), type, auth_config)
      onCreated(res.data)
    } catch (err) {
      setError(apiError(err, "Impossible de lancer l'analyse."))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-title">
        <div className="dialog-head">
          <div><h2 id="dlg-title">Nouvelle analyse</h2><p>Choisissez un type d'analyse et une cible.</p></div>
          <button className="btn btn-ghost icon-btn" type="button" onClick={onClose} aria-label="Fermer">
            <X size={16} strokeWidth={1.8} aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="dialog-body">
            {error && (
              <div className="alert" role="alert">
                <TriangleAlert size={16} strokeWidth={1.8} aria-hidden="true" /><span>{error}</span>
              </div>
            )}

            <fieldset>
              <legend className="label">Type d'analyse</legend>
              <div className="choice-grid">
                {SCAN_TYPES.map(({ key, label, hint, icon: Icon }) => (
                  <button key={key} type="button" className="choice" aria-pressed={type === key} onClick={() => setType(key)}>
                    <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                    <div><b>{label}</b><span>{hint}</span></div>
                  </button>
                ))}
              </div>
            </fieldset>

            <div className="field">
              <label htmlFor="target">Cible</label>
              <input ref={targetRef} className="input mono" id="target" type="text" required autoComplete="off" autoCapitalize="none"
                     spellCheck={false} placeholder={SCAN_TYPE[type].placeholder} aria-describedby="target-hint"
                     value={target} onChange={(e) => setTarget(e.target.value)} />
              <span className="hint" id="target-hint">N'analysez que des systèmes que vous possédez ou que vous êtes autorisé à tester.</span>
            </div>

            {type === 'authenticated_web' && (
              <fieldset className="stack" style={{ padding: 16, border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <legend className="label" style={{ padding: '0 6px' }}>Identifiants de connexion</legend>
                <div className="grid-2" style={{ gap: 12, gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))' }}>
                  <div className="field"><label htmlFor="auth-login">Email ou nom d'utilisateur</label>
                    <input className="input" id="auth-login" autoComplete="off" value={auth.login_identifier} onChange={setA('login_identifier')} /></div>
                  <div className="field"><label htmlFor="auth-pwd">Mot de passe</label>
                    <input className="input" id="auth-pwd" type="password" autoComplete="new-password" value={auth.password} onChange={setA('password')} /></div>
                </div>
                <div className="field"><label htmlFor="auth-url">URL de connexion <span className="muted" style={{ fontWeight: 400 }}>(optionnel)</span></label>
                  <input className="input mono" id="auth-url" placeholder="https://app.example.com/login" value={auth.login_url} onChange={setA('login_url')} />
                  <span className="hint">Détectée automatiquement si vide.</span></div>
                <div className="field"><label htmlFor="auth-token">Jeton d'accès <span className="muted" style={{ fontWeight: 400 }}>(optionnel)</span></label>
                  <input className="input mono" id="auth-token" placeholder="Bearer eyJhbGciOi…" autoComplete="off" value={auth.provided_token} onChange={setA('provided_token')} />
                  <span className="hint">S'il est renseigné, l'email et le mot de passe sont ignorés.</span></div>
                <p className="xs muted">Les identifiants servent uniquement pendant l'analyse et ne sont pas enregistrés.</p>
              </fieldset>
            )}
          </div>

          <div className="dialog-foot">
            <button className="btn" type="button" onClick={onClose}>Annuler</button>
            <button className="btn btn-primary" type="submit" disabled={submitting}>
              {submitting && <span className="spinner" aria-hidden="true" />}
              {submitting ? 'Lancement…' : "Lancer l'analyse"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
