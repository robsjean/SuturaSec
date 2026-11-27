import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Check, Circle, Eye } from 'lucide-react'
import { authApi } from '../services/api'
import AuthLayout, { FormError } from '../components/AuthLayout'
import { apiError } from '../lib/scan'

const checksFor = (p) => [
  { key: 'len', ok: p.length >= 8, label: '8 caractères minimum' },
  { key: 'upper', ok: /[A-Z]/.test(p), label: 'Une majuscule' },
  { key: 'lower', ok: /[a-z]/.test(p), label: 'Une minuscule' },
  { key: 'digit', ok: /[0-9]/.test(p), label: 'Un chiffre' },
  { key: 'special', ok: /[!@#$%^&*()\-_=+[\]{};:'",.<>?/\\|`~]/.test(p), label: 'Un caractère spécial' },
]

const strengthOf = (n) =>
  n <= 1 ? { level: 1, label: 'très faible' } : n === 2 ? { level: 2, label: 'faible' } : n <= 4 ? { level: 3, label: 'acceptable' } : { level: 4, label: 'robuste' }

export default function RegisterPage() {
  const [form, setForm] = useState({ email: '', username: '', password: '', confirm: '' })
  const [showPwd, setShowPwd] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [autoLoggedIn, setAutoLoggedIn] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

  const checks = checksFor(form.password)
  const strength = strengthOf(checks.filter((c) => c.ok).length)
  const match = form.password.length > 0 && form.password === form.confirm
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    const unmet = checks.filter((c) => !c.ok).map((c) => c.label.toLowerCase())
    if (form.username.trim().length < 3) return setError("Le nom d'utilisateur doit faire au moins 3 caractères.")
    if (!form.email.trim()) return setError("L'adresse e-mail est requise.")
    if (unmet.length) return setError('Mot de passe : ' + unmet.join(', ') + '.')
    if (!match) return setError('Les mots de passe ne correspondent pas.')
    setLoading(true)
    try {
      await authApi.register({ email: form.email.trim(), username: form.username.trim(), password: form.password })
      setSuccess(true)
      // Connexion automatique : pas besoin de ressaisir ses identifiants
      try {
        await login(form.username.trim(), form.password)
        setAutoLoggedIn(true)
        setTimeout(() => navigate('/dashboard'), 900)
      } catch { /* repli : bouton « Se connecter » */ }
    } catch (err) {
      setError(err.response ? apiError(err, "Erreur lors de l'inscription.") : 'Erreur réseau. Vérifiez votre connexion.')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <AuthLayout>
        <div className="auth-form" style={{ alignItems: 'flex-start' }}>
          <span style={{ width: 44, height: 44, borderRadius: '50%', background: 'var(--ok-bg)', color: 'var(--ok)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Check size={22} strokeWidth={2} aria-hidden="true" />
          </span>
          <div className="stack-sm">
            <h1>Compte créé</h1>
            <p className="muted">{autoLoggedIn ? 'Connexion à votre espace…' : 'Votre espace est prêt. Connectez-vous pour lancer votre première analyse.'}</p>
          </div>
          {!autoLoggedIn && <Link className="btn btn-ink btn-lg btn-block" to="/login">Se connecter</Link>}
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <div className="auth-form">
        <div className="stack-sm">
          <h1>Créer un compte</h1>
          <p className="muted">Gratuit, sans carte bancaire.</p>
        </div>

        <FormError>{error}</FormError>

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="reg-user">Nom d'utilisateur</label>
            <input className="input" id="reg-user" type="text" required minLength={3} autoComplete="username" autoCapitalize="none"
                   spellCheck={false} aria-describedby="reg-user-hint" value={form.username} onChange={set('username')} />
            <span className="hint" id="reg-user-hint">3 caractères minimum.</span>
          </div>
          <div className="field">
            <label htmlFor="reg-email">Adresse e-mail</label>
            <input className="input" id="reg-email" type="email" required autoComplete="email" placeholder="vous@entreprise.com"
                   value={form.email} onChange={set('email')} />
          </div>
          <div className="field">
            <label htmlFor="reg-pwd">Mot de passe</label>
            <div className="pw-wrap">
              <input className="input" id="reg-pwd" type={showPwd ? 'text' : 'password'} required autoComplete="new-password"
                     aria-describedby="reg-pwd-checks" value={form.password} onChange={set('password')} />
              <button type="button" onClick={() => setShowPwd(!showPwd)} aria-label={showPwd ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}>
                <Eye size={16} strokeWidth={1.8} aria-hidden="true" />
              </button>
            </div>
            {form.password.length > 0 && (
              <div className="stack-sm" style={{ gap: 6 }}>
                <div className="strength" aria-hidden="true">
                  {[1, 2, 3, 4].map((i) => <span key={i} className={i <= strength.level ? 'on' : ''} />)}
                </div>
                <span className="hint">Robustesse : {strength.label}</span>
              </div>
            )}
            <ul className="checks" id="reg-pwd-checks">
              {checks.map((c) => (
                <li key={c.key} className={c.ok ? 'ok' : ''}>
                  {c.ok ? <Check size={12} strokeWidth={2.4} aria-hidden="true" /> : <Circle size={12} strokeWidth={2} aria-hidden="true" />}
                  <span>{c.label}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="field">
            <label htmlFor="reg-confirm">Confirmer le mot de passe</label>
            <input className="input" id="reg-confirm" type={showPwd ? 'text' : 'password'} required autoComplete="new-password"
                   aria-invalid={form.confirm.length > 0 && !match} value={form.confirm} onChange={set('confirm')} />
            {form.confirm.length > 0 && !match && <span className="hint text-crit">Les mots de passe ne correspondent pas.</span>}
          </div>
          <button className="btn btn-ink btn-lg btn-block" type="submit" disabled={loading}>
            {loading && <span className="spinner" aria-hidden="true" />}
            {loading ? 'Création…' : 'Créer mon compte'}
          </button>
          <p className="xs muted">N'analysez que des systèmes que vous possédez ou que vous êtes autorisé à tester.</p>
        </form>

        <p className="small muted" style={{ textAlign: 'center' }}>
          Déjà un compte ? <Link to="/login">Se connecter</Link>
        </p>
      </div>
    </AuthLayout>
  )
}
