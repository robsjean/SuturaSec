import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import AuthLayout, { FormError } from '../components/AuthLayout'
import { apiError } from '../lib/scan'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPwd, setShowPwd] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(form.username.trim(), form.password)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response ? apiError(err, 'Identifiants incorrects.') : 'Erreur réseau. Vérifiez votre connexion.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout>
      <div className="auth-form">
        <div className="stack-sm">
          <h1>Connexion</h1>
          <p className="muted">Accédez à vos analyses de sécurité.</p>
        </div>

        <FormError>{error}</FormError>

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="login-user">Nom d'utilisateur</label>
            <input className="input" id="login-user" type="text" required autoComplete="username" autoCapitalize="none"
                   spellCheck={false} aria-invalid={!!error} value={form.username}
                   onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="login-pwd">Mot de passe</label>
            <div className="pw-wrap">
              <input className="input" id="login-pwd" type={showPwd ? 'text' : 'password'} required autoComplete="current-password"
                     aria-invalid={!!error} value={form.password}
                     onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <button type="button" onClick={() => setShowPwd(!showPwd)} aria-label={showPwd ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}>
                <Eye size={16} strokeWidth={1.8} aria-hidden="true" />
              </button>
            </div>
          </div>
          <button className="btn btn-ink btn-lg btn-block" type="submit" disabled={loading || !form.username || !form.password}>
            {loading && <span className="spinner" aria-hidden="true" />}
            {loading ? 'Connexion…' : 'Se connecter'}
          </button>
        </form>

        <p className="small muted" style={{ textAlign: 'center' }}>
          Pas encore de compte ? <Link to="/register">Créer un compte</Link>
        </p>
      </div>
    </AuthLayout>
  )
}
