import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Un 401 sur /auth/login signifie « identifiants incorrects » : on laisse
    // la page de connexion afficher l'erreur au lieu de la recharger.
    const isLogin = err.config?.url?.startsWith('/auth/login')
    if (err.response?.status === 401 && !isLogin) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const authApi = {
  register: (data) => api.post('/auth/register', data),
  login: (username, password, remember = false) => {
    const form = new FormData()
    form.append('username', username)
    form.append('password', password)
    form.append('remember', remember ? 'true' : 'false')
    return api.post('/auth/login', form)
  },
  me: () => api.get('/auth/me'),
}

export const scansApi = {
  create: (target, scan_type, auth_config = null, authorization_confirmed = false) =>
    api.post('/scans', {
      target, scan_type, authorization_confirmed,
      ...(auth_config ? { auth_config } : {}),
    }),
  // Lien de rapport à portée limitée (10 min, ce scan uniquement)
  reportLink: (id) => api.post(`/scans/${id}/report-link`),
  list: () => api.get('/scans'),
  get: (id) => api.get(`/scans/${id}`),
  delete: (id) => api.delete(`/scans/${id}`),
}

export default api
