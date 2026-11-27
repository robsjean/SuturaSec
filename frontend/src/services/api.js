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
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const authApi = {
  register: (data) => api.post('/auth/register', data),
  login: (username, password) => {
    const form = new FormData()
    form.append('username', username)
    form.append('password', password)
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
