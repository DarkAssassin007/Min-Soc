/**
 * API client for the Mini SOC backend.
 *
 * - one place for the base URL, the bearer token and error shaping
 * - automatic single refresh-and-retry when an access token expires, so an
 *   analyst never loses their place in a table because a token timed out
 * - errors carry `status` and a human message taken from the backend envelope
 */

const BASE = import.meta.env.VITE_API_BASE || '/api/v1'
const ACCESS_KEY = 'mini-soc.access-token'
const REFRESH_KEY = 'mini-soc.refresh-token'
const USER_KEY = 'mini-soc.user'

export class ApiError extends Error {
  constructor(message, status, detail) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

export function getTokens() {
  return {
    access: localStorage.getItem(ACCESS_KEY),
    refresh: localStorage.getItem(REFRESH_KEY),
  }
}

export function setTokens({ access_token, refresh_token }) {
  if (access_token) localStorage.setItem(ACCESS_KEY, access_token)
  if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token)
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
  localStorage.removeItem(USER_KEY)
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function setStoredUser(user) {
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user))
  else localStorage.removeItem(USER_KEY)
}

function messageFrom(payload, fallback) {
  if (!payload) return fallback
  if (typeof payload === 'string') return payload
  if (payload.message) return payload.message
  if (Array.isArray(payload.problems) && payload.problems.length) {
    return payload.problems.map((p) => `${p.field || 'request'}: ${p.message}`).join('; ')
  }
  if (Array.isArray(payload.messages)) return payload.messages.join('; ')
  return fallback
}

async function parse(response) {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

let refreshInFlight = null

async function refreshTokens() {
  const { refresh } = getTokens()
  if (!refresh) return false
  if (!refreshInFlight) {
    refreshInFlight = fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
    })
      .then(async (response) => {
        if (!response.ok) return false
        const data = await parse(response)
        if (data?.access_token) {
          setTokens(data)
          setStoredUser(data.user)
          return true
        }
        return false
      })
      .catch(() => false)
      .finally(() => {
        refreshInFlight = null
      })
  }
  return refreshInFlight
}

export async function request(path, options = {}) {
  const { method = 'GET', body, auth = true, retry = true, signal } = options
  const headers = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (auth) {
    const { access } = getTokens()
    if (access) headers.Authorization = `Bearer ${access}`
  }

  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })

  if (response.status === 401 && auth && retry && (await refreshTokens())) {
    return request(path, { ...options, retry: false })
  }

  const payload = await parse(response)
  if (!response.ok) {
    throw new ApiError(
      messageFrom(payload, `request failed (${response.status})`),
      response.status,
      payload,
    )
  }
  return payload
}

export const api = {
  get: (path, options) => request(path, { ...options, method: 'GET' }),
  post: (path, body, options) => request(path, { ...options, method: 'POST', body }),
  patch: (path, body, options) => request(path, { ...options, method: 'PATCH', body }),
  put: (path, body, options) => request(path, { ...options, method: 'PUT', body }),

  async login(username, password) {
    const data = await request('/auth/login', {
      method: 'POST',
      body: { username, password },
      auth: false,
    })
    setTokens(data)
    setStoredUser(data.user)
    return data.user
  },

  async bootstrap(username, password) {
    const data = await request('/auth/bootstrap', {
      method: 'POST',
      body: { username, password },
      auth: false,
    })
    setTokens(data)
    setStoredUser(data.user)
    return data.user
  },

  async logout() {
    const { refresh } = getTokens()
    try {
      if (refresh) await request('/auth/logout', { method: 'POST', body: { refresh_token: refresh } })
    } catch {
      /* logging out locally is what matters */
    }
    clearTokens()
  },

  async me() {
    const user = await request('/auth/me')
    setStoredUser(user)
    return user
  },

  async needsBootstrap() {
    try {
      await request('/users', { auth: false })
      return false
    } catch (error) {
      if (error.status === 401) return false
      return true
    }
  },
}

export function buildQuery(params = {}) {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    search.set(key, value)
  })
  const query = search.toString()
  return query ? `?${query}` : ''
}

export default api
